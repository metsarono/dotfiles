#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve()
ROOT = HERE.parents[5]
APPLY = ROOT / "all/.local/bin/bun-apply"
BUILD_LIB = ROOT / "all/.local/bin/dotcortex-bun-build-lib"


class BunApplyFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="bun-apply-help-")
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.repo = self.home / "DotCortex"
        self.bin = self.home / ".local/bin"
        self.global_manifest = self.repo / "all/.local/share/dotcortex/manifests/bun/global.ssv"
        self.build_manifest = self.root / "build.ssv"
        self.state = self.root / "state"
        self.global_dir = self.root / "bun-global"
        self.source = self.root / "source"
        self.call_log = self.root / "runner.log"
        self.build_log = self.root / "build.log"

        self.bin.mkdir(parents=True)
        self.global_manifest.parent.mkdir(parents=True)
        self.global_manifest.write_text("# PKG VERSION FLAGS REGISTRY EXTRA\n", encoding="utf-8")
        self.global_dir.mkdir()
        self.source.mkdir()
        (self.source / "package.json").write_text('{"name":"fixture"}\n', encoding="utf-8")

        runner = self.bin / "dotcortex-bun-env"
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf 'runner:%s\\n' \"$*\" >> \"$BUN_TEST_CALL_LOG\"\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
        os.symlink(BUILD_LIB, self.bin / "dotcortex-bun-build-lib")

        rows = [
            self._row("chosen", 'printf "%s\\n" chosen >> "$BUN_TEST_BUILD_LOG"'),
            self._row("other", 'printf "%s\\n" other >> "$BUN_TEST_BUILD_LOG"'),
        ]
        self.build_manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
        self.env = {
            "HOME": str(self.home),
            "PATH": "/usr/bin:/bin",
            "DOTCORTEX_ROOT": str(self.repo),
            "BUN_BUILD_MANIFEST": str(self.build_manifest),
            "BUN_BUILD_STATE_ROOT": str(self.state),
            "DOTCORTEX_BUN_ENV": str(runner),
            "BUN_GLOBAL_DIR": str(self.global_dir),
            "BUN_BUILD_ONLY": "chosen",
            "ENFORCE": "0",
            "UNINSTALL": "0",
            "UPDATE": "0",
            "BUN_TEST_CALL_LOG": str(self.call_log),
            "BUN_TEST_BUILD_LOG": str(self.build_log),
        }

    def _row(self, name: str, build: str) -> str:
        fields = [name, "local", str(self.source), "unused", "unused", ".", "none", build, "none"]
        return shlex.join(fields)

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(APPLY), *args],
            capture_output=True,
            text=True,
            env=self.env,
            check=False,
        )

    def assert_no_apply(self, case: unittest.TestCase) -> None:
        case.assertFalse(self.call_log.exists(), "help/rejection reached the Bun runner")
        case.assertFalse(self.build_log.exists(), "help/rejection ran a build command")
        case.assertFalse(self.state.exists(), "help/rejection created build state")

    def close(self) -> None:
        self.temporary.cleanup()


class BunApplyCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = BunApplyFixture()
        self.addCleanup(self.fixture.close)

    def test_long_help_prints_complete_usage_without_apply(self) -> None:
        result = self.fixture.run("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertTrue(result.stdout.startswith("Usage: bun-apply [-h|--help]\n"))
        for name in (
            "ENFORCE", "UNINSTALL", "UPDATE", "BUN_BUILD_ONLY", "DOTCORTEX_ROOT",
            "PROVISION_APPLY", "BUN_INSTALL", "BUN_GLOBAL_DIR", "BUN_GLOBAL_BIN_DIR",
            "BUN_BUILD_MANIFEST", "BUN_BUILD_STATE_ROOT", "DOTCORTEX_BUN_ENV",
            "XDG_STATE_HOME",
        ):
            with self.subTest(name=name):
                self.assertIn(name, result.stdout)
        self.fixture.assert_no_apply(self)

    def test_short_help_prints_usage_without_apply(self) -> None:
        result = self.fixture.run("-h")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertIn("Usage: bun-apply", result.stdout)
        self.fixture.assert_no_apply(self)

    def test_unknown_flag_fails_closed_with_usage(self) -> None:
        result = self.fixture.run("--definitely-not-a-bun-apply-flag")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("unknown argument", result.stderr)
        self.assertIn("Usage: bun-apply", result.stderr)
        self.fixture.assert_no_apply(self)

    def test_help_with_extra_argument_fails_closed(self) -> None:
        result = self.fixture.run("--help", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("does not accept additional arguments", result.stderr)
        self.assertIn("Usage: bun-apply", result.stderr)
        self.fixture.assert_no_apply(self)

    def test_no_argument_apply_preserves_selected_build_behavior(self) -> None:
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("== bun apply ==", result.stdout)
        self.assertIn(">> [chosen] build:", result.stdout)
        self.assertIn("Done.", result.stdout)
        self.assertEqual(self.fixture.build_log.read_text(encoding="utf-8"), "chosen\n")
        self.assertNotIn("other", self.fixture.build_log.read_text(encoding="utf-8"))
        self.assertTrue(self.fixture.call_log.exists(), "valid apply did not reach the fake runner")
        self.assertTrue((self.fixture.state / "chosen/build.fp").is_file())
        self.assertFalse((self.fixture.state / "other").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
