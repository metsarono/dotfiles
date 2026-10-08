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


class PatchSeriesFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="bun-patch-series-")
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.dotcortex = self.home / "DotCortex"
        self.bin = self.home / ".local/bin"
        self.global_manifest = self.dotcortex / "all/.local/share/dotcortex/manifests/bun/global.ssv"
        self.build_manifest = self.root / "build.ssv"
        self.state = self.root / "state"
        self.global_dir = self.root / "bun-global"
        self.checkout = self.root / "checkout"
        self.patch = self.dotcortex / "patches/fixture.patch"
        self.runner_log = self.root / "runner.log"

        self.bin.mkdir(parents=True)
        self.global_manifest.parent.mkdir(parents=True)
        self.global_manifest.write_text("# PKG VERSION FLAGS REGISTRY EXTRA\n", encoding="utf-8")
        self.patch.parent.mkdir(parents=True)
        self.global_dir.mkdir()
        self.checkout.mkdir()

        self.git("init", "--quiet")
        (self.checkout / "managed.txt").write_text("base\n", encoding="utf-8")
        (self.checkout / "local.txt").write_text("untouched\n", encoding="utf-8")
        self.git("add", "managed.txt", "local.txt")
        self.git(
            "-c", "user.name=DotCortex Test", "-c", "user.email=dotcortex@example.invalid",
            "commit", "--quiet", "-m", "base",
        )
        self.ref = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("remote", "add", "origin", str(self.checkout))

        runner = self.bin / "dotcortex-bun-env"
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf 'runner:%s\\n' \"$*\" >> \"$BUN_PATCH_RUNNER_LOG\"\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
        os.symlink(BUILD_LIB, self.bin / "dotcortex-bun-build-lib")

        self.env = {
            "HOME": str(self.home),
            "PATH": "/usr/bin:/bin",
            "DOTCORTEX_ROOT": str(self.dotcortex),
            "BUN_BUILD_MANIFEST": str(self.build_manifest),
            "BUN_BUILD_STATE_ROOT": str(self.state),
            "DOTCORTEX_BUN_ENV": str(runner),
            "BUN_GLOBAL_DIR": str(self.global_dir),
            "BUN_BUILD_ONLY": "fixture",
            "ENFORCE": "0",
            "UNINSTALL": "0",
            "UPDATE": "0",
            "BUN_PATCH_RUNNER_LOG": str(self.runner_log),
        }
        self.write_patch("v1")
        self.write_manifest()

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.checkout), *args],
            capture_output=True,
            text=True,
            check=True,
        )

    def write_patch(self, value: str) -> None:
        managed = self.checkout / "managed.txt"
        previous = managed.read_text(encoding="utf-8")
        managed.write_text(f"{value}\n", encoding="utf-8")
        try:
            diff = self.git("diff", "--binary", "--full-index", self.ref, "--", "managed.txt").stdout
        finally:
            managed.write_text(previous, encoding="utf-8")
        if not diff:
            raise AssertionError("fixture patch unexpectedly empty")
        self.patch.write_text(diff, encoding="utf-8")

    def write_manifest(self, *, allow_untracked: str = "") -> None:
        extra = "patches=patches/fixture.patch"
        if allow_untracked:
            extra += f";allow-untracked={allow_untracked}"
        fields = [
            "fixture", "git", str(self.checkout), str(self.checkout), self.ref,
            ".", "none", "true", "none", extra,
        ]
        self.build_manifest.write_text(shlex.join(fields) + "\n", encoding="utf-8")

    def run(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(APPLY)],
            capture_output=True,
            text=True,
            env=self.env,
            check=False,
        )

    def diff(self) -> str:
        return self.git("diff", "--binary", "--full-index", self.ref).stdout

    def close(self) -> None:
        self.temporary.cleanup()


class BunPatchSeriesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = PatchSeriesFixture()
        self.addCleanup(self.fixture.close)

    def assert_failed_without_mutation(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.fixture.checkout / "managed.txt").read_text(encoding="utf-8"),
            "base\n",
        )

    def test_pristine_checkout_applies_series_and_records_exact_state(self) -> None:
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("apply patch series (1 patches)", result.stdout)
        self.assertEqual(
            (self.fixture.checkout / "managed.txt").read_text(encoding="utf-8"),
            "v1\n",
        )
        state = self.fixture.state / "fixture/patch-series"
        self.assertEqual((state / "schema").read_text(encoding="utf-8"), "1\n")
        self.assertTrue((state / "applied.patch").is_file())

    def test_already_current_checkout_is_a_successful_noop(self) -> None:
        self.fixture.git("apply", str(self.fixture.patch))
        before = self.fixture.diff()
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("patch series current", result.stdout)
        self.assertEqual(self.fixture.diff(), before)

    def test_patch_version_change_replaces_only_recorded_prior_series(self) -> None:
        first = self.fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.fixture.write_patch("v2")

        second = self.fixture.run()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("replace recognized prior patch series", second.stdout)
        self.assertEqual(
            (self.fixture.checkout / "managed.txt").read_text(encoding="utf-8"),
            "v2\n",
        )
        self.assertEqual(
            (self.fixture.checkout / "local.txt").read_text(encoding="utf-8"),
            "untouched\n",
        )
        self.assertEqual(self.fixture.git("diff", "--name-only", self.fixture.ref).stdout, "managed.txt\n")

    def test_unrecorded_stale_series_fails_loudly_and_is_preserved(self) -> None:
        self.fixture.git("apply", str(self.fixture.patch))
        self.fixture.write_patch("v2")
        result = self.fixture.run()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("not recognized as the managed patch series", result.stderr)
        self.assertEqual(
            (self.fixture.checkout / "managed.txt").read_text(encoding="utf-8"),
            "v1\n",
        )

    def test_unknown_tracked_edit_is_refused_and_preserved(self) -> None:
        local = self.fixture.checkout / "local.txt"
        local.write_text("operator work\n", encoding="utf-8")
        result = self.fixture.run()
        self.assert_failed_without_mutation(result)
        self.assertIn("not recognized as the managed patch series", result.stderr)
        self.assertEqual(local.read_text(encoding="utf-8"), "operator work\n")

    def test_staged_edit_is_refused_and_preserved(self) -> None:
        local = self.fixture.checkout / "local.txt"
        local.write_text("staged operator work\n", encoding="utf-8")
        self.fixture.git("add", "local.txt")
        result = self.fixture.run()
        self.assert_failed_without_mutation(result)
        self.assertIn("staged checkout edits", result.stderr)
        self.assertEqual(local.read_text(encoding="utf-8"), "staged operator work\n")

    def test_unknown_untracked_file_is_refused_and_preserved(self) -> None:
        note = self.fixture.checkout / "operator-note.txt"
        note.write_text("keep me\n", encoding="utf-8")
        result = self.fixture.run()
        self.assert_failed_without_mutation(result)
        self.assertIn("unknown untracked checkout path: operator-note.txt", result.stderr)
        self.assertEqual(note.read_text(encoding="utf-8"), "keep me\n")

    def test_declared_generated_untracked_file_may_coexist(self) -> None:
        generated = self.fixture.checkout / "generated.out"
        generated.write_text("managed output\n", encoding="utf-8")
        self.fixture.write_manifest(allow_untracked="generated.out")
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(generated.read_text(encoding="utf-8"), "managed output\n")
        self.assertEqual(
            (self.fixture.checkout / "managed.txt").read_text(encoding="utf-8"),
            "v1\n",
        )

    def test_inapplicable_patch_fails_loudly_before_mutation(self) -> None:
        self.fixture.patch.write_text(
            "diff --git a/managed.txt b/managed.txt\n"
            "--- a/managed.txt\n"
            "+++ b/managed.txt\n"
            "@@ -1 +1 @@\n"
            "-not-the-base\n"
            "+v2\n",
            encoding="utf-8",
        )
        result = self.fixture.run()
        self.assert_failed_without_mutation(result)
        self.assertIn("patch applies neither", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
