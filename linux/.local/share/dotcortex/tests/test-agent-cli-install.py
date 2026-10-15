#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
INSTALL = ROOT / "all/.local/bin/agent-cli-install"


class AgentCliInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.bin = base / "bin"
        self.bin.mkdir()
        self.manifests = base / "agent-cli"
        self.manifests.mkdir()
        (self.manifests / "vibe.ssv").write_text(
            "# MANAGER PACKAGE [VERSION] [ROLE]\n"
            "pip mistral-vibe\n"
            "pip mistralai \"\" dependency\n"
        )
        (self.bin / "id").write_text("#!/bin/sh\nexit 0\n")
        (self.bin / "sudo").write_text(
            "#!/bin/sh\n"
            "while [ \"$#\" -gt 0 ]; do last=\"$1\"; shift; done\n"
            "/bin/sh -c \"$last\"\n"
        )
        for p in (self.bin / "id", self.bin / "sudo"):
            p.chmod(0o755)
        self.env = dict(
            os.environ,
            AGENT_CLI_MANIFESTS=str(self.manifests),
            AGENT_CLI_HOST="testhost",
            PATH=f"{self.bin}:/usr/bin:/bin",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_cli(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(INSTALL), "--only", "vibe", *args],
            env=env or self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

    def test_vibe_dry_run_shows_all_python_choices_and_dependency(self) -> None:
        out = self.run_cli()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("uv tool uninstall 'mistral-vibe'", out.stdout)
        self.assertIn("pipx uninstall 'mistral-vibe'", out.stdout)
        self.assertIn("python3 -m pip uninstall -y 'mistral-vibe'", out.stdout)
        self.assertIn("dependency mistralai", out.stdout)
        self.assertNotIn("+ sudo", out.stdout, "dry-run must not execute")

    def apply_with(self, manager: str) -> list[str]:
        log = Path(self.tmp.name) / f"{manager}.log"
        for name in ("uv", "pipx", "python3"):
            (self.bin / name).unlink(missing_ok=True)
        manager_path = self.bin / manager
        manager_path.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$AGENT_TEST_LOG\"\n"
        )
        manager_path.chmod(0o755)
        env = dict(self.env, AGENT_TEST_LOG=str(log))
        out = self.run_cli("--apply", env=env)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        return log.read_text().splitlines()

    def test_uninstall_precedes_install_for_uv_pipx_and_pip(self) -> None:
        for manager, uninstall, install in (
            ("uv", "tool uninstall mistral-vibe", "tool install mistral-vibe"),
            ("pipx", "uninstall mistral-vibe", "install mistral-vibe"),
            ("python3", "-m pip uninstall -y mistral-vibe", "-m pip install --user mistral-vibe"),
        ):
            with self.subTest(manager=manager):
                lines = self.apply_with(manager)
                before = lines.index(uninstall)
                after = lines.index(install)
                self.assertLess(before, after)


if __name__ == "__main__":
    unittest.main()
