#!/usr/bin/env python3
from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
CHECK = ROOT / "all/.local/bin/agent-fleet-check"
USERS = ROOT / "all/.local/bin/agent-users-bootstrap"


def free_uid() -> int:
    """A uid/gid in the reserved band that nothing on this host holds."""
    for uid in range(2090, 2100):
        taken = subprocess.run(["getent", "passwd", str(uid)], capture_output=True).returncode == 0
        taken |= subprocess.run(["getent", "group", str(uid)], capture_output=True).returncode == 0
        if not taken:
            return uid
    raise unittest.SkipTest("no free test uid in 2090-2099")


class AgentFleetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        conf = Path(self.tmp.name)
        (conf / "fleet.ssv").write_text(f"# alias hostname\nself {socket.gethostname()}\n")
        (conf / "uids.ssv").write_text(
            "# tool uid provision\n"
            f"ghost {free_uid()} yes\n"
            f"clash {os.getuid()} yes\n"
            "parked 2010 no\n"
        )
        self.env = dict(os.environ, AGENT_CLI_CONF=str(conf), AGENT_UIDS_FILE=str(conf / "uids.ssv"))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_tool(self, tool: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(tool), *args], env=self.env, text=True, capture_output=True, check=False)

    def test_reports_missing_and_collision(self) -> None:
        out = self.run_tool(CHECK)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("MISSING agent-ghost", out.stdout)
        self.assertIn("COLLISION agent-clash", out.stdout)
        self.assertNotIn("agent-parked", out.stdout, "provision=no agents are not gaps")

    def test_agents_column_narrows_the_host(self) -> None:
        conf = Path(self.env["AGENT_CLI_CONF"])
        (conf / "fleet.ssv").write_text(f"# alias hostname reach agents warm\nself {socket.gethostname()} - ghost -\n")
        out = self.run_tool(CHECK)
        self.assertIn("MISSING agent-ghost", out.stdout)
        self.assertNotIn("agent-clash", out.stdout, "an agent the host does not carry is not expected there")

    def test_apply_needs_provision(self) -> None:
        self.assertEqual(self.run_tool(CHECK, "--apply").returncode, 2)

    def test_users_bootstrap_dry_run_and_guards(self) -> None:
        dry = self.run_tool(USERS, "--only", "ghost,clash")
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertIn("DRY-RUN: sudo useradd --uid", dry.stdout)
        self.assertIn("COLLISION", dry.stdout)
        self.assertNotIn("+ sudo", dry.stdout, "dry-run must not execute")
        bad = self.run_tool(USERS, "--only", "nosuch")
        self.assertEqual(bad.returncode, 1)


if __name__ == "__main__":
    unittest.main()
