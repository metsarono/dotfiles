#!/usr/bin/env python3
"""agent-cli-install lanes: no agent CLI pinned (ruling 2026-10-05), host lanes still replace the fleet lane. Dry-run only, no root."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
INSTALL = ROOT / "all/.local/bin/agent-cli-install"
MANIFESTS = ROOT / "all/.config/agent-cli"
# Runtimes an agent lane may still pin; everything else in a lane is an agent CLI.
RUNTIMES = {"bun"}


def lane_lines(path: Path) -> list[list[str]]:
    return [l.split() for l in path.read_text().splitlines() if l.strip() and not l.lstrip().startswith("#")]


class AgentCliLaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        stub = Path(self.tmp.name) / "bin"
        stub.mkdir()
        (stub / "id").write_text("#!/bin/sh\nexit 0\n")  # every agent user "exists"
        (stub / "id").chmod(0o755)
        self.env = dict(os.environ, PATH=f"{stub}:{os.environ['PATH']}")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def dry(self, host: str, only: str, manifests: Path = MANIFESTS) -> str:
        out = subprocess.run(["bash", str(INSTALL), "--only", only],
                             env=dict(self.env, AGENT_CLI_HOST=host, AGENT_CLI_MANIFESTS=str(manifests)),
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertNotIn("+ ", out.stdout, "dry-run must not run anything")
        return out.stdout

    def test_no_agent_cli_is_pinned(self) -> None:
        for lane in [*MANIFESTS.glob("*.ssv"), *MANIFESTS.glob("hosts/*@agent-*.ssv")]:
            for fields in lane_lines(lane):
                if fields[0] == "npm" and fields[1] not in RUNTIMES:
                    self.assertEqual(len(fields), 2, f"{lane.name} pins {' '.join(fields[1:])}")

    def test_honey_installs_latest(self) -> None:
        out = self.dry("beelink", "codex,opencode")
        self.assertNotIn("host lane", out)
        for pkg in ("@openai/codex", "opencode-ai", "@grinev/opencode-telegram-bot", "agent-browser"):
            self.assertIn(f"npm install -g '{pkg}'", out)
        self.assertNotRegex(out, r"npm install -g '(@openai/codex|opencode-ai|@grinev/opencode-telegram-bot)@")

    def test_a_host_lane_replaces_the_fleet_lane(self) -> None:
        fixture = Path(self.tmp.name) / "agent-cli"
        shutil.copytree(MANIFESTS, fixture)
        (fixture / "hosts").mkdir(exist_ok=True)
        (fixture / "hosts/testhost@agent-opencode.ssv").write_text("# MANAGER PACKAGE [VERSION]\nnpm opencode-ai\n")
        out = self.dry("testhost", "opencode", fixture)
        self.assertIn("hosts/testhost@agent-opencode.ssv", out)
        self.assertNotIn("agent-browser", out)
        self.assertIn("agent-browser", self.dry("otherhost", "opencode", fixture))

    def test_host_lanes_only_name_provisioned_agents(self) -> None:
        tools = {l[0] for l in lane_lines(MANIFESTS / "uids.ssv") if l[2] == "yes"}
        for lane in (MANIFESTS / "hosts").glob("*@agent-*.ssv"):
            self.assertIn(lane.stem.split("@agent-", 1)[1], tools, lane.name)


if __name__ == "__main__":
    unittest.main()
