from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest

ANCHOR = Path(__file__).resolve().parents[3] / "bin" / "session-anchor"

FAKE_SSH = """#!/usr/bin/env bash
printf '%s\\n' "$@" > "$FAKE_ROOT/ssh-args"
sleep "${FAKE_SSH_HOLD:-0}"
"""


class SessionAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ssh = self.root / "ssh"
        self.ssh.write_text(FAKE_SSH)
        self.ssh.chmod(self.ssh.stat().st_mode | stat.S_IXUSR)
        (self.root / "key").write_text("k")
        (self.root / "known").write_text("127.0.0.1 ssh-ed25519 AAAA\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def env(self, **extra: str) -> dict:
        return dict(os.environ, FAKE_ROOT=str(self.root), SESSION_ANCHOR_KEY=str(self.root / "key"),
                    SESSION_ANCHOR_KNOWN_HOSTS=str(self.root / "known"), SESSION_ANCHOR_STATE_DIR=str(self.root / "state"),
                    SESSION_ANCHOR_SSH_BIN=str(self.ssh), **extra)

    def run_anchor(self, *args: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([str(ANCHOR), *args], env=self.env(**extra), text=True, capture_output=True, timeout=30)

    def test_refuses_without_machine_local_setup(self) -> None:
        (self.root / "key").unlink()
        result = self.run_anchor("--once")
        self.assertEqual(result.returncode, 69)
        self.assertFalse((self.root / "ssh-args").exists())

    def test_connects_loopback_with_pinned_host_key_only(self) -> None:
        result = self.run_anchor("--once")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = (self.root / "ssh-args").read_text().split("\n")
        self.assertEqual(args[-2], "127.0.0.1")  # loopback only
        joined = " ".join(args)
        for required in ("IdentitiesOnly=yes", "BatchMode=yes", "StrictHostKeyChecking=yes",
                         "UserKnownHostsFile=%s" % (self.root / "known"), "GlobalKnownHostsFile=/dev/null", "-T"):
            self.assertIn(required, joined)
        self.assertNotIn("accept-new", joined)
        self.assertNotIn("StrictHostKeyChecking=no", joined)

    def test_second_supervisor_stands_down(self) -> None:
        first = subprocess.Popen([str(ANCHOR), "--once"], env=self.env(FAKE_SSH_HOLD="3"))
        try:
            time.sleep(0.5)
            second = self.run_anchor("--once")
            self.assertEqual(second.returncode, 0)
        finally:
            first.wait(timeout=30)
        self.assertEqual(first.returncode, 0)

    def test_help_is_side_effect_free(self) -> None:
        result = subprocess.run([str(ANCHOR), "--help"], text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
