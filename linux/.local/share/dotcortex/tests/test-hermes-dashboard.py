#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
SCRIPT = ROOT / "linux/.local/share/dotcortex/sysv/hermes-dashboard"
CRON = ROOT / "linux/.local/share/dotcortex/sysv/hermes-dashboard.cron"

SSD = r"""#!/bin/sh
echo "$@" >> "$STUB_LOG"
case "$1" in
  --status) [ -e "$STUB_RUNNING" ] ;;
esac
"""
SS = r"""#!/bin/sh
[ -e "$STUB_PORT_BUSY" ] && echo "LISTEN 0 128 127.0.0.1:9119 0.0.0.0:*"
exit 0
"""


class Harness:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.home = tmp / "home"
        (self.home / ".local/bin").mkdir(parents=True)
        (self.home / "DotCortex").mkdir()
        hermes = self.home / ".local/bin/hermes"
        hermes.write_text("#!/bin/sh\n")
        hermes.chmod(0o755)
        self.bin = tmp / "bin"
        self.bin.mkdir()
        for name, body in (("start-stop-daemon", SSD), ("ss", SS)):
            f = self.bin / name
            f.write_text(body)
            f.chmod(0o755)
        self.log = tmp / "ssd.log"
        self.running = tmp / "running"
        self.busy = tmp / "busy"
        self.state = self.home / ".local/state/hermes-dashboard"

    def run(self, verb: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HERMES_DASHBOARD_USER": subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip(),
            "HERMES_DASHBOARD_HOME": str(self.home),
            "STUB_LOG": str(self.log),
            "STUB_RUNNING": str(self.running),
            "STUB_PORT_BUSY": str(self.busy),
        }
        return subprocess.run([str(SCRIPT), verb], env=env, text=True, capture_output=True, timeout=20)

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []


class HermesDashboardInit(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.h = Harness(Path(self._tmp.name))

    def test_start_passes_user_dir_env_and_command(self) -> None:
        r = self.h.run("start")
        self.assertEqual(r.returncode, 0, r.stderr)
        (call,) = [c for c in self.h.calls() if c.startswith("--start")]
        self.assertIn("--background", call)
        self.assertIn("--make-pidfile", call)
        self.assertIn(f"--chdir {self.h.home}/DotCortex", call)
        self.assertIn(f"HOME={self.h.home}", call)
        self.assertIn(f"PATH={self.h.home}/.local/bin:", call)
        self.assertTrue(call.endswith(f"{self.h.home}/.local/bin/hermes dashboard --no-open"), call)
        self.assertIn("hermes-dashboard.log", call)
        self.assertEqual(oct((self.h.state).stat().st_mode & 0o777), "0o700")

    def test_start_refuses_when_port_already_in_use(self) -> None:
        self.h.busy.touch()
        r = self.h.run("start")
        self.assertEqual(r.returncode, 1)
        self.assertFalse([c for c in self.h.calls() if c.startswith("--start")])
        self.assertIn("REFUSED", (self.h.state / "hermes-dashboard.log").read_text())

    def test_start_is_idempotent_when_ours_is_running(self) -> None:
        self.h.running.touch()
        self.h.busy.touch()
        r = self.h.run("start")
        self.assertEqual(r.returncode, 0)
        self.assertFalse([c for c in self.h.calls() if c.startswith("--start")])

    def test_stop_leaves_marker_and_stops_by_pidfile(self) -> None:
        self.assertEqual(self.h.run("stop").returncode, 0)
        self.assertTrue((self.h.state / "stopped").exists())
        (call,) = [c for c in self.h.calls() if c.startswith("--stop")]
        self.assertIn("--retry=TERM/30/KILL/5", call)
        self.assertEqual(self.h.run("start").returncode, 0)
        self.assertFalse((self.h.state / "stopped").exists())

    def test_watch_respawns_only_when_nothing_serves(self) -> None:
        self.h.run("stop"); self.h.run("start")  # creates state dir, clears marker
        self.h.log.unlink()
        self.assertEqual(self.h.run("watch").returncode, 0)
        self.assertEqual(len([c for c in self.h.calls() if c.startswith("--start")]), 1)
        self.h.log.unlink()
        self.h.running.touch()
        self.h.run("watch")
        self.assertFalse([c for c in self.h.calls() if c.startswith("--start")])
        self.h.running.unlink()
        self.h.busy.touch()
        self.h.run("watch")
        self.assertFalse([c for c in self.h.calls() if c.startswith("--start")])

    def test_watch_honours_manual_stop_and_absent_state(self) -> None:
        self.assertEqual(self.h.run("watch").returncode, 0)  # no state dir yet
        self.assertEqual(self.h.calls(), [])
        self.h.run("stop")
        self.h.log.unlink()
        self.h.run("watch")
        self.assertEqual(self.h.calls(), [])

    def test_status_exit_codes(self) -> None:
        self.assertEqual(self.h.run("status").returncode, 3)
        self.h.running.touch()
        self.assertEqual(self.h.run("status").returncode, 0)

    def test_bad_verb_and_lsb_header(self) -> None:
        self.assertEqual(self.h.run("bogus").returncode, 2)
        text = SCRIPT.read_text()
        self.assertIn("# Provides:          hermes-dashboard", text)
        self.assertNotIn("openrc-run", text)

    def test_no_secrets_or_addresses_in_artifacts(self) -> None:
        for path in (SCRIPT, CRON):
            text = path.read_text()
            self.assertNotIn(".hermes/", text)
            for needle in ("token", "password", "100.", "secret", "api_key"):
                self.assertNotIn(needle, text.lower(), (path, needle))

    def test_cron_probe_runs_as_root_every_five_minutes(self) -> None:
        self.assertIn("*/5 * * * * root /etc/init.d/hermes-dashboard watch", CRON.read_text())


if __name__ == "__main__":
    unittest.main()
