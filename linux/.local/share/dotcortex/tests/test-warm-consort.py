#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
BODY = ROOT / "linux/.local/share/dotcortex/openrc/warm-consort"
CONF = ROOT / "linux/.local/share/dotcortex/openrc/conf.d"

STUBS = r"""
ebegin() { :; }; eend() { return "${1:-0}"; }
einfo() { echo "INFO $*"; }; eerror() { echo "ERR $*"; }
checkpath() { echo "CHECKPATH $*"; }
hostname() { echo testhost; }
getent() {
    case "$2" in
        gille) echo "gille:x:1000:1000::$FAKE_HOME:/bin/sh" ;;
        agent-claude) echo "agent-claude:x:2002:2002::$FAKE_HOME:/bin/bash" ;;
        rooty) echo "rooty:x:0:0::$FAKE_HOME:/bin/sh" ;;
        *) return 2 ;;
    esac
}
su() { printf 'SU %s\n' "$*"; }
"""


class WarmConsortTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        (self.home / "metsatron-peer").mkdir(parents=True)
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def put_bin(self, rel: str) -> Path:
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexec sleep 30\n")
        path.chmod(0o755)
        return path

    def body(self, svc: str, script: str, conf: str = "") -> subprocess.CompletedProcess[str]:
        prog = f"{STUBS}\nFAKE_HOME='{self.home}'\nRC_SVCNAME='{svc}'\n{conf}\n. '{BODY}'\n{script}\n"
        return subprocess.run(["bash", "-c", prog], capture_output=True, text=True, timeout=30)

    def test_instance_derives_from_the_service_name(self) -> None:
        self.put_bin(".local/bin/claude-warm")
        out = self.body("claude-warm.agent-claude",
                        'warm_valid && echo "$warm_user|$warm_socket|$warm_session|$xdg|$warm_pidfile|$warm_log|$warm_log_mode|$warm_agent|$warm_bin"')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn(
            f"agent-claude|claude-warm|claude-warm|/run/claude-warm.agent-claude|"
            f"/run/claude-warm.agent-claude/claude-warm.agent-claude.pid|/var/log/claude-warm.agent-claude.log|0640|"
            f"testhost-claude-agent-claude|{self.home}/.local/bin/claude-warm", out.stdout)

    def test_unstowed_account_falls_back_to_its_checkout(self) -> None:
        bin_ = self.put_bin("DotCortex/all/.local/bin/codex-warm")
        out = self.body("codex-warm.agent-claude", 'warm_valid && echo "BIN $warm_bin"',
                        f"warm_checkout='{self.tmp.name}/none'")
        self.assertIn(f"BIN {bin_}", out.stdout)

    def test_unstowed_account_prefers_the_system_checkout(self) -> None:
        self.put_bin("DotCortex/all/.local/bin/claude-warm")
        lane = Path(self.tmp.name) / "system"
        sys_bin = lane / "all/.local/bin/claude-warm"
        sys_bin.parent.mkdir(parents=True)
        sys_bin.write_text("#!/bin/sh\nexec sleep 30\n")
        sys_bin.chmod(0o755)
        out = self.body("claude-warm.agent-claude", 'warm_valid && echo "BIN $warm_bin"', f"warm_checkout='{lane}'")
        self.assertIn(f"BIN {sys_bin}", out.stdout)

    def test_agent_reference_conf_keeps_the_herdr_name_and_needs_its_lane(self) -> None:
        conf = (CONF / "claude-warm.agent-claude").read_text()
        out = self.body("claude-warm.agent-claude", 'echo "$warm_user|$warm_agent|$warm_cwd"', conf)
        self.assertIn("agent-claude|honey-opus|/home/agent-claude/metsatron-peer", out.stdout)
        missing = f"{self.tmp.name}/no-lane"
        out = self.body("claude-warm.agent-claude", 'warm_valid; echo "RC=$?"', conf + f"\nwarm_cwd='{missing}'")
        self.assertIn("RC=1", out.stdout)
        self.assertIn(f"working dir {missing} missing", out.stdout)

    def test_bare_service_needs_conf(self) -> None:
        self.put_bin(".local/bin/claude-warm")
        out = self.body("claude-warm", "warm_valid; echo rc=$?")
        self.assertIn("rc=1", out.stdout)
        self.assertIn("no account", out.stdout)

    def test_compat_conf_reproduces_the_hand_written_scripts(self) -> None:
        self.put_bin(".local/bin/claude-warm")
        conf = (CONF / "claude-warm").read_text().replace("/home/gille", str(self.home))
        out = self.body("claude-warm", "start", conf)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        su = next(line for line in out.stdout.splitlines() if line.startswith("SU "))
        self.assertIn("-l gille", su)
        self.assertIn("XDG_RUNTIME_DIR='/run/warm'", su)
        self.assertIn(f"PATH='{self.home}/.local/bin:/usr/local/bin:/usr/bin:/bin'", su)
        self.assertIn("CLAUDE_WARM_HERDR_AGENT='honey-opus'", su)
        self.assertIn("tmux new-session -d -s 'warm'", su, "default socket, session warm")
        self.assertNotIn("-L", su)
        self.assertIn("echo $$ > /run/warm/claude-warm.pid; exec ", su)
        self.assertIn("--model claude-opus-4-8 >> /var/log/claude-warm.log", su)

    def test_codex_gets_no_claude_herdr_name(self) -> None:
        self.put_bin(".local/bin/codex-warm")
        conf = (CONF / "codex-warm").read_text().replace("/home/gille", str(self.home))
        out = self.body("codex-warm", "start", conf)
        su = next(line for line in out.stdout.splitlines() if line.startswith("SU "))
        self.assertNotIn("CLAUDE_WARM_HERDR_AGENT", su)
        self.assertIn("-s 'codex'", su)
        self.assertIn("echo $$ > /run/warm/codex-warm.pid", su)

    def test_instance_appends_to_the_login_path(self) -> None:
        self.put_bin(".local/bin/claude-warm")
        out = self.body("claude-warm.agent-claude", "start")
        su = next(line for line in out.stdout.splitlines() if line.startswith("SU "))
        self.assertIn('PATH="${PATH}:${HOME}/.local/bin"', su)
        self.assertIn("tmux -L 'claude-warm' new-session", su)

    def test_root_is_refused(self) -> None:
        self.put_bin(".local/bin/claude-warm")
        out = self.body("claude-warm.rooty", "warm_valid; echo rc=$?")
        self.assertIn("rc=1", out.stdout)
        self.assertIn("root", out.stdout)

    def test_unknown_account_and_kind_are_refused(self) -> None:
        self.assertIn("rc=1", self.body("claude-warm.nobody-here", "warm_valid; echo rc=$?").stdout)
        self.assertIn("rc=1", self.body("gemini-warm.gille", "warm_valid; echo rc=$?").stdout)

    def test_pid_file_names_one_supervisor_among_several(self) -> None:
        bin_ = self.put_bin(".local/bin/claude-warm")
        procs = [subprocess.Popen(["bash", "-c", f"exec -a '{bin_}' sleep 30"]) for _ in range(2)]
        try:
            time.sleep(0.2)
            pidfile = self.run_dir / "svc.pid"
            pidfile.write_text(f"{procs[1].pid}\n")
            conf = f"warm_user=gille\nwarm_pidfile='{pidfile}'"
            out = self.body("claude-warm", "warm_pid", conf)
            self.assertEqual(out.stdout.strip(), str(procs[1].pid))
            pidfile.write_text("999999\n")
            out = self.body("claude-warm", 'warm_pid; echo "rc=$?"', conf)
            self.assertEqual(out.stdout.strip(), "rc=1", "a stale pid file is not a running supervisor")
        finally:
            for p in procs:
                p.kill()
                p.wait()


if __name__ == "__main__":
    unittest.main()
