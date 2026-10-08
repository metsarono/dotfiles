#!/usr/bin/env python3
"""OpenCode OpenRC bodies and Honey instances (agents-bots-opencode-openrc.org)."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


LANE = Path(__file__).resolve().parents[1] / "opencode-openrc"

STUBS = r"""
ebegin() { :; }; eend() { return "${1:-0}"; }
einfo() { echo "INFO $*"; }; eerror() { echo "ERR $*"; }; ewarn() { echo "WARN $*"; }
checkpath() { echo "CHECKPATH $*"; }
getent() { [ "$2" = agent-opencode ] && echo "agent-opencode:x:2005:2005::/home/agent-opencode:/bin/bash"; }
use() { echo "USE $*"; }; need() { echo "NEED $*"; }; after() { echo "AFTER $*"; }
"""

SHOW = 'echo "CMD=$command|$command_args|$command_user|$pidfile|$output_log|$error_log|$directory|$HOME|$OPENCODE_TELEGRAM_HOME"; echo "PATH=$PATH"'


def run(body: str, conf: str, script: str, svc: str) -> subprocess.CompletedProcess[str]:
    prog = f"{STUBS}\nRC_SVCNAME='{svc}'\nPATH=/usr/bin:/bin\n{conf}\n. '{LANE / body}'\n{script}\n"
    return subprocess.run(["bash", "-c", prog], capture_output=True, text=True, timeout=30)


class OpencodeOpenrcTests(unittest.TestCase):
    def conf(self, name: str) -> str:
        return (LANE / "conf" / name).read_text()

    def test_serve_reproduces_the_hand_written_script(self) -> None:
        out = run("opencode-serve", self.conf("honey-opencode-serve"), SHOW, "honey-opencode-serve")
        self.assertIn("CMD=/home/agent-opencode/.local/bin/opencode|serve --hostname 127.0.0.1 --port 4096|"
                      "agent-opencode:agent-opencode|/run/honey-opencode-serve.pid|/var/log/honey-opencode-serve.log|"
                      "/var/log/honey-opencode-serve.log|/home/agent-opencode|/home/agent-opencode|", out.stdout)
        self.assertIn("PATH=/usr/bin:/bin:/home/agent-opencode/.local/bin:"
                      "/home/agent-opencode/.guix-extra-profiles/agent/agent/bin\n", out.stdout)

    def test_bot_reproduces_the_hand_written_script(self) -> None:
        out = run("opencode-telegram", self.conf("honey-opencode-bot"), SHOW + "; depend", "honey-opencode-bot")
        self.assertIn("CMD=/home/agent-opencode/.local/bin/opencode-telegram|start --mode installed|"
                      "agent-opencode:agent-opencode|/run/honey-opencode-bot.pid|/var/log/honey-opencode-bot.log|"
                      "/var/log/honey-opencode-bot.log|/home/agent-opencode|/home/agent-opencode|"
                      "/home/agent-opencode/.config/opencode-telegram-bot", out.stdout)
        self.assertIn("NEED honey-opencode-serve", out.stdout)
        self.assertIn("AFTER net honey-opencode-serve", out.stdout)

    def test_auth_file_is_parsed_not_sourced_and_password_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth = Path(tmp) / "auth.env"
            marker = Path(tmp) / "sourced"
            auth.write_text(f"touch {marker}\nOPENCODE_SERVER_USERNAME=u\nOPENCODE_SERVER_PASSWORD=\n")
            conf = self.conf("honey-opencode-serve") + f"\nopencode_auth_file='{auth}'\n"
            out = run("opencode-serve", conf, "start_pre; echo RC=$?", "honey-opencode-serve")
            self.assertIn("RC=1", out.stdout)
            self.assertIn("OPENCODE_SERVER_PASSWORD empty", out.stdout)
            self.assertFalse(marker.exists(), "the auth file was sourced")
            auth.write_text("OPENCODE_SERVER_PASSWORD=pw\n")
            out = run("opencode-serve", conf, 'start_pre; echo "RC=$? U=$OPENCODE_SERVER_USERNAME"', "honey-opencode-serve")
            self.assertIn("RC=0 U=opencode", out.stdout)

    def test_missing_settings_are_refused(self) -> None:
        out = run("opencode-serve", 'opencode_user="agent-opencode"', "start_pre; echo RC=$?", "x")
        self.assertIn("RC=1", out.stdout)
        out = run("opencode-telegram", 'opencode_user="agent-opencode"\nopencode_port="1"', "start_pre; echo RC=$?", "x")
        self.assertIn("RC=1", out.stdout)

    def test_patch_guard_runs_as_the_user_against_the_launchers_package(self) -> None:
        stub = 'setpriv() { echo "SETPRIV $*"; }\n'
        with tempfile.TemporaryDirectory() as tmp:
            guard = Path(tmp) / "FORGE/bin/opencode-telegram-patch-apply"
            guard.parent.mkdir(parents=True)
            guard.write_text("#!/bin/sh\n")
            guard.chmod(0o755)
            conf = self.conf("honey-opencode-bot") + f"\nopencode_patch_apply='{guard}'\nopencode_patch_root='{tmp}'\n"
            out = run("opencode-telegram", conf, stub + f'output_log="{tmp}/log"; apply_patches; echo RC=$?; cat "{tmp}/log"',
                      "honey-opencode-bot")
            self.assertIn("RC=0", out.stdout)
            self.assertIn("SETPRIV --reuid=agent-opencode --regid=agent-opencode --init-groups env -i "
                          f"HOME=/home/agent-opencode", out.stdout)
            self.assertIn(f"HELMCORTEX_ROOT={tmp} NPM_CONFIG_PREFIX=/home/agent-opencode/.local "
                          f"OPENCODE_TELEGRAM_BIN=/home/agent-opencode/.local/bin/opencode-telegram {guard}", out.stdout)
            refuse = 'setpriv() { return 1; }\n'
            out = run("opencode-telegram", conf, refuse + f'output_log="{tmp}/log"; apply_patches; echo RC=$?',
                      "honey-opencode-bot")
            self.assertIn("RC=1", out.stdout)
            self.assertIn("refused", out.stdout)
        out = run("opencode-telegram", self.conf("honey-opencode-bot") + "\nopencode_patch_apply=/nonexistent\n",
                  "apply_patches; echo RC=$?", "honey-opencode-bot")
        self.assertIn("RC=1", out.stdout)

    def test_patch_guard_is_off_unless_configured(self) -> None:
        out = run("opencode-telegram", 'opencode_user="agent-opencode"',
                  'setpriv() { echo CALLED; }; apply_patches; echo RC=$?', "x")
        self.assertIn("RC=0", out.stdout)
        self.assertNotIn("CALLED", out.stdout)

    def test_installer_dry_run_changes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            etc = Path(tmp)
            (etc / "init.d").mkdir()
            (etc / "conf.d").mkdir()
            (etc / "init.d/honey-opencode-bot").write_text("old\n")
            out = subprocess.run(["bash", str(LANE / "opencode-openrc-install"), "--dry-run", "honey-opencode-bot",
                                  "telegram", str(LANE / "conf/honey-opencode-bot")],
                                 env={"PATH": "/usr/bin:/bin", "OPENCODE_OPENRC_ETC": tmp},
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn(f"would: cp -p {etc}/init.d/honey-opencode-bot", out.stdout)
            self.assertIn(f"would: install -m 0644 -o root -g root {LANE}/conf/honey-opencode-bot {etc}/conf.d/honey-opencode-bot",
                          out.stdout)
            self.assertEqual((etc / "init.d/honey-opencode-bot").read_text(), "old\n")
            self.assertFalse((etc / "conf.d/honey-opencode-bot").exists())


if __name__ == "__main__":
    unittest.main()
