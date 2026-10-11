#!/usr/bin/env python3
"""Cross-host Claude wake fixtures: no SSH, live sessions, or private config."""
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import tempfile
import types
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[5]
BIN = ROOT / "all/.local/bin"


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class ClaudeWakeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, MAILCORTEX_ROOT=str(self.base / "Mail"),
                                  MAILCORTEX_RUNTIME=str(self.base / "state"))
        self.env.start()
        self.addCleanup(self.env.stop)
        self.w = load("fixture_watcher", BIN / "mailcortex-seat-watcher")
        self.c = load("fixture_claude", BIN / "mailcortex_claude.py")
        self.record = {"host": "fixture-host", "mailbox": "consorts/worker",
                       "harness": "claude", "transport": "claude-ssh",
                       "rate_limit_seconds": 120, "coalesce_seconds": 2,
                       "ssh_target": "YOUR_SSH_ALIAS", "remote_user": "YOUR_AGENT_USER",
                       "claude_target": {"tmux_socket": "/tmp/YOUR_TMUX_SOCKET",
                                         "tmux_session": "YOUR_TMUX_SESSION",
                                         "runtime_dir": "/run/YOUR_RUNTIME"}}
        self.registry = {"schema": "mailcortex.seats.v1", "host": "fixture-host",
                         "seats": {"worker": self.record}}
        self.mailbox = self.base / "Mail/consorts/worker"
        for leaf in ("new", "cur", "tmp"):
            (self.mailbox / leaf).mkdir(parents=True)
        self.owner = {"channel": "claude-" + "a" * 32, "session_id": "b" * 32,
                      "supervisor_pid": 123, "epoch": 1, "pane_id": "%1", "pane_tty": "/dev/pts/1"}

    def mail(self, n):
        m = EmailMessage()
        m["Message-ID"] = f"<m{n}@fixture.helm>"
        m["From"] = "sender@fixture.helm"
        m["To"] = "worker@fixture.helm"
        m.set_content("untrusted body must never enter terminal input")
        (self.mailbox / "new" / str(n)).write_bytes(m.as_bytes())

    def receipt(self, n):
        return self.w.MAILCORTEX.load_receipt("worker", f"<m{n}@fixture.helm>")

    def adapter(self, status="idle", delivery="accepted"):
        def runner(argv, **kw):
            request = json.loads(kw["input"])
            value = {"protocol": self.c.PROTOCOL, "target": request["target"],
                     "request_id": request["request_id"], "status": status if request["operation"] == "status" else delivery,
                     "owner": self.owner}
            return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")
        return self.c.ClaudeSSHAdapter(self.w, runner=mock.Mock(side_effect=runner))

    def test_registry_accepts_exact_claude_target(self):
        p = self.base / "registry.json"
        p.write_text(json.dumps(self.registry)); p.chmod(0o600)
        self.assertEqual(self.w.load_registry(p, "fixture-host"), self.registry)

    def test_registry_rejects_unsafe_identity_and_unbounded_timing(self):
        p = self.base / "registry.json"
        for field, value in (("ssh_target", "-oProxyCommand=bad"), ("remote_user", "user;bad"),
                             ("rate_limit_seconds", 0), ("rate_limit_seconds", float("nan")),
                             ("coalesce_seconds", -1), ("harness", "codex")):
            with self.subTest(field=field, value=value):
                r = dict(self.record); r[field] = value
                p.write_text(json.dumps(dict(self.registry, seats={"worker": r}))); p.chmod(0o600)
                with self.assertRaises(self.w.WatcherError):
                    self.w.load_registry(p, "fixture-host")

    def test_short_wake_never_pastes_mail_content(self):
        self.mail(1)
        prompt = self.w.wake_prompt(self.record, self.mailbox / "new/1")
        self.assertLess(len(prompt), 400)
        self.assertIn("/inbox", prompt)
        self.assertNotIn("untrusted body", prompt)
        self.assertNotIn("return the final", prompt)

    def test_burst_is_coalesced_and_restart_does_not_repeat(self):
        for n in range(3): self.mail(n)
        a = self.adapter()
        self.assertEqual(self.w.locked_scan(self.registry, a, now=10), 0)
        self.assertEqual(a.runner.call_count, 0)
        self.assertEqual(self.w.locked_scan(self.registry, a, now=12), 1)
        self.assertEqual(a.runner.call_count, 2)
        self.assertTrue(all(self.receipt(n)["wake_state"] == "injected" for n in range(3)))
        self.assertEqual(self.w.locked_scan(self.registry, self.adapter(), now=200), 0)

    def test_busy_then_idle_preserves_all_mail(self):
        self.mail(1)
        self.w.locked_scan(self.registry, self.adapter(), now=10)
        self.assertEqual(self.w.locked_scan(self.registry, self.adapter(status="busy"), now=12), 0)
        self.assertEqual(self.receipt(1)["wake_state"], "queued")
        self.assertEqual(self.w.locked_scan(self.registry, self.adapter(), now=14), 1)
        self.assertTrue((self.mailbox / "new/1").exists())
        self.assertIsNone(self.receipt(1)["handling_state"])

    def test_new_burst_waits_for_rate_limit(self):
        self.mail(1); a = self.adapter()
        self.w.locked_scan(self.registry, a, now=10)
        self.w.locked_scan(self.registry, a, now=12)
        self.mail(2)
        self.assertEqual(self.w.locked_scan(self.registry, a, now=15), 0)
        self.assertEqual(self.w.locked_scan(self.registry, a, now=131), 0)
        self.assertEqual(self.w.locked_scan(self.registry, a, now=132), 1)

    def test_busy_at_admission_is_queued_and_can_retry(self):
        self.mail(1)
        self.w.locked_scan(self.registry, self.adapter(), now=10)
        self.assertEqual(self.w.locked_scan(self.registry, self.adapter(delivery="busy"), now=12), 0)
        self.assertEqual(self.receipt(1)["wake_state"], "queued")
        self.assertEqual(self.w.locked_scan(self.registry, self.adapter(), now=14), 1)

    def test_lost_ack_marks_entire_batch_unknown_without_resend(self):
        self.mail(1); self.mail(2)
        a = self.adapter()
        self.w.locked_scan(self.registry, a, now=10)
        a.runner.side_effect = [subprocess.CompletedProcess([], 0, json.dumps({
            "protocol": self.c.PROTOCOL, "target": self.record["claude_target"],
            "request_id": "ignored", "status": "idle", "owner": self.owner}), "")]
        # A runner that can answer status, then loses the delivery ACK.
        def lost(argv, **kw):
            r = json.loads(kw["input"])
            if r["operation"] == "admit": raise subprocess.TimeoutExpired(argv, 20)
            return subprocess.CompletedProcess(argv, 0, json.dumps(dict(
                protocol=self.c.PROTOCOL, target=r["target"], request_id=r["request_id"],
                status="idle", owner=self.owner)), "")
        a.runner.side_effect = lost
        self.assertEqual(self.w.locked_scan(self.registry, a, now=12), 0)
        self.assertEqual(self.receipt(1)["wake_state"], "delivery_unknown")
        self.assertEqual(self.receipt(2)["wake_state"], "delivery_unknown")
        self.assertEqual(self.w.locked_scan(self.registry, self.adapter(), now=300), 0)

    def test_transport_uses_bounded_publickey_ssh_and_json_stdin(self):
        a = self.adapter(); target = a.resolve_idle_pane(self.record)
        a.deliver(self.record, target, "short wake")
        argv = a.runner.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/ssh")
        for option in ("BatchMode=yes", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                       "PreferredAuthentications=publickey", "ConnectTimeout=10", "ConnectionAttempts=1"):
            self.assertIn(option, argv)
        self.assertNotIn("short wake", " ".join(argv))
        self.assertLessEqual(a.runner.call_args.kwargs["timeout"], 30)

    def test_old_or_wrong_authority_cannot_inject(self):
        a = self.adapter()
        for value in ({"ok": True}, {"protocol": "old", "status": "idle"}):
            a.runner.return_value = subprocess.CompletedProcess([], 0, json.dumps(value), "")
            a.runner.side_effect = None
            with self.assertRaises(self.w.WatcherError): a.resolve_idle_pane(self.record)

    def test_owner_gate_refuses_mid_turn_permission_and_old_typed_input(self):
        o = self.fake_owner()
        for field, value in (("status", "active"), ("screen_state", "blocked"),
                             ("screen_state", "unknown"), ("last_local_input", 11),
                             ("compacting", True), ("recovery_pending", True),
                             ("transcript_gate_blocked", True), ("lifecycle_health", "missing")):
            with self.subTest(field=field):
                setattr(o, field, value)
                with mock.patch.object(self.c, "pending_terminal", return_value=False):
                    self.assertEqual(self.c.owner_control(o, self.request(), self.fake_warm())["status"], "busy")
                setattr(o, field, getattr(self.fake_owner(), field))

    def fake_warm(self):
        return types.SimpleNamespace(now=lambda: 1000, write_all=mock.Mock())

    def fake_owner(self):
        return types.SimpleNamespace(channel=self.owner["channel"], session_id=self.owner["session_id"],
            completed_turn_epoch=1, status="idle", screen_state="idle", last_normal_stop=10,
            last_local_input=None, last_lifecycle_activity=10, lifecycle_health="wired", compacting=False,
            recovery_pending=False, recovery_awaiting=False, transcript_gate_blocked=False,
            transcript_quiescence_deadline=None, transcript_partial=b"", master_fd=99,
            stdin_eof=False, input_classifier=types.SimpleNamespace(pending=bytearray()),
            _gate_reason=lambda purpose: None, _write_state=mock.Mock(), timer_generation=0,
            _guard_log=mock.Mock(), _record_transcript_activity=mock.Mock())

    def request(self):
        return {"kind": "control", "command": "mailcortex-admit", "channel": self.owner["channel"],
                "protocol": self.c.PROTOCOL, "request_id": "c" * 32, "owner": self.owner,
                "target": self.record["claude_target"], "text": "short wake"}

    def test_owner_claims_before_pty_write_and_second_wake_is_busy(self):
        o = self.fake_owner(); w = self.fake_warm()
        w.write_all.side_effect = lambda fd, data: self.assertEqual(o.status, "active")
        with mock.patch.object(self.c, "owner_matches", return_value=True), \
             mock.patch.object(self.c, "pending_terminal", return_value=False):
            self.assertEqual(self.c.owner_control(o, self.request(), w)["status"], "accepted")
            self.assertEqual(self.c.owner_control(o, self.request(), w)["status"], "busy")
        w.write_all.assert_called_once_with(99, b"short wake\r")

    def test_owner_refuses_pending_terminal_and_wrong_epoch(self):
        o = self.fake_owner()
        with mock.patch.object(self.c, "owner_matches", return_value=True), \
             mock.patch.object(self.c, "pending_terminal", return_value=True):
            self.assertEqual(self.c.owner_control(o, self.request(), self.fake_warm())["status"], "busy")
        with mock.patch.object(self.c, "owner_matches", return_value=False):
            self.assertEqual(self.c.owner_control(o, self.request(), self.fake_warm())["status"], "unavailable")

    def test_remote_helper_refuses_ambiguous_panes_and_different_owner(self):
        request = {"protocol": self.c.PROTOCOL, "request_id": "c" * 32,
                   "operation": "status", "target": self.record["claude_target"]}
        with mock.patch.object(self.c, "resolve_owner", side_effect=RuntimeError("unsafe")):
            self.assertEqual(self.c.remote_request(request)["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
