#!/usr/bin/env python3
"""Cross-host Claude wake fixtures: no SSH, live sessions, or private config."""
import importlib.machinery
import importlib.util
import json
import os
import shutil
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
                      "supervisor_pid": 123, "supervisor_start_time": "12345", "epoch": 1, "pane_id": "%1", "pane_tty": "/dev/pts/1"}

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

    def test_unknown_attempt_also_rate_limits_new_mail(self):
        self.mail(1)
        self.w.MAILCORTEX.write_wake_receipt("worker", "<m1@fixture.helm>", "delivery_unknown",
                                            wake_updated_at=10)
        self.mail(2); a = self.adapter()
        self.w.locked_scan(self.registry, a, now=20)
        self.assertEqual(self.w.locked_scan(self.registry, a, now=22), 0)
        self.assertEqual(a.runner.call_count, 0)
        self.assertEqual(self.w.locked_scan(self.registry, a, now=130), 1)
        self.assertEqual(self.receipt(1)["wake_state"], "delivery_unknown")

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
                             ("transcript_gate_blocked", True), ("lifecycle_health", "missing"), ("mailcortex_input_dirty", True)):
            with self.subTest(field=field):
                setattr(o, field, value)
                with mock.patch.object(self.c, "pending_terminal", return_value=False), \
                     mock.patch.object(self.c, "owner_matches", return_value=True):
                    self.assertEqual(self.c.owner_control(o, self.request(), self.fake_warm())["status"], "busy")
                setattr(o, field, getattr(self.fake_owner(), field))

    def fake_warm(self):
        return types.SimpleNamespace(now=lambda: 1000, write_all=mock.Mock())

    def fake_owner(self):
        import contextlib
        import threading
        return types.SimpleNamespace(channel=self.owner["channel"], session_id=self.owner["session_id"],
            mailcortex_admission_lock=threading.RLock(), mailcortex_start_time="12345",
            _mailcortex_barrier=contextlib.nullcontext, _mailcortex_refresh_screen=lambda: False,
            completed_turn_epoch=1, status="idle", screen_state="idle", last_normal_stop=10,
            last_local_input=None, last_lifecycle_activity=10, lifecycle_health="wired", compacting=False,
            recovery_pending=False, recovery_awaiting=False, transcript_gate_blocked=False,
            transcript_quiescence_deadline=None, transcript_partial=b"", master_fd=99,
            stdin_eof=False, mailcortex_input_dirty=False,
            input_classifier=types.SimpleNamespace(buffer=bytearray(), in_bracketed_paste=False),
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

    def test_remote_roundtrip_rechecks_exact_owner_and_keeps_lost_ipc_unknown(self):
        r = {"protocol": self.c.PROTOCOL, "request_id": "c" * 32, "operation": "admit",
             "target": self.record["claude_target"], "owner": self.owner, "text": "short wake"}
        with mock.patch.object(self.c, "resolve_owner", return_value=(self.owner, self.base / "socket")), \
             mock.patch.object(self.c, "socket_request", return_value=dict(
                 protocol=self.c.PROTOCOL, request_id=r["request_id"], owner=self.owner, status="accepted")) as ipc:
            self.assertEqual(self.c.remote_request(r)["status"], "accepted")
            self.assertEqual(ipc.call_args.args[1]["command"], "mailcortex-admit")
            r["owner"] = dict(self.owner, epoch=2)
            self.assertEqual(self.c.remote_request(r)["status"], "unavailable")
            self.assertEqual(ipc.call_count, 1)
            r["owner"] = self.owner
            ipc.side_effect = OSError("lost acknowledgement")
            self.assertEqual(self.c.remote_request(r)["status"], "unknown")

    def test_partial_pty_write_keeps_owner_claim_unknown(self):
        o = self.fake_owner(); warm = self.fake_warm()
        warm.write_all.side_effect = OSError("partial write")
        with mock.patch.object(self.c, "owner_matches", return_value=True), \
             mock.patch.object(self.c, "pending_terminal", return_value=False):
            self.assertEqual(self.c.owner_control(o, self.request(), warm)["status"], "unknown")
            self.assertEqual(o.status, "active")
            self.assertEqual(self.c.owner_control(o, self.request(), warm)["status"], "busy")

    def test_resolve_owner_binds_private_runtime_to_exact_single_tmux_pane(self):
        import socket
        target = dict(self.record["claude_target"], tmux_socket=str(self.short_dir("sock") / "s"),
                      runtime_dir=str(self.short_dir("rt")))
        root = Path(target["runtime_dir"]) / "claude-idle-compaction" / self.owner["channel"]
        root.mkdir(parents=True)
        root.chmod(0o700); root.parent.chmod(0o700)
        control = root / "control.sock"
        with socket.socket(socket.AF_UNIX) as tmux, socket.socket(socket.AF_UNIX) as ipc:
            tmux.bind(target["tmux_socket"]); os.chmod(target["tmux_socket"], 0o660)
            ipc.bind(str(control)); control.chmod(0o600)
            state = root / "state.json"
            state.write_text(json.dumps(dict(self.owner, supervisor_pid=os.getpid(),
                supervisor_start_time=self.c.process_start_time(os.getpid()),
                completed_turn_epoch=1, control_socket=str(control))))
            state.chmod(0o600)
            row = f"YOUR_TMUX_SESSION\t%1\t{os.getpid()}\t/dev/pts/1\t0\t0\n"
            result = subprocess.CompletedProcess([], 0, row, "")
            with mock.patch.object(self.c.subprocess, "run", return_value=result) as run:
                owner, path = self.c.resolve_owner(target)
                self.assertEqual(path, control)
                self.assertEqual(owner["supervisor_pid"], os.getpid())
                self.assertIn("=YOUR_TMUX_SESSION", run.call_args.args[0])
                for bad in (row + row, row.replace("\t0\t0", "\t0\t1"), row.replace("YOUR_TMUX_SESSION", "other")):
                    result.stdout = bad
                    with self.assertRaises(ValueError): self.c.resolve_owner(target)
                result.stdout = row
                state.chmod(0o644)
                with self.assertRaises(ValueError): self.c.resolve_owner(target)

    def test_tmux_socket_permissions_require_a_real_private_parent(self):
        import socket
        directory = self.short_dir("sock")
        path = directory / "s"
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(path))
            for mode in (0o600, 0o660, 0o770):
                with self.subTest(socket_mode=oct(mode)):
                    path.chmod(mode)
                    self.c.private_tmux_socket(path)
            for mode in (0o601, 0o602, 0o604, 0o667):
                with self.subTest(socket_mode=oct(mode)):
                    path.chmod(mode)
                    with self.assertRaises(ValueError): self.c.private_tmux_socket(path)
            path.chmod(0o660)
            for mode in (0o710, 0o720, 0o740, 0o701, 0o702, 0o704, 0o750, 0o770, 0o755, 0o1700, 0o600):
                with self.subTest(parent_mode=oct(mode)):
                    directory.chmod(mode)
                    with self.assertRaises((ValueError, OSError)): self.c.private_tmux_socket(path)
            directory.chmod(0o700)
            link = self.base / 'linked-parent'
            link.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(ValueError): self.c.private_tmux_socket(link / path.name)
            socket_link = directory / 'linked-socket'
            socket_link.symlink_to(path)
            with self.assertRaises(ValueError): self.c.private_tmux_socket(socket_link)
            ordinary = directory / 'ordinary'
            ordinary.write_text('fixture'); ordinary.chmod(0o600)
            with self.assertRaises(ValueError): self.c.private_tmux_socket(ordinary)
            with self.assertRaises((ValueError, OSError)): self.c.private_tmux_socket(ordinary / 's')
            # The exception is only for tmux; control sockets stay owner-only.
            import stat
            with self.assertRaises(ValueError): self.c.private_path(path, stat.S_ISSOCK)

    def test_tmux_socket_and_parent_foreign_owners_refuse(self):
        import socket
        directory = self.short_dir("sock")
        path = directory / "s"
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(path)); path.chmod(0o660)
            original = Path.lstat
            for foreign in (path, directory):
                def lstat(candidate):
                    value = original(candidate)
                    return types.SimpleNamespace(st_mode=value.st_mode,
                        st_uid=value.st_uid + 1 if candidate == foreign else value.st_uid)
                with self.subTest(foreign=foreign.name), mock.patch.object(Path, 'lstat', lstat):
                    with self.assertRaises(ValueError): self.c.private_tmux_socket(path)

    def test_fresh_idle_boundary_preserves_every_admission_gate(self):
        fresh = self.fake_owner()
        fresh.completed_turn_epoch = 0
        fresh.last_normal_stop = None
        fresh.mailcortex_startup_idle_at = 10
        gates = (("status", "starting"), ("status", "active"),
                 ("screen_state", "blocked"), ("screen_state", "unknown"),
                 ("lifecycle_health", "missing"), ("compacting", True),
                 ("recovery_pending", True), ("recovery_awaiting", True),
                 ("mailcortex_input_dirty", True), ("transcript_gate_blocked", True),
                 ("transcript_partial", b'{'), ("transcript_quiescence_deadline", 20),
                 ("last_local_input", 10), ("last_lifecycle_activity", 11),
                 ("completed_turn_epoch", 1), ("mailcortex_startup_idle_at", None))
        for field, value in gates:
            with self.subTest(field=field, value=value):
                previous = getattr(fresh, field)
                setattr(fresh, field, value)
                warm = self.fake_warm()
                with mock.patch.object(self.c, 'owner_matches', return_value=True), \
                     mock.patch.object(self.c, 'pending_terminal', return_value=False):
                    self.assertEqual(self.c.owner_control(fresh, self.request(), warm)['status'], 'busy')
                warm.write_all.assert_not_called()
                setattr(fresh, field, previous)
        warm = self.fake_warm()
        with mock.patch.object(self.c, 'owner_matches', return_value=True), \
             mock.patch.object(self.c, 'pending_terminal', return_value=True):
            self.assertEqual(self.c.owner_control(fresh, self.request(), warm)['status'], 'busy')
        warm.write_all.assert_not_called()
        fresh._gate_reason = lambda purpose: 'session-disabled'
        self.assertTrue(self.c.admission_busy(fresh))

    def test_status_failure_and_bad_claude_mail_do_not_block_other_seats(self):
        self.mail(1)
        mailbox = self.base / "Mail/seats/other"
        for leaf in ("new", "cur", "tmp"): (mailbox / leaf).mkdir(parents=True)
        (mailbox / "new/one").write_bytes((self.mailbox / "new/1").read_bytes())
        local = dict(host="fixture-host", mailbox="seats/other", harness="codex", transport="herdr",
                     herdr_target="local", herdr_session="local", rate_limit_seconds=0)
        registry = dict(self.registry, seats={"worker": self.record, "other": local})
        fallback = mock.Mock()
        fallback.resolve_idle_pane.return_value = "wT:p1"
        a = self.adapter()
        a.runner.side_effect = OSError("ssh unavailable")
        factory = types.SimpleNamespace(for_record=lambda r: a if r["transport"] == "claude-ssh" else fallback)
        self.w.locked_scan(self.registry, a, now=10)
        self.assertEqual(self.w.locked_scan(registry, factory, now=12), 1)
        self.assertEqual(self.receipt(1)["wake_state"], "queued")
        (self.mailbox / "new/bad").write_text("malformed")
        self.assertEqual(self.w.locked_scan(registry, factory, now=14), 0)

    def test_permission_appearing_between_check_and_write_never_gets_input(self):
        import contextlib
        o = self.fake_owner(); warm = self.fake_warm()
        @contextlib.contextmanager
        def barrier():
            # The child emits a permission prompt after the initial poll.
            self.assertTrue(o.mailcortex_admission_lock._is_owned())
            o.screen_state = "blocked"
            yield
        o._mailcortex_barrier = barrier
        with mock.patch.object(self.c, "owner_matches", return_value=True), \
             mock.patch.object(self.c, "pending_terminal", return_value=False):
            self.assertEqual(self.c.owner_control(o, self.request(), warm)["status"], "busy")
        warm.write_all.assert_not_called()
        self.assertEqual(o.status, "idle")

    def test_human_typing_during_admission_never_gets_a_wake(self):
        import contextlib
        o = self.fake_owner(); warm = self.fake_warm()
        @contextlib.contextmanager
        def barrier():
            o.mailcortex_input_dirty = True
            yield
        o._mailcortex_barrier = barrier
        with mock.patch.object(self.c, "owner_matches", return_value=True), \
             mock.patch.object(self.c, "pending_terminal", return_value=False):
            self.assertEqual(self.c.owner_control(o, self.request(), warm)["status"], "busy")
        warm.write_all.assert_not_called()

    def test_admission_rereads_screen_instead_of_cached_idle(self):
        o = self.fake_owner(); warm = self.fake_warm()
        o._mailcortex_refresh_screen = lambda: setattr(o, "screen_state", "blocked")
        with mock.patch.object(self.c, "owner_matches", return_value=True), \
             mock.patch.object(self.c, "pending_terminal", return_value=False):
            self.assertEqual(self.c.owner_control(o, self.request(), warm)["status"], "busy")
        warm.write_all.assert_not_called()

    def test_missing_or_failed_barrier_fails_closed(self):
        o = self.fake_owner(); warm = self.fake_warm()
        o._mailcortex_barrier = mock.Mock(side_effect=OSError("cannot stop child"))
        with mock.patch.object(self.c, "owner_matches", return_value=True), \
             mock.patch.object(self.c, "pending_terminal", return_value=False):
            self.assertEqual(self.c.owner_control(o, self.request(), warm)["status"], "unavailable")
        warm.write_all.assert_not_called()

    def test_owner_instance_is_rechecked_at_write(self):
        o = self.fake_owner(); warm = self.fake_warm()
        with mock.patch.object(self.c, "owner_matches", side_effect=[True, False]), \
             mock.patch.object(self.c, "pending_terminal", return_value=False):
            self.assertEqual(self.c.owner_control(o, self.request(), warm)["status"], "unavailable")
        warm.write_all.assert_not_called()

    def test_owner_requires_process_start_time(self):
        self.assertFalse(self.c.valid_owner({k:v for k,v in self.owner.items() if k != "supervisor_start_time"}))
        expected = dict(self.owner, supervisor_pid=os.getpid(),
                        supervisor_start_time="wrong", pane_tty="/dev/pts/1")
        with mock.patch.object(self.c.os, "ttyname", return_value="/dev/pts/1"), \
             mock.patch.dict(os.environ, TMUX_PANE="%1"):
            self.assertFalse(self.c.owner_matches(self.fake_owner(), expected))

    def test_crash_after_injecting_is_recovered_and_alerted_without_retry(self):
        self.mail(1); self.mail(2)
        a = self.adapter()
        self.w.locked_scan(self.registry, a, now=10)
        a.deliver = mock.Mock(side_effect=SystemExit("watcher killed"))
        with self.assertRaises(SystemExit):
            self.w.locked_scan(self.registry, a, now=12)
        self.assertEqual(self.receipt(1)["wake_state"], "injecting")
        restarted = self.adapter()
        with mock.patch.object(self.w, "report_error") as alert:
            self.assertEqual(self.w.locked_scan(self.registry, restarted, now=15), 0)
            self.assertEqual(alert.call_count, 2)
        for n in (1, 2):
            receipt = self.receipt(n)
            self.assertEqual(receipt["wake_state"], "delivery_unknown")
            self.assertEqual(receipt["reason"], "interrupted_attempt")
            self.assertIn("attempt_id", receipt)
            self.assertIn("attempt_start_time", receipt)
        self.assertEqual(restarted.runner.call_count, 0)
        with mock.patch.object(self.w, "report_error") as alert:
            self.w.locked_scan(self.registry, restarted, now=300)
            alert.assert_not_called()

    def test_legacy_injecting_without_mail_is_also_recovered(self):
        self.w.MAILCORTEX.write_wake_receipt("worker", "<m1@fixture.helm>", "injecting",
                                            wake_updated_at=10)
        with mock.patch.object(self.w, "report_error") as alert:
            self.w.locked_scan(self.registry, self.adapter(), now=12)
            alert.assert_called_once()
        self.assertEqual(self.receipt(1)["wake_state"], "delivery_unknown")

    def test_malformed_message_is_quarantined_and_valid_same_seat_continues(self):
        (self.mailbox / "new/0bad").write_text("not a valid message")
        self.mail(1); a = self.adapter()
        with mock.patch.object(self.w, "report_error") as alert:
            self.w.locked_scan(self.registry, a, now=10)
            alert.assert_called_once()
        self.assertFalse((self.mailbox / "new/0bad").exists())
        quarantined = list((self.mailbox / "quarantine").iterdir())
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0].read_text(), "not a valid message")
        diagnostics = list((self.base / "state/rejected/worker").glob("*.json"))
        self.assertEqual(len(diagnostics), 1)
        rejected = json.loads(diagnostics[0].read_text())
        self.assertEqual(rejected["filename"], "0bad")
        self.assertEqual(rejected["first_seen_at"], 10)
        self.assertEqual(rejected["state"], "quarantined")
        self.assertEqual(self.w.locked_scan(self.registry, a, now=12), 1)
        self.assertEqual(self.receipt(1)["wake_state"], "injected")

    def test_disabled_launcher_execs_original_with_exact_argv_and_environment(self):
        args = ["--resume", "saved-session", "--control", "state"]
        for flag in (None, "0", "false"):
            with self.subTest(flag=flag), mock.patch.dict(os.environ, clear=True):
                os.environ["PATH"] = "/usr/bin:/bin"
                os.environ["FIXTURE_ENV"] = "preserved"
                if flag is not None: os.environ["MAILCORTEX_CLAUDE_WAKE"] = flag
                before = dict(os.environ)
                with mock.patch.object(self.c.os, "execv", side_effect=SystemExit) as execute:
                    with self.assertRaises(SystemExit): self.c.launch(args)
                original = str(BIN / "claude-warm")
                execute.assert_called_once_with(original, [original, *args])
                self.assertEqual(dict(os.environ), before)

    def test_disabled_launcher_help_control_and_failure_match_original(self):
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.base),
               "XDG_RUNTIME_DIR": str(self.base / "runtime"),
               "CLAUDE_IDLE_REAL_EXECUTABLE": str(self.base / "missing-executable"),
               "MAILCORTEX_CLAUDE_WAKE": "0"}
        for args in (["--help"], ["--control", "unsupported"], ["--resume", "saved-session"]):
            results = [subprocess.run([str(BIN / name), *args], env=env, capture_output=True,
                                      timeout=8) for name in ("claude-warm", "mailcortex-claude-warm")]
            self.assertEqual([(r.returncode, r.stdout, r.stderr) for r in results[:1]],
                             [(r.returncode, r.stdout, r.stderr) for r in results[1:]])

    def short_dir(self, leaf):
        """AF_UNIX sockets cap at 108 bytes; sandbox tempdirs can exceed that.
        Runtime/socket dirs go under /tmp with short randomized names."""
        # Budget: AF_UNIX caps at 108 bytes; claude-warm adds
        # /claude-idle-compaction/claude-<32hex>/control.sock (~76 bytes)
        # under XDG_RUNTIME_DIR, so the leaf path must stay under ~30.
        import secrets
        path = Path("/tmp") / f"mw{os.getpid()}-{secrets.token_hex(2)}-{leaf}"
        path.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
        return path

    def start_pty(self, admission_race=False, fresh=False, startup_screen="❯ ", expected_status="idle"):
        import pty
        import select
        import time
        runtime = self.short_dir("rt")
        home = Path(tempfile.mkdtemp(dir=self.base, prefix="pty-home-"))
        fake = self.base / "fake-claude"
        fake.write_text("#!/usr/bin/env python3\nimport os,sys,signal\n"
                        "signal.signal(signal.SIGUSR1, lambda *a: print('Do you want to proceed?', flush=True))\n"
                        "signal.signal(signal.SIGUSR2, lambda *a: print(" + repr(startup_screen) + ", flush=True))\n"
                        "print('\\u276f ', flush=True)\n"
                        "for line in sys.stdin: print('RECEIVED:' + line.strip(), flush=True)\n")
        fake.chmod(0o755)
        master, slave = pty.openpty()
        tty = os.ttyname(slave)
        env = dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(runtime), MAILCORTEX_CLAUDE_WAKE='1',
                   XDG_STATE_HOME=str(self.short_dir("st")), TMUX_PANE='%1',
                   CLAUDE_IDLE_REAL_EXECUTABLE=str(fake), CLAUDE_IDLE_CACHE_PROFILE='short',
                   CLAUDE_SHORT_CACHE_IDLE_COMPACT_SECONDS='600', CLAUDE_IDLE_WATCHED_SERVERS='',
                   CLAUDE_IDLE_COMPACT_TRANSCRIPT_QUIESCENCE_SECONDS='1')
        # Explicit allowlist: no credentials, interactive hooks, or real session endpoints.
        env = {k:v for k,v in env.items() if k in {'MAILCORTEX_CLAUDE_WAKE','PATH','HOME','XDG_RUNTIME_DIR','XDG_STATE_HOME','TMUX_PANE',
                'CLAUDE_IDLE_REAL_EXECUTABLE','CLAUDE_IDLE_CACHE_PROFILE',
                'CLAUDE_SHORT_CACHE_IDLE_COMPACT_SECONDS','CLAUDE_IDLE_WATCHED_SERVERS',
                'CLAUDE_IDLE_COMPACT_TRANSCRIPT_QUIESCENCE_SECONDS'}}
        launcher = BIN / 'mailcortex-claude-warm'
        if admission_race:
            # Force a real permission screen precisely after the cached idle check,
            # before the actual kernel barrier. No production timing hook is added.
            launcher = self.base / 'race-launcher'
            launcher.write_text("#!/usr/bin/env python3\n"
                "import contextlib,os,select,signal,sys\n"
                "sys.path.insert(0," + repr(str(BIN)) + ")\n"
                "import mailcortex_claude as c\n"
                "original=c.paused_child\n"
                "@contextlib.contextmanager\n"
                "def raced(owner):\n"
                " os.kill(owner.pid,signal.SIGUSR1)\n"
                " assert select.select([owner.master_fd],[],[],2)[0]\n"
                " with original(owner): yield\n"
                "c.paused_child=raced\n"
                "raise SystemExit(c.launch(sys.argv[1:]))\n")
            launcher.chmod(0o755)
        process = subprocess.Popen([str(launcher)], stdin=slave,
                                   stdout=slave, stderr=slave, env=env, start_new_session=True)
        os.close(slave)
        output = bytearray()
        def cleanup():
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=2)
            os.close(master)
        self.addCleanup(cleanup)
        def drain(duration=0.05):
            until = time.monotonic() + duration
            while time.monotonic() < until:
                ready, _, _ = select.select([master], [], [], max(0, until-time.monotonic()))
                if ready:
                    try: output.extend(os.read(master, 65536))
                    except OSError: break
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            paths = list(runtime.glob('claude-idle-compaction/claude-*/state.json'))
            drain()
            if paths and b'\xe2\x9d\xaf' in output: break
            if process.poll() is not None: self.fail(output.decode(errors='replace'))
        self.assertTrue(paths, output.decode(errors='replace'))
        path = paths[0]
        state = json.loads(path.read_text())
        control = Path(state['control_socket'])
        transcript = home / 'transcript.jsonl'; transcript.write_text('')
        sid = 'b' * 32
        def event(name):
            return self.c.socket_request(control, dict(kind='event', channel=state['channel'],
                event=name, session_id=sid, transcript_path=str(transcript), stop_hook_active=False))
        self.assertTrue(event('session-start')['ok'])
        if not fresh:
            self.assertTrue(event('stop')['ok'])
        import signal
        os.kill(state['pid'], signal.SIGUSR2)
        owner = dict(self.owner, channel=state['channel'], session_id=sid,
                     supervisor_pid=process.pid, supervisor_start_time=state["supervisor_start_time"], epoch=0 if fresh else 1, pane_tty=tty)
        request = dict(self.request(), channel=state['channel'], owner=owner)
        # Status requests omit the admission-only text field.
        def status():
            r = dict(request, command='mailcortex-status'); r.pop('text')
            return self.c.socket_request(control, r)
        while time.monotonic() < deadline:
            drain()
            if status()['status'] == expected_status: break
        self.assertEqual(status()['status'], expected_status, output.decode(errors='replace'))
        return control, request, event, master, output, drain, path

    def test_real_pty_fresh_idle_seat_admits_without_a_stop(self):
        control, request, event, master, output, drain, path = self.start_pty(fresh=True)
        state = json.loads(path.read_text())
        self.assertEqual(state['completed_turn_epoch'], 0)
        self.assertIsNone(state['last_normal_stop'])
        self.assertFalse(state['dirty'])
        self.assertIsNone(state['timer_deadline'])
        self.assertIsNotNone(state['mailcortex_startup_idle_at'])
        # Startup readiness is exclusively a mail boundary. Neither native
        # compaction nor other manual injections may borrow it.
        for command in ('trigger', 'inject'):
            response = self.c.socket_request(control, dict(kind='control',
                channel=state['channel'], command=command, text='/reload-plugins'))
            self.assertFalse(response['ok'])
            self.assertEqual(response['state']['last_gate_rejection_reason'], 'no-normal-stop')
        self.assertEqual(self.c.socket_request(control, request)['status'], 'accepted')
        drain(0.2)
        self.assertIn(b'RECEIVED:short wake', output)
        self.assertEqual(self.c.socket_request(control, request)['status'], 'busy')

    def test_real_pty_fresh_startup_notice_or_prompt_gets_no_wake(self):
        for screen in ('Starting Claude; please wait',
                       'WARNING: Loading development channels\n❯ ',
                       'WARNING: Loading development channels\nEnter to confirm\n❯ ',
                       'Do you want to proceed?\n❯ ', '❯ unfinished draft',
                       '✻ Working…', 'Select a startup option\n❯ Continue'):
            with self.subTest(screen=screen):
                control, request, event, master, output, drain, path = self.start_pty(
                    fresh=True, startup_screen=screen, expected_status='busy')
                drain(0.2)
                self.assertEqual(self.c.socket_request(control, request)['status'], 'busy')
                self.assertNotIn(b'RECEIVED:short wake', output)
                self.assertEqual(json.loads(path.read_text())['completed_turn_epoch'], 0)

    def test_real_pty_fresh_activity_cannot_borrow_startup_idle(self):
        for activity in ('user-prompt-submit', 'session-activity', 'typing',
                         'user-record', 'assistant-record', 'malformed-record', 'partial-record'):
            with self.subTest(activity=activity):
                control, request, event, master, output, drain, path = self.start_pty(fresh=True)
                state = json.loads(path.read_text())
                if activity in ('user-prompt-submit', 'session-activity'):
                    self.assertTrue(event(activity)['ok'])
                elif activity == 'typing':
                    os.write(master, b'half typed')
                else:
                    payload = {'user-record': '{"type":"user"}\n',
                               'assistant-record': '{"type":"assistant"}\n',
                               'malformed-record': '{bad-json}\n',
                               'partial-record': '{"type":'}[activity]
                    with Path(state['transcript_path']).open('a') as stream:
                        stream.write(payload)
                drain(0.2)
                self.assertEqual(self.c.socket_request(control, request)['status'], 'busy')
                self.assertNotIn(b'RECEIVED:short wake', output)

    def test_real_pty_fresh_permission_between_check_and_write_gets_no_wake(self):
        control, request, event, master, output, drain, path = self.start_pty(
            admission_race=True, fresh=True)
        self.assertEqual(self.c.socket_request(control, request)['status'], 'busy')
        drain(0.2)
        self.assertIn(b'Do you want to proceed?', output)
        self.assertNotIn(b'RECEIVED:', output)
        self.assertNotIn(b'short wake', output)

    def test_real_pty_owner_admits_once_without_terminal_typing(self):
        control, request, event, master, output, drain, path = self.start_pty()
        self.assertEqual(self.c.socket_request(control, request)['status'], 'accepted')
        drain(0.2)
        self.assertIn(b'RECEIVED:short wake', output)
        self.assertEqual(self.c.socket_request(control, request)['status'], 'busy')

    def test_real_pty_permission_between_idle_check_and_write_gets_no_wake(self):
        control, request, event, master, output, drain, path = self.start_pty(admission_race=True)
        self.assertEqual(self.c.socket_request(control, request)['status'], 'busy')
        drain(0.2)
        self.assertIn(b'Do you want to proceed?', output)
        self.assertNotIn(b'RECEIVED:', output)
        self.assertNotIn(b'short wake', output)
        self.assertEqual(json.loads(path.read_text())['status'], 'idle')

    def test_barrier_resumes_fake_child_when_supervisor_is_killed(self):
        import signal
        import time
        child = subprocess.Popen(['/usr/bin/python3', '-c', 'import time; time.sleep(20)'])
        self.addCleanup(lambda: (os.kill(child.pid, signal.SIGCONT), child.terminate(), child.wait(timeout=3)))
        ready = self.base / 'barrier-ready'
        # A disposable supervisor fixture, never the user's supervisor.
        script = self.base / 'crash-owner.py'
        script.write_text('import sys,time,types\nfrom pathlib import Path\n'
            + 'sys.path.insert(0,' + repr(str(BIN)) + ')\nimport mailcortex_claude as c\n'
            + 'owner=types.SimpleNamespace(pid=' + str(child.pid) + ',_pty_still_owned=lambda:True)\n'
            + 'with c.paused_child(owner):\n Path(' + repr(str(ready)) + ').touch()\n time.sleep(20)\n')
        supervisor = subprocess.Popen(['/usr/bin/python3', str(script)])
        self.addCleanup(lambda: (supervisor.kill() if supervisor.poll() is None else None, supervisor.wait(timeout=3)))
        deadline = time.monotonic() + 3
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(ready.exists())
        stat_path = Path(f'/proc/{child.pid}/stat')
        self.assertEqual(stat_path.read_text().rsplit(')',1)[1].split()[0], 'T')
        supervisor.kill(); supervisor.wait(timeout=3)
        while stat_path.read_text().rsplit(')',1)[1].split()[0] == 'T' and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertNotEqual(stat_path.read_text().rsplit(')',1)[1].split()[0], 'T')

    def test_real_pty_permission_screen_refuses(self):
        import signal
        control, request, event, master, output, drain, path = self.start_pty()
        state = json.loads(path.read_text())
        os.kill(state['pid'], signal.SIGUSR1)
        drain(0.2)
        self.assertEqual(self.c.socket_request(control, request)['status'], 'busy')
        self.assertNotIn(b'RECEIVED:short wake', output)

    def test_real_pty_stop_does_not_erase_half_typed_input(self):
        control, request, event, master, output, drain, path = self.start_pty()
        self.assertTrue(event('user-prompt-submit')['ok'])
        os.write(master, b'half typed')
        drain(0.2)
        self.assertTrue(event('stop')['ok'])
        request['owner']['epoch'] = 2
        drain(1.3)
        self.assertEqual(self.c.socket_request(control, request)['status'], 'busy')
        self.assertNotIn(b'RECEIVED:short wake', output)


if __name__ == "__main__":
    unittest.main()
