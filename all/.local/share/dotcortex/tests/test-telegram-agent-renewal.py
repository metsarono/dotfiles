"""Hermetic renewal protocol tests: fake ownership, manager, time and ledger."""
from __future__ import annotations

import argparse
from contextlib import closing
import copy
import datetime as dt
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
FIXTURE_SCRIPT = HERE / "generated/all/.local/bin/telegram-agent-watchdog"
INSTALLED_SCRIPT = HERE.parents[2] / "bin/telegram-agent-watchdog"
SCRIPT = Path(os.environ.get("RENEW_WATCHDOG_SCRIPT", str(FIXTURE_SCRIPT if FIXTURE_SCRIPT.exists() else INSTALLED_SCRIPT)))
loader = SourceFileLoader("renew_watchdog", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
w = importlib.util.module_from_spec(spec)
loader.exec_module(w)


class OwnerProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        scripts = self.root/"fixture/FORGE/scripts"
        scripts.mkdir(parents=True)
        self.supervisor = str(scripts/"codex_supervisor.py")
        self.adapter = str(scripts/"codex_telegram.py")
        self.args = argparse.Namespace(pid_dir=str(self.root/"pids"), codex_supervisor=self.supervisor)
        Path(self.args.pid_dir).mkdir()
        Path(self.supervisor).write_text("fixture supervisor\n")
        Path(self.adapter).write_text("fixture adapter\n")
        (Path(self.args.pid_dir)/"codex-helmastra-telegram.pid").write_text("10")
        (Path(self.args.pid_dir)/"codex-helmastra-telegram.child.ready").write_text("11")
        patcher = patch.object(w, "PROC_ROOT", self.root/"proc")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.proc(10, 1, 100, self.args.codex_supervisor)
        self.proc(11, 10, 110, self.adapter)

    def proc(self, pid, parent, start, script):
        root = w.PROC_ROOT/str(pid)
        root.mkdir(parents=True, exist_ok=True)
        fields = ["S", str(parent)] + ["0"]*17 + [str(start)]
        (root/"stat").write_text(str(pid) + " (fake ) command) " + " ".join(fields))
        (root/"cmdline").write_bytes(b"python3\0" + os.fsencode(script) + b"\0")

    def test_exact_parent_child_uid_and_kernel_start_prove_owner(self):
        self.assertEqual(w.codex_owner(self.args, "11:110"),
            {"generation":"10:100", "adapter":"11:110", "uid":os.getuid()})

    def test_live_supervisor_source_is_resolved_without_launcher_path_guessing(self):
        self.args.codex_supervisor = None
        self.assertEqual(w.codex_owner(self.args, "11:110"),
            {"generation":"10:100", "adapter":"11:110", "uid":os.getuid()})

    def test_configured_supervisor_must_match_live_process(self):
        self.args.codex_supervisor = "/elsewhere/codex_supervisor.py"
        with self.assertRaises(ValueError):
            w.codex_owner(self.args, "11:110")

    def test_inherited_env_label_does_not_prove_wrapper(self):
        self.proc(10, 1, 100, "/arbitrary/codex_supervisor.py")
        with patch.dict(os.environ, {"TELEGRAM_AGENT_SELF":"codex"}), self.assertRaises(ValueError):
            w.codex_owner(self.args, "11:110")

    def test_child_of_different_parent_refused(self):
        self.proc(11, 99, 110, self.adapter)
        with self.assertRaises(ValueError):
            w.codex_owner(self.args, "11:110")

    def test_reused_adapter_pid_with_different_start_refused(self):
        self.proc(11, 10, 999, self.adapter)
        with self.assertRaises(ValueError):
            w.codex_owner(self.args, "11:110")

    def test_start_changed_during_inspection_refused(self):
        real = w.process_identity
        count = {10:0}
        def inspect(pid):
            if pid == 10:
                count[10] += 1
                if count[10] == 2:
                    self.proc(10, 1, 999, self.args.codex_supervisor)
            return real(pid)
        with patch.object(w, "process_identity", side_effect=inspect), self.assertRaises(ValueError):
            w.codex_owner(self.args, "11:110")

    def test_other_uid_process_refused(self):
        from types import SimpleNamespace
        with patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=os.getuid()+1)), self.assertRaises(ValueError):
            w.process_identity(10)

    def test_missing_owner_marker_does_not_prove_old_generation_absent(self):
        (Path(self.args.pid_dir)/"codex-helmastra-telegram.pid").unlink()
        self.assertIsNone(w.codex_owner(self.args))
        with self.assertRaises(ValueError):
            w.require_old_generation_absent({"generation":"10:100"})


class RenewalWatchdogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.adapter = self.root / "adapter"
        self.adapter.mkdir(mode=0o700)
        self.args = w.parse_args(["--expected-host", "fixture", "--state-dir", str(self.root / "watchdog"),
            "--adapter-state-dir", str(self.adapter), "--pid-dir", str(self.root / "pids"),
            "--intent-dir", str(self.root / "intent"), "--codex-supervisor", "/fixture/FORGE/scripts/codex_supervisor.py",
            "--manager", "fake-manager", "--backoff", "5"])
        self.old_owner = {"generation": "10:100", "adapter": "11:110", "uid": os.getuid()}
        self.new_owner = {"generation": "20:200", "adapter": "21:210", "uid": os.getuid()}
        self.owner = copy.deepcopy(self.old_owner)
        self.request = {"schema": w.REQUEST_SCHEMA, "mode": "renew", "id": "a" * 32,
            "agent": "codex", **self.old_owner, "task_id": 1, "old_thread_id": "old-thread",
            "requester_pid": 9999, "requested_at": 1000, "self_requested": True}
        self.path = Path(self.args.state_dir) / "requests/codex.json"
        self.put(self.path, self.request)
        self.state = {"schema": w.STATE_SCHEMA, "agents": {}}
        self.calls = []
        self.manager_start_result = 0
        self.manager_status_up = True
        self.publish_resumed = True
        self.auto_stop_absent = True
        self.ready = {"schema": "codex.telegram.renew-ready.v1", "request_id": self.request["id"],
            **self.old_owner, "old_thread_id": "old-thread", "new_thread_id": "new-thread",
            "transaction_id": "b" * 32, "seed_sha256": hashlib.sha256(b"seed content").hexdigest(),
            "task_id": 1, "admission_holding": True, "quiescent": True, "ready_at": 1001}
        self.receipt = {"id": "b" * 32, "phase": "committed", "external_request": copy.deepcopy(self.request),
            "old_thread_id": "old-thread", "candidate_thread_id": "new-thread", "seed": "seed content",
            "seed_sha256": self.ready["seed_sha256"], "previous_state": {"thread_id": "old-thread"}}
        self.put(self.adapter / "sessions.json", {"7": {"thread_id": "new-thread", "renewal": self.receipt}})
        db = self.adapter / "tasks.sqlite3"
        with closing(sqlite3.connect(db)) as c, c:
            c.execute("CREATE TABLE tasks (task_id INTEGER PRIMARY KEY, chat_id INTEGER, message_id INTEGER, status TEXT, delivered INTEGER)")
            c.execute("INSERT INTO tasks VALUES (1,7,100,'succeeded',1)")
            c.execute("INSERT INTO tasks VALUES (2,7,101,'accepted',0)")
        db.chmod(0o600)
        self.addCleanup(patch.stopall)
        patch.object(w, "codex_owner", side_effect=lambda *a, **kw: copy.deepcopy(self.owner)).start()
        def old_process(pid):
            if pid == 10 and self.owner is not None and self.owner["generation"] == "10:100":
                return "10:100", 1, []
            raise FileNotFoundError("fake process absent")
        patch.object(w,"process_identity",side_effect=old_process).start()
        patch.object(w, "run_manager", side_effect=self.manager).start()
        # Any unexpected subprocess or network attempt is an immediate failure.
        patch.object(subprocess, "run", side_effect=AssertionError("unmocked subprocess forbidden")).start()

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def manager(self, executable, args, timeout):
        self.assertEqual(executable, "fake-manager")
        self.calls.append(tuple(args))
        if args == ["stop", "codex"]:
            if self.auto_stop_absent:
                self.owner = None
            return subprocess.CompletedProcess(args, 0, "stopped")
        if args == ["start", "codex"]:
            if self.manager_start_result == 0:
                self.owner = copy.deepcopy(self.new_owner)
                if self.publish_resumed:
                    self.put(self.adapter / "renew-resumed.json", {
                        "schema": "codex.telegram.renew-resumed.v1", "request_id": self.request["id"],
                        **self.new_owner, "old_generation": self.request["generation"],
                        "new_thread_id": "new-thread", "transaction_id": "b" * 32, "admission_holding": True})
            return subprocess.CompletedProcess(args, self.manager_start_result, "fixture start")
        if args == ["status"]:
            return subprocess.CompletedProcess(args, 0, "  codex-helmastra: " + ("RUNNING" if self.manager_status_up else "STOPPED"))
        raise AssertionError(args)

    def run_once(self, now=1002):
        return w.process_requests(self.args, "fixture", self.state, dt.datetime.fromtimestamp(now, dt.timezone.utc), now)

    def publish_ready(self, **fields):
        self.put(self.adapter / "renew-ready.json", dict(self.ready, **fields))

    def accept_release(self):
        release = json.loads((self.adapter/"renew-release.json").read_text())
        ack = {**release, "schema":"codex.telegram.renew-released.v1", "admission_holding":False}
        state = json.loads((self.adapter/"sessions.json").read_text())
        state["7"]["renewal"]["released_at"] = 1003
        self.put(self.adapter/"sessions.json", state)
        self.put(self.adapter/"renew-released.json", ack)

    def journal(self):
        return json.loads((Path(self.args.state_dir) / "renewals" / (self.request["id"] + ".json")).read_text())

    def set_task(self, status, delivered):
        with closing(sqlite3.connect(self.adapter / "tasks.sqlite3")) as c, c:
            c.execute("UPDATE tasks SET status=?, delivered=? WHERE task_id=1", (status, delivered))

    def assert_no_bounce(self):
        self.assertEqual(self.calls, [])
        self.assertTrue(self.path.exists())
        self.assertFalse((self.adapter / "renew-release.json").exists())

    def test_missing_ready_waits_even_if_requester_shell_has_exited(self):
        self.assertEqual(self.run_once(), [])
        self.assert_no_bounce()

    def test_requester_shell_liveness_is_not_used_as_readiness(self):
        self.publish_ready()
        with patch.object(w, "pid_alive", side_effect=AssertionError("shell pid is not a gate")):
            events = self.run_once()
        self.assertEqual(events[0]["kind"], "renew_pending")
        self.assertEqual(self.journal()["phase"], "release-issued")

    def test_active_source_task_prevents_restart(self):
        self.publish_ready()
        self.set_task("running", 0)
        events = self.run_once()
        self.assertIn("active or undelivered", events[0]["body"])
        self.assert_no_bounce()

    def test_completed_but_undelivered_result_prevents_restart(self):
        self.publish_ready()
        self.set_task("succeeded", 0)
        self.run_once()
        self.assert_no_bounce()

    def test_other_running_or_undelivered_task_prevents_restart(self):
        for status in ("running", "succeeded"):
            with self.subTest(status=status):
                with closing(sqlite3.connect(self.adapter / "tasks.sqlite3")) as c, c:
                    c.execute("UPDATE tasks SET status=?, delivered=0 WHERE task_id=2", (status,))
                self.publish_ready()
                self.run_once()
                self.assert_no_bounce()

    def test_stale_or_mismatched_ready_fields_prevent_restart(self):
        for key, bad in {"request_id":"c" * 32, "generation":"10:999", "uid":os.getuid()+1,
            "task_id":2, "old_thread_id":"different", "new_thread_id":"different",
            "transaction_id":"c"*32, "seed_sha256":"bad", "admission_holding":False,
            "quiescent":False}.items():
            with self.subTest(field=key):
                self.publish_ready(**{key:bad})
                self.run_once()
                self.assert_no_bounce()

    def test_live_owner_generation_must_match_ready(self):
        self.publish_ready()
        self.owner["generation"] = "10:999"
        self.run_once()
        self.assert_no_bounce()

    def test_private_ready_receipt_is_required(self):
        self.publish_ready()
        (self.adapter / "renew-ready.json").chmod(0o644)
        self.run_once()
        self.assert_no_bounce()

    def test_unverified_or_changed_candidate_pin_prevents_restart(self):
        self.publish_ready()
        state = json.loads((self.adapter / "sessions.json").read_text())
        state["7"]["thread_id"] = "old-thread"
        self.put(self.adapter / "sessions.json", state)
        self.run_once()
        self.assert_no_bounce()

    def test_seed_tampering_prevents_restart(self):
        self.publish_ready()
        state = json.loads((self.adapter / "sessions.json").read_text())
        state["7"]["renewal"]["seed"] = "changed"
        self.put(self.adapter / "sessions.json", state)
        self.run_once()
        self.assert_no_bounce()

    def test_seeded_commit_bounce_resume_release_is_once_only_and_keeps_pending(self):
        self.publish_ready()
        events = self.run_once()
        self.assertEqual(events[0]["kind"], "renew_pending")
        self.assertEqual(self.calls, [("stop","codex"),("start","codex"),("status",)])
        release = json.loads((self.adapter / "renew-release.json").read_text())
        self.assertEqual(release, {"schema":"codex.telegram.renew-release.v1", "request_id":self.request["id"],
            **self.new_owner, "old_generation":"10:100", "new_thread_id":"new-thread", "transaction_id":"b"*32})
        self.assertEqual(self.journal()["phase"], "release-issued")
        self.assertTrue(self.path.exists())
        self.accept_release()
        self.assertEqual(self.run_once(now=1003)[0]["kind"], "renew_done")
        self.assertEqual(self.journal()["phase"], "released")
        self.assertEqual(w.renew_cooldown(self.args),1003)
        self.assertFalse(self.path.exists())
        with closing(sqlite3.connect(self.adapter / "tasks.sqlite3")) as c:
            self.assertEqual(c.execute("SELECT status FROM tasks WHERE task_id=2").fetchone()[0], "accepted")
        self.put(self.path, self.request)  # crash after release, before queue removal
        self.assertEqual(self.run_once(), [])
        self.assertEqual(len(self.calls), 3)

    def test_adapter_replacement_same_supervisor_can_reproject_ready(self):
        self.owner["adapter"] = "12:120"
        self.publish_ready(adapter="12:120")
        self.assertEqual(self.run_once()[0]["kind"], "renew_pending")
        self.accept_release()
        self.assertEqual(self.run_once(now=1003)[0]["kind"], "renew_done")

    def test_successor_receipt_mismatch_never_releases_or_bounces_twice(self):
        self.publish_ready()
        self.publish_resumed = False
        self.run_once()
        self.assertTrue(self.path.exists())
        self.put(self.adapter / "renew-resumed.json", {"schema":"codex.telegram.renew-resumed.v1",
            "request_id":self.request["id"], **self.new_owner, "old_generation":"10:100",
            "new_thread_id":"wrong", "transaction_id":"b"*32, "admission_holding":True})
        self.run_once()
        self.assertEqual(self.calls, [("stop","codex"),("start","codex")])
        self.assertFalse((self.adapter / "renew-release.json").exists())

    def test_successor_waits_for_manager_readiness_before_release(self):
        self.publish_ready()
        self.manager_status_up = False
        self.assertEqual(self.run_once()[0]["kind"], "renew_pending")
        self.assertTrue(self.path.exists())
        self.manager_status_up = True
        self.assertEqual(self.run_once(now=1003)[0]["kind"], "renew_pending")
        self.accept_release()
        self.assertEqual(self.run_once(now=1004)[0]["kind"], "renew_done")
        self.assertEqual(self.calls.count(("stop","codex")), 1)

    def test_failed_start_retries_manager_only_without_repeating_stop(self):
        self.publish_ready()
        self.manager_start_result = 1
        self.assertEqual(self.run_once()[0]["kind"], "renew_pending")
        self.assertEqual(self.journal()["phase"], "start-retry")
        self.assertEqual(self.run_once(now=1003), [])
        self.manager_start_result = 0
        self.assertEqual(self.run_once(now=1008)[0]["kind"], "renew_pending")
        self.accept_release()
        self.assertEqual(self.run_once(now=1009)[0]["kind"], "renew_done")
        self.assertEqual(self.calls, [("stop","codex"),("start","codex"),("start","codex"),("status",)])

    def test_stop_intent_is_durable_before_effect_and_crash_never_repeats_stop(self):
        self.publish_ready()
        def interrupted_manager(executable, args, timeout):
            self.assertEqual(args, ["stop", "codex"])
            self.assertEqual(self.journal()["phase"], "stop-intent")
            raise OSError("simulated watchdog crash at stop")
        with patch.object(w, "run_manager", side_effect=interrupted_manager):
            self.assertEqual(self.run_once()[0]["kind"], "renew_recovery_required")
        self.assertEqual(self.journal()["phase"], "stop-intent")
        events = self.run_once(now=1003)
        self.assertEqual(events[0]["kind"], "renew_recovery_required")
        self.assertEqual(self.journal()["phase"], "recovery-required")
        self.assertEqual(self.calls, [])

    def test_post_stop_crash_observes_absent_owner_and_starts_once(self):
        self.publish_ready()
        journal = {"schema":w.RENEW_JOURNAL_SCHEMA, "request_id":self.request["id"],
            "phase":"stop-intent", "new_thread_id":"new-thread", "transaction_id":"b"*32,
            "seed_sha256":self.ready["seed_sha256"], "attempts":0, "updated_at":1001}
        self.put(Path(self.args.state_dir)/"renewals"/(self.request["id"]+".json"), journal)
        self.owner = None
        self.assertEqual(self.run_once()[0]["kind"], "renew_pending")
        self.accept_release()
        self.assertEqual(self.run_once(now=1003)[0]["kind"], "renew_done")
        self.assertEqual(self.calls, [("start","codex"),("status",)])

    def test_committed_missing_ready_timeout_keeps_queue_and_surfaces_recovery(self):
        events = self.run_once(now=2000)
        self.assertEqual(events[0]["kind"], "renew_pending")
        self.assertEqual(self.journal()["phase"], "waiting-ready")
        self.assert_no_bounce()

    def test_uncommitted_missing_ready_timeout_retains_until_failure_ack(self):
        self.put(self.adapter/"sessions.json", {"7":{"thread_id":"old-thread"}})
        events = self.run_once(now=2000)
        self.assertEqual(events[0]["kind"], "renew_pending")
        self.assertTrue(self.path.exists())
        self.assertEqual(self.calls, [])

    def test_adapter_precommit_refusal_is_consumed_without_restart(self):
        self.put(self.adapter/"sessions.json", {"7":{"thread_id":"old-thread"}})
        self.put(self.adapter/"renew-failed.json", {"schema":"codex.telegram.renew-failed.v1",
            "request_id":self.request["id"], "old_thread_id":"old-thread", "reason":"quota held"})
        self.assertEqual(self.run_once()[0]["kind"], "renew_rejected")
        self.assertFalse(self.path.exists())
        self.assertEqual(self.calls, [])

    def test_matching_failure_cannot_abandon_committed_pin(self):
        self.put(self.adapter/"renew-failed.json", {"schema":"codex.telegram.renew-failed.v1",
            "request_id":self.request["id"], "old_thread_id":"old-thread", "reason":"stale failure"})
        self.assertEqual(self.run_once()[0]["kind"], "renew_recovery_required")
        self.assert_no_bounce()

    def test_late_ready_after_timeout_can_complete_without_losing_queue(self):
        self.assertEqual(self.run_once(now=2000)[0]["kind"], "renew_pending")
        self.assertEqual(self.run_once(now=2001), [])  # persisted notice dedup
        self.publish_ready()
        self.assertEqual(self.run_once(now=2002)[0]["kind"], "renew_pending")
        self.accept_release()
        self.assertEqual(self.run_once(now=2003)[0]["kind"], "renew_done")
        self.assertEqual(self.calls.count(("stop","codex")), 1)

    def test_no_done_before_release_ack_and_timeout_never_rebounces(self):
        self.publish_ready()
        self.assertEqual(self.run_once()[0]["kind"], "renew_pending")
        self.assertTrue(self.path.exists())
        self.assertEqual(self.run_once(now=2000)[0]["kind"], "renew_pending")
        self.assertEqual(self.run_once(now=2001), [])
        self.assertEqual(self.journal()["phase"], "release-issued")
        self.assertEqual(self.calls, [("stop","codex"),("start","codex"),("status",)])

    def test_release_ack_requires_persisted_release_and_exact_live_identity(self):
        self.publish_ready()
        self.run_once()
        self.accept_release()
        ack = json.loads((self.adapter/"renew-released.json").read_text())
        for key, value in {"request_id":"c"*32,"adapter":"21:999","new_thread_id":"wrong",
            "transaction_id":"c"*32,"admission_holding":True}.items():
            with self.subTest(field=key):
                self.put(self.adapter/"renew-released.json", {**ack,key:value})
                self.run_once(now=1003)
                self.assertTrue(self.path.exists())
        self.put(self.adapter/"renew-released.json", ack)
        state = json.loads((self.adapter/"sessions.json").read_text())
        state["7"]["renewal"].pop("released_at")
        self.put(self.adapter/"sessions.json", state)
        self.run_once(now=1004)
        self.assertTrue(self.path.exists())

    def test_pending_task_may_run_after_accepted_release_before_watchdog_ack_check(self):
        self.publish_ready()
        self.run_once()
        self.accept_release()
        with closing(sqlite3.connect(self.adapter/"tasks.sqlite3")) as c, c:
            c.execute("UPDATE tasks SET status='running' WHERE task_id=2")
        self.assertEqual(self.run_once(now=1003)[0]["kind"], "renew_done")

    def test_release_publish_crash_recovers_without_requiring_pre_release_idle(self):
        self.publish_ready()
        original = w.renew_journal_write
        def interrupted(path, payload):
            original(path, payload)
            if path == self.adapter/"renew-release.json":
                self.assertEqual(self.journal()["phase"], "release-intent")
                raise OSError("simulated post-publication sync ambiguity")
        with patch.object(w,"renew_journal_write",side_effect=interrupted):
            self.assertEqual(self.run_once()[0]["kind"], "renew_recovery_required")
        self.accept_release()
        with closing(sqlite3.connect(self.adapter/"tasks.sqlite3")) as c, c:
            c.execute("UPDATE tasks SET status='running' WHERE task_id=2")
        self.assertEqual(self.run_once(now=1003)[0]["kind"], "renew_done")
        self.assertEqual(self.calls.count(("stop","codex")), 1)

    def test_nested_malformed_session_receipt_fails_closed(self):
        self.publish_ready()
        for bad in ([],None,"bad"):
            with self.subTest(value=bad):
                self.put(self.adapter/"sessions.json", {"7":{"thread_id":"new-thread","renewal":bad}})
                self.run_once()
                self.assert_no_bounce()

    def test_missing_marker_during_stopped_recovery_cannot_start_over_live_old_generation(self):
        self.publish_ready()
        self.manager_start_result = 1
        self.run_once()
        self.owner = None  # pid marker gone, but old /proc generation survives
        with patch.object(w,"process_identity",return_value=("10:100",1,[])):
            events = self.run_once(now=1008)
        self.assertEqual(events[0]["kind"],"renew_recovery_required")
        self.assertEqual(self.journal()["phase"],"recovery-required")
        self.assertEqual(self.calls,[("stop","codex"),("start","codex")])

    def test_first_journal_directory_and_parent_are_synced_before_return(self):
        path = Path(self.args.state_dir)/"renewals"/(self.request["id"]+".json")
        synced = []
        real = os.fsync
        def sync(fd):
            st = os.fstat(fd)
            synced.append((st.st_dev,st.st_ino))
            return real(fd)
        with patch.object(w.os,"fsync",side_effect=sync):
            w.renew_journal_write(path,{"phase":"stop-intent"})
        directories = [p.stat() for p in (path.parent,path.parent.parent)]
        self.assertEqual(synced[-2:],[(s.st_dev,s.st_ino) for s in directories])

    def test_source_task_in_other_chat_cannot_authorize_restart(self):
        self.publish_ready()
        with closing(sqlite3.connect(self.adapter/"tasks.sqlite3")) as c, c:
            c.execute("UPDATE tasks SET chat_id=99 WHERE task_id=1")
        self.assertEqual(self.run_once()[0]["kind"],"renew_recovery_required")
        self.assert_no_bounce()

    def test_dry_run_never_writes_journal_release_or_restarts(self):
        self.publish_ready()
        self.args.dry_run = True
        self.assertEqual(self.run_once(), [])
        self.assert_no_bounce()
        self.assertFalse((Path(self.args.state_dir)/"renewals").exists())

    def test_unsupported_harness_renew_never_falls_back_to_revive(self):
        self.request["agent"] = "ductor"
        self.put(self.path, self.request)
        self.assertEqual(self.run_once()[0]["kind"], "renew_recovery_required")
        self.assertEqual(self.calls, [])

    def request_cli(self, *extra):
        self.path.unlink(missing_ok=True)
        self.put(self.adapter/"renew-origin.json", {"schema":"codex.telegram.renew-origin.v1",
            **self.old_owner, "task_id":1, "old_thread_id":"old-thread"})
        with patch.object(w, "generation_of", return_value="10:100"):
            return w.request_main(["codex", "--renew", "--state-dir", self.args.state_dir,
                "--adapter-state-dir", self.args.adapter_state_dir, "--pid-dir", self.args.pid_dir,
                "--codex-supervisor", self.args.codex_supervisor, *extra])

    def test_request_cli_embeds_private_reviewed_seed_with_exact_hash(self):
        seed = self.root/"reviewed-seed.txt"
        seed.write_text("Scope, grants, pending tasks and continuity.")
        seed.chmod(0o600)
        digest = hashlib.sha256(seed.read_bytes()).hexdigest()
        self.assertEqual(self.request_cli("--seed-file", str(seed), "--seed-sha256", digest), 0)
        request = json.loads(self.path.read_text())
        self.assertEqual(request["continuity_seed"], seed.read_text())
        self.assertEqual(request["seed_sha256"], digest)
        self.assertEqual(request["seed_kind"], "operator-reviewed")
        self.assertNotIn("seed_file", request)
        self.assertNotIn("adapter_state_dir", request)

    def test_request_cli_refuses_public_symlink_oversized_or_hash_mismatched_seed(self):
        seed = self.root/"seed.txt"
        seed.write_text("reviewed")
        seed.chmod(0o600)
        digest = hashlib.sha256(seed.read_bytes()).hexdigest()
        self.assertEqual(self.request_cli("--seed-file", str(seed), "--seed-sha256", "wrong"), 2)
        seed.chmod(0o644)
        self.assertEqual(self.request_cli("--seed-file", str(seed), "--seed-sha256", digest), 2)
        seed.chmod(0o600)
        link = self.root/"seed-link"
        link.symlink_to(seed)
        self.assertEqual(self.request_cli("--seed-file", str(link), "--seed-sha256", digest), 2)
        seed.write_text("x"*(200*1024+1))
        self.assertEqual(self.request_cli("--seed-file", str(seed), "--seed-sha256", digest), 2)
        self.assertFalse(self.path.exists())

    def test_request_cli_refuses_unimplemented_renew_harness(self):
        self.path.unlink()
        self.assertEqual(w.request_main(["ductor", "--renew", "--state-dir", self.args.state_dir]), 2)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
