from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve()
WATCHDOG = HERE.parents[3] / "bin" / "telegram-agent-watchdog"
HOST = socket.gethostname()

FAKE_MANAGER = """#!/usr/bin/env bash
root="$FAKE_ROOT"
case "$1" in
  enabled) cat "$root/enabled" ;;
  status) cat "$root/status"; [ ! -f "$root/status_fail" ] || exit 1 ;;
  start) echo "$2" >> "$root/starts"; echo "start:$2" >> "$root/calls"; if [ -f "$root/start_fail" ]; then exit 1; fi
         [ ! -f "$root/status_after_start" ] || cp "$root/status_after_start" "$root/status" ;;
  stop) echo "stop:$2" >> "$root/calls"; [ ! -f "$root/stop_fail" ] || exit 1 ;;
  *) exit 2 ;;
esac
"""


FAKE_NURSE = """#!/usr/bin/env bash
root="$FAKE_ROOT"
case "$1" in
  status) if [ -f "$root/nurse_status_after_revive" ]; then cat "$root/nurse_status_after_revive"; else cat "$root/nurse_status"; fi ;;
  revive) printf '%s\\n' "$*" >> "$root/revive_args"; [ ! -f "$root/delay_nurse" ] || sleep 0.2; shift; for a in "$@"; do case "$a" in --*) ;; *) [ "$a" = "$(cat "$root/session_id" 2>/dev/null)" ] || echo "$a" >> "$root/revives" ;; esac; done ;;
  live-session) echo "$2 $3" >> "$root/live_checks"; if [ -f "$root/live_check_fail" ]; then exit 3; elif [ -f "$root/live_refusal" ]; then cat "$root/live_refusal"; else echo '{"live": false}'; fi ;;
  *) exit 2 ;;
esac
"""


FAKE_TMUX = """#!/usr/bin/env bash
if [ -f "$FAKE_ROOT/tmux_dead" ]; then echo "no server running on /tmp/tmux-1000/default" >&2; exit 1; fi
if [ -f "$FAKE_ROOT/tmux_broken" ]; then echo "some other failure" >&2; exit 1; fi
echo "Fable: 1 windows"
"""


class WatchdogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.manager = self.root / "manager"
        self.manager.write_text(FAKE_MANAGER)
        self.manager.chmod(self.manager.stat().st_mode | stat.S_IXUSR)
        (self.root / "enabled").write_text("ductor codex\n")
        self.set_status("RUNNING", "RUNNING")
        self.nurse = self.root / "nurse"
        self.nurse.write_text(FAKE_NURSE)
        self.nurse.chmod(self.nurse.stat().st_mode | stat.S_IXUSR)
        self.set_warm({})
        self.tmux = self.root / "tmux"
        self.tmux.write_text(FAKE_TMUX)
        self.tmux.chmod(self.tmux.stat().st_mode | stat.S_IXUSR)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def set_status(self, ductor: str, codex: str) -> None:
        (self.root / "status").write_text(
            "Host: x\nRunning processes:\n  ductor: %s\n  codex-helmastra (--telegram): %s\n" % (ductor, codex)
        )

    def run_watchdog(self, *extra: str, backoff: str = "0") -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(WATCHDOG), "--expected-host", HOST, "--manager", str(self.manager),
             "--state-dir", str(self.root / "state"), "--intent-dir", str(self.root / "intent"),
             "--boot-lock", str(self.root / "boot.lock"), "--spool", str(self.root / "spool"),
             "--pid-dir", str(self.root / "pids"), "--backoff", backoff,
             "--warm-file", str(self.root / "warm"), "--nurse", str(self.nurse), "--tmux", str(self.tmux), *extra],
            env=dict(os.environ, FAKE_ROOT=str(self.root), XDG_STATE_HOME=str(self.root / "xdg-state"),
                     XDG_RUNTIME_DIR=str(self.root / "xdg-runtime")), text=True, capture_output=True, timeout=30,
        )

    def starts(self) -> list[str]:
        path = self.root / "starts"
        return path.read_text().split() if path.exists() else []

    def events(self) -> list[dict]:
        return [json.loads(p.read_text()) for p in sorted((self.root / "spool").glob("*.json"))]

    def test_healthy_agents_are_left_alone(self) -> None:
        result = self.run_watchdog()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.starts(), [])
        self.assertEqual(self.events(), [])

    def test_down_agent_is_relaunched_and_alerted(self) -> None:
        self.set_status("RUNNING", "STOPPED")
        self.run_watchdog()
        self.assertEqual(self.starts(), ["codex"])
        self.assertEqual([e["kind"] for e in self.events()], ["down"])
        self.set_status("RUNNING", "RUNNING")
        self.run_watchdog()
        self.assertEqual([e["kind"] for e in self.events()], ["down", "recovered"])
        self.assertEqual(self.events()[1]["severity"], "notice")

    def test_operator_stop_marker_is_respected(self) -> None:
        (self.root / "intent").mkdir()
        (self.root / "intent" / "codex").write_text("")
        self.set_status("RUNNING", "STOPPED")
        self.run_watchdog()
        self.assertEqual(self.starts(), [])

    def test_disabled_agent_is_never_touched(self) -> None:
        (self.root / "enabled").write_text("ductor\n")
        self.set_status("RUNNING", "STOPPED")
        self.run_watchdog()
        self.assertEqual(self.starts(), [])

    def test_unreadable_status_never_relaunches(self) -> None:
        (self.root / "status").write_text("Host: x\nnothing useful here\n")
        self.run_watchdog()
        self.assertEqual(self.starts(), [])
        self.assertEqual({e["kind"] for e in self.events()}, {"probe_unknown"})

    def test_empty_status_output_never_relaunches(self) -> None:
        (self.root / "status").write_text("")
        (self.root / "status_fail").write_text("")
        self.run_watchdog()
        self.assertEqual(self.starts(), [])

    def test_status_lines_are_read_even_when_the_status_call_exits_nonzero(self) -> None:
        # The real host exits 1 when any agent is degraded; the other agents' lines still count.
        self.set_status("RUNNING", "STOPPED")
        (self.root / "status_fail").write_text("")
        self.run_watchdog()
        self.assertEqual(self.starts(), ["codex"])

    def test_attempt_cap_holds_and_alerts_once(self) -> None:
        self.set_status("RUNNING", "STOPPED")
        (self.root / "start_fail").write_text("")
        for _ in range(6):
            self.run_watchdog("--max-attempts", "2")
        self.assertEqual(self.starts(), ["codex", "codex"])
        kinds = [e["kind"] for e in self.events()]
        self.assertEqual(kinds.count("down"), 1)
        self.assertEqual(kinds.count("relaunch_failed"), 1)

    def test_backoff_blocks_immediate_retry(self) -> None:
        self.set_status("RUNNING", "STOPPED")
        (self.root / "start_fail").write_text("")
        self.run_watchdog(backoff="3600")
        self.run_watchdog(backoff="3600")
        self.assertEqual(self.starts(), ["codex"])

    def request(self, agent: str, requester_pid: int, env: dict | None = None) -> subprocess.CompletedProcess:
        request_env = {key: value for key, value in os.environ.items()
                       if key not in {"TELEGRAM_AGENT_SELF", "CLAUDE_WARM_HERDR_AGENT"}}
        request_env.update({"FAKE_ROOT": str(self.root), "XDG_STATE_HOME": str(self.root / "xdg-state"),
                            "XDG_RUNTIME_DIR": str(self.root / "xdg-runtime")})
        request_env.update(env or {})
        return subprocess.run(
            [str(WATCHDOG), "request", agent, "--requester-pid", str(requester_pid),
             "--state-dir", str(self.root / "state"), "--pid-dir", str(self.root / "pids"),
             "--warm-file", str(self.root / "warm"), "--nurse", str(self.nurse)],
            env=request_env,
            text=True, capture_output=True, timeout=30,
        )

    def prepare_warm_request(self, name: str = "Fable") -> str:
        session_id = "01234567-89ab-cdef-0123-456789abcdef"
        self.root.joinpath("warm").write_text(name + "\n")
        self.root.joinpath("session_id").write_text(session_id)
        transcript = self.root / (session_id + ".jsonl")
        transcript.write_text("{}\n")
        state_root = self.root / "xdg-state/claude-idle-compaction"
        channel = "claude-0123456789abcdef0123456789abcdef"
        runtime = self.root / "xdg-runtime/claude-idle-compaction" / channel
        state_root.mkdir(parents=True)
        runtime.mkdir(parents=True)
        (state_root / ("last-session.%s.json" % name)).write_text(json.dumps({"channel": channel}))
        (runtime / "state.json").write_text(json.dumps({"supervisor_pid": os.getpid(), "session_id": session_id,
                                                        "transcript_path": str(transcript),
                                                        "argv": ["claude", "--resume", "deadbeef-dead-beef-dead-beefdeadbeef"]}))
        self.set_warm({name: "field"})
        return session_id

    def request_warm(self, name: str = "Fable", requester_pid: int | None = None,
                     env: dict | None = None) -> subprocess.CompletedProcess:
        self.prepare_warm_request(name)
        return self.request("warm-" + name.lower(), requester_pid or self.dead_pid(), env=env)

    def calls(self) -> list[str]:
        path = self.root / "calls"
        return path.read_text().split() if path.exists() else []

    def dead_pid(self) -> int:
        proc = subprocess.Popen(["true"])
        proc.wait()
        return proc.pid

    def test_revive_waits_for_the_requesting_turn_to_detach(self) -> None:
        holder = subprocess.Popen(["sleep", "30"])
        try:
            self.assertEqual(self.request("codex", holder.pid).returncode, 0)
            self.run_watchdog()
            self.assertEqual(self.calls(), [])
            self.assertTrue((self.root / "state/requests/codex.json").exists())
        finally:
            holder.kill()
            holder.wait()

    def test_revive_stops_then_starts_externally_after_detach(self) -> None:
        (self.root / "status_after_start").write_text("Host: x\n  ductor: RUNNING\n  codex-helmastra (--telegram): RUNNING\n")
        self.request("codex", self.dead_pid())
        self.run_watchdog()
        self.assertEqual(self.calls(), ["stop:codex", "start:codex"])
        self.assertEqual([e["kind"] for e in self.events()], ["revive_done"])
        self.assertFalse((self.root / "state/requests/codex.json").exists())

    def test_revive_request_is_idempotent(self) -> None:
        holder = subprocess.Popen(["sleep", "30"])
        try:
            self.request("codex", holder.pid)
            second = self.request("codex", holder.pid)
            self.assertEqual(second.returncode, 0)
            self.assertIn("already pending", second.stdout)
            self.assertEqual(len(list((self.root / "state/requests").glob("*.json"))), 1)
        finally:
            holder.kill()
            holder.wait()

    def test_revive_cooldown_refuses_a_second_revive(self) -> None:
        (self.root / "status_after_start").write_text("Host: x\n  ductor: RUNNING\n  codex-helmastra (--telegram): RUNNING\n")
        self.request("codex", self.dead_pid())
        self.run_watchdog()
        self.request("codex", self.dead_pid())
        self.run_watchdog()
        self.assertEqual(self.calls(), ["stop:codex", "start:codex"])
        # Spool files from two runs in the same second sort by random id, not time.
        self.assertCountEqual([e["kind"] for e in self.events()], ["revive_done", "revive_rejected"])

    def test_stale_generation_is_dropped_without_restart(self) -> None:
        (self.root / "pids").mkdir()
        holder = subprocess.Popen(["sleep", "30"])
        try:
            (self.root / "pids/codex-helmastra-telegram.pid").write_text(str(holder.pid))
            self.request("codex", self.dead_pid())
            holder.kill()
            holder.wait()
            successor = subprocess.Popen(["sleep", "30"])
            try:
                (self.root / "pids/codex-helmastra-telegram.pid").write_text(str(successor.pid))
                self.run_watchdog()
            finally:
                successor.kill()
                successor.wait()
        finally:
            holder.kill()
        self.assertEqual(self.calls(), [])
        self.assertEqual([e["kind"] for e in self.events()], ["revive_stale"])

    def test_failed_revive_clears_the_stop_marker_so_healing_continues(self) -> None:
        (self.root / "intent").mkdir()
        (self.root / "intent/codex").write_text("")
        (self.root / "start_fail").write_text("")
        self.request("codex", self.dead_pid())
        self.run_watchdog()
        self.assertFalse((self.root / "intent/codex").exists())
        self.assertIn("revive_failed", [e["kind"] for e in self.events()])

    def test_request_is_self_targeted_by_default(self) -> None:
        refused = self.request("ductor", self.dead_pid(), env={"TELEGRAM_AGENT_SELF": "codex"})
        self.assertEqual(refused.returncode, 2)
        self.assertFalse((self.root / "state/requests/ductor.json").exists())

    def set_warm(self, verdicts: dict[str, str]) -> None:
        members = [{"name": name, "verdict": verdict} for name, verdict in verdicts.items()]
        (self.root / "nurse_status").write_text(json.dumps({"members": members}))

    def revives(self) -> list[str]:
        path = self.root / "revives"
        return path.read_text().split() if path.exists() else []

    def test_listed_warm_seat_request_is_accepted_with_live_generation_and_transcript(self) -> None:
        session_id = self.prepare_warm_request()
        result = self.request("warm-fable", self.dead_pid(), env={"CLAUDE_WARM_HERDR_AGENT": "Fable"})
        self.assertEqual(result.returncode, 0, result.stderr)
        queued = json.loads((self.root / "state/requests/warm-fable.json").read_text())
        self.assertEqual(queued["resume_session"], session_id)
        self.assertNotEqual(queued["resume_session"], "deadbeef-dead-beef-dead-beefdeadbeef")
        self.assertTrue(queued["generation"].startswith(str(os.getpid()) + ":"))
        self.assertTrue(queued["self_requested"])

    def test_warm_environment_targets_self_when_argument_is_omitted(self) -> None:
        session_id = self.prepare_warm_request()
        result = subprocess.run(
            [str(WATCHDOG), "request", "--requester-pid", str(self.dead_pid()),
             "--state-dir", str(self.root / "state"), "--warm-file", str(self.root / "warm"),
             "--nurse", str(self.nurse)],
            env=dict(os.environ, FAKE_ROOT=str(self.root), XDG_STATE_HOME=str(self.root / "xdg-state"),
                     XDG_RUNTIME_DIR=str(self.root / "xdg-runtime"), CLAUDE_WARM_HERDR_AGENT="Fable"),
            text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        queued = json.loads((self.root / "state/requests/warm-fable.json").read_text())
        self.assertEqual(queued["resume_session"], session_id)
        self.assertTrue(queued["self_requested"])

    def test_warm_request_uses_newest_reported_transcript_by_mtime(self) -> None:
        self.prepare_warm_request()
        newest_id = "fedcba98-7654-3210-fedc-ba9876543210"
        newest = self.root / (newest_id + ".jsonl")
        newest.write_text("{}\n")
        os.utime(newest, ns=(newest.stat().st_atime_ns, newest.stat().st_mtime_ns + 10_000_000_000))
        (self.root / "nurse_status").write_text(json.dumps({"members": [{"name": "Fable", "verdict": "field",
                                                                          "transcripts": [str(self.root / ("01234567-89ab-cdef-0123-456789abcdef.jsonl")), str(newest)]}]}))
        result = self.request("warm-fable", self.dead_pid())
        self.assertEqual(result.returncode, 0, result.stderr)
        queued = json.loads((self.root / "state/requests/warm-fable.json").read_text())
        self.assertEqual(queued["resume_session"], newest_id)

    def test_unlisted_warm_seat_request_is_rejected(self) -> None:
        self.prepare_warm_request("Fable")
        (self.root / "warm").write_text("Opus\n")
        result = self.request("warm-fable", self.dead_pid())
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / "state/requests/warm-fable.json").exists())

    def test_stale_warm_generation_is_dropped(self) -> None:
        self.prepare_warm_request()
        self.assertEqual(self.request("warm-fable", self.dead_pid()).returncode, 0)
        state_path = self.root / "xdg-runtime/claude-idle-compaction/claude-0123456789abcdef0123456789abcdef/state.json"
        state = json.loads(state_path.read_text())
        state["supervisor_pid"] = self.dead_pid()
        state_path.write_text(json.dumps(state))
        self.run_watchdog()
        self.assertEqual(self.revives(), [])
        self.assertEqual([event["kind"] for event in self.events()], ["revive_stale"])

    def test_warm_revive_command_readiness_and_receipt(self) -> None:
        session_id = self.prepare_warm_request()
        self.assertEqual(self.request("warm-fable", self.dead_pid(), env={"CLAUDE_WARM_HERDR_AGENT": "Fable"}).returncode, 0)
        self.run_watchdog()
        self.assertEqual((self.root / "revive_args").read_text().splitlines(),
                         ["revive --no-visit --resume %s Fable" % session_id])
        event = self.events()[0]
        self.assertEqual(event["kind"], "revive_done")
        self.assertEqual(event["payload"]["code_staleness"], "fresh")
        receipt = json.loads((self.root / "state/receipt.json").read_text())
        self.assertEqual(receipt["request_receipts"][0]["code_staleness"], "fresh")
        self.assertFalse(receipt["request_receipts"][0]["force_escalated"])

    def test_warm_revive_runs_the_live_session_guard_first(self) -> None:
        session_id = self.prepare_warm_request()
        self.assertEqual(self.request("warm-fable", self.dead_pid()).returncode, 0)
        self.run_watchdog()
        checks = (self.root / "live_checks").read_text().splitlines()
        self.assertEqual(len(checks), 1)
        seat, checked_id = checks[0].split()
        self.assertEqual((seat, checked_id), ("Fable", session_id))
        self.assertEqual(self.revives(), ["Fable"])
        self.assertEqual([event["kind"] for event in self.events()], ["revive_done"])

    def test_live_session_guard_rejects_the_revive_without_killing_anything(self) -> None:
        session_id = self.prepare_warm_request()
        (self.root / "live_refusal").write_text(json.dumps({
            "schema": "helmcortex.nurse-joy.live-session.v1", "session": session_id, "live": True,
            "kind": "background", "pid": 4242, "name": "probe-session", "source": "claude-agents-registry",
            "message": "session %s is live in a background pty host (pid 4242, name probe-session) — "
                       "reattach with `claude attach %s`, never relaunch onto it" % (session_id, session_id[:8])}))
        self.assertEqual(self.request("warm-fable", self.dead_pid()).returncode, 0)
        self.run_watchdog()
        self.assertEqual(self.revives(), [])  # nurse-joy revive was never invoked
        self.assertFalse((self.root / "revive_args").exists())
        self.assertFalse((self.root / "state/requests/warm-fable.json").exists())  # the request is dropped
        events = self.events()
        self.assertEqual([event["kind"] for event in events], ["revive_rejected"])
        self.assertIn("never relaunch onto it", events[0]["body"])
        self.assertEqual(events[0]["payload"]["resume_session"], session_id)

    def test_live_session_guard_fails_closed_when_the_check_cannot_run(self) -> None:
        session_id = self.prepare_warm_request()
        (self.root / "live_check_fail").write_text("")
        self.assertEqual(self.request("warm-fable", self.dead_pid()).returncode, 0)
        self.run_watchdog()
        self.assertEqual(self.revives(), [])
        events = self.events()
        self.assertEqual([event["kind"] for event in events], ["revive_rejected"])
        self.assertIn("unavailable", events[0]["body"])

    def test_warm_readiness_must_be_verified(self) -> None:
        self.prepare_warm_request()
        (self.root / "nurse_status_after_revive").write_text(json.dumps({"members": [{"name": "Fable", "verdict": "unknown"}]}))
        self.request("warm-fable", self.dead_pid())
        self.run_watchdog()
        self.assertEqual(self.events()[0]["kind"], "revive_failed")
        receipt = json.loads((self.root / "state/receipt.json").read_text())
        self.assertEqual(receipt["request_receipts"][0]["code_staleness"], "unknown")

    def test_degraded_warm_readiness_is_up_and_receipt_marks_stale_code(self) -> None:
        self.prepare_warm_request()
        (self.root / "nurse_status_after_revive").write_text(json.dumps({"members": [{"name": "Fable", "verdict": "degraded"}]}))
        self.request("warm-fable", self.dead_pid())
        self.run_watchdog()
        self.assertEqual(self.events()[0]["kind"], "revive_done")
        receipt = json.loads((self.root / "state/receipt.json").read_text())
        self.assertEqual(receipt["request_receipts"][0]["code_staleness"], "stale")

    def test_warm_revive_cooldown_is_honoured(self) -> None:
        self.prepare_warm_request()
        self.request("warm-fable", self.dead_pid())
        self.run_watchdog()
        self.request("warm-fable", self.dead_pid())
        self.run_watchdog()
        self.assertEqual(len((self.root / "revive_args").read_text().splitlines()), 1)
        self.assertEqual([event["kind"] for event in self.events()], ["revive_done", "revive_rejected"])

    def test_force_escalation_is_limited_to_self_requested_warm_revives(self) -> None:
        self.prepare_warm_request()
        (self.root / "delay_nurse").write_text("")
        self.request("warm-fable", self.dead_pid(), env={"CLAUDE_WARM_HERDR_AGENT": "Fable"})
        self.run_watchdog("--warm-revive-grace", "0.05")
        args = (self.root / "revive_args").read_text().splitlines()
        self.assertEqual(len(args), 2)
        self.assertIn("--force", args[1])
        self.assertTrue(json.loads((self.root / "state/receipt.json").read_text())["request_receipts"][0]["force_escalated"])

        other = WatchdogTests()
        other.setUp()
        try:
            other.prepare_warm_request()
            (other.root / "delay_nurse").write_text("")
            other.request("warm-fable", other.dead_pid())  # explicit target without self identity: never force
            other.run_watchdog("--warm-revive-grace", "0.05")
            args = (other.root / "revive_args").read_text().splitlines()
            self.assertEqual(len(args), 1)
            self.assertNotIn("--force", args[0])
        finally:
            other.tearDown()

    def test_no_warm_list_never_calls_nurse(self) -> None:
        self.set_warm({"Fable": "down"})
        self.run_watchdog()
        self.assertEqual(self.revives(), [])

    def test_down_warm_session_is_revived_through_nurse_joy(self) -> None:
        (self.root / "warm").write_text("Fable\nOpus  # sealed consort\nHaiku\n")
        self.set_warm({"Fable": "field", "Opus": "down", "Haiku": "field", "Auryn": "down"})
        self.run_watchdog()
        self.assertEqual(self.revives(), ["opus"])  # Auryn is down but not listed: untouched
        self.assertEqual(self.starts(), [])  # never routed through the Telegram host manager
        self.assertEqual([(e["kind"], e["payload"]["agent"]) for e in self.events()], [("down", "warm-opus")])
        self.set_warm({"Fable": "field", "Opus": "field", "Haiku": "field"})
        self.run_watchdog()
        self.assertEqual([e["kind"] for e in self.events()], ["down", "recovered"])

    def test_warm_operator_stop_marker_is_respected(self) -> None:
        (self.root / "warm").write_text("Opus\n")
        (self.root / "intent").mkdir()
        (self.root / "intent" / "warm-opus").write_text("")
        self.set_warm({"Opus": "down"})
        self.run_watchdog()
        self.assertEqual(self.revives(), [])

    def test_unreadable_or_unusual_warm_state_never_revives(self) -> None:
        (self.root / "warm").write_text("Opus\nHaiku\nFable\n")
        self.set_warm({"Opus": "fainted", "Haiku": "field"})  # Fable missing from the roster entirely
        self.run_watchdog()
        self.assertEqual(self.revives(), [])
        (self.root / "nurse_status").write_text("not json")
        self.run_watchdog()
        self.assertEqual(self.revives(), [])

    def test_degraded_warm_session_counts_as_up(self) -> None:
        (self.root / "warm").write_text("Opus\n")
        self.set_warm({"Opus": "degraded"})
        (self.root / "tmux_dead").write_text("")  # even a failed tmux probe never overrides an observed live verdict
        self.run_watchdog()
        self.assertEqual(self.revives(), [])

    def test_unknown_with_dead_tmux_server_is_down_and_revived(self) -> None:
        (self.root / "warm").write_text("Fable\nOpus\n")
        self.set_warm({"Fable": "unknown", "Opus": "unknown"})
        (self.root / "tmux_dead").write_text("")
        self.run_watchdog()
        self.assertEqual(sorted(self.revives()), ["fable", "opus"])

    def test_unknown_with_live_or_unreadable_tmux_is_left_alone(self) -> None:
        (self.root / "warm").write_text("Opus\n")
        self.set_warm({"Opus": "unknown"})
        self.run_watchdog()  # tmux server answers: unknown stays unknown
        (self.root / "tmux_broken").write_text("")
        self.run_watchdog()  # tmux probe fails for another reason: still no action
        self.assertEqual(self.revives(), [])

    def test_revive_runs_with_a_runtime_dir_even_from_cron(self) -> None:
        self.nurse.write_text(FAKE_NURSE.replace('echo "$a" >> "$root/revives"', 'echo "$a:${XDG_RUNTIME_DIR:-MISSING}" >> "$root/revives"'))
        (self.root / "warm").write_text("Opus\n")
        self.set_warm({"Opus": "down"})
        env = {k: v for k, v in os.environ.items() if k != "XDG_RUNTIME_DIR"}
        subprocess.run(
            [str(WATCHDOG), "--expected-host", HOST, "--manager", str(self.manager),
             "--state-dir", str(self.root / "state"), "--intent-dir", str(self.root / "intent"),
             "--boot-lock", str(self.root / "boot.lock"), "--spool", str(self.root / "spool"),
             "--pid-dir", str(self.root / "pids"), "--backoff", "0",
             "--warm-file", str(self.root / "warm"), "--nurse", str(self.nurse), "--tmux", str(self.tmux)],
            env=dict(env, FAKE_ROOT=str(self.root)), text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(self.revives(), ["opus:/run/user/%d" % os.getuid()])

    def test_warm_attempt_cap_holds(self) -> None:
        (self.root / "warm").write_text("Opus\n")
        self.set_warm({"Opus": "down"})
        for _ in range(5):
            self.run_watchdog()
        self.assertEqual(self.revives(), ["opus", "opus", "opus"])
        self.assertIn("relaunch_failed", [e["kind"] for e in self.events()])

    def test_wrong_host_refuses(self) -> None:
        result = subprocess.run([str(WATCHDOG), "--expected-host", "not-" + HOST, "--manager", str(self.manager)],
                                text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)

    def test_help_is_side_effect_free(self) -> None:
        result = subprocess.run([str(WATCHDOG), "--help"], text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
