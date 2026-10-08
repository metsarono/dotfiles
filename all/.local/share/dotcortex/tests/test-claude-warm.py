#!/usr/bin/env python3
"""Black-box tests for the claude-warm PTY supervisor."""

from __future__ import annotations

import ast
import contextlib
import datetime
import io
import json
import fcntl
import importlib.machinery
import importlib.util
import os
import pty
import pathlib
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unittest
from unittest import mock


HERE = pathlib.Path(__file__).resolve()
REPO = HERE.parents[5]
WARM = REPO / "all/.local/bin/claude-warm"
OBSERVER = REPO / "all/.local/bin/claude-warm-live-observe"
WATCHDOG = REPO / "all/.local/bin/claude-poller-watchdog"
HOOK = REPO / "all/.local/bin/claude-hook-idle-event"
STATUSLINE = REPO / "all/.local/bin/claude-statusline"


FAKE_CLAUDE = r'''#!/usr/bin/env python3
import fcntl
import os
import select
import signal
import struct
import subprocess
import sys
import termios
import time


def report_size(_signum=None, _frame=None):
    try:
        raw = fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8)
        rows, columns = struct.unpack("HH", raw[:4])
        os.write(1, (f"SIZE:{rows}x{columns}\n").encode())
    except OSError:
        pass


def emit_development_channel_prompt():
    entry = next(
        (
            argument.split("=", 1)[1]
            for argument in sys.argv
            if argument.startswith("--emit-dev-channel-prompt=")
        ),
        None,
    )
    if entry is None:
        return
    delay = next(
        (
            float(argument.split("=", 1)[1])
            for argument in sys.argv
            if argument.startswith("--dev-channel-prompt-delay=")
        ),
        0.0,
    )
    if delay:
        time.sleep(delay)
    prompt = (
        b"\x1b[31mWARNING: Loading development channels\x1b[0m\n"
        b"--dangerously-load-development-channels is for local channel development only. "
        b"Do not use this option to run channels you have downloaded off the internet.\n"
        b"Please use --channels to run a list of approved channels.\n"
        + f"Channels: {entry}\n".encode()
        + b"\x1b[1mI am using this for local development\x1b[0m\n"
        b"Exit\n"
    )
    if "--alter-dev-channel-prompt" in sys.argv:
        prompt = prompt.replace(
            b"Please use --channels to run a list of approved channels.",
            b"Please use --channels to run approved channels.",
        )

    def write_prompt():
        if "--fragment-dev-channel-prompt" not in sys.argv:
            os.write(1, prompt)
            return
        # Split both an ANSI escape and stable prompt phrases across distinct
        # writes, as the real Ink renderer does while painting the PTY.
        cuts = (2, 19, 71, 149, 231, 257, len(prompt))
        start = 0
        for end in cuts:
            os.write(1, prompt[start:end])
            start = end
            time.sleep(0.04)

    write_prompt()
    if "--repeat-dev-channel-prompt" in sys.argv:
        write_prompt()


def main():
    os.write(1, (f"ARGS:{sys.argv[1:]!r}\n").encode())
    report_size()
    if "--emit-terminal-modes" in sys.argv:
        os.write(1, b"\x1b[?1000h\x1b[?1004h\x1b[?1049h")
    signal.signal(signal.SIGWINCH, report_size)
    channel_child = None
    if "--spawn-channel-process" in sys.argv:
        channel_child = subprocess.Popen(
            [
                os.environ["CLAUDE_TEST_PYTHON"],
                "-c",
                "import time; time.sleep(60)",
                "server.ts",
            ]
        )
    if "--exit-status=7" in sys.argv:
        return 7
    emit_development_channel_prompt()
    try:
        while True:
            readable, _, _ = select.select([0], [], [], 0.1)
            if not readable:
                continue
            data = os.read(0, 65536)
            if not data:
                return 0
            os.write(1, (f"INPUT:{data!r}\n").encode())
            if b"/compact" in data:
                os.write(1, b"COMPACT_RECEIVED\n")
    finally:
        if channel_child is not None and channel_child.poll() is None:
            channel_child.terminate()
            channel_child.wait()


raise SystemExit(main())
'''


FAKE_PRESERVATION_BRIDGE = r'''#!/usr/bin/env python3
import json
import os
import sys
import time


request = json.load(sys.stdin)
calls = os.environ.get("CLAUDE_TEST_PRESERVATION_CALLS")
if calls:
    with open(calls, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(request, sort_keys=True) + "\n")
mode = os.environ.get("CLAUDE_TEST_PRESERVATION_MODE", "directive")
if mode == "unavailable":
    raise SystemExit(78)
if mode == "stale":
    print(json.dumps({
        "schema": "fleet.preservation-sync.v1",
        "ok": False,
        "error": "telemetry-refresh-required",
        "next_action": "central-authority-unavailable",
    }))
    raise SystemExit(0)
if mode == "malformed":
    print("not-json")
    raise SystemExit(0)
if mode == "wrong-contract":
    print(json.dumps({
        "schema": "fleet.preservation-sync.v1",
        "bridge_adapter": "wrong.Adapter",
        "bridge_protocol": "wrong-protocol",
        "ok": True,
    }))
    raise SystemExit(0)
if mode == "slow":
    time.sleep(2.0)
owner = request["owner_state"]
completed = owner.get("native_state") == "native_completed"
print(json.dumps({
    "schema": "fleet.preservation-sync.v1",
    "bridge_adapter": "federated_preservation.SshAuthorityTransport",
    "bridge_protocol": "stdin-json-v1",
    "ok": True,
    "pool_key": request["pool"]["pool_key"],
    "observation_age_seconds": 1.0,
    "limiting_headroom_percent": 5.0,
    "aggregate_reserve_percent": 8.0,
    "decision": "admit_work" if completed else "request_native_preservation",
    "protection_enabled": True,
    "nudge_enabled": False,
    "generation_loaded": owner["loaded_generation"] == owner["installed_generation"],
    "directive": None if completed or mode == "none" else {
        "request_id": "preserve-test-request",
        "reservation_id": "preserve:preserve-test-request",
    },
    "next_action": "none" if completed or mode == "none" else "invoke-native-owner",
}))
'''


PRESERVATION_ENV_KEYS = (
    "CLAUDE_WARM_PRESERVATION_BRIDGE",
    "CLAUDE_WARM_PRESERVATION_BRIDGE_ADAPTER",
    "CLAUDE_WARM_PRESERVATION_AUTHORITY_HOST",
    "CLAUDE_WARM_PRESERVATION_AUTHORITY_IDENTITY",
    "CLAUDE_WARM_PRESERVATION_AUTHORITY_EXECUTABLE",
    "CLAUDE_WARM_PRESERVATION_LEDGER_ROOT",
    "CLAUDE_WARM_PRESERVATION_TELEMETRY_SOURCE",
    "CLAUDE_WARM_PRESERVATION_TELEMETRY_HOST",
    "CLAUDE_WARM_PRESERVATION_TRANSPORT",
    "CLAUDE_WARM_PRESERVATION_PROVIDER",
    "CLAUDE_WARM_PRESERVATION_ACCOUNT_HASH",
    "CLAUDE_WARM_PRESERVATION_MODEL_POOL",
    "CLAUDE_WARM_PRESERVATION_ESTIMATE_PERCENT",
    "CLAUDE_WARM_PRESERVATION_ESTIMATE_UNCERTAINTY_PERCENT",
    "CLAUDE_WARM_PRESERVATION_IN_FLIGHT_RESERVE_PERCENT",
    "CLAUDE_WARM_PRESERVATION_CONTROL_RESERVE_PERCENT",
    "CLAUDE_WARM_PRESERVATION_PROTECTION_ENABLED",
    "CLAUDE_WARM_PRESERVATION_NUDGE_ENABLED",
    "CLAUDE_WARM_PRESERVATION_POLL_SECONDS",
    "CLAUDE_WARM_PRESERVATION_BRIDGE_TIMEOUT_SECONDS",
    "CLAUDE_TEST_PRESERVATION_CALLS",
    "CLAUDE_TEST_PRESERVATION_MODE",
)


# Captured Kikin metadata shape for the delayed 2026-08-04 production record.
# Content and all identifiers are deliberately redacted; the classifier only
# needs the public record type/subtype and lifecycle metadata shape.
AWAY_SUMMARY_FIXTURE = {
    "content": "<redacted>",
    "cwd": "<redacted>",
    "entrypoint": "cli",
    "gitBranch": "<redacted>",
    "isMeta": False,
    "isSidechain": False,
    "parentUuid": "<redacted>",
    "sessionId": "<redacted>",
    "slug": "<redacted>",
    "subtype": "away_summary",
    "timestamp": "2026-08-04T03:11:40.142Z",
    "type": "system",
    "userType": "external",
    "uuid": "<redacted>",
    "version": "2.1.220",
}


def wait_until(predicate, timeout=5.0, message="condition did not become true"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError(message)


class Session:
    """One supervised fake Claude process and its private runtime directory."""

    def __init__(
        self,
        delay=10,
        ttl=60,
        extra_args=(),
        terminal=False,
        cache_result=None,
        channel=False,
        attach_wait=30,
        recovery_cooldown=0,
        recovery_confirm=1,
        spawn_channel=False,
        retry=300,
        compact_timeout=900,
        preservation=False,
        preservation_mode="directive",
        accept_dev_channels="",
        dev_channel_accept_window=60,
        lifecycle_wait=180,
    ):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="cw", dir="/tmp"))
        self.environment = None
        self.fake = self.root / "fake-claude"
        self.fake.write_text(FAKE_CLAUDE, encoding="utf-8")
        self.fake.chmod(0o700)
        self.preservation_calls = self.root / "preservation-calls.jsonl"
        if preservation:
            self.preservation_bridge = self.root / "fake-preservation-bridge"
            self.preservation_bridge.write_text(FAKE_PRESERVATION_BRIDGE, encoding="utf-8")
            self.preservation_bridge.chmod(0o700)
        self.transcript = self.root / "transcript.jsonl"
        self.transcript.write_text("", encoding="utf-8")
        environment = os.environ.copy()
        for key in PRESERVATION_ENV_KEYS:
            environment.pop(key, None)
        environment.pop("CLAUDE_WARM_ACCEPT_DEV_CHANNELS", None)
        environment.pop("CLAUDE_WARM_DEV_CHANNEL_ACCEPT_WINDOW_SECONDS", None)
        environment.update(
            {
                "XDG_RUNTIME_DIR": str(self.root),
                # sys.executable can be empty when PATH is absent; procfs still
                # retains the actual interpreter running this Linux-only suite.
                "CLAUDE_TEST_PYTHON": os.readlink("/proc/self/exe"),
                "CLAUDE_IDLE_REAL_EXECUTABLE": str(self.fake),
                "CLAUDE_IDLE_COMPACT_SECONDS": str(delay),
                "CLAUDE_IDLE_COMPACT_LONG_CACHE_TTL_SECONDS": str(ttl),
                "CLAUDE_IDLE_COMPACT_STATUS_STOP_SKEW_SECONDS": "2",
                "CLAUDE_IDLE_COMPACT_TRANSCRIPT_QUIESCENCE_SECONDS": "0.1",
                "CLAUDE_IDLE_COMPACT_TRANSCRIPT_POLL_SECONDS": "1",
                "CLAUDE_IDLE_CACHE_PROFILE": "long",
                "CLAUDE_IDLE_COMPACTION_DEBUG": "1",
                "XDG_STATE_HOME": str(self.root / "state"),
                "CLAUDE_IDLE_CHANNEL_ATTACH_WAIT_SECONDS": str(attach_wait),
                "CLAUDE_IDLE_CHANNEL_RECOVERY_COOLDOWN_SECONDS": str(recovery_cooldown),
                "CLAUDE_IDLE_CHANNEL_RECOVERY_CONFIRM_SECONDS": str(recovery_confirm),
                "CLAUDE_IDLE_COMPACT_RETRY_SECONDS": str(retry),
                "CLAUDE_IDLE_COMPACT_TIMEOUT_SECONDS": str(compact_timeout),
                "CLAUDE_WARM_ACCEPT_DEV_CHANNELS": accept_dev_channels,
                "CLAUDE_WARM_DEV_CHANNEL_ACCEPT_WINDOW_SECONDS": str(
                    dev_channel_accept_window
                ),
                "CLAUDE_IDLE_LIFECYCLE_WAIT_SECONDS": str(lifecycle_wait),
            }
        )
        self.environment = environment
        if preservation:
            environment.update({
                "CLAUDE_WARM_PRESERVATION_BRIDGE": str(self.preservation_bridge),
                "CLAUDE_WARM_PRESERVATION_BRIDGE_ADAPTER": "federated_preservation.SshAuthorityTransport",
                "CLAUDE_WARM_PRESERVATION_AUTHORITY_HOST": "authority-host",
                "CLAUDE_WARM_PRESERVATION_AUTHORITY_IDENTITY": "kikin-kushi",
                "CLAUDE_WARM_PRESERVATION_AUTHORITY_EXECUTABLE": "/opt/helmcortex/fleet-preservation",
                "CLAUDE_WARM_PRESERVATION_LEDGER_ROOT": "/var/lib/helmcortex/fleet-preservation",
                "CLAUDE_WARM_PRESERVATION_TELEMETRY_SOURCE": "authority:authority-host",
                "CLAUDE_WARM_PRESERVATION_TELEMETRY_HOST": "t480s",
                "CLAUDE_WARM_PRESERVATION_TRANSPORT": "ssh",
                "CLAUDE_WARM_PRESERVATION_PROVIDER": "claude",
                "CLAUDE_WARM_PRESERVATION_ACCOUNT_HASH": "sha256:account",
                "CLAUDE_WARM_PRESERVATION_MODEL_POOL": "opus",
                "CLAUDE_WARM_PRESERVATION_ESTIMATE_PERCENT": "5",
                "CLAUDE_WARM_PRESERVATION_ESTIMATE_UNCERTAINTY_PERCENT": "1",
                "CLAUDE_WARM_PRESERVATION_IN_FLIGHT_RESERVE_PERCENT": "0.5",
                "CLAUDE_WARM_PRESERVATION_CONTROL_RESERVE_PERCENT": "0.5",
                "CLAUDE_WARM_PRESERVATION_PROTECTION_ENABLED": "1",
                "CLAUDE_WARM_PRESERVATION_NUDGE_ENABLED": "0",
                "CLAUDE_WARM_PRESERVATION_POLL_SECONDS": "0.1",
                "CLAUDE_WARM_PRESERVATION_BRIDGE_TIMEOUT_SECONDS": "1",
                "CLAUDE_TEST_PRESERVATION_CALLS": str(self.preservation_calls),
                "CLAUDE_TEST_PRESERVATION_MODE": preservation_mode,
            })
        if channel:
            extra_args = ("--channels", "plugin:fixture@fixture", *extra_args)
            if spawn_channel:
                extra_args = (*extra_args, "--spawn-channel-process")
        self.cache_result_path = self.root / "cache-result.json"
        self.cache_calls = self.root / "cache-calls.jsonl"
        environment["FLEET_CACHE_POLICY_PATH"] = str(self.root / "missing-policy.json")
        if cache_result is not None:
            self.cache_result_path.write_text(json.dumps(cache_result), encoding="utf-8")
            cache_helper = self.root / "cache-policy"
            cache_helper.write_text(
                "#!/usr/bin/env python3\nimport json,pathlib,sys\n"
                f"root=pathlib.Path({str(self.root)!r})\n"
                "with (root/'cache-calls.jsonl').open('a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                "print((root/'cache-result.json').read_text())\n", encoding="utf-8",
            )
            cache_helper.chmod(0o700)
            policy = self.root / "cache-policy.json"
            policy.write_text("{}", encoding="utf-8")
            environment["FLEET_CACHE_POLICY_HELPER"] = str(cache_helper)
            environment["FLEET_CACHE_POLICY_PATH"] = str(policy)
        self.parent_master = None
        self.outer_tty_fd = None
        self.outer_tty_baseline = None
        self.outer_tty_after = None
        if terminal:
            self.parent_master, parent_slave = pty.openpty()
            self.outer_tty_fd = os.dup(parent_slave)
            self.outer_tty_baseline = termios.tcgetattr(self.outer_tty_fd)
            self.process = subprocess.Popen(
                [str(WARM), *extra_args],
                stdin=parent_slave,
                stdout=parent_slave,
                stderr=parent_slave,
                env=environment,
            )
            os.close(parent_slave)
            self.output_fd = self.parent_master
        else:
            self.process = subprocess.Popen(
                [str(WARM), *extra_args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
            )
            assert self.process.stdout is not None
            self.output_fd = self.process.stdout.fileno()
        os.set_blocking(self.output_fd, False)
        self.output = bytearray()
        self.state_path = wait_until(self._find_state, message="state file missing")
        self.channel = self.state_path.parent.name
        self.socket_path = self.state_path.parent / "control.sock"
        self.session_id = "fixture-session"

    def _find_state(self):
        paths = list((self.root / "claude-idle-compaction").glob("claude-*/state.json"))
        return paths[0] if paths else None

    def read_state(self):
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def guard_events(self):
        path = self.root / "state" / "claude-idle-compaction" / f"{self.channel}.channel-guard.log"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        events = []
        for line in lines:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    def output_contains(self, needle):
        if isinstance(needle, str):
            needle = needle.encode()
        while True:
            ready, _, _ = select.select([self.output_fd], [], [], 0)
            if not ready:
                break
            data = os.read(self.output_fd, 65536)
            if not data:
                break
            self.output.extend(data)
        return needle in self.output

    def wait_output(self, needle, timeout=5):
        try:
            wait_until(lambda: self.output_contains(needle), timeout, f"missing output {needle!r}")
        except AssertionError as error:
            raise AssertionError(
                f"{error}; state={self.read_state()!r}; output={bytes(self.output)!r}"
            ) from error

    def ipc(self, message):
        message = dict(message)
        message.setdefault("kind", "event")
        message.setdefault("channel", self.channel)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(str(self.socket_path))
            connection.sendall((json.dumps(message) + "\n").encode())
            return json.loads(connection.recv(65536).decode())

    def event(self, event, **fields):
        message = {"event": event, "session_id": self.session_id, **fields}
        return self.ipc(message)

    def status(self, tokens=80000, session_id=None, timestamp=None, model="Opus 4.8"):
        payload = {
            "channel": self.channel,
            "session_id": session_id or self.session_id,
            "model": model,
            "current_input_context_tokens": tokens,
            "update_timestamp": timestamp if timestamp is not None else time.time(),
        }
        path = self.state_path.parent / "status.json"
        temporary = path.with_name(".status-test.tmp")
        temporary.write_text(json.dumps(payload), encoding="utf-8")
        temporary.replace(path)

    def append_transcript(self, entry):
        with self.transcript.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry) + "\n")

    def control(self, command, **fields):
        return self.ipc({"kind": "control", "command": command, **fields})

    def submit_local_byte(self, data=b"x"):
        if self.parent_master is not None:
            os.write(self.parent_master, data)
        else:
            assert self.process.stdin is not None
            self.process.stdin.write(data)
            self.process.stdin.flush()

    def set_size(self, rows, columns):
        assert self.parent_master is not None
        fcntl.ioctl(self.parent_master, termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, columns, 0, 0))

    def stop_and_bind(self, wait_quiescence=True):
        self.event("session-start", transcript_path=str(self.transcript))
        self.status()
        self.event("stop", stop_hook_active=False)
        if wait_quiescence:
            wait_until(
                lambda: self.read_state()
                and self.read_state().get("transcript_quiescence_deadline") is None,
                message="transcript quiescence was not established",
            )

    def close(self):
        if self.process.poll() is None:
            try:
                self.event("session-end")
            except (OSError, ConnectionError, json.JSONDecodeError):
                pass
            if self.process.stdin is not None:
                try:
                    self.process.stdin.close()
                except OSError:
                    pass
            elif self.parent_master is not None:
                self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.send_signal(signal.SIGTERM)
                self.process.wait(timeout=5)
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.parent_master is not None:
            self.output_contains(b"")
            try:
                self.outer_tty_after = termios.tcgetattr(self.outer_tty_fd)
            except OSError:
                self.outer_tty_after = None
            os.close(self.parent_master)
            self.parent_master = None
        if self.outer_tty_fd is not None:
            os.close(self.outer_tty_fd)
            self.outer_tty_fd = None
        shutil.rmtree(self.root, ignore_errors=True)


class ClaudeWarmTests(unittest.TestCase):
    def setUp(self):
        self.sessions = []
        loader = importlib.machinery.SourceFileLoader("claude_warm_test_module", str(WARM))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.module = importlib.util.module_from_spec(spec)
        loader.exec_module(self.module)

    def tearDown(self):
        for session in reversed(self.sessions):
            session.close()

    def make_session(self, **kwargs):
        session = Session(**kwargs)
        self.sessions.append(session)
        return session

    def test_custom_anthropic_endpoint_retains_profile_fallback(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "fixture-custom"}), mock.patch.object(self.module.subprocess, "run", side_effect=AssertionError("guessed endpoint")):
            idle, ttl, decision = self.module.measured_cache_window("Opus 4.8", "short")
        self.assertEqual((idle, ttl), (self.module.IDLE_SECONDS["short"], self.module.TTL_SECONDS["short"]))
        self.assertEqual(decision["mode"], "fallback")

    def cache_decision(self, compact=1, expiry=2):
        return {"mode": "measured", "confidence": "supported",
                "provider": "anthropic", "endpoint_id": "anthropic-default",
                "model": "claude-opus-4-8", "compact_before_seconds": compact,
                "cache_expires_seconds": expiry, "reason": "exact-harness"}

    def test_cache_adversarial_stdout_uses_fixed_fallback_timer(self):
        valid = self.cache_decision()
        invalid = [[], None, True, 5, "wrong", {},
                   {**valid, "mode": "fallback", "confidence": "fallback", "reason": "policy-stale"},
                   {**valid, "mode": "observed", "confidence": "observed"},
                   {**valid, "confidence": "insufficient"},
                   {**valid, "model": "other-model"},
                   {**valid, "endpoint_id": "other-endpoint"}]
        invalid += [{**valid, "compact_before_seconds": value}
                    for value in (None, "1", True, -1, 0, float("nan"), float("inf"), 3)]
        invalid += [{**valid, "cache_expires_seconds": value}
                    for value in (None, "2", False, -1, 0, float("nan"), float("inf"), 1)]
        for decision in invalid:
            with self.subTest(decision=decision):
                session = self.make_session(delay=20, ttl=30, cache_result=decision,
                                            extra_args=("--model", "fixture-model"))
                session.stop_and_bind()
                state = session.read_state()
                self.assertEqual(state["cache_policy"]["mode"], "fallback")
                self.assertAlmostEqual(state["timer_deadline"] - state["last_normal_stop"], 20, delta=0.1)
                self.assertFalse(session.output_contains("COMPACT_RECEIVED"))
                session.close()

    def test_cache_policy_change_at_fire_rearms_without_early_compaction(self):
        session = self.make_session(delay=20, ttl=30, cache_result=self.cache_decision(),
                                    extra_args=("--model", "fixture-model"))
        session.stop_and_bind()
        session.cache_result_path.write_text(json.dumps(self.cache_decision(5, 6)), encoding="utf-8")
        wait_until(lambda: session.read_state() and
                   session.read_state()["last_state_transition"] == "policy-refreshed-rearmed", timeout=4)
        state = session.read_state()
        self.assertAlmostEqual(state["timer_deadline"] - state["last_normal_stop"], 5, delta=0.1)
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))
        calls = [json.loads(line) for line in session.cache_calls.read_text().splitlines()]
        self.assertGreaterEqual(len(calls), 2)
        for command in calls:
            self.assertEqual(command[command.index("--endpoint")+1], "anthropic-default")
            self.assertNotIn("--allow-observed", command)

    def test_cache_rejected_current_snapshot_cannot_reuse_previous_model(self):
        session = self.make_session(delay=5, ttl=6, cache_result=self.cache_decision())
        session.stop_and_bind()
        session.status(session_id="different-owner-session", model="Sonnet 4.6")
        wait_until(lambda: session.read_state() and session.read_state()["cache_policy"]["mode"] == "fallback", timeout=3)
        state = session.read_state()
        self.assertAlmostEqual(state["timer_deadline"] - state["last_normal_stop"], 5, delta=0.1)
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_cache_current_snapshot_model_at_fire_rearms(self):
        session = self.make_session(delay=20, ttl=30, cache_result=self.cache_decision())
        session.stop_and_bind()
        session.status(model="Sonnet 4.6")
        decision = self.cache_decision(5, 6)
        decision["model"] = "claude-sonnet-4-6"
        session.cache_result_path.write_text(json.dumps(decision), encoding="utf-8")
        wait_until(lambda: session.read_state() and session.read_state()["last_state_transition"] == "policy-refreshed-rearmed", timeout=4)
        calls = [json.loads(line) for line in session.cache_calls.read_text().splitlines()]
        self.assertEqual(calls[-1][calls[-1].index("--model")+1], "Sonnet 4.6")
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_measured_cache_window_uses_current_model_and_strict_policy(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = pathlib.Path(raw_root)
            helper = root / "cache-policy"
            policy = root / "cache-policy.json"
            helper.write_text("fixture", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            decision = {
                "compact_before_seconds": 7080,
                "cache_expires_seconds": 7200,
                "mode": "measured",
                "confidence": "supported",
                "provider": "anthropic",
                "endpoint_id": "anthropic-default",
                "model": "claude-opus-4-8",
                "reason": "endpoint-model-transfer",
            }
            completed = subprocess.CompletedProcess([], 0, json.dumps(decision), "")
            with mock.patch.dict(os.environ, {
                "FLEET_CACHE_POLICY_HELPER": str(helper),
                "FLEET_CACHE_POLICY_PATH": str(policy),
            }), mock.patch.object(self.module.subprocess, "run", return_value=completed) as run:
                compact_after, cache_expires, resolved = self.module.measured_cache_window(
                    "Opus 4.8", "long"
                )
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--model") + 1], "Opus 4.8")
        self.assertNotIn("--allow-observed", command)
        self.assertEqual((compact_after, cache_expires), (7080, 7200))
        self.assertEqual(resolved["reason"], "endpoint-model-transfer")

    def test_action_refresh_rearms_when_new_policy_deadline_is_later(self):
        supervisor = object.__new__(self.module.Supervisor)
        supervisor.current_model = "Opus 4.8"
        supervisor.cache_profile = "long"
        supervisor.cache_idle_seconds = 60
        supervisor.cache_ttl_seconds = 120
        supervisor.cache_policy = {"mode": "fallback", "reason": "startup"}
        supervisor.timer_generation = 4
        supervisor.timer_deadline = None
        supervisor.timer_kind = None
        supervisor.last_state_transition = "armed"
        supervisor._read_snapshot = mock.Mock(return_value=({}, None))
        supervisor._idle_anchor = mock.Mock(return_value=900.0)
        supervisor._guard_log = mock.Mock()
        supervisor._write_state = mock.Mock()
        decision = {
            "mode": "measured", "reason": "exact-harness",
            "confidence": "supported", "source_harness": "claude",
            "provider": "anthropic", "endpoint_id": "anthropic-default",
            "model": "claude-opus-4-8", "observed_at": "2026-09-30T00:00:00Z",
            "sample_count": 500, "session_count": 40,
        }
        with mock.patch.object(self.module, "now", return_value=1000.0), mock.patch.object(
            self.module, "measured_cache_window", return_value=(300, 360, decision)
        ):
            self.assertFalse(supervisor._refresh_cache_policy_for_action())
        self.assertEqual(supervisor.timer_generation, 5)
        self.assertEqual(supervisor.timer_deadline, 1200.0)
        self.assertEqual(supervisor.timer_kind, "compact")
        self.assertEqual(supervisor.last_state_transition, "policy-refreshed-rearmed")
        event, fields = supervisor._guard_log.call_args.args[0], supervisor._guard_log.call_args.kwargs
        self.assertEqual(event, "policy-refreshed-rearmed")
        self.assertEqual(fields["policy_model"], "claude-opus-4-8")
        self.assertEqual(fields["policy_session_count"], 40)

    def test_automatic_attempt_refreshes_policy_before_final_gate(self):
        supervisor = object.__new__(self.module.Supervisor)
        supervisor.timer_generation = 7
        supervisor._refresh_cache_policy_for_action = mock.Mock(return_value=False)
        supervisor._gate_reason = mock.Mock(side_effect=AssertionError("gate ran before refresh"))
        self.assertFalse(supervisor.attempt(expected_generation=7, purpose="compact"))
        supervisor._refresh_cache_policy_for_action.assert_called_once_with()
        supervisor._gate_reason.assert_not_called()

    def test_session_without_lifecycle_hooks_is_flagged_loudly(self):
        """No hook event after launch means the idle timer can never arm (2026-09-30)."""
        session = self.make_session(lifecycle_wait=1)
        alarm = session.root / "state" / "claude-idle-compaction" / f"{session.channel}.LIFECYCLE-HOOKS-MISSING"
        wait_until(lambda: (session.read_state() or {}).get("lifecycle_health") == "missing",
                   message="an unwired session was not flagged")
        state = session.read_state()
        self.assertEqual(state["last_state_transition"], "lifecycle-hooks-missing")
        self.assertTrue(alarm.is_file())
        self.assertEqual(json.loads(alarm.read_text())["channel"], session.channel)
        listed = subprocess.run([str(WARM), "--control", "list"], capture_output=True, text=True,
                                env=session.environment, timeout=10)
        self.assertIn("claude-hook-idle-event is not wired", listed.stderr)
        # A late first event (hooks fixed, or Claude got past a blocking prompt) clears it.
        session.event("session-start", transcript_path=str(session.transcript))
        self.assertEqual(session.read_state()["lifecycle_health"], "wired")
        self.assertFalse(alarm.exists())

    def test_channel_session_records_missing_lifecycle_hooks_in_guard_log(self):
        session = self.make_session(channel=True, spawn_channel=True, lifecycle_wait=1)
        wait_until(lambda: any(e.get("event") == "lifecycle-hooks-missing" for e in session.guard_events()),
                   message="the guard log did not record the unwired session")
        session.event("session-start", transcript_path=str(session.transcript))
        wait_until(lambda: any(e.get("event") == "lifecycle-hooks-recovered" for e in session.guard_events()),
                   message="the guard log did not record the recovery")

    def test_wired_session_is_never_flagged(self):
        session = self.make_session(lifecycle_wait=1)
        session.event("session-start", transcript_path=str(session.transcript))
        time.sleep(1.5)
        self.assertEqual(session.read_state()["lifecycle_health"], "wired")
        self.assertFalse(any(e.get("event") == "lifecycle-hooks-missing" for e in session.guard_events()))

    def test_herdr_registration_uses_supported_pane_contract(self):
        """The PTY owner reports logical identity and releases it cleanly."""
        root = pathlib.Path(tempfile.mkdtemp(prefix="cw-herdr-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        socket_path = root / "herdr.sock"
        requests = []
        stop = threading.Event()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        server.listen(8)
        server.setblocking(False)

        def serve():
            while not stop.is_set():
                ready, _, _ = select.select([server], [], [], 0.05)
                if not ready:
                    continue
                try:
                    connection, _ = server.accept()
                except OSError:
                    if stop.is_set():
                        return
                    raise
                with connection:
                    payload = connection.recv(8192).splitlines()[0]
                    requests.append(json.loads(payload.decode("utf-8")))
                    connection.sendall(b'{"result":{}}\n')

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(stop.set)
        self.addCleanup(server.close)
        with mock.patch.dict(
            os.environ,
            {
                "HERDR_ENV": "1",
                "HERDR_SOCKET_PATH": str(socket_path),
                "HERDR_PANE_ID": "w4:pP",
                "CLAUDE_WARM_HERDR_AGENT": "Fable",
            },
            clear=False,
        ):
            reporter = self.module.HerdrReporter()
            reporter.child_pid = 12345
            reporter.register("fixture-session")
            reporter.report_state("working", "fixture-session")
            reporter.report_state("idle", "fixture-session")
            reporter.release()
        wait_until(lambda: len(requests) >= 7, message="Herdr requests were not received")
        methods = [request["method"] for request in requests]
        self.assertIn("pane.report_agent_session", methods)
        self.assertIn("pane.report_agent", methods)
        self.assertIn("pane.report_metadata", methods)
        self.assertEqual(methods[-1], "pane.release_agent")
        self.assertNotIn("pane.report_agent", methods[:2])
        for request in requests:
            params = request["params"]
            self.assertEqual(params["pane_id"], "w4:pP")
            self.assertEqual(params["source"], "claude-warm")
            self.assertEqual(params["agent"], "Fable")
        metadata = next(
            request["params"]
            for request in requests
            if request["method"] == "pane.report_metadata"
        )
        self.assertEqual(metadata["display_agent"], "Fable")
        self.assertEqual(metadata["tokens"]["claude_pid"], "12345")
        self.assertEqual(metadata["tokens"]["pty_owner"], "claude-warm")

    def test_herdr_identity_labels_are_preserved_by_all_wrappers(self):
        wrappers = {
            "Opus": pathlib.Path.home() / "HelmCortex/FORGE/bin/claude-opus",
            "Fable": pathlib.Path.home() / "HelmCortex/FORGE/bin/claude-fable",
            "Auryn": pathlib.Path.home() / "HelmCortex/FORGE/bin/claude-auryn",
        }
        for label, wrapper in wrappers.items():
            if not wrapper.is_file():
                self.skipTest(f"wrapper is not present: {wrapper}")
            source = wrapper.read_text(encoding="utf-8")
            self.assertIn(f"CLAUDE_WARM_HERDR_AGENT={label}", source)
            self.assertIn("claude-warm", source)

    def test_herdr_reporter_is_inert_outside_herdr(self):
        with mock.patch.dict(
            os.environ,
            {"HERDR_ENV": "0", "CLAUDE_WARM_HERDR_AGENT": "Fable"},
            clear=False,
        ):
            reporter = self.module.HerdrReporter()
            self.assertFalse(reporter.enabled)
            reporter.register("fixture-session")
            reporter.report_state("working", "fixture-session")
            reporter.release()

    def test_claude_screen_classifier_mirrors_visible_detector_evidence(self):
        classifier = self.module.ClaudeScreenClassifier()
        self.assertEqual(classifier.feed(b"\x1b]0;Claude Code\x07"), "unknown")
        self.assertEqual(classifier.feed("\x1b[2K  ❯\n".encode()), "idle")
        self.assertEqual(
            classifier.feed("✻ Working… (esc to interrupt)\n".encode()),
            "working",
        )
        self.assertEqual(
            classifier.feed(
                "Do you want to proceed?\n❯ 1. Yes\n  2. No\nEsc to cancel\n".encode()
            ),
            "blocked",
        )
        self.assertEqual(
            classifier.feed("\x1b[2K────────────────\n❯\n".encode()),
            "idle",
        )
        classifier.reset()
        self.assertEqual(
            classifier.feed("✻ Crunched for 16m 38s\n\n❯\n".encode()),
            "idle",
        )

    def test_development_channel_recorded_prompt_accepts_opted_in_server_once(self):
        session = self.make_session(
            accept_dev_channels="server:mailcortex",
            extra_args=("--emit-dev-channel-prompt=server:mailcortex",),
        )
        session.wait_output("INPUT:b'\\n'")
        self.assertEqual(bytes(session.output).count(b"INPUT:b'\\n'"), 1)
        state = session.read_state()
        self.assertEqual(
            state["accepted_development_channels"], ["server:mailcortex"]
        )
        accepted = [
            event
            for event in session.guard_events()
            if event.get("event") == "development-channel-accepted"
        ]
        self.assertEqual(len(accepted), 1)
        self.assertEqual(accepted[0]["channels"], ["server:mailcortex"])

    def test_development_channel_prompt_without_opt_in_sends_no_enter(self):
        session = self.make_session(
            extra_args=("--emit-dev-channel-prompt=server:mailcortex",),
        )
        session.wait_output("Channels: server:mailcortex")
        time.sleep(0.2)
        self.assertNotIn(b"INPUT:", bytes(session.output))

    def test_development_channel_prompt_for_other_server_sends_no_enter(self):
        session = self.make_session(
            accept_dev_channels="server:mailcortex",
            extra_args=("--emit-dev-channel-prompt=server:other",),
        )
        session.wait_output("Channels: server:other")
        time.sleep(0.2)
        self.assertNotIn(b"INPUT:", bytes(session.output))

    def test_development_channel_prompt_after_startup_window_sends_no_enter(self):
        session = self.make_session(
            accept_dev_channels="server:mailcortex",
            dev_channel_accept_window=0.05,
            extra_args=(
                "--emit-dev-channel-prompt=server:mailcortex",
                "--dev-channel-prompt-delay=0.2",
            ),
        )
        session.wait_output("Channels: server:mailcortex")
        time.sleep(0.2)
        self.assertNotIn(b"INPUT:", bytes(session.output))

    def test_development_channel_prompt_repeated_sends_exactly_one_enter(self):
        session = self.make_session(
            accept_dev_channels="server:mailcortex",
            extra_args=(
                "--emit-dev-channel-prompt=server:mailcortex",
                "--repeat-dev-channel-prompt",
            ),
        )
        session.wait_output("INPUT:b'\\n'")
        time.sleep(0.2)
        session.output_contains(b"")
        self.assertEqual(bytes(session.output).count(b"INPUT:b'\\n'"), 1)

    def test_development_channel_altered_prompt_sends_no_enter(self):
        session = self.make_session(
            accept_dev_channels="server:mailcortex",
            extra_args=(
                "--emit-dev-channel-prompt=server:mailcortex",
                "--alter-dev-channel-prompt",
            ),
        )
        session.wait_output("Please use --channels to run approved channels.")
        time.sleep(0.2)
        self.assertNotIn(b"INPUT:", bytes(session.output))

    def test_development_channel_ansi_fragmented_prompt_still_accepts_once(self):
        session = self.make_session(
            accept_dev_channels="server:mailcortex",
            extra_args=(
                "--emit-dev-channel-prompt=server:mailcortex",
                "--fragment-dev-channel-prompt",
            ),
        )
        session.wait_output("INPUT:b'\\n'")
        self.assertEqual(bytes(session.output).count(b"INPUT:b'\\n'"), 1)

    def test_arguments_and_full_pty_submission(self):
        session = self.make_session(delay=0, extra_args=("--resume", "fixture", "--model", "test"))
        session.wait_output("ARGS:['--resume', 'fixture', '--model', 'test']")
        initial = session.read_state()
        self.assertRegex(initial["loaded_generation"], r"^[0-9a-f]{64}$")
        self.assertEqual(initial["loaded_generation"], initial["installed_generation"])
        self.assertTrue(initial["generation_loaded"])
        session.stop_and_bind()
        session.wait_output("COMPACT_RECEIVED")
        self.assertEqual(session.read_state()["compacting"], True)
        session.event("post-compact")
        wait_until(lambda: session.read_state() and not session.read_state()["dirty"])
        self.assertEqual(
            bytes(session.output).count(b"INPUT:b'/compact\\n'"),
            1,
        )
        state = session.read_state()
        self.assertIsNone(state["timer_deadline"])
        self.assertEqual(state["last_injection_result"], "succeeded")
        self.assertEqual(state["last_state_transition"], "compaction-completed")

    def test_later_normal_turn_arms_a_fresh_timer(self):
        session = self.make_session(delay=1)
        session.stop_and_bind()
        session.wait_output("COMPACT_RECEIVED", timeout=3)
        session.event("post-compact")
        wait_until(lambda: session.read_state() and not session.read_state()["dirty"])
        session.status(tokens=80000)
        session.event("user-prompt-submit")
        session.event("stop", stop_hook_active=False)
        wait_until(
            lambda: session.read_state()
            and session.read_state()["timer_deadline"] is not None,
            message="later normal turn did not arm a fresh timer",
        )
        self.assertTrue(session.read_state()["dirty"])

    def test_federation_automatic_trigger_uses_existing_owner_gate(self):
        session = self.make_session(delay=3300, preservation=True)
        session.stop_and_bind()
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_federation_last_result"] in {
                "directive-delivered", "accepted"
            },
            message="configured federation did not poll",
        )
        session.wait_output("COMPACT_RECEIVED")
        state = session.read_state()
        self.assertIn(state["preservation_state"], {"requested", "native_started"})
        self.assertEqual(state["preservation_federation_last_decision"], "request_native_preservation")
        self.assertFalse(state["preservation_federation_nudge_enabled"])

    def test_federation_estimate_scales_upward_from_live_context(self):
        client = self.module.PreservationFederationClient.__new__(
            self.module.PreservationFederationClient
        )
        client.config = {"estimate": 5.0}
        client.owner = mock.Mock(
            current_tokens=271672,
            current_model="Opus 4.8",
            post_compact_baseline_tokens=None,
        )
        self.assertEqual(client._scaled_estimate(), (3.0, True))
        client.owner.current_tokens = 500000
        self.assertEqual(client._scaled_estimate(), (5.0, True))
        client.owner.current_tokens = 1000000
        self.assertEqual(client._scaled_estimate(), (10.0, True))

    def test_federation_estimate_excludes_known_uncompactable_context(self):
        client = self.module.PreservationFederationClient.__new__(
            self.module.PreservationFederationClient
        )
        client.config = {"estimate": 4.0}
        client.owner = mock.Mock(
            current_tokens=self.module.MIN_TOKENS - 1,
            current_model="Opus 4.8",
            post_compact_baseline_tokens=None,
        )
        self.assertEqual(client._scaled_estimate(), (0.0, False))

    def test_federation_unknown_context_uses_full_conservative_estimate(self):
        client = self.module.PreservationFederationClient.__new__(
            self.module.PreservationFederationClient
        )
        client.config = {"estimate": 5.0}
        client.owner = mock.Mock(
            current_tokens=None,
            current_model=None,
            post_compact_baseline_tokens=None,
        )
        self.assertEqual(client._scaled_estimate(), (5.0, True))

    def test_federation_sonnet_uses_one_third_opus_weight(self):
        client = self.module.PreservationFederationClient.__new__(
            self.module.PreservationFederationClient
        )
        client.config = {"estimate": 5.0}
        client.owner = mock.Mock(
            current_tokens=300000,
            current_model="Sonnet 4.6",
            post_compact_baseline_tokens=None,
        )
        self.assertEqual(client._scaled_estimate(), (1.0, True))
        client.owner.current_model = "unknown-future-model"
        self.assertEqual(client._scaled_estimate(), (3.0, True))

    def test_federation_haiku_uses_one_third_sonnet_weight(self):
        client = self.module.PreservationFederationClient.__new__(
            self.module.PreservationFederationClient
        )
        client.config = {"estimate": 5.0}
        client.owner = mock.Mock(
            current_tokens=900000,
            current_model="Haiku 4.5",
            post_compact_baseline_tokens=None,
        )
        self.assertEqual(client._scaled_estimate(), (1.0, True))

    def test_federation_fable_model_costs_three_times_opus(self):
        client = self.module.PreservationFederationClient.__new__(
            self.module.PreservationFederationClient
        )
        client.config = {"estimate": 5.0}
        client.owner = mock.Mock(
            current_tokens=500000,
            current_model="claude-fable-5",
            post_compact_baseline_tokens=None,
        )
        self.assertEqual(client._scaled_estimate(), (15.0, True))

    def test_federation_excludes_latest_post_compact_baseline(self):
        client = self.module.PreservationFederationClient.__new__(
            self.module.PreservationFederationClient
        )
        client.config = {"estimate": 5.0}
        client.owner = mock.Mock(
            current_tokens=97000,
            current_model="Sonnet 4.6",
            post_compact_baseline_tokens=22666,
        )
        self.assertEqual(client._scaled_estimate(), (0.5, True))
        client.owner.current_tokens = 90000
        client.owner.post_compact_baseline_tokens = 25000
        self.assertEqual(client._scaled_estimate(), (0.0, False))

    def test_post_compact_loads_exact_transcript_baseline(self):
        session = self.make_session(delay=3300)
        session.event("session-start", transcript_path=str(session.transcript))
        with session.transcript.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({
                "type": "system",
                "subtype": "compact_boundary",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "compactMetadata": {"preTokens": 97465, "postTokens": 22666},
            }) + "\n")
        session.event("post-compact")
        state = session.read_state()
        self.assertEqual(state["post_compact_baseline_tokens"], 22666)
        self.assertIsNotNone(state["post_compact_baseline_at"])
        session.stop_and_bind()
        session.status(tokens=90000, model="Sonnet 4.6")
        session.control("trigger")
        wait_until(
            lambda: session.read_state()
            and session.read_state()["last_cancellation_reason"] == "below-token-threshold"
        )
        self.assertEqual(session.read_state()["unpreserved_context_tokens"], 67334)

    def test_slow_bridge_does_not_block_owner_ipc_progress(self):
        session = self.make_session(delay=3300, preservation=True, preservation_mode="slow")
        session.stop_and_bind()
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_federation_poll_in_flight"],
            message="slow bridge did not enter flight",
        )
        started = time.monotonic()
        response = session.control("state")
        elapsed = time.monotonic() - started
        self.assertTrue(response["ok"])
        self.assertLess(elapsed, 0.5)
        session.status(tokens=81234)
        session.submit_local_byte(b"ping\n")
        session.wait_output("INPUT:b'ping\\n'")
        snapshot = json.loads((session.state_path.parent / "status.json").read_text())
        self.assertEqual(snapshot["current_input_context_tokens"], 81234)

    def test_slow_bridge_allows_only_one_poll_in_flight(self):
        session = self.make_session(delay=3300, preservation=True, preservation_mode="slow")
        session.stop_and_bind()
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_federation_poll_in_flight"],
            message="slow bridge did not enter flight",
        )
        time.sleep(0.4)
        self.assertEqual(len(session.preservation_calls.read_text(encoding="utf-8").splitlines()), 1)

    def test_federation_stale_telemetry_fails_closed_without_injection(self):
        session = self.make_session(delay=3300, preservation=True, preservation_mode="stale")
        session.stop_and_bind()
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_federation_last_result"] == "failed-closed",
            message="stale telemetry was not rejected",
        )
        self.assertEqual(session.read_state()["preservation_federation_last_error"], "telemetry-refresh-required")
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_federation_unavailable_authority_fails_closed_without_injection(self):
        session = self.make_session(delay=3300, preservation=True, preservation_mode="unavailable")
        session.stop_and_bind()
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_federation_last_error"] == "bridge-exit-78",
            message="unavailable authority was not recorded",
        )
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_federation_malformed_output_fails_closed_without_injection(self):
        session = self.make_session(delay=3300, preservation=True, preservation_mode="malformed")
        session.stop_and_bind()
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_federation_last_error"] == "invalid-bridge-response",
            message="malformed bridge output was not rejected",
        )
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_federation_timeout_fails_closed_without_injection(self):
        session = self.make_session(delay=3300, preservation=True, preservation_mode="slow")
        session.stop_and_bind()
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_federation_last_error"] == "bridge-timeout",
            timeout=3,
            message="bridge timeout was not recorded",
        )
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_federation_wrong_contract_fails_closed_without_injection(self):
        session = self.make_session(delay=3300, preservation=True, preservation_mode="wrong-contract")
        session.stop_and_bind()
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_federation_last_error"] == "invalid-bridge-contract",
            message="wrong bridge contract was not rejected",
        )
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_federation_replay_delivers_one_request_id_idempotently(self):
        session = self.make_session(delay=3300, preservation=True)
        session.stop_and_bind()
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_state"] in {"requested", "native_started"},
            message="first preservation directive was not delivered",
        )
        session.wait_output("COMPACT_RECEIVED")
        first = len(session.preservation_calls.read_text(encoding="utf-8").splitlines())
        wait_until(
            lambda: len(session.preservation_calls.read_text(encoding="utf-8").splitlines()) > first,
            message="replay poll did not reach bridge",
        )
        self.assertEqual(session.read_state()["preservation_request_id"], "preserve-test-request")
        self.assertEqual(bytes(session.output).count(b"COMPACT_RECEIVED"), 1)

    def test_federation_busy_owner_waits_for_validated_stop(self):
        session = self.make_session(delay=3300, preservation=True)
        session.event("session-start", transcript_path=str(session.transcript))
        session.status(tokens=80000)
        session.event("stop", stop_hook_active=False)
        session.event("user-prompt-submit")
        wait_until(lambda: session.read_state() and session.read_state()["status"] == "active")
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_state"] == "requested",
            message="busy owner did not queue preservation",
        )
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))
        session.status(tokens=80000)
        session.event("stop", stop_hook_active=False)
        session.wait_output("COMPACT_RECEIVED")

    def test_federation_native_completion_is_reported_after_post_compact(self):
        session = self.make_session(delay=3300, preservation=True)
        session.stop_and_bind()
        session.wait_output("COMPACT_RECEIVED")
        session.event("post-compact")
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_state"] == "native_completed",
            message="native completion was not persisted",
        )
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_federation_last_decision"] == "admit_work",
            message="completed native state was not reconciled with federation",
        )
        state = session.read_state()
        self.assertFalse(state["dirty"])
        self.assertTrue(state["preservation_federation_generation_loaded"])

    def test_unconfigured_federation_is_inert(self):
        session = self.make_session(delay=3300)
        session.stop_and_bind()
        time.sleep(0.2)
        state = session.read_state()
        self.assertFalse(state["preservation_federation_enabled"])
        self.assertIsNone(state["preservation_federation_next_poll_monotonic"])
        self.assertIsNone(state["preservation_federation_last_poll_at"])
        self.assertIsNone(state["preservation_federation_last_result"])
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_disabled_federation_does_not_spin_or_create_poll_deadline(self):
        session = self.make_session(delay=3300)
        owner = self.module.PreservationFederationClient.__new__(
            self.module.PreservationFederationClient
        )
        owner.enabled = False
        owner.next_poll = None
        owner.bridge_thread = None
        owner.bridge_result = None
        calls = 0

        def fake_failure(_reason):
            nonlocal calls
            calls += 1

        owner._failure = fake_failure
        for _ in range(10000):
            self.module.PreservationFederationClient.poll(owner)
        self.assertEqual(calls, 0)
        self.assertIsNone(owner.next_poll)
        self.assertIsNone(owner.bridge_thread)
        self.assertIsNone(session.read_state()["preservation_federation_next_poll_monotonic"])

    def test_last_session_record_survives_exit(self):
        # The runtime dir is removed at exit; the label-keyed record under
        # XDG_STATE_HOME is what nurse-joy resumes a fainted bot from.
        with mock.patch.dict(os.environ, {"CLAUDE_WARM_HERDR_AGENT": "TestBot"}, clear=False):
            session = self.make_session(delay=30, channel=True)
        session.stop_and_bind()
        record_path = session.root / "state" / "claude-idle-compaction" / "last-session.TestBot.json"
        wait_until(lambda: record_path.exists(), message="last-session record not written on bind")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(record["session_id"], session.session_id)
        self.assertEqual(record["agent"], "TestBot")
        self.assertEqual(record["event"], "session-bound")
        channel_path = session.root / "state" / "claude-idle-compaction" / f"{session.read_state()['channel']}.last-session.json"
        self.assertTrue(channel_path.exists())
        session.event("session-end")
        if session.process.stdin is not None:
            session.process.stdin.close()
        session.process.wait(timeout=10)
        self.assertEqual(json.loads(record_path.read_text(encoding="utf-8"))["event"], "supervisor-exit")

        # A nested one-shot claude inherits the supervisor's control-socket
        # env; its lifecycle hooks arrive here from another project directory
        # and must not steal the binding or end the governor (the 2026-08-20
        # overnight no-compact).  channel=True so the guard log exists: the
        # test only ever passed when it inherited CLAUDE_IDLE_WATCHED_SERVERS
        # from a supervised parent session.
        session = self.make_session(delay=30, channel=True)
        session.stop_and_bind()
        foreign_id = "one-shot-session"
        foreign_transcript = session.root / "foreign-project" / f"{foreign_id}.jsonl"
        response = session.event(
            "session-start",
            session_id=foreign_id,
            transcript_path=str(foreign_transcript),
        )
        self.assertEqual(response.get("ignored"), "foreign-session")
        self.assertEqual(session.read_state()["session_id"], session.session_id)
        response = session.event("session-end", session_id=foreign_id)
        self.assertEqual(response.get("error"), "session-mismatch")
        session.status(tokens=80000)
        session.event("user-prompt-submit")
        session.event("stop", stop_hook_active=False)
        wait_until(
            lambda: session.read_state()
            and session.read_state()["timer_deadline"] is not None,
            message="real session did not arm after a foreign session-start",
        )
        self.assertTrue(
            any(
                entry.get("event") == "foreign-session-ignored"
                for entry in session.guard_events()
            )
        )

    def test_rejected_compaction_clears_transient_flag_without_rearm(self):
        session = self.make_session(delay=0)
        session.stop_and_bind()
        session.wait_output("COMPACT_RECEIVED")
        self.assertTrue(session.read_state()["compacting"])
        session.append_transcript({
            "type": "system",
            "subtype": "local_command",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() + 1)),
            "content": "Not enough messages to compact.",
        })
        wait_until(
            lambda: session.read_state()
            and not session.read_state()["compacting"]
            and session.read_state()["last_cancellation_reason"] == "compaction-failed"
        )
        self.assertTrue(session.read_state()["dirty"])
        session.event("stop", stop_hook_active=False)
        time.sleep(0.2)
        self.assertIsNone(session.read_state()["timer_deadline"])
        self.assertEqual(bytes(session.output).count(b"COMPACT_RECEIVED"), 1)

    def test_rejected_preservation_compaction_persists_recovery(self):
        session = self.make_session(delay=3300, channel=True)
        session.stop_and_bind()
        state = session.read_state()
        response = session.control(
            "preserve",
            request_id="preserve-rejected",
            reservation_id="reserve-rejected",
            expected_session_id=session.session_id,
            expected_supervisor_pid=state["supervisor_pid"],
            expected_epoch=state["completed_turn_epoch"],
        )
        self.assertTrue(response["ok"])
        session.wait_output("COMPACT_RECEIVED")
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_state"] == "native_started"
        )
        session.append_transcript({
            "type": "system",
            "subtype": "local_command",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() + 1)),
            "content": "Not enough messages to compact.",
        })
        wait_until(
            lambda: session.read_state()
            and session.read_state()["preservation_state"] == "pending_recovery"
        )
        state = session.read_state()
        self.assertEqual(state["preservation_failure"], "transcript-rejected")
        self.assertFalse(state["compacting"])

    def test_stop_failure_clears_compacting_and_preserves_dirty(self):
        # A stop-failure with a living child must not leave the loop unarmed:
        # the 2026-08-26 4091 afternoon showed a cancelled compaction waiting
        # hours for activity.  Contract: compacting cleared, dirty preserved,
        # status back to idle, and a retry timer re-armed.
        session = self.make_session(delay=0)
        session.stop_and_bind()
        session.wait_output("COMPACT_RECEIVED")
        session.event("stop-failure")
        wait_until(
            lambda: session.read_state()
            and not session.read_state()["compacting"]
            and session.read_state()["status"] == "idle"
            and session.read_state()["timer_deadline"] is not None
        )
        state = session.read_state()
        self.assertTrue(state["dirty"])
        self.assertEqual(state["last_rearm_reason"], "stop-failure-retry")

    def test_resize_signal_reaches_child(self):
        session = self.make_session(terminal=True)
        session.wait_output("SIZE:")
        session.set_size(55, 123)
        session.process.send_signal(signal.SIGWINCH)
        # The supervisor owns the child PTY.  The changed size must reach the
        # fake child through its SIGWINCH handler.
        session.wait_output("SIZE:55x123")

    def test_local_keystroke_cancels(self):
        session = self.make_session(delay=1)
        session.stop_and_bind()
        session.submit_local_byte(b"draft")
        try:
            wait_until(lambda: session.read_state() and session.read_state()["last_cancellation_reason"] == "user-input")
        except AssertionError as error:
            raise AssertionError(f"{error}; state={session.read_state()!r}; output={bytes(session.output)!r}") from error
        time.sleep(1.3)
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_terminal_protocol_traffic_does_not_cancel_timer(self):
        session = self.make_session(delay=2, terminal=True, channel=True)
        session.wait_output("ARGS:")
        session.wait_output("SIZE:")
        session.stop_and_bind()
        protocol = (
            b"\x1b[<35;10;20M",
            b"\x1b[<35;11;21m",
            b"\x1b[M" + bytes((35, 10, 20)),
            b"\x1b[I",
            b"\x1b[O",
            b"\x1b[12;34R",
            b"\x1b[6n",
            b"\x1b[?1;2c",
            b"\x1b[>0;95;0c",
            b"\x1b]10;rgb:ffff/ffff/ffff\x07",
        )
        for sequence in protocol:
            session.submit_local_byte(sequence)
        session.submit_local_byte(b"\x1b[<35;10;")
        session.submit_local_byte(b"20M")
        session.set_size(55, 123)
        session.process.send_signal(signal.SIGWINCH)
        wait_until(
            lambda: {
                kind
                for event in session.guard_events()
                if event.get("event") == "terminal-input"
                for kind in event.get("classifications", {})
            }
            >= {
                "sgr-mouse-report",
                "focus-report",
                "cursor-position-report",
                "device-status-report",
                "device-attribute-report",
            },
            message="terminal protocol bytes were not classified",
        )
        self.assertEqual(session.read_state().get("timer_kind"), "compact")
        self.assertNotEqual(session.read_state()["last_cancellation_reason"], "user-input")
        self.assertFalse(
            any(
                event.get("reason") == "user-input"
                for event in session.guard_events()
                if event.get("event") == "cancelled"
            )
        )
        terminal_events = [
            event for event in session.guard_events() if event.get("event") == "terminal-input"
        ]
        classifications = {
            kind
            for event in terminal_events
            for kind in event.get("classifications", {})
        }
        self.assertIn("sgr-mouse-report", classifications)
        self.assertIn("focus-report", classifications)
        self.assertIn("cursor-position-report", classifications)
        self.assertIn("device-status-report", classifications)
        self.assertIn("device-attribute-report", classifications)
        debug_path = pathlib.Path(session.read_state()["channel_debug_log"])
        self.assertNotIn("35;10;20", debug_path.read_text(encoding="utf-8"))
        self.assertNotIn(b"[claude-warm]", bytes(session.output))

    def test_bracketed_paste_framing_is_protocol_but_payload_cancels_once(self):
        session = self.make_session(delay=2, channel=True)
        session.stop_and_bind()
        session.submit_local_byte(b"\x1b[200")
        session.submit_local_byte(b"~")
        session.submit_local_byte(b"\x1b[201")
        session.submit_local_byte(b"~")
        wait_until(
            lambda: session.read_state()
            and session.read_state().get("timer_kind") == "compact",
            message="bracketed-paste framing cancelled the timer",
        )
        session.submit_local_byte(b"\x1b[200~pasted text\x1b[201~")
        wait_until(
            lambda: sum(
                event.get("reason") == "user-input"
                for event in session.guard_events()
                if event.get("event") == "cancelled"
            ) == 1,
            message="bracketed-paste payload did not cancel once",
        )
        session.submit_local_byte(b"more pasted text")
        time.sleep(0.1)
        self.assertEqual(
            sum(
                event.get("reason") == "user-input"
                for event in session.guard_events()
                if event.get("event") == "cancelled"
            ),
            1,
        )

    def test_keyboard_variants_cancel_once(self):
        keyboard_inputs = (
            b"x",
            "é".encode("utf-8"),
            b"\x7f",
            b"\r",
            b"\x1b",
            b"\x1b[A",
            b"\x1b[3~",
            b"\x1b[97;1u",
            b"\x1b[57361;1;9u",
        )
        for payload in keyboard_inputs:
            session = self.make_session(delay=30, channel=True)
            session.stop_and_bind()
            session.submit_local_byte(payload)
            wait_until(
                lambda: sum(
                    event.get("reason") == "user-input"
                    for event in session.guard_events()
                    if event.get("event") == "cancelled"
                ) == 1,
                message=f"keyboard input was not classified as human: {payload!r}",
            )
            session.submit_local_byte(payload)
            time.sleep(0.1)
            self.assertEqual(
                sum(
                    event.get("reason") == "user-input"
                    for event in session.guard_events()
                    if event.get("event") == "cancelled"
                ),
                1,
            )

    def test_claude_output_and_resize_do_not_count_as_input(self):
        session = self.make_session(
            delay=2,
            terminal=True,
            channel=True,
            extra_args=("--emit-terminal-modes",),
        )
        session.wait_output("ARGS:")
        session.stop_and_bind()
        session.set_size(48, 111)
        session.process.send_signal(signal.SIGWINCH)
        wait_until(
            lambda: session.read_state()
            and session.read_state().get("timer_kind") == "compact",
            message="Claude output or resize cancelled the timer",
        )
        self.assertNotIn(b"[claude-warm]", bytes(session.output))

    def test_terminal_state_is_restored_after_supervisor_exit(self):
        session = self.make_session(terminal=True, extra_args=("--emit-terminal-modes",))
        baseline = session.outer_tty_baseline
        session.wait_output("ARGS:")
        session.close()
        self.assertEqual(session.outer_tty_after, baseline)
        self.assertIn(b"\x1b[?1000l", bytes(session.output))
        self.assertIn(b"\x1b[?1004l", bytes(session.output))
        self.assertNotIn(b"\x1b[?1049l", bytes(session.output))

    def test_unicode_and_paste_bytes_proxy_through_pty(self):
        session = self.make_session(terminal=True)
        session.wait_output("ARGS:")
        session.submit_local_byte("héllo pasted\nsecond line\n".encode("utf-8"))
        first_chunk = b"INPUT:b'h\\xc3\\xa9llo pasted\\n'"
        second_chunk = b"INPUT:b'second line\\n'"
        wait_until(
            lambda: session.output_contains("")
            and first_chunk in bytes(session.output)
            and second_chunk in bytes(session.output),
            message="Unicode/paste bytes did not reach the fake PTY child",
        )

    def test_transcript_append_cancels(self):
        session = self.make_session(delay=1)
        session.stop_and_bind()
        # The production transcript is JSONL; a complete non-attachment entry
        # represents remote/channel activity without putting message content in
        # the supervisor log.
        session.append_transcript(
            {
                "type": "user",
                "timestamp": time.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 1)
                ),
            }
        )
        wait_until(lambda: session.read_state() and session.read_state()["last_cancellation_reason"] == "transcript-activity")
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_delayed_away_summary_does_not_cancel_or_move_deadline(self):
        """The exact delayed recap record is not a new user/channel turn."""
        session = self.make_session(delay=3300, ttl=3600, channel=True)
        session.stop_and_bind()
        armed = session.read_state()
        deadline = armed["timer_deadline"]
        self.assertEqual(armed["timer_kind"], "compact")
        self.assertEqual(armed["cache_profile"], "long")
        self.assertAlmostEqual(
            deadline - armed["last_normal_stop"], 3300.0, places=2
        )
        simulated_delayed_record_at = armed["last_normal_stop"] + 185.644
        self.assertLess(simulated_delayed_record_at, deadline)
        session.append_transcript(AWAY_SUMMARY_FIXTURE)
        wait_until(
            lambda: session.read_state()
            and session.read_state()["last_transcript_classification"] == "internal-recap"
        )
        state = session.read_state()
        self.assertEqual(state["timer_kind"], "compact")
        self.assertAlmostEqual(state["timer_deadline"], deadline, places=3)
        self.assertFalse(state["transcript_gate_blocked"])
        self.assertEqual(
            len(
                [
                    event
                    for event in session.guard_events()
                    if event.get("event") == "armed" and event.get("kind") == "compact"
                ]
            ),
            1,
        )
        self.assertFalse(
            any(
                event.get("reason") == "transcript-activity"
                for event in session.guard_events()
                if event.get("event") == "cancelled"
            )
        )
        away_events = [
            event
            for event in session.guard_events()
            if event.get("event") == "transcript-record-ignored"
            and event.get("record_type") == "system"
            and event.get("record_subtype") == "away_summary"
        ]
        self.assertEqual(len(away_events), 1)
        self.assertEqual(away_events[0]["classification"], "internal-recap")

    def test_former_140_second_acceptance_predates_delayed_summary(self):
        """The old accelerated test fired before the observed +185.644s recap."""
        self.assertLess(140.0, 185.644)
        session = self.make_session(delay=0, ttl=300)
        session.stop_and_bind()
        session.wait_output("COMPACT_RECEIVED", timeout=3)
        self.assertEqual(bytes(session.output).count(b"INPUT:b'/compact\\n'"), 1)
        session.event("post-compact")
        wait_until(lambda: session.read_state() and not session.read_state()["dirty"])
        session.append_transcript(AWAY_SUMMARY_FIXTURE)
        time.sleep(0.2)
        self.assertEqual(bytes(session.output).count(b"INPUT:b'/compact\\n'"), 1)
        self.assertFalse(session.read_state()["compacting"])

    def test_internal_transcript_records_do_not_cancel_or_slide_deadline(self):
        session = self.make_session(delay=5)
        session.stop_and_bind()
        deadline = session.read_state()["timer_deadline"]
        records = [
            AWAY_SUMMARY_FIXTURE,
            {"type": "system", "subtype": "channel_send_failure"},
            {"type": "system", "subtype": "channel_send_retry"},
            {"type": "progress"},
            {"type": "status"},
            {"type": "queue-operation"},
            {"type": "file-history-snapshot"},
            {"type": "summary"},
            {"type": "user", "isMeta": True, "isSidechain": False},
            {"type": "assistant"},
        ]
        for record in records:
            session.append_transcript(record)
        wait_until(
            lambda: session.read_state()
            and session.read_state()["last_transcript_classification"] == "assistant-output"
        )
        state = session.read_state()
        self.assertEqual(state["timer_kind"], "compact")
        self.assertAlmostEqual(state["timer_deadline"], deadline, places=3)
        self.assertFalse(state["transcript_gate_blocked"])
        self.assertNotEqual(state["last_cancellation_reason"], "transcript-activity")

    def test_split_and_malformed_transcript_records_block_only_the_final_gate(self):
        session = self.make_session(delay=5)
        session.stop_and_bind()
        deadline = session.read_state()["timer_deadline"]
        encoded = json.dumps(AWAY_SUMMARY_FIXTURE).encode()
        with session.transcript.open("ab") as stream:
            stream.write(encoded[: len(encoded) // 2])
        time.sleep(0.2)
        state = session.read_state()
        self.assertIsNone(state["last_transcript_classification"])
        self.assertEqual(state["timer_deadline"], deadline)
        with session.transcript.open("ab") as stream:
            stream.write(encoded[len(encoded) // 2 :] + b"\n")
        wait_until(
            lambda: session.read_state()
            and session.read_state()["last_transcript_classification"] == "internal-recap"
        )
        with session.transcript.open("a", encoding="utf-8") as stream:
            stream.write("{malformed-json}\n[]\n")
        wait_until(
            lambda: session.read_state()
            and session.read_state()["transcript_gate_blocked"]
        )
        state = session.read_state()
        self.assertEqual(state["timer_deadline"], deadline)
        result = session.control("trigger")
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"]["last_gate_rejection_reason"], "transcript-uncertain")
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_final_assistant_flush_does_not_cancel_idle_timer(self):
        session = self.make_session(delay=1)
        session.stop_and_bind(wait_quiescence=False)
        session.append_transcript(
            {
                "type": "assistant",
                "timestamp": time.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() + 1)
                ),
            }
        )
        wait_until(
            lambda: session.read_state()
            and session.read_state()["timer_deadline"] is not None,
            message="final assistant flush cancelled the timer",
        )
        self.assertNotEqual(session.read_state()["last_cancellation_reason"], "transcript-activity")
        session.wait_output("COMPACT_RECEIVED", timeout=3)

    def test_stop_bookkeeping_does_not_cancel_idle_timer(self):
        session = self.make_session(delay=1)
        session.stop_and_bind()
        session.append_transcript({"type": "system", "subtype": "stop_hook_summary"})
        session.append_transcript({"type": "system", "subtype": "turn_duration"})
        session.append_transcript({"type": "last-prompt"})
        session.append_transcript({"type": "mode"})
        session.append_transcript({"type": "permission-mode"})
        session.append_transcript({"type": "ai-title"})
        time.sleep(0.2)
        state = session.read_state()
        self.assertIsNotNone(state["timer_deadline"])
        self.assertNotEqual(state["last_cancellation_reason"], "transcript-activity")
        session.wait_output("COMPACT_RECEIVED", timeout=3)

    def test_new_user_record_cancels_even_with_coarse_timestamp(self):
        session = self.make_session(delay=1)
        session.stop_and_bind(wait_quiescence=False)
        session.append_transcript(
            {
                "type": "user",
                "channel": "telegram",
                "timestamp": time.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 1)
                ),
            }
        )
        wait_until(
            lambda: session.read_state()
            and session.read_state()["last_cancellation_reason"] == "transcript-activity"
        )
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_channel_prompt_event_cancels(self):
        session = self.make_session(delay=1)
        session.stop_and_bind()
        session.event("user-prompt-submit")
        wait_until(lambda: session.read_state() and session.read_state()["last_cancellation_reason"] == "prompt-submit")
        time.sleep(1.3)
        self.assertFalse(session.output_contains("COMPACT_RECEIVED"))

    def test_snapshot_before_turn_and_session_mismatch_block(self):
        session = self.make_session(delay=30)
        session.stop_and_bind()
        session.status(timestamp=time.time() - 120)
        session.control("trigger")
        wait_until(lambda: session.read_state() and session.read_state()["last_cancellation_reason"] == "status-snapshot-before-stop")
        session.status(session_id="replacement-session")
        session.control("trigger")
        wait_until(lambda: session.read_state() and session.read_state()["last_cancellation_reason"] == "status-session-mismatch")

    def test_end_of_turn_snapshot_remains_valid_after_idle_delay(self):
        loader = importlib.machinery.SourceFileLoader("claude_warm_fixture", str(WARM))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        root = pathlib.Path(tempfile.mkdtemp(prefix="cw-snapshot", dir="/tmp"))
        try:
            snapshot = root / "status.json"
            snapshot.write_text(
                json.dumps(
                    {
                        "channel": "claude-" + "a" * 32,
                        "session_id": "fixture-session",
                        "current_input_context_tokens": 210000,
                        "update_timestamp": 1000.5,
                    }
                ),
                encoding="utf-8",
            )
            supervisor = object.__new__(module.Supervisor)
            supervisor.snapshot_path = snapshot
            supervisor.channel = "claude-" + "a" * 32
            supervisor.session_id = "fixture-session"
            supervisor.last_normal_stop = 1000.0
            supervisor.completed_turn_epoch = 4
            supervisor.current_tokens = None
            supervisor.status_timestamp = None
            supervisor.status_snapshot_epoch = None
            with mock.patch.object(module, "now", return_value=4600.0):
                payload, error = supervisor._read_snapshot()
            self.assertIsNone(error)
            self.assertEqual(payload["current_input_context_tokens"], 210000)
            self.assertEqual(supervisor.status_snapshot_epoch, 4)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_pty_ownership_uses_device_identity_across_path_aliases(self):
        loader = importlib.machinery.SourceFileLoader("claude_warm_pty_identity", str(WARM))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        supervisor = object.__new__(module.Supervisor)
        supervisor.pid = 4242
        supervisor.master_fd = 9
        supervisor.child_tty = None
        supervisor.child_tty_device = None
        with mock.patch.object(module, "child_alive", return_value=True), mock.patch.object(
            module.os, "getpgid", return_value=4242
        ), mock.patch.object(
            supervisor, "_read_child_tty_device", return_value=34833
        ), mock.patch.object(
            supervisor, "_read_child_tty", return_value="/dev/pts/17"
        ):
            self.assertIsNone(supervisor._pty_ownership_failure())
        self.assertEqual(supervisor.child_tty, "/dev/pts/17")
        self.assertEqual(supervisor.child_tty_device, 34833)

        # Once bound, an alias pathname is display-only while the device
        # identity remains the ownership invariant.
        supervisor.child_tty = "/dev/pts/0"
        supervisor.child_tty_device = 34833
        with mock.patch.object(module, "child_alive", return_value=True), mock.patch.object(
            module.os, "getpgid", return_value=4242
        ), mock.patch.object(
            supervisor, "_read_child_tty_device", return_value=34833
        ), mock.patch.object(
            supervisor, "_read_child_tty", return_value="/dev/pts/17"
        ):
            self.assertIsNone(supervisor._pty_ownership_failure())
        self.assertEqual(supervisor.child_tty, "/dev/pts/17")
        with mock.patch.object(module, "child_alive", return_value=True), mock.patch.object(
            module.os, "getpgid", return_value=4242
        ), mock.patch.object(
            supervisor, "_read_child_tty_device", return_value=34834
        ):
            self.assertEqual(supervisor._pty_ownership_failure(), "stdin-not-pty")

    def test_production_defaults_and_resolver_rejects_wrapper(self):
        loader = importlib.machinery.SourceFileLoader("claude_warm_defaults", str(WARM))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.IDLE_SECONDS["long"], 55 * 60)
        self.assertEqual(module.TTL_SECONDS["long"], 60 * 60)
        self.assertEqual(module.MIN_TOKENS, 70000)
        root = pathlib.Path(tempfile.mkdtemp(prefix="cw-resolver", dir="/tmp"))
        try:
            with mock.patch.dict(
                os.environ,
                {"CLAUDE_IDLE_REAL_EXECUTABLE": str(WARM)},
                clear=False,
            ), mock.patch.object(module.shutil, "which", return_value=str(WARM)), mock.patch.object(
                module.pathlib.Path, "home", return_value=root
            ):
                with self.assertRaises(RuntimeError):
                    module.resolve_claude()
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_canonical_fable_telegram_launcher_delegates_to_supervisor(self):
        launcher = pathlib.Path(
            os.environ.get(
                "CLAUDE_IDLE_FABLE_LAUNCHER",
                str(pathlib.Path.home() / "HelmCortex/FORGE/bin/claude-fable"),
            )
        )
        if not launcher.is_file():
            self.skipTest("the machine-local Fable launcher is not present")
        source = launcher.read_text(encoding="utf-8")
        self.assertIn("Usage: claude-fable [--telegram]", source)
        self.assertIn("claude-warm --model", source)
        self.assertIn("--channels plugin:telegram@claude-plugins-official", source)

    def test_below_threshold_is_dormant_and_cold_cache_still_compacts(self):
        session = self.make_session(delay=30, ttl=1, channel=True)
        session.stop_and_bind()
        session.status(tokens=69999)
        session.control("trigger")
        wait_until(lambda: session.read_state() and session.read_state()["last_cancellation_reason"] == "below-token-threshold")
        self.assertEqual(session.read_state()["last_gate_rejection_reason"], "below-token-threshold")
        refusal = [
            event for event in session.guard_events()
            if event.get("event") == "gate-refused"
            and event.get("reason") == "below-token-threshold"
        ]
        self.assertEqual(len(refusal), 1)
        self.assertFalse(refusal[0]["transient"])
        self.assertEqual(session.read_state()["rearm_count"], 0)
        time.sleep(1.2)
        session.status(tokens=80000)
        # Ruling 2026-08-21: an expired warm-cache TTL no longer vetoes the
        # compaction; it is only recorded on the request.
        session.control("trigger")
        session.wait_output("COMPACT_RECEIVED")
        requested = [
            event for event in session.guard_events()
            if event.get("event") == "compaction-requested"
        ]
        self.assertEqual(len(requested), 1)
        self.assertEqual(requested[0]["cache"], "cold")
        self.assertFalse(requested[0]["queued_behind_turn"])

    def test_keystroke_rearms_and_compacts_after_idle_window(self):
        # The 2026-08-20 Opus overnight: one keystroke at 22:33 cancelled the
        # armed timer and nothing re-armed it until the morning.
        session = self.make_session(delay=1, retry=1, channel=True)
        session.stop_and_bind()
        session.submit_local_byte(b"x")
        wait_until(
            lambda: session.read_state()
            and session.read_state()["last_rearm_reason"] == "user-input"
            and session.read_state()["timer_deadline"] is not None,
            message="keystroke did not re-arm the timer",
        )
        self.assertEqual(session.read_state()["last_cancellation_reason"], "user-input")
        rearmed = [e for e in session.guard_events() if e.get("event") == "rearmed"]
        self.assertEqual(len(rearmed), 1)
        self.assertEqual(rearmed[0]["reason"], "user-input")
        # A second keystroke slides the window quietly: no second cancel/rearm.
        session.submit_local_byte(b"y")
        time.sleep(0.2)
        self.assertEqual(
            sum(1 for e in session.guard_events() if e.get("event") in {"rearmed", "cancelled"} and e.get("reason") == "user-input"),
            2,
        )
        session.wait_output("COMPACT_RECEIVED", timeout=4)
        requested = [e for e in session.guard_events() if e.get("event") == "compaction-requested"]
        self.assertEqual(requested[-1]["cache"], "warm")

    def test_live_turn_does_not_veto_after_idle_window(self):
        # The 2026-08-20 Fable overnight, generalized: activity cancels once,
        # re-arms, and a turn that never reaches Stop still gets its /compact
        # queued behind it once the idle window has passed.
        session = self.make_session(delay=1, retry=1, channel=True)
        session.stop_and_bind()
        session.event("session-activity")
        wait_until(
            lambda: session.read_state()
            and session.read_state()["status"] == "active"
            and session.read_state()["last_rearm_reason"] == "session-activity",
            message="mid-turn activity did not re-arm",
        )
        # Inside the idle window the gate still refuses, transiently.
        session.control("trigger")
        refusals = [
            e for e in session.guard_events()
            if e.get("event") == "gate-refused" and e.get("reason") == "session-active"
        ]
        self.assertEqual(len(refusals), 1)
        self.assertTrue(refusals[0]["transient"])
        self.assertIsNotNone(session.read_state()["timer_deadline"])
        session.wait_output("COMPACT_RECEIVED", timeout=4)
        requested = [e for e in session.guard_events() if e.get("event") == "compaction-requested"]
        self.assertTrue(requested[-1]["queued_behind_turn"])
        # The running turn's Stop is consumed as the compaction's Stop and
        # PostCompact closes the cycle as usual.
        session.event("stop", stop_hook_active=False)
        session.event("post-compact")
        wait_until(lambda: session.read_state() and not session.read_state()["dirty"])

    def test_transient_gate_refusal_rearms_but_dormant_does_not(self):
        session = self.make_session(delay=1, retry=1, channel=True)
        session.stop_and_bind()
        # Snapshot missing at fire time is transient: the timer re-arms.
        (session.state_path.parent / "status.json").unlink()
        wait_until(
            lambda: any(
                e.get("event") == "gate-refused" and e.get("reason") == "status-snapshot-missing"
                for e in session.guard_events()
            ),
            timeout=4,
        )
        wait_until(
            lambda: session.read_state()
            and session.read_state()["last_rearm_reason"] == "gate-refused:status-snapshot-missing"
            and session.read_state()["timer_deadline"] is not None,
            message="transient refusal did not re-arm",
        )
        session.status(tokens=80000)
        session.wait_output("COMPACT_RECEIVED", timeout=4)

    def test_compaction_timeout_clears_latch_and_rearms(self):
        session = self.make_session(delay=0, retry=1, compact_timeout=1, channel=True)
        session.stop_and_bind()
        session.wait_output("COMPACT_RECEIVED")
        self.assertTrue(session.read_state()["compacting"])
        wait_until(
            lambda: any(
                e.get("event") == "compaction-failed" and e.get("reason") == "timeout"
                for e in session.guard_events()
            ),
            timeout=4,
            message="lost compaction was not timed out",
        )
        wait_until(lambda: session.read_state() and not session.read_state()["compacting"])
        self.assertTrue(session.read_state()["dirty"])
        self.assertEqual(session.read_state()["last_rearm_reason"], "compaction-timeout")
        wait_until(
            lambda: session.output_contains(b"COMPACT_RECEIVED")
            and bytes(session.output).count(b"COMPACT_RECEIVED") >= 2,
            timeout=5,
            message="timed-out compaction was not retried",
        )
        # The retry's real Stop is not swallowed: PostCompact closes normally.
        session.event("post-compact")
        wait_until(lambda: session.read_state() and not session.read_state()["dirty"])

    def test_profile_change_rearms_with_new_delay(self):
        session = self.make_session(delay=30)
        session.stop_and_bind()
        before = session.read_state()["timer_deadline"]
        session.control("profile", profile="short")
        after = session.read_state()
        self.assertEqual(after["cache_profile"], "short")
        self.assertNotEqual(after["timer_deadline"], before)

    def test_hook_and_statusline_route_to_owner(self):
        session = self.make_session(delay=30)
        environment = os.environ.copy()
        environment.update(
            {
                "CLAUDE_IDLE_OWNER": "pty-supervisor",
                "CLAUDE_IDLE_CHANNEL": session.channel,
                "CLAUDE_IDLE_CONTROL_SOCKET": str(session.socket_path),
                "CLAUDE_IDLE_RUNTIME_DIR": str(session.state_path.parent),
            }
        )
        start = {
            "hook_event_name": "SessionStart",
            "session_id": session.session_id,
            "transcript_path": str(session.transcript),
        }
        subprocess.run(
            [str(HOOK)], input=json.dumps(start).encode(), env=environment,
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        status = {
            "session_id": session.session_id,
            "context_window": {"total_input_tokens": 80000},
        }
        subprocess.run(
            [str(STATUSLINE)], input=json.dumps(status).encode(), env=environment,
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        wait_until(lambda: session.read_state() and session.read_state()["session_id"] == session.session_id)
        snapshot = json.loads((session.state_path.parent / "status.json").read_text())
        self.assertEqual(snapshot["current_input_context_tokens"], 80000)
        stop = {
            "hook_event_name": "Stop",
            "session_id": session.session_id,
            "stop_hook_active": False,
            "last_assistant_message": "fixture completion",
        }
        subprocess.run(
            [str(HOOK)], input=json.dumps(stop).encode(), env=environment,
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        wait_until(lambda: session.read_state() and session.read_state()["dirty"])

    def test_statusline_registry_fallback_without_owner_environment(self):
        session = self.make_session(delay=30)
        session.event("session-start", transcript_path=str(session.transcript))
        environment = os.environ.copy()
        environment.update(
            {
                "XDG_RUNTIME_DIR": str(session.root),
                "CLAUDE_IDLE_OWNER": "",
                "CLAUDE_IDLE_CHANNEL": "",
                "CLAUDE_IDLE_RUNTIME_DIR": "",
            }
        )
        payload = {
            "session_id": session.session_id,
            "cwd": str(REPO),
            "model": {"display_name": "Claude Test"},
            "context_window": {"total_input_tokens": 81234},
        }
        subprocess.run(
            [str(STATUSLINE)], input=json.dumps(payload).encode(), env=environment,
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        snapshot_path = session.state_path.parent / "status.json"
        wait_until(lambda: snapshot_path.exists())
        snapshot = json.loads(snapshot_path.read_text())
        self.assertEqual(snapshot["channel"], session.channel)
        self.assertEqual(snapshot["session_id"], session.session_id)
        self.assertEqual(snapshot["current_input_context_tokens"], 81234)

    def test_two_sessions_are_isolated(self):
        first = self.make_session(delay=0)
        second = self.make_session(delay=30)
        self.assertNotEqual(first.channel, second.channel)
        first.stop_and_bind()
        first.wait_output("COMPACT_RECEIVED")
        self.assertFalse(second.read_state()["dirty"])
        second.stop_and_bind()
        second.submit_local_byte(b"x")
        time.sleep(0.2)
        self.assertFalse(second.output_contains("COMPACT_RECEIVED"))

    def test_channel_launch_attach_pass_and_fail(self):
        attached = self.make_session(
            channel=True,
            spawn_channel=True,
            attach_wait=2,
        )
        wait_until(
            lambda: attached.read_state() and attached.read_state()["channel_health"] == "attached",
            message="channel process was not recognized",
        )
        self.assertIn("plugin:fixture:fixture", attached.read_state()["watched_servers"])
        failed = self.make_session(channel=True, attach_wait=0)
        wait_until(
            lambda: failed.read_state() and failed.read_state()["channel_health"] == "failed-attach",
            message="missing channel process was not reported",
        )

    def test_channel_death_is_idempotent_and_bounded(self):
        session = self.make_session(
            channel=True,
            spawn_channel=True,
            attach_wait=2,
            recovery_confirm=1,
        )
        session.stop_and_bind()
        removed = {
            "type": "attachment",
            "attachment": {
                "type": "mcp_instructions_delta",
                "addedNames": [],
                "removedNames": ["plugin:fixture:fixture"],
            },
        }
        session.append_transcript(removed)
        session.append_transcript(removed)
        wait_until(
            lambda: session.read_state() and session.read_state()["channel_recovery_pending"],
            message="channel death did not create a recovery generation",
        )
        wait_until(
            lambda: session.read_state()
            and session.read_state()["channel_recovery_attempts"] >= 1
            and session.read_state()["channel_recovery_awaiting"],
            message="first reconnect was not injected",
        )
        session.wait_output("/mcp reconnect plugin:fixture:fixture", timeout=3)
        session.event("stop", stop_hook_active=False)
        wait_until(
            lambda: session.read_state()
            and session.read_state()["channel_recovery_attempts"] >= 2
            and session.read_state()["channel_recovery_awaiting"],
            message="second reconnect was not bounded/injected",
        )
        session.wait_output("/mcp reconnect plugin:fixture:fixture", timeout=3)
        session.event("stop", stop_hook_active=False)
        wait_until(
            lambda: session.read_state()
            and session.read_state()["channel_recovery_reload_attempted"]
            and session.read_state()["channel_recovery_awaiting"],
            message="reload fallback was not injected",
        )
        session.wait_output("/reload-plugins", timeout=3)
        session.event("stop", stop_hook_active=False)
        wait_until(
            lambda: session.read_state() and session.read_state()["channel_health"] == "dead",
            message="bounded recovery did not fail visibly",
            timeout=6,
        )
        # The fake child echoes the command once before each INPUT line. Count
        # the bytes received by the child, not the echoed terminal display.
        self.assertEqual(
            bytes(session.output).count(b"INPUT:b'/mcp reconnect plugin:fixture:fixture\\n'"),
            2,
        )
        self.assertEqual(bytes(session.output).count(b"INPUT:b'/reload-plugins\\n'"), 1)

    def test_channel_add_reemission_does_not_start_recovery(self):
        session = self.make_session(channel=True, spawn_channel=True, attach_wait=2)
        session.stop_and_bind()
        added = {
            "type": "attachment",
            "attachment": {
                "type": "mcp_instructions_delta",
                "addedNames": ["plugin:fixture:fixture"],
                "removedNames": [],
            },
        }
        session.append_transcript(added)
        session.append_transcript(added)
        wait_until(
            lambda: session.read_state() and session.read_state()["channel_health"] == "attached"
        )
        time.sleep(1.2)
        self.assertFalse(session.read_state()["channel_recovery_pending"])
        self.assertEqual(session.read_state()["timer_kind"], "compact")
        self.assertIsNotNone(session.read_state()["timer_deadline"])
        self.assertFalse(session.output_contains("/mcp reconnect"))

    def test_channel_recovery_confirmation_does_not_rearm_on_command_stop(self):
        session = self.make_session(
            channel=True,
            spawn_channel=True,
            attach_wait=2,
            recovery_confirm=2,
        )
        session.stop_and_bind()
        session.append_transcript({
            "type": "attachment",
            "attachment": {
                "type": "mcp_instructions_delta",
                "addedNames": [],
                "removedNames": ["plugin:fixture:fixture"],
            },
        })
        wait_until(
            lambda: session.read_state()
            and session.read_state()["channel_recovery_awaiting"]
        )
        session.append_transcript({
            "type": "attachment",
            "attachment": {
                "type": "mcp_instructions_delta",
                "addedNames": ["plugin:fixture:fixture"],
                "removedNames": [],
            },
        })
        wait_until(
            lambda: session.read_state()
            and session.read_state()["channel_health"] == "attached"
            and not session.read_state()["channel_recovery_pending"]
        )
        session.event("stop", stop_hook_active=False)
        time.sleep(0.2)
        self.assertIsNone(session.read_state()["timer_deadline"])

    def test_channel_death_waits_for_idle_and_prompt_cancels(self):
        session = self.make_session(channel=True, spawn_channel=True, attach_wait=2)
        session.event("session-start", transcript_path=str(session.transcript))
        session.append_transcript({
            "type": "attachment",
            "attachment": {
                "type": "mcp_instructions_delta",
                "addedNames": ["plugin:fixture:fixture"],
                "removedNames": [],
            },
        })
        session.event("user-prompt-submit")
        session.append_transcript({
            "type": "attachment",
            "attachment": {
                "type": "mcp_instructions_delta",
                "addedNames": [],
                "removedNames": ["plugin:fixture:fixture"],
            },
        })
        wait_until(lambda: session.read_state() and session.read_state()["channel_recovery_pending"])
        self.assertIsNone(session.read_state()["timer_deadline"])
        time.sleep(0.5)
        self.assertFalse(session.output_contains("/mcp reconnect"))
        session.event("user-prompt-submit")
        wait_until(lambda: session.read_state() and not session.read_state()["channel_recovery_pending"])
        self.assertFalse(session.output_contains("/mcp reconnect"))

    def test_channel_death_mid_turn_waits_for_stop(self):
        session = self.make_session(channel=True, spawn_channel=True, attach_wait=2)
        session.event("session-start", transcript_path=str(session.transcript))
        session.event("user-prompt-submit")
        session.append_transcript({
            "type": "attachment",
            "attachment": {
                "type": "mcp_instructions_delta",
                "addedNames": [],
                "removedNames": ["plugin:fixture:fixture"],
            },
        })
        wait_until(lambda: session.read_state() and session.read_state()["channel_recovery_pending"])
        time.sleep(0.5)
        self.assertFalse(session.output_contains("/mcp reconnect"))
        session.event("stop", stop_hook_active=False)
        wait_until(lambda: session.output_contains("/mcp reconnect plugin:fixture:fixture"))

    def test_inject_is_whitelist_only(self):
        session = self.make_session(delay=30)
        session.stop_and_bind()
        refused = session.control("inject", text="/bin/sh")
        self.assertFalse(refused["ok"])
        accepted = session.control("inject", text="/reload-plugins")
        self.assertTrue(accepted["ok"])
        session.wait_output("/reload-plugins")

    def test_exit_status_and_runtime_cleanup(self):
        session = self.make_session(extra_args=("--exit-status=7",))
        session.wait_output("ARGS:")
        session.process.wait(timeout=5)
        self.assertEqual(session.process.returncode, 7)
        runtime = session.root
        session.close()
        self.assertFalse(runtime.exists())

    def test_observation_harness_never_controls_an_interactive_supervisor(self):
        """The live acceptance observer must remain state/log read-only."""
        self.assertTrue(OBSERVER.is_file())
        source = OBSERVER.read_text(encoding="utf-8")
        tree = compile(source, str(OBSERVER), "exec", ast.PyCF_ONLY_AST)
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertNotIn("kill", calls)
        self.assertNotIn("send_signal", calls)
        self.assertNotIn("write", calls)
        self.assertNotIn('"inject"', source)
        self.assertNotIn('"trigger"', source)
        self.assertNotIn('"cancel"', source)
        self.assertNotIn("thread/compact/start", source)
        self.assertNotIn("SIGSTOP", source)
        self.assertNotIn("SIGCONT", source)

    def test_observation_harness_parses_list_shapes_and_snapshot_timestamps(self):
        loader = importlib.machinery.SourceFileLoader(
            "claude_warm_live_observe", str(OBSERVER)
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        channel = "claude-" + "a" * 32
        records = [{"channel": channel}, {"channel": "claude-" + "b" * 32}]
        self.assertEqual(module.parse_records(json.dumps(records)), records)
        self.assertEqual(module.parse_records("\n".join(json.dumps(item) for item in records)), records)
        self.assertEqual(module.timestamp_epoch(1700000000)[1], "integer")
        self.assertEqual(module.timestamp_epoch(1700000000.5)[1], "float")
        self.assertEqual(module.timestamp_epoch("1700000000.5")[1], "numeric-string")
        self.assertEqual(module.timestamp_epoch("2026-08-03T05:00:00Z")[1], "iso8601")

    def test_observer_success_report_accepts_an_aged_snapshot(self):
        """The completed-compaction report path keeps its regression bound defined."""
        loader = importlib.machinery.SourceFileLoader(
            "claude_warm_live_observe_success", str(OBSERVER)
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        channel = "claude-" + "c" * 32
        base = {
            "channel": channel,
            "supervisor_pid": 101,
            "pid": 102,
            "session_id": "observer-fixture-session",
            "cache_profile": "long",
            "watched_servers": [],
            "current_input_context_tokens": 80000,
            "dirty": True,
            "compacting": False,
            "timer_deadline": 240.0,
            "timer_kind": "compact",
            "last_injection_result": None,
        }
        armed = dict(base)
        completed = {
            **base,
            "dirty": False,
            "compacting": False,
            "timer_deadline": None,
            "timer_kind": None,
            "last_injection_result": "succeeded",
        }
        events = [
            {"event": "armed", "kind": "compact", "delay": 140, "timestamp": 100.0},
            {
                "event": "transcript-record-ignored",
                "classification": "internal-recap",
                "record_type": "system",
                "record_subtype": "away_summary",
                "timestamp": 185.644,
            },
            {"event": "injection-attempted", "purpose": "compact", "timestamp": 250.0},
            {"event": "compaction-requested", "timestamp": 250.0},
            {"event": "compaction-completed", "timestamp": 251.0},
        ]
        root = pathlib.Path(tempfile.mkdtemp(prefix="observer-success-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        guard = root / "guard.log"
        guard.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
        base["channel_guard_log"] = str(guard)
        states = iter([base, armed, completed, completed])
        sessions = iter([
            [{"channel": "claude-" + "d" * 32}],
            [{"channel": channel}],
        ])
        arguments = module.build_parser().parse_args([
            "--discovery-timeout", "1",
            "--arm-timeout", "1",
            "--compaction-timeout", "1",
            "--quiet-seconds", "0",
        ])
        self.assertEqual(arguments.former_snapshot_max_age, 120.0)
        with (
            mock.patch.object(module, "runtime_root", return_value=root),
            mock.patch.object(module, "control_command", return_value=root / "fake-warmctl"),
            mock.patch.object(module, "list_sessions", side_effect=lambda _command: next(sessions)),
            mock.patch.object(module, "read_state", side_effect=lambda _root, _channel: next(states)),
            mock.patch.object(module, "process_present", return_value=True),
            mock.patch.object(module, "supervisor_environment", return_value={
                "CLAUDE_IDLE_CACHE_PROFILE": "long",
                "CLAUDE_IDLE_COMPACT_SECONDS": "140",
                "CLAUDE_IDLE_COMPACT_LONG_CACHE_TTL_SECONDS": "300",
                "CLAUDE_IDLE_COMPACT_MIN_TOKENS": "1",
                "CLAUDE_IDLE_COMPACTION_DEBUG": "1",
            }),
            mock.patch.object(module, "read_status", return_value=(
                {"channel": channel, "session_id": "observer-fixture-session"},
                0.0,
                "integer",
                80000,
            )),
            mock.patch.object(module, "read_guard", return_value=events),
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = module.run(arguments)
        self.assertEqual(result, 0, output.getvalue())
        self.assertIn('result="PASS"', output.getvalue())
        self.assertIn('snapshot_age_at_callback_seconds=250.0', output.getvalue())
        self.assertIn('away_summary_observed=1', output.getvalue())
        self.assertIn('away_summary_classification="internal-recap"', output.getvalue())
        self.assertIn('away_summary_timer_preserved=true', output.getvalue())

    def test_signal_propagation_and_runtime_cleanup(self):
        session = self.make_session()
        session.wait_output("ARGS:")
        runtime = session.root
        session.process.send_signal(signal.SIGTERM)
        session.process.wait(timeout=5)
        self.assertEqual(session.process.returncode, 128 + signal.SIGTERM)
        session.close()
        self.assertFalse(runtime.exists())

    def load_watchdog(self):
        loader = importlib.machinery.SourceFileLoader("claude_poller_watchdog", str(WATCHDOG))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def watchdog_fixture(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="poller-watchdog-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        state_root = root / "state"
        runtime_root = root / "runtime"
        channels_root = root / "channels"
        proc_root = root / "proc"
        channel = "claude-" + "e" * 32
        record = {
            "agent": "Fable",
            "argv": ["--channels", "plugin:telegram@claude-plugins-official"],
            "channel": channel,
            "event": "session-bound",
            "pid": 102,
            "recorded_at": 100.0,
            "session_id": "fixture-session",
            "supervisor_pid": 101,
        }
        runtime = {
            "channel": channel,
            "compacting": False,
            "pid": 102,
            "session_id": "fixture-session",
            "status": "idle",
            "supervisor_pid": 101,
        }
        path = runtime_root / channel / "state.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(runtime), encoding="utf-8")

        def proc(pid, parent, state="S"):
            path = proc_root / str(pid) / "stat"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{pid} (fixture) {state} {parent} " + "0 " * 24, encoding="utf-8")

        proc(101, 1)
        proc(102, 101)
        return root, record, state_root, runtime_root, channels_root, proc_root, proc

    def assess_watchdog(self, record, state_root, runtime_root, channels_root, proc_root):
        module = self.load_watchdog()
        return module.assess_record(
            record,
            state_root=state_root,
            runtime_root=runtime_root,
            channels_root=channels_root,
            proc_root=proc_root,
            current_time=1000.0,
            startup_grace=300.0,
        )

    def test_watchdog_marks_dead_stale_pid_deaf(self):
        _root, record, state_root, runtime_root, channels_root, proc_root, _proc = self.watchdog_fixture()
        lock = channels_root / "telegram-fable/bot.pid"
        lock.parent.mkdir(parents=True)
        lock.write_text("404", encoding="utf-8")
        assessment = self.assess_watchdog(record, state_root, runtime_root, channels_root, proc_root)
        self.assertEqual((assessment["status"], assessment["reason"]), ("deaf", "poller-dead"))

    def test_watchdog_marks_live_foreign_pid_deaf(self):
        _root, record, state_root, runtime_root, channels_root, proc_root, proc = self.watchdog_fixture()
        proc(201, 1)
        lock = channels_root / "telegram-fable/bot.pid"
        lock.parent.mkdir(parents=True)
        lock.write_text("201", encoding="utf-8")
        assessment = self.assess_watchdog(record, state_root, runtime_root, channels_root, proc_root)
        self.assertEqual((assessment["status"], assessment["reason"]), ("deaf", "poller-foreign"))

    def test_watchdog_accepts_owned_poller_and_ignores_old_log_mtime(self):
        root, record, state_root, runtime_root, channels_root, proc_root, proc = self.watchdog_fixture()
        proc(201, 102)
        lock = channels_root / "telegram-fable/bot.pid"
        lock.parent.mkdir(parents=True)
        lock.write_text("201", encoding="utf-8")
        old_log = root / "poller.log"
        old_log.write_text("quiet", encoding="utf-8")
        os.utime(old_log, (1, 1))
        assessment = self.assess_watchdog(record, state_root, runtime_root, channels_root, proc_root)
        self.assertEqual((assessment["status"], assessment["reason"]), ("healthy", "poller-owned"))

    def test_watchdog_generation_drift_is_diagnostic_only(self):
        _root, record, state_root, runtime_root, channels_root, proc_root, proc = self.watchdog_fixture()
        runtime_path = runtime_root / record["channel"] / "state.json"
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        runtime["generation_loaded"] = False
        runtime_path.write_text(json.dumps(runtime), encoding="utf-8")
        proc(201, 102)
        lock = channels_root / "telegram-fable/bot.pid"
        lock.parent.mkdir(parents=True)
        lock.write_text("201", encoding="utf-8")
        assessment = self.assess_watchdog(record, state_root, runtime_root, channels_root, proc_root)
        self.assertEqual((assessment["status"], assessment["reason"]), ("healthy", "poller-owned"))

    def test_watchdog_skips_reused_or_incoherent_owner_pid_tree(self):
        _root, record, state_root, runtime_root, channels_root, proc_root, proc = self.watchdog_fixture()
        proc(102, 1)
        assessment = self.assess_watchdog(record, state_root, runtime_root, channels_root, proc_root)
        self.assertEqual((assessment["status"], assessment["reason"]), ("skip", "owner-tree-incoherent"))

    def test_watchdog_skips_missing_runtime_state(self):
        _root, record, state_root, runtime_root, channels_root, proc_root, _proc = self.watchdog_fixture()
        shutil.rmtree(runtime_root)
        assessment = self.assess_watchdog(record, state_root, runtime_root, channels_root, proc_root)
        self.assertEqual((assessment["status"], assessment["reason"]), ("skip", "missing-runtime-state"))

    def test_watchdog_skips_clean_exit(self):
        _root, record, state_root, runtime_root, channels_root, proc_root, _proc = self.watchdog_fixture()
        record["event"] = "supervisor-exit"
        assessment = self.assess_watchdog(record, state_root, runtime_root, channels_root, proc_root)
        self.assertEqual((assessment["status"], assessment["reason"]), ("skip", "deliberate-exit"))

    def test_watchdog_skips_busy_owner_and_startup_grace(self):
        _root, record, state_root, runtime_root, channels_root, proc_root, _proc = self.watchdog_fixture()
        runtime_path = runtime_root / record["channel"] / "state.json"
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        runtime["status"] = "active"
        runtime_path.write_text(json.dumps(runtime), encoding="utf-8")
        busy = self.assess_watchdog(record, state_root, runtime_root, channels_root, proc_root)
        self.assertEqual((busy["status"], busy["reason"]), ("skip", "owner-busy"))
        record["recorded_at"] = 900.0
        grace = self.assess_watchdog(record, state_root, runtime_root, channels_root, proc_root)
        self.assertEqual((grace["status"], grace["reason"]), ("skip", "startup-grace"))

    def test_watchdog_constructs_guarded_nurse_joy_command(self):
        module = self.load_watchdog()
        command = module.revive_command(pathlib.Path("/opt/bin/nurse-joy"), "Fable", "fixture-session")
        self.assertEqual(command, ["/opt/bin/nurse-joy", "revive", "Fable", "--resume", "fixture-session", "--no-visit"])
        self.assertNotIn("--force", command)

    def test_watchdog_wrong_host_guard_runs_before_state_mutation(self):
        module = self.load_watchdog()
        root = pathlib.Path(tempfile.mkdtemp(prefix="poller-watchdog-host-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        arguments = module.build_parser().parse_args([
            "--expected-host", "expected-host",
            "--watchdog-root", str(root / "must-not-exist"),
            "--json",
        ])
        output = io.StringIO()
        with mock.patch.object(module.socket, "gethostname", return_value="other-host"), contextlib.redirect_stdout(output):
            self.assertEqual(module.run(arguments), 0)
        self.assertFalse((root / "must-not-exist").exists())
        self.assertIn('"reason":"wrong-host"', output.getvalue())

    def test_watchdog_cooldown_and_failed_revive_alert_threshold(self):
        module = self.load_watchdog()
        entry = {"failures": 1, "last_attempt": 900.0}
        self.assertEqual(
            module.retry_disposition(entry, current_time=1000.0, cooldown=300.0, alert_cooldown=3600.0, max_failures=3),
            "cooldown",
        )
        entry["failures"] = 3
        self.assertEqual(
            module.retry_disposition(entry, current_time=1000.0, cooldown=300.0, alert_cooldown=3600.0, max_failures=3),
            "alert-cooldown",
        )
        self.assertEqual(
            module.retry_disposition(entry, current_time=5000.0, cooldown=300.0, alert_cooldown=3600.0, max_failures=3),
            "attempt",
        )

    def test_watchdog_requires_persistent_deaf_observation(self):
        module = self.load_watchdog()
        entry = {"failures": 0}
        self.assertEqual(
            module.confirmation_disposition(entry, reason="poller-dead", fingerprint="101:10/102:20/404:none", current_time=1000.0, confirm_seconds=120.0),
            "observe",
        )
        self.assertEqual(
            module.confirmation_disposition(entry, reason="poller-dead", fingerprint="101:10/102:20/404:none", current_time=1119.0, confirm_seconds=120.0),
            "observe",
        )
        self.assertEqual(
            module.confirmation_disposition(entry, reason="poller-dead", fingerprint="101:10/102:20/404:none", current_time=1120.0, confirm_seconds=120.0),
            "confirmed",
        )
        self.assertEqual(
            module.confirmation_disposition(entry, reason="poller-foreign", fingerprint="101:10/102:20/201:30", current_time=1200.0, confirm_seconds=120.0),
            "observe",
        )

    def test_watchdog_pid_birth_fingerprint_change_restarts_confirmation(self):
        module = self.load_watchdog()
        entry = {"failures": 0}
        self.assertEqual(
            module.confirmation_disposition(entry, reason="poller-dead", fingerprint="101:10/102:20/404:30", current_time=1000.0, confirm_seconds=120.0),
            "observe",
        )
        self.assertEqual(
            module.confirmation_disposition(entry, reason="poller-dead", fingerprint="101:11/102:20/404:30", current_time=1200.0, confirm_seconds=120.0),
            "observe",
        )
        self.assertEqual(entry["deaf_since"], 1200.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
