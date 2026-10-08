#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
import pwd
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest


HERE = Path(__file__).resolve()
REPO = HERE.parents[5]
WARM = REPO / "all/.local/bin/opencode-warm"
WARM_EVENT = REPO / "all/.local/bin/opencode-warm-event"
WARMCTL = REPO / "all/.local/bin/opencode-warmctl"
WAKEUP = REPO / "all/.local/bin/opencode-wakeup"
PLUGIN = REPO / "all/.config/opencode/plugins/continuity.js"
CONFIG = REPO / "all/.config/opencode/opencode.json"
POLICY_INSTALLER = REPO / "all/.local/bin/opencode-continuity-policy-install"
BOT_MANAGER = REPO / "all/.local/bin/telegram-agent-host"


class FixtureState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.status = "idle"
        self.messages = []
        self.legacy_status = 204
        self.v2_status = 503
        self.posts: list[tuple[str, dict]] = []
        self.message_gets = 0
        self.mutate_message_on_second_get = False
        self.summarize_delay = 0.0
        self.prompt_delay = 0.0


class FixtureHandler(BaseHTTPRequestHandler):
    fixture: FixtureState

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def send_json(self, status: int, value: object) -> None:
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/session/status":
            value = {} if self.fixture.status == "absent" else {"session-1": {"type": self.fixture.status}}
            self.send_json(200, value)
            return
        if self.path == "/session/session-1/message":
            self.fixture.message_gets += 1
            if self.fixture.mutate_message_on_second_get and self.fixture.message_gets == 2:
                self.fixture.messages.append({"info": {
                    "id": "assistant-2", "role": "assistant", "finish": "stop",
                    "providerID": "fixture-provider", "modelID": "fixture-model",
                    "time": {"completed": time.time()},
                    "tokens": {"input": 61000, "cache": {"read": 6000, "write": 5000}},
                }, "parts": []})
            self.send_json(200, self.fixture.messages)
            return
        self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        with self.fixture.lock:
            self.fixture.posts.append((self.path, body))
        if self.path == "/api/session/session-1/compact":
            self.send_json(self.fixture.v2_status, {"status": self.fixture.v2_status})
            return
        if self.path == "/session/session-1/summarize":
            if self.fixture.summarize_delay:
                time.sleep(self.fixture.summarize_delay)
            self.send_response(self.fixture.legacy_status)
            self.end_headers()
            return
        if self.path == "/session/session-1/prompt_async":
            if self.fixture.prompt_delay:
                time.sleep(self.fixture.prompt_delay)
            self.send_response(204)
            self.end_headers()
            return
        self.send_json(404, {"error": "not found"})


OWNER_HELPER = """#!/usr/bin/env python3
import json, pathlib, sys
state = json.loads(pathlib.Path(sys.argv[sys.argv.index('--state') + 1]).read_text())
if state.get('test_owner_bad'):
    print(json.dumps({'status': 'degraded', 'reasons': ['fixture-stale-owner']}))
    raise SystemExit(1)
print(json.dumps({
    'status': 'running', 'project': '/home/metsatron/HelmCortex',
    'host': '127.0.0.1', 'port': 4096,
    'owner': 'telegram-agent-host:opencode',
    'backend': {'valid': True}, 'poller': {'valid': True},
    'session': {'status': 'bound', 'session_id': 'session-1'},
}))
"""

POLICY_HELPER = """#!/usr/bin/env python3
import json, os, sys
request = json.load(sys.stdin)
def argument(name):
    try:
        return sys.argv[sys.argv.index(name) + 1]
    except (ValueError, IndexError):
        return None
print(json.dumps({
    'schema': 'helmcortex.opencode-continuity-policy-decision.v1',
    'action': os.environ.get('FIXTURE_POLICY_ACTION', 'CONTINUE_LOCAL'),
    'session_id': request['session_id'],
    'provider': argument('--provider'),
    'model_pool': argument('--model-pool'),
    'request_cache_expires_at': request['cache_expires_at'],
    'reset': {'reset_at': float(os.environ.get('FIXTURE_RESET_AT', str(__import__('time').time() + 60)))},
}))
"""

CACHE_POLICY_HELPER = """#!/usr/bin/env python3
import json, os, pathlib
if os.environ.get('FIXTURE_CACHE_CALLS'):
    pathlib.Path(os.environ['FIXTURE_CACHE_CALLS']).write_text('called')
print(json.dumps({
    'compact_before_seconds': 7080,
    'cache_expires_seconds': 7200,
    'mode': 'measured', 'confidence': 'supported',
    'provider': 'fixture-provider', 'endpoint_id': 'fixture-provider',
    'model': 'fixture-model', 'reason': 'exact-harness',
}))
"""


class OpenCodeWarmFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="opencode-warm-")
        root = Path(self.temp.name)
        self.root = root
        self.state_dir = root / "continuity"
        self.owner_state = root / "owner.json"
        self.owner_helper = root / "opencode-owner"
        self.owner_helper.write_text(OWNER_HELPER, encoding="utf-8")
        self.owner_helper.chmod(0o700)
        self.policy_helper = root / "opencode-continuity-policy"
        self.policy_helper.write_text(POLICY_HELPER, encoding="utf-8")
        self.policy_helper.chmod(0o700)
        self.cache_policy_helper = root / "cache-policy"
        self.cache_policy_helper.write_text(CACHE_POLICY_HELPER, encoding="utf-8")
        self.cache_policy_helper.chmod(0o700)
        self.cache_policy = root / "cache-policy.json"
        self.cache_policy.write_text("{}", encoding="utf-8")
        self.scheduler_log = root / "scheduled.json"
        self.scheduler = root / "timeark-oneshot-schedule"
        self.scheduler.write_text(
            "#!/usr/bin/env python3\nimport json,os,sys\n"
            "job=json.load(sys.stdin)\n"
            "open(os.environ['FIXTURE_SCHEDULER_LOG'],'w').write(json.dumps(job))\n"
            "disarm=os.environ.get('FIXTURE_DISARM_PATH')\n"
            "if disarm:\n"
            " state=json.loads(open(disarm).read())\n"
            " state.update(policy='OFF',agent_state='DISARMED')\n"
            " open(disarm,'w').write(json.dumps(state))\n"
            "print(json.dumps(job))\n",
            encoding="utf-8",
        )
        self.scheduler.chmod(0o700)
        self.fixture = FixtureState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        FixtureHandler.fixture = self.fixture
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.write_owner()
        self.write_messages()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def write_owner(self, **overrides: object) -> None:
        value: dict[str, object] = {
            "schema": "helmcortex.opencode-owner.v2",
            "owner": "telegram-agent-host:opencode", "bot": "opencode",
            "project": "/home/metsatron/HelmCortex", "host": "127.0.0.1", "port": 4096,
            "backend_pid": 1, "backend_start_ticks": 1,
            "backend_cwd": "/home/metsatron/HelmCortex", "backend_argv": ["opencode", "serve"],
            "poller_pid": 2, "poller_start_ticks": 2,
            "poller_cwd": "/home/metsatron/HelmCortex", "poller_argv": ["poller", "start", "--mode", "installed"],
            "poller_package": "@grinev/opencode-telegram-bot", "poller_package_version": "0.22.5",
            "session_binding": {
                "status": "bound", "project_worktree": "/home/metsatron/HelmCortex",
                "session_directory": "/home/metsatron/HelmCortex", "session_id": "session-1",
            },
        }
        value.update(overrides)
        self.owner_state.write_text(json.dumps(value), encoding="utf-8")

    def write_messages(self, **overrides: object) -> None:
        info: dict[str, object] = {
            "id": "assistant-1", "role": "assistant", "finish": "stop",
            "providerID": "fixture-provider", "modelID": "fixture-model",
            "time": {"completed": time.time()},
            "tokens": {"input": 60000, "cache": {"read": 6000, "write": 5000}},
        }
        info.update(overrides)
        self.fixture.messages = [{"info": info, "parts": []}]

    def fingerprint(self) -> str:
        module = load_module()
        owner = json.loads(self.owner_state.read_text(encoding="utf-8"))
        return module.owner_fingerprint(owner, "session-1")

    def write_receipts(self, **overrides: object) -> None:
        created = time.time()
        fingerprint = self.fingerprint()
        checkpoint = {
            "schema": "dotcortex.opencode-continuity-receipt.v1", "kind": "checkpoint",
            "session_id": "session-1", "message_id": "assistant-1", "checkpoint_id": "checkpoint-1",
            "owner_fingerprint": fingerprint, "created_at": created,
        }
        handoff = {
            "schema": "dotcortex.opencode-continuity-receipt.v1", "kind": "handoff",
            "session_id": "session-1", "message_id": "assistant-1", "checkpoint_id": "checkpoint-1",
            "handoff_id": "handoff-1", "reference": "continuity://fixture/handoff-1",
            "owner_fingerprint": fingerprint, "created_at": created,
            "critical": {
                "objective": "verify-opencode-compaction",
                "next": "report-CANARY-GREEN",
                "prohibition": "never-touch-production",
            },
        }
        checkpoint.update(overrides.get("checkpoint", {}))
        handoff.update(overrides.get("handoff", {}))
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        (self.state_dir / "checkpoint.json").write_text(json.dumps(checkpoint), encoding="utf-8")
        (self.state_dir / "handoff.json").write_text(json.dumps(handoff), encoding="utf-8")

    def write_compaction_event(self, observed_at: float | None = None) -> None:
        event_dir = self.state_dir / "events"
        event_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        event = {
            "schema": "dotcortex.opencode-continuity-event.v1",
            "type": "session.compacted", "session_id": "session-1",
            "observed_at": time.time() if observed_at is None else observed_at,
        }
        (event_dir / "session-1.json").write_text(json.dumps(event), encoding="utf-8")

    def add_summary(self, completed_at: float | None = None) -> None:
        self.fixture.messages.append({"info": {
            "id": "summary-1", "role": "assistant", "summary": True, "finish": "stop",
            "time": {"completed": time.time() if completed_at is None else completed_at},
        }, "parts": []})

    def call(self, observed_at: float | None = None, event: str = "session.idle", **env_overrides: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update({
            "XDG_STATE_HOME": str(self.root / "xdg-state"),
            "FLEET_CACHE_POLICY_HELPER": str(self.cache_policy_helper),
            "FLEET_CACHE_POLICY_PATH": str(self.root / "missing-policy.json"),
            "OPENCODE_WARM_STATE_DIR": str(self.state_dir),
            "OPENCODE_WARM_OWNER_STATE": str(self.owner_state),
            "OPENCODE_WARM_OWNER_HELPER": str(self.owner_helper),
            "OPENCODE_WARM_BASE_URL": f"http://127.0.0.1:{self.server.server_port}",
            "OPENCODE_WARM_MIN_CONTEXT_TOKENS": "70000",
            "OPENCODE_WARM_MAX_TELEMETRY_AGE": "120",
        })
        environment.update(env_overrides)
        at = time.time() if observed_at is None else observed_at
        return subprocess.run(
            [str(WARM), "--session", "session-1", "--event", event, "--observed-at", str(at)],
            capture_output=True, text=True, env=environment, timeout=10,
        )

    def policy_env(self, action: str = "CONTINUE_LOCAL") -> dict[str, str]:
        return {
            "OPENCODE_WARM_POLICY_HELPER": str(self.policy_helper),
            "OPENCODE_WARM_POLICY_ROOT": str(self.root / "authority"),
            "OPENCODE_WARM_POLICY_AUTHORITY_IDENTITY": "kikin-kushi",
            "OPENCODE_WARM_POLICY_TELEMETRY_HOST": "t480s",
            "OPENCODE_WARM_POLICY_PROVIDER": "opencode-go",
            "OPENCODE_WARM_POLICY_ACCOUNT_HASH": "sha256:fixture",
            "OPENCODE_WARM_POLICY_MODEL_POOL": "deepseek-v4.1-flash",
            "OPENCODE_WARM_POLICY_ESTIMATED_PRESERVATION_PERCENT": "3",
            "OPENCODE_WARM_POLICY_ESTIMATE_UNCERTAINTY_PERCENT": "1",
            "OPENCODE_WARM_POLICY_IN_FLIGHT_RESERVE_PERCENT": "0.5",
            "OPENCODE_WARM_POLICY_CONTROL_RESERVE_PERCENT": "0.5",
            "OPENCODE_WARM_POLICY_SAFETY_MARGIN_SECONDS": "60",
            "OPENCODE_WARM_CACHE_TTL_SECONDS": "1800",
            "FIXTURE_POLICY_ACTION": action,
        }

    def arm_nudge(self, *, reset_epoch: int | None = None) -> dict:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        value = {
            "schema": "dotcortex.opencode-nudge-state.v1", "policy": "AGENT",
            "agent_state": "ARMED", "reset_epoch": reset_epoch,
            "sent_for_reset_epoch": None, "delivery_state": "none",
        }
        (self.state_dir / "nudge.json").write_text(json.dumps(value), encoding="utf-8")
        return value

    def nudge_env(self, action: str = "CONTINUE_LOCAL") -> dict[str, str]:
        value = self.policy_env(action)
        value.update({
            "OPENCODE_WARM_NUDGE_SCHEDULER": str(self.scheduler),
            "OPENCODE_WARM_WAKEUP_ADAPTER": str(WAKEUP),
            "OPENCODE_WARM_NUDGE_DELAY_SECONDS": "0",
            "OPENCODE_WARM_NUDGE_EXPIRY_SECONDS": "300",
            "OPENCODE_WARM_NUDGE_TIMEZONE": "Australia/Melbourne",
            "FIXTURE_SCHEDULER_LOG": str(self.scheduler_log),
        })
        return value

    def assert_refused(self, result: subprocess.CompletedProcess[str], reason: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(reason, result.stderr)

    def policy_env(self, action: str = "CONTINUE_LOCAL") -> dict[str, str]:
        return {
            "OPENCODE_WARM_POLICY_HELPER": str(self.policy_helper),
            "OPENCODE_WARM_POLICY_ROOT": str(self.root / "authority"),
            "OPENCODE_WARM_POLICY_AUTHORITY_IDENTITY": "fixture-host",
            "OPENCODE_WARM_POLICY_TELEMETRY_HOST": "fixture-sensor",
            "OPENCODE_WARM_POLICY_PROVIDER": "opencode-go",
            "OPENCODE_WARM_POLICY_ACCOUNT_HASH": "sha256:fixture",
            "OPENCODE_WARM_POLICY_MODEL_POOL": "deepseek-v4.1-flash",
            "OPENCODE_WARM_POLICY_ESTIMATED_PRESERVATION_PERCENT": "3",
            "OPENCODE_WARM_POLICY_ESTIMATE_UNCERTAINTY_PERCENT": "1",
            "OPENCODE_WARM_POLICY_IN_FLIGHT_RESERVE_PERCENT": "0.5",
            "OPENCODE_WARM_POLICY_CONTROL_RESERVE_PERCENT": "0.5",
            "OPENCODE_WARM_POLICY_SAFETY_MARGIN_SECONDS": "60",
            "OPENCODE_WARM_CACHE_TTL_SECONDS": "1800",
            "FIXTURE_POLICY_ACTION": action,
        }

    def test_provider_configuration_does_not_bind_active_endpoint(self):
        self.write_receipts()
        # A declared custom route using the same label cannot authenticate
        # the backend route of the completed native message.
        config = self.root / "opencode.json"
        config.write_text(json.dumps({"provider": {"fixture-provider": {
            "options": {"baseURL": "declared-custom-route"}}}}), encoding="utf-8")
        environment = self.policy_env("CONTINUE_LOCAL")
        environment.update(OPENCODE_CONFIG=str(config),
                           FLEET_CACHE_POLICY_HELPER=str(self.cache_policy_helper),
                           FLEET_CACHE_POLICY_PATH=str(self.cache_policy),
                           FIXTURE_CACHE_CALLS=str(self.root / "cache-calls"))
        decided = self.call(**environment)
        self.assertEqual(decided.returncode, 0, decided.stderr)
        policy = json.loads(decided.stdout)["policy"]
        self.assertAlmostEqual(policy["request_cache_expires_at"] - self.fixture.messages[-1]["info"]["time"]["completed"], 1800, delta=1)
        self.assertEqual(policy["cache_policy"], {"mode": "fallback", "reason": "endpoint-unknown"})
        self.assertFalse((self.root / "cache-calls").exists())
        self.assertEqual(self.fixture.posts, [])

    def test_cache_validator_shape_is_not_runtime_endpoint_certification(self):
        decision = {"mode": "measured", "confidence": "supported",
                    "provider": "fixture-provider", "endpoint_id": "fixture-route",
                    "model": "fixture-model", "compact_before_seconds": 7080,
                    "cache_expires_seconds": 7200}
        module = load_module()
        self.assertEqual(module.validated_cache_decision(decision, "fixture-provider", "fixture-route", "fixture-model"), decision)
        with self.assertRaises(ValueError):
            module.validated_cache_decision(decision, "fixture-provider", "other-route", "fixture-model")

    def test_cache_invalid_stdout_retains_fixed_authority_ttl(self):
        self.write_receipts()
        valid = {"mode": "measured", "confidence": "supported",
                 "provider": "fixture-provider", "endpoint_id": "fixture-provider",
                 "model": "fixture-model", "compact_before_seconds": 7080,
                 "cache_expires_seconds": 7200}
        invalid = [[], None, True, {}, {**valid, "confidence": "observed"},
                   {**valid, "model": "other"}, {**valid, "endpoint_id": "other"}]
        invalid += [{**valid, "cache_expires_seconds": v}
                    for v in (None, "7200", True, -1, 0, float("nan"), float("inf"), 7000)]
        for value in invalid:
            with self.subTest(value=value):
                # Shape validation alone does not certify runtime routing.
                with self.assertRaises(ValueError):
                    load_module().validated_cache_decision(value, "fixture-provider", "fixture-provider", "fixture-model")
                self.cache_policy_helper.write_text(
                    "#!/usr/bin/env python3\nprint(" + repr(json.dumps(value)) + ")\n", encoding="utf-8")
                environment = self.policy_env()
                environment.update(FLEET_CACHE_POLICY_HELPER=str(self.cache_policy_helper),
                                   FLEET_CACHE_POLICY_PATH=str(self.cache_policy))
                decided = self.call(**environment)
                self.assertEqual(decided.returncode, 0, decided.stderr)
                payload = json.loads(decided.stdout)
                self.assertAlmostEqual(payload["policy"]["request_cache_expires_at"] -
                                       self.fixture.messages[-1]["info"]["time"]["completed"], 1800, delta=1)
                self.assertEqual(self.fixture.posts, [])

    def test_policy_changes_before_summarize_preserve_without_post(self):
        self.write_receipts()
        calls = self.root / "authority-calls"
        for action in ("CONTINUE_LOCAL", "WAIT_AND_NUDGE"):
            with self.subTest(action=action):
                calls.write_text("0", encoding="utf-8")
                self.policy_helper.write_text(
                    "#!/usr/bin/env python3\nimport json,pathlib,sys\n"
                    f"p=pathlib.Path({str(calls)!r})\n"
                    "count=int(p.read_text())\np.write_text(str(count+1))\n"
                    "json.load(sys.stdin)\n"
                    "print(json.dumps({'schema':'helmcortex.opencode-continuity-policy-decision.v1',"
                    f"'action':'HANDOFF_AND_COMPACT' if count == 0 else {action!r}}}))\n",
                    encoding="utf-8")
                decided = self.call(**self.policy_env())
                self.assertEqual(decided.returncode, 0, decided.stderr)
                payload = json.loads(decided.stdout)
                self.assertEqual(payload["action"], "skipped")
                self.assertEqual(payload["policy"]["action"], action)
                self.assertEqual(calls.read_text(), "2")
                self.assertEqual(self.fixture.posts, [])
                self.assertFalse(json.loads((self.state_dir / "state.json").read_text())["in_flight"])

    def test_idle_busy_unknown_status(self) -> None:
        self.write_receipts()
        for status, reason in (("busy", "session-status-busy"), ("unknown", "session-status-unknown")):
            self.fixture.status = status
            self.assert_refused(self.call(), reason)
        self.fixture.status = "idle"
        self.assertEqual(self.call().returncode, 0)

    def test_absent_session_in_valid_status_map_is_idle(self) -> None:
        self.write_receipts()
        self.fixture.status = "absent"
        self.assertEqual(self.call().returncode, 0)

    def test_token_threshold(self) -> None:
        self.write_messages(tokens={"input": 10, "cache": {"read": 0, "write": 0}})
        self.assertEqual(self.call().returncode, 0)
        self.assertEqual(self.fixture.posts, [])

    def test_opencode_model_limit_and_reserved_headroom_are_declared(self) -> None:
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
        self.assertTrue(config["compaction"]["auto"])
        self.assertEqual(config["compaction"]["reserved"], 16000)
        model = config["provider"]["opencode-go"]["models"]["deepseek-v4.1-flash"]
        self.assertEqual(model["limit"]["context"], 1000000)
        self.assertEqual(model["limit"]["output"], 384000)

    def test_ecco_overlay_is_instance_scoped_and_targets_800k(self) -> None:
        manager = BOT_MANAGER.read_text(encoding="utf-8")
        self.assertIn("OPENCODE_CONFIG_CONTENT", manager)
        self.assertIn('"context":832000', manager)
        self.assertIn('"output":384000', manager)
        self.assertIn('"reserved":16000', manager)
        # OpenCode 1.18.30 caps the declared output at 32k for this path.
        runtime_output = min(384000, 32000)
        self.assertEqual(832000 - runtime_output, 800000)
        self.assertEqual(1000000 - runtime_output, 968000)
        self.assertEqual(200000 - runtime_output, 168000)

    def test_go_provider_policy_identity_reaches_authority_helper(self) -> None:
        self.write_receipts()
        decided = self.call(**self.policy_env("CONTINUE_LOCAL"))
        self.assertEqual(decided.returncode, 0, decided.stderr)
        payload = json.loads(decided.stdout)
        self.assertEqual(payload["policy"]["provider"], "opencode-go")
        self.assertEqual(payload["policy"]["model_pool"], "deepseek-v4.1-flash")

    def test_public_policy_template_has_no_codex_binding(self) -> None:
        template = (REPO / "all/.bots/templates/opencode-continuity.env").read_text(encoding="utf-8")
        self.assertIn("OPENCODE_WARM_POLICY_ROOT=YOUR_AUTHORITY_STATE_ROOT", template)
        self.assertIn("OPENCODE_WARM_POLICY_PROVIDER=YOUR_POLICY_PROVIDER", template)
        self.assertIn("OPENCODE_WARM_POLICY_ACCOUNT_HASH=YOUR_OPAQUE_ACCOUNT_HASH", template)
        self.assertIn("OPENCODE_WARM_POLICY_MODEL_POOL=YOUR_MODEL_POOL", template)
        self.assertNotIn("fleet-preservation/codex", template)

    def test_policy_installer_rejects_placeholders_and_dry_runs_rendered_file(self) -> None:
        public = REPO / "all/.bots/templates/opencode-continuity.env"
        rejected = subprocess.run(
            [str(POLICY_INSTALLER), "--source", str(public)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("unresolved placeholder", rejected.stderr)
        source = self.root / "rendered-policy.env"
        values = self.nudge_env()
        source.write_text(
            "\n".join(f"{key}={value}" for key, value in values.items() if key.startswith("OPENCODE_WARM_")) + "\n",
            encoding="utf-8",
        )
        accepted = subprocess.run(
            [str(POLICY_INSTALLER), "--source", str(source), "--user", pwd.getpwuid(os.getuid()).pw_name],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("DRY-RUN", accepted.stdout)

    def test_stale_owner(self) -> None:
        self.write_receipts()
        self.write_owner(test_owner_bad=True)
        self.assert_refused(self.call(), "owner-inspect-not-running")
        self.assertEqual(self.fixture.posts, [])

    def test_missing_handoff_or_checkpoint(self) -> None:
        result = self.call()
        self.assert_refused(result, "checkpoint-receipt-missing")
        self.state_dir.mkdir(mode=0o700, exist_ok=True)
        (self.state_dir / "checkpoint.json").write_text("{}", encoding="utf-8")
        self.assert_refused(self.call(), "handoff-receipt-missing")

    def test_stale_telemetry_unknown_tokens_and_concurrent_compaction(self) -> None:
        self.write_receipts()
        self.assert_refused(self.call(observed_at=time.time() - 121), "telemetry-stale")
        self.write_messages(tokens={"input": 60000, "cache": {"read": 6000}})
        self.assert_refused(self.call(), "context-tokens-unknown")
        self.write_messages()
        self.state_dir.mkdir(mode=0o700, exist_ok=True)
        (self.state_dir / "state.json").write_text(json.dumps({"schema": "dotcortex.opencode-warm.v1", "in_flight": True}), encoding="utf-8")
        self.write_receipts()
        self.assert_refused(self.call(), "concurrent-compaction")

    def test_single_fire(self) -> None:
        self.write_receipts()
        first = self.call()
        second = self.call()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual([path for path, _body in self.fixture.posts], ["/session/session-1/summarize"])

    def test_authority_policy_can_preserve_warm_cache_without_compaction(self) -> None:
        self.write_receipts()
        decided = self.call(**self.policy_env("CONTINUE_LOCAL"))
        self.assertEqual(decided.returncode, 0, decided.stderr)
        payload = json.loads(decided.stdout)
        self.assertEqual(payload["reason"], "continuity-policy-continue")
        self.assertEqual(self.fixture.posts, [])

    def test_unbound_provider_endpoint_keeps_fixed_authority_ttl(self) -> None:
        self.write_receipts()
        completed_at = self.fixture.messages[-1]["info"]["time"]["completed"]
        environment = self.policy_env("CONTINUE_LOCAL")
        environment.update({
            "FLEET_CACHE_POLICY_HELPER": str(self.cache_policy_helper),
            "FLEET_CACHE_POLICY_PATH": str(self.cache_policy),
            "FIXTURE_CACHE_CALLS": str(self.root / "cache-calls"),
        })
        decided = self.call(**environment)
        self.assertEqual(decided.returncode, 0, decided.stderr)
        payload = json.loads(decided.stdout)
        self.assertEqual(payload["reason"], "continuity-policy-continue")
        self.assertAlmostEqual(
            payload["policy"]["request_cache_expires_at"] - completed_at,
            1800,
            delta=1,
        )
        self.assertEqual(payload["policy"]["cache_policy"], {"mode": "fallback", "reason": "endpoint-unknown"})
        self.assertFalse((self.root / "cache-calls").exists())
        self.assertEqual(self.fixture.posts, [])

    def test_wait_and_nudge_schedules_one_typed_timeark_job(self) -> None:
        self.write_receipts()
        self.arm_nudge()
        reset_at = time.time() + 30
        environment = self.nudge_env("WAIT_AND_NUDGE")
        environment["FIXTURE_RESET_AT"] = str(reset_at)
        decided = self.call(**environment)
        self.assertEqual(decided.returncode, 0, decided.stderr)
        payload = json.loads(decided.stdout)
        self.assertEqual(payload["action"], "waiting")
        scheduled = json.loads(self.scheduler_log.read_text(encoding="utf-8"))
        self.assertEqual((scheduled["lane"], scheduled["target"]), ("agent-wakeup", "opencode"))
        self.assertTrue(scheduled["id"].startswith("opencode:"))
        nudge = json.loads((self.state_dir / "nudge.json").read_text(encoding="utf-8"))
        self.assertEqual(nudge["reset_epoch"], int(reset_at))
        self.assertEqual(nudge["delivery_state"], "scheduled")

    def test_wait_and_nudge_never_reschedules_same_reset_epoch(self) -> None:
        self.write_receipts()
        reset_at = int(time.time() + 30)
        nudge = self.arm_nudge(reset_epoch=reset_at)
        nudge["sent_for_reset_epoch"] = reset_at
        (self.state_dir / "nudge.json").write_text(json.dumps(nudge), encoding="utf-8")
        environment = self.nudge_env("WAIT_AND_NUDGE")
        environment["FIXTURE_RESET_AT"] = str(reset_at)
        decided = self.call(**environment)
        self.assertEqual(decided.returncode, 0, decided.stderr)
        self.assertEqual(json.loads(decided.stdout)["reason"], "nudge-already-delivered-for-reset")
        self.assertFalse(self.scheduler_log.exists())

    def test_disarm_during_schedule_is_not_overwritten(self) -> None:
        self.write_receipts()
        self.arm_nudge()
        reset_at = int(time.time() + 30)
        environment = self.nudge_env("WAIT_AND_NUDGE")
        environment["FIXTURE_RESET_AT"] = str(reset_at)
        environment["FIXTURE_DISARM_PATH"] = str(self.state_dir / "nudge.json")
        decided = self.call(**environment)
        self.assertEqual(decided.returncode, 0, decided.stderr)
        self.assertEqual(json.loads(decided.stdout)["reason"], "nudge-disarmed-before-record")
        nudge = json.loads((self.state_dir / "nudge.json").read_text(encoding="utf-8"))
        self.assertEqual((nudge["policy"], nudge["agent_state"]), ("OFF", "DISARMED"))
        self.assertNotIn("job_id", nudge)

    def wakeup_job(self, reset_epoch: int) -> dict:
        module = load_module()
        owner = json.loads(self.owner_state.read_text(encoding="utf-8"))
        digest = __import__("hashlib").sha256(
            f"{module.owner_fingerprint(owner, 'session-1')}\0session-1\0{reset_epoch}".encode()
        ).hexdigest()
        handoff = json.loads((self.state_dir / "handoff.json").read_text(encoding="utf-8"))
        current = time.time()
        return {
            "schema": "timeark.oneshot.v1", "id": f"opencode:{digest}",
            "idempotency_key": f"opencode:{digest}", "due_at": current - 1,
            "expires_at": current + 300, "timezone": "Australia/Melbourne",
            "lane": "agent-wakeup", "target": "opencode", "reference": handoff["reference"],
            "state": "claimed", "claim_owner": "fixture-dispatcher", "lease_until": current + 60,
            "attempts": 1, "created_at": current - 60, "updated_at": current, "detail": "claimed",
        }

    def call_wakeup(self, job: dict, **environment_overrides: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update({
            "FLEET_CACHE_POLICY_HELPER": str(self.cache_policy_helper),
            "FLEET_CACHE_POLICY_PATH": str(self.root / "missing-policy.json"),
            "OPENCODE_WARM_STATE_DIR": str(self.state_dir),
            "OPENCODE_WARM_OWNER_STATE": str(self.owner_state),
            "OPENCODE_WARM_OWNER_HELPER": str(self.owner_helper),
            "OPENCODE_WARM_BASE_URL": f"http://127.0.0.1:{self.server.server_port}",
        })
        environment.update(self.policy_env("CONTINUE_LOCAL"))
        environment.update(environment_overrides)
        return subprocess.run(
            [str(WAKEUP)], input=json.dumps(job), capture_output=True, text=True,
            env=environment, timeout=10,
        )

    def test_wakeup_adapter_posts_once_and_replay_uses_receipt(self) -> None:
        self.write_receipts()
        reset_epoch = int(time.time())
        self.arm_nudge(reset_epoch=reset_epoch)
        job = self.wakeup_job(reset_epoch)
        first = self.call_wakeup(job)
        second = self.call_wakeup(job)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(first.stdout)["outcome"], "delivered")
        self.assertEqual(json.loads(second.stdout)["outcome"], "delivered")
        prompts = [entry for entry in self.fixture.posts if entry[0].endswith("/prompt_async")]
        self.assertEqual(len(prompts), 1)
        self.assertTrue(prompts[0][1]["messageID"].startswith("msg_"))

    def test_wakeup_timeout_is_uncertain_and_never_replayed(self) -> None:
        self.write_receipts()
        reset_epoch = int(time.time())
        self.arm_nudge(reset_epoch=reset_epoch)
        job = self.wakeup_job(reset_epoch)
        self.fixture.prompt_delay = 0.2
        first = self.call_wakeup(job, OPENCODE_WARM_API_TIMEOUT="0.05")
        second = self.call_wakeup(job, OPENCODE_WARM_API_TIMEOUT="0.05")
        self.assertEqual(json.loads(first.stdout)["outcome"], "uncertain")
        self.assertEqual(json.loads(second.stdout)["outcome"], "uncertain")
        prompts = [entry for entry in self.fixture.posts if entry[0].endswith("/prompt_async")]
        self.assertEqual(len(prompts), 1)

    def test_invalid_policy_response_falls_back_to_native_compaction(self) -> None:
        self.write_receipts()
        self.policy_helper.write_text("#!/bin/sh\nprintf '{}\\n'\n", encoding="utf-8")
        self.policy_helper.chmod(0o700)
        decided = self.call(**self.policy_env())
        self.assertEqual(decided.returncode, 0, decided.stderr)
        payload = json.loads(decided.stdout)
        self.assertEqual(payload["policy"]["mode"], "policy-response-invalid")
        self.assertEqual([path for path, _body in self.fixture.posts], ["/session/session-1/summarize"])

    def test_nudge_controls_are_durable_and_force_is_one_shot_pending(self) -> None:
        environment = os.environ.copy()
        environment["OPENCODE_WARM_STATE_DIR"] = str(self.state_dir)
        armed = subprocess.run(
            [str(WARMCTL), "arm"], capture_output=True, text=True,
            env=environment, timeout=5,
        )
        self.assertEqual(armed.returncode, 0, armed.stderr)
        self.assertEqual(json.loads(armed.stdout)["agent_state"], "ARMED")
        forced = subprocess.run(
            [str(WARMCTL), "force-next"], capture_output=True, text=True,
            env=environment, timeout=5,
        )
        self.assertEqual(forced.returncode, 0, forced.stderr)
        self.assertTrue(json.loads(forced.stdout)["force_pending"])
        disarmed = subprocess.run(
            [str(WARMCTL), "disarm"], capture_output=True, text=True,
            env=environment, timeout=5,
        )
        state = json.loads(disarmed.stdout)
        self.assertEqual((state["policy"], state["agent_state"]), ("OFF", "DISARMED"))
        self.assertFalse(state["force_pending"])
        status = subprocess.run(
            [str(WARMCTL), "status"], capture_output=True, text=True,
            env=environment, timeout=5,
        )
        self.assertEqual(json.loads(status.stdout)["nudge"]["policy"], "OFF")

    def test_checkpoint_control_prepares_without_compacting(self) -> None:
        environment = os.environ.copy()
        environment.update({
            "FLEET_CACHE_POLICY_HELPER": str(self.cache_policy_helper),
            "FLEET_CACHE_POLICY_PATH": str(self.root / "missing-policy.json"),
            "OPENCODE_WARM_STATE_DIR": str(self.state_dir),
            "OPENCODE_WARM_OWNER_STATE": str(self.owner_state),
            "OPENCODE_WARM_OWNER_HELPER": str(self.owner_helper),
            "OPENCODE_WARM_BASE_URL": f"http://127.0.0.1:{self.server.server_port}",
            "OPENCODE_WARM_MIN_CONTEXT_TOKENS": "70000",
        })
        checkpointed = subprocess.run(
            [str(WARMCTL), "checkpoint", "session-1"], capture_output=True,
            text=True, env=environment, timeout=10,
        )
        self.assertEqual(checkpointed.returncode, 0, checkpointed.stderr)
        self.assertEqual(json.loads(checkpointed.stdout)["action"], "prepared")
        self.assertEqual(self.fixture.posts, [])

    def test_authority_policy_can_preserve_warm_cache_without_compaction(self) -> None:
        self.write_receipts()
        completed = self.call(**self.policy_env())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["reason"], "continuity-policy-continue")
        self.assertEqual(self.fixture.posts, [])

    def test_incomplete_policy_binding_falls_back_to_native_compaction(self) -> None:
        self.write_receipts()
        completed = self.call(OPENCODE_WARM_POLICY_HELPER=str(self.policy_helper))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual([path for path, _body in self.fixture.posts], ["/session/session-1/summarize"])
        self.assertEqual(json.loads(completed.stdout)["policy"]["mode"], "policy-binding-incomplete")

    def test_event_bridge_prepares_handoff_and_fires(self) -> None:
        environment = os.environ.copy()
        environment.update({
            "XDG_STATE_HOME": str(self.root / "xdg-state"),
            "FLEET_CACHE_POLICY_HELPER": str(self.cache_policy_helper),
            "FLEET_CACHE_POLICY_PATH": str(self.root / "missing-policy.json"),
            "OPENCODE_WARM_STATE_DIR": str(self.state_dir),
            "OPENCODE_WARM_OWNER_STATE": str(self.owner_state),
            "OPENCODE_WARM_OWNER_HELPER": str(self.owner_helper),
            "OPENCODE_WARM_BASE_URL": f"http://127.0.0.1:{self.server.server_port}",
            "OPENCODE_WARM_MIN_CONTEXT_TOKENS": "70000",
        })
        invoked = subprocess.run([
            str(WARM_EVENT), "--session", "session-1", "--event", "session.idle",
            "--observed-at", str(time.time()),
        ], capture_output=True, text=True, env=environment, timeout=15)
        self.assertEqual(invoked.returncode, 0, invoked.stderr)
        self.assertEqual([path for path, _body in self.fixture.posts], ["/session/session-1/summarize"])
        handoff = json.loads((self.state_dir / "handoff.json").read_text(encoding="utf-8"))
        self.assertEqual(handoff["session_id"], "session-1")
        self.assertEqual(handoff["message_id"], "assistant-1")
        self.assertTrue(handoff["reference"].startswith("continuity://opencode/"))
        self.assertEqual(handoff["critical"]["next"], "wait-for-explicit-input")

    def test_failed_compaction_can_retry(self) -> None:
        self.write_receipts()
        self.fixture.legacy_status = 500
        self.assert_refused(self.call(), "legacy-summarize-http-500")
        state = json.loads((self.state_dir / "state.json").read_text(encoding="utf-8"))
        self.assertFalse(state["in_flight"])
        self.fixture.legacy_status = 204
        self.assertEqual(self.call().returncode, 0)
        self.assertEqual(len(self.fixture.posts), 2)

    def test_summarize_read_timeout_remains_pending_until_native_event(self) -> None:
        self.write_receipts()
        self.fixture.summarize_delay = 0.2
        requested = self.call(OPENCODE_WARM_API_TIMEOUT="0.05")
        self.assertEqual(requested.returncode, 0, requested.stderr)
        state = json.loads((self.state_dir / "state.json").read_text(encoding="utf-8"))
        receipt = json.loads((self.state_dir / "receipt.json").read_text(encoding="utf-8"))
        self.assertTrue(state["in_flight"])
        self.assertEqual(receipt["status"], "pending")
        self.assertEqual(receipt["response"], "timeout-pending")
        self.write_compaction_event()
        self.add_summary(completed_at=time.time() + 0.3)
        confirmed = self.call(event="session.compacted")
        self.assertEqual(confirmed.returncode, 0, confirmed.stderr)
        receipt = json.loads((self.state_dir / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "success")

    def test_success_resets_compaction_gate_and_records_receipt(self) -> None:
        self.write_receipts()
        self.assertEqual(self.call().returncode, 0)
        state = json.loads((self.state_dir / "state.json").read_text(encoding="utf-8"))
        receipt = json.loads((self.state_dir / "receipt.json").read_text(encoding="utf-8"))
        self.assertTrue(state["in_flight"])
        self.assertEqual(receipt["status"], "pending")
        self.write_compaction_event()
        self.add_summary()
        confirmed = self.call(event="session.compacted")
        self.assertEqual(confirmed.returncode, 0, confirmed.stderr)
        state = json.loads((self.state_dir / "state.json").read_text(encoding="utf-8"))
        receipt = json.loads((self.state_dir / "receipt.json").read_text(encoding="utf-8"))
        self.assertFalse(state["in_flight"])
        self.assertEqual(state["current_tokens"], 0)
        self.assertEqual(receipt["status"], "success")
        self.assertEqual(receipt["summary_message_id"], "summary-1")
        self.assertEqual(receipt["transport"], "legacy-summarize")

    def test_compaction_confirmation_requires_event_and_summary(self) -> None:
        self.write_receipts()
        self.assertEqual(self.call().returncode, 0)
        self.assert_refused(self.call(event="session.compacted"), "compaction-event-missing")
        self.write_compaction_event()
        self.assert_refused(self.call(event="session.compacted"), "compaction-summary-missing")

    def test_new_message_before_summarize_invalidates_request(self) -> None:
        self.write_receipts()
        self.fixture.mutate_message_on_second_get = True
        self.assert_refused(self.call(), "session-changed-before-summarize")
        self.assertEqual(self.fixture.posts, [])

    def test_v2_probe_flag_never_sends_a_mutating_probe(self) -> None:
        self.write_receipts()
        result = self.call(OPENCODE_WARM_V2_PROBE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([path for path, _body in self.fixture.posts], [
            "/session/session-1/summarize",
        ])
        receipt = json.loads((self.state_dir / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "pending")
        self.assertEqual(receipt["v2"], "disabled-untrusted")

    def test_warmctl_status_is_read_only_and_help_is_lawful(self) -> None:
        environment = os.environ.copy()
        environment["OPENCODE_WARM_STATE_DIR"] = str(self.state_dir)
        help_result = subprocess.run([str(WARMCTL), "--help"], capture_output=True, text=True, env=environment)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("status", help_result.stdout)
        status = subprocess.run([str(WARMCTL), "status"], capture_output=True, text=True, env=environment)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout), {"nudge": None, "receipt": None, "state": None})
        self.assertFalse(self.state_dir.exists())

    def test_plugin_injects_bounded_handoff_and_disables_autocontinue(self) -> None:
        self.write_receipts()
        environment = os.environ.copy()
        environment["OPENCODE_WARM_STATE_DIR"] = str(self.state_dir)
        script = f'''import {{ OpenCodeContinuityPlugin }} from {json.dumps(PLUGIN.as_uri())};
const hooks = await OpenCodeContinuityPlugin();
const compacting = {{context: []}};
await hooks["experimental.session.compacting"]({{sessionID: "session-1"}}, compacting);
const continuation = {{enabled: true}};
await hooks["experimental.compaction.autocontinue"]({{sessionID: "session-1"}}, continuation);
console.log(JSON.stringify({{context: compacting.context, enabled: continuation.enabled}}));'''
        invoked = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True, text=True, env=environment, timeout=10,
        )
        self.assertEqual(invoked.returncode, 0, invoked.stderr)
        value = json.loads(invoked.stdout)
        self.assertFalse(value["enabled"])
        self.assertEqual(len(value["context"]), 1)
        self.assertIn("continuity://fixture/handoff-1", value["context"][0])
        self.assertIn("never-touch-production", value["context"][0])

    def test_plugin_rejects_stale_handoff(self) -> None:
        self.write_receipts(handoff={"created_at": time.time() - 1801})
        environment = os.environ.copy()
        environment["OPENCODE_WARM_STATE_DIR"] = str(self.state_dir)
        script = f'''import {{ OpenCodeContinuityPlugin }} from {json.dumps(PLUGIN.as_uri())};
const hooks = await OpenCodeContinuityPlugin();
const compacting = {{context: []}};
await hooks["experimental.session.compacting"]({{sessionID: "session-1"}}, compacting);
const continuation = {{enabled: true}};
await hooks["experimental.compaction.autocontinue"]({{sessionID: "session-1"}}, continuation);
console.log(JSON.stringify({{context: compacting.context, enabled: continuation.enabled}}));'''
        invoked = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True, text=True, env=environment, timeout=10,
        )
        self.assertEqual(invoked.returncode, 0, invoked.stderr)
        self.assertEqual(json.loads(invoked.stdout), {"context": [], "enabled": True})

    def test_plugin_dispatches_idle_and_compacted_events(self) -> None:
        dispatch_log = self.root / "dispatch.log"
        dispatcher = self.root / "dispatcher"
        dispatcher.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$OPENCODE_TEST_DISPATCH_LOG\"\n",
            encoding="utf-8",
        )
        dispatcher.chmod(0o700)
        environment = os.environ.copy()
        environment.update({
            "FLEET_CACHE_POLICY_HELPER": str(self.cache_policy_helper),
            "FLEET_CACHE_POLICY_PATH": str(self.root / "missing-policy.json"),
            "OPENCODE_WARM_STATE_DIR": str(self.state_dir),
            "OPENCODE_WARM_EVENT_BIN": str(dispatcher),
            "OPENCODE_TEST_DISPATCH_LOG": str(dispatch_log),
            "OPENCODE_WARM_IDLE_DELAY_SECONDS": "0",
        })
        script = f'''import {{ OpenCodeContinuityPlugin }} from {json.dumps(PLUGIN.as_uri())};
const hooks = await OpenCodeContinuityPlugin();
await hooks.event({{event: {{type: "session.idle", properties: {{sessionID: "session-1"}}}}}});
await hooks.event({{event: {{type: "session.compacted", properties: {{sessionID: "session-1"}}}}}});'''
        invoked = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True, text=True, env=environment, timeout=10,
        )
        self.assertEqual(invoked.returncode, 0, invoked.stderr)
        lines = dispatch_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("--session session-1 --event session.idle --observed-at", lines[0])
        self.assertIn("--session session-1 --event session.compacted --observed-at", lines[1])
        event = json.loads((self.state_dir / "events/session-1.json").read_text(encoding="utf-8"))
        self.assertEqual(event["type"], "session.compacted")

    def test_plugin_resets_idle_timer_after_each_quiet_boundary(self) -> None:
        dispatch_log = self.root / "delayed-dispatch.log"
        dispatcher = self.root / "delayed-dispatcher"
        dispatcher.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$OPENCODE_TEST_DISPATCH_LOG\"\n",
            encoding="utf-8",
        )
        dispatcher.chmod(0o700)
        environment = os.environ.copy()
        environment.update({
            "FLEET_CACHE_POLICY_HELPER": str(self.cache_policy_helper),
            "FLEET_CACHE_POLICY_PATH": str(self.root / "missing-policy.json"),
            "OPENCODE_WARM_STATE_DIR": str(self.state_dir),
            "OPENCODE_WARM_EVENT_BIN": str(dispatcher),
            "OPENCODE_TEST_DISPATCH_LOG": str(dispatch_log),
            "OPENCODE_WARM_IDLE_DELAY_SECONDS": "0.05",
        })
        script = f'''import {{ OpenCodeContinuityPlugin }} from {json.dumps(PLUGIN.as_uri())};
const hooks = await OpenCodeContinuityPlugin();
await hooks.event({{event: {{type: "session.idle", properties: {{sessionID: "session-1"}}}}}});
await new Promise(resolve => setTimeout(resolve, 20));
await hooks.event({{event: {{type: "session.idle", properties: {{sessionID: "session-1"}}}}}});
await new Promise(resolve => setTimeout(resolve, 80));'''
        invoked = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True, text=True, env=environment, timeout=10,
        )
        self.assertEqual(invoked.returncode, 0, invoked.stderr)
        lines = dispatch_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIn("--event session.idle", lines[0])


def load_module():
    loader = SourceFileLoader("opencode_warm", str(WARM))
    spec = importlib.util.spec_from_loader("opencode_warm", loader)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    unittest.main()
