"""Unit tests for the Ductor idle-compaction seam (no network, no real CLI).

Loads idle_compact.py from the DotCortex seam directory (next to this tests
directory, or DOTCORTEX_DUCTOR_SEAMS) against the installed ductor_bot.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import importlib.util
import os
import sys
from unittest import mock
from ductor_bot.session.key import SessionKey

try:
    import ductor_bot  # noqa: F401  (the seam imports ductor_bot.cli.types)
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("ductor_bot is not installed")

_SEAMS = Path(os.environ.get("DOTCORTEX_DUCTOR_SEAMS", Path(__file__).resolve().parents[1] / "ductor-seams"))
_spec = importlib.util.spec_from_file_location("ductor_idle_compact_seam", _SEAMS / "idle_compact.py")
ic = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ic
_spec.loader.exec_module(ic)


@dataclass
class FakeSession:
    session_id: str
    provider: str
    last_active: str
    model: str = "m"
    reasoning_effort: str = ""
    chat_id: int = 1

    @property
    def session_key(self):
        return SessionKey(chat_id=self.chat_id)


class FakeSessions:
    def __init__(self, sessions):
        self.sessions = sessions

    async def list_all(self):
        return list(self.sessions)

    async def get_active(self, key):
        for s in self.sessions:
            if s.chat_id == key.chat_id:
                return s
        return None


class FakeLockPool:
    def __init__(self):
        self.locks = {}

    def get(self, key):
        return self.locks.setdefault(key, asyncio.Lock())


@dataclass
class FakeCLI:
    calls: list = field(default_factory=list)

    async def execute(self, request):
        self.calls.append(request)
        return SimpleNamespace(is_error=False, result="", session_id=request.resume_session)


def ago(minutes: float) -> str:
    return (datetime.now(UTC) - timedelta(minutes=minutes)).isoformat()


class FakeCodexClient:
    """Canned app-server replies: no subprocess, no network."""

    def __init__(self, account, config):
        self._account = account
        self._config = config
        self.calls: list[str] = []
        self._proc = SimpleNamespace(returncode=None)
        self._reader = SimpleNamespace(done=lambda: False)
        self._environment = {}
        self._cwd = "/fixture/workspace"

    verified_subscription_identity = ic._CodexAppServer.verified_subscription_identity

    async def start(self):
        self.calls.append("start")

    async def close(self):
        self.calls.append("close")

    async def request(self, method, params=None, **kwargs):
        self.calls.append(method)
        if method == "account/read":
            return self._account
        if method == "config/read":
            return self._config
        if method == "account/rateLimits/read":
            return {"accountId": self._account.get("workspaceRouting", {}).get("chatgptAccountId")}
        return {}

    async def wait_compaction(self, session_id, timeout=None):
        self.calls.append("wait_compaction")
        return True


class IdleCompactTests(unittest.IsolatedAsyncioTestCase):
    def make(self, sessions, config=None, busy=False):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "config").mkdir()
        (tmp / "config" / "config.json").write_text(json.dumps(config or {}))
        cli = FakeCLI()
        orch = SimpleNamespace(
            _paths=SimpleNamespace(
                sessions_path=tmp / "sessions.json",
                config_path=tmp / "config" / "config.json",
                workspace=tmp,
            ),
            _sessions=FakeSessions(sessions),
            _lock_pool=FakeLockPool(),
            _cli_service=cli,
            is_chat_busy=lambda chat_id, topic_id=None: busy,
        )
        comp = ic.IdleCompactor(orch)
        codex_calls = []

        async def fake_codex(session, settings):
            codex_calls.append(session.session_id)
            return "done"

        comp._compact_codex = fake_codex
        return comp, cli, codex_calls, tmp

    async def tick(self, comp):
        await comp._tick(comp._settings())

    async def test_claude_compacts_after_55_minutes_once(self):
        s = FakeSession("c1", "claude", ago(56))
        comp, cli, _, _ = self.make([s])
        await self.tick(comp)
        await self.tick(comp)
        self.assertEqual([r.prompt for r in cli.calls], ["/compact"])
        self.assertEqual(cli.calls[0].resume_session, "c1")

    async def test_claude_not_before_threshold(self):
        comp, cli, _, _ = self.make([FakeSession("c1", "claude", ago(40))])
        await self.tick(comp)
        self.assertEqual(cli.calls, [])

    async def test_codex_compacts_after_25_not_claude_window(self):
        comp, cli, codex, _ = self.make([FakeSession("x1", "codex", ago(26))])
        await self.tick(comp)
        self.assertEqual(codex, ["x1"])
        self.assertEqual(cli.calls, [])

    # -- native subscription gate ---------------------------------------------

    def native_account(self, **overrides):
        account = {"type": "chatgpt", "chatgptAccountId": "acct-123"}
        account.update(overrides)
        return {"requiresOpenaiAuth": True, "account": account,
                "workspaceRouting": {"backendOrigin": "https://chatgpt.com",
                                     "chatgptAccountId": account["chatgptAccountId"]}}

    def native_config(self, effective=None, origins=None):
        return {"config": effective if effective is not None else {},
                "origins": origins if origins is not None else {}}

    async def identity(self, account=None, config=None):
        comp, _, _, _ = self.make([])
        client = FakeCodexClient(account or self.native_account(),
                                 config or self.native_config())
        return await client.verified_subscription_identity(), client

    async def test_native_chatgpt_subscription_is_accepted(self):
        identity, _ = await self.identity()
        self.assertEqual(identity["auth_mode"], "chatgpt")
        self.assertEqual(len(identity["account_key"]), 64)
        self.assertNotIn("acct-123", json.dumps(identity))

    async def test_api_key_profile_is_not_a_subscription(self):
        identity, _ = await self.identity(account={
            "requiresOpenaiAuth": True,
            "account": {"type": "apiKey"},
            "workspaceRouting": {"backendOrigin": "https://chatgpt.com",
                                 "chatgptAccountId": "acct-123"}})
        self.assertIsNone(identity)

    async def test_custom_provider_route_is_rejected(self):
        identity, _ = await self.identity(config=self.native_config(
            {"model_provider": "azure", "base_url": "https://example.invalid"}))
        self.assertIsNone(identity)

    async def test_api_key_override_is_rejected(self):
        identity, _ = await self.identity(config=self.native_config({"api_key": "sk-x"}))
        self.assertIsNone(identity)

    async def test_foreign_backend_origin_is_rejected(self):
        identity, _ = await self.identity(account={
            "requiresOpenaiAuth": True, "account": {"type": "chatgpt"},
            "workspaceRouting": {"backendOrigin": "https://api.openai.com",
                                 "chatgptAccountId": "acct-123"}})
        self.assertIsNone(identity)

    async def test_unverified_subscription_suppresses_and_never_compacts(self):
        comp, _, _, _ = self.make([])
        session = FakeSession("x1", "codex", ago(26))
        settings = comp._settings()
        client = FakeCodexClient({"requiresOpenaiAuth": True, "account": {"type": "apiKey"},
                                  "workspaceRouting": {}}, self.native_config())
        with mock.patch.object(ic.shutil, "which", return_value="/usr/bin/codex"), \
                mock.patch.object(ic, "_CodexAppServer", lambda cli, cwd: client):
            outcome = await ic.IdleCompactor._compact_codex(comp, session, settings)
        self.assertEqual(outcome, "suppressed")
        self.assertEqual(client.calls[:3], ["start", "account/read", "config/read"])
        self.assertNotIn("thread/resume", client.calls)
        self.assertNotIn("thread/compact/start", client.calls)

    async def test_verified_subscription_suppresses_and_never_compacts(self):
        comp, _, _, _ = self.make([])
        session = FakeSession("x1", "codex", ago(26))
        client = FakeCodexClient(self.native_account(), self.native_config())
        with mock.patch.object(ic.shutil, "which", return_value="/usr/bin/codex"), \
                mock.patch.object(ic, "_CodexAppServer", lambda cli, cwd: client):
            outcome = await ic.IdleCompactor._compact_codex(comp, session, comp._settings())
        self.assertEqual(outcome, "suppressed")
        self.assertNotIn("thread/resume", client.calls)
        self.assertNotIn("thread/compact/start", client.calls)

    async def test_expired_cache_is_skipped_and_marked(self):
        comp, cli, codex, tmp = self.make(
            [FakeSession("x1", "codex", ago(31)), FakeSession("c1", "claude", ago(61), chat_id=2)]
        )
        await self.tick(comp)
        self.assertEqual((codex, cli.calls), ([], []))
        self.assertEqual(set(json.loads((tmp / "idle_compaction.json").read_text())), {"x1", "c1"})

    async def test_new_activity_rearms(self):
        s = FakeSession("c1", "claude", ago(56))
        comp, cli, _, _ = self.make([s])
        await self.tick(comp)
        s.last_active = ago(57)  # a later turn, idle again
        await self.tick(comp)
        self.assertEqual(len(cli.calls), 2)

    async def test_busy_chat_defers(self):
        comp, cli, _, _ = self.make([FakeSession("c1", "claude", ago(56))], busy=True)
        await self.tick(comp)
        self.assertEqual(cli.calls, [])

    async def test_config_overrides_and_disable(self):
        comp, cli, codex, _ = self.make(
            [FakeSession("x1", "codex", ago(21))], config={"idle_compaction": {"codex_idle_minutes": 20}}
        )
        await self.tick(comp)
        self.assertEqual(codex, ["x1"])
        comp2, cli2, _, _ = self.make([FakeSession("c1", "claude", ago(56))], config={"idle_compaction": {"enabled": False}})
        comp2.start()
        self.assertIsNone(comp2._task)

    async def test_state_survives_restart(self):
        s = FakeSession("c1", "claude", ago(56))
        comp, cli, _, tmp = self.make([s])
        await self.tick(comp)
        comp_b = ic.IdleCompactor(comp._orch)
        await self.tick(comp_b)
        self.assertEqual(len(cli.calls), 1)

    async def test_other_providers_ignored(self):
        comp, cli, codex, _ = self.make([FakeSession("g1", "gemini", ago(500))])
        await self.tick(comp)
        self.assertEqual((codex, cli.calls), ([], []))

    def test_window_resolves_current_model_and_preserves_fallback(self):
        settings = ic.IdleCompactSettings()
        decision = {
            "compact_before_seconds": 7080,
            "cache_expires_seconds": 7200,
        }
        completed = SimpleNamespace(stdout=json.dumps(decision))
        with mock.patch.object(ic.subprocess, "run", return_value=completed) as run:
            self.assertEqual(settings.window("codex", "gpt-5.6-sol"), (7080.0, 7200.0))
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--model") + 1], "gpt-5.6-sol")
        with mock.patch.object(ic.subprocess, "run", side_effect=OSError("offline")):
            self.assertEqual(settings.window("codex", "gpt-5.6-sol"), (1500.0, 1800.0))


class SubscriptionIdleTests(IdleCompactTests):
    def native(self):
        client = ic._CodexAppServer("codex", "/fixture/workspace")
        client._proc = SimpleNamespace(returncode=None)
        client._reader = SimpleNamespace(done=lambda: False)
        client._environment = {}
        account = {"requiresOpenaiAuth": True, "account": {"type": "chatgpt"},
                   "workspaceRouting": {"backendOrigin": "https://chatgpt.com",
                       "chatgptAccountId": "fixture-account", "accountRoutingOverride": "NO_CONSTRAINT"}}
        config = {"config": {"model_provider": None, "model_providers": {},
            "chatgpt_base_url": "https://chatgpt.com/backend-api/", "base_url": None,
            "openai_base_url": None, "api_base": None, "api_key": None}, "origins": {}}
        limits = {"accountId": "fixture-account"}
        async def request(method, params):
            return {"account/read": account, "config/read": config,
                    "account/rateLimits/read": limits}[method]
        client.request = mock.AsyncMock(side_effect=request)
        client.start = mock.AsyncMock()
        client.close = mock.AsyncMock()
        client.wait_compaction = mock.AsyncMock(return_value=True)
        return client, account, config, limits

    async def test_native_defaults_verify_without_physical_expiry_claim(self):
        client, _, _, _ = self.native()
        result = await client.verified_subscription_identity()
        self.assertEqual(len(result["account_key"]), 64)
        self.assertFalse(result["physical_expiry_known"])
        self.assertEqual(result["source_url"], ic._SUBSCRIPTION_CACHE_SOURCE)
        self.assertEqual(client.request.await_args_list[1].args,
            ("config/read", {"includeLayers": False, "cwd": "/fixture/workspace"}))
        for call in client.request.await_args_list:
            if call.args[0] == "account/read":
                self.assertEqual(call.args[1], {"refreshToken": False})

    async def test_verified_subscription_suppresses_before_resume_once(self):
        session = FakeSession("x1", "codex", ago(26))
        comp, _, _, tmp = self.make([session])
        comp._compact_codex = ic.IdleCompactor._compact_codex.__get__(comp)
        client, _, _, _ = self.native()
        with mock.patch.object(ic, "_CodexAppServer", return_value=client), \
                mock.patch.object(ic.shutil, "which", return_value="codex"), \
                self.assertLogs(ic.logger, "INFO") as logs:
            await self.tick(comp)
            await self.tick(comp)
        methods = [c.args[0] for c in client.request.await_args_list]
        self.assertNotIn("thread/resume", methods)
        self.assertNotIn("thread/compact/start", methods)
        client.start.assert_awaited_once()
        client.wait_compaction.assert_not_awaited()
        client.close.assert_awaited_once()
        self.assertTrue(any("suppressed" in row for row in logs.output))
        self.assertFalse(any("Idle compaction done" in row for row in logs.output))
        self.assertEqual(session.last_active, json.loads((tmp / "idle_compaction.json").read_text())["x1"])
        self.assertEqual(comp._compacting, set())
        self.assertEqual(session.session_id, "x1")

    async def test_api_custom_mismatch_and_overrides_do_not_verify(self):
        for case in ("api", "provider", "custom", "backend", "account", "origin",
                     "origins_missing", "base", "key", "environment", "malformed"):
            with self.subTest(case=case):
                client, account, config, limits = self.native()
                if case == "api": account["account"]["type"] = "apiKey"
                elif case == "provider": config["config"]["model_provider"] = "custom"
                elif case == "custom": config["config"]["model_providers"]["openai"] = {}
                elif case == "backend": account["workspaceRouting"]["backendOrigin"] = "https://custom.invalid"
                elif case == "account": limits["accountId"] = "another-account"
                elif case == "origin": config["origins"]["chatgpt_base_url"] = {}
                elif case == "origins_missing": config.pop("origins")
                elif case == "base": config["config"]["chatgpt_base_url"] = "https://custom.invalid"
                elif case == "key": config["config"]["api_key"] = "fixture-key"
                elif case == "environment": client._environment["OPENAI_API_KEY"] = "fixture-key"
                elif case == "malformed": account["account"] = None
                self.assertIsNone(await client.verified_subscription_identity())

    async def test_failure_dead_or_replaced_connection_never_verifies(self):
        for case in ("rpc_error", "timeout", "exit", "replacement", "reader_exit", "account_switch"):
            with self.subTest(case=case):
                client, _, _, _ = self.native()
                original = client.request.side_effect
                async def request(method, params):
                    if case == "rpc_error": raise RuntimeError("fixture RPC failure")
                    if case == "timeout": raise TimeoutError()
                    result = await original(method, params)
                    if case == "exit": client._proc.returncode = 1
                    if case == "replacement": client._proc = SimpleNamespace(returncode=None)
                    if case == "reader_exit": client._reader = SimpleNamespace(done=lambda: True)
                    if case == "account_switch" and client.request.await_count == 4:
                        return {"requiresOpenaiAuth": True, "account": {"type": "chatgpt"},
                                "workspaceRouting": {"chatgptAccountId": "another-account"}}
                    return result
                client.request.side_effect = request
                self.assertIsNone(await client.verified_subscription_identity())

    async def test_unverified_scope_retains_conservative_suppression(self):
        comp, _, _, _ = self.make([])
        client, _, _, _ = self.native()
        client.verified_subscription_identity = mock.AsyncMock(return_value=None)
        client.request = mock.AsyncMock(return_value={})
        with mock.patch.object(ic, "_CodexAppServer", return_value=client), \
                mock.patch.object(ic.shutil, "which", return_value="codex"):
            result = await ic.IdleCompactor._compact_codex(comp,
                FakeSession("x1", "codex", ago(26)), ic.IdleCompactSettings())
        self.assertEqual(result, "suppressed")
        client.request.assert_not_awaited()
        client.wait_compaction.assert_not_awaited()
        client.close.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
