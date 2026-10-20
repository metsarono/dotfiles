"""Disposable-copy checks for Nano's atomic Telegram idle admission seam."""
from __future__ import annotations

import asyncio
import contextlib
import importlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import MethodType, SimpleNamespace
import unittest


ALL_OVERLAY = Path(__file__).resolve().parents[4]
PATCH = Path(os.environ.get("NANOBOT_IDLE_PROMPT_TEST_PATCH", str(ALL_OVERLAY / ".bots/patches/nanobot-idle-prompt.patch")))


class NanoIdlePromptSeamTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source_value = os.environ.get("NANOBOT_SOURCE", "").strip()
        if source_value:
            source = Path(source_value).resolve()
        else:
            spec = importlib.util.find_spec("nanobot")
            if spec is None or not spec.submodule_search_locations:
                raise unittest.SkipTest("declared Nano runtime is unavailable")
            source = Path(next(iter(spec.submodule_search_locations)))
        if not (source / "agent/loop.py").is_file() \
                or not (source / "cli/gateway_runtime.py").is_file():
            raise unittest.SkipTest("NANOBOT_SOURCE lacks the pinned runtime files")
        cls.temporary = tempfile.TemporaryDirectory(prefix="nano-idle-prompt-")
        cls.site = Path(cls.temporary.name) / "site"
        shutil.copytree(source, cls.site / "nanobot")
        applied = subprocess.run(
            ["patch", "--batch", "--fuzz=0", "-d", str(cls.site), "-p1", "-i", str(PATCH)],
            text=True, capture_output=True, check=False,
        )
        if applied.returncode:
            raise AssertionError(applied.stdout + applied.stderr)
        compiled = subprocess.run(
            [sys.executable, "-m", "py_compile",
             str(cls.site / "nanobot/agent/loop.py"),
             str(cls.site / "nanobot/cli/gateway_runtime.py")],
            text=True, capture_output=True, check=False,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)
        for name in tuple(sys.modules):
            if name == "nanobot" or name.startswith("nanobot."):
                sys.modules.pop(name, None)
        sys.path.insert(0, str(cls.site))
        importlib.invalidate_caches()
        from nanobot.agent.loop import AgentLoop
        from nanobot.bus.events import InboundMessage
        cls.AgentLoop = AgentLoop
        cls.InboundMessage = InboundMessage

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "site"):
            with contextlib.suppress(ValueError):
                sys.path.remove(str(cls.site))
        for name in tuple(sys.modules):
            if name == "nanobot" or name.startswith("nanobot."):
                sys.modules.pop(name, None)
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    def make_loop(self):
        entered, finish = asyncio.Event(), asyncio.Event()
        lock = asyncio.Lock()
        calls = []
        class Publisher:
            async def user_input_accepted(inner, message, session_key):
                calls.append(("accepted", message.channel, session_key))
        fake = SimpleNamespace(
            _running=True, _active_tasks={}, _background_tasks=set(),
            _deferred_automation_turns={}, _pending_queues={},
            _session_locks={"telegram:YOUR_CHAT_ID": lock},
            _concurrency_gate=None, _unified_session=False,
            bus=SimpleNamespace(inbound_size=0),
            runtime_event_publisher=Publisher(),
        )
        fake._effective_session_key = MethodType(self.AgentLoop._effective_session_key, fake)
        fake._get_session_lock = lambda session_key: fake._session_locks.setdefault(
            session_key, asyncio.Lock())
        fake._track_active_task = MethodType(self.AgentLoop._track_active_task, fake)
        fake._active_task_done = MethodType(self.AgentLoop._active_task_done, fake)
        fake._idle_prompt_lock_claimable = self.AgentLoop._idle_prompt_lock_claimable
        fake.idle_prompt_busy = MethodType(self.AgentLoop.idle_prompt_busy, fake)
        async def dispatch(message, *, _admitted_lock=None):
            calls.append(("dispatch", message.channel, message.chat_id, message.session_key))
            self.assertIs(_admitted_lock, lock)
            self.assertTrue(lock.locked())
            entered.set()
            await finish.wait()
        fake._dispatch = dispatch
        message = self.InboundMessage(
            channel="telegram", sender_id="mailcortex", chat_id="YOUR_CHAT_ID",
            content="MailCortex delivery", session_key_override="telegram:YOUR_CHAT_ID",
        )
        return fake, message, lock, entered, finish, calls

    async def test_acceptance_reserves_real_session_lock_before_ack(self):
        fake, message, lock, entered, finish, calls = self.make_loop()
        outcome = await self.AgentLoop.try_admit_idle_message(fake, message)
        self.assertEqual(outcome, "accepted")
        self.assertTrue(lock.locked())
        await entered.wait()
        self.assertEqual(calls[-1], (
            "dispatch", "telegram", "YOUR_CHAT_ID", "telegram:YOUR_CHAT_ID"))
        finish.set()
        await asyncio.gather(*tuple(fake._active_tasks["telegram:YOUR_CHAT_ID"]))
        await asyncio.sleep(0)
        self.assertFalse(lock.locked())

    async def test_second_admission_is_busy_and_never_dispatches(self):
        fake, message, lock, entered, finish, calls = self.make_loop()
        self.assertEqual(
            await self.AgentLoop.try_admit_idle_message(fake, message), "accepted")
        await entered.wait()
        self.assertEqual(
            await self.AgentLoop.try_admit_idle_message(fake, message), "busy")
        self.assertEqual(sum(item[0] == "dispatch" for item in calls), 1)
        finish.set()
        await asyncio.gather(*tuple(fake._active_tasks["telegram:YOUR_CHAT_ID"]))

    async def test_queued_input_and_stopped_gateway_fail_closed(self):
        fake, message, lock, entered, finish, calls = self.make_loop()
        fake.bus.inbound_size = 1
        self.assertEqual(
            await self.AgentLoop.try_admit_idle_message(fake, message), "busy")
        fake.bus.inbound_size = 0
        fake._running = False
        self.assertEqual(
            await self.AgentLoop.try_admit_idle_message(fake, message), "unavailable")
        self.assertEqual(calls, [])
        self.assertFalse(lock.locked())

    async def test_notified_lock_waiter_counts_as_busy(self):
        fake, message, lock, entered, finish, calls = self.make_loop()
        await lock.acquire()
        waiter = asyncio.create_task(lock.acquire())
        await asyncio.sleep(0)
        lock.release()
        self.assertEqual(
            await self.AgentLoop.try_admit_idle_message(fake, message), "busy")
        await waiter
        lock.release()
        self.assertEqual(calls, [])

    def test_disposable_patch_is_repeatable_and_endpoint_is_authenticated(self):
        reverse = subprocess.run(
            ["patch", "--batch", "--fuzz=0", "--dry-run", "--reverse",
             "-d", str(self.site), "-p1", "-i", str(PATCH)],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(reverse.returncode, 0, reverse.stdout + reverse.stderr)
        runtime = (self.site / "nanobot/cli/gateway_runtime.py").read_text(encoding="utf-8")
        self.assertIn("NANOBOT_MAILCORTEX_TOKEN_FILE", runtime)
        self.assertIn("/mailcortex/idle-prompt", runtime)
        self.assertIn('"status": outcome', runtime)

    def make_runtime_loop(self, unified=True):
        """Real loop/session/resolver/delivery; only the provider is synthetic."""
        from unittest import mock
        from copy import deepcopy
        from nanobot.bus.queue import MessageBus
        from nanobot.config.schema import ModelPresetConfig
        from nanobot.providers.base import LLMProvider, LLMResponse
        from nanobot.providers.factory import ProviderSnapshot
        from nanobot.session.manager import SessionManager

        root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="nano-routing-")))
        self.enterContext(mock.patch.object(Path, "home", return_value=root))
        self.enterContext(mock.patch.dict(os.environ, {"HOME": str(root)}))
        calls = []
        class Provider(LLMProvider):
            def __init__(inner, name):
                super().__init__(provider_name=name)
            def get_default_model(inner):
                return "GLM"
            async def chat(inner, messages, tools=None, model=None, **kwargs):
                calls.append((inner.provider_name, model, deepcopy(messages)))
                return LLMResponse(content="fixture reply", finish_reason="stop")
        providers = {name: Provider(name) for name in ("gateway", "codex", "stale", "later", "dream")}
        presets = {name: ModelPresetConfig(model=model, provider="custom") for name, model in
                   (("codex", "Codex"), ("stale", "StaleTelegram"), ("later", "LaterCodex"), ("dream", "DreamOverride"))}
        def snapshot(name):
            return ProviderSnapshot(providers[name], presets[name].model, 100000,
                                    ("fixture", name), model_preset=name)
        workspace = root / "workspace"
        workspace.mkdir()
        loop = self.AgentLoop(
            MessageBus(), providers["gateway"], workspace, model="GLM",
            context_window_tokens=100000, unified_session=unified,
            session_manager=SessionManager(workspace, sessions_root=root / "sessions"),
            model_presets=presets, preset_snapshot_loader=snapshot,
        )
        loop._running = True
        self.addAsyncCleanup(loop.aclose)
        for key, preset, marker in (("unified:default", "codex", "UNIFIED_HISTORY"),
                                    ("telegram:YOUR_CHAT_ID", "stale", "STALE_HISTORY")):
            loop.set_session_model_preset(key, preset)
            session = loop.sessions.get_or_create(key)
            session.add_message("user", marker)
            session.add_message("assistant", "prior reply")
            loop.sessions.save(session)
        return loop, calls, root

    async def endpoint(self, agent):
        """Compile the actual nested server; capture its handler without a socket."""
        import ast
        from unittest import mock
        from nanobot.cli import gateway_runtime
        tree = ast.parse((self.site / "nanobot/cli/gateway_runtime.py").read_text())
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_run_gateway")
        server = next(n for n in run.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "_health_server")
        namespace = dict(vars(gateway_runtime), agent=agent, channels=SimpleNamespace())
        exec(compile(ast.fix_missing_locations(ast.Module(body=[server], type_ignores=[])),
                     "<actual-health-server>", "exec"), namespace)
        captured = []
        class Server:
            async def __aenter__(inner): return inner
            async def __aexit__(inner, *args): pass
            async def serve_forever(inner): pass
        async def start(handler, *args):
            captured.append(handler)
            return Server()
        with mock.patch.object(asyncio, "start_server", start), \
             mock.patch.dict(namespace, {"_print_gateway_health_endpoint": lambda *args: None}):
            await namespace["_health_server"]("fixture", 0)
        return captured[0]

    async def request(self, handler, method="POST", *, value=None, query=None, token="fixture-token"):
        import json
        from urllib.parse import urlencode
        path = "/mailcortex/idle-prompt"
        if method == "GET":
            path += "/status?" + urlencode(query or {"session_key": "telegram:YOUR_CHAT_ID"})
        if value is None:
            value = {"protocol": "nanobot.idle_prompt.v1", "request_id": "a" * 32,
                     "target": {"mode": "telegram_gateway", "channel": "telegram",
                                "chat_id": "YOUR_CHAT_ID", "session_key": "telegram:YOUR_CHAT_ID"},
                     "text": "wake current conversation"}
        body = json.dumps(value).encode() if method == "POST" else b""
        reader = asyncio.StreamReader()
        reader.feed_data((f"{method} {path} HTTP/1.0\r\nAuthorization: Bearer {token}\r\n"
                          f"Content-Length: {len(body)}\r\n\r\n").encode() + body)
        reader.feed_eof()
        class Writer:
            data = b""
            def write(inner, data): inner.data += data
            async def drain(inner): pass
            def close(inner): pass
        writer = Writer()
        await handler(reader, writer)
        head, body = writer.data.split(b"\r\n\r\n", 1)
        return int(head.split()[1]), json.loads(body)

    def token_file(self, root):
        from unittest import mock
        token = root / "token"
        token.write_text("fixture-token\n")
        token.chmod(0o600)
        self.enterContext(mock.patch.dict(os.environ, {"NANOBOT_MAILCORTEX_TOKEN_FILE": str(token)}))
        return token

    async def settle(self, loop):
        tasks = [task for group in loop._active_tasks.values() for task in group]
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
        await asyncio.sleep(0)

    async def test_endpoint_dispatch_uses_unified_history_runtime_and_later_selection(self):
        loop, calls, root = self.make_runtime_loop()
        self.token_file(root)
        handler = await self.endpoint(loop)
        stale_before = loop.sessions.read_session_file("telegram:YOUR_CHAT_ID")
        for expected, preset in (("Codex", "codex"), ("LaterCodex", "later")):
            loop.set_session_model_preset("unified:default", preset)
            code, status = await self.request(handler, "GET")
            self.assertEqual((code, status["known"], status["busy"]), (200, True, False))
            code, result = await self.request(handler)
            self.assertEqual((code, result["status"]), (202, "accepted"))
            self.assertEqual(result["session_key"], "telegram:YOUR_CHAT_ID")
            task_keys = set(loop._active_tasks)
            reserved = loop._get_session_lock("unified:default").locked()
            await self.settle(loop)
            self.assertEqual(calls[-1][:2], (preset, expected))
            self.assertEqual(status["effective_session_key"], "unified:default")
            self.assertEqual(result["effective_session_key"], "unified:default")
            self.assertEqual(task_keys, {"unified:default"})
            self.assertTrue(reserved)
            prompt = str(calls[-1][2])
            self.assertIn("UNIFIED_HISTORY", prompt)
            self.assertNotIn("STALE_HISTORY", prompt)
            self.assertEqual(loop.model, "GLM")
        session = loop.sessions.get_or_create("unified:default")
        self.assertEqual(sum(m["content"] == "fixture reply" for m in session.messages), 2)
        self.assertEqual(loop.sessions.read_session_file("telegram:YOUR_CHAT_ID"), stale_before)
        # User-facing completion still goes to the validated Telegram route.
        outbound = []
        while loop.bus.outbound_size:
            outbound.append(await loop.bus.consume_outbound())
        self.assertTrue(any(m.channel == "telegram" and m.chat_id == "YOUR_CHAT_ID"
                            and m.content == "fixture reply" for m in outbound))

    async def test_endpoint_nonunified_keeps_exact_telegram_session(self):
        loop, calls, root = self.make_runtime_loop(unified=False)
        self.token_file(root)
        handler = await self.endpoint(loop)
        code, status = await self.request(handler, "GET")
        self.assertEqual((code, status.get("effective_session_key")), (200, "telegram:YOUR_CHAT_ID"))
        code, result = await self.request(handler)
        self.assertEqual(code, 202)
        self.assertEqual(result.get("effective_session_key"), "telegram:YOUR_CHAT_ID")
        await self.settle(loop)
        self.assertEqual(calls[-1][:2], ("stale", "StaleTelegram"))
        self.assertIn("STALE_HISTORY", str(calls[-1][2]))
        self.assertNotIn("UNIFIED_HISTORY", str(calls[-1][2]))

    async def test_unified_locked_and_notified_waiter_reject_at_endpoint(self):
        loop, calls, root = self.make_runtime_loop()
        self.token_file(root)
        handler = await self.endpoint(loop)
        lock = loop._get_session_lock("unified:default")
        await lock.acquire()
        code, status = await self.request(handler, "GET")
        self.assertEqual((code, status["busy"]), (200, True))
        self.assertEqual((await self.request(handler))[0], 409)
        waiter = asyncio.create_task(lock.acquire())
        await asyncio.sleep(0)
        lock.release()
        # Exercise the no-suspension admission check while the lock is unlocked
        # but a notified unified-session waiter still owns the next acquire.
        self.assertFalse(lock.locked())
        self.assertEqual(await loop.try_admit_idle_message(
            loop.idle_prompt_message("YOUR_CHAT_ID", "wake")), "busy")
        self.assertEqual((await self.request(handler))[0], 409)
        await waiter
        lock.release()
        self.assertFalse(calls)

    async def test_endpoint_auth_validation_and_unavailable_remain_closed(self):
        loop, calls, root = self.make_runtime_loop()
        token = self.token_file(root)
        handler = await self.endpoint(loop)
        for method in ("GET", "POST"):
            self.assertEqual((await self.request(handler, method, token="wrong"))[0], 401)
            token.chmod(0o644)
            self.assertEqual((await self.request(handler, method))[0], 401)
            token.chmod(0o600)
        import copy
        value = {"protocol": "nanobot.idle_prompt.v1", "request_id": "b" * 32,
                 "target": {"mode": "telegram_gateway", "channel": "telegram",
                            "chat_id": "YOUR_CHAT_ID", "session_key": "telegram:YOUR_CHAT_ID"}, "text": "wake"}
        for field, bad in (("session_key", "unified:default"), ("session_key", "telegram:OTHER"),
                           ("channel", "websocket"), ("mode", "direct"), ("chat_id", ""),
                           ("chat_id", 123), ("extra", True)):
            broken = copy.deepcopy(value)
            broken["target"][field] = bad
            code, result = await self.request(handler, value=broken)
            self.assertEqual((code, result["status"]), (400, "invalid"))
        for field, bad in (("request_id", "bad"), ("protocol", "wrong"), ("text", " "), ("extra", True)):
            code, result = await self.request(handler, value=value | {field: bad})
            self.assertEqual((code, result["status"]), (400, "invalid"))
        code, status = await self.request(handler, "GET", query={"session_key": "unified:default"})
        self.assertEqual((code, status["known"], status["busy"]), (503, False, True))
        loop.stop()
        code, status = await self.request(handler, "GET")
        self.assertEqual((code, status["known"], status["busy"]), (503, False, True))
        self.assertEqual((await self.request(handler))[0], 503)
        self.assertFalse(calls)
        self.assertFalse(loop._active_tasks)

    def test_dream_inherits_live_and_persisted_unified_selection_without_writes(self):
        loop, calls, root = self.make_runtime_loop()
        def files():
            return {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        before = files()
        self.assertEqual(loop.dream_runtime().model, "Codex")
        self.assertEqual(files(), before)
        loop.set_session_model_preset("unified:default", "later")
        self.assertEqual(loop.dream_runtime().model, "LaterCodex")
        loop.sessions.invalidate("unified:default")
        before = files()
        self.assertEqual(loop.dream_runtime().model, "LaterCodex")
        self.assertIsNone(loop.sessions.get_cached("unified:default"))
        self.assertEqual(files(), before)
        self.assertEqual(loop.model, "GLM")
        self.assertFalse(calls)

    def test_dream_override_missing_session_and_nonunified_default(self):
        loop, calls, root = self.make_runtime_loop()
        loop.dream_model_preset = "dream"
        self.assertEqual(loop.dream_runtime().model, "DreamOverride")
        loop._unified_session = False
        self.assertEqual(loop.dream_runtime().model, "DreamOverride")
        loop.dream_model_preset = None
        self.assertIsNone(loop.dream_runtime())
        loop._unified_session = True
        loop.sessions.delete_session("unified:default")
        self.assertIsNone(loop.dream_runtime())
        self.assertIsNone(loop.sessions.get_cached("unified:default"))
        self.assertIsNone(loop.sessions.read_session_snapshot("unified:default"))
        self.assertFalse(calls)


    def test_dream_invalid_selection_fails_without_rewriting_session(self):
        loop, calls, root = self.make_runtime_loop()
        session = loop.sessions.get_or_create("unified:default")
        session.metadata["_nanobot_model_preset"] = "removed"
        loop.sessions.save(session)
        before = loop.sessions.read_session_file("unified:default")
        with self.assertRaises(KeyError):
            loop.dream_runtime()
        self.assertEqual(loop.sessions.read_session_file("unified:default"), before)
        self.assertEqual(session.metadata["_nanobot_model_preset"], "removed")
        self.assertEqual(loop.model, "GLM")
        self.assertFalse(calls)


if __name__ == "__main__":
    unittest.main()
