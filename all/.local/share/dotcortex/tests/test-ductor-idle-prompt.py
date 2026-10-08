"""Conditional Ductor admission tests: copied package, no socket or live CLI."""
from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

FIXTURE = Path(__file__).with_name("test-ductor-busy-state.py")
spec = importlib.util.spec_from_file_location("ductor_busy_fixture", FIXTURE)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
from ductor_bot.api.crypto import E2ESession
from ductor_bot.api.server import _SecureChannel
from ductor_bot.api import idle_prompt as seam
from ductor_bot.bus.bus import MessageBus
from ductor_bot.bus.envelope import LockMode, Origin


class Socket:
    closed = False
    def __init__(self):
        self.frames = []
    async def send_str(self, frame):
        self.frames.append(frame)


class IdlePromptTests(unittest.IsolatedAsyncioTestCase):
    setUp = fixture.BusyTests.setUp
    request = fixture.BusyTests.request

    def channel(self, allowed=True):
        client, server = E2ESession(), E2ESession()
        client.set_remote_key(server.local_pk_b64)
        server.set_remote_key(client.local_pk_b64)
        socket = Socket()
        channel = _SecureChannel(socket, server, idle_prompt_allowed=allowed)
        return client, channel

    def prepare(self):
        self.server.set_idle_message_handler(lambda channel, key, data:
            seam.handle_idle_message(self.orch, self.server, channel, key, data))
        self.telegram = []
        test = self
        class Telegram:
            transport_name = "tg"
            async def deliver(inner, envelope):
                test.telegram.append(envelope)
            async def deliver_broadcast(inner, envelope):
                raise AssertionError("wake reply must be unicast")
        bus = MessageBus(self.orch._lock_pool)
        bus.register_transport(Telegram())
        self.orch._message_bus = bus
        self.calls = []
        self.entered = asyncio.Event(); self.finish = asyncio.Event()
        async def handler(key, text):
            self.assertTrue(self.orch._lock_pool.is_locked(key.lock_key))
            self.assertTrue(self.server._lock_pool.is_locked(key.lock_key))
            self.calls.append((key, text)); self.entered.set()
            await self.finish.wait()
            return SimpleNamespace(text="handled", stream_fallback=False)
        self.orch.handle_message_streaming = handler

    async def route(self, client, channel, **overrides):
        payload = {"type": "idle_message", "request_id": "a" * 32,
                   "session_key": fixture.KEY.storage_key, "text": "MailCortex delivery",
                   "mirror_to_telegram": True}
        payload.update(overrides)
        await self.server._route_text_message(channel, client.encrypt(payload), fixture.KEY,
            self.server._lock_pool.get(fixture.KEY.lock_key))
        return [client.decrypt(frame) for frame in channel.ws.frames]

    async def settle(self):
        self.finish.set()
        await asyncio.gather(*list(self.server._idle_tasks))

    async def test_idle_admission_uses_real_router_and_holds_both_lock_owners(self):
        self.prepare(); client, channel = self.channel()
        frames = await self.route(client, channel)
        self.assertEqual(frames, [{"type": "idle_admission", "request_id": "a" * 32,
            "session_key": fixture.KEY.storage_key, "status": "accepted"}])
        await self.entered.wait()
        self.assertEqual(self.calls, [(fixture.KEY, "MailCortex delivery")])
        self.assertTrue(self.orch._lock_pool.is_locked(fixture.KEY.lock_key))
        await self.settle()
        self.assertFalse(self.orch._lock_pool.is_locked(fixture.KEY.lock_key))
        self.assertFalse(self.server._lock_pool.is_locked(fixture.KEY.lock_key))
        self.assertEqual(len(self.telegram), 1)
        envelope = self.telegram[0]
        self.assertEqual((envelope.origin, envelope.chat_id, envelope.topic_id,
                          envelope.transport, envelope.result_text, envelope.lock_mode),
                         (Origin.WEBHOOK_WAKE, fixture.KEY.chat_id, fixture.KEY.topic_id,
                          "tg", "handled", LockMode.NONE))

    async def test_mid_turn_nacks_without_dispatch_and_can_retry_when_idle(self):
        self.prepare(); client, channel = self.channel()
        async with self.orch._lock_pool.get(fixture.KEY.lock_key):
            frames = await self.route(client, channel)
        self.assertEqual(frames[-1]["status"], "busy")
        self.assertEqual(self.calls, [])
        channel.ws.frames.clear()
        self.assertEqual((await self.route(client, channel))[-1]["status"], "accepted")
        await self.settle()

    async def test_turn_start_during_async_session_lookup_is_refused(self):
        self.prepare(); client, channel = self.channel()
        async def lookup(key):
            await self.orch._lock_pool.get(key.lock_key).acquire()
            return self.session
        self.sessions.get_active.side_effect = lookup
        frames = await self.route(client, channel)
        self.assertEqual(frames[-1]["status"], "busy")
        self.assertEqual(self.calls, [])
        self.orch._lock_pool.get(fixture.KEY.lock_key).release()

    async def test_api_owner_compaction_and_active_process_each_refuse(self):
        self.prepare()
        for reason in ("api", "compaction", "process"):
            client, channel = self.channel()
            if reason == "api":
                lock = self.server._lock_pool.get(fixture.KEY.lock_key); await lock.acquire()
            elif reason == "compaction":
                self.orch._idle_compactor._compacting.add(fixture.KEY.storage_key)
            else:
                self.orch._process_registry.register(1, SimpleNamespace(returncode=None, pid=1), "fixture")
            self.assertEqual((await self.route(client, channel))[-1]["status"], "busy")
            if reason == "api":
                lock.release()
            elif reason == "compaction":
                self.orch._idle_compactor._compacting.clear()
        self.assertEqual(self.calls, [])

    async def test_unlocked_lock_with_pending_waiter_refuses_without_yield(self):
        self.prepare(); client, channel = self.channel()
        lock = self.orch._lock_pool.get(fixture.KEY.lock_key)
        await lock.acquire()
        waiter = asyncio.create_task(lock.acquire())
        await asyncio.sleep(0)
        lock.release()
        frames = await self.route(client, channel)
        self.assertEqual(frames[-1]["status"], "busy")
        self.assertEqual(self.calls, [])
        await waiter; lock.release()

    async def test_missing_authority_identity_or_peer_fails_closed(self):
        self.prepare()
        for change in ({"session_key": "tg:2"}, {"request_id": "bad"}, {"text": ""},
                       {"mirror_to_telegram": False}):
            client, channel = self.channel()
            self.assertNotEqual((await self.route(client, channel, **change))[-1]["status"], "accepted")
        client, channel = self.channel(allowed=False)
        self.assertEqual((await self.route(client, channel))[-1]["status"], "unavailable")
        client, channel = self.channel()
        self.orch._message_bus = None
        self.assertEqual((await self.route(client, channel))[-1]["status"], "unavailable")
        self.prepare(); client, channel = self.channel()
        self.orch._lock_pool = None
        self.assertEqual((await self.route(client, channel))[-1]["status"], "unavailable")
        self.assertEqual(self.calls, [])

    async def test_disconnect_after_admission_does_not_abort_accepted_turn(self):
        self.prepare(); client, channel = self.channel()
        await self.route(client, channel)
        channel.ws.closed = True
        await self.entered.wait(); await self.settle()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.orch._lock_pool.is_locked(fixture.KEY.lock_key))

    async def test_handler_failure_and_shutdown_release_locks(self):
        self.prepare(); client, channel = self.channel()
        async def failed(*args):
            raise RuntimeError("fixture failure")
        self.orch.handle_message_streaming = failed
        with self.assertLogs(seam.logger, "ERROR"):
            await self.route(client, channel); await self.settle()
        self.assertFalse(self.orch._lock_pool.is_locked(fixture.KEY.lock_key))
        self.prepare(); client, channel = self.channel()
        await self.route(client, channel); await self.entered.wait()
        await self.server.stop()
        self.assertFalse(self.orch._lock_pool.is_locked(fixture.KEY.lock_key))
        self.assertFalse(self.server._lock_pool.is_locked(fixture.KEY.lock_key))
        self.assertEqual(self.server._idle_tasks, set())

    async def test_loopback_proxy_and_default_session_capability_gates(self):
        self.prepare()
        request = fixture.BusyTests.request(self)
        self.assertTrue(seam.idle_peer_allowed(self.server, request))
        for request in (fixture.BusyTests.request(self, peer="YOUR_PEER"),
                        fixture.BusyTests.request(self, extra={"Forwarded": "YOUR_PROXY"}),
                        fixture.BusyTests.request(self, extra={"X-Forwarded-Host": "YOUR_PROXY"})):
            self.assertFalse(seam.idle_peer_allowed(self.server, request))
        self.server._config.token = ""
        self.assertFalse(seam.idle_peer_allowed(self.server, fixture.BusyTests.request(self)))

    async def test_cancellation_before_turn_starts_releases_claimed_locks(self):
        self.prepare(); client, channel = self.channel()
        await self.route(client, channel)
        await self.server.stop()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.orch._lock_pool.is_locked(fixture.KEY.lock_key))
        self.assertFalse(self.server._lock_pool.is_locked(fixture.KEY.lock_key))

    async def test_shutdown_refuses_admission_even_during_session_lookup(self):
        self.prepare(); client, channel = self.channel()
        async def lookup(key):
            await self.server.stop()
            return self.session
        self.sessions.get_active.side_effect = lookup
        self.assertEqual((await self.route(client, channel))[-1]["status"], "unavailable")
        self.sessions.get_active.side_effect = None
        self.assertEqual((await self.route(client, channel))[-1]["status"], "unavailable")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.server._idle_tasks, set())
        self.assertFalse(self.orch._lock_pool.is_locked(fixture.KEY.lock_key))
        self.assertFalse(self.server._lock_pool.is_locked(fixture.KEY.lock_key))

    async def test_second_admission_cannot_enter_during_first_turn(self):
        self.prepare(); client, channel = self.channel()
        await self.route(client, channel); await self.entered.wait()
        other, second = self.channel()
        self.assertEqual((await self.route(other, second, request_id="b" * 32))[-1]["status"], "busy")
        self.assertEqual(len(self.calls), 1)
        await self.settle()

    async def test_authority_exception_never_claims_or_dispatches(self):
        self.prepare(); client, channel = self.channel()
        self.sessions.get_active.side_effect = RuntimeError("fixture unavailable")
        with self.assertLogs(seam.logger, "ERROR"):
            self.assertEqual((await self.route(client, channel))[-1]["status"], "unavailable")
        self.assertEqual(self.calls, [])
        self.assertFalse(self.server._lock_pool.is_locked(fixture.KEY.lock_key))

    async def test_regular_encrypted_message_still_uses_original_handler(self):
        client, channel = self.channel()
        self.server.set_message_handler(mock.AsyncMock(return_value=SimpleNamespace(
            text="normal result", stream_fallback=False)))
        await self.server._route_text_message(channel, client.encrypt({"type": "message", "text": "normal"}),
            fixture.KEY, self.server._lock_pool.get(fixture.KEY.lock_key))
        self.assertEqual(client.decrypt(channel.ws.frames[-1])["text"], "normal result")
        self.server._handle_message.assert_awaited_once()

    def client_wire(self, *, ack_mode=None):
        import aiohttp
        import importlib.machinery
        watcher_path = Path(__file__).resolve().parents[5] / "all/.local/bin/mailcortex-seat-watcher"
        loader = importlib.machinery.SourceFileLoader("ductor_wire_watcher", str(watcher_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        watcher = importlib.util.module_from_spec(spec); spec.loader.exec_module(watcher)
        test = self
        class AuthSocket:
            closed = False
            async def receive(inner):
                return SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=json.dumps(inner.auth))
            async def send_json(inner, value):
                inner.answer = value
            async def close(inner):
                inner.closed = True
        class ClientSocket:
            def __init__(inner):
                inner.auth_socket = AuthSocket(); inner.server_socket = Socket()
                inner.sent = []; inner.channel = None
            async def __aenter__(inner):
                return inner
            async def __aexit__(inner, *args):
                inner.server_socket.closed = True
            async def send_json(inner, value):
                inner.auth_socket.auth = value
                result = await test.server._authenticate(inner.auth_socket)
                if result:
                    inner.key, box = result
                    inner.channel = _SecureChannel(inner.server_socket, box, idle_prompt_allowed=True)
            async def receive_json(inner, timeout):
                return inner.auth_socket.answer
            async def send_str(inner, frame):
                inner.sent.append(inner.channel.decrypt(frame))
                await test.server._route_text_message(inner.channel, frame, inner.key,
                    test.server._lock_pool.get(inner.key.lock_key))
            async def receive(inner, timeout):
                if ack_mode == "lost":
                    raise TimeoutError("fixture ACK loss")
                frame = inner.server_socket.frames[0]
                if ack_mode in {"request_id", "session_key"}:
                    # Re-encrypt an authentic but identity-mismatched ACK.
                    box = inner.channel._e2e
                    value = {"type": "idle_admission", "request_id": inner.sent[0]["request_id"],
                             "session_key": fixture.KEY.storage_key, "status": "accepted"}
                    value[ack_mode] = "wrong"
                    frame = box.encrypt(value)
                return SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=frame)
        socket = ClientSocket()
        class Session:
            async def __aenter__(inner):
                return inner
            async def __aexit__(inner, *args):
                pass
            def ws_connect(inner, url):
                test.assertTrue(url.endswith("/ws"))
                return socket
        return watcher, socket, mock.patch.object(aiohttp, "ClientSession", return_value=Session())

    async def test_production_watcher_client_and_real_authenticated_router_agree(self):
        self.prepare(); watcher, socket, patch = self.client_wire()
        settings = {"url": "http://localhost:YOUR_PORT", "token": "YOUR_API_TOKEN"}
        with patch as factory:
            await watcher.DuctorAdapter()._deliver_idle(settings, fixture.KEY.storage_key, "MailCortex delivery")
        factory.assert_called_once()
        self.assertFalse(factory.call_args.kwargs["trust_env"])
        self.assertEqual(set(socket.auth_socket.auth), {"type", "token", "e2e_pk"})
        self.assertEqual(socket.sent[0]["type"], "idle_message")
        self.assertEqual(socket.sent[0]["session_key"], fixture.KEY.storage_key)
        self.assertIs(socket.sent[0]["mirror_to_telegram"], True)
        await self.entered.wait(); await self.settle()
        self.assertEqual(len(self.calls), 1)

    async def test_production_client_negative_ack_is_safe_busy_retry(self):
        self.prepare(); watcher, socket, patch = self.client_wire()
        with patch:
            async with self.orch._lock_pool.get(fixture.KEY.lock_key):
                with self.assertRaises(watcher.DuctorNotAdmittedError) as caught:
                    await watcher.DuctorAdapter()._deliver_idle(
                        {"url": "http://localhost:YOUR_PORT", "token": "YOUR_API_TOKEN"},
                        fixture.KEY.storage_key, "mail")
        self.assertEqual(caught.exception.reason, "busy")
        self.assertEqual(self.calls, [])

    async def test_production_client_lost_or_wrong_ack_is_ambiguous_not_safe_retry(self):
        for mode in ("lost", "request_id", "session_key"):
            self.prepare(); watcher, socket, patch = self.client_wire(ack_mode=mode)
            with patch, self.assertRaises(watcher.WatcherError) as caught:
                await watcher.DuctorAdapter()._deliver_idle(
                    {"url": "http://localhost:YOUR_PORT", "token": "YOUR_API_TOKEN"},
                    fixture.KEY.storage_key, "mail")
            self.assertNotIsInstance(caught.exception, watcher.DuctorNotAdmittedError)
            await self.entered.wait(); await self.settle()
            self.assertEqual(len(self.calls), 1)

    async def test_production_client_dependency_loss_before_send_is_safe_refusal(self):
        import builtins
        self.prepare(); watcher, socket, patch = self.client_wire()
        original = builtins.__import__
        def unavailable(name, *args, **kwargs):
            if name == "aiohttp":
                raise ImportError("fixture dependency loss")
            return original(name, *args, **kwargs)
        with mock.patch.object(builtins, "__import__", side_effect=unavailable), \
                self.assertRaises(watcher.DuctorNotAdmittedError):
            await watcher.DuctorAdapter()._deliver_idle(
                {"url": "http://localhost:YOUR_PORT", "token": "YOUR_API_TOKEN"},
                fixture.KEY.storage_key, "mail")
        self.assertFalse(hasattr(socket.auth_socket, "auth"))
        self.assertEqual(self.calls, [])

    async def test_production_client_redirect_refused_before_authentication(self):
        import aiohttp
        self.prepare(); watcher, socket, patch = self.client_wire()
        options = {}
        class Redirect:
            async def __aenter__(inner):
                trace = options["trace_configs"][0]
                trace.freeze()
                await trace.on_request_redirect.send(None, None, None)
                raise AssertionError("redirect was not refused")
            async def __aexit__(inner, *args):
                pass
        class Session:
            async def __aenter__(inner):
                return inner
            async def __aexit__(inner, *args):
                pass
            def ws_connect(inner, url):
                return Redirect()
        def factory(**kwargs):
            options.update(kwargs)
            return Session()
        with mock.patch.object(aiohttp, "ClientSession", side_effect=factory), \
                self.assertRaises(watcher.DuctorNotAdmittedError):
            await watcher.DuctorAdapter()._deliver_idle(
                {"url": "http://localhost:YOUR_PORT", "token": "YOUR_API_TOKEN"},
                fixture.KEY.storage_key, "mail")
        self.assertFalse(options["trust_env"])
        self.assertFalse(hasattr(socket.auth_socket, "auth"))
        self.assertEqual(self.calls, [])

    async def test_production_client_bad_auth_never_sends_prompt(self):
        self.prepare(); watcher, socket, patch = self.client_wire()
        with patch, self.assertRaises(watcher.DuctorNotAdmittedError):
            await watcher.DuctorAdapter()._deliver_idle(
                {"url": "http://localhost:YOUR_PORT", "token": "wrong"}, fixture.KEY.storage_key, "mail")
        self.assertEqual(socket.sent, [])
        self.assertEqual(self.calls, [])

    async def test_lifecycle_wires_real_conditional_handler(self):
        await fixture.BusyTests.test_lifecycle_wires_real_authority(self)
        server = self.orch._api_stop.__self__
        self.assertIsNotNone(server._idle_message_handler)
        response = await server._handle_busy(fixture.BusyTests.request(self))
        self.assertEqual(json.loads(response.text)["idle_prompt"], "ductor.idle_prompt.v2")


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        fixture.TEMP.cleanup()
