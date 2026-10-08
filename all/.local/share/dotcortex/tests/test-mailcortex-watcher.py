#!/usr/bin/env python3
from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
WATCHER = ROOT / "all/.local/bin/mailcortex-seat-watcher"


def load_module(path: Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class FakeAdapter:
    def __init__(self, *, busy=False, fail=False):
        self.busy = busy
        self.fail = fail
        self.deliveries = []

    def resolve_idle_pane(self, record):
        return None if self.busy else "wT:p1"

    def deliver(self, record, pane_id, prompt):
        self.deliveries.append((record["herdr_target"], pane_id, prompt))
        if self.fail:
            raise RuntimeError("ambiguous transport failure")


class FakeHTTPResponse:
    def __init__(self, payload, status=200):
        self.payload = json.dumps(payload).encode("utf-8")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


class WatcherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "Mail"
        self.runtime = self.base / "runtime"
        os.environ.update(MAILCORTEX_ROOT=str(self.root),
                          MAILCORTEX_RUNTIME=str(self.runtime),
                          MAILCORTEX_HOSTNAME="test-host")
        self.mailbox = self.root / "seats/builder"
        for leaf in ("tmp", "new", "cur"):
            (self.mailbox / leaf).mkdir(parents=True)
        self.watcher = load_module(WATCHER, "mailcortex_watcher_test")
        self.registry = {"schema": "mailcortex.seats.v1", "host": "test-host", "seats": {"builder": {
            "host": "test-host", "mailbox": "seats/builder", "harness": "codex",
            "transport": "herdr", "herdr_session": "builder-session",
            "herdr_target": "builder-agent", "rate_limit_seconds": 0,
        }}}

    def tearDown(self):
        self.temp.cleanup()

    def mail(self, mid, filename):
        message = EmailMessage()
        message["From"] = "sender@node.helm"
        message["To"] = "seat+builder@node.helm"
        message["Subject"] = "wake"
        message["Message-ID"] = mid
        message.set_content("hello")
        (self.mailbox / "new" / filename).write_bytes(message.as_bytes())

    def receipt(self, mid):
        return self.watcher.MAILCORTEX.load_receipt("builder", mid)

    def test_idle_injects_once_and_duplicate_filename_does_not_repeat(self):
        self.mail("<same@node.helm>", "a")
        self.mail("<same@node.helm>", "b")
        adapter = FakeAdapter()
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10), 1)
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=11), 0)
        self.assertEqual(len(adapter.deliveries), 1)
        self.assertIn("MailCortex delivery", adapter.deliveries[0][-1])
        self.assertIn("Message-ID: <same@node.helm>", adapter.deliveries[0][-1])
        self.assertEqual(self.receipt("<same@node.helm>")["wake_state"], "injected")

    def test_in_flight_sync_temp_file_is_not_a_wake(self):
        self.mail("<partial@node.helm>", ".syncthing.123.host.tmp")
        adapter = FakeAdapter()
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10), 0)
        self.assertEqual(adapter.deliveries, [])

    def test_busy_and_rate_limit_defer_without_drop(self):
        self.mail("<busy@node.helm>", "a")
        adapter = FakeAdapter(busy=True)
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10), 0)
        self.assertEqual(self.receipt("<busy@node.helm>")["wake_state"], "queued")
        adapter.busy = False
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=11), 1)
        self.registry["seats"]["builder"]["rate_limit_seconds"] = 30
        self.mail("<later@node.helm>", "b")
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=20), 0)
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=42), 1)

    def test_handling_state_preserves_wake_and_does_not_reinject(self):
        mid = "<deferred@node.helm>"
        self.mail(mid, "a")
        adapter = FakeAdapter()
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10), 1)
        self.watcher.MAILCORTEX.write_handling_receipt("builder", mid, "handling_deferred")
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=11), 0)
        receipt = self.receipt(mid)
        self.assertEqual(receipt["wake_state"], "injected")
        self.assertEqual(receipt["handling_state"], "handling_deferred")
        self.assertEqual(len(adapter.deliveries), 1)

    def test_ambiguous_delivery_is_not_retried(self):
        mid = "<unknown@node.helm>"
        self.mail(mid, "a")
        adapter = FakeAdapter(fail=True)
        with self.assertRaisesRegex(self.watcher.WatcherError, "outcome is unknown"):
            self.watcher.locked_scan(self.registry, adapter, now=10)
        self.assertEqual(self.receipt(mid)["wake_state"], "delivery_unknown")
        adapter.fail = False
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=11), 0)
        self.assertEqual(len(adapter.deliveries), 1)

    def test_message_id_hash_has_no_sanitizing_collision(self):
        first = self.watcher.MAILCORTEX.receipt_path("builder", "<a+b@node.helm>")
        second = self.watcher.MAILCORTEX.receipt_path("builder", "<a/b@node.helm>")
        self.assertNotEqual(first, second)

    def test_malformed_mail_and_corrupt_receipt_fail_loud(self):
        (self.mailbox / "new/bad").write_text("not RFC 822")
        with self.assertRaisesRegex(self.watcher.WatcherError, "valid Message-ID"):
            self.watcher.locked_scan(self.registry, FakeAdapter())
        (self.mailbox / "new/bad").unlink()
        mid = "<bad-receipt@node.helm>"
        self.mail(mid, "good")
        path = self.watcher.MAILCORTEX.receipt_path("builder", mid)
        path.parent.mkdir(parents=True)
        path.write_text("{}")
        with self.assertRaisesRegex(self.watcher.WatcherError, "receipt is invalid"):
            self.watcher.locked_scan(self.registry, FakeAdapter())

    def test_registry_and_scan_lock_fail_closed(self):
        registry_path = self.base / "registry.json"
        registry_path.write_text(json.dumps(self.registry))
        registry_path.chmod(0o600)
        with self.assertRaises(self.watcher.WatcherError):
            self.watcher.load_registry(registry_path, "other-host")
        lock_path = self.runtime / "watcher.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(self.watcher.WatcherError, "owns the scan lock"):
                self.watcher.locked_scan(self.registry, FakeAdapter())

    def test_registry_accepts_exact_transport_shapes_and_consort_mailboxes(self):
        records = {
            "builder": self.registry["seats"]["builder"],
            "ductbot": {
                "host": "test-host", "mailbox": "consorts/ductbot", "harness": "ductor",
                "transport": "ductor", "ductor_config": "YOUR_DUCTOR_CONFIG",
                "rate_limit_seconds": 0,
            },
            "deepbot": {
                "host": "test-host", "mailbox": "consorts/deepbot", "harness": "deepseek",
                "transport": "deepseek", "deepseek_url": "http://localhost:YOUR_PORT",
                "deepseek_cookie_file": "YOUR_DEEPSEEK_COOKIE_FILE",
                "deepseek_session": "telegram-YOUR_DEEPSEEK_SESSION", "rate_limit_seconds": 0,
            },
            "hermesbot": {
                "host": "test-host", "mailbox": "seats/hermesbot", "harness": "hermes",
                "transport": "hermes", "hermes_url": "http://localhost:YOUR_HERMES_PORT",
                "hermes_api_key_file": "YOUR_HERMES_API_KEY_FILE",
                "hermes_target": {"mode": "gateway_platform_session",
                    "session_key": "agent:YOUR_PROFILE:telegram:dm:YOUR_HERMES_CHAT_ID"},
                "rate_limit_seconds": 0,
            },
            "nanobot": {
                "host": "test-host", "mailbox": "consorts/nanobot", "harness": "nanobot",
                "transport": "nanobot", "nanobot_url": "http://localhost:YOUR_NANOBOT_PORT",
                "nanobot_api_token_file": "YOUR_NANOBOT_API_TOKEN_FILE",
                "nanobot_target": {"mode": "telegram_gateway",
                    "channel": "telegram", "chat_id": "YOUR_NANOBOT_CHAT_ID",
                    "session_key": "telegram:YOUR_NANOBOT_CHAT_ID"},
                "rate_limit_seconds": 0,
            },
        }
        registry_path = self.base / "registry.json"
        registry_path.write_text(json.dumps({"schema": "mailcortex.seats.v1", "host": "test-host", "seats": records}))
        registry_path.chmod(0o600)
        loaded = self.watcher.load_registry(registry_path, "test-host")
        self.assertEqual(loaded["seats"]["ductbot"]["mailbox"], "consorts/ductbot")
        hidden = dict(records["deepbot"], deepseek_session="YOUR_HIDDEN_DEEPSEEK_SESSION")
        registry_path.write_text(json.dumps({"schema": "mailcortex.seats.v1", "host": "test-host",
                                             "seats": {"deepbot": hidden}}))
        with self.assertRaisesRegex(self.watcher.WatcherError, "invalid DeepSeek target"):
            self.watcher.load_registry(registry_path, "test-host")
        for name, record in records.items():
            invalid = dict(record)
            invalid["unexpected"] = True
            registry_path.write_text(json.dumps({"schema": "mailcortex.seats.v1", "host": "test-host", "seats": {name: invalid}}))
            with self.assertRaisesRegex(self.watcher.WatcherError, "fields are not exact"):
                self.watcher.load_registry(registry_path, "test-host")

    def test_consort_mailbox_is_delivered_and_path_guards_remain_canonical(self):
        mailbox = self.root / "consorts/ductbot"
        for leaf in ("tmp", "new", "cur"):
            (mailbox / leaf).mkdir(parents=True)
        record = dict(self.registry["seats"]["builder"], mailbox="consorts/ductbot")
        registry = {"schema": "mailcortex.seats.v1", "host": "test-host", "seats": {"ductbot": record}}
        message = EmailMessage()
        message["From"] = "sender@node.helm"
        message["To"] = "consort+ductbot@node.helm"
        message["Subject"] = "wake"
        message["Message-ID"] = "<consort@node.helm>"
        message.set_content("hello")
        (mailbox / "new/message").write_bytes(message.as_bytes())
        adapter = FakeAdapter()
        self.assertEqual(self.watcher.locked_scan(registry, adapter, now=10), 1)
        self.assertEqual(len(adapter.deliveries), 1)
        self.assertIn("MailCortex delivery", adapter.deliveries[0][-1])
        (mailbox / "new/message").unlink()
        (mailbox / "new").rmdir()
        (mailbox / "cur").rmdir()
        (mailbox / "tmp").rmdir()
        mailbox.rmdir()
        mailbox.symlink_to(self.base / "outside", target_is_directory=True)
        (self.base / "outside").mkdir()
        with self.assertRaisesRegex(self.watcher.WatcherError, "absent or unsafe"):
            self.watcher.locked_scan(registry, FakeAdapter(), now=11)

    def ductor_fixture(self, *, states=None, outcome="accepted"):
        config = self.base / "ductor.json"
        config.write_text(json.dumps({"api": {"enabled": True, "host": "localhost",
            "port": 0, "token": "YOUR_API_TOKEN", "chat_id": 1}}))
        config.chmod(0o600)
        record = {"host": "test-host", "mailbox": "seats/builder", "harness": "ductor",
                  "transport": "ductor", "ductor_config": str(config), "rate_limit_seconds": 0}
        self.registry["seats"]["builder"] = record
        calls = []
        busy = iter(states or [False] * 10)
        def opener(request, timeout):
            calls.append((request, timeout))
            return FakeHTTPResponse({"busy": next(busy), "known": True,
                "session_key": "tg:1", "reasons": [], "idle_prompt": "ductor.idle_prompt.v2"})
        deliveries = []
        async def client(settings, target, prompt):
            deliveries.append((settings, target, prompt))
            if outcome != "accepted":
                raise self.watcher.DuctorNotAdmittedError(outcome)
        adapter = self.watcher.DuctorAdapter(opener=opener, client=client)
        return config, adapter, calls, deliveries

    def test_ductor_idle_delivery_carries_mail_once_on_rescan(self):
        config, adapter, calls, deliveries = self.ductor_fixture()
        mid = "<ductor@node.helm>"; self.mail(mid, "a"); self.mail(mid, "b")
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10), 1)
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=11), 0)
        self.assertEqual(len(deliveries), 1)
        self.assertEqual(deliveries[0][1], "tg:1")
        prompt = deliveries[0][2]
        for text in ("MailCortex delivery", mid, "Subject: wake", "hello"):
            self.assertIn(text, prompt)
        self.assertNotIn("MailCortex will return", prompt)
        self.assertEqual(self.receipt(mid)["wake_state"], "injected")
        self.assertIsNone(self.receipt(mid)["handling_state"])
        self.assertTrue((self.mailbox / "new/a").is_file())
        self.assertTrue(calls[0][0].full_url.endswith("/busy"))
        self.assertEqual(calls[0][0].get_header("Authorization"), "Bearer YOUR_API_TOKEN")

    def test_ductor_mid_turn_waits_then_delivers(self):
        config, adapter, calls, deliveries = self.ductor_fixture(states=[True, False])
        mid = "<waiting@node.helm>"; self.mail(mid, "a")
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10), 0)
        self.assertEqual(self.receipt(mid)["reason"], "busy")
        self.assertEqual(deliveries, [])
        self.assertTrue((self.mailbox / "new/a").is_file())
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=11), 1)

    def test_ductor_unavailable_retains_queued_mail_and_other_seats_continue(self):
        config, adapter, calls, deliveries = self.ductor_fixture()
        herdr = self.add_herdr_seat()
        class Factory:
            def for_record(inner, record):
                return adapter if record["transport"] == "ductor" else herdr
        mid = "<offline@node.helm>"; self.mail(mid, "a")
        with mock.patch.object(adapter, "resolve_idle_pane", side_effect=self.watcher.WatcherError("Ductor input unavailable")), mock.patch("sys.stderr"):
            self.assertEqual(self.watcher.locked_scan(self.registry, Factory(), now=10), 1)
        self.assertEqual(self.receipt(mid)["wake_state"], "queued")
        self.assertEqual(self.receipt(mid)["reason"], "transport_unavailable")
        self.assertEqual(deliveries, [])
        self.assertTrue((self.mailbox / "new/a").is_file())
        self.assertEqual(len(herdr.deliveries), 1)
        self.assertEqual(self.watcher.locked_scan(self.registry, Factory(), now=11), 1)

    def test_ductor_busy_race_is_an_explicit_non_admission_not_unknown_delivery(self):
        config, adapter, calls, deliveries = self.ductor_fixture(outcome="busy")
        mid = "<race@node.helm>"; self.mail(mid, "a")
        with mock.patch("sys.stderr"):
            self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10), 0)
        self.assertEqual(self.receipt(mid)["wake_state"], "queued")
        self.assertEqual(self.receipt(mid)["reason"], "busy")
        self.assertTrue((self.mailbox / "new/a").is_file())

    def test_ductor_ambiguous_delivery_is_never_resent(self):
        config, adapter, calls, deliveries = self.ductor_fixture()
        async def lost(*args):
            raise self.watcher.WatcherError("Ductor admission outcome is unknown")
        adapter.client = lost
        mid = "<lost@node.helm>"; self.mail(mid, "a")
        with mock.patch("sys.stderr"):
            self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10), 0)
        self.assertEqual(self.receipt(mid)["wake_state"], "delivery_unknown")
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=11), 0)
        self.assertEqual(len(calls), 1)

    def test_ductor_observation_only_wrong_identity_and_unknown_authority_refuse(self):
        config, adapter, calls, deliveries = self.ductor_fixture()
        good = {"busy": False, "known": True, "session_key": "tg:1",
                "reasons": [], "idle_prompt": "ductor.idle_prompt.v2"}
        for payload in (good | {"idle_prompt": None}, good | {"session_key": "tg:2"},
                        good | {"known": False}, good | {"busy": 0}):
            with self.subTest(payload=payload):
                adapter.opener = lambda request, timeout: FakeHTTPResponse(payload)
                with self.assertRaises(self.watcher.WatcherError):
                    adapter.resolve_idle_pane(self.registry["seats"]["builder"])
        self.assertEqual(deliveries, [])

    def test_ductor_private_config_and_loopback_required(self):
        config, adapter, calls, deliveries = self.ductor_fixture()
        original = config.read_text()
        for api in ({"enabled": False}, {"token": ""}, {"host": "YOUR_NON_LOOPBACK_HOST"},
                    {"chat_id": False}, {"port": "YOUR_PORT"}):
            data = json.loads(original); data["api"].update(api)
            config.write_text(json.dumps(data))
            with self.subTest(api=api), self.assertRaises(self.watcher.WatcherError):
                adapter.resolve_idle_pane(self.registry["seats"]["builder"])
        config.write_text(original); config.chmod(0o644)
        with self.assertRaises(self.watcher.WatcherError):
            adapter.resolve_idle_pane(self.registry["seats"]["builder"])
        self.assertEqual(calls, [])

    def hermes_record(self):
        key = self.base / "hermes.key"
        key.write_text("YOUR_HERMES_API_KEY\n")
        key.chmod(0o600)
        return {
            "host": "test-host", "mailbox": "seats/hermesbot", "harness": "hermes",
            "transport": "hermes", "hermes_url": "http://localhost:YOUR_HERMES_PORT",
            "hermes_api_key_file": str(key), "hermes_target": {
                "mode": "gateway_platform_session",
                "session_key": "agent:YOUR_PROFILE:telegram:dm:YOUR_HERMES_CHAT_ID",
            }, "rate_limit_seconds": 0,
        }

    def test_hermes_delivery_targets_the_telegram_platform_session(self):
        record = self.hermes_record()
        calls = []

        def opener(request, timeout):
            calls.append((request, timeout))
            body = json.loads(request.data)
            if request.full_url.endswith("/status"):
                return FakeHTTPResponse({"protocol": "hermes.gateway_idle_prompt.v1",
                    "known": True, "busy": False,
                    "session_key": "agent:YOUR_PROFILE:telegram:dm:YOUR_HERMES_CHAT_ID"})
            return FakeHTTPResponse({"protocol": "hermes.gateway_idle_prompt.v1",
                "request_id": body["request_id"],
                "session_key": "agent:YOUR_PROFILE:telegram:dm:YOUR_HERMES_CHAT_ID",
                "status": "accepted"}, status=202)

        adapter = self.watcher.HermesAdapter(opener=opener)
        target = "agent:YOUR_PROFILE:telegram:dm:YOUR_HERMES_CHAT_ID"
        self.assertEqual(adapter.resolve_idle_pane(record), target)
        adapter.deliver(record, target, "wake")
        self.assertEqual([call[0].get_method() for call in calls], ["POST", "POST"])
        self.assertTrue(calls[0][0].full_url.endswith("/api/gateway/idle-prompt/status"))
        self.assertTrue(calls[1][0].full_url.endswith("/api/gateway/idle-prompt"))
        self.assertEqual(json.loads(calls[0][0].data),
                         {"protocol": "hermes.gateway_idle_prompt.v1", "session_key": target})
        body = json.loads(calls[1][0].data)
        self.assertEqual(set(body), {"protocol", "request_id", "session_key", "text"})
        self.assertEqual(body["protocol"], "hermes.gateway_idle_prompt.v1")
        self.assertEqual(body["session_key"], target)
        self.assertEqual(body["text"], "wake")
        headers = {key.lower(): value for key, value in calls[1][0].header_items()}
        self.assertEqual(headers["authorization"], "Bearer YOUR_HERMES_API_KEY")
        self.assertEqual(calls[0][1], 15)
        self.assertEqual(calls[1][1], 15)

    def test_hermes_busy_is_queued_and_never_interrupts(self):
        record = self.hermes_record() | {"mailbox": "seats/builder"}
        self.registry["seats"]["builder"] = record
        mid = "<hermes-busy@node.helm>"
        self.mail(mid, "hermes")
        calls = []
        def opener(request, timeout):
            calls.append(request)
            return FakeHTTPResponse({"protocol": "hermes.gateway_idle_prompt.v1", "known": True,
                "busy": True, "session_key": record["hermes_target"]["session_key"]})
        self.assertEqual(self.watcher.locked_scan(
            self.registry, self.watcher.HermesAdapter(opener=opener), now=10), 0)
        receipt = self.receipt(mid)
        self.assertEqual(receipt["wake_state"], "queued")
        self.assertEqual(receipt["reason"], "busy")
        self.assertEqual(len(calls), 1)

    def test_hermes_lost_admission_ack_is_unknown_and_never_resent(self):
        record = self.hermes_record() | {"mailbox": "seats/builder"}
        self.registry["seats"]["builder"] = record
        mid = "<hermes-lost@node.helm>"; self.mail(mid, "hermes")
        calls = []
        def opener(request, timeout):
            calls.append(request)
            if request.full_url.endswith("/status"):
                return FakeHTTPResponse({"protocol": "hermes.gateway_idle_prompt.v1",
                    "known": True, "busy": False,
                    "session_key": record["hermes_target"]["session_key"]})
            raise TimeoutError("fixture lost acknowledgement")
        with mock.patch("sys.stderr"):
            self.assertEqual(self.watcher.locked_scan(
                self.registry, self.watcher.HermesAdapter(opener=opener), now=10), 0)
        self.assertEqual(self.receipt(mid)["wake_state"], "delivery_unknown")
        self.assertEqual(self.watcher.locked_scan(
            self.registry, self.watcher.HermesAdapter(opener=opener), now=11), 0)
        self.assertEqual(len(calls), 2)

    def nanobot_record(self):
        key = self.base / "nanobot.key"
        key.write_text("YOUR_NANOBOT_API_TOKEN\n"); key.chmod(0o600)
        return {"host": "test-host", "mailbox": "consorts/nanobot", "harness": "nanobot",
            "transport": "nanobot", "nanobot_url": "http://localhost:YOUR_NANOBOT_PORT",
            "nanobot_api_token_file": str(key), "nanobot_target": {
                "mode": "telegram_gateway", "channel": "telegram",
                "chat_id": "YOUR_NANOBOT_CHAT_ID",
                "session_key": "telegram:YOUR_NANOBOT_CHAT_ID"}, "rate_limit_seconds": 0}

    def test_nanobot_atomic_interface_targets_telegram_session(self):
        record = self.nanobot_record(); calls = []
        def opener(request, timeout):
            calls.append(request)
            body = json.loads(request.data) if request.data else {}
            if request.get_method() == "GET":
                return FakeHTTPResponse({"protocol": "nanobot.idle_prompt.v1", "known": True,
                    "busy": False, "session_key": record["nanobot_target"]["session_key"]})
            return FakeHTTPResponse({"protocol": "nanobot.idle_prompt.v1",
                "request_id": body["request_id"],
                "session_key": body["target"]["session_key"],
                "status": "accepted"}, status=202)
        adapter = self.watcher.NanobotAdapter(opener=opener)
        target = record["nanobot_target"]["session_key"]
        self.assertEqual(adapter.resolve_idle_pane(record), target)
        adapter.deliver(record, target, "wake")
        self.assertEqual([request.get_method() for request in calls], ["GET", "POST"])
        body = json.loads(calls[1].data)
        self.assertEqual(body["target"], record["nanobot_target"])
        self.assertEqual(body["text"], "wake")
        self.assertRegex(body["request_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(calls[1].headers["Authorization"], "Bearer YOUR_NANOBOT_API_TOKEN")

    def test_nanobot_busy_and_lost_ack_have_distinct_receipt_states(self):
        record = self.nanobot_record() | {"mailbox": "seats/builder"}
        self.registry["seats"]["builder"] = record
        mid = "<nano-busy@node.helm>"; self.mail(mid, "a")
        busy_calls = []
        def busy(request, timeout):
            busy_calls.append(request)
            return FakeHTTPResponse({"protocol": "nanobot.idle_prompt.v1", "known": True,
                "busy": True, "session_key": record["nanobot_target"]["session_key"]})
        self.assertEqual(self.watcher.locked_scan(
            self.registry, self.watcher.NanobotAdapter(opener=busy), now=10), 0)
        self.assertEqual(self.receipt(mid)["wake_state"], "queued")
        self.assertEqual(self.receipt(mid)["reason"], "busy")
        (self.mailbox / "new/a").unlink()
        mid = "<nano-lost@node.helm>"; self.mail(mid, "b")
        lost_calls = []
        def lost(request, timeout):
            lost_calls.append(request)
            if request.get_method() == "GET":
                return FakeHTTPResponse({"protocol": "nanobot.idle_prompt.v1", "known": True,
                    "busy": False, "session_key": record["nanobot_target"]["session_key"]})
            raise TimeoutError("fixture lost acknowledgement")
        with mock.patch("sys.stderr"):
            self.assertEqual(self.watcher.locked_scan(
                self.registry, self.watcher.NanobotAdapter(opener=lost), now=11), 0)
        self.assertEqual(self.receipt(mid)["wake_state"], "delivery_unknown")
        self.assertEqual(self.watcher.locked_scan(
            self.registry, self.watcher.NanobotAdapter(opener=lost), now=12), 0)
        self.assertEqual(len(lost_calls), 2)

    def test_deepseek_busy_detection_prevents_prompt_until_session_is_idle(self):
        cookie = self.base / "deepseek.cookie"
        cookie.write_text("session=YOUR_COOKIE")
        cookie.chmod(0o600)
        record = {
            "host": "test-host", "mailbox": "consorts/deepbot", "harness": "deepseek",
            "transport": "deepseek", "deepseek_url": "http://localhost:YOUR_PORT",
            "deepseek_cookie_file": str(cookie),
            "deepseek_session": "telegram-YOUR_DEEPSEEK_SESSION",
            "rate_limit_seconds": 0,
        }
        running = iter((True, False))
        calls = []

        def opener(request, timeout):
            body = json.loads(request.data)
            calls.append((request, timeout, body))
            if body["method"] == "session/list":
                value = {"items": [{"sessionId": "telegram-YOUR_DEEPSEEK_SESSION",
                                    "running": next(running)}]}
            else:
                value = {"accepted": True}
            return FakeHTTPResponse({"type": "server-response", "rpcId": body["rpcId"],
                                     "result": {"ok": True, "value": value}})

        adapter = self.watcher.DeepSeekAdapter(opener=opener)
        self.assertIsNone(adapter.resolve_idle_pane(record))
        self.assertEqual(adapter.resolve_idle_pane(record), "telegram-YOUR_DEEPSEEK_SESSION")
        adapter.deliver(record, "telegram-YOUR_DEEPSEEK_SESSION", "/inbox")
        self.assertEqual([call[2]["method"] for call in calls],
                         ["session/list", "session/list", "session/prompt"])
        self.assertTrue(all(call[2]["type"] == "client-request" for call in calls))
        self.assertEqual(calls[0][2]["payload"]["args"], {"_request": {}})
        self.assertEqual(calls[-1][2]["payload"]["args"]["request"]["mode"], "queue")
        self.assertRegex(calls[-1][2]["payload"]["args"]["request"]["requestId"],
                         r"^mailcortex-[0-9a-f]{32}$")
        self.assertEqual(calls[-1][0].headers["Cookie"], "session=YOUR_COOKIE")

    def test_deepseek_busy_queues_and_lost_ack_is_never_resent(self):
        cookie = self.base / "deepseek.cookie"
        cookie.write_text("session=YOUR_COOKIE")
        cookie.chmod(0o600)
        record = {
            "host": "test-host", "mailbox": "seats/builder", "harness": "deepseek",
            "transport": "deepseek", "deepseek_url": "http://localhost:YOUR_PORT",
            "deepseek_cookie_file": str(cookie),
            "deepseek_session": "telegram-YOUR_DEEPSEEK_SESSION",
            "rate_limit_seconds": 0,
        }
        self.registry["seats"]["builder"] = record
        self.mail("<deepseek-lost@node.helm>", "a")
        running = iter((True, False))
        calls = []

        def opener(request, timeout):
            body = json.loads(request.data)
            calls.append(body)
            if body["method"] == "session/list":
                value = {"items": [{"sessionId": record["deepseek_session"],
                                    "running": next(running)}]}
                return FakeHTTPResponse({"type": "server-response", "rpcId": body["rpcId"],
                                         "result": {"ok": True, "value": value}})
            self.assertEqual(body["method"], "session/prompt")
            raise TimeoutError("fixture lost acknowledgement")

        adapter = self.watcher.DeepSeekAdapter(opener=opener)
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10), 0)
        self.assertEqual(self.receipt("<deepseek-lost@node.helm>")["wake_state"], "queued")
        self.assertEqual([call["method"] for call in calls], ["session/list"])
        with mock.patch("sys.stderr"):
            self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=11), 0)
        self.assertEqual(self.receipt("<deepseek-lost@node.helm>")["wake_state"],
                         "delivery_unknown")
        prompt = calls[-1]["payload"]["args"]["request"]
        self.assertEqual(prompt["sessionId"], record["deepseek_session"])
        self.assertRegex(prompt["requestId"], r"^mailcortex-[0-9a-f]{32}$")
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=12), 0)
        self.assertEqual([call["method"] for call in calls],
                         ["session/list", "session/list", "session/prompt"])

    def test_deepseek_wake_carries_the_mail_herdr_keeps_inbox(self):
        mail = self.base / "mail.eml"
        mail.write_bytes(b"From: fable@test-host.helm\r\nTo: deepbot@test-host.helm\r\n"
                         b"Subject: Comms check\r\nMessage-ID: <1.2@test-host.helm>\r\n\r\n"
                         b"Wolf, reply with Fox.\r\n")
        prompt = self.watcher.wake_prompt({"transport": "deepseek"}, mail)
        self.assertIn("Subject: Comms check", prompt)
        self.assertIn("Wolf, reply with Fox.", prompt)
        self.assertIn("MailCortex delivery", prompt)
        self.assertIn("Sender: fable@test-host.helm", prompt)
        self.assertIn("Message-ID: <1.2@test-host.helm>", prompt)
        self.assertIn("act according to your harness", prompt)
        self.assertNotEqual(prompt, "/inbox")
        herdr_prompt = self.watcher.wake_prompt({"transport": "herdr"}, mail)
        self.assertIn("MailCortex delivery", herdr_prompt)
        self.assertIn("/inbox", herdr_prompt)

    def deep_fixture(self):
        record = {"host": "test-host", "mailbox": "seats/builder", "harness": "deepseek",
                  "transport": "deepseek", "deepseek_url": "http://localhost:YOUR_PORT",
                  "deepseek_cookie_file": str(self.base / "cookie"),
                  "deepseek_session": "telegram-YOUR_DEEPSEEK_SESSION",
                  "rate_limit_seconds": 0}
        self.registry["seats"]["builder"] = record
        for leaf in ("tmp", "new", "cur"):
            (self.root / "consorts/sender" / leaf).mkdir(parents=True)
        class Adapter:
            def __init__(self):
                self.calls = []; self.result = ("pending", None)
            def resolve_idle_pane(self, record):
                return record["deepseek_session"]
            def deliver(self, record, target, prompt, request_id=None):
                self.calls.append((target, prompt, request_id))
            def reply(self, record, request_id):
                assert request_id == self.calls[0][2]
                return self.result
        return record, Adapter()

    def reply_events(self, request="ours", reason="completed"):
        def e(seq, kind, data):
            return {"type": "event", "event": {"seq": seq, "type": kind, "data": data}}
        return [e(0, "turn/start", {"turn": 1}),
                e(1, "user/message", {"source": {"kind": "user", "rpcId": request}}),
                e(2, "assistant/message", {"turn": 1, "message": {"content": [
                    {"type": "thinking", "text": "private reasoning"},
                    {"type": "text", "text": "Fox"}]}}),
                e(3, "turn/end", {"turn": 1, "reason": {"kind": reason}})]

    def test_mailback_matches_request_not_latest_turn_and_requires_completion(self):
        records = self.reply_events()
        later = self.reply_events("unrelated")
        for row in later:
            row["event"]["seq"] += 4
            if "turn" in row["event"]["data"]:
                row["event"]["data"]["turn"] = 2
        later[2]["event"]["data"]["message"]["content"] = [{"type": "text", "text": "wrong reply"}]
        self.assertEqual(self.watcher.completed_reply(records + later, "ours"), ("ready", "Fox"))
        self.assertEqual(self.watcher.completed_reply(records[:-1], "ours"), ("pending", None))
        self.assertEqual(self.watcher.completed_reply(records[1:], "ours"), ("pending", None))
        for reason in ("aborted", "error", "interrupted", "max-tokens"):
            self.assertEqual(self.watcher.completed_reply(self.reply_events(reason=reason), "ours"), ("failed", None))
        records[2]["event"]["type"] = "user/message"
        records[2]["event"]["data"] = {"source": {"kind": "user", "rpcId": "other"}}
        self.assertEqual(self.watcher.completed_reply(records, "ours"), ("failed", None))

    def test_mailback_roundtrip_is_threaded_private_and_does_not_claim_handling(self):
        record, adapter = self.deep_fixture()
        mid = "<request@node.helm>"
        self.mail(mid, "a"); self.mail("<second@node.helm>", "b")
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10), 1)
        self.assertEqual(self.receipt(mid)["reply_context"]["request_id"], adapter.calls[0][2])
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=11), 0)
        self.assertEqual(self.receipt("<second@node.helm>")["reason"], "reply_pending")
        adapter.result = ("ready", "Fox")
        (self.mailbox / "new/b").unlink()
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=12), 0)
        from email import policy
        from email.parser import BytesParser
        files = list((self.root / "consorts/sender/new").iterdir())
        self.assertEqual(len(files), 1)
        msg = BytesParser(policy=policy.default).parsebytes(files[0].read_bytes())
        self.assertEqual(msg["From"], "seat+builder@node.helm")
        self.assertEqual(msg["To"], "sender@node.helm")
        self.assertEqual(msg["In-Reply-To"], mid)
        self.assertEqual(msg["References"], mid)
        self.assertEqual(msg["Auto-Submitted"], "auto-replied")
        self.assertEqual(msg.get_content().strip(), "Fox")
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.receipt(mid)["reply_state"], "delivered")
        self.assertIsNone(self.receipt(mid)["handling_state"])
        self.assertEqual(self.receipt(mid)["wake_state"], "injected")
        self.watcher.locked_scan(self.registry, adapter, now=13)
        self.assertEqual(len(list(files[0].parent.iterdir())), 1)

    def test_mailback_recovers_after_publish_before_receipt_even_when_seen(self):
        record, adapter = self.deep_fixture()
        mid = "<crash@node.helm>"; self.mail(mid, "a")
        self.watcher.locked_scan(self.registry, adapter, now=10)
        adapter.result = ("ready", "Fox")
        atomic = self.watcher.MAILCORTEX.atomic_json
        def fail_after_publish(path, value):
            if value.get("reply_state") == "delivered":
                raise OSError("fixture crash after publication")
            atomic(path, value)
        with mock.patch.object(self.watcher.MAILCORTEX, "atomic_json", fail_after_publish):
            with mock.patch("sys.stderr"):
                self.watcher.locked_scan(self.registry, adapter, now=11)
        self.assertEqual(self.receipt(mid)["reply_state"], "ready")
        target = self.root / "consorts/sender"
        path = next((target / "new").iterdir())
        path.rename(target / "cur" / (path.name + ":2,S"))
        self.watcher.locked_scan(self.registry, adapter, now=12)
        self.assertEqual(list((target / "new").iterdir()), [])
        self.assertEqual(len(list((target / "cur").iterdir())), 1)
        self.assertEqual(self.receipt(mid)["reply_state"], "delivered")

    def test_mailback_refuses_redirects_unknown_senders_and_automatic_loops(self):
        record, adapter = self.deep_fixture()
        cases = (("From", "outside@example.com"), ("From", "unknown@node.helm"),
                 ("To", "other@node.helm"), ("From", "seat+builder@node.helm"))
        for index, (header, value) in enumerate(cases):
            mid = f"<bad{index}@node.helm>"
            self.mail(mid, str(index))
            path = self.mailbox / "new" / str(index)
            message = self.watcher.MAILCORTEX.parse_message(path)
            message.replace_header(header, value); path.write_bytes(message.as_bytes())
            with mock.patch("sys.stderr"):
                self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10 + index), 1)
            self.assertEqual(self.receipt(mid)["reply_state"], "failed")
            self.assertNotIn("reply_context", self.receipt(mid))
            self.assertIn("No mail-back is possible", adapter.calls[-1][1])
        self.mail("<auto@node.helm>", "auto")
        path = self.mailbox / "new/auto"
        message = self.watcher.MAILCORTEX.parse_message(path)
        message.replace_header("From", "sender@node.helm")
        message["Auto-Submitted"] = "auto-replied"; path.write_bytes(message.as_bytes())
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=20), 0)
        self.assertEqual(len(adapter.calls), len(cases))
        self.assertEqual(self.receipt("<auto@node.helm>")["reason"], "auto_submitted")
        self.assertIsNone(self.receipt("<auto@node.helm>")["handling_state"])
        receipt_path = self.watcher.MAILCORTEX.receipt_path("builder", "<auto@node.helm>")
        unchanged = receipt_path.read_bytes()
        self.watcher.locked_scan(self.registry, adapter, now=21)
        self.assertEqual(receipt_path.read_bytes(), unchanged)

    def add_herdr_seat(self):
        mailbox = self.root / "seats/fox"
        for leaf in ("tmp", "new", "cur"):
            (mailbox / leaf).mkdir(parents=True)
        self.registry["seats"]["fox"] = {
            "host": "test-host", "mailbox": "seats/fox", "harness": "codex",
            "transport": "herdr", "herdr_session": "fox-session",
            "herdr_target": "fox-agent", "rate_limit_seconds": 0}
        msg = EmailMessage()
        msg["From"] = "sender@node.helm"; msg["To"] = "seat+fox@node.helm"
        msg["Message-ID"] = "<fox@node.helm>"; msg.set_content("hello fox")
        (mailbox / "new/a").write_bytes(msg.as_bytes())
        return FakeAdapter()

    def adapters(self, deep, herdr):
        class Factory:
            def for_record(self, record):
                return deep if record["transport"] == "deepseek" else herdr
        return Factory()

    def test_missing_sender_mailbox_wakes_orca_and_herdr_in_same_scan(self):
        record, deep = self.deep_fixture()
        herdr = self.add_herdr_seat()
        mid = "<nano@node.helm>"; self.mail(mid, "a")
        path = self.mailbox / "new/a"
        message = self.watcher.MAILCORTEX.parse_message(path)
        message.replace_header("From", "nano@node.helm"); path.write_bytes(message.as_bytes())
        factory = self.adapters(deep, herdr)
        with mock.patch("sys.stderr") as diagnostic:
            self.assertEqual(self.watcher.locked_scan(self.registry, factory, now=10), 2)
            self.assertTrue(diagnostic.write.called)
        receipt = self.receipt(mid)
        self.assertEqual(receipt["wake_state"], "injected")
        self.assertEqual(receipt["reply_state"], "failed")
        self.assertEqual(receipt["reply_reason"], "return_path_unavailable")
        self.assertIn("not provisioned", receipt["reply_error"])
        self.assertIn("No mail-back is possible", deep.calls[0][1])
        self.assertEqual(len(herdr.deliveries), 1)
        self.assertFalse((self.root / "consorts/nano").exists())
        self.assertEqual(self.watcher.locked_scan(self.registry, factory, now=11), 0)
        self.assertEqual(len(deep.calls), 1)

    def test_broken_snapshot_retains_pending_receipt_and_herdr_still_wakes(self):
        record, deep = self.deep_fixture()
        mid = "<snapshot@node.helm>"; self.mail(mid, "a")
        self.watcher.locked_scan(self.registry, deep, now=10)
        herdr = self.add_herdr_seat()
        factory = self.adapters(deep, herdr)
        with mock.patch.object(deep, "reply", side_effect=self.watcher.WatcherError("snapshot unavailable")), \
             mock.patch("sys.stderr") as diagnostic:
            self.assertEqual(self.watcher.locked_scan(self.registry, factory, now=11), 1)
            self.assertTrue(diagnostic.write.called)
        receipt = self.receipt(mid)
        self.assertEqual(receipt["reply_state"], "pending")
        self.assertEqual(receipt["reply_error"], "snapshot unavailable")
        self.assertEqual(receipt["reply_error_at"], 11)
        self.assertEqual(len(herdr.deliveries), 1)
        deep.result = ("ready", "Fox")
        self.watcher.locked_scan(self.registry, factory, now=12)
        self.assertEqual(self.receipt(mid)["reply_state"], "delivered")

    def test_expired_transport_cookie_only_queues_its_message(self):
        record, deep = self.deep_fixture()
        herdr = self.add_herdr_seat()
        mid = "<cookie@node.helm>"; self.mail(mid, "a")
        with mock.patch.object(deep, "resolve_idle_pane", side_effect=self.watcher.WatcherError("DeepSeek RPC returned an error")), \
             mock.patch("sys.stderr"):
            self.assertEqual(self.watcher.locked_scan(self.registry, self.adapters(deep, herdr), now=10), 1)
        self.assertEqual(self.receipt(mid)["wake_state"], "queued")
        self.assertEqual(self.receipt(mid)["reason"], "transport_unavailable")
        self.assertEqual(deep.calls, [])
        self.assertEqual(len(herdr.deliveries), 1)

    def test_one_bad_reply_does_not_block_another_receipt_settlement(self):
        record, deep = self.deep_fixture()
        for index in range(2):
            mid = f"<separate{index}@node.helm>"
            self.watcher.MAILCORTEX.write_wake_receipt("builder", mid, "injected",
                reply_context={"session": "telegram-YOUR_DEEPSEEK_SESSION", "request_id": str(index),
                               "sender": "seat+builder@node.helm", "to": "sender@node.helm", "subject": "test"},
                reply_state="pending")
        def reply(record, request_id):
            if request_id == "0":
                raise self.watcher.WatcherError("one bad history")
            return "ready", "Fox"
        with mock.patch.object(deep, "reply", side_effect=reply), mock.patch("sys.stderr"):
            self.watcher.locked_scan(self.registry, deep, now=10)
        self.assertEqual(self.receipt("<separate0@node.helm>")["reply_state"], "pending")
        self.assertEqual(self.receipt("<separate1@node.helm>")["reply_state"], "delivered")

    def test_mailback_failed_turn_and_legacy_receipts_never_publish(self):
        record, adapter = self.deep_fixture()
        mid = "<failed@node.helm>"; self.mail(mid, "a")
        self.watcher.locked_scan(self.registry, adapter, now=10)
        adapter.result = ("failed", None)
        self.watcher.locked_scan(self.registry, adapter, now=11)
        self.assertEqual(self.receipt(mid)["reply_state"], "failed")
        self.assertEqual(list((self.root / "consorts/sender/new").iterdir()), [])
        self.mail("<legacy@node.helm>", "b")
        self.watcher.MAILCORTEX.write_wake_receipt("builder", "<legacy@node.helm>", "injected")
        self.watcher.locked_scan(self.registry, adapter, now=12)
        self.assertEqual(len(adapter.calls), 1)

    def test_returned_mail_still_wakes_herdr_without_an_autoreply_loop(self):
        self.mail("<reply@node.helm>", "a")
        path = self.mailbox / "new/a"
        message = self.watcher.MAILCORTEX.parse_message(path)
        message["Auto-Submitted"] = "auto-replied"
        path.write_bytes(message.as_bytes())
        adapter = FakeAdapter()
        self.assertEqual(self.watcher.locked_scan(self.registry, adapter, now=10), 1)
        self.assertIn("MailCortex delivery", adapter.deliveries[0][-1])
        self.assertIn("/inbox", adapter.deliveries[0][-1])

    def test_mailback_collision_fails_without_overwriting_and_symlinks_are_refused(self):
        record, adapter = self.deep_fixture()
        mid = "<collision@node.helm>"; self.mail(mid, "a")
        self.watcher.locked_scan(self.registry, adapter, now=10)
        receipt = self.receipt(mid)
        receipt.update(reply_body="Fox", reply_ready_at=11)
        name = self.watcher.publish_reply("builder", mid, receipt)
        path = self.root / "consorts/sender/new" / name
        path.write_text("different bytes")
        with self.assertRaisesRegex(self.watcher.WatcherError, "collision"):
            self.watcher.publish_reply("builder", mid, receipt)
        self.assertEqual(path.read_text(), "different bytes")
        path.unlink()
        path.symlink_to(self.base / "outside")
        with self.assertRaisesRegex(self.watcher.WatcherError, "collision"):
            self.watcher.publish_reply("builder", mid, receipt)

    def test_mailback_snapshot_paginates_to_turn_start_and_rejects_wrong_session(self):
        record, adapter = self.deep_fixture()
        cookie = self.base / "cookie"; cookie.write_text("test-cookie"); cookie.chmod(0o600)
        records = self.reply_events()
        snapshot = {"type": "snapshot", "header": {"id": "telegram-YOUR_DEEPSEEK_SESSION"},
                    "cursor": 3, "records": records[1:], "hasMore": True}
        calls = []
        def rpc(record, method, args):
            calls.append((method, args))
            return {"records": records[:1], "hasMore": False}
        real = self.watcher.DeepSeekAdapter()
        with mock.patch.object(self.watcher.shutil, "which", return_value="fixture-dsh"), \
             mock.patch.object(self.watcher.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(snapshot), "")), \
             mock.patch.object(real, "_rpc", side_effect=rpc):
            self.assertEqual(real.reply(record, "ours"), ("ready", "Fox"))
            self.assertEqual(calls[0][0], "session/page")
            self.assertEqual(calls[0][1]["request"]["beforeSeq"], 1)
            self.assertEqual(calls[0][1]["request"]["throughSeq"], 3)
            snapshot["header"]["id"] = "wrong-session"
            with mock.patch.object(self.watcher.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(snapshot), "")):
                with self.assertRaisesRegex(self.watcher.WatcherError, "target mismatch"):
                    real.reply(record, "ours")

    def test_production_adapter_uses_verified_herdr_shape_and_commands(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            if command[3:5] == ["agent", "get"]:
                payload = {"result": {"agent": {"name": "builder-agent",
                           "pane_id": "wT:p1", "agent_status": "idle"}}}
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
            if command[3:5] == ["pane", "run"]:
                return subprocess.CompletedProcess(command, 0, "{}", "")
            self.fail(f"unexpected Herdr command: {command}")

        record = self.registry["seats"]["builder"]
        adapter = self.watcher.HerdrAdapter(runner=runner)
        pane = adapter.resolve_idle_pane(record)
        self.assertEqual(pane, "wT:p1")
        adapter.deliver(record, pane, "/inbox")
        self.assertEqual(calls, [
            ["herdr", "--session", "builder-session", "agent", "get", "builder-agent"],
            ["herdr", "--session", "builder-session", "pane", "run", "wT:p1", "/inbox"],
        ])

    def test_production_adapter_accepts_done_but_not_unknown(self):
        states = iter(("done", "unknown"))

        def runner(command, **kwargs):
            payload = {"result": {"agent": {"name": "builder-agent",
                       "pane_id": "wT:p1", "agent_status": next(states)}}}
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

        record = self.registry["seats"]["builder"]
        adapter = self.watcher.HerdrAdapter(runner=runner)
        self.assertEqual(adapter.resolve_idle_pane(record), "wT:p1")
        self.assertIsNone(adapter.resolve_idle_pane(record))


if __name__ == "__main__":
    unittest.main()
