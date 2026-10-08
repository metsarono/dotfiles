#!/usr/bin/env python3
"""Fixture tests for mailcortex-xmpp-bridge (no network, no slixmpp)."""

import asyncio
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
import types
import unittest
import xml.etree.ElementTree as ET
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import patch

BRIDGE = Path(os.environ.get("MAILCORTEX_XMPP_BRIDGE", "~/.local/bin/mailcortex-xmpp-bridge")).expanduser()
loader = importlib.machinery.SourceFileLoader("bridge", str(BRIDGE))
spec = importlib.util.spec_from_loader("bridge", loader)
bridge = importlib.util.module_from_spec(spec)
loader.exec_module(bridge)


def base_config(tmp: Path) -> dict:
    secret = tmp / "secret"
    secret.write_text("s" * 32)
    os.chmod(secret, 0o600)
    return {
        "component_jid": "seats.example.test",
        "owner_jids": ["owner@example.test"],
        "bridge_address": "seat+xmpp-bridge@host.helm",
        "component_secret_file": str(secret),
        "seats": {"fable": "fable@host.helm", "worker": "seat+worker@host.helm"},
    }


class FakeRun:
    def __init__(self, outputs=None):
        self.calls = []
        self.outputs = outputs or {}

    def __call__(self, argv, capture_output, text):
        self.calls.append(argv)
        out = self.outputs.get(argv[1], "")
        return subprocess.CompletedProcess(argv, 0, out, "")


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def write(self, data):
        path = self.tmp / "bridge.json"
        path.write_text(json.dumps(data))
        return path

    def test_valid_config_builds_reverse_map(self):
        cfg = bridge.load_config(self.write(base_config(self.tmp)))
        self.assertEqual(cfg["bridge_seat"], "xmpp-bridge")
        self.assertEqual(cfg["reverse"]["fable"], "fable")

    def test_bridge_address_must_be_a_seat(self):
        data = base_config(self.tmp)
        data["bridge_address"] = "bridge@host.helm"
        with self.assertRaises(bridge.BridgeError):
            bridge.load_config(self.write(data))

    def test_duplicate_target_refused(self):
        data = base_config(self.tmp)
        data["seats"]["other"] = "fable@host.helm"
        with self.assertRaises(bridge.BridgeError):
            bridge.load_config(self.write(data))

    def test_owner_must_be_bare_jid(self):
        data = base_config(self.tmp)
        data["owner_jids"] = ["owner@example.test/phone"]
        with self.assertRaises(bridge.BridgeError):
            bridge.load_config(self.write(data))

    def test_secret_mode_enforced(self):
        cfg = bridge.load_config(self.write(base_config(self.tmp)))
        os.chmod(cfg["component_secret_file"], 0o644)
        with self.assertRaises(bridge.BridgeError):
            bridge.read_secret(cfg["component_secret_file"])

    def test_optional_permission_and_bot_maps_validate(self):
        data = base_config(self.tmp) | {
            "permission_secrets": {"fable": str(self.tmp / "permission.secret")},
            "bots": {"fable": "FixtureBot"},
        }
        (self.tmp / "permission.secret").write_text("p" * 32)
        os.chmod(self.tmp / "permission.secret", 0o600)
        cfg = bridge.load_config(self.write(data))
        self.assertEqual(cfg["bots"], {"fable": "FixtureBot"})
        self.assertEqual(cfg["permission_secrets"]["fable"], self.tmp / "permission.secret")
        for change in ({"permission_secrets": {"ghost": "YOUR_SECRET_FILE"}},
                       {"bots": {"ghost": "FixtureBot"}},
                       {"bots": {"fable": "bad bot"}}):
            with self.subTest(change=change):
                with self.assertRaises(bridge.BridgeError):
                    bridge.load_config(self.write(base_config(self.tmp) | change))


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.secret = self.tmp / "secret"
        self.secret.write_text("s" * 32)
        os.chmod(self.secret, 0o600)
        data = base_config(self.tmp) | {
            "permission_secrets": {"fable": str(self.secret)},
        }
        path = self.tmp / "bridge.json"
        path.write_text(json.dumps(data))
        self.cfg = bridge.load_config(path)

    def test_normalized_replies_and_request_shape(self):
        self.assertEqual(bridge.normalize_permission_text("Yes, A B C D E."), "yes abcde")
        self.assertEqual(bridge.permission_reply("YES, A B C D E."), ("allow", "abcde"))
        self.assertEqual(bridge.permission_reply("no abcde"), ("deny", "abcde"))
        self.assertIsNone(bridge.permission_reply("yes abcde please"))
        rendered = ("From: fable@host.helm\nSubject: [permission] Bash\n"
                    "Message-ID: <permission@host.helm>\n\nrequest_id: abcde\n")
        self.assertEqual(bridge.permission_request(rendered),
                         ("abcde", "Bash", "request_id: abcde"))

    def test_decision_mail_uses_fixed_auth_header(self):
        run = FakeRun({"send": "decision.msg\n"})
        name = bridge.decision_mail(self.cfg, "fable", "abcde", "allow",
                                    "s" * 32, 123, run)
        self.assertEqual(name, "decision.msg")
        argv = run.calls[0]
        self.assertEqual(argv[argv.index("--permission-auth") + 1],
                         bridge.permission_auth_value("s" * 32, "fable", "abcde", "allow", 123))


class VoiceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        data = base_config(self.tmp) | {"upload_base_url": "https://uploads.example.test/file_share/"}
        config = self.tmp / "bridge.json"
        config.write_text(json.dumps(data))
        self.cfg = bridge.load_config(config)
        self.url = self.cfg["upload_base_url"] + "slot/note.ogg"
        self.audio_paths = []
        self.raw = b"OggS\x00original voice"

    def download(self, cfg, url, path):
        self.audio_paths.append(path)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        path.write_bytes(self.raw)
        path.chmod(0o600)

    def test_oob_and_url_only_detection(self):
        for body in ("", "caption", self.url):
            self.assertEqual(bridge.voice_url(self.cfg, FakeMessage(body, self.url)), self.url)
        self.assertEqual(bridge.voice_url(self.cfg, FakeMessage(self.url)), self.url)
        self.assertIsNone(bridge.voice_url(self.cfg, FakeMessage("See " + self.url)))
        self.assertIsNone(bridge.voice_url(self.cfg, FakeMessage("hello")))

    def test_plain_foreign_http_and_unconfigured_links_arrive_as_text_mail(self):
        root = self.tmp / "Mail"
        maildir = root / "consorts/fable"
        for leaf in ("tmp", "new", "cur"):
            (maildir / leaf).mkdir(parents=True)
        command = Path(__file__).resolve().parents[5] / "all/.local/bin/mailcortex"
        original = bridge.inbound_mail
        def run(argv, **kwargs):
            self.assertNotIn("--attach", argv)
            return subprocess.run([str(command), *argv[1:]],
                                  env=os.environ | {"MAILCORTEX_ROOT": str(root)}, **kwargs)
        def text_mail(cfg, sender, local, body):
            return original(cfg, sender, local, body, run)
        cases = ((self.cfg, "https://foreign.example.test/article"),
                 (self.cfg, self.url.replace("https:", "http:")),
                 (self.cfg | {"upload_base_url": ""}, self.url))
        for cfg, link in cases:
            with self.subTest(link=link, configured=bool(cfg["upload_base_url"])):
                msg = FakeMessage(link)
                before = set((maildir / "new").iterdir())
                with patch.object(bridge, "inbound_mail", side_effect=text_mail), \
                        patch.object(bridge, "inbound_voice", side_effect=AssertionError("plain link entered voice lane")):
                    asyncio.run(bridge.deliver_inbound(cfg, msg, "owner@example.test", "fable",
                                                      bridge.voice_url(cfg, msg)))
                delivered, = set((maildir / "new").iterdir()) - before
                message = BytesParser(policy=policy.default).parsebytes(delivered.read_bytes())
                self.assertFalse(message.is_multipart())
                self.assertTrue(str(message["Subject"]).startswith("[xmpp] "))
                self.assertEqual(message["To"], "fable@host.helm")
                body = message.get_content().replace("\r\n", "\n")
                self.assertIn("\n\n" + link + "\n", body)
                self.assertEqual(msg.replies, [])

    def test_oob_foreign_http_and_unconfigured_links_keep_refusal(self):
        cases = ((self.cfg, "https://foreign.example.test/file_share/slot/note.ogg"),
                 (self.cfg, self.url.replace("https:", "http:")),
                 (self.cfg | {"upload_base_url": ""}, self.url))
        for cfg, link in cases:
            msg = FakeMessage(self.url, link)
            with patch.object(bridge, "download_voice") as download, \
                    patch.object(bridge, "transcribe_voice", return_value="fixture words") as transcribe, \
                    patch.object(bridge, "mailcortex", return_value="fixture.msg") as mail:
                self.assertEqual(bridge.voice_url(cfg, msg), link)
                with self.assertLogs(bridge.LOG, level="ERROR"):
                    asyncio.run(bridge.deliver_inbound(cfg, msg, "owner@example.test", "fable",
                                                      bridge.voice_url(cfg, msg)))
                download.assert_not_called()
                transcribe.assert_not_called()
                mail.assert_not_called()
            self.assertEqual(len(msg.replies), 1)
            self.assertTrue(msg.replies[0].startswith("Voice note could not be transcribed: "))

    def test_foreign_host_refused_before_fetch_transcribe_or_mail(self):
        run = FakeRun()
        for url in ("https://evil.example.test/file_share/slot/note.ogg",
                    "https://uploads.example.test.evil.test/file_share/slot/note.ogg"):
            with self.assertRaisesRegex(bridge.BridgeError, "foreign upload host"):
                bridge.inbound_voice(self.cfg, "owner@example.test", "fable", url,
                                     run, self.download, lambda _: "hello")
        self.assertEqual(self.audio_paths, [])
        self.assertEqual(run.calls, [])

    def test_https_port_path_and_config_guards(self):
        for url in (self.url.replace("https:", "http:"),
                    self.url.replace("uploads.example.test", "uploads.example.test:444"),
                    self.url.replace("/file_share/", "/private/"),
                    self.url.replace("slot/", "../"),
                    self.url.replace("slot/", "%2e%2e/"),
                    self.url + "?token=fixture", self.url + "#fragment",
                    self.url.replace("https://", "https://user:password@")):
            with self.assertRaises(bridge.BridgeError):
                bridge.validate_upload_url(self.cfg, url)
        with self.assertRaisesRegex(bridge.BridgeError, "not configured"):
            bridge.validate_upload_url(self.cfg | {"upload_base_url": ""}, self.url)
        for base in ("http://uploads.example.test/file_share/", "https://uploads.example.test/",
                     "https://uploads.example.test/file_share", 42):
            path = self.tmp / "invalid.json"
            path.write_text(json.dumps(base_config(self.tmp) | {"upload_base_url": base}))
            with self.assertRaises(bridge.BridgeError):
                bridge.load_config(path)

    def test_download_stream_size_headers_permissions_and_failures(self):
        class Response(io.BytesIO):
            status = 200
            def __init__(self, payload, length=None):
                super().__init__(payload)
                self.headers = {} if length is None else {"Content-Length": str(length)}
        def opener(response):
            def open_(request, timeout):
                self.assertEqual(request.full_url, self.url)
                self.assertEqual(timeout, 5)
                return response
            return open_
        good = self.tmp / "good.ogg"
        bridge.download_voice(self.cfg, self.url, good, opener(Response(self.raw, len(self.raw))))
        self.assertEqual(good.read_bytes(), self.raw)
        self.assertEqual(good.stat().st_mode & 0o777, 0o600)
        for response in (Response(b"", bridge.VOICE_LIMIT + 1), Response(b""),
                         Response(b"a", 10), Response(b"a", "not-a-number")):
            with self.assertRaises(bridge.BridgeError):
                bridge.download_voice(self.cfg, self.url, self.tmp / "bad", opener(response))
            if (self.tmp / "bad").exists():
                (self.tmp / "bad").unlink()
        with patch.object(bridge, "VOICE_LIMIT", 4):
            with self.assertRaisesRegex(bridge.BridgeError, "exceeds"):
                bridge.download_voice(self.cfg, self.url, self.tmp / "stream-cap", opener(Response(b"abcde")))
        with patch.object(bridge.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaisesRegex(bridge.BridgeError, "timed out"):
                bridge.download_voice(self.cfg, self.url, self.tmp / "timeout", opener(Response(b"a")))
        with self.assertRaisesRegex(bridge.BridgeError, "redirects refused"):
            bridge.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example.test/")
        with patch.object(bridge.urllib.request, "build_opener") as build:
            build.return_value.open.side_effect = OSError("TLS failed")
            with self.assertRaisesRegex(bridge.BridgeError, "download failed"):
                bridge.download_voice(self.cfg, self.url, self.tmp / "tls-failure")
            self.assertEqual(build.call_args.args[0].proxies, {})
            self.assertIsInstance(build.call_args.args[1], bridge.NoRedirect)

    def test_transcriber_cli_quality_and_empty_refusals(self):
        audio = self.tmp / "voice.ogg"
        audio.write_bytes(self.raw)
        def runner(raw, status=0):
            def run(argv, **kwargs):
                self.assertEqual(argv[:2], [str(Path.home() / "HelmCortex/FORGE/bin/whisper-transcribe"), str(audio)])
                self.assertEqual(kwargs["timeout"], 600)
                Path(argv[argv.index("--out") + 1]).write_text(raw)
                return subprocess.CompletedProcess(argv, status, "", "")
            return run
        self.assertEqual(bridge.transcribe_voice(audio, runner("---\nwhisper_quality: clean\n---\n\nSpoken words.\n")), "Spoken words.")
        for raw, status in (("---\nwhisper_quality: clean\n---\n\n", 0),
                            ("---\nwhisper_quality: suspect\n---\nwords", 4),
                            ("---\nwhisper_quality: non-speech\n---\n[non-speech audio]", 0),
                            ("words without provenance", 0)):
            with self.assertRaises(bridge.BridgeError):
                bridge.transcribe_voice(audio, runner(raw, status))
        for error in (subprocess.TimeoutExpired("whisper", 600), FileNotFoundError("whisper")):
            with patch.object(bridge.subprocess, "run", side_effect=error) as run:
                with self.assertRaises(bridge.BridgeError):
                    bridge.transcribe_voice(audio, run)

    def test_voice_mail_real_mime_roundtrip_and_temp_cleanup(self):
        root = self.tmp / "Mail"
        maildir = root / "consorts/fable"
        for leaf in ("tmp", "new", "cur"):
            (maildir / leaf).mkdir(parents=True)
        command = Path(__file__).resolve().parents[5] / "all/.local/bin/mailcortex"
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(Path(argv[argv.index("--attach") + 1]).read_bytes(), self.raw)
            return subprocess.run([str(command), *argv[1:]], env=os.environ | {"MAILCORTEX_ROOT": str(root)}, **kwargs)
        name, transcript = bridge.inbound_voice(self.cfg, "owner@example.test/phone", "fable",
                                    self.url, run, self.download, lambda _: "Spoken words.")
        self.assertEqual(len(calls), 1)
        self.assertEqual(transcript, "Spoken words.")
        message = BytesParser(policy=policy.default).parsebytes((maildir / "new" / name).read_bytes())
        self.assertEqual(message["Subject"], "[xmpp voice] Spoken words.")
        self.assertEqual(message["To"], "fable@host.helm")
        self.assertEqual(message["From"], self.cfg["bridge_address"])
        body = message.get_body(preferencelist=("plain",)).get_content().replace("\r\n", "\n")
        self.assertIn("\n\nSpoken words.\n", body)
        self.assertIn("XMPP-From: owner@example.test", message.get_body().get_content())
        part, = message.iter_attachments()
        self.assertEqual(part.get_filename(), "voice-note.ogg")
        self.assertEqual(part.get_payload(decode=True), self.raw)
        self.assertFalse(self.audio_paths[0].parent.exists())
        self.assertEqual(list((maildir / "tmp").iterdir()), [])

    def test_empty_and_failed_transcription_cleanup_without_mail(self):
        run = FakeRun()
        for transcriber in (lambda _: "", lambda _: (_ for _ in ()).throw(bridge.BridgeError("whisper failed"))):
            with self.assertRaises(bridge.BridgeError):
                bridge.inbound_voice(self.cfg, "owner@example.test", "fable", self.url,
                                     run, self.download, transcriber)
            self.assertFalse(self.audio_paths[-1].parent.exists())
        self.assertEqual(run.calls, [])
        def failed_download(cfg, url, path):
            self.download(cfg, url, path)
            raise bridge.BridgeError("fetch failed after partial write")
        with self.assertRaises(bridge.BridgeError):
            bridge.inbound_voice(self.cfg, "owner@example.test", "fable", self.url,
                                 run, failed_download, lambda _: "should not run")
        self.assertFalse(self.audio_paths[-1].parent.exists())
        self.assertEqual(run.calls, [])

    def test_failure_replies_once_and_worker_leaves_loop_responsive(self):
        msg = FakeMessage(self.url)
        async def failure():
            with patch.object(bridge, "inbound_voice", side_effect=bridge.BridgeError("whisper failed\nretry")):
                with self.assertLogs(bridge.LOG, level="ERROR"):
                    await bridge.deliver_inbound(self.cfg, msg, "owner@example.test", "fable", self.url)
        asyncio.run(failure())
        self.assertEqual(msg.replies, ["Voice note could not be transcribed: whisper failed retry"])
        started, release = threading.Event(), threading.Event()
        def slow(*args):
            started.set()
            if not release.wait(2):
                raise bridge.BridgeError("test worker was not released")
            return "delivered.msg", "fixture transcript"
        async def responsive():
            with patch.object(bridge, "inbound_voice", side_effect=slow):
                job = asyncio.create_task(bridge.deliver_inbound(self.cfg, FakeMessage(self.url),
                                          "owner@example.test", "fable", self.url))
                try:
                    for _ in range(100):
                        if started.is_set():
                            break
                        await asyncio.sleep(0.005)
                    self.assertTrue(started.is_set())
                    self.assertFalse(job.done())
                finally:
                    release.set()
                    await job
        asyncio.run(responsive())


class FakeMessage:
    def __init__(self, body, oob=None, sender="owner@example.test/phone", local="fable", mid="fixture-id"):
        self.xml = ET.Element("message")
        if oob:
            ET.SubElement(ET.SubElement(self.xml, "{jabber:x:oob}x"), "{jabber:x:oob}url").text = oob
        self.values = {"body": body, "type": "chat", "from": sender,
                       "to": types.SimpleNamespace(user=local), "id": mid}
        self.replies = []
    def __getitem__(self, key):
        return self.values[key]
    def reply(self, text):
        self.replies.append(text)
        return self
    def chat(self):
        self.values["type"] = "chat"
        return self
    def send(self):
        pass


class ComponentVoiceTests(unittest.TestCase):
    setUp = VoiceTests.setUp

    def test_adhoc_commands_are_fixed_and_mutations_need_confirmation(self):
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        asyncio.set_event_loop(loop)
        self.addCleanup(asyncio.set_event_loop, None)
        instances = []
        class ComponentBase:
            def __init__(self, *args):
                self.disconnected = loop.create_future()
                self.handlers = {}
                instances.append(self)
            def register_plugin(self, name):
                pass
            def add_event_handler(self, name, handler):
                self.handlers[name] = handler
            def connect(self):
                self.disconnected.set_result(None)
        cfg = self.cfg | {"bots": {"fable": "FixtureBot"}}
        with patch.dict("sys.modules", {"slixmpp": types.SimpleNamespace(ComponentXMPP=ComponentBase)}), \
                patch.object(bridge, "state_root", return_value=self.tmp / "state"):
            self.assertEqual(bridge.run_bridge(cfg), 1)
        component, = instances
        with patch.object(bridge.shutil, "which", return_value="/bin/claude-warmctl"):
            self.assertEqual(component.command_names("fable"),
                             ["status", "seats", "revive", "compact"])
            self.assertEqual(component.command_names("worker"), ["status", "seats"])
            with patch.object(bridge.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, "queued", "")) as run:
                ok, result = component.execute_command("owner@example.test", "fable", "compact")
            self.assertTrue(ok)
            self.assertEqual(run.call_args.args[0], ["claude-warmctl", "inject", "FixtureBot", "/compact"])
            self.assertEqual(result, "queued")
        class Iq:
            def __init__(self, sender):
                self.values = {"from": sender}
            def __getitem__(self, key):
                return self.values[key]
        session = {"payload": [], "next": None}
        loop.run_until_complete(component.begin_command(Iq("owner@example.test"), session,
                                                        "fable", "revive"))
        self.assertTrue(session["has_next"])
        with self.assertRaises(Exception):
            loop.run_until_complete(component.begin_command(Iq("evil@example.test"), {},
                                                            "fable", "revive"))
        with patch.object(bridge.subprocess, "run", side_effect=AssertionError("not confirmed")):
            loop.run_until_complete(component.finish_command(session["payload"][0], session))
        self.assertFalse(session["has_next"])

    # Exercise the registered production handler, not only helper calls.
    def test_production_handler_bodyless_owner_dedupe_unknown_and_capacity(self):
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        asyncio.set_event_loop(loop)
        self.addCleanup(asyncio.set_event_loop, None)
        instances = []
        class ComponentBase:
            def __init__(self, *args):
                self.disconnected = loop.create_future()
                self.handlers = {}
                instances.append(self)
            def register_plugin(self, name):
                pass
            def add_event_handler(self, name, handler):
                self.handlers[name] = handler
            def send_message(self, **kwargs):
                self.sent_messages = getattr(self, "sent_messages", [])
                self.sent_messages.append(kwargs)
            def connect(self):
                self.disconnected.set_result(None)
        permission = self.tmp / "permission.secret"
        permission.write_text("p" * 32)
        permission.chmod(0o600)
        self.cfg["permission_secrets"] = {"fable": permission}
        with patch.dict("sys.modules", {"slixmpp": types.SimpleNamespace(ComponentXMPP=ComponentBase)}), \
                patch.object(bridge, "state_root", return_value=self.tmp / "state"):
            self.assertEqual(bridge.run_bridge(self.cfg), 1)
        component, = instances
        async def exercise():
            with patch.object(bridge, "inbound_voice", return_value=("voice.msg", "heard words")) as worker, \
                    patch.object(bridge, "transcribe_permission_voice", return_value=""):
                owner = FakeMessage("", self.url)
                await component.handlers["message"](owner)
                worker.assert_called_once_with(self.cfg, "owner@example.test", "fable", self.url)
                await component.handlers["message"](owner)
                self.assertEqual(worker.call_count, 1)
                await component.handlers["message"](FakeMessage("", self.url, sender="evil@example.test"))
                self.assertEqual(worker.call_count, 1)
                ghost = FakeMessage("", self.url, local="ghost")
                await component.handlers["message"](ghost)
                self.assertEqual(ghost.replies, ["No such seat."])
                component.voice_jobs = bridge.VOICE_JOBS
                full = FakeMessage("", self.url, mid="new-id")
                await component.handlers["message"](full)
                self.assertEqual(worker.call_count, 1)
                self.assertIn("capacity reached", full.replies[0])
                # Plain links stay deliverable even when voice workers are full.
                with patch.object(bridge, "inbound_mail", return_value="text.msg") as text:
                    for index, link in enumerate(("https://foreign.example.test/article",
                                                  self.url.replace("https:", "http:"))):
                        plain = FakeMessage(link, mid=f"plain-{index}")
                        await component.handlers["message"](plain)
                        text.assert_called_with(self.cfg, "owner@example.test", "fable", link)
                        self.assertEqual(plain.replies, [])
                    self.cfg["upload_base_url"] = ""
                    unconfigured = FakeMessage(self.url, mid="plain-unconfigured")
                    await component.handlers["message"](unconfigured)
                    text.assert_called_with(self.cfg, "owner@example.test", "fable", self.url)
                    self.assertEqual(unconfigured.replies, [])
                    self.assertEqual(text.call_count, 3)
                self.assertEqual(worker.call_count, 1)
                unknown = FakeMessage("yes abcde", mid="permission-unknown")
                await component.handlers["message"](unknown)
                self.assertEqual(component.sent_messages[-1]["mbody"],
                                 "Unknown permission request abcde.")
                component.answered_permissions.add(("fable", "bcdef"))
                replay = FakeMessage("yes bcdef", mid="permission-replay")
                await component.handlers["message"](replay)
                self.assertEqual(component.sent_messages[-1]["mbody"],
                                 "Permission request bcdef was already answered.")
        loop.run_until_complete(exercise())
        rendered = "From: fable@host.helm\nSubject: Re: [xmpp] hi\nMessage-ID: <fixture>\n\n**reply**"
        with patch.object(bridge, "pending_outbound", return_value=["reply.msg"]), \
                patch.object(bridge, "mailcortex", return_value=rendered) as mail, \
                patch.object(bridge, "relay_reply") as relay:
            loop.run_until_complete(component.relay_outbound())
        relay.assert_awaited_once_with(component, self.cfg, "fable", "**reply**")
        self.assertEqual(mail.call_args_list[-1].args[0],
                         ["receipt", self.cfg["bridge_seat"], "<fixture>", "handling_completed"])


class StylingTests(unittest.TestCase):
    def test_table_and_adversarial_code(self):
        cases = (
            ("**bold** __b__ *italic* _i_ ~~gone~~", "*bold* *b* _italic_ _i_ ~gone~"),
            ("# Heading\n## **Bold** and *italic*\n", "*Heading*\n*Bold and _italic_*\n"),
            ("[site](https://example.test/a)\n- one\n+ two\n* three", "site (https://example.test/a)\n• one\n• two\n• three"),
            ("**use `**literal** *x*`**", "*use `**literal** *x*`*"),
            ("``a ` **bold** ~~x~~`` and **yes**", "``a ` **bold** ~~x~~`` and *yes*"),
            ("```md\n# literal\n**b** *i* [x](url)\n```\n**yes**", "```md\n# literal\n**b** *i* [x](url)\n```\n*yes*"),
            ("~~~~\n~~strike~~\n~~~\n**still code**\n~~~~\n*x*", "~~~~\n~~strike~~\n~~~\n**still code**\n~~~~\n_x_"),
            ("    **indented code**\n\t*x*\n**prose**", "    **indented code**\n\t*x*\n*prose*"),
            ("`unclosed **code**", "`unclosed **code**"),
            ("before `multi\n**literal**\nend`\n**yes**", "before `multi\n**literal**\nend`\n*yes*"),
            ("[x](https://example.test/**raw**) ![alt](url)", "x (https://example.test/**raw**) ![alt](url)"),
            ("```\n**unclosed fence**", "```\n**unclosed fence**"),
            (r"\*literal* \**literal**", r"\*literal* \**literal**"),
            ("foo_bar_baz foo**bar**baz ***ambiguous***", "foo_bar_baz foo**bar**baz ***ambiguous***"),
            ("[nested](https://example.test/a(b)) - [x] task", "[nested](https://example.test/a(b)) - [x] task"),
            ("- [ ] checkbox\n---\n** spaced **\n", "- [ ] checkbox\n---\n** spaced **\n"),
            ("# Header ###\r\n**b**\r\n", "*Header*\r\n*b*\r\n"),
            ("\x000\x00 **literal**", "\x000\x00 **literal**"),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(bridge.markdown_to_styling(raw), expected)


class ReplyVoiceTests(unittest.TestCase):
    setUp = VoiceTests.setUp
    download = VoiceTests.download

    def slot(self, put=None, get=None, header="Authorization", value="Bearer fixture"):
        iq = ET.Element("iq")
        slot = ET.SubElement(iq, "{" + bridge.UPLOAD_NS + "}slot")
        upload = ET.SubElement(slot, "{" + bridge.UPLOAD_NS + "}put", {"url": put or self.url})
        ET.SubElement(upload, "{" + bridge.UPLOAD_NS + "}header", {"name": header}).text = value
        ET.SubElement(slot, "{" + bridge.UPLOAD_NS + "}get", {"url": get or self.url})
        return types.SimpleNamespace(xml=iq)

    def component(self, slot_error=None):
        fixture = self
        class Component:
            def __init__(self):
                self.messages, self.slots = [], []
            def send_message(self, **kwargs):
                self.messages.append(types.SimpleNamespace(xml=ET.Element("message"), values=kwargs))
            def make_message(self, **kwargs):
                message = types.SimpleNamespace(xml=ET.Element("message"), values=kwargs)
                message.send = lambda: self.messages.append(message)
                return message
            def __getitem__(self, key):
                fixture.assertEqual(key, "xep_0363")
                return self
            async def request_slot(self, *args, **kwargs):
                self.slots.append((args, kwargs))
                if slot_error:
                    raise slot_error
                return fixture.slot()
        return Component()

    def voiced_config(self):
        return self.cfg | {"voices": {"fable": "FixtureAgent"}, "upload_service_jid": "example.test"}

    def test_config_optional_map_and_required_host(self):
        self.assertEqual(self.cfg["voices"], {})
        valid = base_config(self.tmp) | {
            "upload_base_url": self.cfg["upload_base_url"],
            "voices": {"fable": "FixtureAgent"}, "upload_service_jid": "example.test"}
        path = self.tmp / "voices.json"
        path.write_text(json.dumps(valid))
        self.assertEqual(bridge.load_config(path)["voices"], valid["voices"])
        for change in ({"voices": []}, {"voices": {"ghost": "FixtureAgent"}},
                       {"voices": {"fable": "--rule"}}, {"voices": {"fable": ""}},
                       {"voices": {"fable": 5}}, {"upload_service_jid": ""},
                       {"upload_service_jid": self.cfg["component_jid"]},
                       {"upload_service_jid": "user@example.test"}, {"upload_base_url": ""}):
            with self.subTest(change=change):
                path.write_text(json.dumps(valid | change))
                with self.assertRaises(bridge.BridgeError):
                    bridge.load_config(path)

    def test_display_names_map_owners_only(self):
        self.assertEqual(self.cfg["display_names"], {})
        path = self.tmp / "names.json"
        valid = base_config(self.tmp) | {"display_names": {"owner@example.test": "Metsatron"}}
        path.write_text(json.dumps(valid))
        self.assertEqual(bridge.load_config(path)["display_names"], {"owner@example.test": "Metsatron"})
        for names in ([], {"stranger@example.test": "X"}, {"owner@example.test": ""},
                      {"owner@example.test": "two\nlines"}, {"owner@example.test": " pad"},
                      {"owner@example.test": 5}):
            with self.subTest(names=names):
                path.write_text(json.dumps(valid | {"display_names": names}))
                with self.assertRaises(bridge.BridgeError):
                    bridge.load_config(path)

    def test_echo_only_after_delivery_and_preserves_every_line(self):
        msg = FakeMessage(self.url)
        def mail(args, run):
            self.assertEqual(msg.replies, [])
            return "delivered.msg"
        with patch.object(bridge, "download_voice", side_effect=self.download), \
                patch.object(bridge, "transcribe_voice", return_value="one\n\n**two**"), \
                patch.object(bridge, "mailcortex", side_effect=mail):
            asyncio.run(bridge.deliver_inbound(self.cfg, msg, "owner@example.test", "fable", self.url))
        self.assertEqual(msg.replies, ['> Re: owner\n> "one\n> \n> **two**"'])
        msg = FakeMessage(self.url)
        cfg = dict(self.cfg, display_names={"owner@example.test": "Metsatron"})
        with patch.object(bridge, "download_voice", side_effect=self.download), \
                patch.object(bridge, "transcribe_voice", return_value="hello"), \
                patch.object(bridge, "mailcortex", return_value="delivered.msg"):
            asyncio.run(bridge.deliver_inbound(cfg, msg, "owner@example.test/phone", "fable", self.url))
        self.assertEqual(msg.replies, ['> Re: Metsatron\n> "hello"'])
        for failure in ("transcribe", "mail"):
            msg = FakeMessage(self.url)
            with patch.object(bridge, "download_voice", side_effect=self.download), \
                    patch.object(bridge, "transcribe_voice", return_value="one") as transcribe, \
                    patch.object(bridge, "mailcortex", return_value="delivered.msg") as mail:
                (transcribe if failure == "transcribe" else mail).side_effect = bridge.BridgeError(failure + " failed")
                with self.assertLogs(bridge.LOG, level="ERROR"):
                    asyncio.run(bridge.deliver_inbound(self.cfg, msg, "owner@example.test", "fable", self.url))
            self.assertEqual(len(msg.replies), 1)
            self.assertFalse(msg.replies[0].startswith("> "))

    def test_text_only_without_mapping_never_renders_or_requests_slot(self):
        for cfg in (self.cfg, self.voiced_config() | {"voices": {"worker": "OtherAgent"}}):
            component = self.component()
            with patch.object(bridge, "render_voice", side_effect=AssertionError("unmapped seat rendered")):
                asyncio.run(bridge.relay_reply(component, cfg, "fable", "**reply**"))
            self.assertEqual([m.values["mbody"] for m in component.messages], ["*reply*"])
            self.assertEqual(component.slots, [])

    def test_voice_end_to_end_stubs_shape_order_and_cleanup(self):
        component, cfg, calls, directories = self.component(), self.voiced_config(), [], []
        main_thread = threading.get_ident()
        def run(argv, **kwargs):
            self.assertNotEqual(threading.get_ident(), main_thread)
            self.assertEqual([m.values["mbody"] for m in component.messages], ["*reply*"])
            calls.append((argv, kwargs))
            Path(argv[-1]).write_bytes(b"OggS fixture" if argv[0] == "ffmpeg" else b"RIFF fixture")
            directories.append(Path(argv[-1]).parent)
            if argv[0] != "ffmpeg":
                self.assertEqual(Path(argv[-2]).read_text(), "reply")
            return subprocess.CompletedProcess(argv, 0, "", "")
        def put(cfg_, url, audio, headers):
            self.assertNotEqual(threading.get_ident(), main_thread)
            self.assertEqual(audio.read_bytes(), b"OggS fixture")
            self.assertEqual(headers, {"authorization": "Bearer fixture"})
            self.assertEqual(url, self.url)
        render = bridge.render_voice
        with patch.object(bridge, "render_voice", side_effect=lambda *args: render(*args, run=run)), \
                patch.object(bridge, "put_voice", side_effect=put):
            asyncio.run(bridge.relay_reply(component, cfg, "fable", "**reply**"))
        self.assertEqual(calls[0][0][1:5], ["render", "--agent", "FixtureAgent", "--no-play"])
        self.assertEqual(calls[0][1]["timeout"], bridge.RENDER_SECONDS)
        self.assertIn("-nostdin", calls[1][0])
        for option, value in (("-ac", "1"), ("-c:a", "libopus"), ("-b:a", "24k"), ("-application", "voip")):
            self.assertEqual(calls[1][0][calls[1][0].index(option) + 1], value)
        self.assertEqual(component.slots, [(("example.test", "reply.ogg", 12, "audio/ogg"),
                                          {"ifrom": "fable@seats.example.test", "timeout": 30})])
        text, voice = component.messages
        self.assertEqual(voice.values["mbody"], self.url)
        self.assertEqual(voice.values["mfrom"], "fable@seats.example.test")
        self.assertEqual(voice.values["mto"], "owner@example.test")
        self.assertEqual(voice.xml.find("{jabber:x:oob}x/{jabber:x:oob}url").text, self.url)
        self.assertTrue(all(not path.exists() for path in directories))

    def test_render_cap_timeout_empty_encode_and_stderr(self):
        paths = []
        def run(argv, **kwargs):
            paths.append(Path(argv[-1]))
            if argv[0] != "ffmpeg":
                self.assertEqual(len(Path(argv[-2]).read_text()), bridge.VOICE_TEXT_LIMIT)
                self.assertEqual(Path(argv[-2]).stat().st_mode & 0o777, 0o600)
            Path(argv[-1]).write_bytes(b"fixture")
            return subprocess.CompletedProcess(argv, 0, "", "")
        with self.assertLogs(bridge.LOG, level="INFO") as logs:
            audio = bridge.render_voice("x" * (bridge.VOICE_TEXT_LIMIT + 1), "FixtureAgent", self.tmp, run)
        self.assertIn("truncated", " ".join(logs.output))
        self.assertEqual(audio.stat().st_mode & 0o777, 0o600)
        for result in (subprocess.CompletedProcess([], 2, "", "encoder refused\n"),
                       subprocess.CompletedProcess([], 9, "", "")):
            def fail(argv, **kwargs):
                return result
            with self.assertRaisesRegex(bridge.BridgeError, "encoder refused|exit status 9"):
                bridge.render_voice("reply", "FixtureAgent", self.tmp, fail)
        def encode_fail(argv, **kwargs):
            Path(argv[-1]).write_bytes(b"fixture")
            return subprocess.CompletedProcess(argv, 3 if argv[0] == "ffmpeg" else 0, "", "encode refused")
        with self.assertRaisesRegex(bridge.BridgeError, "encode failed: encode refused"):
            bridge.render_voice("reply", "FixtureAgent", self.tmp, encode_fail)
        for error in (subprocess.TimeoutExpired("pvox", 600), FileNotFoundError("pvox")):
            with self.assertRaises(bridge.BridgeError):
                bridge.render_voice("reply", "FixtureAgent", self.tmp, lambda *a, **k: (_ for _ in ()).throw(error))
        with tempfile.TemporaryDirectory() as empty:
            with self.assertRaisesRegex(bridge.BridgeError, "produced no audio"):
                bridge.render_voice("reply", "FixtureAgent", Path(empty), lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""))

    def test_failures_keep_text_reply_once_and_hide_capabilities(self):
        audio = self.tmp / "reply.ogg"
        audio.write_bytes(b"fixture")
        for stage in ("render", "encode", "slot", "put"):
            component = self.component(BridgeSlotFailure() if stage == "slot" else None)
            error = bridge.BridgeError(stage + " failed " + self.url + " Bearer private-token")
            with patch.object(bridge, "render_voice", return_value=audio) as render, \
                    patch.object(bridge, "put_voice") as put:
                if stage in {"render", "encode"}:
                    render.side_effect = error
                if stage == "put":
                    put.side_effect = error
                with self.assertLogs(bridge.LOG, level="ERROR") as logs:
                    asyncio.run(bridge.relay_reply(component, self.voiced_config(), "fable", "**reply**"))
            self.assertEqual(len(component.messages), 2)
            self.assertEqual(component.messages[0].values["mbody"], "*reply*")
            self.assertTrue(component.messages[1].values["mbody"].startswith("Voice reply failed: "))
            output = " ".join(logs.output) + component.messages[1].values["mbody"]
            self.assertNotIn(self.url, output)
            self.assertNotIn("private-token", output)
            if stage == "slot":
                self.assertIn("forbidden", output)

    def test_slot_allowlist_headers_and_worker_put(self):
        for iq in (self.slot(put="https://evil.example.test/file_share/x"),
                   self.slot(get="https://evil.example.test/file_share/x"),
                   self.slot(header="Host"), self.slot(value="Bearer fixture\r\ninjected"),
                   types.SimpleNamespace(xml=ET.Element("iq"))):
            with self.assertRaises(bridge.BridgeError):
                bridge.parse_slot(self.cfg, iq)
        audio = self.tmp / "put.ogg"
        audio.write_bytes(b"OggS fixture")
        class Response(io.BytesIO):
            status = 201
        def opener(request, timeout):
            self.assertEqual(request.method, "PUT")
            self.assertEqual(request.full_url, self.url)
            self.assertEqual(request.data, audio.read_bytes())
            self.assertEqual(request.get_header("Content-type"), "audio/ogg")
            self.assertEqual(request.get_header("Content-length"), str(len(request.data)))
            self.assertEqual(request.get_header("Authorization"), "Bearer fixture")
            self.assertEqual(timeout, 30)
            return Response()
        bridge.put_voice(self.cfg, self.url, audio, {"authorization": "Bearer fixture"}, opener)
        with patch.object(bridge.urllib.request, "build_opener") as build:
            build.return_value.open.side_effect = OSError(self.url)
            with self.assertRaisesRegex(bridge.BridgeError, "network or TLS"):
                bridge.put_voice(self.cfg, self.url, audio, {})
            self.assertEqual(build.call_args.args[0].proxies, {})
            self.assertIsInstance(build.call_args.args[1], bridge.NoRedirect)

    def test_workers_leave_loop_responsive_and_cancel_before_cleanup(self):
        started, release = threading.Event(), threading.Event()
        directories = []
        def render(text, agent, directory):
            directories.append(directory)
            started.set()
            if not release.wait(2):
                raise bridge.BridgeError("fixture worker not released")
            self.assertTrue(directory.exists())
            audio = directory / "reply.ogg"
            audio.write_bytes(b"fixture")
            return audio
        async def exercise():
            component = self.component()
            with patch.object(bridge, "render_voice", side_effect=render), patch.object(bridge, "put_voice"):
                job = asyncio.create_task(bridge.relay_reply(component, self.voiced_config(), "fable", "reply"))
                try:
                    for _ in range(100):
                        if started.is_set():
                            break
                        await asyncio.sleep(0.005)
                    self.assertTrue(started.is_set())
                    self.assertFalse(job.done())
                    job.cancel()
                    await asyncio.sleep(0.005)
                    job.cancel()
                    await asyncio.sleep(0.005)
                    self.assertTrue(directories[0].exists())
                finally:
                    release.set()
                    with self.assertRaises(asyncio.CancelledError):
                        await job
            self.assertFalse(directories[0].exists())
            self.assertEqual(len(component.messages), 1)
        asyncio.run(exercise())

    def test_mailcortex_stderr_and_empty_fallback(self):
        for stderr, expected in ((" failure details\n", "failure details"), (" \n", "exit status 7 (no stderr)")):
            result = subprocess.CompletedProcess([], 7, "must not leak stdout", stderr)
            with self.assertRaises(bridge.BridgeError) as error:
                bridge.mailcortex(["inbox", "fixture"], lambda *a, **k: result)
            self.assertIn(expected, str(error.exception))
            self.assertNotIn("must not leak", str(error.exception))


class BridgeSlotFailure(Exception):
    condition = "forbidden"


class GateTests(unittest.TestCase):
    def test_stranger_refused(self):
        gate = bridge.Gate(["owner@example.test"], 3)
        self.assertEqual(gate.admit("evil@example.test/x", 0), "unauthorized")

    def test_resource_stripped_and_rate_limited(self):
        gate = bridge.Gate(["owner@example.test"], 2)
        self.assertIsNone(gate.admit("Owner@example.test/phone", 0))
        self.assertIsNone(gate.admit("owner@example.test/laptop", 1))
        self.assertEqual(gate.admit("owner@example.test", 2), "rate_limited")
        self.assertIsNone(gate.admit("owner@example.test", 61))


class SeenTests(unittest.TestCase):
    def test_dedupe_persists_across_instances(self):
        path = Path(tempfile.mkdtemp()) / "seen.json"
        self.assertTrue(bridge.Seen(path).check_and_add("k1"))
        again = bridge.Seen(path)
        self.assertFalse(again.check_and_add("k1"))
        self.assertTrue(again.check_and_add(None))


class RoutingTests(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        path = tmp / "bridge.json"
        path.write_text(json.dumps(base_config(tmp)))
        self.cfg = bridge.load_config(path)

    def test_inbound_sends_from_bridge_to_seat(self):
        run = FakeRun({"send": "123.msg\n"})
        name = bridge.inbound_mail(self.cfg, "owner@example.test/phone", "fable", "Hello there\nsecond line", run)
        self.assertEqual(name, "123.msg")
        argv = run.calls[0]
        self.assertEqual(argv[:6], ["mailcortex", "send", "--from", "seat+xmpp-bridge@host.helm", "--to", "fable@host.helm"])
        self.assertEqual(argv[argv.index("--subject") + 1], "[xmpp] Hello there")
        body = argv[argv.index("--body") + 1]
        self.assertIn("XMPP-From: owner@example.test\n", body)
        self.assertIn("--to seat+xmpp-bridge@host.helm", body)

    def test_inbound_unknown_seat_sends_nothing(self):
        run = FakeRun()
        with self.assertRaises(bridge.BridgeError):
            bridge.inbound_mail(self.cfg, "owner@example.test", "ghost", "hi", run)
        self.assertEqual(run.calls, [])

    def test_pending_only_new(self):
        run = FakeRun({"inbox": "cur\told\td\tf\ts\nnew\tfresh\td\tf\ts\n"})
        self.assertEqual(bridge.pending_outbound(self.cfg, run), ["fresh"])

    def test_outbound_maps_sender_and_keeps_subject(self):
        rendered = ("Date: x\nFrom: fable@host.helm\nTo: seat+xmpp-bridge@host.helm\n"
                    "Subject: Build finished\nMessage-ID: <1@host.helm>\n\nAll green.\n")
        local, text, mid = bridge.render_outbound(self.cfg, rendered)
        self.assertEqual((local, mid), ("fable", "<1@host.helm>"))
        self.assertEqual(text, "Build finished\n\nAll green.")

    def test_outbound_reply_subject_dropped(self):
        rendered = ("From: seat+worker@host.helm\nSubject: Re: [xmpp] Hello\n"
                    "Message-ID: <2@host.helm>\n\nDone.\n")
        self.assertEqual(bridge.render_outbound(self.cfg, rendered)[:2], ("worker", "Done."))

    def test_outbound_sender_from_another_machine_maps(self):
        rendered = ("From: seat+worker@other-node.helm\nSubject: Re: [xmpp] Hey\n"
                    "Message-ID: <4@other-node.helm>\n\nOn it.\n")
        self.assertEqual(bridge.render_outbound(self.cfg, rendered)[:2], ("worker", "On it."))

    def test_outbound_unmapped_sender(self):
        rendered = "From: stranger@host.helm\nSubject: x\nMessage-ID: <3@host.helm>\n\nhi\n"
        self.assertIsNone(bridge.render_outbound(self.cfg, rendered)[0])


class RoomTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        data = base_config(self.tmp) | {
            "upload_base_url": "https://uploads.example.test/file_share/",
            "upload_service_jid": "example.test",
            "voices": {"fable": "Fable"},
            "rooms": {
                "comms": {
                    "jid": "comms@rooms.example.test",
                    "lead": "fable",
                    "seats": ["fable", "worker"],
                }
            },
            "nicks": {"worker": "Orca"},
        }
        path = self.tmp / "rooms.json"
        path.write_text(json.dumps(data))
        self.cfg = bridge.load_config(path)
        self.room = self.cfg["rooms"]["comms"]

    def test_room_config_defaults_and_validation(self):
        self.assertEqual(self.room["nicks"], {"fable": "Fable", "worker": "Orca"})
        self.assertEqual(self.cfg["room_by_jid"][self.room["jid"]], self.room)
        cases = []
        cases.append({"rooms": {"comms": {"jid": "comms@rooms.example.test/occupant",
                                             "lead": "fable", "seats": ["fable"]}}})
        cases.append({"rooms": {"comms": {"jid": "comms@rooms.example.test",
                                             "lead": "ghost", "seats": ["fable"]}}})
        cases.append({"rooms": {"comms": {"jid": "comms@rooms.example.test",
                                             "lead": "fable", "seats": ["ghost"]}}})
        cases.append({"nicks": {"fable": "Same", "worker": "same"}, "rooms": {
            "comms": {"jid": "comms@rooms.example.test", "lead": "fable",
                      "seats": ["fable", "worker"]}
        }})
        cases.append({"rooms": {
            "comms": {"jid": "comms@rooms.example.test", "lead": "fable", "seats": ["fable"]},
            "ops": {"jid": "ops@other.example.test", "lead": "fable", "seats": ["fable"]},
        }})
        for change in cases:
            with self.subTest(change=change):
                data = json.loads(json.dumps(base_config(self.tmp)))
                data.update(change)
                path = self.tmp / "invalid-room.json"
                path.write_text(json.dumps(data))
                with self.assertRaises(bridge.BridgeError):
                    bridge.load_config(path)

    def test_room_addressing_and_prefix_stripping(self):
        cases = (
            ("Fable: hello", ["fable"], "hello", None),
            ("@Fable @Orca hello", ["fable", "worker"], "hello", None),
            ("@all hello", ["fable", "worker"], "hello", None),
            ("plain line", ["fable"], "plain line", None),
            ("Unknown: hello", [], "Unknown: hello", "Unknown"),
        )
        for raw, seats, body, unknown in cases:
            with self.subTest(raw=raw):
                self.assertEqual(bridge.address_room(self.room, raw), (seats, body, unknown))

    def test_room_mail_has_room_header_subject_and_id_capture(self):
        run = FakeRun({"send": "room.msg\t<room@example.test>\n"})
        name, message_id = bridge.inbound_mail(
            self.cfg, "owner@example.test/phone", "fable", "briefing",
            run, capture_id=True, room=self.room)
        self.assertEqual((name, message_id), ("room.msg", "<room@example.test>"))
        argv = run.calls[0]
        self.assertEqual(argv[argv.index("--subject") + 1], "[xmpp #comms] briefing")
        self.assertIn("XMPP-Room: comms@rooms.example.test\n", argv[argv.index("--body") + 1])
        self.assertIn("--print-id", argv)

    def test_room_map_is_capped_and_private(self):
        path = self.tmp / "state" / "room-map.json"
        mapping = bridge.RoomMap(path)
        for index in range(bridge.SEEN_CAP + 1):
            mapping.add(f"<{index}@example.test>", self.room["jid"])
        self.assertIsNone(mapping.get("<0@example.test>"))
        self.assertEqual(mapping.get(f"<{bridge.SEEN_CAP}@example.test>"), self.room["jid"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_room_reply_is_groupchat_only_and_unjoined_falls_back(self):
        class Component:
            def __init__(self):
                self.messages = []
            def send_message(self, **kwargs):
                self.messages.append(kwargs)
        cfg = dict(self.cfg, voices={})
        component = Component()
        asyncio.run(bridge.relay_reply(component, cfg, "fable", "**reply**",
                                        self.room, {(self.room["jid"], "fable")}))
        self.assertEqual(len(component.messages), 1)
        self.assertEqual(component.messages[0]["mtype"], "groupchat")
        self.assertEqual(component.messages[0]["mto"], self.room["jid"])
        component.messages.clear()
        asyncio.run(bridge.relay_reply(component, cfg, "fable", "reply", self.room, set()))
        self.assertEqual([message["mtype"] for message in component.messages], ["chat"])
        self.assertIn("not posted", component.messages[0]["mbody"])

    def test_history_and_origin_identifiers_are_recognized(self):
        message = FakeMessage("hello", mid="stanza")
        ET.SubElement(message.xml, "{urn:xmpp:delay}delay")
        ET.SubElement(message.xml, "{urn:xmpp:sid:0}origin-id", {"id": "origin"})
        self.assertTrue(bridge.has_xml_element(message, "delay"))
        self.assertEqual(bridge.stanza_key(message, "room|"), "room|origin-id:origin")

    def test_room_authentication_drops_spoof_history_duplicate_and_nonowner(self):
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        asyncio.set_event_loop(loop)
        self.addCleanup(asyncio.set_event_loop, None)
        instances = []
        sent_presences = []
        class Presence:
            def __init__(self, pto, pfrom):
                self.xml = ET.Element("presence")
                self.pto, self.pfrom, self.sent = pto, pfrom, False
            def send(self):
                self.sent = True
                sent_presences.append(self)
        class ComponentBase:
            def __init__(self, *args):
                self.disconnected = loop.create_future()
                self.handlers = {}
                self.messages = []
                instances.append(self)
            def register_plugin(self, name):
                pass
            def add_event_handler(self, name, handler):
                self.handlers[name] = handler
            def connect(self):
                self.disconnected.set_result(None)
            def make_presence(self, pto=None, pfrom=None):
                return Presence(pto, pfrom)
            def send_message(self, **kwargs):
                self.messages.append(kwargs)
        cfg = dict(self.cfg, voices={})
        with patch.dict("sys.modules", {"slixmpp": types.SimpleNamespace(ComponentXMPP=ComponentBase)}), \
                patch.object(bridge, "state_root", return_value=self.tmp / "state"):
            bridge.run_bridge(cfg)
        component, = instances
        component.join_room(self.room, "fable")
        component.join_room(self.room, "worker")
        self.assertEqual(sent_presences[0].pto, "comms@rooms.example.test/Fable")
        self.assertEqual(sent_presences[0].pfrom, "fable@seats.example.test")
        history = sent_presences[0].xml.find("{" + bridge.MUC_NS + "}x/{" + bridge.MUC_NS + "}history")
        self.assertEqual(history.get("maxstanzas"), "0")
        class RoomPresence:
            def __init__(self, room_jid, nick, real):
                self.values = {"from": room_jid + "/" + nick, "type": "available"}
                self.xml = ET.Element("presence")
                item = ET.SubElement(self.xml, "{" + bridge.MUC_USER_NS + "}item")
                item.set("jid", real)
            def __getitem__(self, key):
                return self.values[key]
        component.handlers["presence"](RoomPresence(self.room["jid"], "admiral", "owner@example.test/phone"))
        component.handlers["presence"](RoomPresence(self.room["jid"], "intruder", "evil@example.test/phone"))
        calls = []
        def deliver(cfg, sender, local, body, run=subprocess.run, capture_id=False, room=None):
            calls.append((sender, local, body, room["jid"]))
            return "fixture.msg", "<" + local + "@example.test>"
        async def direct(function, *args, **kwargs):
            return function(*args, **kwargs)
        with patch.object(bridge, "inbound_mail", side_effect=deliver), \
                patch.object(bridge.asyncio, "to_thread", side_effect=direct):
            def room_message(body, nick="admiral", mid="fixture"):
                msg = FakeMessage(body, sender=self.room["jid"] + "/" + nick,
                                  local="fable", mid=mid)
                msg.values["type"] = "groupchat"
                return msg
            loop.run_until_complete(component.handlers["message"](room_message("plain", mid="lead")))
            loop.run_until_complete(component.handlers["message"](room_message("@Orca addressed", mid="seat")))
            loop.run_until_complete(component.handlers["message"](room_message("@all everyone", mid="all")))
            loop.run_until_complete(component.handlers["message"](room_message("evil", "intruder", "evil")))
            loop.run_until_complete(component.handlers["message"](room_message("spoof", "Fable", "spoof")))
            delayed = room_message("history", mid="history")
            ET.SubElement(delayed.xml, "{urn:xmpp:delay}delay")
            loop.run_until_complete(component.handlers["message"](delayed))
            loop.run_until_complete(component.handlers["message"](room_message("duplicate", mid="seat")))
            loop.run_until_complete(component.handlers["message"](room_message("@Unknown nope", mid="unknown")))
        self.assertEqual([(local, body) for _sender, local, body, _room in calls],
                         [("fable", "plain"), ("worker", "addressed"),
                          ("fable", "everyone"), ("worker", "everyone")])
        self.assertEqual(len(component.messages), 1)
        self.assertIn("Known nicknames", component.messages[0]["mbody"])


class ServiceEnsureTests(unittest.TestCase):
    LOCAL = "YOUR_LOCAL_INTERFACE"
    TAILNET = "YOUR_TAILNET_INTERFACE"
    C2S_PORT = "5222"
    HTTPS_PORT = "1"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.fakebin = self.home / "fakebin"
        self.fakebin.mkdir()
        self.base = self.home / ".config/mailcortex/xmpp"
        self.site = self.home / ".config/mailcortex/xmpp-private"
        self.data = self.home / ".local/share/mailcortex/xmpp"
        self.state = self.home / ".local/state/mailcortex/xmpp"
        self.base.mkdir(parents=True)
        self.site.mkdir(parents=True)
        self.data.mkdir(parents=True)
        self.state.mkdir(parents=True)
        (self.base / "prosody.cfg.lua").write_text("-- fixture\n")
        (self.site / "bridge.json").write_text("{}\n")
        (self.site / "local.cfg.lua").write_text(
            f'c2s_interfaces = {{ "{self.LOCAL}", "{self.TAILNET}" }}\n'
            f'c2s_ports = {{ {self.C2S_PORT} }}\n'
            f'https_interfaces = {{ "{self.TAILNET}" }}\n'
            f'https_ports = {{ {self.HTTPS_PORT} }}\n')
        self.prosody_starts = self.home / "prosody-starts"
        self.bridge_starts = self.home / "bridge-starts"
        self.current_ss = self.home / "ss-current"
        self.healthy_ss = self.home / "ss-healthy"
        self.ip_output = self.home / "ip-output"
        self.current_ss.write_text(self.ss_rows(
            self.LOCAL, self.C2S_PORT, self.TAILNET, self.C2S_PORT,
            self.TAILNET, self.HTTPS_PORT))
        self.healthy_ss.write_text(self.current_ss.read_text())
        self.ip_output.write_text(self.ip_rows(self.LOCAL, self.TAILNET))
        self.write_fake("ss", """starts=$(wc -l < "$MAILCORTEX_TEST_PROSODY_STARTS" 2>/dev/null || printf '0')
if [ "$starts" -ge 2 ]; then cat "$MAILCORTEX_TEST_SS_HEALTHY"; else cat "$MAILCORTEX_TEST_SS_CURRENT"; fi
""")
        self.write_fake("ip", """cat "$MAILCORTEX_TEST_IP_OUTPUT"
""")
        self.write_fake("prosody", """printf '%s\\n' "$$" > "$MAILCORTEX_TEST_PROSODY_PID"
printf '%s\\n' start >> "$MAILCORTEX_TEST_PROSODY_STARTS"
trap 'exit 0' TERM INT
while :; do sleep 0.05; done
""")
        self.write_fake("mailcortex-xmpp-bridge", """if [ "$1" = --check ]; then exit 0; fi
if [ "$1" != --fixture ]; then printf '%s\\n' start >> "$MAILCORTEX_TEST_BRIDGE_STARTS"; fi
printf '%s\\n' "$$" > "$MAILCORTEX_TEST_BRIDGE_PID"
trap 'exit 0' TERM INT
while :; do sleep 0.05; done
""")
        self.env = os.environ.copy() | {
            "HOME": str(self.home),
            "PATH": str(self.fakebin) + ":" + os.environ.get("PATH", "/usr/bin:/bin"),
            "MAILCORTEX_TEST_PROSODY_PID": str(self.data / "prosody.pid"),
            "MAILCORTEX_TEST_PROSODY_STARTS": str(self.prosody_starts),
            "MAILCORTEX_TEST_BRIDGE_PID": str(self.state / "bridge.pid"),
            "MAILCORTEX_TEST_BRIDGE_STARTS": str(self.bridge_starts),
            "MAILCORTEX_TEST_SS_CURRENT": str(self.current_ss),
            "MAILCORTEX_TEST_SS_HEALTHY": str(self.healthy_ss),
            "MAILCORTEX_TEST_IP_OUTPUT": str(self.ip_output),
        }
        self.service = Path(__file__).resolve().parents[5] / "linux/.local/bin/mailcortex-xmpp-service"
        self.processes = []
        self.start_fixture("prosody", "--config", str(self.base / "prosody.cfg.lua"))
        self.start_fixture("mailcortex-xmpp-bridge", "--fixture")

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def write_fake(self, name, body):
        path = self.fakebin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    @staticmethod
    def ss_rows(*pairs):
        return "".join(
            f"LISTEN 0 128 {address}:{port} peer:*\n"
            for address, port in zip(pairs[::2], pairs[1::2]))

    @staticmethod
    def ip_rows(*addresses):
        return "".join(
            f"2: fixture0 inet {address}/32 scope global\n"
            for address in addresses)

    def start_fixture(self, command, *args):
        process = subprocess.Popen(
            [str(self.fakebin / command), *args], env=self.env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(process)
        deadline = time.monotonic() + 2
        pidfile = self.data / "prosody.pid" if command == "prosody" else self.state / "bridge.pid"
        while time.monotonic() < deadline and not pidfile.exists():
            time.sleep(0.01)
        self.assertTrue(pidfile.exists(), f"{command} fixture did not write its pid")
        self.assertIsNone(process.poll(), f"{command} fixture exited")

    def run_ensure(self):
        return subprocess.run(
            [str(self.service), "ensure"], env=self.env,
            text=True, capture_output=True, check=False)

    def assert_private_values_are_silent(self, result):
        output = result.stdout + result.stderr
        for value in (self.LOCAL, self.TAILNET):
            self.assertNotIn(value, output)
        for log in self.home.rglob("*.log"):
            content = log.read_text()
            self.assertNotIn(self.LOCAL, content)
            self.assertNotIn(self.TAILNET, content)

    def test_healthy_listeners_are_a_noop(self):
        result = self.run_ensure()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.prosody_starts.read_text().splitlines(), ["start"])
        self.assertFalse(self.bridge_starts.exists())
        self.assert_private_values_are_silent(result)

    def test_present_but_missing_tailnet_listener_restarts_once(self):
        self.current_ss.write_text(self.ss_rows(self.LOCAL, self.C2S_PORT))
        result = self.run_ensure()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.prosody_starts.read_text().splitlines(), ["start", "start"])
        self.assertFalse(self.bridge_starts.exists())
        self.assertIn("restarting Prosody", result.stderr)
        self.assert_private_values_are_silent(result)

    def test_absent_tailnet_address_defers_without_restart(self):
        self.current_ss.write_text(self.ss_rows(self.LOCAL, self.C2S_PORT))
        self.ip_output.write_text(self.ip_rows(self.LOCAL))
        result = self.run_ensure()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.prosody_starts.read_text().splitlines(), ["start"])
        self.assertFalse(self.bridge_starts.exists())
        self.assertIn("not present yet", result.stderr)
        self.assert_private_values_are_silent(result)


if __name__ == "__main__":
    unittest.main()
