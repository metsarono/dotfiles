"""Regression checks for Nano's Telegram-to-pvox terminal reply lane."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from nanobot.bus.events import OutboundMessage
from nanobot.bus.outbound_events import ProgressEvent
from nanobot.bus.queue import MessageBus
from nanobot.channels.telegram.runtime import TelegramChannel, TelegramConfig, _StreamBuf
from nanobot.events import ContextCompactionEvent


ALL_OVERLAY = Path(__file__).resolve().parents[4]
VOICE_HOOK = ALL_OVERLAY / ".local/bin/claude-hook-voice-reply"


def make_channel() -> TelegramChannel:
    channel = TelegramChannel(
        TelegramConfig(token="test-token", rich_messages=False),
        MessageBus(),
    )
    channel._app = SimpleNamespace(bot=SimpleNamespace(
        edit_message_text=AsyncMock(),
        send_message=AsyncMock(),
    ))
    channel._app_ready.set()
    return channel


class RuntimeVoiceReplyTest(unittest.IsolatedAsyncioTestCase):
    async def test_terminal_send_queues_only_after_success(self):
        channel = make_channel()
        channel._send_text = AsyncMock()
        channel._queue_voice_reply = Mock()
        message = OutboundMessage("telegram", "7", "delivered terminal text")

        await channel.send(message)

        channel._send_text.assert_awaited_once()
        channel._queue_voice_reply.assert_called_once_with("delivered terminal text")

        channel._send_text.reset_mock(side_effect=True)
        channel._queue_voice_reply.reset_mock()
        channel._send_text.side_effect = RuntimeError("delivery failed")
        with self.assertRaisesRegex(RuntimeError, "delivery failed"):
            await channel.send(message)
        channel._queue_voice_reply.assert_not_called()

    async def test_progress_and_compaction_events_stay_silent(self):
        channel = make_channel()
        channel._send_text = AsyncMock()
        channel._send_compaction_notice = AsyncMock()
        channel._queue_voice_reply = Mock()

        await channel.send(OutboundMessage(
            "telegram", "7", "tool progress",
            event=ProgressEvent(content="tool progress", tool_hint=True),
        ))
        await channel.send(OutboundMessage(
            "telegram", "7", "compacting",
            event=ContextCompactionEvent("compact-1", "started"),
        ))

        channel._send_text.assert_awaited_once()
        channel._send_compaction_notice.assert_awaited_once()
        channel._queue_voice_reply.assert_not_called()

    async def test_stream_speaks_once_at_successful_stream_end(self):
        channel = make_channel()
        channel._queue_voice_reply = Mock()
        channel._stream_bufs["7"] = _StreamBuf(
            text="one streamed terminal reply",
            message_id=17,
            last_edit=time.monotonic(),
        )

        await channel.send_delta("7", " still streaming", stream_id="stream-1")
        channel._queue_voice_reply.assert_not_called()

        await channel.send_delta("7", "", stream_id="stream-1", stream_end=True)
        await channel.send_delta("7", "", stream_id="stream-1", stream_end=True)

        channel._queue_voice_reply.assert_called_once_with(
            "one streamed terminal reply still streaming",
        )

    async def test_relay_payload_uses_nanobot_identity_and_kill_switch(self):
        channel = make_channel()
        with tempfile.TemporaryDirectory(prefix="nano-voice-payload-") as root:
            root_path = Path(root)
            capture = root_path / "payload.json"
            identity = root_path / "identity"
            relay = root_path / "relay"
            relay.write_text(
                "#!/bin/sh\n"
                "printf '%s' \"$CLAUDE_WARM_HERDR_AGENT\" > \"$NANO_IDENTITY\"\n"
                "cat > \"$NANO_CAPTURE\"\n",
                encoding="utf-8",
            )
            relay.chmod(0o755)
            env = {
                "NANOBOT_VOICE_REPLY_COMMAND": str(relay),
                "NANO_CAPTURE": str(capture),
                "NANO_IDENTITY": str(identity),
                "PVOX_REPLY_OFF": "",
            }
            with patch.dict(os.environ, env):
                await channel._run_voice_reply("voice payload ✓")
            self.assertEqual(identity.read_text(encoding="utf-8"), "Nanobot")
            self.assertEqual(
                json.loads(capture.read_text(encoding="utf-8")),
                {"tool_input": {"text": "voice payload ✓"}},
            )

        channel._voice_reply_tasks.clear()
        with patch.dict(os.environ, {"PVOX_REPLY_OFF": "1"}):
            channel._queue_voice_reply("must stay silent")
        self.assertFalse(channel._voice_reply_tasks)


class SharedRelayIntegrationTest(unittest.TestCase):
    def _run_hook(self, fail_host: str = "") -> tuple[list[str], str, str]:
        self.assertTrue(VOICE_HOOK.is_file(), f"missing tangled hook: {VOICE_HOOK}")
        with tempfile.TemporaryDirectory(prefix="nano-shared-relay-") as root:
            home = Path(root)
            bindir = home / "bin"
            pvox = home / "HelmCortex/FORGE/VoxForge/bin/pvox"
            bindir.mkdir(parents=True)
            pvox.parent.mkdir(parents=True)
            ssh_log = home / "ssh.log"
            pvox_log = home / "pvox.log"
            cache = home / "cache"

            pvox.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" >> \"$PVOX_LOG\"\n"
                "case \"${1:-}\" in\n"
                "  voicespec) printf '%s\\n' '{\"engine\":\"piper\",\"voice\":\"test\",\"speed\":1.0}' ;;\n"
                "  clean) cat ;;\n"
                "  render) out=\"${@: -1}\"; printf 'RIFFnano' > \"$out\" ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            pvox.chmod(0o755)
            ssh = bindir / "ssh"
            ssh.write_text(
                "#!/usr/bin/env bash\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  case \"$1\" in -o) shift 2 ;; *) host=\"$1\"; shift; break ;; esac\n"
                "done\n"
                "cat >/dev/null\n"
                "printf '%s\\n' \"$host\" >> \"$SSH_LOG\"\n"
                "[ -n \"${SSH_FAIL_HOST:-}\" ] && [ \"$host\" = \"$SSH_FAIL_HOST\" ] && exit 1\n"
                "exit 0\n",
                encoding="utf-8",
            )
            ssh.chmod(0o755)

            env = os.environ.copy()
            env.update({
                "HOME": str(home),
                "PATH": f"{bindir}:{env.get('PATH', '')}:/usr/bin:/bin",
                "XDG_CACHE_HOME": str(cache),
                "CLAUDE_WARM_HERDR_AGENT": "Nanobot",
                "PVOX_REPLY_HOST": "s24",
                "PVOX_REPLY_FALLBACK_HOST": "t480s",
                "PVOX_REPLY_NO_ONDEVICE": "1",
                "PVOX_LOG": str(pvox_log),
                "SSH_LOG": str(ssh_log),
                "SSH_FAIL_HOST": fail_host,
            })
            env.pop("PVOX_REPLY_OFF", None)
            subprocess.run(
                [str(VOICE_HOOK)],
                input=json.dumps({"tool_input": {"text": "Nano relay test"}}),
                text=True,
                env=env,
                check=True,
                timeout=10,
            )

            reply_log = cache / "pvox-reply.log"
            deadline = time.monotonic() + 10
            expected = "delivered=t480s" if fail_host else "delivered=s24"
            while time.monotonic() < deadline:
                log_text = reply_log.read_text(encoding="utf-8") if reply_log.exists() else ""
                if expected in log_text:
                    break
                time.sleep(0.05)
            else:
                self.fail(f"shared relay did not finish: {log_text!r}")

            hosts = ssh_log.read_text(encoding="utf-8").splitlines()
            pvox_calls = pvox_log.read_text(encoding="utf-8")
            return hosts, pvox_calls, log_text

    def test_nanobot_maps_to_haiku_and_prefers_s24(self):
        hosts, pvox_calls, log_text = self._run_hook()
        self.assertEqual(hosts, ["s24"])
        self.assertIn("render --agent Haiku --no-play", pvox_calls)
        self.assertIn("voice=Haiku", log_text)
        self.assertIn("delivered=s24", log_text)

    def test_t480s_is_used_only_after_s24_delivery_failure(self):
        hosts, _, log_text = self._run_hook(fail_host="s24")
        self.assertEqual(hosts, ["s24", "t480s"])
        self.assertIn("host=s24 DELIVER-FAIL", log_text)
        self.assertIn("delivered=t480s", log_text)


if __name__ == "__main__":
    unittest.main()
