#!/usr/bin/env python3
"""Black-box Stop guard fixtures; no live sessions or channel credentials."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]
GUARD = ROOT / "all/.local/bin/claude-hook-telegram-delivery-guard"
WAKE = "[mailcortex-wake] MailCortex: new mail is waiting in consorts/YOUR_SEAT on YOUR_MAIL_HOST. Open /inbox, read all pending mail, and handle it with your harness tools."
CHANNEL = '<channel source="telegram" chat_id="YOUR_INBOUND_CHAT">hello</channel>'
REPLY = "mcp__plugin_telegram_telegram__reply"


def user(content):
    return {"type": "user", "message": {"role": "user", "content": content}}


def assistant(*blocks):
    return {"type": "assistant", "message": {"role": "assistant", "content": list(blocks)}}


TEXT = {"type": "text", "text": "Handled the mail."}


class DeliveryGuardTests(unittest.TestCase):
    def run_guard(self, records, *, chat="YOUR_REPLY_CHAT", active=False, channel=True, payload=None):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            transcript = home / "transcript.jsonl"
            transcript.write_text("".join(json.dumps(record) + "\n" for record in records))
            env = {"HOME": directory, "PATH": os.environ["PATH"]}
            if channel:
                env["CLAUDE_IDLE_CHANNEL"] = "claude-fixture"
            if chat is not None:
                env["MAILCORTEX_WAKE_REPLY_CHAT"] = chat
            data = payload if payload is not None else {"transcript_path": str(transcript), "stop_hook_active": active}
            result = subprocess.run(["bash", str(GUARD)], input=json.dumps(data), capture_output=True, text=True, env=env, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            return json.loads(result.stdout) if result.stdout else None

    def assert_block(self, records, **kwargs):
        verdict = self.run_guard(records, **kwargs)
        self.assertIsNotNone(verdict, "Stop passed without requiring Telegram delivery")
        self.assertEqual(verdict["decision"], "block")
        return verdict["reason"]

    def test_wake_text_without_reply_blocks_and_names_chat(self):
        reason = self.assert_block([user(WAKE), assistant(TEXT)])
        self.assertIn("YOUR_REPLY_CHAT", reason)
        self.assertIn("MAILCORTEX_WAKE_REPLY_CHAT", reason)
        self.assertNotIn("chat_id from the inbound", reason)

    def test_wake_text_with_reply_passes(self):
        reply = {"type": "tool_use", "name": REPLY, "input": {"chat_id": "YOUR_REPLY_CHAT", "text": "Handled."}}
        self.assertIsNone(self.run_guard([user(WAKE), assistant(TEXT, reply)]))

    def test_wake_reason_uses_configured_fixture_chat(self):
        reason = self.assert_block([user(WAKE), assistant(TEXT)], chat="fixture-reply-chat")
        self.assertIn("chat_id=fixture-reply-chat, from MAILCORTEX_WAKE_REPLY_CHAT", reason)
        self.assertNotIn("placeholder", reason)

    def test_wake_text_with_edit_message_passes(self):
        edit = {"type": "tool_use", "name": "mcp__plugin_telegram_telegram__edit_message", "input": {}}
        self.assertIsNone(self.run_guard([user(WAKE), assistant(TEXT, edit)]))

    def test_wake_without_configured_chat_blocks_and_says_unset(self):
        reason = self.assert_block([user(WAKE), assistant(TEXT)], chat=None)
        self.assertIn("MAILCORTEX_WAKE_REPLY_CHAT is unset", reason)
        self.assertNotIn("chat_id from the inbound", reason)

    def test_wake_empty_chat_blocks_and_says_unset(self):
        reason = self.assert_block([user(WAKE), assistant(TEXT)], chat="")
        self.assertIn("MAILCORTEX_WAKE_REPLY_CHAT is unset", reason)

    def test_wake_placeholder_chat_is_explicitly_unprovisioned(self):
        reason = self.assert_block([user(WAKE), assistant(TEXT)], chat="YOUR_TELEGRAM_CHAT_ID")
        self.assertIn("MAILCORTEX_WAKE_REPLY_CHAT", reason)
        self.assertIn("placeholder", reason)

    def test_wake_block_list_prompt_and_tool_result_preserve_last_real_prompt(self):
        records = [user([{"type": "text", "text": WAKE}]),
                   assistant({"type": "tool_use", "name": "Read", "id": "fixture", "input": {}}),
                   user([{"type": "tool_result", "tool_use_id": "fixture", "content": "fixture mail"}]), assistant(TEXT)]
        self.assert_block(records)

    def test_wake_reply_from_previous_turn_does_not_satisfy_current_turn(self):
        self.assert_block([user(CHANNEL), assistant({"type": "tool_use", "name": REPLY, "input": {}}), user(WAKE), assistant(TEXT)])

    def test_plain_tui_prompt_passes(self):
        self.assertIsNone(self.run_guard([user("Please read this file."), assistant(TEXT)]))

    def test_tui_mentioning_marker_passes(self):
        self.assertIsNone(self.run_guard([user("Explain the [mailcortex-wake] marker."), assistant(TEXT)]))

    def test_tui_after_wake_passes(self):
        self.assertIsNone(self.run_guard([user(WAKE), assistant(TEXT), user("Now answer here."), assistant(TEXT)]))

    def test_telegram_channel_without_reply_blocks_as_before(self):
        reason = self.assert_block([user(CHANNEL), assistant(TEXT)], chat=None)
        self.assertIn("chat_id from the inbound <channel> tag", reason)

    def test_telegram_channel_with_reply_or_edit_passes_as_before(self):
        for name in (REPLY, "mcp__plugin_telegram_telegram__edit_message"):
            with self.subTest(name=name):
                self.assertIsNone(self.run_guard([user(CHANNEL), assistant(TEXT, {"type": "tool_use", "name": name, "input": {}})]))

    def test_stop_hook_active_passes_for_wake_and_channel(self):
        for prompt in (WAKE, CHANNEL):
            with self.subTest(prompt=prompt):
                self.assertIsNone(self.run_guard([user(prompt), assistant(TEXT)], active=True))

    def test_silent_turn_passes_for_wake_and_channel(self):
        for prompt in (WAKE, CHANNEL):
            with self.subTest(prompt=prompt):
                self.assertIsNone(self.run_guard([user(prompt), assistant({"type": "thinking", "thinking": "fixture"})]))

    def test_non_channel_session_passes_as_before(self):
        self.assertIsNone(self.run_guard([user(CHANNEL), assistant(TEXT)], channel=False))

    def test_missing_transcript_and_malformed_payload_fail_open(self):
        for payload in ({}, {"transcript_path": "/tmp/YOUR_MISSING_TRANSCRIPT"}, []):
            with self.subTest(payload=payload):
                self.assertIsNone(self.run_guard([], payload=payload))


if __name__ == "__main__":
    unittest.main()
