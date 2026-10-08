#!/usr/bin/env python3
"""Offline fixtures for fleet-wide spoken-reply text normalisation."""

import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[5]
NORMALIZER = ROOT / "all/.local/bin/voice-text-normalize"
CLAUDE_HOOK = ROOT / "all/.local/bin/claude-hook-voice-reply"
HONEY_HOOK = ROOT / "all/.local/share/dotcortex/honey-claude/bin/honey-claude-voice-reply"
MAIL_BRIDGE = ROOT / "all/.local/bin/mailcortex-xmpp-bridge"


class NormalizerTests(unittest.TestCase):
    def normalize(self, text, format_name="markdown"):
        result = subprocess.run(
            [str(NORMALIZER), "--format", format_name], input=text,
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_real_markdown_v2_fixture_is_plain_speech(self):
        raw = (
            "\\# \\*Fleet reply\\*\n"
            "\\- Use `codex_telegram` with \\(snake_case\\)\\.\n"
            "\\- Read [the guide](https://example.invalid/guide)\\!\n"
            "1\\. Keep *bold*, __underlined__, ~struck~, and ||hidden|| text\\."
        )
        spoken = self.normalize(raw, "markdownv2")
        self.assertIn("Fleet reply", spoken)
        self.assertIn("codex_telegram", spoken)
        self.assertIn("snake_case", spoken)
        self.assertIn("Read the guide", spoken)
        self.assertIn("bold", spoken)
        self.assertNotIn("https", spoken)
        self.assertNotIn("\\", spoken)
        self.assertNotIn("*", spoken)

    def test_plain_markdown_structure_becomes_speech(self):
        raw = "## Heading\n> **Quoted** words\n\n* first\n* second with `inline_code`"
        spoken = self.normalize(raw)
        self.assertIn("Heading", spoken)
        self.assertIn("Quoted words", spoken)
        self.assertIn("first", spoken)
        self.assertIn("second with inline_code", spoken)
        self.assertNotIn("#", spoken)
        self.assertNotIn(">", spoken)
        self.assertNotIn("`", spoken)
        self.assertNotIn("*", spoken)

    def test_long_fence_is_omitted_and_short_fence_is_kept(self):
        long_block = "before\n```python\n" + ("print('too long')\n" * 80) + "```\nafter"
        spoken = self.normalize(long_block)
        self.assertIn("before", spoken)
        self.assertIn("code block omitted", spoken)
        self.assertIn("after", spoken)
        self.assertNotIn("too long", spoken)
        short = self.normalize("```python\nprint('kept')\n```")
        self.assertIn("print('kept')", short)
        self.assertNotIn("`", short)

    def test_identifiers_keep_internal_underscores_and_forbidden_symbols_never_survive(self):
        spoken = self.normalize(r"_soft_ snake_case codex_telegram C:\\temp **bold**")
        self.assertIn("snake_case", spoken)
        self.assertIn("codex_telegram", spoken)
        self.assertNotIn("\\", spoken)
        self.assertNotIn("*", spoken)


class ReplyPathTests(unittest.TestCase):
    def test_claude_hook_normalizes_before_its_length_cap_and_detach(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_setsid = root / "setsid"
            fake_setsid.write_text('#!/bin/sh\nprintf "%s\\0" "$@" > "$TEST_SETSID_LOG"\n')
            fake_setsid.chmod(0o755)
            receipt = root / "setsid-args"
            env = {
                **os.environ,
                "PATH": f"{root}:{os.environ['PATH']}",
                "XDG_CACHE_HOME": directory,
                "TEST_SETSID_LOG": str(receipt),
                "VOICE_TEXT_NORMALIZER": str(NORMALIZER),
                "CLAUDE_WARM_HERDR_AGENT": "Default",
                "PVOX_REPLY_MAX_CHARS": "5",
            }
            payload = {"tool_input": {"format": "markdownv2", "text": r"\*\*brief\*\*"}}
            result = subprocess.run(
                [str(CLAUDE_HOOK)], input=json.dumps(payload), text=True,
                capture_output=True, env=env, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            deadline = time.monotonic() + 2
            while not receipt.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            arguments = receipt.read_bytes().split(b"\0")[:-1]
            self.assertEqual(arguments[5], b"brief")

    def test_claude_normalizer_failure_skips_speech_without_logging_reply_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            failing = root / "normalizer"
            failing.write_text("#!/bin/sh\nexit 2\n")
            failing.chmod(0o755)
            raw = "reply-text-must-not-leak"
            env = {
                **os.environ,
                "XDG_CACHE_HOME": directory,
                "VOICE_TEXT_NORMALIZER": str(failing),
                "CLAUDE_WARM_HERDR_AGENT": "Default",
            }
            result = subprocess.run(
                [str(CLAUDE_HOOK)], input=json.dumps({"tool_input": {"text": raw}}),
                text=True, capture_output=True, env=env, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            log = (root / "pvox-reply.log").read_text()
            self.assertIn("normalize-failed", log)
            self.assertNotIn(raw, log)

    def test_honey_hook_normalizes_before_its_length_cap_and_fake_tts(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_python = Path(directory) / "kitten-venv/bin/python"
            fake_python.parent.mkdir(parents=True)
            fake_python.write_text("#!/bin/sh\nexit 0\n")
            fake_python.chmod(0o755)
            env = {
                "HOME": directory,
                "HONEY_VOICE": "FixtureVoice",
                "HONEY_VOICE_MAX_CHARS": "5",
                "VOICE_TEXT_NORMALIZER": str(NORMALIZER),
            }
            with patch.dict(os.environ, env, clear=False):
                module = runpy.run_path(str(HONEY_HOOK), run_name="honey_voice_fixture")
            spoken = []
            module["main"].__globals__["render_and_send"] = (
                lambda text, chat_id, reply_to: spoken.append(text)
            )
            payload = {"tool_input": {
                "format": "markdownv2", "text": r"\*\*brief\*\*",
                "chat_id": "fixture-chat",
            }}
            with patch.dict(os.environ, env, clear=False), patch(
                    "sys.stdin", io.StringIO(json.dumps(payload))):
                module["main"](detach=False)
            self.assertEqual(spoken, ["brief"])

    def test_honey_normalizer_failure_skips_fake_tts_without_logging_reply_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_python = root / "kitten-venv/bin/python"
            fake_python.parent.mkdir(parents=True)
            fake_python.write_text("#!/bin/sh\nexit 0\n")
            fake_python.chmod(0o755)
            failing = root / "normalizer"
            failing.write_text("#!/bin/sh\nexit 7\n")
            failing.chmod(0o755)
            raw = "honey-reply-text-must-not-leak"
            env = {
                "HOME": directory,
                "HONEY_VOICE": "FixtureVoice",
                "VOICE_TEXT_NORMALIZER": str(failing),
            }
            with patch.dict(os.environ, env, clear=False):
                module = runpy.run_path(str(HONEY_HOOK), run_name="honey_voice_failure_fixture")
            module["main"].__globals__["render_and_send"] = (
                lambda *_args: self.fail("fake TTS ran after normalizer failure")
            )
            payload = {"tool_input": {"text": raw, "chat_id": "fixture-chat"}}
            with patch.dict(os.environ, env, clear=False), patch(
                    "sys.stdin", io.StringIO(json.dumps(payload))):
                module["main"](detach=False)
            log = (root / ".cache/honey-voice-reply.log").read_text()
            self.assertIn("normalize-failed", log)
            self.assertNotIn(raw, log)

    def test_mailcortex_normalizes_before_cap_with_fake_pvox(self):
        module = runpy.run_path(str(MAIL_BRIDGE), run_name="mailcortex_voice_fixture")
        observed = []

        def fake_run(argv, **_kwargs):
            output = Path(argv[-1])
            if argv[1] == "render":
                observed.append(Path(argv[-2]).read_text())
                output.write_bytes(b"RIFF fixture")
            else:
                output.write_bytes(b"OggS fixture")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ, {"VOICE_TEXT_NORMALIZER": str(NORMALIZER)}, clear=False):
            module["render_voice"](
                r"**Mail** uses `snake_case` and a [link](https://example.invalid/guide).",
                "FixtureAgent", Path(directory), fake_run,
            )
        self.assertEqual(observed, ["Mail uses snake_case and a link."])
        self.assertNotIn("*", observed[0])
        self.assertNotIn("\\", observed[0])


if __name__ == "__main__":
    unittest.main()
