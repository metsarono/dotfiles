"""Disposable-copy checks for Hermes's Telegram conditional-admission seam."""
from __future__ import annotations

import ast
import asyncio
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest


ALL_OVERLAY = Path(__file__).resolve().parents[4]
PATCH = ALL_OVERLAY / ".bots/patches/hermes-mailcortex-idle-prompt.patch"
SOURCE_FILES = ("gateway/run_inbound.py", "gateway/platforms/api_server.py")


class FakeMessageEvent:
    def __init__(self, **values):
        self.__dict__.update(values)
        self._gateway_accepted = False


class HermesIdlePromptSeamTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source_value = os.environ.get("HERMES_AGENT_SOURCE", "").strip()
        if not source_value:
            raise unittest.SkipTest("set HERMES_AGENT_SOURCE to the reviewed Hermes checkout")
        source = Path(source_value).resolve()
        if not all((source / relative).is_file() for relative in SOURCE_FILES):
            raise unittest.SkipTest("HERMES_AGENT_SOURCE lacks the pinned gateway files")
        cls.temporary = tempfile.TemporaryDirectory(prefix="hermes-idle-prompt-")
        cls.site = Path(cls.temporary.name) / "site"
        for relative in SOURCE_FILES:
            destination = cls.site / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, destination)
        applied = subprocess.run(
            ["patch", "--batch", "--fuzz=0", "-d", str(cls.site), "-p1", "-i", str(PATCH)],
            text=True, capture_output=True, check=False,
        )
        if applied.returncode:
            raise AssertionError(applied.stdout + applied.stderr)
        compiled = subprocess.run(
            [sys.executable, "-m", "py_compile",
             *(str(cls.site / relative) for relative in SOURCE_FILES)],
            text=True, capture_output=True, check=False,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

        inbound = ast.parse((cls.site / SOURCE_FILES[0]).read_text(encoding="utf-8"))
        owner = next(node for node in inbound.body
                     if isinstance(node, ast.ClassDef) and node.name == "GatewayInboundMixin")
        wanted = {"_gateway_idle_prompt_busy", "gateway_idle_prompt_status",
                  "admit_gateway_idle_prompt"}
        methods = [node for node in owner.body
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and node.name in wanted]
        if {node.name for node in methods} != wanted:
            raise AssertionError("patched GatewayInboundMixin lacks the admission methods")
        seam_class = ast.ClassDef(
            name="Seam", bases=[], keywords=[], body=methods, decorator_list=[])
        ast.fix_missing_locations(seam_class)
        namespace = {
            "MessageEvent": FakeMessageEvent,
            "MessageType": SimpleNamespace(TEXT="text"),
            "getattr": getattr,
        }
        exec(compile(ast.Module(body=[seam_class], type_ignores=[]), "<hermes-seam>", "exec"),
             namespace)
        cls.Seam = namespace["Seam"]

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    def make_runner(self, *, busy: bool):
        calls = []

        class Adapter:
            async def handle_message(inner, event):
                calls.append(event)
                event._gateway_accepted = True

        runner = self.Seam()
        adapter = Adapter()
        runner._active_work_count = lambda: int(busy)
        runner._background_tasks = set()
        runner.adapters = {"telegram": SimpleNamespace(
            _active_sessions={}, _pending_messages={})}

        async def target(session_key):
            self.assertEqual(session_key, "agent:YOUR_PROFILE:telegram:dm:YOUR_CHAT_ID")
            return (SimpleNamespace(session_id="YOUR_SESSION_ID"),
                    SimpleNamespace(platform="telegram", chat_type="dm"), adapter)

        runner._gateway_idle_prompt_target = target
        return runner, calls

    async def test_busy_refuses_before_platform_dispatch(self):
        runner, calls = self.make_runner(busy=True)
        outcome = await runner.admit_gateway_idle_prompt(
            "agent:YOUR_PROFILE:telegram:dm:YOUR_CHAT_ID", "MailCortex delivery")
        self.assertEqual(outcome, "busy")
        self.assertEqual(calls, [])

    async def test_acceptance_uses_strict_gateway_identity_and_real_adapter(self):
        runner, calls = self.make_runner(busy=False)
        outcome = await runner.admit_gateway_idle_prompt(
            "agent:YOUR_PROFILE:telegram:dm:YOUR_CHAT_ID", "MailCortex delivery")
        self.assertEqual(outcome, "accepted")
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].internal)
        self.assertFalse(calls[0].allow_gateway_control)
        self.assertEqual(calls[0].metadata, {
            "hermes_plugin_id": "mailcortex", "hermes_plugin_injection": True,
            "gateway_session_key": "agent:YOUR_PROFILE:telegram:dm:YOUR_CHAT_ID",
            "gateway_session_id": "YOUR_SESSION_ID", "gateway_session_strict": True,
        })

    def test_disposable_patch_is_repeatable_and_routes_are_authenticated(self):
        reverse = subprocess.run(
            ["patch", "--batch", "--fuzz=0", "--dry-run", "--reverse",
             "-d", str(self.site), "-p1", "-i", str(PATCH)],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(reverse.returncode, 0, reverse.stdout + reverse.stderr)
        api = (self.site / SOURCE_FILES[1]).read_text(encoding="utf-8")
        self.assertIn('("POST", "/api/gateway/idle-prompt/status",', api)
        self.assertIn('("POST", "/api/gateway/idle-prompt",', api)
        tree = ast.parse(api)
        handlers = {node.name: node for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for name in ("_handle_gateway_idle_prompt_status", "_handle_gateway_idle_prompt"):
            decorators = [ast.unparse(item) for item in handlers[name].decorator_list]
            self.assertIn("_require_auth", decorators)

    def test_target_is_telegram_dm_only_and_ack_follows_adapter_claim(self):
        inbound = (self.site / SOURCE_FILES[0]).read_text(encoding="utf-8")
        self.assertIn('source.platform != Platform.TELEGRAM or source.chat_type != "dm"', inbound)
        busy_at = inbound.index("if self._gateway_idle_prompt_busy():", inbound.index(
            "async def admit_gateway_idle_prompt"))
        claim_at = inbound.index("await adapter.handle_message(event)", busy_at)
        ack_at = inbound.index('return "accepted" if getattr(event, "_gateway_accepted"', claim_at)
        self.assertLess(busy_at, claim_at)
        self.assertLess(claim_at, ack_at)


if __name__ == "__main__":
    unittest.main()
