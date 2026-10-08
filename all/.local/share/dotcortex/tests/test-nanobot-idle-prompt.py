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
PATCH = ALL_OVERLAY / ".bots/patches/nanobot-idle-prompt.patch"


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


if __name__ == "__main__":
    unittest.main()
