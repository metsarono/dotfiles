"""Disposable copied-package busy API/applier tests; no sockets or real CLI."""
from __future__ import annotations

import asyncio
import hashlib
import importlib
import itertools
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import ductor_bot

SEAMS = Path(__file__).resolve().parents[1] / "ductor-seams"
APPLIER = SEAMS.parents[2] / "bin/ductor-seam-apply"
INSTALLED = Path(ductor_bot.__file__).resolve().parent
TEMP = tempfile.TemporaryDirectory(prefix="ductor-busy-test-")
SITE = Path(TEMP.name)


def snapshot(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts}


def pristine(site):
    shutil.copytree(INSTALLED, site / "ductor_bot", ignore=shutil.ignore_patterns("__pycache__"))
    patch = SEAMS / "idle_compact_lifecycle.patch"
    command = ["patch", "-d", str(site), "-p1", "--fuzz=0", "--reverse", "--force", "-s"]
    dry = subprocess.run(command + ["--dry-run"], input=patch.read_bytes(), capture_output=True)
    if dry.returncode == 0:
        subprocess.run(command, input=patch.read_bytes(), capture_output=True, check=True)
    return site


def apply(site, *args):
    env = dict(os.environ, DOTCORTEX_DUCTOR_SEAMS=str(SEAMS), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(["bash", str(APPLIER), "--site", str(site), *args],
                          env=env, text=True, capture_output=True)


pristine(SITE)
applied = apply(SITE)
if applied.returncode:
    raise RuntimeError(applied.stdout + applied.stderr)
print("FIXTURE CLEAN APPLY:\n" + applied.stdout, flush=True)
if os.environ.get("DUCTOR_BUSY_MUTANT"):
    target = SITE / "ductor_bot/api/busy_state.py"
    source = target.read_text()
    needle = 'result["busy"] = any(signals.values())'
    assert source.count(needle) == 1
    target.write_text(source.replace(needle, 'result["busy"] = False'))

del sys.modules["ductor_bot"]
sys.path.insert(0, str(SITE))
importlib.invalidate_caches()
from ductor_bot.api import busy_state as bs
from ductor_bot.api.server import ApiServer
from ductor_bot.bus.lock_pool import LockPool
from ductor_bot.cli.process_registry import ProcessRegistry
from ductor_bot.orchestrator.idle_compact import IdleCompactor, IdleCompactSettings
from ductor_bot.session.key import SessionKey
from aiohttp.test_utils import make_mocked_request

assert Path(bs.__file__).resolve().is_relative_to(SITE)
LOOPBACK = socket.gethostbyname("localhost")
KEY = SessionKey(chat_id=1)  # synthetic fixture identity


class BusyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.session = SimpleNamespace(session_id="fixture-session", session_key=KEY)
        self.sessions = SimpleNamespace(get_active=mock.AsyncMock(return_value=self.session))
        self.orch = SimpleNamespace(_sessions=self.sessions, _lock_pool=LockPool(),
                                    _process_registry=ProcessRegistry(),
                                    _idle_compactor=SimpleNamespace(_compacting=set()))
        self.server = ApiServer(SimpleNamespace(token="YOUR_API_TOKEN", host=LOOPBACK,
                                                allow_public=True, port=0), default_chat_id=1)
        self.server.set_busy_state_handler(lambda: bs.main_busy_state(self.orch, self.server))

    def request(self, token="YOUR_API_TOKEN", peer=LOOPBACK, query="", extra=None):
        headers = {"Authorization": "Bearer " + token} if token is not None else {}
        headers.update(extra or {})
        request = make_mocked_request("GET", "/busy" + query, headers=headers)
        request._cache["remote"] = peer
        return request

    async def state(self):
        response = await self.server._handle_busy(self.request())
        self.assertEqual(response.status, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        return json.loads(response.text)

    async def test_idle_and_exact_identity(self):
        self.assertEqual(await self.state(), {"busy": False, "known": True,
                         "session_key": KEY.storage_key, "reasons": []})

    async def test_active_turn(self):
        self.orch._process_registry.register(1, SimpleNamespace(returncode=None, pid=1), "fixture")
        state = await self.state()
        self.assertTrue(state["busy"])
        self.assertIn("active_turn", state["reasons"])

    async def test_held_session_lock(self):
        lock = self.orch._lock_pool.get(KEY.lock_key)
        async with lock:
            state = await self.state()
            self.assertTrue(state["busy"])
            self.assertIn("session_lock", state["reasons"])
        self.assertFalse((await self.state())["busy"])

    async def test_api_lock(self):
        async with self.server._lock_pool.get(KEY.lock_key):
            self.assertTrue((await self.state())["busy"])

    async def test_compaction_marker(self):
        self.orch._idle_compactor._compacting.add(KEY.storage_key)
        state = await self.state()
        self.assertTrue(state["busy"])
        self.assertIn("compaction", state["reasons"])

    async def test_real_compaction_lifecycle_and_cancellation(self):
        with tempfile.TemporaryDirectory() as home:
            self.orch._paths = SimpleNamespace(sessions_path=Path(home) / "sessions.json")
            self.orch.is_chat_busy = lambda *args: False
            comp = IdleCompactor(self.orch)
            self.orch._idle_compactor = comp
            self.session.last_active = "fixture-time"
            self.session.provider = "claude"
            self.session.model = "fixture-model"
            entered = asyncio.Event()
            async def wait(*args):
                entered.set()
                await asyncio.Event().wait()
            comp._compact_claude = wait
            task = asyncio.create_task(comp._compact_locked(self.session, IdleCompactSettings()))
            await entered.wait()
            self.assertIn(KEY.storage_key, comp._compacting)
            state = await self.state()
            self.assertTrue(state["busy"])
            self.assertIn("compaction", state["reasons"])
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(comp._compacting, set())
            self.assertFalse((await self.state())["busy"])

    async def test_missing_authorities_are_busy(self):
        for name in ("_sessions", "_lock_pool", "_process_registry", "_idle_compactor"):
            with self.subTest(name=name), mock.patch.object(self.orch, name, None):
                state = await self.state()
                self.assertTrue(state["busy"])
                self.assertFalse(state["known"])

    async def test_unknown_or_wrong_session_is_busy(self):
        for session in (None, SimpleNamespace(session_id="", session_key=KEY),
                        SimpleNamespace(session_id="wrong", session_key=SessionKey(transport="mx", chat_id=1))):
            self.sessions.get_active.return_value = session
            state = await self.state()
            self.assertTrue(state["busy"])
            self.assertFalse(state["known"])

    async def test_busy_signal_after_session_lookup(self):
        async def lookup(key):
            await self.orch._lock_pool.get(key.lock_key).acquire()
            return self.session
        self.sessions.get_active.side_effect = lookup
        self.assertTrue((await self.state())["busy"])
        self.orch._lock_pool.get(KEY.lock_key).release()

    async def test_auth_refusal(self):
        for token in (None, "wrong", ""):
            response = await self.server._handle_busy(self.request(token=token))
            self.assertEqual(response.status, 401)
        self.sessions.get_active.assert_not_awaited()
        self.server._config.token = ""
        self.assertEqual((await self.server._handle_busy(self.request(token=""))).status, 401)

    async def test_loopback_and_proxy_refusal(self):
        for request in (self.request(peer="invalid-peer"), self.request(peer=None),
                        self.request(extra={"Forwarded": "for=YOUR_PEER"}),
                        self.request(extra={"X-Forwarded-For": "YOUR_PEER"})):
            self.assertEqual((await self.server._handle_busy(request)).status, 403)
        self.server._config.host = "YOUR_NON_LOOPBACK_HOST"
        self.assertEqual((await self.server._handle_busy(self.request())).status, 403)
        self.sessions.get_active.assert_not_awaited()

    async def test_query_refused(self):
        self.assertEqual((await self.server._handle_busy(self.request(query="?chat_id=2"))).status, 400)

    async def test_errors_fail_loud(self):
        self.sessions.get_active.side_effect = RuntimeError("fixture authority failure")
        with self.assertLogs(bs.logger, level="ERROR"):
            response = await self.server._handle_busy(self.request())
        self.assertEqual(response.status, 503)
        self.assertEqual(json.loads(response.text), {"busy": True, "known": False,
                         "error": "busy_state_unavailable"})
        self.server._busy_state_handler = None
        self.assertEqual((await self.server._handle_busy(self.request())).status, 503)

    async def test_route_registered_without_socket(self):
        with mock.patch("ductor_bot.api.server.web.AppRunner") as runner, \
             mock.patch("ductor_bot.api.server.web.TCPSite") as site:
            runner.return_value.setup = mock.AsyncMock()
            site.return_value.start = mock.AsyncMock()
            await self.server.start()
            app = runner.call_args.args[0]
            route = [r for r in app.router.routes() if r.method == "GET"
                     and r.resource.canonical == "/busy"]
            self.assertEqual(len(route), 1)
            self.assertEqual(route[0].handler, self.server._handle_busy)

    async def test_lifecycle_wires_real_authority(self):
        from ductor_bot.orchestrator.lifecycle import start_api_server
        self.server._config.chat_id = KEY.chat_id
        self.orch.handle_message_streaming = mock.AsyncMock()
        self.orch.abort = mock.AsyncMock()
        self.orch._providers = SimpleNamespace(
            build_provider_info=lambda observer: [], resolve_runtime_target=lambda model: ("codex", model))
        self.orch._observers = SimpleNamespace(codex_cache_obs=None)
        self.orch._config = SimpleNamespace(model="fixture-model")
        config = SimpleNamespace(api=self.server._config, allowed_user_ids=[], file_access="workspace")
        paths = SimpleNamespace(workspace=SITE, api_files_dir=SITE / "files")
        with mock.patch.object(ApiServer, "start", new=mock.AsyncMock()):
            await start_api_server(self.orch, config, paths)
        wired = self.orch._api_stop.__self__
        response = await wired._handle_busy(self.request())
        self.assertEqual(response.status, 200)
        self.assertFalse(json.loads(response.text)["busy"])

    async def test_malformed_authority_fails_loud(self):
        with mock.patch.object(self.orch._process_registry, "has_active", return_value=None), \
             self.assertLogs(bs.logger, level="ERROR"):
            response = await self.server._handle_busy(self.request())
        self.assertEqual(response.status, 503)


class ApplyTests(unittest.TestCase):
    def test_idempotence_and_check(self):
        before = snapshot(SITE)
        result = apply(SITE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("already applied", result.stdout)
        self.assertEqual(snapshot(SITE), before)
        checked = apply(SITE, "--check")
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        print("IDEMPOTENCE/CHECK:\n" + result.stdout + checked.stdout)

    def test_drift_refusal_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            site = pristine(Path(root))
            target = site / "ductor_bot/api/server.py"
            target.write_text(target.read_text().replace(
                'app.router.add_get("/health", self._handle_health)',
                'app.router.add_get("/upstream-change", self._handle_health)'))
            before = snapshot(site)
            result = apply(site)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("upstream drift", result.stderr)
            self.assertEqual(snapshot(site), before)
            print("DRIFT REFUSAL:\n" + result.stdout + result.stderr)

    def test_ordered_series_all_valid_hook_states(self):
        for mirror, compact, stage in itertools.product((False, True), (False, True), range(3)):
            with self.subTest(mirror=mirror, compact=compact, stage=stage), tempfile.TemporaryDirectory() as root:
                site = Path(root)
                shutil.copytree(SITE / "ductor_bot", site / "ductor_bot",
                                ignore=shutil.ignore_patterns("__pycache__"))
                patches = []
                if not mirror:
                    patches.append("idle_prompt_telegram.patch")
                if stage < 2:
                    patches.append("idle_prompt_api.patch")
                if stage < 1:
                    patches.append("busy_state_api.patch")
                if not compact:
                    patches.append("idle_compact_lifecycle.patch")
                for name in patches:
                    subprocess.run(["patch", "-d", str(site), "-p1", "--fuzz=0",
                                    "--reverse", "--force", "-s"],
                                   input=(SEAMS / name).read_bytes(), check=True, capture_output=True)
                before = snapshot(site)
                checked = apply(site, "--check")
                self.assertEqual(checked.returncode, int(bool(patches)), checked.stdout + checked.stderr)
                self.assertEqual(snapshot(site), before)
                result = apply(site)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                after = snapshot(site)
                result = apply(site)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("already applied", result.stdout)
                self.assertEqual(snapshot(site), after)
                self.assertEqual(apply(site, "--check").returncode, 0)

    def test_admission_drift_refuses_before_mutation_on_applied_series(self):
        with tempfile.TemporaryDirectory() as root:
            site = Path(root)
            shutil.copytree(SITE / "ductor_bot", site / "ductor_bot",
                            ignore=shutil.ignore_patterns("__pycache__"))
            target = site / "ductor_bot/api/server.py"
            needle = "        self._idle_message_handler = None"
            source = target.read_text()
            self.assertEqual(source.count(needle), 1)
            target.write_text(source.replace(needle, needle + "  # fixture upstream drift"))
            before = snapshot(site)
            for args in ((), ("--check",)):
                result = apply(site, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("upstream drift", result.stderr)
                self.assertEqual(snapshot(site), before)

    def test_forced_idle_mutant_fails_active_turn_test(self):
        env = dict(os.environ, DUCTOR_BUSY_MUTANT="1", PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, __file__, "BusyTests.test_active_turn", "-v"],
                                env=env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL: test_active_turn", result.stderr)
        self.assertIn("AssertionError: False is not true", result.stderr)
        print("EXPECTED RED MUTANT:\n" + result.stdout + result.stderr)


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        TEMP.cleanup()
