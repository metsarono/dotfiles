"""Idle compaction: compact a main session before its provider's prompt cache expires.

A resumed session whose prompt cache has expired is re-read in full at the
uncached price on the next turn.  Compacting shortly before the cache expires
runs the compaction turn at the cached price and leaves a small context for
the next turn.  The provider decides when the cache expires, so each provider
has its own idle threshold:

- Claude: ``/compact`` through the normal CLI path (``claude -p --resume``),
  which keeps the session id.  Default 55 minutes idle (1-hour cache).
- Codex: ``thread/compact/start`` through a short-lived ``codex app-server``.
  Conservative default 25/30 minutes for API/custom/unverified routes.
  Verified ChatGPT subscriptions suppress this idle-cache action; the reviewed
  provider assurance does not establish physical cache residency.

A session is compacted at most once per idle period: the ``last_active``
value it was compacted at is persisted, so a restart never repeats it.  A
session that is already past its cache window is skipped (compacting it would
pay the uncached price that idle compaction exists to avoid).  The per-session
lock is held for the whole compaction, so a user message waits for it instead
of racing a second writer onto the same transcript.

Settings come from the optional ``idle_compaction`` object in config.json
(AgentConfig ignores unknown keys, so no schema change is needed).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ductor_bot.cli.types import AgentRequest

if TYPE_CHECKING:
    from ductor_bot.orchestrator.core import Orchestrator
    from ductor_bot.session.manager import SessionData

logger = logging.getLogger(__name__)

_STATE_FILE = "idle_compaction.json"
_SUBSCRIPTION_CACHE_SOURCE = "https://x.com/thsottiaux/status/2112712984644784534"
_SUBSCRIPTION_CACHE_EFFECTIVE = 1792545002.0  # 2026-10-21T01:10:02Z
_SUBSCRIPTION_SUPPRESSED = "subscription_idle_suppressed"
_SUBSCRIPTION_ROUTE_ENV = frozenset({
    "OPENAI_BASE_URL", "OPENAI_API_BASE", "OPENAI_API_KEY", "CODEX_API_KEY",
    "CHATGPT_BASE_URL", "CODEX_CHATGPT_BASE_URL", "CODEX_BASE_URL", "AZURE_OPENAI_ENDPOINT",
})


@dataclass(frozen=True, slots=True)
class IdleCompactSettings:
    enabled: bool = True
    claude_idle_minutes: float = 55.0
    claude_cache_minutes: float = 60.0
    codex_idle_minutes: float = 25.0
    codex_cache_minutes: float = 30.0
    tick_seconds: float = 60.0
    timeout_seconds: float = 900.0

    @classmethod
    def load(cls, config_path: Path) -> IdleCompactSettings:
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8")).get("idle_compaction")
        except (OSError, ValueError):
            raw = None
        if not isinstance(raw, dict):
            return cls()
        values: dict[str, Any] = {}
        for name in cls.__dataclass_fields__:
            if name in raw:
                values[name] = bool(raw[name]) if name == "enabled" else float(raw[name])
        return cls(**values)

    def window(self, provider: str, model: str = "unknown") -> tuple[float, float] | None:
        """Return (compact_after, cache_expires) in seconds, or None if unsupported."""
        if provider == "claude":
            fallback = (self.claude_idle_minutes * 60, self.claude_cache_minutes * 60)
            policy_provider, endpoint = "anthropic", "anthropic-default"
        elif provider == "codex":
            fallback = (self.codex_idle_minutes * 60, self.codex_cache_minutes * 60)
            policy_provider, endpoint = "openai", "openai-codex-oauth"
        else:
            return None
        helper = Path(os.environ.get(
            "FLEET_CACHE_POLICY_HELPER", str(Path.home() / "HelmCortex/FORGE/bin/cache-policy")
        )).expanduser()
        policy = Path(os.environ.get(
            "FLEET_CACHE_POLICY_PATH",
            str(Path.home() / "HelmCortex/ROOTS/DotRoot/agent-session/centre/data/cache-policy.json"),
        )).expanduser()
        try:
            completed = subprocess.run(
                [str(helper), "resolve", "--policy", str(policy), "--harness", "ductor",
                 "--provider", policy_provider, "--endpoint", endpoint, "--model", model,
                 "--fallback-compact", str(int(fallback[0])),
                 "--fallback-cache", str(int(fallback[1]))],
                capture_output=True, text=True, timeout=5, check=True,
            )
            decision = json.loads(completed.stdout)
            return float(decision["compact_before_seconds"]), float(decision["cache_expires_seconds"])
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            return fallback


class IdleCompactor:
    """Background loop that compacts idle main sessions per provider."""

    def __init__(self, orch: Orchestrator) -> None:
        self._orch = orch
        self._home = orch._paths.sessions_path.parent
        self._state_path = self._home / _STATE_FILE
        self._task: asyncio.Task[None] | None = None
        self._compacting: set[str] = set()

    # -- lifecycle ------------------------------------------------------------

    def start(self) -> None:
        settings = self._settings()
        if not settings.enabled:
            logger.info("Idle compaction disabled in config")
            return
        self._task = asyncio.create_task(self._run())
        logger.info(
            "Idle compaction started (claude %.0fm/%.0fm, codex %.0fm/%.0fm)",
            settings.claude_idle_minutes,
            settings.claude_cache_minutes,
            settings.codex_idle_minutes,
            settings.codex_cache_minutes,
        )

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    def _settings(self) -> IdleCompactSettings:
        return IdleCompactSettings.load(self._orch._paths.config_path)

    # -- state ----------------------------------------------------------------

    def _load_state(self) -> dict[str, str]:
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}

    def _save_state(self, state: dict[str, str]) -> None:
        tmp = self._state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self._state_path)

    # -- loop -----------------------------------------------------------------

    async def _run(self) -> None:
        while True:
            settings = self._settings()
            await asyncio.sleep(settings.tick_seconds)
            if not settings.enabled:
                continue
            try:
                await self._tick(settings)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Idle compaction tick failed")

    async def _tick(self, settings: IdleCompactSettings) -> None:
        state = self._load_state()
        live_ids = set()
        for session in await self._orch._sessions.list_all():
            sid = session.session_id
            if not sid:
                continue
            live_ids.add(sid)
            if state.get(sid) == session.last_active:
                continue  # already compacted for this idle period
            window = settings.window(session.provider, session.model or "unknown")
            if window is None:
                continue
            compact_after, cache_expires = window
            idle = (datetime.now(UTC) - datetime.fromisoformat(session.last_active)).total_seconds()
            if idle < compact_after:
                continue
            if idle >= cache_expires:
                logger.info(
                    "Idle compaction skipped provider=%s session=%s reason=cache_expired idle=%ds",
                    session.provider,
                    sid,
                    int(idle),
                )
                state[sid] = session.last_active
                continue
            done = await self._compact_locked(session, settings)
            if done:
                state[sid] = session.last_active
        stale = [sid for sid in state if sid not in live_ids]
        for sid in stale:
            del state[sid]
        self._save_state(state)

    async def _compact_locked(self, session: SessionData, settings: IdleCompactSettings) -> bool:
        orch = self._orch
        key = session.session_key
        if orch._lock_pool is None:
            return False
        if orch.is_chat_busy(key.chat_id, key.topic_id):
            logger.debug("Idle compaction deferred: chat busy session=%s", session.session_id)
            return False
        lock = orch._lock_pool.get(key.lock_key)
        if lock.locked():
            return False
        async with lock:
            current = await orch._sessions.get_active(key)
            if current is None or current.session_id != session.session_id:
                return True  # replaced or reset: nothing left to compact
            if current.last_active != session.last_active:
                return False  # a turn landed meanwhile; re-evaluate next tick
            logger.info(
                "Idle compaction start provider=%s session=%s model=%s",
                session.provider,
                session.session_id,
                session.model,
            )
            self._compacting.add(key.storage_key)
            try:
                if session.provider == "claude":
                    ok = await self._compact_claude(session, settings)
                else:
                    ok = await self._compact_codex(session, settings)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Idle compaction failed session=%s", session.session_id)
                return True  # do not retry a failing compaction every tick
            finally:
                self._compacting.discard(key.storage_key)
            logger.info(
                "Idle compaction %s provider=%s session=%s",
                "suppressed (verified subscription cache assurance)" if ok == _SUBSCRIPTION_SUPPRESSED
                else "done" if ok else "failed",
                session.provider,
                session.session_id,
            )
            return True

    # -- providers ------------------------------------------------------------

    async def _compact_claude(self, session: SessionData, settings: IdleCompactSettings) -> bool:
        key = session.session_key
        request = AgentRequest(
            prompt="/compact",
            model_override=session.model or None,
            provider_override="claude",
            effort_override=session.reasoning_effort or None,
            chat_id=key.chat_id,
            topic_id=key.topic_id,
            transport=key.transport,
            process_label="idle-compact",
            resume_session=session.session_id,
            timeout_seconds=settings.timeout_seconds,
        )
        response = await self._orch._cli_service.execute(request)
        if response.is_error:
            logger.warning("Claude idle compaction error: %s", response.result[:200])
            return False
        if response.session_id and response.session_id != session.session_id:
            logger.warning(
                "Claude idle compaction returned a new session id %s (kept %s)",
                response.session_id,
                session.session_id,
            )
        return True

    async def _compact_codex(self, session: SessionData, settings: IdleCompactSettings) -> bool | str:
        cli = shutil.which("codex")
        if cli is None:
            logger.warning("Codex idle compaction skipped: codex CLI not on PATH")
            return False
        cwd = str(self._orch._paths.workspace)
        client = _CodexAppServer(cli, cwd)
        try:
            await client.start()
            if await client.verified_subscription_identity() is not None:
                return _SUBSCRIPTION_SUPPRESSED
            resume: dict[str, Any] = {"threadId": session.session_id, "excludeTurns": True}
            if session.model:
                resume["model"] = session.model
            if session.reasoning_effort:
                resume["config"] = {"model_reasoning_effort": session.reasoning_effort}
            await asyncio.wait_for(client.request("thread/resume", resume), 120)
            await asyncio.wait_for(
                client.request("thread/compact/start", {"threadId": session.session_id}), 120
            )
            return await asyncio.wait_for(
                client.wait_compaction(session.session_id), settings.timeout_seconds
            )
        finally:
            await client.close()


class _CodexAppServer:
    """Minimal JSON-RPC client for one ``codex app-server`` compaction."""

    def __init__(self, cli: str, cwd: str) -> None:
        self._cli = cli
        self._cwd = cwd
        self._proc: asyncio.subprocess.Process | None = None
        self._next_id = 0
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._notes: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._reader: asyncio.Task[None] | None = None
        self._environment: dict[str, str] | None = None

    async def start(self) -> None:
        self._environment = os.environ.copy()
        self._proc = await asyncio.create_subprocess_exec(
            self._cli,
            "app-server",
            cwd=self._cwd,
            env=self._environment,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=64 * 1024 * 1024,
        )
        self._reader = asyncio.create_task(self._read())
        await asyncio.wait_for(
            self.request(
                "initialize",
                {"clientInfo": {"name": "ductor-idle-compact", "title": "Ductor", "version": "1"}},
            ),
            60,
        )
        await self._send({"jsonrpc": "2.0", "method": "initialized", "params": {}})

    async def verified_subscription_identity(self) -> dict[str, Any] | None:
        """Read metadata on this idle owner's connection; never refresh or run a turn."""
        proc, reader, environment = self._proc, self._reader, self._environment
        def same_connection() -> bool:
            return (proc is not None and self._proc is proc and proc.returncode is None
                    and reader is not None and self._reader is reader and not reader.done())
        async def read(method: str, params: dict[str, Any]) -> Any:
            if not same_connection():
                raise ValueError("idle management connection changed")
            result = await asyncio.wait_for(self.request(method, params), 5)
            if not same_connection():
                raise ValueError("idle management connection changed")
            return result
        try:
            if (environment is None or any(environment.get(k) for k in _SUBSCRIPTION_ROUTE_ENV)
                    or datetime.now(UTC).timestamp() < _SUBSCRIPTION_CACHE_EFFECTIVE):
                return None
            account = await read("account/read", {"refreshToken": False})
            config = await read("config/read", {"includeLayers": False, "cwd": self._cwd})
            limits = await read("account/rateLimits/read", {})
            if (not isinstance(account, dict) or account.get("requiresOpenaiAuth") is not True
                    or not isinstance(account.get("account"), dict)
                    or account["account"].get("type") != "chatgpt"):
                return None
            route = account.get("workspaceRouting")
            if (not isinstance(route, dict) or route.get("backendOrigin") != "https://chatgpt.com"
                    or not isinstance(route.get("chatgptAccountId"), str)
                    or not route["chatgptAccountId"] or not isinstance(limits, dict)
                    or limits.get("accountId") != route["chatgptAccountId"]):
                return None
            effective = config.get("config") if isinstance(config, dict) else None
            if not isinstance(effective, dict) or effective.get("model_provider") not in (None, "openai"):
                return None
            custom = effective.get("model_providers")
            if custom is not None and (not isinstance(custom, dict) or custom.get("openai") is not None):
                return None
            base = effective.get("chatgpt_base_url")
            # Native config/read materializes this default without an origin.
            origins = config.get("origins")
            if base is not None and (base != "https://chatgpt.com/backend-api/"
                    or not isinstance(origins, dict) or "chatgpt_base_url" in origins):
                return None
            if any(effective.get(k) is not None for k in ("base_url", "openai_base_url", "api_base", "api_key")):
                return None
            # Re-read auth after the other RPCs to refuse account/route switches.
            latest = await read("account/read", {"refreshToken": False})
            if (not isinstance(latest, dict) or latest.get("requiresOpenaiAuth") is not True
                    or latest.get("account") != account["account"]
                    or latest.get("workspaceRouting") != route):
                return None
            return {"account_key": hashlib.sha256(route["chatgptAccountId"].encode()).hexdigest(),
                    "auth_mode": "chatgpt", "endpoint_id": "openai-codex-oauth",
                    "backend_origin": "https://chatgpt.com", "source_url": _SUBSCRIPTION_CACHE_SOURCE,
                    "effective_at": _SUBSCRIPTION_CACHE_EFFECTIVE, "physical_expiry_known": False}
        except (OSError, ValueError, TypeError, RuntimeError, TimeoutError):
            return None

    async def _send(self, message: dict[str, Any]) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        self._proc.stdin.write((json.dumps(message) + "\n").encode())
        await self._proc.stdin.drain()

    async def request(self, method: str, params: dict[str, Any]) -> Any:
        self._next_id += 1
        rid = self._next_id
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        self._pending[rid] = future
        await self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        return await future

    async def _read(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            line = await self._proc.stdout.readline()
            if not line:
                break
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if "id" in message and "method" not in message:
                future = self._pending.pop(message["id"], None)
                if future is not None and not future.done():
                    if "error" in message:
                        future.set_exception(RuntimeError(str(message["error"])))
                    else:
                        future.set_result(message.get("result"))
            elif "id" in message and "method" in message:
                # A server request (approval, elicitation): compaction needs none.
                await self._send(
                    {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "declined"}}
                )
            else:
                await self._notes.put(message)
        for future in self._pending.values():
            if not future.done():
                future.set_exception(RuntimeError("codex app-server exited"))
        await self._notes.put({"method": "__eof__", "params": {}})

    async def wait_compaction(self, thread_id: str) -> bool:
        """Wait for the compaction turn's completion, not only the start ACK."""
        started = False
        turn_id: str | None = None
        while True:
            message = await self._notes.get()
            method = message.get("method", "")
            if method == "__eof__":
                return False
            params = message.get("params") or {}
            turn = params.get("turn") if isinstance(params.get("turn"), dict) else {}
            if (params.get("threadId") or turn.get("threadId")) != thread_id:
                continue
            if method == "turn/started":
                started = True
                raw = params.get("turnId") or turn.get("id")
                turn_id = str(raw) if raw is not None else None
                continue
            if not started or method not in {"turn/completed", "turn/failed", "turn/interrupted"}:
                continue
            raw = params.get("turnId") or turn.get("id")
            if turn_id is not None and raw is not None and str(raw) != turn_id:
                continue
            error = params.get("error") or turn.get("error")
            status = params.get("status") or turn.get("status")
            if method != "turn/completed" or error or status in {"failed", "interrupted"}:
                logger.warning("Codex compaction turn ended method=%s status=%s error=%s", method, status, error)
                return False
            return True

    async def close(self) -> None:
        if self._proc is not None and self._proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                self._proc.terminate()
            with contextlib.suppress(asyncio.TimeoutError, ProcessLookupError):
                await asyncio.wait_for(self._proc.wait(), 10)
            if self._proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    self._proc.kill()
        if self._reader is not None:
            self._reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader


def start_idle_compaction(orch: Orchestrator) -> IdleCompactor:
    compactor = IdleCompactor(orch)
    compactor.start()
    orch._idle_compactor = compactor  # type: ignore[attr-defined]
    return compactor


async def stop_idle_compaction(orch: Orchestrator) -> None:
    compactor = getattr(orch, "_idle_compactor", None)
    if compactor is not None:
        await compactor.stop()
