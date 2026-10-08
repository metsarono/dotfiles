"""Keep filesystem search from blocking Nanobot's gateway event loop."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
from pathlib import Path
import signal
import time
from typing import Any

from nanobot.agent.tools.base import ToolResult
from nanobot.security.workspace_access import (
    bind_workspace_scope,
    current_workspace_scope,
    reset_workspace_scope,
)

_MAX_CHILDREN = 4
_TIMEOUT_SECONDS = 60.0


def _child(send: Any, tool: Any, params: dict[str, Any], scope: Any) -> None:
    if os.name == "posix":
        os.setsid()
        try:
            Path("/proc/self/comm").write_text("nanobot-search\n", encoding="utf-8")
        except OSError:
            pass
    token = bind_workspace_scope(scope) if scope is not None else None
    try:
        result = asyncio.run(tool.execute(**params))
        send.send((bool(getattr(result, "is_error", False)), str(result)))
    except BaseException as exc:
        send.send((True, f"Error: {type(exc).__name__}: {exc}"))
    finally:
        if token is not None:
            reset_workspace_scope(token)
        send.close()


async def isolated_search(tool: Any, params: dict[str, Any], name: str,
                          timeout: float = _TIMEOUT_SECONDS) -> str:
    """Run native search in a spawned process; return a bounded tool result."""
    if name not in {"grep", "find_files"}:
        return ToolResult.error(f"Error: unsupported isolated tool {name}")
    active = [child for child in multiprocessing.active_children()
              if child.name == "nanobot-search"]
    if len(active) >= _MAX_CHILDREN:
        return ToolResult.error("Error: search workers are still blocked; retry later")
    ctx = multiprocessing.get_context("spawn")
    receive, send = ctx.Pipe(duplex=False)
    child = ctx.Process(target=_child, args=(send, tool, params,
                                             current_workspace_scope()),
                        name="nanobot-search", daemon=True)
    started = False
    try:
        child.start()
        started = True
        send.close()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if receive.poll(0):
                try:
                    is_error, result = receive.recv()
                except EOFError:
                    return ToolResult.error(f"Error: {name} search worker exited without a result")
                return ToolResult.error(result) if is_error else result
            if not child.is_alive():
                return ToolResult.error(f"Error: {name} search worker exited without a result")
            await asyncio.sleep(0.05)
        return ToolResult.error(
            f"Error: {name} search worker timed out after {timeout:g} seconds; "
            "narrow the path and retry"
        )
    except asyncio.CancelledError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        return ToolResult.error(f"Error: cannot start {name} search worker: {exc}")
    finally:
        receive.close()
        send.close()
        if started:
            child.join(timeout=0.1)
            if child.is_alive():
                try:
                    if os.name == "posix" and os.getpgid(child.pid) == child.pid:
                        os.killpg(child.pid, signal.SIGKILL)
                    else:
                        child.kill()
                except (OSError, ProcessLookupError):
                    pass
                child.join(timeout=0.1)
