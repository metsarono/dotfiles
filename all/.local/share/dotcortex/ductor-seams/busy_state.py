"""Read-only main-session status for the direct API, never prompt admission."""
from __future__ import annotations

import ipaddress
import logging

from aiohttp import web
from ductor_bot.session.key import SessionKey

logger = logging.getLogger(__name__)


async def main_busy_state(orch, server):
    key = SessionKey(chat_id=server._default_chat_id)
    result = {"busy": True, "known": False, "session_key": key.storage_key, "reasons": []}
    pool = getattr(orch, "_lock_pool", None)
    registry = getattr(orch, "_process_registry", None)
    sessions = getattr(orch, "_sessions", None)
    compactor = getattr(orch, "_idle_compactor", None)
    api_pool = getattr(server, "_lock_pool", None)
    if (key.chat_id <= 0 or pool is None or registry is None or sessions is None
            or api_pool is None or compactor is None
            or not isinstance(getattr(compactor, "_compacting", None), set)):
        result["reasons"] = ["authority_missing"]
        return result
    session = await sessions.get_active(key)
    if session is None or not session.session_id or session.session_key != key:
        result["reasons"] = ["session_unknown"]
        return result
    # All live signals are read synchronously after the asynchronous lookup.
    signals = {
        "active_turn": registry.has_active(key.chat_id),
        "session_lock": pool.is_locked(key.lock_key),
        "api_lock": api_pool.is_locked(key.lock_key),
        "compaction": key.storage_key in compactor._compacting,
    }
    if any(type(value) is not bool for value in signals.values()):
        raise RuntimeError("invalid busy authority result")
    result["reasons"] = [name for name, active in signals.items() if active]
    result["known"] = True
    result["busy"] = any(signals.values())
    return result


def _loopback(value):
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


async def handle_busy_request(server, request):
    headers = {"Cache-Control": "no-store"}
    def reply(body, status=200):
        return web.json_response(body, status=status, headers=headers)
    if not server._config.token or not server._verify_bearer(request):
        return reply({"error": "unauthorized"}, 401)
    if (not _loopback(server._config.host) or not _loopback(request.remote or "")
            or any(name.lower() == "forwarded" or name.lower().startswith("x-forwarded-")
                   for name in request.headers)):
        return reply({"error": "loopback_required"}, 403)
    if request.query:
        return reply({"error": "default_session_only"}, 400)
    handler = server._busy_state_handler
    if handler is None:
        return reply({"busy": True, "known": False, "error": "authority_missing"}, 503)
    try:
        state = await handler()
        if getattr(server, "_idle_message_handler", None) is not None:
            state["idle_prompt"] = "ductor.idle_prompt.v2"
        return reply(state)
    except Exception:
        logger.exception("Main-session busy authority failed")
        return reply({"busy": True, "known": False, "error": "busy_state_unavailable"}, 503)
