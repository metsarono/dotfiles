"""Atomic idle admission on Ductor's existing encrypted input surface."""
from __future__ import annotations

import asyncio
import logging
import re
from ductor_bot.api.busy_state import _loopback, main_busy_state
from ductor_bot.session.key import SessionKey

logger = logging.getLogger(__name__)
PROTOCOL = "ductor.idle_prompt.v2"


def idle_peer_allowed(server, request):
    return bool(server._config.token and _loopback(server._config.host)
        and _loopback(request.remote or "")
        and not any(name.lower() == "forwarded" or name.lower().startswith("x-forwarded-")
                    for name in request.headers))


def _claimable(lock):
    # asyncio.Lock.acquire's uncontended fast path has no suspension. An unlocked
    # lock with a notified-but-not-resumed waiter is NOT that path. Fail closed
    # on a different lock implementation instead of guessing its await semantics.
    return (type(lock) is asyncio.Lock and not lock.locked()
            and not any(not waiter.cancelled() for waiter in (lock._waiters or ())))


async def _run_turn(orch, server, channel, key, text, start):
    try:
        await start.wait()
        result = await orch.handle_message_streaming(key, text)
        from ductor_bot.bus.adapters import from_webhook_wake
        from ductor_bot.bus.envelope import LockMode
        envelope = from_webhook_wake(key.chat_id, text)
        envelope.topic_id = key.topic_id
        envelope.transport = key.transport
        envelope.result_text = result.text
        envelope.status = "success"
        envelope.lock_mode = LockMode.NONE
        await orch._message_bus.submit(envelope)
        logger.info("Idle-admitted turn completed key=%s", key.storage_key)
        await channel.send({"type": "result", "text": result.text,
                            "stream_fallback": result.stream_fallback})
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Idle-admitted turn failed key=%s", key.storage_key)


async def handle_idle_message(orch, server, channel, key, data):
    request_id = data.get("request_id")
    async def reply(status):
        await channel.send({"type": "idle_admission", "request_id": request_id,
                            "session_key": key.storage_key, "status": status})
    if (set(data) != {"type", "request_id", "session_key", "text", "mirror_to_telegram"}
            or not isinstance(request_id, str) or not re.fullmatch(r"[0-9a-f]{32}", request_id)
            or not isinstance(data.get("text"), str) or not data["text"].strip()
            or len(data["text"]) > 16000 or data["session_key"] != key.storage_key
            or data["mirror_to_telegram"] is not True):
        await reply("invalid"); return
    bus = getattr(orch, "_message_bus", None)
    telegram = any(getattr(item, "transport_name", None) == "tg"
                   for item in getattr(bus, "_transports", ()))
    if (not channel.idle_prompt_allowed or key != SessionKey(chat_id=server._default_chat_id)
            or key.transport != "tg" or not callable(getattr(bus, "submit", None)) or not telegram):
        await reply("unavailable"); return
    try:
        state = await main_busy_state(orch, server)
        if (server._idle_stopping or state["known"] is not True
                or state["session_key"] != key.storage_key):
            await reply("unavailable"); return
        if state["busy"] is not False:
            await reply("busy"); return
        pools = (server._lock_pool, orch._lock_pool)
        locks = []
        for pool in pools:
            lock = pool.get(key.lock_key)
            if lock not in locks:
                locks.append(lock)
        if not all(_claimable(lock) for lock in locks):
            await reply("busy"); return
        # No suspension occurs between the authoritative decision and these
        # uncontended acquire calls. Both pools remain held for the whole turn.
        acquired = []
        try:
            for lock in locks:
                await lock.acquire()
                acquired.append(lock)
            start = asyncio.Event()
            task = asyncio.create_task(_run_turn(orch, server, channel, key, data["text"], start))
        except BaseException:
            for lock in reversed(acquired):
                lock.release()
            raise
        server._idle_tasks.add(task)
        def settled(done):
            # A task cancelled before its coroutine first runs still owns locks.
            for lock in reversed(locks):
                lock.release()
            server._idle_tasks.discard(done)
        task.add_done_callback(settled)
    except Exception:
        logger.exception("Idle prompt authority unavailable")
        await reply("unavailable"); return
    try:
        await reply("accepted")
    finally:
        # Admission is irrevocable even if sending the ACK fails. The watcher
        # records ambiguity; the server still runs the accepted turn once.
        start.set()
