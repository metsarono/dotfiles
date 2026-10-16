#!/usr/bin/env python3
"""Delete Telegram permission prompts for requests the approval gate allowed.

Usage: telegram_permission_recall.py <hook-start-epoch>   (hook event JSON on stdin)
See agents-approval-telegram-recall.org for the identification rules.
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PREFIX = '\U0001f510 Permission: '
SWEEP_SECONDS = 8.0
SETTLE_SECONDS = 3.0  # our prompt is posted while the hook runs; the next request comes later
PROBE_AHEAD = 12
TAIL_BYTES = 4 * 1024 * 1024
ANCHOR_RES = (
    re.compile(r'message_id=\\?"(\d+)\\?"'),
    re.compile(r'sent \(id: (\d+)\)'),
)
LOG = Path(os.path.expanduser('~/.local/state/dotcortex/telegram-permission-recall.jsonl'))


def _log(**row):
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps({'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'), **row}) + '\n')
    except OSError:
        pass


def _token(state_dir):
    try:
        text = (state_dir / '.env').read_text(encoding='utf-8')
    except OSError:
        return None
    for line in text.splitlines():
        match = re.fullmatch(r'\s*TELEGRAM_BOT_TOKEN\s*=\s*(\S+)\s*', line)
        if match:
            return match.group(1)
    return None


def _chat(state_dir):
    try:
        access = json.loads((state_dir / 'access.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    chats = access.get('allowFrom') if isinstance(access, dict) else None
    if not isinstance(chats, list) or len(chats) != 1 or not re.fullmatch(r'-?\d+', str(chats[0])):
        return None
    return str(chats[0])


def _transcript_tail(path):
    try:
        with open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - TAIL_BYTES))
            data = handle.read().decode('utf-8', errors='replace')
    except (OSError, TypeError):
        return None
    return data if size <= TAIL_BYTES else data.split('\n', 1)[-1]


def _anchor(tail):
    ids = [int(m) for regex in ANCHOR_RES for m in regex.findall(tail)]
    return max(ids) if ids else None


def _logged_floor(session):
    """Highest message id this session's earlier sweeps saw or deleted.

    The transcript anchor only moves when a Telegram message enters the
    session; prompts alone keep raising the chat's ids, so after twelve
    unanswered-by-text prompts they ran past the probe range and were never
    seen (Admiral 7316). Earlier sweeps record how far the chat has got."""
    try:
        with LOG.open('rb') as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - 262144))
            lines = handle.read().decode('utf-8', 'replace').splitlines()
    except OSError:
        return None
    best = None
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or row.get('session') != session:
            continue
        for key in ('seen', 'message_id'):
            if key == 'message_id' and row.get('action') != 'deleted':
                continue  # an anomaly row may name a later request's prompt
            value = row.get(key)
            if type(value) is int and (best is None or value > best):
                best = value
    return best


def _unresolved(tail):
    """Unresolved tool calls in the newest assistant message only.

    Parallel tool calls share one assistant message id, so that batch is the
    only place another live request can be waiting. A call interrupted or
    refused long ago never gets a tool_result in the transcript; counting it
    stalled every later sweep (Admiral 7409)."""
    uses, results, last_group = {}, set(), None
    for line in tail.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        message = row.get('message') if isinstance(row, dict) else None
        content = message.get('content') if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        group = message.get('id') or row.get('uuid')
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get('type') == 'tool_use' and block.get('id'):
                uses[block['id']] = group
                last_group = group
            elif block.get('type') == 'tool_result' and block.get('tool_use_id'):
                results.add(block['tool_use_id'])
    return {use for use, group in uses.items() if group == last_group and use not in results}


def _call(base, token, method, payload):
    request = urllib.request.Request(
        f'{base}/bot{token}/{method}', data=json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return json.loads(response.read() or b'{}')
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read() or b'{}')
        except ValueError:
            return {'ok': False, 'description': f'http {exc.code}'}
    except (OSError, ValueError):
        return {'ok': False, 'description': 'transport'}


def sweep(event, started, *, state_dir, base, now=time.time, sleep=time.sleep, sweep_seconds=SWEEP_SECONDS,
          settle_seconds=SETTLE_SECONDS):
    """Return the deleted message id as a one-item list (empty when nothing qualifies)."""
    decided = now()  # the wrapper starts this right after the gate allowed
    session = event.get('session_id', '') if isinstance(event, dict) else ''
    token, chat = _token(state_dir), _chat(state_dir)
    if not token or not chat:
        _log(session=session, action='skip', why='no_token' if not token else 'chat_not_single')
        return []
    tail = _transcript_tail(event.get('transcript_path')) if isinstance(event, dict) else None
    if tail is None:
        _log(session=session, action='skip', why='no_transcript')
        return []
    if len(_unresolved(tail)) > 1:
        _log(session=session, action='skip', why='other_request_pending')
        return []
    anchor = _anchor(tail)
    floor = _logged_floor(session) if session else None
    if anchor is not None and floor is not None:
        anchor = max(anchor, floor)
    if anchor is None:
        _log(session=session, action='skip', why='no_anchor')
        return []
    done, deleted, seen = set(), [], None
    deadline = min(started + sweep_seconds, decided + settle_seconds)
    while now() < deadline:
        for message_id in range(anchor + 1, anchor + 1 + PROBE_AHEAD):
            if message_id in done:
                continue
            reply = _call(base, token, 'editMessageReplyMarkup', {'chat_id': chat, 'message_id': message_id})
            if not reply.get('ok'):
                description = str(reply.get('description', ''))
                if 'not found' not in description:
                    done.add(message_id)  # user message, button-less bot message, or other refusal
                    seen = message_id if seen is None else max(seen, message_id)
                continue
            done.add(message_id)
            message = reply.get('result') if isinstance(reply.get('result'), dict) else {}
            text, date = message.get('text', ''), message.get('date')
            in_window = isinstance(date, int) and int(started) - 1 <= date <= int(decided) + 1
            if not (isinstance(text, str) and text.startswith(PREFIX) and in_window):
                _log(session=session, action='anomaly', message_id=message_id, why='stripped_but_not_a_windowed_permission')
                if isinstance(text, str) and text.startswith(PREFIX):
                    deadline = 0  # a later request's prompt: stop before touching anything newer
                    break  # and never record it as seen: its own sweep must still reach it
                seen = message_id if seen is None else max(seen, message_id)
                continue
            seen = message_id if seen is None else max(seen, message_id)
            if _call(base, token, 'deleteMessage', {'chat_id': chat, 'message_id': message_id}).get('ok'):
                deleted.append(message_id)
                _log(session=session, action='deleted', message_id=message_id)
            deadline = 0  # one request, one prompt
            break
        sleep(0.5)
    _log(session=session, action='swept', anchor=anchor, deleted=deleted, **({'seen': seen} if seen is not None else {}))
    return deleted


def main(argv):
    state = os.environ.get('TELEGRAM_STATE_DIR')
    if not state or len(argv) != 2:
        _log(action='skip', why='no_state_dir' if not state else 'bad_argv')
        return 0
    try:
        started = float(argv[1])
        event = json.loads(sys.stdin.read(1024 * 1024))
    except ValueError:
        _log(action='skip', why='bad_input')
        return 0
    base = os.environ.get('TELEGRAM_API_BASE', 'https://api.telegram.org').rstrip('/')
    sweep(event, started, state_dir=Path(state), base=base)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
