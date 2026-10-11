#!/usr/bin/env python3
"""Shared unattended presence and queue contract; no model, replay or secret reads."""
import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
import time
from zoneinfo import ZoneInfo

DEFERRED_ACTION = 'continue with other work or a genuinely different in-policy method; never retry, rephrase or route around this refusal'
DEFERRED_MESSAGE = "deferred: queued for the Admiral's morning review; " + DEFERRED_ACTION


def _utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds')


def _unattended(manifest):
    section = manifest.get('unattended', {}) if isinstance(manifest, dict) else {}
    if not isinstance(section, dict):
        raise ValueError('unattended')
    return section


def _minutes(section, key, default):
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 1440:
        raise ValueError(key)
    return value


def _presence_path(manifest):
    value = _unattended(manifest).get('presence_file', '~/.local/state/dotcortex/admiral-last-seen')
    if not isinstance(value, str) or not value:
        raise ValueError('presence file')
    return Path(value).expanduser()


def _presence_mtime(manifest):
    section = _unattended(manifest)
    host = section.get('presence_host')
    if host is not None:
        if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', host) or 'YOUR_' in host:
            raise ValueError('presence host')
        # One authority on the peer; the same helper stamps and reads it. Never
        # recurse to a second authority or evaluate any request-provided shell.
        argv = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
                '-o', 'KbdInteractiveAuthentication=no', '-o', 'PreferredAuthentications=publickey',
                '-o', 'ConnectTimeout=1', '-o', 'ConnectionAttempts=1', host, 'approval-presence status']
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=0.7, check=False)
            value = float(result.stdout.strip())
            return value if result.returncode == 0 and math.isfinite(value) else None
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return None
    try:
        info = _presence_path(manifest).lstat()
        return info.st_mtime if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 else None
    except FileNotFoundError:
        return None


def _away_status(manifest, now=None):
    try:
        section = _unattended(manifest)
        flag = section.get('away_flag', '~/.config/dotcortex/approval-away')
        if not isinstance(flag, str) or not flag:
            raise ValueError('away flag')
        if Path(flag).expanduser().exists():
            return True, 'away_flag'
        current = now or datetime.datetime.now(datetime.timezone.utc)
        window = _minutes(section, 'presence_window_minutes', 20) * 60
        stamp = _presence_mtime(manifest)
        if stamp is not None and 0 <= current.timestamp() - stamp <= window:
            return False, 'presence'
        if section.get('enabled') is False:
            return False, 'disabled'
        quiet = section.get('quiet_hours', {})
        if not isinstance(quiet, dict):
            raise ValueError('quiet hours')
        if quiet.get('enabled', bool(section)) is False:
            return False, 'present'
        current = current.astimezone(ZoneInfo(quiet.get('timezone', 'Australia/Melbourne')))
        def minute(raw):
            if not isinstance(raw, str) or not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', raw):
                raise ValueError('quiet time')
            hour, mins = map(int, raw.split(':'))
            return hour * 60 + mins
        start, end = minute(quiet.get('start', '23:00')), minute(quiet.get('end', '08:00'))
        if start == end:
            raise ValueError('empty quiet window')
        clock = current.hour * 60 + current.minute
        away = start <= clock < end if start < end else clock >= start or clock < end
        return away, 'quiet_hours' if away else 'present'
    except (ValueError, TypeError, OSError, KeyError):
        return True, 'invalid_unattended'


def _presence_stamp(manifest):
    section = _unattended(manifest)
    host = section.get('presence_host')
    if host is not None:
        if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', host) or 'YOUR_' in host:
            raise ValueError('presence host')
        # Same authority as status. A transport failure must not pretend the
        # shared stamp was refreshed; local seats do not invent a second clock.
        result = subprocess.run(['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
            '-o', 'KbdInteractiveAuthentication=no', '-o', 'PreferredAuthentications=publickey',
            '-o', 'ConnectTimeout=1', '-o', 'ConnectionAttempts=1', host, 'approval-presence stamp'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.7, check=False)
        return result.returncode == 0
    path = _presence_path(manifest)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise OSError('invalid presence stamp')
        os.fchmod(fd, 0o600)
        os.utime(fd, None)
        return True
    finally:
        os.close(fd)


def _presence_prompt(event, manifest):
    if not isinstance(event, dict) or event.get('hook_event_name') != 'UserPromptSubmit':
        return False
    prompt = event.get('prompt')
    if not isinstance(prompt, str):
        return False
    # Channel tags are authored by Claude Code; only the opening envelope is
    # inspected, never a forged tag further down in a message body.
    if prompt.lstrip().startswith('<channel '):
        match = re.match(r'\s*<channel\s+([^>]+)>', prompt)
        attrs = dict(re.findall(r'([A-Za-z_]+)="([^"<>]*)"', match.group(1))) if match else {}
        user = _unattended(manifest).get('admiral_telegram_user_id', 'YOUR_ADMIRAL_USER_ID')
        if not isinstance(user, str) or not user.isdecimal() or attrs.get('user_id') != user or 'telegram' not in attrs.get('source', '').casefold():
            return False
    else:
        # Known non-human prompt sources never refresh presence. Unknown
        # explicit sources fail closed; ordinary terminal input has no source.
        if event.get('source') not in (None, 'terminal', 'user') or event.get('is_automated') is True:
            return False
        if prompt.lstrip().startswith(('<task-notification', '<channel', '<system-reminder')):
            return False
    return _presence_stamp(manifest)


def _present_refusal(manifest):
    section = manifest.get('gate_inversion', {}) if isinstance(manifest, dict) else {}
    return 'deny' if isinstance(section, dict) and section.get('present_refusal') == 'deny' else 'ask'


def _morning_queue_path():
    return Path(os.environ.get('SO_APPROVAL_MORNING_QUEUE') or Path.home() / '.local/state/dotcortex/approval-morning-queue.jsonl')


@contextlib.contextmanager
def _morning_queue_file():
    path = _morning_queue_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise OSError('queue is not a private regular file')
        os.fchmod(fd, 0o600)
        deadline = time.monotonic() + 1.0
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('queue lock deadline')
                time.sleep(0.005)
        with os.fdopen(fd, 'a+', encoding='utf-8') as file:
            fd = None
            yield file
    finally:
        if fd is not None:
            os.close(fd)


def _normalized_command(command):
    if not isinstance(command, str):
        return command
    # Quoting and line breaks are semantic. Collapse only unquoted horizontal
    # whitespace; never shlex.join away the difference between '$VAR' and "$VAR".
    out, quote, escaped = [], None, False
    for char in command.strip():
        if escaped:
            out.append(char); escaped = False; continue
        if char == '\\' and quote != "'":
            escaped = True; out.append(char); continue
        if char == quote:
            quote = None
        elif quote is None and char in {"'", '"'}:
            quote = char
        if quote is None and char in ' \t':
            if not out or out[-1] == ' ':
                continue
            char = ' '
        out.append(char)
    return ''.join(out)


def _queue_identity(event, manifest):
    payload = event if isinstance(event, dict) else {}
    tool = payload.get('tool_input') if isinstance(payload.get('tool_input'), dict) else {}
    seat = manifest.get('coordinator_ops', {}).get('seat_account') if isinstance(manifest.get('coordinator_ops'), dict) else None
    seat = seat or _unattended(manifest).get('seat_id') or str(Path.home())
    # Different directories and different content writes are different requests.
    data = {**tool}
    data.pop('description', None); data.pop('timeout', None)
    if 'command' in data:
        data['command'] = _normalized_command(data['command'])
    sha = hashlib.sha256(json.dumps([payload.get('tool_name'), payload.get('cwd'), data], sort_keys=True, default=str).encode()).hexdigest()
    intent = payload.get('approval_intent') or tool.get('description') or ''
    intent = ' '.join(intent.split()) if isinstance(intent, str) else ''
    if intent.casefold() in {'run shell command','bash command','write file','edit file'}:
        intent = ''
    return seat, sha, intent[:1024]


def _queue_read(file):
    file.seek(0)
    items = {}
    for index, line in enumerate(file):
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError('invalid queue record')
        # Historical append-only records are retained, with a stable legacy ID.
        if 'id' not in record:
            try:
                manifest = _runtime_manifest()
            except (OSError, ValueError, TypeError):
                manifest = {}
            payload = record.get('request') or {'tool_name':record.get('tool'), 'cwd':record.get('cwd'), 'tool_input':{'command':record.get('command')}, 'session_id':record.get('session')}
            seat, sha, intent = _queue_identity(payload,manifest)
            record['id'] = 'legacy-' + hashlib.sha256(json.dumps([seat,intent or sha]).encode()).hexdigest()[:24]
            previous = items.get(record['id'],{})
            stamp = record.get('timestamp') or _utc()
            record.update(schema='dotcortex.approval.queue.v2',seat=seat,intent=intent,
                command_hashes=list(dict.fromkeys(previous.get('command_hashes',[])+[sha])),
                requests=previous.get('requests',[])+([payload] if payload not in previous.get('requests',[]) else []),
                count=previous.get('count',0)+1,first_seen=previous.get('first_seen',stamp),last_seen=stamp,
                context=previous.get('context',{}),request=payload)
        record.setdefault('status', 'open')
        items[record['id']] = record
    return list(items.values())


def _queue_append(file, item):
    file.seek(0, 2)
    item['revision'] = item.get('revision', 0) + 1
    file.write(json.dumps(item, ensure_ascii=True, separators=(',', ':')) + '\n')
    file.flush()
    os.fsync(file.fileno())


def _queue_git(repo, *args):
    env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_TERMINAL_PROMPT='0', LC_ALL='C')
    try:
        result = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', repo, *args],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=0.3, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _queue_context(event):
    context = event.get('approval_context') if isinstance(event, dict) else None
    context = dict(context) if isinstance(context, dict) else {}
    cwd = event.get('cwd') if isinstance(event, dict) else None
    if isinstance(cwd, str) and os.path.exists(Path(cwd) / '.git'):
        branch = _queue_git(cwd, 'symbolic-ref', '--quiet', '--short', 'HEAD')
        tip = _queue_git(cwd, 'rev-parse', 'HEAD')
        base = _queue_git(cwd, 'rev-parse', 'refs/heads/master')
        context.update(repo=cwd, branch=branch, branch_tip=tip, master_at_enqueue=base)
        if (Path(cwd) / '.git').is_file():
            context['worktree'] = cwd
    return context


def _queue_upsert(event, reason, away_reason, manifest, status='open'):
    payload = event if isinstance(event, dict) else {}
    tool = payload.get('tool_input') if isinstance(payload.get('tool_input'), dict) else {}
    seat, sha, intent = _queue_identity(payload, manifest)
    now = _utc()
    context = _queue_context(payload)  # bounded probes stay OUTSIDE the interprocess lock
    with _morning_queue_file() as file:
        items = _queue_read(file)
        item = next((x for x in items if x.get('seat') == seat and x['status'] in {'open', 'held'}
            and (sha in x.get('command_hashes', []) or intent and intent == x.get('intent'))), None)
        inflight = item is not None and item.get('status') == 'held'
        if item is None:
            item = {'schema':'dotcortex.approval.queue.v2', 'id':secrets.token_hex(12), 'seat':seat,
                'count':0, 'first_seen':now, 'command_hashes':[], 'requests':[], 'context':context}
        if not inflight and item.get('request') != event:
            item['context']=context
            for key in ('approved_by','approved_at','approved_request_sha','confirmation','confirmed_at'):
                item.pop(key,None)
        item['count'] += 1
        item['last_seen'] = now
        item['command_hashes'] = list(dict.fromkeys(item['command_hashes'] + [sha]))
        # Preserve every distinct exact request so same-intent dedupe never loses
        # the earlier command. The Desk renders one logical item, with history.
        if payload not in item['requests']:
            item['requests'].append(payload)
        if not inflight:
            item.update(timestamp=now, tool=payload.get('tool_name'), command=tool.get('command'),
                cwd=payload.get('cwd'), session=payload.get('session_id'), intent=intent or item.get('intent', ''),
                reason=reason, away_reason=away_reason, request=event)
        elif not item.get('intent') and intent:
            item['intent'] = intent
        # Dedupe counts/history may grow while held, but the nonce is bound to
        # the ORIGINAL request, preview and session until that hook finishes.
        # A second pending hook must not overwrite a first hook's nonce.
        if item.get('status') != 'held':
            item['status'] = status
        _queue_append(file, item)
        return item['id']


def _queue_morning(event, reason, away_reason):
    try:
        _queue_upsert(event, reason, away_reason, {})
        return True
    except (OSError, ValueError, TypeError, TimeoutError):
        return False


def _queue_update(item_id, update):
    with _morning_queue_file() as file:
        item = next((x for x in _queue_read(file) if x['id'] == item_id), None)
        if item is None or update(item) is False:
            return False
        _queue_append(file, item)
        return True



def _queue_intent(item_id, text):
    if not isinstance(text,str) or not text.strip() or '\n' in text:
        raise ValueError('one-line intent required')
    intent=' '.join(text.split())[:1024]
    with _morning_queue_file() as file:
        items=_queue_read(file)
        item=next((x for x in items if x['id']==item_id and x['status']=='open'),None)
        if item is None:return False
        target=next((x for x in items if x['id']!=item_id and x['status']=='open' and x.get('seat')==item.get('seat') and x.get('intent')==intent),None)
        if target is None:
            item['intent']=intent;_queue_append(file,item);return True
        target['count']+=item['count']
        target['first_seen']=min(target['first_seen'],item['first_seen'])
        latest=max([target,item],key=lambda x:x['last_seen'])
        for key in ('last_seen','timestamp','tool','command','cwd','session','request','context'):
            target[key]=latest.get(key)
        target['command_hashes']=list(dict.fromkeys(target['command_hashes']+item['command_hashes']))
        target['requests']+= [x for x in item['requests'] if x not in target['requests']]
        for key in ('approved_by','approved_at','approved_request_sha','confirmation','confirmed_at'):
            target.pop(key,None)
        item.update(status='obsolete',intent=intent,merged_into=target['id'],resolution='deduplicated into '+target['id'],resolved_at=_utc())
        _queue_append(file,target);_queue_append(file,item)
        return True


def _queue_resolve(item_id, how):
    if not isinstance(how, str) or not how.strip() or '\n' in how:
        raise ValueError('one-line resolution required')
    def update(item):
        if item['status'] != 'open':
            return False
        item.update(status='resolved', resolution=how, resolved_at=_utc())
    return _queue_update(item_id, update)


def _queue_live_allow(event, manifest):
    seat, sha, intent = _queue_identity(event, manifest)
    resolved = []
    if not _morning_queue_path().exists():
        return resolved
    with _morning_queue_file() as file:
        for item in _queue_read(file):
            if item.get('seat') == seat and item['status'] == 'open' and (sha in item.get('command_hashes', []) or intent and intent == item.get('intent')):
                now = _utc()
                item.update(status='resolved', resolution='approved live at ' + now, resolved_at=now)
                _queue_append(file, item)
                resolved.append(item['id'])
    return resolved


def _queue_obsolete_reason(item):
    context = item.get('context', {})
    worktree = context.get('worktree')
    if isinstance(worktree, str) and worktree.startswith('/') and not os.path.exists(worktree):
        return 'worktree gone'
    repo, tip = context.get('repo'), context.get('branch_tip')
    if (isinstance(repo, str) and repo.startswith('/') and context.get('branch') not in (None, 'master')
            and isinstance(tip, str) and re.fullmatch('[0-9a-f]{40,64}', tip)
            and tip != context.get('master_at_enqueue')
            and _queue_git(repo, 'merge-base', '--is-ancestor', tip, 'refs/heads/master') == ''):
        return 'branch landed'
    if context.get('session_ended') is True and context.get('intent_met') is True:
        return 'session ended and intent met'
    return None


def _queue_sweep():
    changed = []
    with _morning_queue_file() as file:
        for item in _queue_read(file):
            if item['status'] == 'held' and item.get('hold_deadline', float('inf')) <= time.time():
                item.update(status='open', away_reason='hold_timeout')
                item.pop('hold_nonce', None)
                _queue_append(file, item)
            if item['status'] == 'open':
                reason = _queue_obsolete_reason(item)
                if reason:
                    item.update(status='obsolete', resolution=reason, resolved_at=_utc())
                    _queue_append(file, item); changed.append(item['id'])
    return changed


def _queue_confirm(item_id, needed, session):
    token = secrets.token_hex(16)
    def update(item):
        if item['status'] != 'open' or session != item.get('session'):
            return False
        if needed is not True:
            item.update(status='obsolete', resolution='seat reports no longer needed', resolved_at=_utc())
        else:
            item.update(confirmation=token, confirmed_session=session, confirmed_at=time.time())
    return token if _queue_update(item_id, update) and needed is True else None




def _queue_authorize(item_id, sender, manifest):
    admiral = _unattended(manifest).get('admiral_telegram_user_id')
    if not isinstance(admiral, str) or not admiral.isdecimal() or sender != admiral:
        return False
    accepted = False
    def update(item):
        nonlocal accepted
        reason = _queue_obsolete_reason(item)
        if item['status'] != 'open' or reason:
            if reason:
                item.update(status='obsolete', resolution=reason, resolved_at=_utc())
            item['ignored_approval_at'] = _utc()
            return
        if item.get('seat') != _queue_identity({}, manifest)[0]:
            return False
        item.update(approved_at=time.time(), approved_by=sender,
            approved_request_sha=_queue_identity(item['request'],manifest)[1])
        accepted = True
    _queue_update(item_id,update)
    return accepted


def _queue_claim(item_id, confirmation):
    result = None
    def update(item):
        nonlocal result
        reason = _queue_obsolete_reason(item)
        if item['status'] != 'open':
            # Approval of a resolved/obsolete/claimed item is audited, no replay.
            item['ignored_approval_at'] = _utc()
            return
        if reason:
            item.update(status='obsolete', resolution=reason, resolved_at=_utc(), ignored_approval_at=_utc())
            return
        request_sha = _queue_identity(item['request'], {'unattended':{}})[1]
        if (not item.get('approved_by') or item.get('approved_request_sha') != request_sha
                or not 0 <= time.time()-item.get('approved_at',0) <= 120):
            return False
        if (not confirmation or item.get('confirmation') != confirmation
                or not 0 <= time.time() - item.get('confirmed_at', 0) <= 60):
            return False
        item.update(status='replay_claimed', claimed_at=_utc())
        item.pop('confirmation', None)
        result = item['request']
    _queue_update(item_id, update)
    return result is not None, result


def _hold_seconds(manifest):
    return _minutes(_unattended(manifest), 'hold_timeout_minutes', 10) * 60


def _queue_begin_hold(item_id, manifest):
    nonce = secrets.token_hex(16)
    def update(item):
        if item['status'] != 'held' or item.get('hold_nonce'):
            return False
        item.pop('hold_delivery_failed',None)
        item.update(hold_nonce=nonce, hold_deadline=time.time()+_hold_seconds(manifest))
    return nonce if _queue_update(item_id, update) else None


def _queue_answer(item_id, nonce, behavior, sender, manifest):
    admiral = _unattended(manifest).get('admiral_telegram_user_id')
    if not isinstance(admiral, str) or not admiral.isdecimal() or sender != admiral or behavior not in {'allow', 'deny'}:
        return False
    def update(item):
        if (item['status'] != 'held' or item.get('hold_nonce') != nonce
                or item.get('hold_deadline', 0) <= time.time() or item.get('hold_answer')
                or item.get('seat') != _queue_identity({}, manifest)[0]):
            return False
        item.update(hold_answer=behavior, answered_at=_utc(), answered_by=sender)
    accepted = _queue_update(item_id, update)
    if accepted:
        _presence_stamp(manifest)
    return accepted


def _queue_hold_result(item_id, nonce):
    with _morning_queue_file() as file:
        item = next((x for x in _queue_read(file) if x['id'] == item_id), {})
        if item.get('status') != 'held' or item.get('hold_nonce') != nonce:
            return None
        if item.get('hold_delivery_failed') is True:return 'unavailable'
        return item.get('hold_answer') if time.time() <= item.get('hold_deadline', 0) else None


def _finish_hold(item_id, nonce, outcome):
    def update(item):
        if item['status'] != 'held' or item.get('hold_nonce') != nonce:
            return False
        if outcome == 'allow':
            item.update(status='resolved', resolution='approved live at '+_utc(), resolved_at=_utc())
        else:
            item.update(status='open', away_reason='hold_timeout' if outcome == 'timeout' else 'human_denied' if outcome == 'deny' else 'away_flag' if outcome == 'away_flag' else 'hold_unavailable')
        item.pop('hold_nonce', None)
        item.pop('hold_answer', None)
    return _queue_update(item_id, update)


def _notify_hold(event, reason, item_id, nonce, manifest):
    argv = _unattended(manifest).get('hold_notify_argv')
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or not x or 'YOUR_' in x for x in argv) or not argv[0].startswith('/'):
        return 'unconfigured'
    # The credential-owning adapter receives the private preview directly; no
    # hash-only notice can give the Admiral enough information to approve.
    message = {'schema':'dotcortex.approval.hold.v1', 'id':item_id, 'nonce':nonce,
        'reason':reason, 'request':event, 'timeout_seconds':_hold_seconds(manifest)}
    try:
        result = subprocess.run(argv, input=json.dumps(message, ensure_ascii=True), text=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.75, check=False)
        return 'sent' if result.returncode == 0 else 'failed'
    except (OSError, subprocess.TimeoutExpired):
        return 'unavailable'


def _hold_admiral(event, reason, manifest):
    # No terminal-only fallback: a missing Telegram bridge immediately defers.
    seconds = _hold_seconds(manifest)
    item_id = _queue_upsert(event, reason, 'presence', manifest, status='held')
    nonce = _queue_begin_hold(item_id, manifest)
    if nonce is None:
        return 'unavailable', item_id
    deadline = time.monotonic()+seconds
    outcome = 'timeout'
    try:
        if _notify_hold(event, reason, item_id, nonce, manifest) != 'sent':
            outcome = 'unavailable'
        else:
            while time.monotonic() < deadline:
                flag = _unattended(manifest).get('away_flag','~/.config/dotcortex/approval-away')
                if Path(flag).expanduser().exists():
                    outcome = 'away_flag'; break
                result = _queue_hold_result(item_id, nonce)
                if result in {'allow', 'deny', 'unavailable'}:
                    outcome = result; break
                time.sleep(min(0.05, max(0, deadline-time.monotonic())))
    finally:
        # Timeout, cancellation and bridge failure all leave an actionable item.
        if not _finish_hold(item_id, nonce, outcome):
            outcome = 'unavailable'
    return outcome, item_id



def telegram_presence_main():
    try:
        value = json.loads(sys.stdin.read(4097))
        manifest = _runtime_manifest()
        user = _unattended(manifest).get('admiral_telegram_user_id')
        if not isinstance(value, dict) or set(value) != {'sender'} or not isinstance(user, str) or not user.isdecimal() or value['sender'] != user:
            return 1
        return 0 if _presence_stamp(manifest) else 1
    except Exception:
        return 1


def observe_main():
    try:
        event = json.loads(sys.stdin.read(1024*1024+1))
        manifest = _runtime_manifest()
        if event.get('hook_event_name') != 'PostToolUse' or _away_status(manifest)[0] or not _morning_queue_path().exists():
            return 0
        resolved = _queue_live_allow(event, manifest)
        if resolved:
            # Native Telegram approval closes outside the PermissionRequest
            # hook. Successful execution is the authority observation, not an
            # agent-authored claim that a request was approved.
            path = Path(os.environ.get('SO_APPROVAL_KIKIN_LOG') or Path.home()/'.local/state/dotcortex/claude-approval-kikin.jsonl')
            path.parent.mkdir(parents=True,exist_ok=True)
            record = {'ts':_utc(),'session':event.get('session_id'),'tool':event.get('tool_name'),
                'decision':'allow','reason':'post_tool_use_live','input_sha':_queue_identity(event,manifest)[1][:12],
                'resolved_queue_ids':resolved}
            fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'a') as file:file.write(json.dumps(record,separators=(',',':'))+'\n')
        return 0
    except Exception:
        return 0


def session_end_main():
    try:
        event=json.loads(sys.stdin.read(1024*1024+1))
        if event.get('hook_event_name') != 'SessionEnd' or not _morning_queue_path().exists():return 0
        with _morning_queue_file() as file:
            for item in _queue_read(file):
                if item.get('session') == event.get('session_id') and item['status'] == 'open':
                    item.setdefault('context',{})['session_ended']=True
                    _queue_append(file,item)
        _queue_sweep()
    except Exception:
        pass
    return 0


def _runtime_manifest():
    path = os.environ.get('SO_APPROVAL_KIKIN_MANIFEST')
    if not path:
        path = str(Path.home()/'.config/dotcortex/claude-approval-canary.kikin.v1.local.json')
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict):
        raise ValueError('manifest')
    return value


def presence_main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prompt', 'stamp', 'status'])
    args = parser.parse_args()
    try:
        manifest = _runtime_manifest()
        if args.action == 'prompt':
            _presence_prompt(json.loads(sys.stdin.read(1024*1024+1)), manifest)
        else:
            # Authority commands never forward; the local manifest determines
            # the one actual stamp file regardless of client's routing setting.
            manifest = {**manifest, 'unattended':{**_unattended(manifest)}}
            manifest['unattended'].pop('presence_host', None)
            if args.action == 'stamp':
                _presence_stamp(manifest)
            else:
                print(_presence_mtime(manifest) or 0)
        return 0
    except Exception:
        return 1


def verdict_main():
    try:
        value = json.loads(sys.stdin.read(4097))
        if isinstance(value,dict) and set(value)=={'id','nonce','action'} and value['action']=='delivery_failed':
            def update(item):
                if item['status']!='held' or item.get('hold_nonce')!=value['nonce']:return False
                item['hold_delivery_failed']=True
            return 0 if _queue_update(value['id'],update) else 1
        if isinstance(value, dict) and set(value) == {'id','nonce','action'} and value['action'] == 'preview':
            manifest = _runtime_manifest()
            with _morning_queue_file() as file:
                item = next((x for x in _queue_read(file) if x['id'] == value['id']), {})
                admiral = _unattended(manifest).get('admiral_telegram_user_id')
                if (item.get('status') != 'held' or item.get('hold_nonce') != value['nonce']
                        or item.get('hold_deadline',0) <= time.time()
                        or item.get('seat') != _queue_identity({},manifest)[0]
                        or not isinstance(admiral,str) or not admiral.isdecimal()):
                    return 1
                print(json.dumps({'request':item['request'],'admiral':admiral,'timeout_seconds':_hold_seconds(manifest)},ensure_ascii=True))
            return 0
        if not isinstance(value, dict) or set(value) != {'id','nonce','behavior','sender'}:
            return 1
        return 0 if _queue_answer(value['id'], value['nonce'], value['behavior'], value['sender'], _runtime_manifest()) else 1
    except Exception:
        return 1


def queue_main():
    parser = argparse.ArgumentParser(description='Live smart approval queue; never executes requests.')
    parser.add_argument('--clear', action='store_true', help='legacy print-and-clear under the same lock')
    commands = parser.add_subparsers(dest='action')
    listing = commands.add_parser('list'); listing.add_argument('--json', action='store_true')
    commands.add_parser('sweep')
    resolve = commands.add_parser('resolve'); resolve.add_argument('id'); resolve.add_argument('--how', required=True)
    intent = commands.add_parser('intent'); intent.add_argument('id'); intent.add_argument('--text', required=True)
    confirm = commands.add_parser('confirm'); confirm.add_argument('id'); confirm.add_argument('--session', required=True)
    confirm.add_argument('--needed', choices=['yes','no'], required=True)
    approve = commands.add_parser('approve'); approve.add_argument('id'); approve.add_argument('--sender',required=True)
    claim = commands.add_parser('claim'); claim.add_argument('id'); claim.add_argument('--confirmation', required=True)
    ended = commands.add_parser('session-ended'); ended.add_argument('session'); ended.add_argument('--intent-met', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'resolve':
            return 0 if _queue_resolve(args.id, args.how) else 1
        if args.action == 'intent':
            return 0 if _queue_intent(args.id,args.text) else 1
        if args.action == 'confirm':
            token = _queue_confirm(args.id, args.needed == 'yes', args.session)
            if token: print(token)
            return 0 if token or args.needed == 'no' else 1
        if args.action == 'approve':
            return 0 if _queue_authorize(args.id,args.sender,_runtime_manifest()) else 1
        if args.action == 'claim':
            ok, request = _queue_claim(args.id, args.confirmation)
            if ok: print(json.dumps(request, ensure_ascii=True))
            return 0 if ok else 1
        if args.action == 'session-ended':
            with _morning_queue_file() as file:
                for item in _queue_read(file):
                    if item.get('session') == args.session and item['status'] == 'open':
                        item.setdefault('context', {}).update(session_ended=True, intent_met=args.intent_met)
                        _queue_append(file, item)
        _queue_sweep()
        if args.action == 'sweep': return 0
        with _morning_queue_file() as file:
            records = _queue_read(file)
            if getattr(args, 'json', False):
                print(json.dumps(records, ensure_ascii=True))
            else:
                if not records: print('No queued requests.')
                for status, label in [('open','Awaiting the Admiral'),('held','Held for the Admiral'),('resolved','Done while you were away'),('obsolete','Obsolete'),('replay_claimed','Replay claimed')]:
                    entries = [x for x in records if x['status'] == status]
                    if entries:
                        print(label)
                        sessions = {}
                        for record in entries: sessions.setdefault(record.get('session') or '(unknown session)', []).append(record)
                        for session, items in sessions.items():
                            print('Session '+json.dumps(session, ensure_ascii=True)+f' ({len(items)} requests)')
                            for item in items: print(json.dumps(item, ensure_ascii=True, sort_keys=True))
            sys.stdout.flush()
            if args.clear:
                file.seek(0); file.truncate(0); file.flush(); os.fsync(file.fileno())
        return 0
    except (OSError, ValueError, TypeError, TimeoutError):
        print('Approval queue unavailable', file=sys.stderr)
        return 1
