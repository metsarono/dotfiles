#!/usr/bin/env python3
"""Conditional Claude mail wake: private SSH topology, PTY-owner admission."""
from __future__ import annotations

import array
import contextlib
import importlib.machinery
import importlib.util
import json
import math
import os
import re
import select
import signal
import socket
import stat
import shutil
import subprocess
import sys
import threading
import time
import types
import uuid
from pathlib import Path

PROTOCOL = "claude.mailcortex_idle.v2"
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
CHANNEL = re.compile(r"claude-[0-9a-f]{32}\Z")
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")


def validate_target(target):
    if not isinstance(target, dict) or set(target) != {"tmux_socket", "tmux_session", "runtime_dir"}:
        raise ValueError("invalid Claude target")
    if not isinstance(target["tmux_session"], str) or not NAME.fullmatch(target["tmux_session"]):
        raise ValueError("invalid tmux session")
    for field in ("tmux_socket", "runtime_dir"):
        value = target[field]
        if (not isinstance(value, str) or not 1 <= len(value) <= 512 or not value.startswith("/")
                or ".." in Path(value).parts or any(ord(c) < 32 for c in value)):
            raise ValueError("invalid Claude runtime path")


def validate_record(record):
    if record["harness"] != "claude":
        raise ValueError("Claude transport requires Claude harness")
    for field in ("ssh_target", "remote_user"):
        if not isinstance(record[field], str) or not NAME.fullmatch(record[field]):
            raise ValueError("invalid Claude SSH identity")
    validate_target(record["claude_target"])
    for field, low, high in (("coalesce_seconds", 1, 30), ("rate_limit_seconds", 30, 86400)):
        v = record[field]
        if type(v) not in (int, float) or not math.isfinite(v) or not low <= v <= high:
            raise ValueError("invalid Claude timing")


class ClaudeSSHAdapter:
    def __init__(self, watcher=None, runner=subprocess.run, *, error_type=None, refusal_type=None):
        self.error = error_type or watcher.WatcherError
        self.refusal = refusal_type or watcher.PromptNotAdmittedError
        self.runner = runner

    def request(self, record, operation, **fields):
        request = {"protocol": PROTOCOL, "request_id": uuid.uuid4().hex,
                   "operation": operation, "target": record["claude_target"], **fields}
        # The only interpolated shell value has the strict NAME grammar.
        command = ("sudo -n -H -u " + record["remote_user"] +
                   " -- /bin/sh -c 'exec \"$HOME/.local/bin/mailcortex-claude-wake\"'")
        argv = ["/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
                "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
                "--", record["ssh_target"], command]
        try:
            validate_record(record)
            result = self.runner(argv, input=json.dumps(request) + "\n", text=True,
                                 capture_output=True, check=False, timeout=25)
            value = json.loads(result.stdout)
            if (result.returncode or not isinstance(value, dict) or value.get("protocol") != PROTOCOL
                    or value.get("request_id") != request["request_id"]
                    or value.get("target") != request["target"]):
                raise ValueError("invalid acknowledgement")
            return value
        except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as error:
            raise self.error("Claude SSH authority unavailable or delivery outcome unknown") from error

    def resolve_idle_pane(self, record):
        value = self.request(record, "status")
        if value.get("status") == "busy":
            return None
        if value.get("status") != "idle" or not valid_owner(value.get("owner")):
            raise self.error("Claude conditional idle authority unavailable")
        return value["owner"]

    def deliver(self, record, target, prompt):
        value = self.request(record, "admit", owner=target, text=prompt)
        if value.get("status") in {"busy", "unavailable", "invalid"}:
            raise self.refusal(value["status"])
        if value.get("status") != "accepted" or value.get("owner") != target:
            raise self.error("Claude admission outcome unknown")


def process_start_time(pid):
    """Linux process-instance fence; never read command lines or environments."""
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def recover_attempts(w, seat, now):
    # Called under the watcher's scan flock: no current admission can own these.
    # Reconcile even if the original mail has since moved out of new/.
    directory = w.MAILCORTEX.runtime_root() / "receipts" / seat
    for path in directory.glob("*.json"):
        if path.is_symlink():
            raise w.WatcherError("unsafe Claude wake receipt")
        value = json.loads(path.read_text())
        mid = value["message_id"]
        receipt = w.safe_receipt(seat, mid)
        if path != w.MAILCORTEX.receipt_path(seat, mid):
            raise w.WatcherError("Claude wake receipt identity mismatch")
        if receipt["wake_state"] == "injecting":
            w.MAILCORTEX.write_wake_receipt(seat, mid, "delivery_unknown",
                reason="interrupted_attempt", recovery_at=now,
                # Retain the original attempt time for the cooldown.
                wake_updated_at=receipt["wake_updated_at"],
                wake_error="Interrupted Claude admission; operator review required; no automatic retry")
            w.report_error(seat, receipt.get("filename", "batch"), w.WatcherError(
                "Recovered interrupted Claude admission to delivery_unknown; operator review required"))


def quarantine_message(w, seat, mailbox, path, error, now):
    """Preserve invalid mail and a durable diagnostic; never let it starve a seat."""
    quarantine = mailbox / "quarantine"
    quarantine.mkdir(mode=0o700, exist_ok=True)
    if quarantine.is_symlink() or not quarantine.is_dir():
        raise w.WatcherError("unsafe Claude quarantine")
    token = uuid.uuid4().hex
    destination = quarantine / token
    marker = w.MAILCORTEX.runtime_root() / "rejected" / seat / (token + ".json")
    diagnostic = dict(schema="mailcortex.rejected.v1", seat=seat, filename=path.name,
                      first_seen_at=now, reason=w.diagnostic(error),
                      quarantine_filename=token, state="quarantine_pending")
    # First persist the diagnosis. A crash before rename leaves reviewable evidence.
    w.MAILCORTEX.atomic_json(marker, diagnostic)
    path.rename(destination)
    w.MAILCORTEX.fsync_directory(path.parent)
    w.MAILCORTEX.fsync_directory(quarantine)
    w.MAILCORTEX.atomic_json(marker, dict(diagnostic, state="quarantined"))
    w.report_error(seat, path.name, w.WatcherError("Malformed Claude mail quarantined; operator review required"))


def scan_batch(api, seat, record, adapter, now):
    """One durable, bounded-window wake for every pending Message-ID in a scan."""
    w = types.SimpleNamespace(**api)
    mailbox = w.MAILCORTEX.mail_root() / record["mailbox"]
    recover_attempts(w, seat, now)
    pending = []
    seen = set()
    for path in sorted((mailbox / "new").iterdir()):
        if path.is_symlink() or not path.is_file() or path.name.startswith("."):
            continue
        try:
            mid = w.message_id(path)
        except Exception as error:
            try:
                quarantine_message(w, seat, mailbox, path, error, now)
            except Exception as quarantine_error:
                w.report_error(seat, path.name, quarantine_error)
            continue
        if mid in seen:
            continue
        seen.add(mid)
        old = w.safe_receipt(seat, mid)
        if old and old["wake_state"] in {"injecting", "injected", "delivery_unknown"}:
            continue
        first = old.get("first_observed_at", now) if old else now
        w.MAILCORTEX.write_wake_receipt(seat, mid, "queued", filename=path.name,
            first_observed_at=first, reason="coalescing", wake_updated_at=now)
        pending.append((mid, path, first))
    if not pending:
        return 0

    def receipts(state, **fields):
        for mid, path, first in pending:
            w.MAILCORTEX.write_wake_receipt(seat, mid, state, filename=path.name,
                first_observed_at=first, wake_updated_at=now, **fields)

    # Fixed window from the oldest pending arrival: continuous mail cannot starve a wake.
    if now < min(item[2] for item in pending) + record["coalesce_seconds"]:
        return 0
    last = w.latest_injection(seat)
    for path in (w.MAILCORTEX.runtime_root() / "receipts" / seat).glob("*.json"):
        if path.is_symlink():
            raise w.WatcherError("unsafe Claude wake receipt")
        value = json.loads(path.read_text())
        if value.get("wake_state") in {"injecting", "delivery_unknown"}:
            receipt = w.safe_receipt(seat, value["message_id"])
            if path != w.MAILCORTEX.receipt_path(seat, value["message_id"]):
                raise w.WatcherError("Claude wake receipt identity mismatch")
            last = max(last, float(receipt["wake_updated_at"]))
    if last and now < last + record["rate_limit_seconds"]:
        receipts("queued", reason="rate_limited")
        return 0
    try:
        owner = adapter.resolve_idle_pane(record)
    except Exception as error:
        receipts("queued", reason="transport_unavailable", wake_error=w.diagnostic(error))
        w.report_error(seat, "batch", error)
        return 0
    if owner is None:
        receipts("queued", reason="busy")
        return 0
    # Persist the ENTIRE batch before any admission request. A crash here cannot replay it.
    receipts("injecting", pane_id=owner, attempt_id=uuid.uuid4().hex,
             attempt_pid=os.getpid(), attempt_start_time=process_start_time(os.getpid()),
             attempt_started_at=now)
    prompt = (f"[mailcortex-wake] MailCortex: new mail is waiting in {record['mailbox']} on {record['host']}. "
              "Open /inbox, read all pending mail, and handle it with your harness tools.")
    try:
        adapter.deliver(record, owner, prompt)
    except w.PromptNotAdmittedError as error:
        receipts("queued", reason=error.reason, wake_error=w.diagnostic(error))
        return 0
    except Exception as error:
        receipts("delivery_unknown", reason="delivery_error", wake_error=w.diagnostic(error))
        w.report_error(seat, "batch", error)
        return 0
    receipts("injected", pane_id=owner)
    return 1


def valid_owner(owner):
    return (isinstance(owner, dict)
            and set(owner) == {"channel", "session_id", "supervisor_pid", "supervisor_start_time", "epoch", "pane_id", "pane_tty"}
            and isinstance(owner["channel"], str) and CHANNEL.fullmatch(owner["channel"]) is not None
            and isinstance(owner["session_id"], str) and re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", owner["session_id"]) is not None
            and type(owner["supervisor_pid"]) is int and owner["supervisor_pid"] > 0
            and isinstance(owner["supervisor_start_time"], str)
            and re.fullmatch(r"[0-9]{1,32}", owner["supervisor_start_time"]) is not None
            and type(owner["epoch"]) is int and owner["epoch"] >= 0
            and isinstance(owner["pane_id"], str) and re.fullmatch(r"%[0-9]+", owner["pane_id"]) is not None
            and isinstance(owner["pane_tty"], str) and re.fullmatch(r"/dev/pts/[0-9]+", owner["pane_tty"]) is not None)


def private_path(path, kind):
    info = path.lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077 or not kind(info.st_mode):
        raise ValueError("unsafe Claude runtime ownership")


def private_tmux_socket(path):
    """tmux uses group-writable sockets behind an owner-only directory."""
    parent = path.parent.lstat()
    info = path.lstat()
    if (parent.st_uid != os.getuid() or not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or info.st_uid != os.getuid() or not stat.S_ISSOCK(info.st_mode)
            or info.st_mode & 0o007):
        raise ValueError("unsafe Claude runtime ownership")


def descendant(pid, ancestor):
    for _ in range(32):
        path = Path(f"/proc/{pid}")
        try:
            owner_uid = path.stat().st_uid
        except FileNotFoundError:
            # Dead supervisor recorded in a stale state directory. Not a
            # descendant, and never a reason to abort discovery for the seat.
            return False
        if owner_uid != os.getuid():
            return False
        if pid == ancestor:
            return True
        fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
        pid = int(fields[1])
        if pid <= 1:
            return False
    return False


def tmux_binary() -> str:
    """Locate tmux without assuming it lives in /usr/bin.

    This host runs tmux from the Guix profile. A hardcoded /usr/bin/tmux raised
    FileNotFoundError inside resolve_owner, which the watcher surfaced as
    "Claude local conditional idle authority unavailable" and every wake for the
    seat stayed queued - a fail-closed that looked like a wedged receipt.
    """
    candidates = [
        shutil.which("tmux"),
        "/usr/bin/tmux",
        "/usr/local/bin/tmux",
        str(Path.home() / ".guix-extra-profiles/core/core/bin/tmux"),
    ]
    for candidate in candidates:
        if candidate and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError("tmux not found; Claude wake authority unavailable")


def resolve_owner(target):
    validate_target(target)
    private_tmux_socket(Path(target["tmux_socket"]))
    result = subprocess.run([tmux_binary(), "-S", target["tmux_socket"], "list-panes", "-s",
        "-t", "=" + target["tmux_session"], "-F",
        "#{session_name}\t#{pane_id}\t#{pane_pid}\t#{pane_tty}\t#{pane_dead}\t#{pane_in_mode}"],
        text=True, capture_output=True, check=True, timeout=3)
    rows = result.stdout.strip().splitlines()
    if len(rows) != 1:
        raise ValueError("tmux target is ambiguous")
    session, pane, pid, tty, dead, mode = rows[0].split("\t")
    if session != target["tmux_session"] or dead != "0" or mode != "0":
        raise ValueError("tmux target unavailable")
    root = Path(target["runtime_dir"]) / "claude-idle-compaction"
    private_path(root, stat.S_ISDIR)
    matches = []
    # Non-recursive discovery under one explicit runtime root, never a home tree.
    for path in root.glob("claude-*/state.json"):
        private_path(path.parent, stat.S_ISDIR)
        private_path(path, stat.S_ISREG)
        state = json.loads(path.read_text())
        supervisor = state["supervisor_pid"]
        if type(supervisor) is not int or supervisor <= 0 or not descendant(supervisor, int(pid)):
            continue
        started = state.get("supervisor_start_time")
        try:
            current_start = process_start_time(supervisor)
        except OSError:
            # Stale state directory for a supervisor that has exited. Skip it
            # instead of letting discovery die on a dead pid.
            continue
        if started != current_start:
            continue
        owner = {"channel": state["channel"], "session_id": state["session_id"],
                 "supervisor_pid": supervisor, "supervisor_start_time": started,
                 "epoch": state["completed_turn_epoch"],
                 "pane_id": pane, "pane_tty": tty}
        if not valid_owner(owner) or path.parent.name != owner["channel"]:
            raise ValueError("invalid Claude owner")
        control = path.parent / "control.sock"
        private_path(control, stat.S_ISSOCK)
        if state.get("control_socket") != str(control):
            raise ValueError("invalid Claude control socket")
        matches.append((owner, control))
    if len(matches) != 1:
        raise ValueError("Claude owner absent or ambiguous")
    return matches[0]


def socket_request(path, request):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(path))
        connection.sendall((json.dumps(request) + "\n").encode())
        data = bytearray()
        while b"\n" not in data:
            chunk = connection.recv(4096)
            if not chunk or len(data) + len(chunk) > 16384:
                raise ValueError("incomplete Claude acknowledgement")
            data.extend(chunk)
        return json.loads(data.split(b"\n", 1)[0])


def remote_request(request):
    ack = {"protocol": PROTOCOL, "target": request.get("target"),
           "request_id": request.get("request_id"), "status": "invalid"}
    operation = request.get("operation")
    required = {"protocol", "request_id", "operation", "target"}
    if operation == "admit": required |= {"owner", "text"}
    if (set(request) != required or request.get("protocol") != PROTOCOL
            or not isinstance(request.get("request_id"), str) or not REQUEST_ID.fullmatch(request["request_id"])
            or operation not in {"status", "admit"}):
        return ack
    try:
        owner, path = resolve_owner(request["target"])
        if operation == "admit" and request["owner"] != owner:
            return dict(ack, status="unavailable")
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        return dict(ack, status="unavailable")
    control = {"kind": "control", "channel": owner["channel"], "protocol": PROTOCOL,
               "request_id": request["request_id"], "owner": owner, "target": request["target"],
               "command": "mailcortex-" + operation}
    if operation == "admit": control["text"] = request["text"]
    try:
        value = socket_request(path, control)
        if (not isinstance(value, dict) or value.get("protocol") != PROTOCOL
                or value.get("request_id") != request["request_id"] or value.get("owner") != owner
                or value.get("status") not in {"idle", "busy", "accepted", "unavailable", "invalid"}):
            raise ValueError("missing conditional capability")
        return dict(ack, status=value["status"], owner=owner)
    except (OSError, ValueError, KeyError, TypeError):
        # Once IPC was attempted a lost response cannot prove non-admission.
        return dict(ack, status="unknown")


def pending_terminal(owner):
    try:
        ready, _, _ = select.select([sys.stdin.fileno(), owner.master_fd, owner.socket.fileno()], [], [], 0)
        return bool(ready) or bool(owner.input_classifier.buffer) or owner.input_classifier.in_bracketed_paste or owner.stdin_eof
    except (OSError, ValueError, AttributeError):
        return True


def owner_matches(owner, expected):
    try:
        return (valid_owner(expected) and expected["channel"] == owner.channel
                and expected["session_id"] == owner.session_id
                and expected["supervisor_pid"] == os.getpid()
                and expected["supervisor_start_time"] == owner.mailcortex_start_time
                and expected["supervisor_start_time"] == process_start_time(os.getpid())
                and expected["epoch"] == owner.completed_turn_epoch
                and expected["pane_id"] == os.environ.get("TMUX_PANE")
                and expected["pane_tty"] == os.ttyname(sys.stdin.fileno()))
    except (OSError, ValueError, AttributeError):
        return False


# Measured against Claude Code 2.1.296 in isolated native/software-cursor PTYs.
# Render acknowledgement plus a quiet window separates text from the submit key.
WAKE_SCREEN_TIMEOUT = 0.75
WAKE_RENDER_QUIET = 0.1


def wake_prompt_matches(classifier, text):
    """Prove the current boxed draft has exactly the printable wake text.

    Retain internal spacing and attributes. Ink wraps at words (dropping one
    separator) or inside a long word; only those two joins are allowed. Extra
    rows, grey/faint text, truncated escapes and unbounded boxes refuse.
    None means a cleared prompt, where rendered hints may count as empty.
    """
    screen = classifier.screen
    visible = classifier._visible_text()
    if (not screen.complete()
            or any(m in visible.lower() for m in classifier.STRONG_BLOCKERS)):
        return False
    lines = screen.lines()
    prompts = [(row, cells) for row, cells in lines
               if classifier.PROMPT_RE.fullmatch("".join(c[0] for c in cells))]
    if not prompts:
        return False
    row, cells = prompts[-1]
    glyph = next(i for i, c in enumerate(cells) if c[0] == classifier.prompt_glyph)
    start = glyph + 2
    if glyph != 0 or len(cells) < start or cells[1][0] not in {" ", "\xa0"}:
        return False
    borders = [r for r, cs in lines if r > row and len(cs) >= 3
               and set("".join(c[0] for c in cs).strip()) == {classifier.prompt_border}]
    if not borders:
        return False
    end = borders[0]
    if not row <= screen.row < end or end - row > 16:
        return False
    if text is None:
        return classifier.prompt_input_state() == "empty"
    by_row = dict(lines)
    parts = []
    for r in range(row, end):
        cs = by_row.get(r, [])
        if r != row and any(c[0] != " " for c in cs[:start]):
            return False
        content = cs[start:]
        while content and content[-1][0] == " ":
            content = content[:-1]
        if not content:
            return False
        for column, cell in enumerate(content, start):
            char, faint, bold, inverse, foreground = cell
            if (len(char) != 1 or not 32 <= ord(char) <= 126 or faint or bold
                    or foreground in classifier.ghost_foregrounds
                    or inverse and (r, column) != (screen.row, screen.column)):
                return False
        parts.append("".join(c[0] for c in content))
    candidates = {parts[0]}
    for part in parts[1:]:
        candidates = {candidate + join + part for candidate in candidates for join in ("", " ")
                      if text.startswith(candidate + join + part)}
    return text in candidates


def wake_wait_screen(owner, text):
    """Observe fresh output while keeping all local forwarding locked out."""
    deadline = time.monotonic() + WAKE_SCREEN_TIMEOUT
    quiet_at = None
    observed = False
    while time.monotonic() < deadline:
        if owner._mailcortex_poll_screen(min(0.02, max(0, deadline - time.monotonic()))):
            observed = True
            quiet_at = time.monotonic()
        if observed and wake_prompt_matches(owner.screen_classifier, text):
            if text is None or time.monotonic() - quiet_at >= WAKE_RENDER_QUIET:
                return True
    return False


def wake_submit_unsafe(owner, expected):
    # The turn is already claimed. Do not borrow the idle-only gate or erase
    # the input-dirty veto just because the expected wake is on screen.
    return (not owner_matches(owner, expected) or pending_terminal(owner)
            or owner.status != "active" or owner.lifecycle_health != "wired"
            or owner.mailcortex_input_dirty or owner.compacting
            or owner.recovery_pending or owner.recovery_awaiting
            or owner.transcript_gate_blocked or owner.transcript_partial
            or owner.transcript_quiescence_deadline is not None)


def wake_failure(owner, ack, stage, reason):
    owner.mailcortex_input_dirty = True
    owner.mailcortex_delivery = dict(request_id=ack["request_id"], status="unknown",
                                    stage=stage, reason=reason)
    owner.last_state_transition = "mailcortex-submit-failed"
    owner._guard_log("mailcortex-submit-failed", **owner.mailcortex_delivery)
    owner._write_state()
    return dict(ack, status="unknown", reason=reason)


def owner_control(owner, request, warm):
    ack = {"protocol": PROTOCOL, "request_id": request.get("request_id"),
           "owner": request.get("owner"), "status": "invalid"}
    operation = request.get("command")
    required = {"kind", "channel", "protocol", "request_id", "owner", "target", "command"}
    if operation == "mailcortex-admit": required.add("text")
    if (set(request) != required or request.get("kind") != "control" or request.get("protocol") != PROTOCOL
            or request.get("channel") != owner.channel
            or not isinstance(request.get("request_id"), str) or not REQUEST_ID.fullmatch(request["request_id"])
            or operation not in {"mailcortex-status", "mailcortex-admit"}):
        return ack
    try: validate_target(request["target"])
    except ValueError: return ack
    if operation == "mailcortex-admit":
        text = request.get("text")
        if (not isinstance(text, str) or not 1 <= len(text) <= 400
                or any(ord(c) < 32 or ord(c) > 126 for c in text)):
            return ack
    # One lock owns input forwarding, screen reads, lifecycle changes and admission.
    # Legacy supervisors without the barrier are deliberately incapable of writing.
    if (not hasattr(owner, "mailcortex_admission_lock")
            or not callable(getattr(owner, "_mailcortex_poll_screen", None))):
        return dict(ack, status="unavailable")
    with owner.mailcortex_admission_lock:
        if not owner_matches(owner, request["owner"]):
            return dict(ack, status="unavailable")
        owner._record_transcript_activity()
        if admission_busy(owner) or pending_terminal(owner):
            return dict(ack, status="busy")
        if operation == "mailcortex-status":
            return dict(ack, status="idle")
        claimed = False
        stage = "text"
        try:
            # A mutex alone cannot stop the child producing a permission screen.
            # Obtain a kernel-acknowledged pause of the child's process tree first.
            with owner._mailcortex_barrier():
                if owner._mailcortex_refresh_screen() or admission_busy(owner) or pending_terminal(owner):
                    return dict(ack, status="busy")
                owner._record_transcript_activity()
                if not owner_matches(owner, request["owner"]):
                    return dict(ack, status="unavailable")
                if admission_busy(owner) or pending_terminal(owner):
                    return dict(ack, status="busy")
                # Claim in memory. No state-file I/O or callbacks between the last
                # screen/input re-read and the write. The paused child cannot redraw;
                # human bytes remain in the parent terminal until the lease ends.
                if owner._mailcortex_refresh_screen() or pending_terminal(owner):
                    return dict(ack, status="busy")
                if owner.screen_state != "idle":
                    return dict(ack, status="busy")
                owner.status = "active"
                owner.timer_deadline = None
                owner.timer_kind = None
                owner.timer_generation += 1
                owner.last_lifecycle_activity = warm.now()
                owner.last_state_transition = "mailcortex-admitted"
                claimed = True
                owner.mailcortex_delivery = dict(request_id=ack["request_id"], status="pending", stage=stage)
                warm.write_all(owner.master_fd, request["text"].encode("ascii"))
            # The guardian resumes the child; the owner lock remains held.
            stage = "render"
            if not wake_wait_screen(owner, request["text"]):
                return wake_failure(owner, ack, stage, "draft-not-observed")
            stage = "submit"
            with owner._mailcortex_barrier():
                owner._mailcortex_refresh_screen()
                owner._record_transcript_activity()
                if wake_submit_unsafe(owner, request["owner"]):
                    return wake_failure(owner, ack, stage, "submit-guard-changed")
                # Final read under the acknowledged pause, then no callbacks
                # or state-file I/O before the standalone submit keystroke.
                owner._mailcortex_refresh_screen()
                if (not wake_prompt_matches(owner.screen_classifier, request["text"])
                        or wake_submit_unsafe(owner, request["owner"])):
                    return wake_failure(owner, ack, stage, "draft-or-input-changed")
                warm.write_all(owner.master_fd, b"\r")
            stage = "observe"
            if not wake_wait_screen(owner, None):
                return wake_failure(owner, ack, stage, "submission-not-observed")
        except (OSError, ValueError, AttributeError, RuntimeError, TypeError):
            if claimed:
                return wake_failure(owner, ack, stage, "pty-or-barrier-failed")
            return dict(ack, status="unavailable")
        owner.mailcortex_delivery = dict(request_id=ack["request_id"], status="accepted", stage=stage)
        owner._guard_log("mailcortex-admitted")
        owner._write_state()
        return dict(ack, status="accepted")


def wake_idle_boundary(owner):
    if owner.last_normal_stop:
        return owner.last_normal_stop
    if owner.completed_turn_epoch == 0:
        return getattr(owner, "mailcortex_startup_idle_at", None)
    return None


def admission_busy(owner):
    boundary = wake_idle_boundary(owner)
    return (owner.status != "idle" or owner.screen_state != "idle" or owner.lifecycle_health != "wired"
            or owner.compacting or owner.recovery_pending or owner.recovery_awaiting
            or getattr(owner, "mailcortex_input_dirty", True)
            or owner.transcript_gate_blocked or owner.transcript_partial
            or owner.transcript_quiescence_deadline is not None
            or not boundary
            or (owner.last_local_input is not None and owner.last_local_input >= boundary)
            or (owner.last_lifecycle_activity is not None and owner.last_lifecycle_activity > boundary)
            or owner._gate_reason("mailcortex") is not None)


def barrier_guardian(descriptor):
    """An isolated crash guardian owns the stop/resume pairs via pidfds only."""
    handles = []
    with socket.socket(fileno=descriptor) as connection:
        try:
            while True:
                data, ancillary, flags, _address = connection.recvmsg(1, socket.CMSG_SPACE(4))
                if not data or data == b"q":
                    break
                received = []
                for level, kind, value in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        fds = array.array("i")
                        fds.frombytes(value[:len(value) - len(value) % fds.itemsize])
                        received.extend(fds)
                handles.extend(received)
                if data != b"s" or len(received) != 1 or flags & socket.MSG_CTRUNC:
                    raise ValueError("invalid barrier descriptor")
                signal.pidfd_send_signal(received[0], signal.SIGSTOP)
                connection.sendall(b"s")
        finally:
            failure = False
            for handle in reversed(handles):
                try:
                    signal.pidfd_send_signal(handle, signal.SIGCONT)
                except ProcessLookupError:
                    pass
                except OSError:
                    failure = True
                finally:
                    os.close(handle)
            try:
                connection.sendall(b"e" if failure else b"r")
            except OSError:
                pass


@contextlib.contextmanager
def crash_guard():
    """Receive-stop acknowledgement precedes admission; EOF always resumes."""
    parent, child = socket.socketpair()
    process = None
    try:
        parent.settimeout(3)
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                    "--barrier-guardian", str(child.fileno())],
            pass_fds=(child.fileno(),), close_fds=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin"})
        child.close()
        yield parent
    finally:
        child.close()
        try:
            if process is not None:
                parent.sendall(b"q")
                if parent.recv(1) != b"r":
                    raise ValueError("child resume not acknowledged")
        finally:
            parent.close()
            if process is not None:
                process.wait(timeout=3)


def write_wake(fd, data):
    # No spinning against a paused child or replaying a partial write.
    if os.write(fd, data) != len(data):
        raise OSError("partial Claude wake write")


@contextlib.contextmanager
def paused_child(owner):
    """Stop only this owned child tree via pidfds, acknowledging every thread.

    No broad process scan or numeric-PID signal fallback. All process discovery
    stays within explicit /proc/PID/task directories on the proc filesystem.
    Failure to acquire the barrier refuses admission and resumes acquired stops.
    """
    if not owner._pty_still_owned() or not owner.pid:
        raise ValueError("PTY ownership unavailable")
    deadline = time.monotonic() + 0.5
    with crash_guard() as guardian:
        todo = [owner.pid]
        seen = set()
        while todo:
            pid = todo.pop()
            if pid in seen:
                continue
            seen.add(pid)
            if len(seen) > 128 or time.monotonic() >= deadline:
                raise ValueError("child barrier exceeded bound")
            proc = Path(f"/proc/{pid}")
            if proc.stat().st_uid != os.getuid():
                raise ValueError("child owner changed")
            started = process_start_time(pid)
            handle = os.pidfd_open(pid)
            try:
                if process_start_time(pid) != started:
                    raise ValueError("child instance changed")
                # Never resume a process stopped by somebody else.
                if proc.joinpath("stat").read_text().rsplit(")", 1)[1].split()[0] in {"T", "t"}:
                    raise ValueError("child already stopped")
                guardian.sendmsg([b"s"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [handle]))])
                if guardian.recv(1) != b"s":
                    raise ValueError("child stop request not acknowledged")
            finally:
                os.close(handle)
            while True:
                tasks = list(proc.joinpath("task").iterdir())
                if tasks and all(t.joinpath("stat").read_text().rsplit(")", 1)[1].split()[0] == "T" for t in tasks):
                    break
                if time.monotonic() >= deadline:
                    raise ValueError("child stop not acknowledged")
                time.sleep(0.001)
            for task in tasks:
                todo.extend(int(value) for value in task.joinpath("children").read_text().split())
        yield


def launch(argv):
    """Disabled by default: exec the original launcher with the original environment."""
    if os.environ.get("MAILCORTEX_CLAUDE_WAKE") != "1":
        original = str(Path(__file__).resolve().with_name("claude-warm"))
        os.execv(original, [original, *argv])
    path = Path(__file__).resolve().with_name("claude-warm")
    loader = importlib.machinery.SourceFileLoader("mailcortex_warm_owner", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    warm = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = warm
    loader.exec_module(warm)
    base = warm.Supervisor

    class MailOwner(base):
        def __init__(self, *args, **kwargs):
            self.mailcortex_admission_lock = threading.RLock()
            self.mailcortex_start_time = process_start_time(os.getpid())
            self.mailcortex_input_dirty = False
            self.mailcortex_startup_pending = False
            self.mailcortex_startup_idle_at = None
            super().__init__(*args, **kwargs)

        def state(self):
            value = super().state()
            value["supervisor_start_time"] = self.mailcortex_start_time
            value["mailcortex_startup_idle_at"] = self.mailcortex_startup_idle_at
            value["mailcortex_delivery"] = getattr(self, "mailcortex_delivery", None)
            return value

        def _injection_idle_boundary(self, purpose):
            if purpose == "mailcortex":
                return wake_idle_boundary(self)
            return super()._injection_idle_boundary(purpose)

        def _mailcortex_barrier(self):
            return paused_child(self)

        def _mailcortex_refresh_screen(self):
            # Drain under the same lock, without the base's development-channel
            # auto-confirm path. Any output during acquisition aborts this wake.
            changed = False
            for _ in range(16):
                ready, _, _ = select.select([self.master_fd], [], [], 0)
                if not ready:
                    break
                data = os.read(self.master_fd, 65536)
                if not data:
                    raise ValueError("child PTY closed")
                changed = True
                self.screen_classifier.feed(data)
                warm.write_all(sys.stdout.fileno(), data)
            else:
                raise ValueError("child output exceeds barrier bound")
            self._mailcortex_classify_screen()
            return changed

        def _mailcortex_poll_screen(self, timeout):
            ready, _, _ = select.select([self.master_fd], [], [], timeout)
            return self._mailcortex_refresh_screen() if ready else False

        def _mailcortex_classify_screen(self):
            visible = self.screen_classifier._visible_text()
            self.screen_state = self.screen_classifier._classify(visible)
            # The shared attributed model distinguishes display hints from
            # drafts. Local-input tracking remains the first admission veto.
            if (self.screen_classifier.prompt_input_state() != "empty"
                    or any(marker in visible.lower() for marker in self.screen_classifier.STRONG_BLOCKERS)
                    or (self.completed_turn_epoch == 0 and self.last_normal_stop is None
                        and warm.DevelopmentChannelPromptMatcher.TITLE.lower() in visible.lower())):
                self.screen_state = "unknown"

        def _mailcortex_finish_startup(self):
            # SessionStart binds identity, but does not prove the TUI is ready.
            # Never infer startup completion from status "starting" alone.
            if not self.mailcortex_startup_pending or self.status != "starting":
                return
            self._record_transcript_activity()
            self._mailcortex_classify_screen()
            if (not self.mailcortex_startup_pending or self.completed_turn_epoch != 0
                    or self.last_normal_stop is not None or self.last_local_input is not None
                    or self.lifecycle_health != "wired" or self.screen_state != "idle"
                    or self.mailcortex_input_dirty or self.compacting
                    or self.recovery_pending or self.recovery_awaiting
                    or self.transcript_gate_blocked or self.transcript_partial
                    or self.transcript_quiescence_deadline is not None or pending_terminal(self)):
                return
            self.mailcortex_startup_pending = False
            self.mailcortex_startup_idle_at = warm.now()
            self.status = "idle"
            self.last_state_transition = "mailcortex-startup-idle"
            self._guard_log("mailcortex-startup-idle")
            self._write_state()

        def _read_stdin(self):
            with self.mailcortex_admission_lock:
                return super()._read_stdin()

        def _read_master(self):
            with self.mailcortex_admission_lock:
                result = super()._read_master()
                if result:
                    previous = self.screen_state
                    self._mailcortex_classify_screen()
                    if self.screen_state != previous:
                        self._write_state()
                    self._mailcortex_finish_startup()
                return result

        def _record_input_observations(self, observations, forwarded=True):
            with self.mailcortex_admission_lock:
                return self._mailcortex_record_input(observations, forwarded)

        def _mailcortex_record_input(self, observations, forwarded):
            if any(human for _kind, _length, human in observations):
                self.mailcortex_input_dirty = True
                self.mailcortex_startup_pending = False
                self.mailcortex_startup_idle_at = None
            return super()._record_input_observations(observations, forwarded=forwarded)

        def _record_transcript_observation(self, classification, **fields):
            if classification in {"user-turn", "assistant-output"}:
                self.mailcortex_startup_pending = False
                self.mailcortex_startup_idle_at = None
            return super()._record_transcript_observation(classification, **fields)

        def _handle_event(self, message):
            with self.mailcortex_admission_lock:
                return self._mailcortex_event(message)

        def _mailcortex_event(self, message):
            previous_session = self.session_id
            response = super()._handle_event(message)
            # A normal Stop resets the governor's activity timestamp, but must
            # NEVER erase unfinished input typed while the preceding turn ran.
            if isinstance(response, dict) and response.get("ok") is True and not response.get("ignored"):
                self.mailcortex_startup_idle_at = None
                self.mailcortex_startup_pending = (
                    message.get("event") == "session-start" and previous_session is None
                    and not self.mailcortex_input_dirty and self.last_local_input is None)
                if message.get("event") == "user-prompt-submit":
                    self.mailcortex_input_dirty = False
                self._write_state()
                if self.mailcortex_startup_pending:
                    self._mailcortex_finish_startup()
            return response

        def _handle_control(self, message):
            with self.mailcortex_admission_lock:
                return self._mailcortex_control(message)

        def _mailcortex_control(self, message):
            if message.get("command") in {"mailcortex-status", "mailcortex-admit"}:
                self._mailcortex_finish_startup()
                self._mailcortex_classify_screen()
                return owner_control(self, message, types.SimpleNamespace(now=warm.now, write_all=write_wake))
            return super()._handle_control(message)

    warm.Supervisor = MailOwner
    return warm.shell_exit_code(warm.main(argv))


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--barrier-guardian":
        raise SystemExit(2)
    barrier_guardian(int(sys.argv[2]))
