#!/usr/bin/env python3
"""Conditional Claude mail wake: private SSH topology, PTY-owner admission."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import math
import os
import re
import select
import socket
import stat
import subprocess
import sys
import types
import uuid
from pathlib import Path

PROTOCOL = "claude.mailcortex_idle.v1"
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


def scan_batch(api, seat, record, adapter, now):
    """One durable, bounded-window wake for every pending Message-ID in a scan."""
    w = types.SimpleNamespace(**api)
    mailbox = w.MAILCORTEX.mail_root() / record["mailbox"]
    pending = []
    seen = set()
    for path in sorted((mailbox / "new").iterdir()):
        if path.is_symlink() or not path.is_file() or path.name.startswith("."):
            continue
        mid = w.message_id(path)
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
    receipts("injecting", pane_id=owner)
    prompt = (f"MailCortex: new mail is waiting in {record['mailbox']} on {record['host']}. "
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
            and set(owner) == {"channel", "session_id", "supervisor_pid", "epoch", "pane_id", "pane_tty"}
            and isinstance(owner["channel"], str) and CHANNEL.fullmatch(owner["channel"]) is not None
            and isinstance(owner["session_id"], str) and re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", owner["session_id"]) is not None
            and type(owner["supervisor_pid"]) is int and owner["supervisor_pid"] > 0
            and type(owner["epoch"]) is int and owner["epoch"] >= 0
            and isinstance(owner["pane_id"], str) and re.fullmatch(r"%[0-9]+", owner["pane_id"]) is not None
            and isinstance(owner["pane_tty"], str) and re.fullmatch(r"/dev/pts/[0-9]+", owner["pane_tty"]) is not None)


def private_path(path, kind):
    info = path.lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077 or not kind(info.st_mode):
        raise ValueError("unsafe Claude runtime ownership")


def descendant(pid, ancestor):
    for _ in range(32):
        path = Path(f"/proc/{pid}")
        if path.stat().st_uid != os.getuid():
            return False
        if pid == ancestor:
            return True
        fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
        pid = int(fields[1])
        if pid <= 1:
            return False
    return False


def resolve_owner(target):
    validate_target(target)
    private_path(Path(target["tmux_socket"]), stat.S_ISSOCK)
    result = subprocess.run(["/usr/bin/tmux", "-S", target["tmux_socket"], "list-panes", "-s",
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
        owner = {"channel": state["channel"], "session_id": state["session_id"],
                 "supervisor_pid": supervisor, "epoch": state["completed_turn_epoch"],
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
                and expected["epoch"] == owner.completed_turn_epoch
                and expected["pane_id"] == os.environ.get("TMUX_PANE")
                and expected["pane_tty"] == os.ttyname(sys.stdin.fileno()))
    except (OSError, ValueError):
        return False


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
    if not owner_matches(owner, request["owner"]):
        return dict(ack, status="unavailable")
    # Reconcile transcript activity before the gate; unknown and partial records veto.
    owner._record_transcript_activity()
    if (owner.status != "idle" or owner.screen_state != "idle" or owner.lifecycle_health != "wired"
            or owner.compacting or owner.recovery_pending or owner.recovery_awaiting
            or getattr(owner, "mailcortex_input_dirty", True)
            or owner.transcript_gate_blocked or owner.transcript_partial
            or owner.transcript_quiescence_deadline is not None
            or not owner.last_normal_stop
            or (owner.last_local_input is not None and owner.last_local_input >= owner.last_normal_stop)
            or (owner.last_lifecycle_activity is not None and owner.last_lifecycle_activity > owner.last_normal_stop)
            or owner._gate_reason("manual") is not None or pending_terminal(owner)):
        return dict(ack, status="busy")
    if operation == "mailcortex-status":
        return dict(ack, status="idle")
    # This executes synchronously on the sole PTY owner's event loop. Claim before write.
    owner.status = "active"
    owner.timer_deadline = None
    owner.timer_kind = None
    owner.timer_generation += 1
    owner.last_lifecycle_activity = warm.now()
    owner.last_state_transition = "mailcortex-admitted"
    owner._write_state()
    try:
        warm.write_all(owner.master_fd, (request["text"] + "\r").encode("ascii"))
    except OSError:
        # Keep the claim: partial PTY writes are ambiguous and must not be retried.
        return dict(ack, status="unknown")
    owner._guard_log("mailcortex-admitted")
    owner._write_state()
    return dict(ack, status="accepted")


def launch(argv):
    """Opt-in launcher: extend the existing PTY owner's control dispatch only."""
    path = Path(__file__).resolve().with_name("claude-warm")
    loader = importlib.machinery.SourceFileLoader("mailcortex_warm_owner", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    warm = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = warm
    loader.exec_module(warm)
    base = warm.Supervisor

    class MailOwner(base):
        def __init__(self, *args, **kwargs):
            self.mailcortex_input_dirty = False
            super().__init__(*args, **kwargs)

        def _record_input_observations(self, observations, forwarded=True):
            if any(human for _kind, _length, human in observations):
                self.mailcortex_input_dirty = True
            return super()._record_input_observations(observations, forwarded=forwarded)

        def _handle_event(self, message):
            response = super()._handle_event(message)
            # A normal Stop resets the governor's activity timestamp, but must
            # NEVER erase unfinished input typed while the preceding turn ran.
            if (response.get("ok") is True and not response.get("ignored")
                    and message.get("event") == "user-prompt-submit"):
                self.mailcortex_input_dirty = False
            return response

        def _handle_control(self, message):
            if message.get("command") in {"mailcortex-status", "mailcortex-admit"}:
                return owner_control(self, message, warm)
            return super()._handle_control(message)

    warm.Supervisor = MailOwner
    return warm.shell_exit_code(warm.main(argv))
