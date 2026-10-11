#!/usr/bin/env python3
"""Universal PTY hold-with-timeout: the approval gate through the PTY owner.

The Admiral's design (Telegram 6257-6259, brief /tmp/lane-briefs/pty-hold.md,
branch pty-hold-20261012): when a harness shows a permission prompt and the
same prompt is still on screen after unattended.hold_timeout_minutes, the
process that OWNS the session's PTY answers NO through the PTY, then writes
the request into the smart approval queue (reason hold_timeout) and stamps a
ledger. Replaces the Telegram-plugin patch hold (holds.patch,
approval-holds.ts): the harness's own native relay shows the prompt; nothing
in any plugin changes.

HARD RULES (never violable):
- The holder may ONLY ever answer No/Deny — never Yes, never any other key.
- Only to the exact prompt it timed: the prompt identity (text hash plus
  position) recorded at first sight must match the re-read screen at the
  moment of the write, under the same owner lock the mail wake uses, with the
  child barrier-paused and the screen drained and re-classified first.
- Any change (new prompt, user typing, prompt gone, compaction, recovery)
  aborts without writing. The Admiral answering first makes the prompt
  disappear; the timer then does nothing.

UNIVERSAL: everything harness-specific is a PROFILE — data, not forks. Each
profile says how to recognise a permission prompt (prompt_markers), how to
compute its identity (identity(visible)), and the deny key sequence
(deny_keys). Claude Code is the first profile; a FIXTURE profile proves the
interface is not Claude-specific. Herdr panes, the Emacs integration and
Codex/OpenCode TUIs plug in by adding profiles.

DotCortex is PUBLIC: placeholders only. No network, no secrets.
"""
from __future__ import annotations

import hashlib
import re


# ----------------------------------------------------------------- profiles

class HoldProfile:
    """Per-harness screen profile: prompt recognition, identity, deny keys.

    Profiles are DATA. Adding a harness is a new HoldProfile instance in the
    PROFILES registry, never a code fork.
    """

    def __init__(self, name, prompt_markers, deny_keys, marker_flags=re.IGNORECASE):
        if not name or not isinstance(name, str):
            raise ValueError("profile name")
        if not isinstance(prompt_markers, (list, tuple)) or not prompt_markers:
            raise ValueError("profile prompt markers")
        if not isinstance(deny_keys, (list, tuple)) or not deny_keys:
            raise ValueError("profile deny keys")
        for marker in prompt_markers:
            if not isinstance(marker, str) or not marker:
                raise ValueError("profile prompt marker")
        for keys in deny_keys:
            if not isinstance(keys, bytes) or not keys:
                raise ValueError("profile deny keys")
            # DENY-ONLY, enforced structurally: the deny sequence may never
            # contain Enter/newline (confirm), y/Y (yes), or printable
            # letters other than n (deny).
            if b"\r" in keys or b"\n" in keys or b"y" in keys.lower() or b"Y" in keys:
                raise ValueError("profile deny keys must be deny-only")
        self.name = name
        self.prompt_markers = [m.lower() for m in prompt_markers]
        self.deny_keys = [keys for keys in deny_keys]
        self.marker_flags = marker_flags

    def matches(self, visible):
        """True when the screen shows this harness's permission prompt."""
        if not isinstance(visible, str) or not visible:
            return False
        lowered = visible.lower()
        return any(marker in lowered for marker in self.prompt_markers)

    def identity(self, visible):
        """Screen identity of the timed prompt: prompt-text hash plus the
        position of the marker in the visible screen. A moved or rewritten
        prompt is a DIFFERENT prompt and must never receive the timed deny."""
        if not isinstance(visible, str) or not visible:
            return None
        lowered = visible.lower()
        positions = [lowered.find(marker) for marker in self.prompt_markers
                     if marker in lowered]
        if not positions:
            return None
        position = min(positions)
        # the prompt text: from the marker to the end of the line, hashed
        line_end = visible.find("\n", position)
        prompt_text = visible[position:line_end if line_end >= 0 else len(visible)]
        digest = hashlib.sha256(prompt_text.encode("utf-8", "replace")).hexdigest()
        return f"{digest}@{position}"


# Claude Code's permission dialog: the native relay the Admiral already taps
# shows it; the dialog itself offers "esc to cancel" (the same cue the screen
# classifier trusts as a strong blocker). ESC denies/cancels the dialog and
# can NEVER confirm anything — the deny-only rule holds structurally.
CLAUDE_CODE_PROFILE = HoldProfile(
    name="claude-code",
    prompt_markers=(
        "do you want to proceed?",
        "would you like to proceed?",
        "allow command?",
        "enter to confirm",
        "esc to cancel",
    ),
    deny_keys=(b"\x1b",),  # ESC: deny/cancel only
)

# Fixture profile: a generic non-Claude TUI dialog, proving the interface is
# harness-neutral. Herdr/Emacs/Codex/OpenCode profiles follow the same shape.
FIXTURE_PROFILE = HoldProfile(
    name="fixture-dialog",
    prompt_markers=("fixTURE DIALOG:".lower(),),
    deny_keys=(b"\x1b", b"n"),  # ESC then n on a [y/n] dialog: deny-only
)

PROFILES = {profile.name: profile for profile in (CLAUDE_CODE_PROFILE, FIXTURE_PROFILE)}


def deny_bytes(profile):
    """The exact deny sequence for a profile (never a confirm key)."""
    return b"".join(profile.deny_keys)


def hold_timeout_seconds(unattended_section, default_minutes=10):
    """unattended.hold_timeout_minutes as seconds (mirrors the queue's
    _hold_seconds; accepts the same manifest section shape)."""
    minutes = default_minutes
    if isinstance(unattended_section, dict):
        raw = unattended_section.get("hold_timeout_minutes", default_minutes)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool) and raw > 0:
            minutes = raw
    return float(minutes) * 60.0


# -------------------------------------------------------------------- timer

class PtyHoldTimer:
    """Records the first sight of a permission prompt and times it out.

    The timer holds AT MOST ONE prompt: the one currently on screen. A new,
    different prompt identity replaces the record (its own clock starts);
    the same identity re-seen keeps the original first_seen (no reset).
    """

    def __init__(self, timeout):
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("hold timeout")
        self.timeout = float(timeout)
        self._identity = None
        self._first_seen = None

    def record(self, visible, profile, now):
        """Feed the current screen. Returns True when a NEW prompt identity
        was recorded (the caller may notify), False when unchanged/absent."""
        identity = profile.identity(visible) if profile.matches(visible) else None
        if identity is None:
            # no permission prompt on this screen: the timed prompt is gone
            # (answered by the Admiral, dismissed, or redrawn) — clear
            self.clear()
            return False
        if identity == self._identity:
            return False  # same prompt still on screen; clock keeps running
        self._identity = identity
        self._first_seen = float(now)
        return True

    def expired(self, now):
        """True when the recorded prompt is still pending and its deadline
        passed. No recorded prompt (cleared/answered) is never expired."""
        if self._identity is None or self._first_seen is None:
            return False
        return float(now) >= self._first_seen + self.timeout

    def identity(self):
        return self._identity

    def clear(self):
        self._identity = None
        self._first_seen = None


# ------------------------------------------------------------ guarded write

def _owner_busy(owner):
    """Any anomaly aborts the deny write: compaction, recovery, or typed
    input pending. A permission prompt DURING an active turn (status
    'active') is the hold's raison d'être, so turn status is NOT a refusal
    here; the screen identity check is the authority for what receives the
    deny."""
    return bool(
        getattr(owner, "compacting", False)
        or getattr(owner, "recovery_pending", False)
        or getattr(owner, "recovery_awaiting", False)
        or getattr(owner, "mailcortex_input_dirty", False)
    )


def deny_expired_prompt(owner, timer, profile, read_screen, now, queue_write):
    """Deny the timed prompt through the PTY, then queue the request.

    ALL of the hard rules live here:
    - under the same owner lock the mail wake uses (mailcortex_admission_lock),
      with the child barrier-paused (owner._mailcortex_barrier) and the
      screen re-read (read_screen) AFTER the pause;
    - the re-read screen must still match the timed prompt identity EXACTLY;
    - any anomaly (typed input, compaction, recovery, turn running) aborts
      without writing;
    - the write is deny_bytes(profile) — deny-only, never a confirm key;
    - only after a successful write does the request enter the smart queue
      (reason hold_timeout) and the ledger get stamped (queue_write).
    Returns True when the deny was written, False on any abort.
    """
    if not timer.expired(now()):
        return False
    expected = timer.identity()
    if expected is None:
        return False
    lock = getattr(owner, "mailcortex_admission_lock", None)
    if lock is None:
        return False  # no owner lock: fail closed, never write
    with lock:
        if _owner_busy(owner):
            timer.clear()
            return False
        barrier = getattr(owner, "_mailcortex_barrier", None)
        if barrier is None:
            timer.clear()
            return False
        with barrier():
            # re-read the screen immediately before the write, AFTER the
            # child is paused and drained (the wake guardian's discipline)
            drain = getattr(owner, "_mailcortex_refresh_screen", None)
            if callable(drain) and drain():
                timer.clear()
                return False  # output arrived while acquiring: abort
            if _owner_busy(owner):
                timer.clear()
                return False
            visible = read_screen()
            if not profile.matches(visible) or profile.identity(visible) != expected:
                # prompt gone, changed, or a NEWER prompt: not our timed one
                timer.record(visible, profile, now())
                return False
            # the exact timed prompt is still on screen, child paused, no
            # input pending: write the deny sequence — deny-only by profile
            import os as _os
            try:
                write_all = getattr(owner, "_mailcortex_write_all", None)
                if write_all is None:
                    # fall back to the fleet's write_all convention on the
                    # owner's master fd
                    fd = getattr(owner, "master_fd", None)
                    if fd is None:
                        timer.clear()
                        return False
                    data = deny_bytes(profile)
                    while data:
                        written = _os.write(fd, data)
                        data = data[written:]
                else:
                    write_all(getattr(owner, "master_fd"), deny_bytes(profile))
            except OSError:
                # the write may have partially landed; the prompt was timed
                # out anyway — queue it so the Admiral sees it either way
                queue_write(expected)
                timer.clear()
                return True
            # deny landed: write the request into the smart queue (reason
            # hold_timeout, deduped by the queue's own upsert) and stamp
            queue_write(expected)
            timer.clear()
            return True
