#!/usr/bin/env python3
"""Deny a timed permission prompt through its PTY owner, then record it.

Profiles carry harness-specific recognition and a single cancellation key.
The owner supplies the shared lock, acknowledged process-tree barrier,
bounded screen drain, pending-input check and attributed screen classifier.
"""
from __future__ import annotations

from collections import namedtuple
import hashlib
import math
import os
import re


def _deny_keys(keys):
    # One cancellation key only: a second key could reach a dismissed dialog's
    # successor. Arbitrary printable bytes and terminal sequences are refused.
    if not isinstance(keys, (tuple, list)) or len(keys) != 1:
        raise ValueError("profile requires one deny key")
    if not isinstance(keys[0], bytes) or keys[0] not in (b"\x1b", b"n"):
        raise ValueError("profile deny key must be ESC or n")
    return tuple(keys)


class HoldProfile(namedtuple("ProfileData", "name prompt_markers deny_keys marker_flags required_markers")):
    """Immutable harness profile; construction and every write validate keys."""
    __slots__ = ()

    def __new__(cls, name, prompt_markers, deny_keys, marker_flags=re.IGNORECASE,
                required_markers=()):
        if not isinstance(name, str) or not name:
            raise ValueError("profile name")
        def markers(values, required=False):
            if (not isinstance(values, (list, tuple)) or required and not values
                    or any(not isinstance(value, str) or not value for value in values)):
                raise ValueError("profile prompt markers")
            return tuple(value.lower() for value in values)
        return super().__new__(cls, name, markers(prompt_markers, True),
                               _deny_keys(deny_keys), marker_flags, markers(required_markers))

    def matches(self, visible):
        if not isinstance(visible, str) or not visible:
            return False
        lowered = visible.lower()
        return (any(marker in lowered for marker in self.prompt_markers)
                and all(marker in lowered for marker in self.required_markers))

    def identity(self, visible):
        """Bind all visible request text and marker position, including context
        above a generic confirmation question and choices below it."""
        if not self.matches(visible):
            return None
        lowered = visible.lower()
        position = min(lowered.index(marker) for marker in self.prompt_markers if marker in lowered)
        digest = hashlib.sha256(visible.encode("utf-8", "replace")).hexdigest()
        return f"{digest}@{position}"


CLAUDE_CODE_PROFILE = HoldProfile(
    "claude-code", ("do you want to proceed?", "would you like to proceed?", "allow command?"),
    (b"\x1b",), required_markers=("esc to cancel",))
FIXTURE_PROFILE = HoldProfile("fixture-dialog", ("fixture dialog:",), (b"n",))
PROFILES = {profile.name: profile for profile in (CLAUDE_CODE_PROFILE, FIXTURE_PROFILE)}


def deny_bytes(profile):
    return b"".join(_deny_keys(profile.deny_keys))


def hold_timeout_seconds(unattended_section, default_minutes=10):
    raw = unattended_section.get("hold_timeout_minutes", default_minutes) if isinstance(unattended_section, dict) else default_minutes
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(raw) or raw <= 0:
        raw = default_minutes
    return float(raw) * 60


class PtyHoldTimer:
    """Time one exact screen; changed or absent prompts reset the deadline."""
    def __init__(self, timeout):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("hold timeout")
        self.timeout = float(timeout)
        self.clear()

    def record(self, visible, profile, now):
        identity = profile.identity(visible)
        if identity is None:
            self.clear()
            return False
        if identity == self._identity:
            return False
        self._identity = identity
        self._first_seen = float(now)
        return True

    def expired(self, now):
        return (self._identity is not None and self._first_seen is not None
                and float(now) >= self._first_seen + self.timeout)

    def identity(self):
        return self._identity

    def clear(self):
        self._identity = None
        self._first_seen = None


def _owner_busy(owner):
    return bool(getattr(owner, "compacting", False)
                or getattr(owner, "recovery_pending", False)
                or getattr(owner, "recovery_awaiting", False)
                or getattr(owner, "mailcortex_input_dirty", True)
                or getattr(owner, "status", None) not in {"active", "idle"})


def deny_expired_prompt(owner, timer, profile, read_screen, now, queue_write):
    """One bounded deny write, only after all owner guards succeed.

    Missing guards, acquisition failures, pending input/output, changed screens
    and write errors abort. No spinning or replay of a failed write. The queue
    callback runs after the barrier releases, with the identity already cleared.
    """
    expected = timer.identity()
    lock = getattr(owner, "mailcortex_admission_lock", None)
    if lock is None or expected is None or not timer.expired(now()):
        return False
    with lock:
        if timer.identity() != expected or not timer.expired(now()):
            return False
        written = False
        try:
            pending = getattr(owner, "_hold_input_pending", None)
            barrier = getattr(owner, "_mailcortex_barrier", None)
            drain = getattr(owner, "_mailcortex_refresh_screen", None)
            if not all(callable(guard) for guard in (pending, barrier, drain)):
                timer.clear()
                return False
            if _owner_busy(owner) or pending():
                timer.clear()
                return False
            with barrier():
                if drain() or _owner_busy(owner) or pending():
                    timer.clear()
                    return False
                visible = read_screen()
                if profile.identity(visible) != expected:
                    timer.record(visible, profile, now())
                    return False
                # No callback or state-file I/O between the final drain/input
                # check and the single write. The acknowledged tree is paused.
                data = deny_bytes(profile)
                fd = owner.master_fd
                if os.get_blocking(fd):
                    raise ValueError("PTY deny requires a nonblocking owner descriptor")
                if drain() or _owner_busy(owner) or pending():
                    timer.clear()
                    return False
                if os.write(fd, data) != len(data):
                    raise OSError("partial PTY deny write")
                written = True
                timer.clear()
        except (OSError, ValueError, AttributeError, RuntimeError, TypeError):
            timer.clear()
            if not written:
                return False
            # A failed resume acknowledgement does not erase an already
            # completed deny. Preserve its request once and report the fault.
            logger = getattr(owner, "_guard_log", None)
            if callable(logger):
                logger("pty-hold-resume-failed")
        try:
            queue_write(expected)
        except Exception:
            # The deny landed. Never repeat it because recording failed.
            logger = getattr(owner, "_guard_log", None)
            if callable(logger):
                logger("pty-hold-queue-failed")
        return True
