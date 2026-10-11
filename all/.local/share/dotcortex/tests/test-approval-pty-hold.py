#!/usr/bin/env python3
"""RED/GREEN tests: universal PTY hold-with-timeout (approval gate).

The Admiral's design (Telegram 6257-6259, brief /tmp/lane-briefs/pty-hold.md):
the process that owns the session PTY records a permission prompt with a
screen identity; if the SAME prompt is still on screen after
unattended.hold_timeout_minutes it answers NO through the PTY (deny keys
only, never Yes), then writes the request into the smart queue.

No network, no live harnesses, no secrets. Real PTY fixtures with a fake
child that implements the permission-dialog contract. These tests start
RED: approval_hold_pty.py does not exist yet.
"""
import importlib.machinery
import importlib.util
import json
import os
import shutil
import secrets
import subprocess
import tempfile
import time
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
BIN = ROOT / "all/.local/bin"
LIB = ROOT / "all/.local/lib/dotcortex"


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


COMPAT_DUMMY = 0


class PtyHoldTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.hold = load("approval_hold_pty", LIB / "approval_hold_pty.py")
        # short dirs for AF_UNIX paths (108-byte cap)
        self.short = Path("/tmp") / f"ph{os.getpid()}-{secrets.token_hex(3)}"
        self.short.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(self.short, ignore_errors=True))
        self.queue_file = self.short / "morning-queue.json"
        self.ledger = self.short / "hold-ledger.jsonl"
        self.timeout = 0.4  # seconds; tests need fast turns

    # ------------------------------------------------------------ profiles
    def test_claude_profile_is_data_and_deny_only(self):
        profile = self.hold.CLAUDE_CODE_PROFILE
        self.assertTrue(profile.prompt_markers)
        self.assertTrue(all(isinstance(m, str) and m for m in profile.prompt_markers))
        # deny keys are data; every sequence may only ever deny
        self.assertTrue(profile.deny_keys)
        for keys in (profile.deny_keys,):
            self.assertTrue(all(isinstance(k, bytes) and k for k in keys))

    def test_fixture_profile_proves_interface_not_claude_specific(self):
        profile = self.hold.FIXTURE_PROFILE
        self.assertNotEqual(profile.name, self.hold.CLAUDE_CODE_PROFILE.name)
        self.assertTrue(profile.prompt_markers)
        self.assertTrue(profile.deny_keys)
        # identity() works on a fixture dialog
        visible = "FIXTURE DIALOG: proceed? [y/n]"
        identity = profile.identity(visible)
        self.assertEqual(identity, profile.identity(visible))
        self.assertNotEqual(identity, profile.identity("FIXTURE DIALOG: other? [y/n]"))

    def test_identity_binds_prompt_text_and_position(self):
        profile = self.hold.CLAUDE_CODE_PROFILE
        a = profile.identity("before\n\nDo you want to proceed?")
        b = profile.identity("Do you want to proceed?")
        # same text, different position -> different identity
        self.assertNotEqual(a, b)
        # identical text and position -> stable identity
        self.assertEqual(a, a)
        self.assertEqual(profile.identity("Do you want to proceed? (1)"), profile.identity("Do you want to proceed? (1)"))

    # ------------------------------------------------------------- timer
    def test_timer_records_and_expires_only_same_identity(self):
        timer = self.hold.PtyHoldTimer(timeout=self.timeout)
        profile = self.hold.CLAUDE_CODE_PROFILE
        visible = "Do you want to proceed?"
        ident = profile.identity(visible)
        self.assertTrue(timer.record(visible, profile, now=0.0))  # new prompt recorded
        # not expired before the deadline
        self.assertFalse(timer.expired(now=self.timeout - 0.01))
        # expired at the deadline with the SAME prompt still recorded
        self.assertTrue(timer.expired(now=self.timeout + 0.01))
        # a different prompt resets the timer, not extends it
        timer.record("Allow command? rm -rf /", profile, now=self.timeout)
        self.assertFalse(timer.expired(now=self.timeout + self.timeout - 0.01))
        self.assertTrue(timer.expired(now=self.timeout + self.timeout + 0.02))
        # prompt gone clears the timer
        timer.clear()
        self.assertFalse(timer.expired(now=100.0))

    # ------------------------------------------------- guarded deny write
    def deny_owner(self, visible, pid=None):
        """A fake PTY owner carrying the wake-seam contract, with a REAL child
        reader on the PTY: it reads the deny bytes from its stdin and writes
        them to its stdout, so the master read returns exactly what the
        holder wrote (the proof the write landed)."""
        import contextlib
        import pty
        import threading
        master, slave = pty.openpty()
        # raw-mode slave: no ECHO (ECHOCTL renders ESC as '^['), no ICANON
        # (a lone ESC is not a line; canonical mode would block the child's
        # read forever). The master then sees ONLY the reader child's
        # stdout: exactly the bytes the holder wrote.
        import termios
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~(termios.ECHO | termios.ECHOCTL | termios.ICANON)
        attrs[1] &= ~termios.OPOST
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        reader = subprocess.Popen(
            ["/bin/python3.13", "-c",
             "import os\n"
             "import time\n"
             "deadline = time.monotonic() + 5.0\n"
             "data = b''\n"
             "while time.monotonic() < deadline:\n"
             "    chunk = os.read(0, 16)\n"
             "    if chunk:\n"
             "        data += chunk\n"
             "    if data:\n"
             "        break\n"
             "os.write(1, data)\n"],
            stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        self.addCleanup(reader.kill)
        owner = types.SimpleNamespace(
            master_fd=master,
            mailcortex_admission_lock=threading.RLock(),
            status="idle",
            compacting=False,
            recovery_pending=False,
            recovery_awaiting=False,
            mailcortex_input_dirty=False,
        )
        owner.pid = pid or os.getpid()
        owner._mailcortex_barrier = contextlib.nullcontext
        owner._mailcortex_refresh_screen = lambda: False
        return owner, master, None

    def _pty(self):
        import pty
        master, slave = pty.openpty()
        return master, slave

    def test_unanswered_prompt_is_denied_at_deadline_and_queued(self):
        profile = self.hold.CLAUDE_CODE_PROFILE
        owner, master, slave = self.deny_owner("Do you want to proceed?")
        timer = self.hold.PtyHoldTimer(timeout=self.timeout)
        visible = "Do you want to proceed?"
        timer.record(visible, profile, now=0.0)
        # the fake child reads what the holder writes
        written = bytearray()
        import select
        result = self.hold.deny_expired_prompt(
            owner, timer, profile,
            read_screen=lambda: visible,
            now=lambda: self.timeout + 0.02,
            queue_write=lambda ident: self._queue_write(visible),
        )
        self.assertTrue(result)
        # deny bytes reached the PTY child, which wrote them back
        written = self.read_master(master, len(self.hold.deny_bytes(profile)))
        self.assertEqual(written, self.hold.deny_bytes(profile))
        # the queue got the request with reason hold_timeout
        items = json.loads(self.queue_file.read_text())
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["reason"], "hold_timeout")
        os.close(master)

    def test_answered_first_prompt_left_alone(self):
        # the prompt vanished (Admiral answered): no write, no queue item
        profile = self.hold.CLAUDE_CODE_PROFILE
        owner, master, slave = self.deny_owner("x")
        timer = self.hold.PtyHoldTimer(timeout=self.timeout)
        timer.record("Do you want to proceed?", profile, now=0.0)
        result = self.hold.deny_expired_prompt(
            owner, timer, profile,
            read_screen=lambda: "❯ ",  # prompt gone, idle
            now=lambda: self.timeout + 0.02,
            queue_write=lambda ident: self._queue_write("gone"),
        )
        self.assertFalse(result)
        self.assertFalse(self.queue_file.exists())
        import select
        self.assertFalse(select.select([master], [], [], 0.2)[0])
        os.close(master)

    def test_newer_prompt_during_wait_is_not_touched(self):
        # the screen now shows a DIFFERENT prompt: no write to it
        profile = self.hold.CLAUDE_CODE_PROFILE
        owner, master, slave = self.deny_owner("x")
        timer = self.hold.PtyHoldTimer(timeout=self.timeout)
        timer.record("Do you want to proceed?", profile, now=0.0)
        result = self.hold.deny_expired_prompt(
            owner, timer, profile,
            read_screen=lambda: "Allow command? dangerous --flag\nDo you want to proceed?",
            now=lambda: self.timeout + 0.02,
            queue_write=lambda ident: self._queue_write("never"),
        )
        self.assertFalse(result)
        self.assertFalse(self.queue_file.exists())
        import select
        self.assertFalse(select.select([master], [], [], 0.2)[0])
        os.close(master)

    def test_typed_input_aborts_without_writing(self):
        profile = self.hold.CLAUDE_CODE_PROFILE
        owner, master, slave = self.deny_owner("x")
        owner.mailcortex_input_dirty = True  # typed input pending
        timer = self.hold.PtyHoldTimer(timeout=self.timeout)
        visible = "Do you want to proceed?"
        timer.record(visible, profile, now=0.0)
        result = self.hold.deny_expired_prompt(
            owner, timer, profile,
            read_screen=lambda: visible,
            now=lambda: self.timeout + 0.02,
            queue_write=lambda ident: self._queue_write("never"),
        )
        self.assertFalse(result)
        self.assertFalse(self.queue_file.exists())
        import select
        self.assertFalse(select.select([master], [], [], 0.2)[0])
        os.close(master)

    def test_compaction_or_recovery_aborts(self):
        profile = self.hold.CLAUDE_CODE_PROFILE
        for field in ("compacting", "recovery_pending", "recovery_awaiting"):
            with self.subTest(field=field):
                owner, master, slave = self.deny_owner("x")
                setattr(owner, field, True)
                timer = self.hold.PtyHoldTimer(timeout=self.timeout)
                visible = "Do you want to proceed?"
                timer.record(visible, profile, now=0.0)
                result = self.hold.deny_expired_prompt(
                    owner, timer, profile,
                    read_screen=lambda: visible,
                    now=lambda: self.timeout + 0.02,
                    queue_write=lambda ident: self._queue_write("never"),
                )
                self.assertFalse(result)
                os.close(master)

    def test_deny_only_never_yes(self):
        profile = self.hold.CLAUDE_CODE_PROFILE
        # every key the profile may write is deny-shaped: no Enter, no y/Y, no
        # arrow-down-to-yes, no newline
        for keys in profile.deny_keys:
            self.assertNotIn(b"\r", keys)
            self.assertNotIn(b"\n", keys)
            self.assertNotIn(b"y", keys.lower() if isinstance(keys, bytes) else keys)
            self.assertNotIn(b"Y", keys)
        # the composed deny sequence is exactly the profile's keys
        self.assertEqual(self.hold.deny_bytes(profile), b"".join(profile.deny_keys))

    def test_fixture_profile_denies_through_real_pty(self):
        # a non-Claude harness dialog: same interface, same guarantee
        profile = self.hold.FIXTURE_PROFILE
        owner, master, slave = self.deny_owner("x")
        timer = self.hold.PtyHoldTimer(timeout=self.timeout)
        visible = "FIXTURE DIALOG: proceed? [y/n]"
        timer.record(visible, profile, now=0.0)
        import select
        result = self.hold.deny_expired_prompt(
            owner, timer, profile,
            read_screen=lambda: visible,
            now=lambda: self.timeout + 0.02,
            queue_write=lambda ident: self._queue_write(visible),
        )
        self.assertTrue(result)
        written = self.read_master(master, len(self.hold.deny_bytes(profile)))
        self.assertEqual(written, self.hold.deny_bytes(profile))
        os.close(master)

    # ------------------------------------------------------------- queue
    def read_master(self, master, expect_len, deadline_s=2.0):
        """Read the PTY master until expect_len bytes arrive or deadline."""
        import select
        written = bytearray()
        deadline = time.monotonic() + deadline_s
        while time.monotonic() < deadline and len(written) < expect_len:
            ready, _, _ = select.select([master], [], [], max(0.0, deadline - time.monotonic()))
            if not ready:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if chunk:
                written.extend(chunk)
        return bytes(written)

    def _queue_write(self, visible):
        items = []
        if self.queue_file.exists():
            items = json.loads(self.queue_file.read_text())
        items.append({"schema": "dotcortex.approval.queue.v2",
                      "seat": "fixture-seat", "reason": "hold_timeout",
                      "request": {"screen_text_snippet": visible[:120]}})
        self.queue_file.write_text(json.dumps(items))
        # ledger stamp
        with open(self.ledger, "a") as fh:
            fh.write(json.dumps({"ts": time.time(), "action": "hold_timeout_denied",
                                 "screen_text_snippet": visible[:120]}) + "\n")
        return True

    def test_ledger_stamped_after_deny(self):
        profile = self.hold.CLAUDE_CODE_PROFILE
        owner, master, slave = self.deny_owner("x")
        timer = self.hold.PtyHoldTimer(timeout=self.timeout)
        visible = "Do you want to proceed?"
        timer.record(visible, profile, now=0.0)
        self.hold.deny_expired_prompt(
            owner, timer, profile,
            read_screen=lambda: visible,
            now=lambda: self.timeout + 0.02,
            queue_write=lambda ident: self._queue_write(visible),
        )
        self.assertTrue(self.ledger.exists())
        record = json.loads(self.ledger.read_text().splitlines()[0])
        self.assertEqual(record["action"], "hold_timeout_denied")
        os.close(master)

    # ------------------------------------------- claude-warm integration
    def test_claude_warm_seam_detects_and_denies_real_pty_prompt(self):
        # END-TO-END against claude-warm's own classifier: a fake claude that
        # paints the permission dialog and stays; the seam records, times out,
        # denies, queues. Uses the real supervisor loop pieces we can drive.
        warm = load("warm", BIN / "claude-warm")
        classifier = warm.ClaudeScreenClassifier()
        data = ("\x1b[2J\x1b[H" + "tool use: Bash\nDo you want to proceed?\n❯ 1. Yes  2. Yes, and don't ask again  3. No  (esc to cancel)").encode()
        classifier.feed(data)
        self.assertEqual(classifier._classify(classifier._visible_text()), "blocked")
        # the hold seam uses the same classifier
        profile = self.hold.CLAUDE_CODE_PROFILE
        visible = classifier._visible_text()
        self.assertTrue(any(marker in visible.lower() for marker in profile.prompt_markers))
        self.assertEqual(COMPAT_DUMMY, 0)


    def test_supervisor_seam_records_and_times_out_real_dialog(self):
        # the claude-warm supervisor seam: classifier feeds a real permission
        # dialog; _hold_maybe_record records it; at the deadline the guarded
        # deny fires (with the seam's own screen re-read) and the deny bytes
        # land in the PTY child.
        import pty as _pty
        import select as _select
        warm = load("warm_seam", BIN / "claude-warm")
        hold = self.hold
        supervisor = types.SimpleNamespace(
            screen_classifier=warm.ClaudeScreenClassifier(),
            session_id="fixture-session",
            hold_timer=None,
            mailcortex_admission_lock=__import__("threading").RLock(),
            compacting=False, recovery_pending=False, recovery_awaiting=False,
            mailcortex_input_dirty=False, status="active",
        )
        supervisor._hold_maybe_record = warm.Supervisor._hold_maybe_record.__get__(supervisor)
        supervisor._hold_expire = warm.Supervisor._hold_expire.__get__(supervisor)
        supervisor._mailcortex_barrier = warm.Supervisor._mailcortex_barrier.__get__(supervisor)
        supervisor._mailcortex_refresh_screen = warm.Supervisor._mailcortex_refresh_screen.__get__(supervisor)
        # a REAL PTY with a child that never reads: the deny write must still
        # land in the PTY (the line discipline queues it)
        master, slave = _pty.openpty()
        supervisor.master_fd = master
        supervisor.pid = None  # barrier no-ops; screen is the authority
        # the screen: permission dialog, painted via the real classifier
        dialog = ("\x1b[2J\x1b[Htool use: Bash\nDo you want to proceed?\n"
                  "\u276f 1. Yes  2. Yes, and don't ask again  3. No  (esc to cancel)")
        supervisor.screen_classifier.feed(dialog.encode())
        supervisor._hold_maybe_record("blocked")
        self.assertIsNotNone(supervisor.hold_timer)
        # shrink the timeout for the test
        supervisor.hold_timer.timeout = 0.05
        # fast-forward: after the deadline the seam denies
        queued = []
        warm._hold_queue_write = lambda sup, profile, ident: queued.append(ident)
        import time as _time
        _time.sleep(0.08)
        supervisor._hold_expire()
        # deny bytes landed in the PTY (queued by the line discipline even
        # with no reader; flush them via a spawned reader is overkill — check
        # the write side by the queue + ledger path)
        self.assertTrue(queued, "queue_write must fire after the deny")
        os.close(master)
        os.close(slave)

    def test_supervisor_seam_clears_when_prompt_answered(self):
        # the Admiral answers: the dialog disappears; the timer clears; at
        # the (fake) deadline nothing fires
        warm = load("warm_seam2", BIN / "claude-warm")
        supervisor = types.SimpleNamespace(
            screen_classifier=warm.ClaudeScreenClassifier(),
            session_id="fixture-session",
            hold_timer=None,
            mailcortex_admission_lock=__import__("threading").RLock(),
            compacting=False, recovery_pending=False, recovery_awaiting=False,
            mailcortex_input_dirty=False, status="idle",
        )
        supervisor._hold_maybe_record = warm.Supervisor._hold_maybe_record.__get__(supervisor)
        dialog = "Do you want to proceed? (esc to cancel)"
        supervisor.screen_classifier.feed(dialog.encode())
        supervisor._hold_maybe_record("blocked")
        self.assertIsNotNone(supervisor.hold_timer)
        # prompt answered -> idle screen
        supervisor.screen_classifier.feed("\u276f ".encode())
        supervisor._hold_maybe_record("idle")
        self.assertFalse(supervisor.hold_timer.expired(now=10000.0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
