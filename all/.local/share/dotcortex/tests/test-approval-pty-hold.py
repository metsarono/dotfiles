#!/usr/bin/env python3
"""RED/GREEN tests: universal PTY hold-with-timeout (approval gate).

The Admiral's design (Telegram 6257-6259, brief /tmp/lane-briefs/pty-hold.md):
the process that owns the session PTY records a permission prompt with a
screen identity; if the SAME prompt is still on screen after
unattended.hold_timeout_minutes it answers NO through the PTY (deny keys
only, never Yes), then writes the request into the smart queue.

No network, no live harnesses, no secrets. Real PTY fixtures with a fake
child that implements the permission-dialog contract. These tests start
Regression suite for the canonical module and the shared owner seam.
"""
import importlib.machinery
import importlib.util
import contextlib
import threading
import sys
from unittest import mock
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
    def test_fullscreen_captured_permission_is_holdable_and_deny_only(self):
        warm = load("fullscreen_hold_owner", BIN / "claude-warm")
        captures = load("fullscreen_hold_captures", Path(__file__).with_name("claude_renderer_captures.py"))
        for mode, frames in captures.FULLSCREEN.items():
            with self.subTest(mode=mode):
                owner = self.screen_owner(warm, "")
                owner.screen_classifier.reset()
                owner.screen_classifier.feed(frames["permission"])
                visible = owner._hold_screen()
                self.assertIsNotNone(visible)
                self.assertEqual(owner.screen_classifier.prompt_input_state(permission_selection=True), "empty")
                self.assertEqual(self.hold.deny_bytes(self.hold.CLAUDE_CODE_PROFILE), b"\x1b")
                timer = self.hold.PtyHoldTimer(1)
                timer.record(visible, self.hold.CLAUDE_CODE_PROFILE, 0)
                guarded, _timer, queue, _deny = self.guarded_fixture()
                with mock.patch.object(os, "write", return_value=1) as write:
                    self.assertTrue(self.hold.deny_expired_prompt(guarded, timer,
                        self.hold.CLAUDE_CODE_PROFILE, read_screen=owner._hold_screen,
                        now=lambda: 1, queue_write=queue))
                    write.assert_called_once_with(guarded.master_fd, b"\x1b")
                owner.mailcortex_input_dirty = True
                owner._hold_maybe_record("blocked")
                self.assertIsNone(owner.hold_timer)
                owner.screen_classifier.feed(b"\x1b[")
                self.assertIsNone(owner._hold_screen())

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
        a = profile.identity("before\n\nDo you want to proceed? (esc to cancel)")
        b = profile.identity("Do you want to proceed? (esc to cancel)")
        # same text, different position -> different identity
        self.assertNotEqual(a, b)
        # identical text and position -> stable identity
        self.assertEqual(a, a)
        self.assertEqual(profile.identity("Do you want to proceed? (esc to cancel) (1)"), profile.identity("Do you want to proceed? (esc to cancel) (1)"))

    # ------------------------------------------------------------- timer
    def test_timer_records_and_expires_only_same_identity(self):
        timer = self.hold.PtyHoldTimer(timeout=self.timeout)
        profile = self.hold.CLAUDE_CODE_PROFILE
        visible = "Do you want to proceed? (esc to cancel)"
        ident = profile.identity(visible)
        self.assertTrue(timer.record(visible, profile, now=0.0))  # new prompt recorded
        # not expired before the deadline
        self.assertFalse(timer.expired(now=self.timeout - 0.01))
        # expired at the deadline with the SAME prompt still recorded
        self.assertTrue(timer.expired(now=self.timeout + 0.01))
        # a different prompt resets the timer, not extends it
        timer.record("Allow command? rm -rf / (esc to cancel)", profile, now=self.timeout)
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
        os.set_blocking(master, False)
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
            [sys.executable, "-c",
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
        def reap():
            if reader.poll() is None:
                reader.kill()
            reader.wait(timeout=5)
        self.addCleanup(reap)
        owner = types.SimpleNamespace(
            master_fd=master,
            mailcortex_admission_lock=threading.RLock(),
            status="idle",
            compacting=False,
            recovery_pending=False,
            recovery_awaiting=False,
            mailcortex_input_dirty=False,
        )
        owner.pid = pid or reader.pid
        owner._mailcortex_barrier = contextlib.nullcontext
        owner._mailcortex_refresh_screen = lambda: False
        owner._hold_input_pending = lambda: False
        return owner, master, None

    def _pty(self):
        import pty
        master, slave = pty.openpty()
        return master, slave

    def test_unanswered_prompt_is_denied_at_deadline_and_queued(self):
        profile = self.hold.CLAUDE_CODE_PROFILE
        owner, master, slave = self.deny_owner("Do you want to proceed? (esc to cancel)")
        timer = self.hold.PtyHoldTimer(timeout=self.timeout)
        visible = "Do you want to proceed? (esc to cancel)"
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
        timer.record("Do you want to proceed? (esc to cancel)", profile, now=0.0)
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
        timer.record("Do you want to proceed? (esc to cancel)", profile, now=0.0)
        result = self.hold.deny_expired_prompt(
            owner, timer, profile,
            read_screen=lambda: "Allow command? dangerous --flag\nDo you want to proceed? (esc to cancel)",
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
        visible = "Do you want to proceed? (esc to cancel)"
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
                visible = "Do you want to proceed? (esc to cancel)"
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
        visible = "Do you want to proceed? (esc to cancel)"
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
        data = ("\x1b[2J\x1b[H" + "tool use: Bash\nDo you want to proceed? (esc to cancel)\n❯ 1. Yes\n  2. Yes, and don't ask again\n  3. No\nEsc to cancel").encode()
        classifier.feed(data)
        self.assertEqual(classifier._classify(classifier._visible_text()), "blocked")
        # the hold seam uses the same classifier
        profile = self.hold.CLAUDE_CODE_PROFILE
        visible = classifier._visible_text()
        self.assertTrue(any(marker in visible.lower() for marker in profile.prompt_markers))
        self.assertEqual(COMPAT_DUMMY, 0)


    def test_supervisor_seam_records_and_times_out_real_dialog(self):
        warm = load("warm_seam", BIN / "claude-warm")
        owner, master, _slave = self.deny_owner("x")
        self.addCleanup(lambda: os.close(master))
        owner.screen_classifier = warm.ClaudeScreenClassifier()
        owner.session_id = "fixture-session"
        owner.hold_timer = None
        owner._hold_screen = warm.Supervisor._hold_screen.__get__(owner)
        owner._hold_maybe_record = warm.Supervisor._hold_maybe_record.__get__(owner)
        owner._hold_expire = warm.Supervisor._hold_expire.__get__(owner)
        dialog = "\x1b[2J\x1b[Hrm OLD\nDo you want to proceed?\n❯ 1. Yes\n 2. No\nEsc to cancel"
        owner.screen_classifier.feed(dialog.encode())
        with mock.patch.object(warm, "_hold_now", return_value=100):
            owner._hold_maybe_record("blocked")
        owner.hold_timer.timeout = 1
        queued = []
        with mock.patch.object(warm, "_hold_now", return_value=101), \
             mock.patch.object(warm, "_hold_queue_write", side_effect=lambda *args: queued.append(args)):
            owner._hold_expire()
        self.assertEqual(self.read_master(master, 1), b"\x1b")
        self.assertEqual(len(queued), 1)

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
        supervisor._hold_screen = warm.Supervisor._hold_screen.__get__(supervisor)
        supervisor._hold_maybe_record = warm.Supervisor._hold_maybe_record.__get__(supervisor)
        dialog = "Do you want to proceed? (esc to cancel) (esc to cancel)"
        supervisor.screen_classifier.feed(dialog.encode())
        supervisor._hold_maybe_record("blocked")
        self.assertIsNotNone(supervisor.hold_timer)
        # prompt answered -> idle screen
        supervisor.screen_classifier.feed("\u276f ".encode())
        supervisor._hold_maybe_record("idle")
        self.assertFalse(supervisor.hold_timer.expired(now=10000.0))

    def test_profile_rejects_every_confirm_or_multikey_sequence(self):
        for keys in [(b'y',), (b'Y',), (b'\r',), (b'\n',), (b' ',), (b'\x1b[B',), (b'1',), (b'n', b'\x1b')]:
            with self.subTest(keys=keys), self.assertRaises(ValueError):
                self.hold.HoldProfile('test', ['dialog'], keys)
        profile = self.hold.CLAUDE_CODE_PROFILE
        with self.assertRaises(AttributeError):
            profile.deny_keys = (b'y',)
        # Even namedtuple replacement cannot bypass validation at the write.
        with self.assertRaises(ValueError):
            self.hold.deny_bytes(profile._replace(deny_keys=(b'y',)))

    def test_claude_requires_permission_question_and_explicit_cancel_cue(self):
        profile = self.hold.CLAUDE_CODE_PROFILE
        for screen in ['Do you want to proceed?', 'enter to confirm', 'some modal (esc to cancel)']:
            self.assertFalse(profile.matches(screen), screen)

    def test_identity_binds_command_above_and_choices_below_generic_question(self):
        profile = self.hold.CLAUDE_CODE_PROFILE
        question = 'Do you want to proceed?\n1. Yes\nEsc to cancel'
        for old, new in [('rm OLD\n'+question, 'rm NEW\n'+question),
                         ('rm OLD\n'+question, 'rm OLD\n'+question.replace('1. Yes','1. Other'))]:
            self.assertNotEqual(profile.identity(old), profile.identity(new))

    def test_invalid_nonfinite_timeouts_are_bounded(self):
        for timeout in [True, False, 0, -1, float('nan'), float('inf')]:
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.hold.PtyHoldTimer(timeout)
            self.assertEqual(self.hold.hold_timeout_seconds({'hold_timeout_minutes': timeout}), 600)

    def guarded_fixture(self):
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self.addCleanup(lambda: os.close(read_fd))
        self.addCleanup(lambda: os.close(write_fd))
        owner = types.SimpleNamespace(master_fd=write_fd, mailcortex_admission_lock=threading.RLock(),
            status='active', compacting=False, recovery_pending=False, recovery_awaiting=False,
            mailcortex_input_dirty=False, _mailcortex_barrier=contextlib.nullcontext,
            _mailcortex_refresh_screen=lambda: False, _hold_input_pending=lambda: False)
        profile = self.hold.CLAUDE_CODE_PROFILE
        visible = 'rm OLD\nDo you want to proceed?\nEsc to cancel'
        timer = self.hold.PtyHoldTimer(1)
        timer.record(visible, profile, now=0)
        queue = mock.Mock()
        def deny():
            return self.hold.deny_expired_prompt(owner, timer, profile,
                read_screen=lambda: visible, now=lambda: 1, queue_write=queue)
        return owner, timer, queue, deny

    def test_missing_owner_guards_abort(self):
        for field in ['mailcortex_admission_lock', '_mailcortex_barrier', '_mailcortex_refresh_screen',
                      '_hold_input_pending', 'mailcortex_input_dirty']:
            owner, timer, queue, deny = self.guarded_fixture()
            delattr(owner, field)
            with self.subTest(field=field), mock.patch.object(os,'write') as write:
                self.assertFalse(deny())
                write.assert_not_called(); queue.assert_not_called()

    def test_pending_input_before_during_and_after_pause_aborts(self):
        for values in [[True], [False, True], [False, False, True]]:
            owner, timer, queue, deny = self.guarded_fixture()
            owner._hold_input_pending = mock.Mock(side_effect=values)
            with self.subTest(values=values), mock.patch.object(os,'write') as write:
                self.assertFalse(deny())
                write.assert_not_called(); queue.assert_not_called()

    def test_output_in_either_drain_aborts(self):
        for values in [[True], [False, True]]:
            owner, timer, queue, deny = self.guarded_fixture()
            owner._mailcortex_refresh_screen = mock.Mock(side_effect=values)
            with self.subTest(values=values), mock.patch.object(os,'write') as write:
                self.assertFalse(deny())
                write.assert_not_called(); queue.assert_not_called()

    def test_failed_pause_or_input_arriving_inside_barrier_aborts(self):
        for failure in [OSError('stop refused'), ValueError('ownership lost')]:
            owner, timer, queue, deny = self.guarded_fixture()
            owner._mailcortex_barrier = mock.Mock(side_effect=failure)
            with self.subTest(failure=failure), mock.patch.object(os,'write') as write:
                self.assertFalse(deny())
                write.assert_not_called(); queue.assert_not_called()
        owner, timer, queue, deny = self.guarded_fixture()
        @contextlib.contextmanager
        def barrier():
            self.assertTrue(owner.mailcortex_admission_lock._is_owned())
            owner.mailcortex_input_dirty = True
            yield
        owner._mailcortex_barrier = barrier
        with mock.patch.object(os,'write') as write:
            self.assertFalse(deny()); write.assert_not_called(); queue.assert_not_called()

    def test_timer_changed_while_waiting_for_lock_aborts(self):
        owner, timer, queue, deny = self.guarded_fixture()
        @contextlib.contextmanager
        def lock():
            timer.record('rm NEW\nDo you want to proceed?\nEsc to cancel', self.hold.CLAUDE_CODE_PROFILE, 0)
            yield
        owner.mailcortex_admission_lock = lock()
        with mock.patch.object(os,'write') as write:
            self.assertFalse(deny()); write.assert_not_called(); queue.assert_not_called()

    def test_failed_zero_or_partial_write_never_reports_a_deny(self):
        # The profile writes exactly one byte, so any short write is zero.
        for result in [0, OSError('PTY unavailable'), BlockingIOError('PTY full')]:
            owner, timer, queue, deny = self.guarded_fixture()
            with self.subTest(result=result), mock.patch.object(os,'write') as write:
                if isinstance(result, Exception): write.side_effect = result
                else: write.return_value = result
                self.assertFalse(deny()); queue.assert_not_called()
                self.assertEqual(write.call_count, 1)
                self.assertFalse(timer.expired(10))

    def test_queue_failure_after_write_never_replays_deny(self):
        owner, timer, queue, deny = self.guarded_fixture()
        owner._guard_log = mock.Mock()
        queue.side_effect = OSError('recording failed')
        with mock.patch.object(os,'write',return_value=1) as write:
            self.assertTrue(deny())
            self.assertFalse(deny())
            self.assertEqual(write.call_count, 1)
            owner._guard_log.assert_called_once_with('pty-hold-queue-failed')

    def screen_owner(self, warm, text):
        supervisor = types.SimpleNamespace(screen_classifier=warm.ClaudeScreenClassifier(),
            session_id='fixture-session', hold_timer=None, mailcortex_input_dirty=False)
        supervisor._hold_screen = warm.Supervisor._hold_screen.__get__(supervisor)
        supervisor._hold_maybe_record = warm.Supervisor._hold_maybe_record.__get__(supervisor)
        supervisor.screen_classifier.feed(('\x1b[2J\x1b[H'+text).encode())
        return supervisor

    def test_shared_classifier_distinguishes_selection_drafts_and_rendered_hints(self):
        warm = load('review_screen', BIN/'claude-warm')
        for row, expected in [('❯ 1. Yes', True), ('❯ rm something', False),
                              ('❯ \x1b[2mrendered hint\x1b[0m', True)]:
            text='Do you want to proceed?\n'+row+'\n────────\nEsc to cancel'
            supervisor=self.screen_owner(warm,text)
            self.assertEqual(supervisor._hold_screen() is not None,expected,row)
            if row == '❯ 1. Yes':
                self.assertEqual(supervisor.screen_classifier.prompt_input_state(), 'typed')
                self.assertEqual(supervisor.screen_classifier.prompt_input_state(permission_selection=True), 'empty')
        supervisor=self.screen_owner(warm,'Do you want to proceed?\n❯ 1. Yes\nEsc to cancel')
        supervisor.screen_classifier.feed(b'\x1b[')
        self.assertIsNone(supervisor._hold_screen())

    def test_unchanged_screen_state_does_not_clear_or_extend_hold(self):
        warm=load('review_redraw',BIN/'claude-warm')
        supervisor=self.screen_owner(warm,'rm OLD\nDo you want to proceed?\n❯ 1. Yes\nEsc to cancel')
        with mock.patch.object(warm,'_hold_now',return_value=100):
            supervisor._hold_maybe_record('blocked')
        identity=supervisor.hold_timer.identity()
        with mock.patch.object(warm,'_hold_now',return_value=200):
            supervisor._hold_maybe_record(None)
        self.assertEqual(supervisor.hold_timer.identity(),identity)
        self.assertEqual(supervisor.hold_timer._first_seen,100)

    def test_screen_reclassified_after_pause_rejects_typed_draft(self):
        warm=load('review_reclassify',BIN/'claude-warm')
        supervisor=self.screen_owner(warm,'rm OLD\nDo you want to proceed?\n❯ 1. Yes\nEsc to cancel')
        with mock.patch.object(warm,'_hold_now',return_value=0):
            supervisor._hold_maybe_record('blocked')
        supervisor.hold_timer.timeout=1
        owner,timer,queue,deny=self.guarded_fixture()
        owner.master_fd=123
        def reclassify():
            supervisor.screen_classifier.feed('\x1b[2J\x1b[HDo you want to proceed?\n❯ typed draft\n────────\nEsc to cancel'.encode())
            return supervisor._hold_screen()
        with mock.patch.object(os,'write') as write:
            self.assertFalse(self.hold.deny_expired_prompt(owner,supervisor.hold_timer,
                self.hold.CLAUDE_CODE_PROFILE,read_screen=reclassify,now=lambda:1,queue_write=queue))
            write.assert_not_called(); queue.assert_not_called()

    def test_plain_owner_uses_same_lock_and_cancels_hold_on_human_input(self):
        warm=load('review_input_owner',BIN/'claude-warm')
        owner=warm.Supervisor.__new__(warm.Supervisor)
        lock=threading.RLock();owner.mailcortex_admission_lock=lock
        with mock.patch.object(warm,'runtime_root',return_value=self.short), \
             mock.patch.object(warm,'persistent_state_root',return_value=self.base):
            warm.Supervisor.__init__(owner,[], '/usr/bin/true')
        self.addCleanup(owner.socket.close);self.addCleanup(owner.selector.close)
        self.assertIs(owner.mailcortex_admission_lock,lock)
        owner.session_id='fixture-session'
        owner.hold_timer=self.hold.PtyHoldTimer(1)
        owner.hold_timer.record('Do you want to proceed? Esc to cancel',self.hold.CLAUDE_CODE_PROFILE,0)
        owner._record_input_observations([('focus',3,False)])
        self.assertFalse(owner.mailcortex_input_dirty)
        self.assertTrue(owner.hold_timer.expired(1))
        owner._record_input_observations([('keyboard',1,True)])
        self.assertTrue(owner.mailcortex_input_dirty)
        self.assertFalse(owner.hold_timer.expired(1))
        owner._handle_event({'kind':'event','channel':owner.channel,'event':'user-prompt-submit','session_id':'fixture-session'})
        self.assertFalse(owner.mailcortex_input_dirty)

    def test_plain_owner_reuses_acknowledged_mail_guardian_and_input_probe(self):
        warm=load('review_guard',BIN/'claude-warm')
        owner=types.SimpleNamespace()
        guardian=types.SimpleNamespace(paused_child=mock.Mock(return_value=contextlib.nullcontext()),
                                       pending_terminal=mock.Mock(return_value=True))
        with mock.patch.object(warm,'_hold_guardian_module',return_value=guardian):
            warm.Supervisor._mailcortex_barrier(owner)
            self.assertTrue(warm.Supervisor._hold_input_pending(owner))
        guardian.paused_child.assert_called_once_with(owner)
        guardian.pending_terminal.assert_called_once_with(owner)

    def test_bounded_drain_reclassifies_and_refuses_excess_output(self):
        warm=load('review_drain',BIN/'claude-warm')
        owner=types.SimpleNamespace(master_fd=123,screen_classifier=warm.ClaudeScreenClassifier(),screen_state='idle')
        with mock.patch('select.select',side_effect=[([123],[],[]),([],[],[])]), \
             mock.patch.object(warm.os,'read',return_value=b'Do you want to proceed? Esc to cancel'), \
             mock.patch.object(warm,'write_all'):
            self.assertTrue(warm.Supervisor._mailcortex_refresh_screen(owner))
            self.assertEqual(owner.screen_state,'blocked')
        with mock.patch('select.select',return_value=([123],[],[])), \
             mock.patch.object(warm.os,'read',return_value=b'x'), mock.patch.object(warm,'write_all'), \
             self.assertRaises(ValueError):
            warm.Supervisor._mailcortex_refresh_screen(owner)

    def test_real_queue_preserves_full_requests_dedupes_and_stamps_private_ledger(self):
        warm=load('review_queue',BIN/'claude-warm')
        errors=[]
        supervisor=types.SimpleNamespace(session_id='fixture-session',
            screen_classifier=warm.ClaudeScreenClassifier(),_guard_log=lambda *args:errors.append(args))
        manifest=self.base/'manifest.json'
        manifest.write_text(json.dumps({'coordinator_ops':{'seat_account':'YOUR_SEAT@YOUR_HOST.helm'}}))
        queue=self.base/'queue.jsonl'
        env={'HOME':str(self.base),'SO_APPROVAL_KIKIN_MANIFEST':str(manifest),'SO_APPROVAL_MORNING_QUEUE':str(queue)}
        with mock.patch.dict(os.environ,env):
            for command in ['rm OLD','rm OLD','rm NEW']:
                supervisor.screen_classifier.feed(('\x1b[2J\x1b[H'+command+'\nDo you want to proceed?\nEsc to cancel').encode())
                visible=supervisor.screen_classifier._visible_text()
                identity=self.hold.CLAUDE_CODE_PROFILE.identity(visible)
                warm._hold_queue_write(supervisor,self.hold.CLAUDE_CODE_PROFILE,identity)
            runtime=__import__('sys').modules['claude_approval_runtime']
            with queue.open() as handle:records=runtime._queue_read(handle)
        self.assertEqual(errors,[])
        self.assertEqual(len(records),2)
        self.assertEqual(records[0]['count'],2)
        self.assertIn('rm OLD',records[0]['request']['tool_input']['screen_text'])
        self.assertIn('rm NEW',records[1]['request']['tool_input']['screen_text'])
        self.assertEqual({row['reason'] for row in records},{'hold_timeout'})
        ledger=self.base/'.local/state/dotcortex/pty-hold-ledger.jsonl'
        self.assertEqual(ledger.stat().st_mode & 0o777,0o600)
        self.assertEqual(len(ledger.read_text().splitlines()),3)
        self.assertEqual(json.loads(ledger.read_text().splitlines()[-1])['queue_id'],records[-1]['id'])

    def test_real_hold_write_waits_for_acknowledged_pause_and_resumes_child(self):
        warm=load('review_real_pause',BIN/'claude-warm')
        owner,master,_slave=self.deny_owner('x')
        self.addCleanup(lambda:os.close(master))
        owner._pty_still_owned=lambda:True
        owner._mailcortex_barrier=warm.Supervisor._mailcortex_barrier.__get__(owner)
        visible='rm OLD\nDo you want to proceed?\nEsc to cancel'
        timer=self.hold.PtyHoldTimer(1)
        timer.record(visible,self.hold.CLAUDE_CODE_PROFILE,0)
        original_write=os.write
        def state():
            return Path(f'/proc/{owner.pid}/stat').read_text().rsplit(')',1)[1].split()[0]
        def write(fd,data):
            self.assertEqual(state(),'T','child must acknowledge stop before deny')
            self.assertTrue(owner.mailcortex_admission_lock._is_owned())
            return original_write(fd,data)
        queued=[]
        def queue(identity):
            self.assertNotEqual(state(),'T','queue I/O must follow child resume')
            queued.append(identity)
        with mock.patch.object(os,'write',side_effect=write):
            self.assertTrue(self.hold.deny_expired_prompt(owner,timer,self.hold.CLAUDE_CODE_PROFILE,
                read_screen=lambda:visible,now=lambda:1,queue_write=queue))
        self.assertEqual(self.read_master(master,1),b'\x1b')
        self.assertEqual(len(queued),1)

    def test_resume_failure_preserves_completed_deny_without_replaying_it(self):
        owner, timer, queue, deny = self.guarded_fixture()
        owner._guard_log = mock.Mock()
        @contextlib.contextmanager
        def barrier():
            yield
            raise ValueError('resume acknowledgement lost')
        owner._mailcortex_barrier = barrier
        with mock.patch.object(os, 'write', return_value=1) as write:
            self.assertTrue(deny())
            self.assertFalse(deny())
            self.assertEqual(write.call_count, 1)
            queue.assert_called_once()
            owner._guard_log.assert_called_once_with('pty-hold-resume-failed')

    def test_hold_timeout_uses_selected_seat_manifest(self):
        warm = load('review_manifest', BIN / 'claude-warm')
        manifest = self.base / 'seat.json'
        manifest.write_text(json.dumps({'unattended': {'hold_timeout_minutes': 2}}))
        with mock.patch.dict(os.environ, {'SO_APPROVAL_KIKIN_MANIFEST': str(manifest)}):
            self.assertEqual(warm._hold_timeout_seconds(), 120)
            manifest.write_text('{invalid')
            self.assertEqual(warm._hold_timeout_seconds(), 600)


    def test_blocking_owner_descriptor_aborts_before_write(self):
        owner, timer, queue, deny = self.guarded_fixture()
        os.set_blocking(owner.master_fd, True)
        with mock.patch.object(os, 'write') as write:
            self.assertFalse(deny())
            write.assert_not_called()
            queue.assert_not_called()

    def test_plain_hold_recording_errors_reach_private_guard_log(self):
        warm = load('review_plain_log', BIN / 'claude-warm')
        owner = types.SimpleNamespace(watched_servers=(), development_channel_opt_ins=(),
            channel='claude-' + '0' * 32, channel_health='none',
            guard_log_path=self.base / 'guard.jsonl', _debug=mock.Mock())
        warm.Supervisor._guard_log(owner, 'pty-hold-record-failed')
        self.assertEqual(json.loads(owner.guard_log_path.read_text())['event'], 'pty-hold-record-failed')
        self.assertEqual(owner.guard_log_path.stat().st_mode & 0o777, 0o600)


class BlockingDialogDismissTests(unittest.TestCase):
    """claude-warm dismisses known non-permission blocking dialogs.

    The 2026-10-16 autocompact prompt froze a warm seat for 2.5 h: it is a
    modal, the seat still classifies idle, and only the permission hold
    existed.  A known dialog carries an exact fingerprint (heading,
    question, highlighted default and the dialog's own footer cues, all
    required) plus one safe key, fired only after a short settle while the
    seat is otherwise idle.  Permission prompts never enter this path;
    unknown dialogs are only logged once, never keyed.
    """

    # The captured autocompact dialog (Telegram 7563, Bunta's seat).
    AUTOcompact_SCREEN = (
        "We recommend compacting earlier\n"
        "\n"
        "Want to autocompact at 400k tokens instead?\n"
        "\n"
        "❯ Keep auto (1m tokens)\n"
        "  Autocompact at ‹ 400k › tokens\n"
        "\n"
        "↑/↓ choose · ←/→ change size · enter confirm · esc not now\n"
    )
    UNKNOWN_SCREEN = (
        "Another modal heading\n"
        "\n"
        "❯ Do the thing\n"
        "\n"
        "↑/↓ choose · enter confirm · esc dismiss\n"
    )
    IDLE_SCREEN = "❯ \n  ⏸ manual mode on · ? for shortcuts · ← for agents\n"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.warm = load("dialog_warm", BIN / "claude-warm")
        self.hold = load("dialog_hold", LIB / "approval_hold_pty.py")
        patcher = mock.patch.object(Path, "home", lambda: self.base)
        patcher.start()
        self.addCleanup(patcher.stop)

    def pty_owner(self):
        """A real PTY whose child echoes what the supervisor writes.

        The slave is fully raw: no ECHO/ICANON, no OPOST, and no ICRNL, so
        the master observes the exact dismiss byte (b"\\r") the supervisor
        wrote instead of the line discipline's CR-to-NL translation."""
        import pty
        import termios
        master, slave = pty.openpty()
        os.set_blocking(master, False)
        attrs = termios.tcgetattr(slave)
        attrs[0] &= ~(termios.ICRNL | termios.INLCR | termios.IGNCR)
        attrs[1] &= ~termios.OPOST
        attrs[3] &= ~(termios.ECHO | termios.ECHOCTL | termios.ICANON)
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        reader = subprocess.Popen(
            [sys.executable, "-c",
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
        def reap():
            if reader.poll() is None:
                reader.kill()
            reader.wait(timeout=5)
        self.addCleanup(reap)
        return master, reader.pid

    def supervisor(self, master, screen=b""):
        supervisor = types.SimpleNamespace(
            screen_classifier=self.warm.ClaudeScreenClassifier(),
            session_id="fixture-session",
            hold_timer=None, dialog_timer=None, dialog_unknown_logged=False,
            mailcortex_admission_lock=threading.RLock(),
            master_fd=master,
            status="idle", compacting=False, recovery_pending=False,
            recovery_awaiting=False, mailcortex_input_dirty=False,
        )
        for name in ("_dialog_screen", "_dialog_visible", "_dialog_maybe_record",
                     "_dialog_maybe_log_unknown", "_dialog_expire",
                     "_hold_screen", "_hold_maybe_record"):
            setattr(supervisor, name, getattr(self.warm.Supervisor, name).__get__(supervisor))
        supervisor._mailcortex_barrier = contextlib.nullcontext
        supervisor._mailcortex_refresh_screen = lambda: False
        supervisor._hold_input_pending = lambda: False
        supervisor._guard_log = mock.Mock()
        if screen:
            supervisor.screen_classifier.feed(b"\x1b[2J\x1b[H" + screen)
        return supervisor

    def read_master(self, master, expect_len, deadline_s=2.0):
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

    def master_quiet(self, master, seconds=0.2):
        """True when no further PTY bytes arrive. The fixture child exits
        right after echoing its byte, so a closed slave (EOF) is quiet,
        not a second key."""
        import select
        ready, _, _ = select.select([master], [], [], seconds)
        if not ready:
            return True
        try:
            return not os.read(master, 4096)
        except OSError:
            return True

    def ledger_records(self, action=None):
        path = self.base / ".local/state/dotcortex/pty-hold-ledger.jsonl"
        if not path.exists():
            return []
        records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        return [record for record in records
                if action is None or record.get("action") == action]

    def test_captured_dialog_detected_while_seat_looks_idle(self):
        master, _pid = self.pty_owner()
        self.addCleanup(lambda: os.close(master))
        supervisor = self.supervisor(master, self.AUTOcompact_SCREEN.encode())
        visible = supervisor.screen_classifier._visible_text()
        # the freeze scenario: the modal is up, yet the seat classifies idle
        self.assertEqual(supervisor.screen_classifier._classify(visible), "idle")
        self.assertIsNotNone(self.warm.match_known_dialog(visible))
        screen, dialog = supervisor._dialog_screen()
        self.assertEqual(screen, visible)
        self.assertEqual(dialog.dialog_id, "autocompact-400k")
        self.assertEqual(dialog.dismiss_key, b"\r")
        # Enter confirms the highlighted default, the Admiral's "Keep auto"
        self.assertIn("keep auto (1m tokens)", visible.lower())
        with mock.patch.object(self.warm, "_hold_now", return_value=100):
            supervisor._dialog_maybe_record()
        self.assertIsNotNone(supervisor.dialog_timer)
        self.assertEqual(self.warm.DIALOG_SETTLE_SECONDS, 5.0)
        self.assertFalse(supervisor.dialog_timer.expired(104.0))
        self.assertTrue(supervisor.dialog_timer.expired(105.5))

    def test_dismiss_fires_enter_once_after_settle_and_ledger_records(self):
        master, _pid = self.pty_owner()
        self.addCleanup(lambda: os.close(master))
        supervisor = self.supervisor(master, self.AUTOcompact_SCREEN.encode())
        with mock.patch.object(self.warm, "_hold_now", return_value=100):
            supervisor._dialog_maybe_record()
        with mock.patch.object(self.warm, "_hold_now", return_value=104.0):
            self.assertFalse(supervisor.dialog_timer.expired(self.warm._hold_now()))
        with mock.patch.object(self.warm, "_hold_now", return_value=106):
            supervisor._dialog_expire()
            supervisor._dialog_expire()  # cleared timer: never a second write
        self.assertEqual(self.read_master(master, 1), b"\r")
        self.assertTrue(self.master_quiet(master))
        records = self.ledger_records("dialog_dismissed")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["dialog"], "autocompact-400k")
        self.assertEqual(records[0]["session"], "fixture-session")
        self.assertTrue(records[0]["dialog_identity"])
        self.assertFalse(self.ledger_records("dialog_unknown"))

    def test_captured_permission_prompt_never_matched_by_dialog_path(self):
        captures = load("dialog_captures", Path(__file__).with_name("claude_renderer_captures.py"))
        for mode, frames in captures.FULLSCREEN.items():
            with self.subTest(mode=mode):
                master, _pid = self.pty_owner()
                try:
                    supervisor = self.supervisor(master, frames["permission"])
                    visible = supervisor.screen_classifier._visible_text()
                    self.assertEqual(supervisor.screen_classifier._classify(visible), "blocked")
                    self.assertIsNone(self.warm.match_known_dialog(visible))
                    self.assertEqual(supervisor._dialog_screen(), (None, None))
                    supervisor._dialog_maybe_record()
                    self.assertIsNone(supervisor.dialog_timer)
                    # the permission path is untouched: the AFK hold still records
                    supervisor._hold_maybe_record("blocked")
                    self.assertIsNotNone(supervisor.hold_timer)
                    self.assertTrue(self.master_quiet(master))
                    self.assertEqual(self.ledger_records(), [])
                finally:
                    os.close(master)

    def test_fingerprint_requires_the_whole_dialog_never_loose_words(self):
        variants = (
            "We recommend compacting earlier\n",
            "↑/↓ choose · ←/→ change size · enter confirm · esc not now\n",
            "We recommend compacting earlier\nWant to autocompact at 400k tokens instead?\n",
            "❯ Keep auto (1m tokens)\n↑/↓ choose · enter confirm · esc not now\n",
            "transcript: we recommend compacting earlier some time ago\n❯ \n",
            "Do you want to proceed?\n❯ 1. Yes\nEsc to cancel\n",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertIsNone(self.warm.match_known_dialog(variant))
        # the complete captured dialog is the only positive match, and its
        # identity binds the whole screen
        dialog = self.warm.match_known_dialog(self.AUTOcompact_SCREEN)
        self.assertEqual(dialog.dialog_id, "autocompact-400k")
        self.assertEqual(dialog.identity(self.AUTOcompact_SCREEN),
                         dialog.identity(self.AUTOcompact_SCREEN))
        self.assertIsNone(dialog.identity(variants[0]))

    def test_unknown_dialog_logged_once_and_never_keyed(self):
        master, _pid = self.pty_owner()
        self.addCleanup(lambda: os.close(master))
        supervisor = self.supervisor(master, self.UNKNOWN_SCREEN.encode())
        supervisor._dialog_maybe_record()
        self.assertIsNone(supervisor.dialog_timer)
        records = self.ledger_records("dialog_unknown")
        self.assertEqual(len(records), 1)
        self.assertIn("enter confirm · esc dismiss", records[0]["screen_text_snippet"])
        self.assertTrue(records[0]["screen_text_snippet"])
        # a redraw of the same episode logs nothing more
        supervisor.screen_classifier.feed(b"\x1b[2J\x1b[H" + self.UNKNOWN_SCREEN.encode())
        supervisor._dialog_maybe_record()
        self.assertEqual(len(self.ledger_records("dialog_unknown")), 1)
        # the episode ends, then a new unknown dialog logs once again
        supervisor.screen_classifier.feed(b"\x1b[2J\x1b[H" + self.IDLE_SCREEN.encode())
        supervisor._dialog_maybe_record()
        supervisor.screen_classifier.feed(b"\x1b[2J\x1b[H" + self.UNKNOWN_SCREEN.encode())
        supervisor._dialog_maybe_record()
        self.assertEqual(len(self.ledger_records("dialog_unknown")), 2)
        # unknown dialogs are left alone: no key ever reaches the PTY
        self.assertTrue(self.master_quiet(master))
        self.assertFalse(self.ledger_records("dialog_dismissed"))

    def test_normal_idle_and_busy_chrome_never_log_dialog_unknown(self):
        captures = load("dialog_chrome", Path(__file__).with_name("claude_renderer_captures.py"))
        for mode, frames in captures.FULLSCREEN.items():
            for name in ("empty", "busy", "post-turn", "suggestion", "typed"):
                with self.subTest(mode=mode, screen=name):
                    master, _pid = self.pty_owner()
                    try:
                        supervisor = self.supervisor(master, frames[name])
                        supervisor._dialog_maybe_record()
                        self.assertIsNone(supervisor.dialog_timer)
                        self.assertEqual(self.ledger_records("dialog_unknown"), [])
                    finally:
                        os.close(master)

    def test_pending_input_aborts_dismiss_without_write_or_ledger(self):
        master, _pid = self.pty_owner()
        self.addCleanup(lambda: os.close(master))
        supervisor = self.supervisor(master, self.AUTOcompact_SCREEN.encode())
        with mock.patch.object(self.warm, "_hold_now", return_value=100):
            supervisor._dialog_maybe_record()
        supervisor._hold_input_pending = lambda: True
        with mock.patch.object(self.warm, "_hold_now", return_value=106):
            supervisor._dialog_expire()
        self.assertTrue(self.master_quiet(master))
        self.assertEqual(self.ledger_records(), [])
        # the guard cleared the timer: no retry at a later deadline
        with mock.patch.object(self.warm, "_hold_now", return_value=200):
            supervisor._dialog_expire()
        self.assertTrue(self.master_quiet(master))

    def test_busy_owner_states_never_dismiss(self):
        for field in ("compacting", "recovery_pending", "recovery_awaiting"):
            with self.subTest(field=field):
                master, _pid = self.pty_owner()
                try:
                    supervisor = self.supervisor(master, self.AUTOcompact_SCREEN.encode())
                    with mock.patch.object(self.warm, "_hold_now", return_value=100):
                        supervisor._dialog_maybe_record()
                    setattr(supervisor, field, True)
                    with mock.patch.object(self.warm, "_hold_now", return_value=106):
                        supervisor._dialog_expire()
                    self.assertTrue(self.master_quiet(master))
                finally:
                    os.close(master)
        # a working screen is not an idle-on-dialog screen even with the
        # fingerprint text present: the state gate holds
        master, _pid = self.pty_owner()
        self.addCleanup(lambda: os.close(master))
        working = self.AUTOcompact_SCREEN + "✻ Working…\n"
        supervisor = self.supervisor(master, working.encode())
        visible = supervisor.screen_classifier._visible_text()
        self.assertEqual(supervisor.screen_classifier._classify(visible), "working")
        self.assertIsNotNone(self.warm.match_known_dialog(visible))
        supervisor._dialog_maybe_record()
        self.assertIsNone(supervisor.dialog_timer)

    def test_dialog_table_is_deny_shape_and_small(self):
        self.assertEqual(self.warm.DIALOG_DISMISS_KEYS, (b"\r",))
        ids = [dialog.dialog_id for dialog in self.warm.KNOWN_BLOCKING_DIALOGS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, ["autocompact-400k"])
        for dialog in self.warm.KNOWN_BLOCKING_DIALOGS:
            self.assertGreaterEqual(len(dialog.required_markers), 4)
            self.assertIn(dialog.dismiss_key, self.warm.DIALOG_DISMISS_KEYS)
        for bad in [b"y", b"\n", b" ", b"\x1b", b"\x1b[B", (b"\r", b"y")]:
            with self.subTest(key=bad), self.assertRaises(ValueError):
                self.warm.BlockingDialog("bad", ("marker",), bad)
        for bad_markers in [(), ("",), (1,)]:
            with self.subTest(markers=bad_markers), self.assertRaises(ValueError):
                self.warm.BlockingDialog("bad", bad_markers, b"\r")
        with self.assertRaises(ValueError):
            self.warm.BlockingDialog("", ("marker",), b"\r")


if __name__ == "__main__":
    unittest.main(verbosity=2)
