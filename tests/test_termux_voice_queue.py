"""A voice must not expire while it waits its turn on the phone's play queue (ruling 2026-10-02).

The S24's detached players queue behind one flock. The old bounds (300 s in termux-kitten-say, 120 s in pvox-phone-play) dropped replies that waited behind a few long ones, so the wait is now a four-hour runaway guard. These tests run termux-kitten-say against stub binaries and a held lock; nothing here touches a phone.
"""

import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
KITTEN = ROOT / "termux/.local/bin/termux-kitten-say"
PHONE_PLAY = ROOT / "termux/.local/bin/pvox-phone-play"
GUARD_SECONDS = 14400

STUBS = {
    "pulseaudio": "#!/bin/sh\nexit 0\n",
    "proot-distro": (
        "#!/bin/sh\n"
        "cat > /dev/null\n"
        "if [ \"${FAKE_KITTEN_PARTIAL:-0}\" = 1 ]; then\n"
        "  printf '[kitten-say] summary chunks=3 rendered=2 skipped=1\\n' >&2\n"
        "else\n"
        "  printf '[kitten-say] summary chunks=1 rendered=1 skipped=0\\n' >&2\n"
        "fi\n"
        "printf 'pcm'\n"
    ),
    "pvox-pcm-start-gate": "#!/bin/sh\ncat\n",
    "sox": "#!/bin/sh\ncat > /dev/null\n",
    "pvox-speech-receipt": '#!/bin/sh\necho "$1 $2 $3" >> "$FAKE_HOME/receipts.log"\n',
}


def write_exe(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class KittenQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="termux-voice-queue-"))
        self.home = self.tmp / "home"
        self.bin = self.tmp / "bin"
        (self.home / ".cache").mkdir(parents=True)
        self.bin.mkdir()
        for name, body in STUBS.items():
            write_exe(self.bin / name, body)
        self.env = {
            **os.environ,
            "HOME": str(self.home),
            "FAKE_HOME": str(self.home),
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "PVOX_SPEAKER_ID": "fable",
            "PVOX_PLAYBACK_ID": "queue-test-1",
        }
        self.env.pop("PVOX_REPLY_LOCK_WAIT", None)
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.tmp)]))

    def hold_lock(self, seconds: int) -> subprocess.Popen:
        holder = subprocess.Popen(
            ["sh", "-c", f'exec 9>"$HOME/.pvox-reply-play.lock"; flock 9; echo held; sleep {seconds}'],
            env=self.env, stdout=subprocess.PIPE, text=True,
        )
        self.assertEqual(holder.stdout.readline().strip(), "held")
        self.addCleanup(holder.kill)
        return holder

    def say(self, env_extra=None, timeout=60) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(KITTEN), "--voice", "Luna", "--speed", "1.2", "hello"],  # the shebang names a Termux path
            env={**self.env, **(env_extra or {})}, capture_output=True, text=True, timeout=timeout,
        )

    def receipts(self) -> list[str]:
        path = self.home / "receipts.log"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def log(self) -> str:
        path = self.home / ".cache" / "kitten-say.log"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def test_a_voice_waits_its_turn_behind_a_busy_queue_instead_of_expiring(self) -> None:
        holder = self.hold_lock(3)
        started = time.time()
        result = self.say()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(time.time() - started, 2, "the voice must have waited for the lock holder")
        self.assertNotIn("status=expired", self.log())
        self.assertIn("rc=0", self.log())
        self.assertIn("chunks=1 rendered=1 skipped=0", self.log())
        self.assertEqual(self.receipts(), ["queued fable queue-test-1", "player_exited fable queue-test-1"])
        holder.wait(timeout=10)

    def test_renderer_summary_marks_partial_audio_without_calling_it_complete(self) -> None:
        result = self.say({"FAKE_KITTEN_PARTIAL": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("chunks=3 rendered=2 skipped=1", self.log())
        self.assertNotIn("chunks=3 rendered=3 skipped=0", self.log())

    def test_the_runaway_guard_still_expires_a_voice_when_asked_to_and_says_so(self) -> None:
        self.hold_lock(6)
        result = self.say({"PVOX_REPLY_LOCK_WAIT": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("status=expired wait=1s", self.log())
        self.assertEqual(self.receipts(), ["queued fable queue-test-1", "player_exited fable queue-test-1"])

    def test_default_wait_is_a_runaway_guard_in_both_phone_players(self) -> None:
        kitten = re.search(r'LOCK_WAIT="\$\{PVOX_REPLY_LOCK_WAIT:-(\d+)\}"', KITTEN.read_text(encoding="utf-8"))
        self.assertIsNotNone(kitten, "termux-kitten-say lost its configurable lock wait")
        self.assertGreaterEqual(int(kitten.group(1)), GUARD_SECONDS)
        play = re.search(r'flock -w "\$\{PVOX_REPLY_LOCK_WAIT:-(\d+)\}" 9', PHONE_PLAY.read_text(encoding="utf-8"))
        self.assertIsNotNone(play, "pvox-phone-play must take the same configurable wait, not a fixed two minutes")
        self.assertGreaterEqual(int(play.group(1)), GUARD_SECONDS)


if __name__ == "__main__":
    unittest.main()
