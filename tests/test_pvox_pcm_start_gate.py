"""The phone's StarFox receipt must not precede actual Kitten PCM."""

import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


GATE = Path(__file__).resolve().parents[1] / "termux/.local/bin/pvox-pcm-start-gate"
PYTHON = sys.executable or getattr(sys, "_base_executable", "") or shutil.which("python3") or "/usr/bin/python3"


class PcmStartGateTests(unittest.TestCase):
    def run_gate(self, pcm: bytes, identify: bool = True, levels: bool = False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            receipt = root / "receipt"
            receipt.write_text(
                '#!/bin/sh\n'
                'if [ "$1" = levels ]; then\n'
                '  while IFS= read -r level; do printf "level %s %s %s\\n" "$2" "$3" "$level" >> "$PVOX_TEST_RECEIPTS"; done\n'
                'else\n'
                '  printf "%s\\n" "$*" >> "$PVOX_TEST_RECEIPTS"\n'
                'fi\n'
            )
            receipt.chmod(0o700)
            env = os.environ.copy()
            env.update(PATH=f"{tmp}:{env.get('PATH', os.defpath)}", PVOX_TEST_RECEIPTS=str(root / "events"))
            if levels:
                env.pop("PVOX_LEVELS_OFF", None)
                env["PVOX_LEVEL_WINDOW_SAMPLES"] = "240"
            else:
                env["PVOX_LEVELS_OFF"] = "1"
            if identify:
                env.update(PVOX_SPEAKER_ID="fable", PVOX_PLAYBACK_ID="play123")
            else:
                env.pop("PVOX_SPEAKER_ID", None)
                env.pop("PVOX_PLAYBACK_ID", None)
            (root / "pvox-speech-receipt").symlink_to(receipt)
            result = subprocess.run(
                [PYTHON, str(GATE)], input=pcm, capture_output=True, env=env, check=True
            )
            events = (root / "events").read_text().splitlines() if (root / "events").exists() else []
            return result.stdout, events

    def test_empty_and_silence_do_not_start(self):
        for pcm in (b"", b"\x00\x00" * 4000):
            with self.subTest(length=len(pcm)):
                self.assertEqual(self.run_gate(pcm), (pcm, []))

    def test_first_signal_starts_once_and_preserves_pcm(self):
        pcm = b"\x00\x00" * 3000 + b"\x01\x00" + b"\x00\x00" * 2000 + b"\xff\x7f"
        self.assertEqual(self.run_gate(pcm), (pcm, ["player_started fable play123"]))

    def test_rms_levels_are_bounded_and_pcm_is_unchanged(self):
        pcm = struct.pack("<720h", *([1_000] * 240 + [12_000] * 240 + [0] * 240))
        output, events = self.run_gate(pcm, levels=True)
        self.assertEqual(output, pcm)
        self.assertEqual(events[0], "player_started fable play123")
        levels = [int(event.rsplit(" ", 1)[1]) for event in events[1:]]
        self.assertEqual(len(levels), 3)
        self.assertTrue(all(0 <= level <= 100 for level in levels))
        self.assertGreater(levels[1], levels[0])
        self.assertEqual(levels[2], 0)

    def test_unidentified_stream_remains_passthrough(self):
        pcm = b"\x01\x00" * 5000
        self.assertEqual(self.run_gate(pcm, identify=False, levels=True), (pcm, []))


if __name__ == "__main__":
    unittest.main()
