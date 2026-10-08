#!/usr/bin/env python3
"""Ductor OpenRC body: PATH and the Honey confs (agents-ductor-seams.org)."""
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


OPENRC = Path(__file__).resolve().parents[1] / "ductor-seams/openrc"
STUBS = """
getent() { echo "$2:x:2001:2001::/home/$2:/bin/sh"; }
"""


def path_for(conf: str) -> str:
    prog = f"{STUBS}\nRC_SVCNAME=t\nPATH=/usr/bin:/bin\n{conf}\n. '{OPENRC / 'ductor'}'\necho \"$PATH\""
    return subprocess.run(["bash", "-c", prog], capture_output=True, text=True, timeout=30).stdout.strip()


class DuctorOpenrcTests(unittest.TestCase):
    def test_path_without_addition_is_unchanged(self) -> None:
        self.assertEqual(path_for('ductor_user="u"; ductor_home="/h"'),
                         "/usr/bin:/bin:/home/u/.local/bin:/home/u/.npm-global/bin")

    def test_honey_codex_appends_the_guix_node(self) -> None:
        conf = (OPENRC / "conf/honey-codex").read_text()
        self.assertEqual(path_for(conf), "/usr/bin:/bin:/home/agent-codex/.local/bin:/home/agent-codex/.npm-global/bin:"
                         "/home/agent-codex/.guix-extra-profiles/agent/agent/bin")


if __name__ == "__main__":
    unittest.main()
