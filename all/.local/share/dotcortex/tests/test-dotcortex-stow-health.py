#!/usr/bin/env python3
"""Tests for dotcortex-stow-health (dotcortex.org): relative and absolute Stow orphans."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
SCANNER = ROOT / "linux/.local/bin/dotcortex-stow-health"


class Home:
    def __init__(self, symlinked_checkout=False):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.home.mkdir()
        if symlinked_checkout:
            real = self.home / "src/dc"
            real.mkdir(parents=True)
            os.symlink("src/dc", self.home / "DotCortex")
        else:
            (self.home / "DotCortex").mkdir()
        dot = self.home / "DotCortex"
        (dot / "all").mkdir()
        (dot / "all/kept").write_text("x\n")
        (self.home / ".local/bin").mkdir(parents=True)
        (self.home / ".local/share").mkdir(parents=True)
        (self.home / "DotCortex-old").mkdir()

    def link(self, rel, target):
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, path)
        return path

    def run(self, *args):
        env = dict(os.environ, HOME=str(self.home))
        env.pop("DOTCORTEX_ROOT", None)
        return subprocess.run(["bash", str(SCANNER), *args], capture_output=True, text=True, env=env)

    def close(self):
        shutil.rmtree(self.tmp)


class StowHealthTests(unittest.TestCase):
    def setUp(self):
        self.box = Home()
        b = self.box
        self.orphans = [
            b.link(".local/bin/honey-opus", "../../DotCortex/honey/.local/bin/honey-opus"),
            b.link(".local/share/honey-claude", "../../DotCortex/honey/.local/share/honey-claude"),
            b.link(".oldabs", str(b.home / "DotCortex/gone")),
            b.link(".config/deep/x", "../../DotCortex/all/../linux/gone"),
        ]
        self.kept = [
            b.link(".foreign", "/nonexistent/elsewhere"),
            b.link(".sibling", "DotCortex-old/gone"),
            b.link(".valid", "DotCortex/all/kept"),
            b.link("DotCortex/all/inrepo", "/home/nobody/x"),
        ]

    def tearDown(self):
        self.box.close()

    def test_scan_tags_orphans_and_removes_nothing(self):
        out = self.box.run()
        self.assertEqual(out.returncode, 0, out.stderr)
        for path in self.orphans:
            self.assertIn(f"BROKEN: {path} -> {os.readlink(path)} (stow orphan)", out.stdout)
            self.assertTrue(path.is_symlink())
        self.assertIn(f"BROKEN: {self.kept[0]} -> /nonexistent/elsewhere\n", out.stdout)
        self.assertNotIn("(stow orphan)", out.stdout.split(str(self.kept[1]))[1].splitlines()[0])
        self.assertNotIn(".valid", out.stdout)
        self.assertNotIn("inrepo", out.stdout, "the checkout itself is never scanned")
        self.assertIn("6 broken, 4 stow orphan(s)", out.stdout)

    def test_fix_stow_removes_relative_and_absolute_orphans_only(self):
        out = self.box.run("--fix-stow")
        self.assertEqual(out.returncode, 0, out.stderr)
        for path in self.orphans:
            self.assertFalse(path.is_symlink(), path)
        for path in self.kept:
            self.assertTrue(path.is_symlink(), path)
        self.assertIn("4 stow orphan(s) removed", out.stdout)

    def test_unknown_argument_is_refused(self):
        self.assertEqual(self.box.run("--fix").returncode, 2)


class SymlinkedCheckoutTests(unittest.TestCase):
    def test_orphans_through_either_path_are_removed(self):
        box = Home(symlinked_checkout=True)
        try:
            via_link = box.link(".a", "DotCortex/gone")
            via_real = box.link(".b", "src/dc/gone")
            inside = box.link("src/dc/all/inrepo", "/home/nobody/x")
            out = box.run("--fix-stow")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertFalse(via_link.is_symlink())
            self.assertFalse(via_real.is_symlink())
            self.assertTrue(inside.is_symlink(), "the real checkout is never scanned either")
        finally:
            box.close()


if __name__ == "__main__":
    unittest.main()
