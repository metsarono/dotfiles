#!/usr/bin/env python3
"""Tests for the host stow lanes (package-host-excludes.org, "Stow lanes")."""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
HELPER = ROOT / "all/.local/bin/dotcortex-stow-excludes"
LAYERS = ROOT / "all/.local/bin/dotcortex-layers"
MANIFEST = ROOT / "all/.provision/host-excludes.ssv"
OTHER_HOSTS = ("x230", "ThinkPad-T480s", "t480", "kikin-kushi", "localhost")


def run(*args, host="beelink", manifest=MANIFEST, check=True):
    env = dict(os.environ, HOST_EXCLUDES=str(manifest), HOST_EXCLUDES_HOSTNAME=host)
    return subprocess.run([str(HELPER), *args], env=env, capture_output=True, text=True, check=check)


class LaneTests(unittest.TestCase):
    def test_only_honey_has_stow_rows(self):
        self.assertIn("--ignore=^\\.config/bspwm", run("ignore-args").stdout.splitlines())
        self.assertEqual(run("skip-hook", "icons-home-sync", check=False).returncode, 0)
        for host in OTHER_HOSTS:
            self.assertEqual(run("ignore-args", host=host).stdout, "", host)
            self.assertEqual(run("skip-hook", "icons-home-sync", host=host, check=False).returncode, 1, host)
            with tempfile.TemporaryDirectory() as tmp:
                out = run("prune", "--target", tmp, "--repo", str(ROOT), host=host)
                self.assertEqual(out.stdout, "", host)

    def test_trait_rows_use_only_stow_lanes(self):
        for line in MANIFEST.read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if fields and fields[0] == "beelink":
                self.assertIn(fields[1], {"stow", "stow-hook"}, line)

    def test_unsafe_paths_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bad in ("../outside", ".config/*", "a/../../b", "/etc"):
                manifest = Path(tmp) / "m.ssv"
                manifest.write_text(f'beelink stow {bad} "x"\n')
                out = run("ignore-args", manifest=manifest, check=False)
                self.assertNotEqual(out.returncode, 0, bad)


@unittest.skipUnless(shutil.which("stow"), "GNU Stow is not installed")
class FoldingTests(unittest.TestCase):
    def test_honey_stack_exposes_no_excluded_path(self):
        pkgs = subprocess.run([str(LAYERS), "resolve", "--host", "beelink", "--user", "metsatron"],
                              capture_output=True, text=True, check=True).stdout.split()
        ignores = run("ignore-args").stdout.split()
        excluded = run("paths").stdout.split()
        with tempfile.TemporaryDirectory() as target:
            out = subprocess.run(["stow", "-n", "-v", f"--target={target}", "--ignore=\\.bak\\.", *ignores, *pkgs],
                                 cwd=ROOT, capture_output=True, text=True)
            self.assertNotIn("All operations aborted", out.stderr + out.stdout)
            links = {}
            for line in (out.stderr + out.stdout).splitlines():
                if m := re.match(r"UNLINK: (\S+)", line):
                    links.pop(m.group(1), None)
                elif m := re.match(r"LINK: (\S+) => (\S+)", line):
                    links[m.group(1)] = m.group(2)
        exposed = []
        for rel, dest in links.items():
            src = ROOT / re.sub(r"^(\.\./)+[^/]+/", "", dest)
            reached = [rel]
            if src.is_dir() and not src.is_symlink():
                reached += [str(Path(rel) / p.relative_to(src)) for p in src.rglob("*")]
            for path in reached:
                if any(path == e or path.startswith(e + "/") for e in excluded):
                    exposed.append(path)
        self.assertEqual(exposed[:10], [], f"{len(exposed)} excluded paths still linked")


class PruneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / "DotCortex"
        self.home = self.tmp / "home"
        for rel in ("all/.config/bspwm/bspwmrc", "all/.config/git/config", "all/.face",
                    "linux/.icons/Chicago95/index.theme"):
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / rel).write_text("x\n")
        (self.home / ".config/bspwm").mkdir(parents=True)
        (self.home / ".config/git").mkdir(parents=True)
        (self.home / ".icons/own").mkdir(parents=True)
        os.symlink("../../../DotCortex/all/.config/bspwm/bspwmrc", self.home / ".config/bspwm/bspwmrc")
        os.symlink("../../../DotCortex/all/.config/git/config", self.home / ".config/git/config")
        os.symlink("../DotCortex/all/.face", self.home / ".face")
        os.symlink(str(self.repo / "linux/.icons/Chicago95"), self.home / ".icons/Chicago95")
        (self.home / ".icons/own/cursor").write_text("mine\n")
        os.symlink("/usr/share/icons/Adwaita", self.home / ".icons/Adwaita")
        self.manifest = self.tmp / "m.ssv"
        self.manifest.write_text('beelink stow .config/bspwm "x"\nbeelink stow .face "x"\nbeelink stow .icons "x"\n')

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def prune(self, *extra):
        return run("prune", "--target", str(self.home), "--repo", str(self.repo), *extra, manifest=self.manifest)

    def test_dry_run_lists_and_changes_nothing(self):
        listed = self.prune().stdout.splitlines()
        self.assertEqual(len(listed), 3, listed)
        self.assertTrue(all(line.startswith("would remove ") for line in listed))
        self.assertTrue((self.home / ".config/bspwm/bspwmrc").is_symlink())

    def test_apply_removes_only_repo_links_and_emptied_dirs(self):
        self.prune("--apply")
        self.assertFalse((self.home / ".config/bspwm").exists(), "emptied dir should go")
        self.assertFalse((self.home / ".face").is_symlink())
        self.assertFalse((self.home / ".icons/Chicago95").is_symlink())
        self.assertTrue((self.home / ".config/git/config").is_symlink(), "not excluded")
        self.assertEqual((self.home / ".icons/own/cursor").read_text(), "mine\n")
        self.assertTrue((self.home / ".icons/Adwaita").is_symlink(), "foreign link kept")
        self.assertTrue((self.home / ".config").is_dir())
        self.assertEqual(self.prune().stdout, "", "second prune finds nothing")


if __name__ == "__main__":
    unittest.main()
