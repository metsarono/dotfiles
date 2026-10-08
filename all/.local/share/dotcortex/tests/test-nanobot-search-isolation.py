"""Synthetic process-boundary checks; no live gateway or filesystem scan."""
from __future__ import annotations

import asyncio
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[4] / ".bots/patches/nanobot-search-isolation.py"
MODULE_DIR = tempfile.TemporaryDirectory(prefix="nano-isolation-module-")
shutil.copyfile(SOURCE, Path(MODULE_DIR.name) / "candidate_search_isolation.py")
sys.path.insert(0, MODULE_DIR.name)
from candidate_search_isolation import isolated_search
from nanobot.agent.tools.search import FindFilesTool, GrepTool
from nanobot.security.workspace_access import (
    bind_workspace_scope,
    current_workspace_scope,
    default_workspace_scope,
    reset_workspace_scope,
)


class FakeSearch:
    def __init__(self, mode: str, pid_file: str | None = None):
        self.mode = mode
        self.pid_file = pid_file

    async def execute(self, **_params):
        if self.mode == "descendant":
            child = subprocess.Popen(["/bin/sleep", "30"],
                                     stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            Path(self.pid_file).write_text(str(child.pid), encoding="utf-8")
        if self.mode == "hang":
            await asyncio.sleep(10)
        if self.mode == "descendant":
            await asyncio.sleep(60)
        scope = current_workspace_scope()
        return str(scope.project_path) if scope else "unscoped"


class SearchIsolationTest(unittest.IsolatedAsyncioTestCase):
    async def test_native_tools_match_isolation_and_reject_outside_workspace(self):
        with (tempfile.TemporaryDirectory(prefix="nano-native-workspace-") as root,
              tempfile.TemporaryDirectory(prefix="nano-native-outside-") as outside):
            workspace = Path(root)
            outside_dir = Path(outside)
            (workspace / "inside.txt").write_text("needle\n", encoding="utf-8")
            outside_file = outside_dir / "outside.txt"
            secret = "OUTSIDE_SECRET_SENTINEL"
            outside_file.write_text(secret + "\n", encoding="utf-8")
            cases = (
                ("grep", GrepTool(workspace=workspace, allowed_dir=workspace,
                                   restrict_to_workspace=True),
                 {"pattern": "needle", "path": str(workspace), "fixed_strings": True,
                  "context_before": 0, "context_after": 0, "head_limit": 10},
                 {"pattern": secret, "path": str(outside_file), "fixed_strings": True}),
                ("find_files", FindFilesTool(workspace=workspace, allowed_dir=workspace,
                                             restrict_to_workspace=True),
                 {"path": str(workspace), "glob": "*.txt", "head_limit": 10},
                 {"path": str(outside_dir), "glob": "*.txt", "head_limit": 10}),
            )
            for name, tool, inside_params, outside_params in cases:
                with self.subTest(tool=name):
                    native = await tool.execute(**inside_params)
                    isolated = await isolated_search(tool, inside_params, name, timeout=5)
                    self.assertFalse(getattr(native, "is_error", False))
                    self.assertEqual(str(isolated), str(native))
                    self.assertEqual(getattr(isolated, "is_error", False),
                                     getattr(native, "is_error", False))
                    self.assertIn("inside.txt", str(isolated))

                    native_denied = await tool.execute(**outside_params)
                    isolated_denied = await isolated_search(tool, outside_params, name, timeout=5)
                    self.assertTrue(getattr(native_denied, "is_error", False))
                    self.assertEqual(str(isolated_denied), str(native_denied))
                    self.assertEqual(getattr(isolated_denied, "is_error", False),
                                     getattr(native_denied, "is_error", False))
                    self.assertNotIn(secret, str(native_denied))
                    self.assertNotIn(secret, str(isolated_denied))

    async def test_native_scope_is_transmitted_to_each_search_kind(self):
        with tempfile.TemporaryDirectory(prefix="nano-scope-") as root:
            token = bind_workspace_scope(default_workspace_scope(Path(root), True))
            try:
                for kind in ("grep", "find_files"):
                    result = await isolated_search(FakeSearch("return"), {}, kind, timeout=5)
                    self.assertEqual(result, root)
            finally:
                reset_workspace_scope(token)

    async def test_timeout_reaps_synthetic_worker(self):
        start = time.monotonic()
        result = await isolated_search(FakeSearch("hang"), {}, "grep", timeout=0.2)
        self.assertIn("timed out", result)
        self.assertLess(time.monotonic() - start, 2)
        self.assertFalse(any(p.name == "nanobot-search" for p in multiprocessing.active_children()))

    async def test_cancel_reaps_synthetic_worker(self):
        task = asyncio.create_task(isolated_search(FakeSearch("hang"), {}, "find_files", timeout=5))
        await asyncio.sleep(0.2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(any(p.name == "nanobot-search" for p in multiprocessing.active_children()))

    async def test_timeout_kills_synthetic_descendant_group(self):
        with tempfile.TemporaryDirectory(prefix="nano-descendant-") as root:
            pid_file = Path(root) / "pid"
            # A spawned interpreter may cold-start through an NFS-backed venv;
            # leave startup headroom while keeping the synthetic descendant alive.
            result = await isolated_search(FakeSearch("descendant", str(pid_file)),
                                           {}, "grep", timeout=10.0)
            self.assertIn("timed out", result)
            self.assertTrue(pid_file.is_file())
            pid = int(pid_file.read_text(encoding="utf-8"))
            for _ in range(20):
                stat = Path(f"/proc/{pid}/stat")
                if not stat.exists() or stat.read_text(encoding="utf-8").rsplit(") ", 1)[1].startswith("Z"):
                    break
                await asyncio.sleep(0.05)
            else:
                self.fail(f"search descendant {pid} survived group kill")


if __name__ == "__main__":
    unittest.main()
