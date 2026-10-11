#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
TOOL = ROOT / "all/.local/bin/helmcortex-remote-lane"


class RemoteLaneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="remote-lane-test-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.remote = self.base / "canonical"
        self.root = self.base / "lane"
        self.env = dict(os.environ, HELMCORTEX_LANE_ROOT=str(self.root),
                        HELMCORTEX_LANE_REMOTE=self.remote.as_uri(),
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="Lane test", GIT_COMMITTER_NAME="Lane test",
                        GIT_AUTHOR_EMAIL="YOUR_AGENT_USER@YOUR_AGENT_HOST.invalid",
                        GIT_COMMITTER_EMAIL="YOUR_AGENT_USER@YOUR_AGENT_HOST.invalid")
        self.git(self.base, "init", "-q", "-b", "master", str(self.remote))
        self.git(self.remote, "config", "uploadpack.allowFilter", "true")
        for p in ("FORGE/demo/a", "FORGE/other/b", "CORTEX/c", "AGENTS.md", ".gitignore"):
            f = self.remote / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("artifact/\n" if p == ".gitignore" else p + "\n")
        self.git(self.remote, "add", "AGENTS.md", ".gitignore", "FORGE", "CORTEX")
        self.git(self.remote, "commit", "-qm", "seed")
        self.master = self.git(self.remote, "rev-parse", "master").stdout.strip()
        result = self.lane("init")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def git(self, cwd, *args, ok=True):
        result = subprocess.run(["git", "-C", str(cwd), *args], env=self.env,
                                text=True, capture_output=True)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def lane(self, *args):
        self.assertTrue(TOOL.is_file(), "RED: helmcortex-remote-lane not implemented")
        return subprocess.run([str(TOOL), *args], env=self.env, text=True,
                              capture_output=True)

    def succeeds(self, *args):
        result = self.lane(*args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def refuses(self, *args):
        result = self.lane(*args)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def start(self, task="job", *paths):
        self.succeeds("start", task, "--paths", *(paths or ("FORGE/demo",)))
        return self.root / "wt" / task

    def commit(self, worktree, text="change\n"):
        (worktree / "FORGE/demo/a").write_text(text)
        self.git(worktree, "add", "FORGE/demo/a")
        self.git(worktree, "commit", "-qm", "task work")
        return self.git(worktree, "rev-parse", "HEAD").stdout.strip()

    def test_partial_clone_and_sparse_current_master(self):
        cache = self.root / "repo"
        self.assertEqual(self.git(cache, "remote").stdout.strip(), "x230")
        self.assertEqual(self.git(cache, "config", "remote.x230.partialclonefilter").stdout.strip(), "blob:none")
        (self.remote / "AGENTS.md").write_text("new master\n")
        self.git(self.remote, "add", "AGENTS.md")
        self.git(self.remote, "commit", "-qm", "canonical moved")
        current = self.git(self.remote, "rev-parse", "master").stdout.strip()
        worktree = self.start()
        self.assertEqual(self.git(worktree, "rev-parse", "HEAD").stdout.strip(), current)
        self.assertEqual(self.git(worktree, "branch", "--show-current").stdout.strip(), "job")
        self.assertTrue((worktree / "FORGE/demo/a").is_file())
        self.assertEqual((worktree / "AGENTS.md").read_text(), "new master\n")
        self.assertFalse((worktree / "FORGE/other/b").exists())
        self.assertFalse((worktree / "CORTEX/c").exists())
        self.assertEqual(self.git(worktree, "status", "--porcelain").stdout, "")

    def test_push_and_done_touch_only_task_ref_normal_remote(self):
        worktree = self.start()
        sha = self.commit(worktree)
        self.git(worktree, "tag", "-a", "unwanted", "-m", "do not publish")
        self.git(self.root / "repo", "config", "push.followTags", "true")
        result = self.succeeds("push", "job")
        self.assertIn(sha, result.stdout)
        self.assertEqual(self.git(self.remote, "rev-parse", "job").stdout.strip(), sha)
        self.assertEqual(self.git(self.remote, "rev-parse", "master").stdout.strip(), self.master)
        self.assertEqual(self.git(self.remote, "tag").stdout, "")
        self.succeeds("done", "job")
        self.assertFalse(worktree.exists())
        self.assertNotEqual(self.git(self.root / "repo", "show-ref", "--verify", "refs/heads/job", ok=False).returncode, 0)
        self.assertEqual(self.git(self.remote, "rev-parse", "job").stdout.strip(), sha)
        self.assertEqual(self.git(self.remote, "status", "--porcelain").stdout, "")

    def test_bare_remote_round_trip(self):
        bare = self.base / "bare"
        self.git(self.base, "clone", "--bare", str(self.remote), str(bare))
        self.git(bare, "config", "uploadpack.allowFilter", "true")
        self.env["HELMCORTEX_LANE_ROOT"] = str(self.base / "bare-lane")
        self.env["HELMCORTEX_LANE_REMOTE"] = bare.as_uri()
        self.root = self.base / "bare-lane"
        self.succeeds("init")
        sha = self.commit(self.start())
        self.succeeds("push", "job")
        self.succeeds("done", "job")
        self.assertEqual(self.git(bare, "rev-parse", "job").stdout.strip(), sha)
        self.assertEqual(self.git(bare, "rev-parse", "master").stdout.strip(), self.master)

    def test_master_and_invalid_task_names_refused(self):
        for verb in ("start", "push", "done"):
            for task in ("master", "../escape", "-option", "bad/ref", "bad..name"):
                self.refuses(verb, task)
        self.assertEqual(self.git(self.remote, "rev-parse", "master").stdout.strip(), self.master)

    def test_dirty_push_refuses_tracked_staged_and_untracked(self):
        worktree = self.start()
        self.commit(worktree)
        f = worktree / "FORGE/demo/a"
        f.write_text("dirty\n")
        self.refuses("push", "job")
        self.git(worktree, "add", "FORGE/demo/a")
        self.refuses("push", "job")
        self.git(worktree, "commit", "-qm", "second task commit")
        stray = worktree / "stray"
        stray.write_text("keep me")
        self.refuses("push", "job")
        self.assertTrue(stray.exists())
        self.assertNotEqual(self.git(self.remote, "show-ref", "--verify", "refs/heads/job", ok=False).returncode, 0)

    def test_empty_push_and_unpushed_done_refused(self):
        worktree = self.start()
        self.refuses("push", "job")
        self.refuses("done", "job")
        self.commit(worktree)
        self.refuses("done", "job")
        self.assertTrue(worktree.exists())

    def test_remote_branch_without_lane_receipt_cannot_authorize_done(self):
        worktree = self.start()
        sha = self.commit(worktree)
        self.git(worktree, "push", "x230", "job:refs/heads/job")
        self.refuses("done", "job")
        self.assertTrue(worktree.exists())
        self.assertEqual(self.git(self.remote, "rev-parse", "job").stdout.strip(), sha)

    def test_done_refuses_remote_sha_drift(self):
        worktree = self.start()
        self.commit(worktree)
        self.succeeds("push", "job")
        self.git(self.remote, "update-ref", "refs/heads/job", self.master)
        self.refuses("done", "job")
        self.assertTrue(worktree.exists())

    def test_done_refuses_deleted_remote_branch(self):
        worktree = self.start()
        self.commit(worktree)
        self.succeeds("push", "job")
        self.git(self.remote, "update-ref", "-d", "refs/heads/job")
        self.refuses("done", "job")
        self.assertTrue(worktree.exists())

    def test_done_refuses_new_commits_and_dirty_work(self):
        worktree = self.start()
        self.commit(worktree)
        self.succeeds("push", "job")
        (worktree / "stray").write_text("keep")
        self.refuses("done", "job")
        (worktree / "stray").unlink()
        self.commit(worktree, "later work\n")
        self.refuses("done", "job")
        self.succeeds("push", "job")
        self.succeeds("done", "job")

    def test_wrong_branch_and_detached_head_refused(self):
        worktree = self.start()
        self.commit(worktree)
        self.git(worktree, "switch", "-c", "other")
        self.refuses("push", "job")
        self.refuses("done", "job")
        self.git(worktree, "switch", "--detach")
        self.refuses("push", "job")

    def test_sparse_settings_are_per_worktree_and_default_is_root_only(self):
        first = self.start()
        second = self.start("second", "CORTEX")
        self.assertTrue((first / "FORGE/demo/a").exists())
        self.assertFalse((first / "CORTEX/c").exists())
        self.assertTrue((second / "CORTEX/c").exists())
        self.assertFalse((second / "FORGE/demo/a").exists())
        self.succeeds("start", "metadata")
        metadata = self.root / "wt/metadata"
        self.assertTrue((metadata / "AGENTS.md").exists())
        self.assertFalse((metadata / "FORGE/demo/a").exists())

    def test_duplicate_local_or_remote_task_refused(self):
        worktree = self.start()
        self.refuses("start", "job")
        self.assertTrue(worktree.exists())
        self.git(self.remote, "branch", "taken")
        self.refuses("start", "taken")

    def test_sparse_traversal_and_missing_paths_refused_before_branch(self):
        for path in ("../escape", "/absolute", "FORGE/../CORTEX", "FORGE/missing", "-bad"):
            self.refuses("start", "bad", "--paths", path)
            self.assertFalse((self.root / "wt/bad").exists())
        worktree = self.start("file-task", "FORGE/demo/a")
        self.assertTrue((worktree / "FORGE/demo/a").exists())

    def test_rejected_push_is_not_forced_and_worktree_survives(self):
        worktree = self.start()
        self.commit(worktree)
        (self.remote / "AGENTS.md").write_text("competing\n")
        self.git(self.remote, "add", "AGENTS.md")
        self.git(self.remote, "commit", "-qm", "competing change")
        remote_sha = self.git(self.remote, "rev-parse", "master").stdout.strip()
        self.git(self.remote, "branch", "job")
        self.refuses("push", "job")
        self.assertEqual(self.git(self.remote, "rev-parse", "job").stdout.strip(), remote_sha)
        self.refuses("done", "job")
        self.assertTrue(worktree.exists())

    def test_status_health_fetch_age_and_active_worktrees(self):
        self.start()
        result = self.succeeds("status")
        self.assertIn("health: ok", result.stdout)
        self.assertIn("fetch age:", result.stdout)
        self.assertIn("job", result.stdout)
        self.assertIn(str(self.root / "wt/job"), result.stdout)

    def test_init_refuses_server_without_partial_clone_support(self):
        self.git(self.remote, "config", "uploadpack.allowFilter", "false")
        target = self.base / "unfiltered-lane"
        self.env["HELMCORTEX_LANE_ROOT"] = str(target)
        self.refuses("init")
        self.assertFalse((target / "lane.json").exists())

    def test_init_refuses_network_filesystem_before_creating_lane(self):
        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        probe = bin_dir / "findmnt"
        probe.write_text("#!/bin/sh\nprintf 'nfs4\\n'\n")
        probe.chmod(0o755)
        self.env["PATH"] = str(bin_dir) + os.pathsep + self.env["PATH"]
        target = self.base / "network-lane"
        self.env["HELMCORTEX_LANE_ROOT"] = str(target)
        result = self.refuses("init")
        self.assertIn("local disk required", result.stderr)
        self.assertFalse(target.exists())

    def test_symlink_lane_and_changed_master_snapshot_refused(self):
        link = self.base / "redirect"
        link.symlink_to(self.root, target_is_directory=True)
        self.env["HELMCORTEX_LANE_ROOT"] = str(link)
        self.refuses("status")
        self.env["HELMCORTEX_LANE_ROOT"] = str(self.root)
        sha = self.commit(self.start())
        self.git(self.root / "repo", "update-ref", "refs/heads/master", sha)
        result = self.refuses("push", "job")
        self.assertIn("immutable clone master changed", result.stderr)
        self.assertEqual(self.git(self.remote, "rev-parse", "master").stdout.strip(), self.master)

    def test_changed_push_url_refused(self):
        self.start()
        self.git(self.root / "repo", "config", "remote.x230.pushurl", str(self.base / "wrong"))
        result = self.refuses("push", "job")
        self.assertIn("push remote changed", result.stderr)

    def test_plain_worktree_remove_preserves_locked_worktree(self):
        worktree = self.start()
        self.commit(worktree)
        self.succeeds("push", "job")
        self.git(self.root / "repo", "worktree", "lock", str(worktree))
        self.refuses("done", "job")
        self.assertTrue(worktree.exists())
        self.git(self.root / "repo", "worktree", "unlock", str(worktree))
        self.succeeds("done", "job")

    def forced_command(self):
        source = (ROOT / "agents-users-remote-lane.org").read_text()
        line = next(line for line in source.splitlines() if line.startswith('restrict,command="'))
        match = re.fullmatch(r'restrict,command="((?:\\.|[^"\\])*)" ssh-ed25519 YOUR_PUBLIC_KEY_BLOB YOUR_AGENT_USER@YOUR_AGENT_HOST helmcortex-lane', line)
        self.assertIsNotNone(match, "documented authorized_keys line must parse exactly")
        command = match[1].replace('\\"', '"').replace('\\\\', '\\')
        command = command.replace("/home/YOUR_CANONICAL_USER/HelmCortex", str(self.remote))
        result = subprocess.run(["/bin/sh", "-n", "-c", command], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return command

    def test_documented_forced_command_rejects_other_repos_and_shell_injection(self):
        command = self.forced_command()
        marker = self.base / "injected"
        for original in ("", "id", f"git-upload-pack '{self.base}/other'",
                         f"git-upload-pack '{self.remote}'; touch '{marker}'",
                         f"git-receive-pack '{self.remote}' --extra"):
            env = dict(self.env, SSH_ORIGINAL_COMMAND=original)
            result = subprocess.run(["/bin/sh", "-c", command], env=env,
                                    text=True, input="", capture_output=True)
            self.assertEqual(result.returncode, 126, result.stderr)
            self.assertFalse(marker.exists())

    def test_documented_forced_command_allows_partial_clone_and_task_only_receive(self):
        command = self.forced_command()
        shim = self.base / "ssh-fixture"
        shim.write_text("#!/usr/bin/env python3\nimport os, sys\n"
                        "os.environ['SSH_ORIGINAL_COMMAND'] = sys.argv[-1]\n"
                        "os.execv('/bin/sh', ['/bin/sh', '-c', os.environ['LANE_TEST_FORCED_COMMAND']])\n")
        shim.chmod(0o755)
        self.env["GIT_SSH_COMMAND"] = shlex.quote(str(shim))
        self.env["GIT_SSH_VARIANT"] = "ssh"
        self.env["LANE_TEST_FORCED_COMMAND"] = command
        self.git(self.remote, "config", "uploadpack.allowFilter", "false")
        copy = self.base / "ssh-copy"
        self.git(self.base, "clone", "--filter=blob:none", f"YOUR_TEST_HOST:{self.remote}", str(copy))
        self.assertEqual(self.git(copy, "config", "remote.origin.partialclonefilter").stdout.strip(), "blob:none")
        self.git(copy, "switch", "-c", "transport-task")
        (copy / "AGENTS.md").write_text("transport commit\n")
        self.git(copy, "add", "AGENTS.md")
        self.git(copy, "commit", "-qm", "transport task")
        sha = self.git(copy, "rev-parse", "HEAD").stdout.strip()
        self.git(copy, "push", "origin", "HEAD:refs/heads/transport-task")
        self.assertEqual(self.git(self.remote, "rev-parse", "transport-task").stdout.strip(), sha)
        # Force is used only by this adversarial fixture to prove the server
        # policy rejects it even if a client bypasses the lane helper.
        for refspec in ("+HEAD:refs/heads/master", ":refs/heads/transport-task",
                        "+master:refs/heads/transport-task", "HEAD:refs/tags/forbidden"):
            result = self.git(copy, "push", "origin", refspec, ok=False)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.git(self.remote, "rev-parse", "master").stdout.strip(), self.master)
        self.assertEqual(self.git(self.remote, "rev-parse", "transport-task").stdout.strip(), sha)


if __name__ == "__main__":
    unittest.main()
