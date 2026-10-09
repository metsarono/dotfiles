#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[5]
HOOK = REPO / "all/.local/bin/claude-hook-permission-request-kikin"
ENGINE = REPO / "all/.local/lib/dotcortex/claude_approval_kikin.py"


def event(tool_name, tool_input, cwd):
    return {"hook_event_name": "PermissionRequest", "tool_name": tool_name, "tool_input": tool_input, "cwd": str(cwd)}


def run_hook(payload, manifest):
    env = {**os.environ, "SO_APPROVAL_KIKIN_MANIFEST": str(manifest)}
    return subprocess.run([str(HOOK)], input=json.dumps(payload), text=True, capture_output=True, env=env, timeout=2, check=False)


def decision(completed):
    if not completed.stdout.strip():
        return "ask"
    return json.loads(completed.stdout)["hookSpecificOutput"]["decision"]["behavior"]


class KikinApprovalHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = json.loads((REPO / "all/.config/dotcortex/claude-approval-canary.kikin.v1.json").read_text())
        self.root = Path(self.temp.name) / "DotCortex"
        (self.root / "FORGE/bin").mkdir(parents=True)
        (self.root / ".git").mkdir()
        (self.root / "README.md").write_text("synthetic\n")
        (self.root / "FORGE/bin/pokemon-centre").write_text("synthetic\n")
        (self.root / "FORGE/bin/clubhouse-bosses-refresh").write_text("synthetic\n")
        self.scratch = Path(self.temp.name) / "scratch"
        self.scratch.mkdir()
        self.message = self.scratch / "message"
        self.message.write_text("test: synthetic\n")
        os.chmod(self.message, 0o600)

    def manifest(self, *enabled):
        data = json.loads(json.dumps(self.base))
        data["roots"] = [str(self.root)]
        data["scratch_roots"] = [str(self.scratch)]
        for item in data["classes"]:
            item["enabled"] = item["name"] in enabled
        path = self.scratch / "manifest.json"
        path.write_text(json.dumps(data))
        return path

    def assert_decision(self, payload, manifest, expected):
        completed = run_hook(payload, manifest)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(decision(completed), expected, completed.stdout)

    def test_all_classes_are_default_off(self):
        manifest = REPO / "all/.config/dotcortex/claude-approval-canary.kikin.v1.json"
        self.assertTrue(all(not item["enabled"] for item in self.base["classes"]))
        self.assert_decision(event("Read", {"file_path": str(self.root / "README.md")}, self.root), manifest, "ask")

    def test_each_class_has_green_and_disabled_paths(self):
        cases = [
            ("local_read", event("Read", {"file_path": str(self.root / "README.md")}, self.root)),
            ("git_observe", event("Bash", {"command": "git status --short"}, self.root)),
            ("centre_render", event("Bash", {"command": "FORGE/bin/pokemon-centre render"}, self.root)),
            ("safe_commit", event("Bash", {"command": f"git commit -F {self.message} -- README.md"}, self.root)),
        ]
        for class_name, payload in cases:
            with self.subTest(class_name=class_name):
                self.assert_decision(payload, self.manifest(class_name), "allow")
                self.assert_decision(payload, self.manifest(), "ask")

    def test_full_red_corpus_never_allows(self):
        manifest = self.manifest("local_read", "git_observe", "centre_render", "safe_commit")
        commands = [
            "cat .env", "cat NEXUS/keys/token", "cat LOGS/Telegram/Personal/chat.md",
            "cat CORTEX/PalmCortex/Diary.md", "git show HEAD:NEXUS/.secrets/token",
            "ssh kikin date", "scp x kikin:/tmp/x", "sudo true", "crontab -l",
            "telegram-agent-host stop fable", "nurse-joy revive Fable", "tmux kill-server",
            "pkill python3", "kill -9 123", "kill", "pip install x", "apt install x",
            "cat README.md > /tmp/copy", "find . -exec cat {} +", "find . -delete",
            "git push", "git reset --keep HEAD~1", "rm -rf README.md", "cat $(printf README.md)",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assert_decision(event("Bash", {"command": command}, self.root), manifest, "ask")

    def test_mount_symlink_and_scratch_output_boundaries(self):
        mount = Path(self.temp.name) / "mount"
        mount.mkdir()
        (mount / "README.md").write_text("mounted\n")
        (mount / ".git").mkdir()
        canonical = Path(self.temp.name) / "HelmCortex"
        canonical.symlink_to(mount, target_is_directory=True)
        data = json.loads(self.manifest("local_read").read_text())
        data["roots"] = [str(canonical)]
        manifest = self.scratch / "mount.json"
        manifest.write_text(json.dumps(data))
        self.assert_decision(event("Read", {"file_path": str(canonical / "README.md")}, canonical), manifest, "allow")
        data["classes"][-2]["enabled"] = True
        manifest.write_text(json.dumps(data))
        self.assert_decision(event("Bash", {"command": "FORGE/bin/pokemon-centre render --out /etc/x"}, canonical), manifest, "ask")

    def test_malformed_input_asks(self):
        manifest = self.manifest("local_read")
        completed = subprocess.run([str(HOOK)], input="{not-json", text=True, capture_output=True, env={**os.environ, "SO_APPROVAL_KIKIN_MANIFEST": str(manifest)}, timeout=2, check=False)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(decision(completed), "ask")


if __name__ == "__main__":
    unittest.main()
