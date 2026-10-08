"""The two Claude settings mergers must share one live regular file."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[5]
APPLY = ROOT / "all/.local/bin/claude-settings-apply"


class ClaudeSettingsApplyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.shared = self.home / "DotCortex/all/.claude/settings.shared.json"
        self.live = self.home / ".claude/settings.json"
        self.shared.parent.mkdir(parents=True)
        self.live.parent.mkdir(parents=True)
        self.baseline = {
            "theme": "dark",
            "enabledPlugins": {"shared@plugin": True},
            "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "claude-hook-stop"}]}]},
        }
        self.private = {
            "matcher": "private",
            "hooks": [{"type": "command", "command": "VAULT=$HOME/HelmCortex; $VAULT/NEXUS/stow/userspace/.claude/hooks/private.sh"}],
        }
        self.private_start = {
            "hooks": [{"type": "command", "command": "VAULT=$HOME/HelmCortex; $VAULT/NEXUS/stow/userspace/.claude/hooks/start.sh"}],
        }
        self.foreign_prompt = {"hooks": [{"type": "prompt", "prompt": "private instruction"}]}
        self.current = {
            "theme": "light", "model": "sonnet", "effortLevel": "high",
            "agentPushNotifEnabled": True, "machineOnly": {"value": 7},
            "enabledPlugins": {"local@plugin": True, "shared@plugin": False},
            "hooks": {
                "Stop": [
                    {"hooks": [
                        {"type": "command", "command": "claude-hook-obsolete"},
                        {"type": "command", "command": "claude-hook-stop"},
                    ]},
                    self.private,
                ],
                "SessionStart": [{"hooks": [{"type": "command", "command": "foreign-command"}]},
                                 self.private_start, self.foreign_prompt],
            },
        }
        self.write(self.shared, self.baseline)
        self.write(self.live, self.current)

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value) + "\n")

    def apply(self):
        return subprocess.run([str(APPLY)], env={**os.environ, "HOME": str(self.home)},
                              text=True, capture_output=True)

    def test_union_and_repeat_are_stable(self):
        self.assertEqual(self.apply().returncode, 0)
        first = json.loads(self.live.read_text())
        self.assertEqual(first["theme"], "dark")
        self.assertEqual(first["model"], "sonnet")
        self.assertEqual(first["effortLevel"], "high")
        self.assertTrue(first["agentPushNotifEnabled"])
        self.assertEqual(first["machineOnly"], {"value": 7})
        self.assertEqual(first["enabledPlugins"], {"shared@plugin": True, "local@plugin": True})
        self.assertIn(self.private, first["hooks"]["Stop"])
        self.assertEqual(first["hooks"]["SessionStart"], self.current["hooks"]["SessionStart"])
        self.assertEqual([entry["command"] for group in first["hooks"]["Stop"]
                          for entry in group["hooks"] if entry["command"].startswith("claude-hook-")],
                         ["claude-hook-stop"])
        self.assertEqual(self.apply().returncode, 0)
        self.assertEqual(json.loads(self.live.read_text()), first)

    def test_invalid_json_keeps_live_bytes(self):
        before = self.live.read_bytes()
        self.shared.write_text("{broken")
        self.assertNotEqual(self.apply().returncode, 0)
        self.assertEqual(self.live.read_bytes(), before)
        self.write(self.shared, self.baseline)
        self.live.write_text("{broken")
        before = self.live.read_bytes()
        self.assertNotEqual(self.apply().returncode, 0)
        self.assertEqual(self.live.read_bytes(), before)

    def test_symlink_refused_without_replacement(self):
        target = self.home / "foreign.json"
        self.write(target, self.current)
        self.live.unlink()
        self.live.symlink_to(target)
        before = target.read_bytes()
        self.assertNotEqual(self.apply().returncode, 0)
        self.assertTrue(self.live.is_symlink())
        self.assertEqual(target.read_bytes(), before)

    def test_shared_hook_must_be_dotcortex_owned(self):
        self.baseline["hooks"]["Stop"].append(self.private)
        self.write(self.shared, self.baseline)
        before = self.live.read_bytes()
        self.assertNotEqual(self.apply().returncode, 0)
        self.assertEqual(self.live.read_bytes(), before)

    def test_full_generated_baseline_keeps_private_group(self):
        self.shared.write_bytes((ROOT / "all/.claude/settings.shared.json").read_bytes())
        self.assertEqual(self.apply().returncode, 0)
        merged = json.loads(self.live.read_text())
        self.assertIn(self.private, merged["hooks"]["Stop"])
        self.assertTrue(merged["agentPushNotifEnabled"])

    def test_stow_ignores_only_live_settings_artifact(self):
        package = self.home / "packages/all/.claude"
        target = self.home / "target/.claude"
        package.mkdir(parents=True)
        target.mkdir(parents=True)
        shutil.copy2(ROOT / "all/.stow-local-ignore", package.parent)
        (package / "settings.json").write_text("{}\n")
        (package / "settings.shared.json").write_text("{}\n")
        (target / "settings.json").write_text("{\"private\": true}\n")
        result = subprocess.run(["stow", "--simulate", "-d", str(package.parent.parent),
                                 "-t", str(target.parent), "all"],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((target / "settings.json").read_text(), '{"private": true}\n')


if __name__ == "__main__":
    unittest.main()
