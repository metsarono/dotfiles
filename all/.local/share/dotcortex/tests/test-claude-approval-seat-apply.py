#!/usr/bin/env python3
import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve()
TOOL = HERE.parents[4] / ".local/bin/claude-approval-seat-apply"
SPEC = importlib.util.spec_from_file_location("approval_seat_apply", TOOL)
if SPEC is None:
    SPEC = importlib.util.spec_from_loader(
        "approval_seat_apply", SourceFileLoader("approval_seat_apply", str(TOOL))
    )
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ApprovalSeatApplyTests(unittest.TestCase):
    def test_fragment_covers_every_kikin_seat(self):
        fragment = MODULE.load_fragment()
        self.assertEqual(tuple(fragment["required_seats"]), MODULE.SEATS)

    def test_merge_replaces_only_our_hook_and_preserves_other_hooks(self):
        fragment = MODULE.load_fragment()
        settings = {
            "hooks": {
                "PermissionRequest": [
                    {"hooks": [{"type": "command", "command": "foreign-hook"}]},
                    {"hooks": [{"type": "command", "command": "old-claude-hook-permission-request-kikin"}]},
                ],
                "SessionStart": [{"hooks": [{"type": "command", "command": "keep-me"}]}],
            },
            "model": "machine-local",
        }
        merged = MODULE.merge_seat_settings(settings, fragment, "haiku")
        commands = [
            item["command"]
            for group in merged["hooks"]["PermissionRequest"]
            for item in group["hooks"]
        ]
        self.assertIn("foreign-hook", commands)
        self.assertEqual(sum(MODULE.HOOK_NAME in item for item in commands), 1)
        self.assertEqual(merged["hooks"]["SessionStart"][0]["hooks"][0]["command"], "keep-me")
        self.assertEqual(merged["model"], "machine-local")

    def test_apply_requires_private_regular_settings_file(self):
        fragment = MODULE.load_fragment()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(json.dumps({"hooks": {}}))
            path.chmod(0o600)
            MODULE.write_json(path, MODULE.merge_seat_settings({"hooks": {}}, fragment, "fable"))
            value = json.loads(path.read_text())
            self.assertEqual(len(value["hooks"]["PermissionRequest"]), 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
