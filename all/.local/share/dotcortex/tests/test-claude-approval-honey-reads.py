#!/usr/bin/env python3
"""Fable's Honey SSH readonly corpus against the shared Kikin engine."""
import json
import http.server
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest


HERE = Path(__file__).resolve()
REPO = HERE.parents[5]
ENGINE = REPO / "all/.local/lib/dotcortex/claude_approval_kikin.py"
HOOK = REPO / "all/.local/bin/claude-hook-permission-request"
MANIFEST_SRC = REPO / "all/.config/dotcortex/claude-approval-canary.kikin.v1.json"


def load_engine():
    import importlib.util
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("honey_reads_engine", str(ENGINE))
    spec = importlib.util.spec_from_loader("honey_reads_engine", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def event(command, cwd):
    return {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(cwd),
    }


class HoneyReadsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = load_engine()
        cls.temp = tempfile.TemporaryDirectory(prefix="honey-reads.")
        cls.root = Path(cls.temp.name) / "DotCortex"
        cls.root.mkdir()
        class AlwaysAllow(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.dumps({
                    "model_sha256": cls.engine.PINNED_MODEL_SHA256,
                    "answers": {"approval.sensitive_effect.v1": {"noul": 0.01}},
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        cls.decider = http.server.HTTPServer(("127.0.0.1", 0), AlwaysAllow)
        cls.decider_thread = threading.Thread(target=cls.decider.serve_forever, daemon=True)
        cls.decider_thread.start()
        cls.decider_url = f"http://127.0.0.1:{cls.decider.server_address[1]}/decide"

    @classmethod
    def tearDownClass(cls):
        cls.decider.shutdown()
        cls.decider.server_close()
        cls.temp.cleanup()

    def manifest(self, *, decider=False):
        data = json.loads(MANIFEST_SRC.read_text(encoding="utf-8"))
        data["roots"] = [str(self.root)]
        data["scratch_roots"] = [str(self.root)]
        data["classes"] = [item for item in data["classes"]]
        ssh = next(item for item in data["classes"] if item["name"] == "ssh_readonly")
        ssh["enabled"] = True
        ssh["readonly_hosts"] = [{
            "host": "honey",
            "remote_home": "/home/gille",
            "remote_path_roots": [
                "/home/gille/DotCortex",
                "/home/gille/HelmCortex",
                "/home/agent-claude",
                "/var/tmp",
                "/etc/init.d",
                "/var/log",
            ],
            "allowed_sudo_targets": ["agent-claude"],
        }]
        if decider:
            data["manifest_version"] = "claude-approval-canary.kikin.v2"
            data["decider"] = {
                "enabled": True,
                "honey_url": None,
                "kikin_url": self.decider_url,
                "timeout_ms": 500,
                "min_allow_confidence": 0.95,
                "questions": "single",
            }
        data["entries"] = {item["name"]: item for item in data["classes"]}
        data["roots"] = tuple(os.path.realpath(item) for item in data["roots"])
        data["scratch_roots"] = tuple(os.path.realpath(item) for item in data["scratch_roots"])
        return data

    def setUp(self):
        self.proof = self.engine._remote_realpath_proven_p3
        self.engine._remote_realpath_proven_p3 = lambda analysis, config: True
        self.addCleanup(self._restore_proof)

    def _restore_proof(self):
        self.engine._remote_realpath_proven_p3 = self.proof

    def classify(self, command, *, decider=False):
        return self.engine.classify(event(command, self.root), self.manifest(decider=decider))

    def test_every_real_honey_read_shape_allows(self):
        commands = [
            "ssh honey 'ls -ld /home/gille/DotCortex'",
            "ssh honey 'git -C /home/gille/DotCortex status --short'",
            "ssh honey 'ps -eo pid,lstart,user,args | grep -i opus'",
            "ssh honey 'sudo -n -u agent-claude tmux -S /tmp/tmux-2002/default capture-pane -p -t honey-opus:0 | tail -20'",
            "ssh honey 'sudo -n -u agent-claude tmux -S /tmp/tmux-2002/default list-windows -t honey-opus'",
            "ssh honey 'sudo -n -u agent-claude cat /home/agent-claude/.local/state/dotcortex/claude-approval-kikin.jsonl | tail -5'",
            "ssh honey 'sudo -n -u agent-claude ls -l /home/agent-claude/.config/dotcortex/'",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.classify(command), (True, "ssh_readonly"))

    def test_sudo_and_secret_floor_corpus_asks_even_with_always_allow_decider(self):
        commands = [
            "ssh honey 'cat /home/gille/Secret Vault/keepass.kdbx'",
            "ssh honey \"cat '/home/gille/Secret Vault/keepass.kdbx'\"",
            "ssh honey 'cat /home/gille/DotCortex/../Secret Vault/keepass.kdbx'",
            "ssh honey 'cat /home/gille/SECRET VAULT/keepass.kdbx'",
            "ssh honey 'cat /home/gille/Secret\\ Vault/keepass.kdbx'",
            "ssh honey 'cat /home/agent-claude/.claude/.credentials.json'",
            "ssh honey 'cat /home/agent-claude/.config/dotcortex/auth.json'",
            "ssh honey 'cat ~/.ssh/config'",
            "ssh honey 'cat /home/gille/HelmCortex/NEXUS/keys/private'",
            "ssh honey 'cat /var/log/approval.token'",
            "ssh honey 'cat /var/tmp/keepass.kdbx'",
            "ssh honey 'sudo -n -u root cat /home/gille/DotCortex/README.md'",
            "ssh honey 'sudo -u agent-claude cat /home/agent-claude/.config/dotcortex/x'",
            "ssh honey 'sudo -n -u agent-claude bash -c id'",
            "ssh honey 'sudo -n -u agent-claude sh -c id'",
            "ssh honey 'sudo -n -u agent-claude python -c id'",
            "ssh honey 'sudo -n -u agent-claude tmux send-keys -t honey-opus:0 x'",
            "ssh honey 'cat /home/gille/DotCortex/README.md > /var/tmp/out'",
            "ssh honey 'rm /var/tmp/out'",
        ]
        manifest = self.manifest(decider=True)
        manifest_path = Path(self.temp.name) / "honey-reads-manifest.json"
        serialized = {key: value for key, value in manifest.items() if key != "entries"}
        serialized["roots"] = list(serialized["roots"])
        serialized["scratch_roots"] = list(serialized["scratch_roots"])
        manifest_path.write_text(json.dumps(serialized), encoding="utf-8")
        log_path = Path(self.temp.name) / "honey-reads.jsonl"
        env = {
            **os.environ,
            "SO_APPROVAL_KIKIN_MANIFEST": str(manifest_path),
            "SO_APPROVAL_KIKIN_LOG": str(log_path),
            "DOTCORTEX_APPROVAL_ENGINE": str(ENGINE),
        }
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.classify(command, decider=True), (False, "true_floor"))
                completed = subprocess.run(
                    [str(HOOK)],
                    input=json.dumps(event(command, self.root)),
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertFalse(completed.stdout.strip(), (command, completed.stdout))
        records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(records), len(commands))
        self.assertTrue(all(record["decision"] == "ask" for record in records))
        self.assertTrue(all(record["reason"] == "true_floor" for record in records))
        self.assertTrue(all("decider_status" not in record for record in records))

    def test_single_readonly_host_manifest_still_loads(self):
        data = self.manifest()
        ssh = data["entries"]["ssh_readonly"]
        ssh.pop("readonly_hosts")
        ssh.update({
            "readonly_host": "honey",
            "remote_home": "/home/gille",
            "remote_path_roots": ["/home/gille/DotCortex"],
        })
        self.assertEqual(self.engine._readonly_host_config(ssh, "honey")["remote_home"], "/home/gille")

    def test_readonly_host_list_selects_each_host(self):
        data = self.manifest()
        ssh = data["entries"]["ssh_readonly"]
        ssh["readonly_hosts"].append({
            "host": "other",
            "remote_home": "/home/other",
            "remote_path_roots": ["/home/other/DotCortex"],
            "allowed_sudo_targets": [],
        })
        command = "ssh other 'ls -ld /home/other/DotCortex'"
        self.assertEqual(self.engine.classify(event(command, self.root), data), (True, "ssh_readonly"))

    def test_manifest_public_placeholders(self):
        raw = MANIFEST_SRC.read_text(encoding="utf-8")
        self.assertIn("YOUR_HONEY_HOST", raw)
        self.assertIn("YOUR_HONEY_USER", raw)
        self.assertIn("YOUR_AGENT_CLAUDE", raw)
        self.assertNotIn('"honey"', raw)
        self.assertNotIn("/home/gille", raw)


if __name__ == "__main__":
    unittest.main()
