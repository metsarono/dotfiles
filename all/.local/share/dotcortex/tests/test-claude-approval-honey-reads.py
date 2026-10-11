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
# Test watchdog only; engine, transport and lock deadlines stay unchanged.
SUBPROCESS_TIMEOUT = 30



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

        cls.decider = http.server.HTTPServer(("localhost", 0), AlwaysAllow)
        cls.decider_thread = threading.Thread(target=cls.decider.serve_forever, daemon=True)
        cls.decider_thread.start()
        cls.decider_url = f"http://localhost:{cls.decider.server_address[1]}/decide"

    @classmethod
    def tearDownClass(cls):
        cls.decider.shutdown()
        cls.decider.server_close()
        cls.temp.cleanup()

    def manifest(self, *, decider=False):
        data = json.loads(MANIFEST_SRC.read_text(encoding="utf-8"))
        data["gate_inversion"] = {"enabled": False, "present_refusal": "deny"}
        data["roots"] = [str(self.root)]
        data["scratch_roots"] = [str(self.root)]
        data["classes"] = [item for item in data["classes"]]
        ssh = next(item for item in data["classes"] if item["name"] == "ssh_readonly")
        ssh["enabled"] = True
        ssh["readonly_hosts"] = [{
            "host": "YOUR_HONEY_HOST",
            "remote_home": "/home/YOUR_HONEY_USER",
            "remote_path_roots": [
                "/home/YOUR_HONEY_USER/DotCortex",
                "/home/YOUR_HONEY_USER/HelmCortex",
                "/home/YOUR_AGENT_CLAUDE",
                "/var/tmp",
                "/etc/init.d",
                "/var/log",
            ],
            "allowed_sudo_targets": ["YOUR_AGENT_CLAUDE"],
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
            "ssh YOUR_HONEY_HOST 'ls -ld /home/YOUR_HONEY_USER/DotCortex'",
            "ssh YOUR_HONEY_HOST 'git -C /home/YOUR_HONEY_USER/DotCortex status --short'",
            "ssh YOUR_HONEY_HOST 'ps -eo pid,lstart,user,args | grep -i opus'",
            "ssh YOUR_HONEY_HOST 'sudo -n -u YOUR_AGENT_CLAUDE tmux -S /tmp/tmux-2002/default capture-pane -p -t honey-opus:0 | tail -20'",
            "ssh YOUR_HONEY_HOST 'sudo -n -u YOUR_AGENT_CLAUDE tmux -S /tmp/tmux-2002/default list-windows -t honey-opus'",
            "ssh YOUR_HONEY_HOST 'sudo -n -u YOUR_AGENT_CLAUDE cat /home/YOUR_AGENT_CLAUDE/.local/state/dotcortex/claude-approval-kikin.jsonl | tail -5'",
            "ssh YOUR_HONEY_HOST 'sudo -n -u YOUR_AGENT_CLAUDE ls -l /home/YOUR_AGENT_CLAUDE/.config/dotcortex/'",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.classify(command), (True, "ssh_readonly"))

    def test_sudo_and_secret_floor_corpus_asks_even_with_always_allow_decider(self):
        commands = [
            "ssh YOUR_HONEY_HOST 'cat /home/YOUR_HONEY_USER/Secret Vault/keepass.kdbx'",
            "ssh YOUR_HONEY_HOST \"cat '/home/YOUR_HONEY_USER/Secret Vault/keepass.kdbx'\"",
            "ssh YOUR_HONEY_HOST 'cat /home/YOUR_HONEY_USER/DotCortex/../Secret Vault/keepass.kdbx'",
            "ssh YOUR_HONEY_HOST 'cat /home/YOUR_HONEY_USER/SECRET VAULT/keepass.kdbx'",
            "ssh YOUR_HONEY_HOST 'cat /home/YOUR_HONEY_USER/Secret\\ Vault/keepass.kdbx'",
            "ssh YOUR_HONEY_HOST 'cat /home/YOUR_AGENT_CLAUDE/.claude/.credentials.json'",
            "ssh YOUR_HONEY_HOST 'cat /home/YOUR_AGENT_CLAUDE/.config/dotcortex/auth.json'",
            "ssh YOUR_HONEY_HOST 'cat ~/.ssh/config'",
            "ssh YOUR_HONEY_HOST 'cat /home/YOUR_HONEY_USER/HelmCortex/NEXUS/keys/private'",
            "ssh YOUR_HONEY_HOST 'cat /var/log/approval.token'",
            "ssh YOUR_HONEY_HOST 'cat /var/tmp/keepass.kdbx'",
            "ssh YOUR_HONEY_HOST 'sudo -n -u root cat /home/YOUR_HONEY_USER/DotCortex/README.md'",
            "ssh YOUR_HONEY_HOST 'sudo -u YOUR_AGENT_CLAUDE cat /home/YOUR_AGENT_CLAUDE/.config/dotcortex/x'",
            "ssh YOUR_HONEY_HOST 'sudo -n -u YOUR_AGENT_CLAUDE bash -c id'",
            "ssh YOUR_HONEY_HOST 'sudo -n -u YOUR_AGENT_CLAUDE sh -c id'",
            "ssh YOUR_HONEY_HOST 'sudo -n -u YOUR_AGENT_CLAUDE python -c id'",
            "ssh YOUR_HONEY_HOST 'sudo -n -u YOUR_AGENT_CLAUDE tmux send-keys -t honey-opus:0 x'",
            "ssh YOUR_HONEY_HOST 'cat /home/YOUR_HONEY_USER/DotCortex/README.md > /var/tmp/out'",
            "ssh YOUR_HONEY_HOST 'rm /var/tmp/out'",
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
            "SO_APPROVAL_KIKIN_LOG": str(log_path), "SO_APPROVAL_MORNING_QUEUE": str(Path(self.temp.name) / "queue.jsonl"),
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
                    timeout=SUBPROCESS_TIMEOUT,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(json.loads(completed.stdout)["hookSpecificOutput"]["decision"]["behavior"], "deny", command)
        records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(records), len(commands))
        self.assertTrue(all(record["decision"] == "deny" for record in records))
        self.assertTrue(all(record["reason"] == "true_floor" for record in records))
        self.assertTrue(all("decider_status" not in record for record in records))

    def test_single_readonly_host_manifest_still_loads(self):
        data = self.manifest()
        ssh = data["entries"]["ssh_readonly"]
        ssh.pop("readonly_hosts")
        ssh.update({
            "readonly_host": "YOUR_HONEY_HOST",
            "remote_home": "/home/YOUR_HONEY_USER",
            "remote_path_roots": ["/home/YOUR_HONEY_USER/DotCortex"],
        })
        self.assertEqual(self.engine._readonly_host_config(ssh, "YOUR_HONEY_HOST")["remote_home"], "/home/YOUR_HONEY_USER")

    def test_readonly_host_list_selects_each_host(self):
        data = self.manifest()
        ssh = data["entries"]["ssh_readonly"]
        ssh["readonly_hosts"].append({
            "host": "other",
            "remote_home": "/home/YOUR_OTHER_USER",
            "remote_path_roots": ["/home/YOUR_OTHER_USER/DotCortex"],
            "allowed_sudo_targets": [],
        })
        command = "ssh other 'ls -ld /home/YOUR_OTHER_USER/DotCortex'"
        self.assertEqual(self.engine.classify(event(command, self.root), data), (True, "ssh_readonly"))

    def test_approval_hook_sources_have_only_public_home_placeholders(self):
        import re
        sources = [REPO / name for name in ("agents-approval.org", "agents-approval-tests.org",
            "agents-approval-legacy.org", "agents-approval-engine-local.org",
            "agents-approval-engine-remote.org", "agents-hooks.org")]
        targets = []
        for source in sources:
            raw = source.read_text(encoding="utf-8")
            targets.extend(REPO / target for target in re.findall(
                r":tangle (all/[^\s]+)", raw
            ) if "approval" in target or "claude-hook" in target)
        # Check canonical prose, fixtures, engines, manifests and wrappers.
        for path in sources + sorted(set(targets)):
            with self.subTest(path=path.relative_to(REPO)):
                raw = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search(
                    r"/+home/(?!YOUR_)[A-Za-z0-9_-]+", raw
                ), str(path.relative_to(REPO)))

    def test_unreviewed_home_is_floor_even_with_always_allow_decider(self):
        # Build a concrete synthetic username from the public placeholder.
        home = "/home/" + "YOUR_HONEY_USER".replace("YOUR_", "fixture_").lower()
        manifest = self.manifest(decider=True)
        for tool, tool_input in (
            ("Bash", {"command": f"cat {home}/notes.md"}),
            ("Bash", {"command": f"ls {home}/notes.md"}),
            ("Bash", {"command": f"cat /{home}/notes.md"}),
            ("Read", {"file_path": home + "/notes.md"}),
        ):
            with self.subTest(tool=tool, tool_input=tool_input):
                payload = event("true", self.root)
                payload.update(tool_name=tool, tool_input=tool_input)
                self.assertEqual(self.engine.classify(payload, manifest),
                                 (False, "true_floor"))
        # Exercise the actual hook, with an ALWAYS-ALLOW Decider configured.
        serialized = {key: value for key, value in manifest.items() if key != "entries"}
        path = Path(self.temp.name) / "outside-home-manifest.json"
        path.write_text(json.dumps(serialized), encoding="utf-8")
        log = Path(self.temp.name) / "outside-home.jsonl"
        completed = subprocess.run([str(HOOK)], input=json.dumps(event(f"cat {home}/notes.md", self.root)),
            text=True, capture_output=True, timeout=SUBPROCESS_TIMEOUT, check=False,
            env={**os.environ, "SO_APPROVAL_KIKIN_MANIFEST": str(path),
                 "SO_APPROVAL_KIKIN_LOG": str(log), "SO_APPROVAL_MORNING_QUEUE": str(Path(self.temp.name) / "queue.jsonl"), "DOTCORTEX_APPROVAL_ENGINE": str(ENGINE)})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["hookSpecificOutput"]["decision"]["behavior"], "deny")
        record = json.loads(log.read_text().splitlines()[-1])
        self.assertEqual(record["reason"], "true_floor")
        self.assertNotIn("decider_status", record)

    def test_home_boundary_is_independent_of_username_in_both_engines(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("home_boundary_p3",
            REPO / "all/.local/lib/dotcortex/claude_approval_p3.py")
        p3 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(p3)
        home = "/home/" + "YOUR_USER".replace("YOUR_", "fixture_").lower()
        root = home + "/DotCortex"
        for engine in (self.engine, p3):
            with self.subTest(engine=engine.__name__):
                self.assertFalse(engine._unreviewed_home_path(root + "/README.org", [root]))
                for path in (home, "/" + home, root + "-other/README.org",
                             root + "/../notes.md", home + "/other/README.org"):
                    self.assertTrue(engine._unreviewed_home_path(path, [root]), path)

    def test_manifest_public_placeholders(self):
        raw = MANIFEST_SRC.read_text(encoding="utf-8")
        self.assertIn("YOUR_HONEY_HOST", raw)
        self.assertIn("YOUR_HONEY_USER", raw)
        self.assertIn("YOUR_AGENT_CLAUDE", raw)
        self.assertNotIn('"honey"', raw)


if __name__ == "__main__":
    unittest.main()
