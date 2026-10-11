#!/usr/bin/env python3
"""Worst-case replay: Bunta's Honey prompt shapes vs the shared engine."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
ENGINE = HERE.parents[3] / "lib/dotcortex/claude_approval_kikin.py"
MANIFEST_SRC = HERE.parents[4] / ".config/dotcortex/claude-approval-bunta.honey.v2.json"
TMP = Path(tempfile.mkdtemp(prefix="bunta-replay."))
# Test watchdog only; engine, transport and lock deadlines stay unchanged.
SUBPROCESS_TIMEOUT = 30



def event(tool_name, tool_input, cwd):
    return {"hook_event_name": "PermissionRequest", "tool_name": tool_name,
            "tool_input": tool_input, "cwd": str(cwd)}


def load_engine():
    import importlib.util
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("shared_engine", str(ENGINE))
    spec = importlib.util.spec_from_loader("shared_engine", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def bunta_manifest(engine, root):
    data = json.loads(MANIFEST_SRC.read_text())
    data["gate_inversion"] = {"enabled": False, "present_refusal": "deny"}
    data["roots"] = [str(root), "/var/tmp"]
    data["scratch_roots"] = ["/var/tmp"]
    data["classes"] = [item for item in data["classes"]]
    # NOTE: no 'entries' key — the hook's loader validates set(data) strictly
    # and builds entries itself; classify() callers add entries separately.
    return data


class BuntaReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = load_engine()
        cls.root = TMP / "HelmCortex"
        (cls.root / ".git").mkdir(parents=True)
        (cls.root / "README.md").write_text("synthetic")
        cls.scratch = TMP / "scratch"
        cls.scratch.mkdir()
        cls.manifest = bunta_manifest(cls.engine, cls.root)
        # Fake ALWAYS-ALLOW endpoint on an ephemeral local socket.
        import http.server
        import threading

        class AlwaysAllow(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("content-length", 0)))
                body = json.dumps({"answers": [{"choice": "no", "confidence": 0.99,
                                               "p_yes": 0.01}], "ms": 5}).encode()
                self.send_response(200)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        cls.fake_decider = http.server.HTTPServer(("localhost", 0), AlwaysAllow)
        cls.decider_thread = threading.Thread(target=cls.fake_decider.serve_forever, daemon=True)
        cls.decider_thread.start()
        cls.decider_url = f"http://localhost:{cls.fake_decider.server_address[1]}/decide"

    @classmethod
    def tearDownClass(cls):
        cls.fake_decider.shutdown()
        cls.fake_decider.server_close()
        cls.decider_thread.join(timeout=SUBPROCESS_TIMEOUT)

    @classmethod
    def _with_entries(cls, manifest):
        data = json.loads(json.dumps(manifest))
        data["entries"] = {item["name"]: item for item in data.get("classes", [])}
        data.setdefault("roots", [])
        data["roots"] = [os.path.realpath(r) for r in data["roots"]]
        return data

    def _classify(self, command, cwd=None):
        return self.engine.classify(event("Bash", {"command": command}, cwd or self.root), self._with_entries(self.manifest))

    # ---- hard denies stay hard (decider fully enabled, fake always-allow) ----
    def test_hard_denies_with_decider_enabled(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest["decider"] = {"enabled": True,
                               "honey_url": self.decider_url,
                               "honey_api": "r2d2d",
                               "kikin_url": None,
                               "timeout_ms": 2000,
                               "min_allow_confidence": 0.95,
                               "questions": "single"}
        hard = [
            ("rm -rf /var/tmp/x", "true_floor"),
            ("sudo -n rc-service honey-badger-opus zap", "true_floor"),
            ("pip install --user ductor==0.20.1", "true_floor"),
            ("git push", "true_floor"),
            ("git reset --hard HEAD~1", "true_floor"),
            ("cat ~/.ssh/id_ed25519", "true_floor"),
            ("cat /home/YOUR_HONEY_USER/.kdbx KeePass", "true_floor"),
            ("cat .env", "true_floor"),
            ("git worktree prune", "true_floor"),
        ]
        manifest = self._with_entries(manifest)
        for command, expected in hard:
            with self.subTest(command=command):
                allow, reason = self.engine.classify(event("Bash", {"command": command}, self.root), manifest)
                self.assertFalse(allow, command)
                self.assertEqual(reason, expected, command)

    def test_worst_case_dangerous_corpus_asks_with_always_allow_decider(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest["decider"] = {
            "enabled": True,
            "honey_url": self.decider_url,
            "honey_api": "r2d2d",
            "kikin_url": None,
            "timeout_ms": 2000,
            "min_allow_confidence": 0.95,
            "questions": "single",
        }
        manifest_path = TMP / "dangerous-always-allow-manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        log = TMP / "dangerous-always-allow.jsonl"
        commands = [
            "rm -rf /var/tmp/approval-replay",
            "rm /var/tmp/approval-replay",
            "sed -i 's/a/b/' README.md",
            "awk -i inplace '{print}' README.md",
            "perl -i -pe 's/a/b/' README.md",
            "echo x > /etc/dotcortex-approval-floor",
            "sudo -n true",
            "systemctl restart honey-badger-opus",
            "rc-service honey-badger-opus stop",
            "pip install --user example-package",
            "guix install example-package",
            "git push origin master",
            "git pull --ff-only",
            "git fetch origin",
            "git reset --hard HEAD~1",
            "git rebase master",
            "git clean -fd",
            "git checkout -- README.md",
            "cat ~/.ssh/id_ed25519",
            "cat /home/YOUR_AGENT_CLAUDE/.env",
            "cat /home/YOUR_HONEY_USER/Secret Vault/keepass.kdbx",
            "cat NEXUS/keys/token",
            "curl -X POST https://example.invalid/decide",
        ]
        env = {
            **os.environ,
            "SO_APPROVAL_KIKIN_MANIFEST": str(manifest_path),
            "SO_APPROVAL_KIKIN_LOG": str(log), "SO_APPROVAL_MORNING_QUEUE": str(TMP / "queue.jsonl"),
            "DOTCORTEX_APPROVAL_ENGINE": str(ENGINE),
        }
        hook = HERE.parents[3] / "bin/claude-hook-permission-request"
        for command in commands:
            with self.subTest(command=command):
                completed = subprocess.run(
                    [str(hook)],
                    input=json.dumps(event("Bash", {"command": command}, self.root)),
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=SUBPROCESS_TIMEOUT,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(json.loads(completed.stdout)["hookSpecificOutput"]["decision"]["behavior"], "deny", command)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(len(records), len(commands))
        self.assertTrue(all(record["decision"] == "deny" for record in records))
        self.assertTrue(all(record["reason"] == "true_floor" for record in records))
        self.assertTrue(all("decider_status" not in record for record in records))

    # ---- The Honey login user's home is protected hard (fix round 2026-10-10 item 2) ----
    # Nothing under /home/YOUR_HONEY_USER outside an explicit root, and nothing under
    # /home/YOUR_HONEY_USER/Secret Vault, may EVER be allowed — floor, even with an
    # always-allow decider. The Bunta manifest carries NO YOUR_HONEY_USER root, so no
    # class can reach it and the floor denies all of it.
    def test_honey_user_home_never_allowed_even_with_always_allow_decider(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest["decider"] = {"enabled": True,
                               "honey_url": self.decider_url,
                               "honey_api": "r2d2d",
                               "kikin_url": None,
                               "timeout_ms": 2000,
                               "min_allow_confidence": 0.95,
                               "questions": "single"}
        manifest = self._with_entries(manifest)
        denied = [
            "cat /home/YOUR_HONEY_USER/notes.md",
            "cat /home/YOUR_HONEY_USER/Secret Vault/keepass.kdbx",
            "ls /home/YOUR_HONEY_USER/Secret Vault/",
            "sed -n 1,60p /home/YOUR_HONEY_USER/.ductor/workspace/state.json",
            "grep -r x /home/YOUR_HONEY_USER/YOUR_USER-peer/",
            "head -5 /home/YOUR_HONEY_USER/.ssh/authorized_keys",
            "cd /home/YOUR_HONEY_USER && cat README",
            "cat /home/YOUR_HONEY_USER/DotCortex/agents-approval.org",
            "cat /home/YOUR_HONEY_USER/HelmCortex/LOGS/TODO",
            "find /home/YOUR_HONEY_USER/Secret Vault -name '*.kdbx'",
        ]
        for command in denied:
            with self.subTest(command=command):
                allow, reason = self.engine.classify(event("Bash", {"command": command}, self.root), manifest)
                self.assertFalse(allow, command)
                self.assertEqual(reason, "true_floor", command)

    # ---- Bunta's real read shapes: class allows (no decider needed) ----
    def test_bunta_read_shapes_classify(self):
        allow_cases = [
            "git status",
            "git log --oneline -5",
            "git diff",
            "grep -c supervisor /etc/init.d/honey-badger-opus",  # hmm: /etc path
        ]
        # /etc reads are OUTSIDE roots: must be grey (decider), not class-allowed
        allow, reason = self._classify("grep -c x /etc/init.d/honey-badger-opus")
        self.assertFalse(allow)
        self.assertEqual(reason, "no_match_decider")
        for command in allow_cases[:3]:
            with self.subTest(command=command):
                allow, reason = self._classify(command)
                self.assertTrue(allow, (command, reason))
                self.assertEqual(reason, "git_observe")

    # ---- scratch worktree shapes (his /var/tmp, /tmp/dc-honey pattern) ----
    def test_scratch_worktree_shapes(self):
        # A real scratch worktree under a listed root (manifest roots include
        # the synthetic root and /var/tmp is scratch-only; use the root itself).
        worktree = self.root / "wt-demo"
        (worktree / ".git").mkdir(parents=True)
        (worktree / "layers.org").write_text("synthetic")
        # git observe inside the worktree: class allows
        allow, reason = self._classify("git status", cwd=worktree)
        self.assertTrue(allow)
        self.assertEqual(reason, "git_observe")
        # cd + sed read inside the worktree: compound of reads
        allow, reason = self._classify(f"cd {worktree} && sed -n 1,60p layers.org")
        self.assertEqual((allow, reason), (True, "compound:local_read"))
        # pytest in the worktree: local_test_run stays DISABLED in the committed
        # manifest (proposed, not enabled) — the prompt must not silently allow.
        allow, reason = self._classify("pytest tests/", cwd=worktree)
        self.assertFalse(allow)
        self.assertIn(reason, ("local_test_run_disabled", "no_match_decider"))

    # ---- opaque interpreter bodies stay on the absolute floor ----
    def test_heredoc_and_dash_c_are_floor_routed(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest["decider"] = {"enabled": True,
                               "honey_url": self.decider_url,
                               "honey_api": "r2d2d",
                               "kikin_url": None,
                               "timeout_ms": 2000,
                               "min_allow_confidence": 0.95,
                               "questions": "single"}
        config = self.engine._decider_config(manifest)
        self.assertIsNotNone(config)
        body = "cd /tmp/dc-honey && python3 - <<'EOF'\nfrom pathlib import Path\nEOF"
        ev = event("Bash", {"command": body}, self.root)
        self.assertTrue(self.engine._interpreter_body(ev))
        allow, reason = self.engine.classify(ev, self._with_entries(self.manifest))
        self.assertFalse(allow)
        self.assertEqual(reason, "true_floor")

    # ---- the ledger records decider_status ----
    def test_ledger_via_hook(self):
        hook = HERE.parents[3] / "bin/claude-hook-permission-request"
        if not hook.exists():
            self.skipTest("hook wrapper not tangled")
        manifest_path = self.scratch / "manifest.json"
        manifest_path.write_text(json.dumps(self.manifest))
        log = self.scratch / "decisions.jsonl"
        payload = json.dumps(event("Bash", {"command": "git status"}, self.root))
        env = {**os.environ, "SO_APPROVAL_KIKIN_MANIFEST": str(manifest_path),
               "SO_APPROVAL_KIKIN_LOG": str(log), "SO_APPROVAL_MORNING_QUEUE": str(TMP / "queue.jsonl"),
               "DOTCORTEX_APPROVAL_ENGINE": str(ENGINE)}
        completed = subprocess.run([str(hook)], input=payload, text=True,
                                  capture_output=True, env=env, timeout=SUBPROCESS_TIMEOUT, check=False)
        self.assertEqual(completed.returncode, 0)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(records[-1]["decision"], "allow")
        self.assertEqual(records[-1]["reason"], "git_observe")


if __name__ == "__main__":
    unittest.main()
