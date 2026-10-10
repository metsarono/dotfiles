#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[5]
HOOK = REPO / "all/.local/bin/claude-hook-permission-request-kikin"
ENGINE = REPO / "all/.local/lib/dotcortex/claude_approval_kikin.py"


def event(tool_name, tool_input, cwd):
    return {"hook_event_name": "PermissionRequest", "tool_name": tool_name, "tool_input": tool_input, "cwd": str(cwd)}


def run_hook(payload, manifest, log=os.devnull):
    # Never let a test write the real decision ledger; os.devnull unless a test reads it.
    env = {**os.environ, "SO_APPROVAL_KIKIN_MANIFEST": str(manifest), "SO_APPROVAL_KIKIN_LOG": str(log)}
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

    def test_decision_ledger_records_reason_without_tool_input(self):
        log = self.scratch / "decisions.jsonl"
        secret_path = str(self.root / "README.md")
        run_hook(event("Read", {"file_path": secret_path}, self.root), self.manifest("local_read"), log)
        run_hook(event("Read", {"file_path": secret_path}, self.root), self.manifest(), log)
        run_hook("not json", self.manifest(), log)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual([(r["decision"], r["reason"]) for r in records],
                         [("allow", "local_read"), ("ask", "local_read_disabled"), ("ask", "not_permission_request")])
        self.assertNotIn(secret_path, log.read_text())
        self.assertEqual(oct(log.stat().st_mode & 0o777), "0o600")

    def test_compound_reads_allow_and_anything_else_asks(self):
        manifest = self.manifest("local_read", "git_observe")
        root = str(self.root)
        allow = [
            f"cd {root} && cat README.md",
            f"cd {root} && sed -n 1,2p README.md | cut -c1-200",
            "grep -n synthetic README.md | head -n 5",
            "cat README.md | wc -l",
            "git status --short && git log --oneline -1",
            "head -n 3 README.md; tail -1 README.md",
            "grep -n 'a|b' README.md | sort -n | uniq -c",
            "grep -n -i -E 'synth\\.etic|x' README.md 2>/dev/null | head -5",
            "timeout 30 grep -n synthetic README.md; echo === ; cat README.md 2>&1 | wc -l",
            "cat README.md 2>/dev/null || true",
            f"cd {root} && ls -la FORGE/bin | grep -iE 'poke|club'",
            "grep -il synthetic README.md",
        ]
        for command in allow:
            with self.subTest(allow=command):
                self.assert_decision(event("Bash", {"command": command, "description": "read"}, self.root), manifest, "allow")
        ask = [
            "cat README.md > copy",
            "cat README.md | tee copy",
            "cat README.md | sh",
            "git status | xargs rm",
            "cat README.md; rm README.md",
            "cat README.md && curl https://example.invalid",
            "cat README.md | sort -o copy",
            "cat README.md & ls",
            "cat $(echo README.md) | head",
            "cd / && cat etc/passwd",
            f"cat README.md || cd {root}",
            f"cd {root} && sed -n '1p;w copy' README.md",
            "sed -n 1p README.md | sed -i s/a/b/ README.md",
            "cat README.md | head -n 5 README.md",
            "cat README.md |",
            "cat 'README.md && ls",
            "printf x && cat README.md",
            'grep -n "$(id)" README.md',
            'grep -n "a\\$b" README.md | head',
            "cat README.md 2>/tmp/err",
            "cat README.md >/dev/null; cat README.md > copy",
            "timeout 30 rm README.md && cat README.md",
            "echo x | sh",
            "grep -rn synthetic . | head",
            "ls -la / && cat README.md",
        ]
        for command in ask:
            with self.subTest(ask=command):
                self.assert_decision(event("Bash", {"command": command}, self.root), manifest, "ask")
        # A compound read still respects a disabled class.
        self.assert_decision(event("Bash", {"command": "cat README.md | wc -l"}, self.root), self.manifest(), "ask")

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

    def _decider_manifest(self, *, honey=None, kikin=None, enabled=True, honey_api=None):
        data = json.loads(self.manifest("local_read", "git_observe").read_text())
        data["manifest_version"] = "claude-approval-canary.kikin.v2"
        data["decider"] = {
            "enabled": enabled,
            "honey_url": honey,
            "kikin_url": kikin,
            "timeout_ms": 800,
            "min_allow_confidence": 0.95,
            "questions": "single",
        }
        if honey_api is not None:
            data["decider"]["honey_api"] = honey_api
        path = self.scratch / "manifest-decider.json"
        path.write_text(json.dumps(data))
        return path

    def _c1_answers(self, *, allow=True):
        # Single-mode contract: noul = P(sensitive). allow → 0.02 (98% confident
        # not sensitive), deny → 0.9 (only 10% confident).
        return {"approval.sensitive_effect.v1": {"type": "noul", "noul": 0.02 if allow else 0.9}}

    def _fake_decider(self, answers=None, *, status=200, delay=0.0):
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                if delay:
                    time.sleep(delay)
                if answers is None:
                    body = "{}"
                else:
                    body = json.dumps({"model_sha256": "b7c132a67934d51c81abc96bb7724800f965ff5a288aed3e1ca7d8bc349c1386", "answers": answers})
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        server.threshold = 0.95
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}/v1/systemone"

    def test_decider_allow_enables_grey_zone(self):
        # 2026-10-10: a plain grey read (no write, no interpreter body) stays
        # single-mode eligible; 'cat > file' now routes dual by design.
        url = self._fake_decider(self._c1_answers(allow=True))
        manifest = self._decider_manifest(kikin=url)
        log = self.scratch / "decider.jsonl"
        payload = event("Bash", {"command": "stat README.md extra.txt"}, self.root)
        run_hook(payload, manifest, log)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(records[-1]["decision"], "allow")
        self.assertEqual(records[-1]["reason"], "decider_allow")
        self.assertEqual(records[-1]["decider_status"], "accepted")
        self.assertEqual(records[-1]["verdict"], "allow")
        self.assertIsInstance(records[-1]["latency_ms"], int)

    def test_decider_denied_asks(self):
        url = self._fake_decider(self._c1_answers(allow=False))
        manifest = self._decider_manifest(kikin=url)
        log = self.scratch / "decider.jsonl"
        run_hook(event("Bash", {"command": "cat README.md > copy"}, self.root), manifest, log)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(records[-1]["decision"], "ask")
        self.assertEqual(records[-1]["decider_status"], "threshold_failed")

    def test_decider_down_asks(self):
        manifest = self._decider_manifest(kikin="http://127.0.0.1:1/v1/systemone")
        log = self.scratch / "decider.jsonl"
        run_hook(event("Bash", {"command": "cat README.md > copy"}, self.root), manifest, log)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(records[-1]["decision"], "ask")
        self.assertEqual(records[-1]["decider_status"], "unavailable")

    def test_decider_timeout_asks(self):
        url = self._fake_decider(self._c1_answers(allow=True), delay=3.0)
        manifest = self._decider_manifest(kikin=url)
        log = self.scratch / "decider.jsonl"
        run_hook(event("Bash", {"command": "cat README.md > copy"}, self.root), manifest, log)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(records[-1]["decision"], "ask")
        self.assertEqual(records[-1]["decider_status"], "timeout")

    def test_true_floor_cannot_be_overridden(self):
        url = self._fake_decider(self._c1_answers(allow=True))
        manifest = self._decider_manifest(kikin=url)
        log = self.scratch / "decider.jsonl"
        floor_commands = [
            "ssh kikin date", "sudo true", "pkill python3", "kill -9 123",
            "pip install x", "rm -rf README.md", "cat .env", "cat NEXUS/keys/token",
        ]
        for command in floor_commands:
            with self.subTest(command=command):
                run_hook(event("Bash", {"command": command}, self.root), manifest, log)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertTrue(all(record["decision"] == "ask" for record in records[-len(floor_commands):]))
        self.assertTrue(all(record["reason"] == "true_floor" for record in records[-len(floor_commands):]))
        self.assertNotIn("decider_status", records[-1])

    def test_decider_disabled_keeps_grey_zone_asking(self):
        manifest = self._decider_manifest(enabled=False)
        log = self.scratch / "decider.jsonl"
        run_hook(event("Bash", {"command": "cat README.md > copy"}, self.root), manifest, log)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(records[-1]["decision"], "ask")
        self.assertNotIn("decider_status", records[-1])

    def _classify_reason(self, payload, manifest):
        """Run the engine's classify directly (imported once) for reason checks."""
        import importlib.util
        from importlib.machinery import SourceFileLoader
        if not hasattr(self, "_engine"):
            loader = SourceFileLoader("kikin_engine_floor", str(ENGINE))
            spec = importlib.util.spec_from_loader("kikin_engine_floor", loader)
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
            self._engine = module
        import json as _json
        data = _json.loads(Path(manifest).read_text())
        data["entries"] = {item["name"]: item for item in data.get("classes", [])}
        return self._engine.classify(payload, data)[1]

    def test_true_floor_destructive_git(self):
        commands = [
            "git push", "git push origin main", "git push --force origin x",
            "git reset --hard HEAD~1", "git reset --merge", "git rebase main",
            "git clean -fd", "git checkout -- file.py", "git restore file.py",
            "git branch -D topic", "git stash drop", "git stash clear",
            "git commit --amend -m x", "git worktree prune", "git worktree remove ../x",
            "git filter-branch --tree-filter x", "git filter-repo --x",
            "git checkout main", "git merge main",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self._classify_reason(event("Bash", {"command": command}, self.root), self.manifest()), "true_floor")

    def test_true_floor_git_reads_still_classify(self):
        # Fable's additions must not floor observation forms:
        manifest = self.manifest("git_observe")
        reads = ["git status", "git status --short", "git log --oneline -3", "git diff"]
        for command in reads:
            with self.subTest(command=command):
                self.assertIn(self._classify_reason(event("Bash", {"command": command}, self.root), manifest), ("git_observe", "git_observe_disabled"))

    def test_true_floor_disk_and_permissions(self):
        commands = [
            "dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sda1", "cryptsetup luksFormat /dev/sda2",
            "wipefs /dev/sda", "fdisk /dev/sda", "parted /dev/sda", "shred secret.bin",
            "truncate -s 0 data.db", "mount /dev/sda1 /mnt", "umount /mnt",
            "chmod -R 777 dir", "chown -R user dir", "crontab -r", "at now",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self._classify_reason(event("Bash", {"command": command}, self.root), self.manifest()), "true_floor")

    def test_plain_chmod_not_floored(self):
        # chmod without -R stays a grey-zone ask, not an absolute floor.
        reason = self._classify_reason(event("Bash", {"command": "chmod +x script.sh"}, self.root), self.manifest("local_read"))
        self.assertIn(reason, ("no_match_decider", "syntax"))

    def test_interpreter_body_detection(self):
        self._classify_reason(event("Bash", {"command": "true"}, self.root), self.manifest())  # load the engine
        bodies = [
            "python3 -c 'import os'",
            "python -c \"import shutil\"",
            "bash -c 'echo hi'",
            "cat <<EOF\nprint(1)\nEOF",
            "python3 <<'PY'\nimport os\nPY",
        ]
        for command in bodies:
            with self.subTest(command=command):
                self.assertTrue(self._engine._interpreter_body(event("Bash", {"command": command}, self.root)))
        plain = ["python3 script.py", "cat README.md", "git status"]
        for command in plain:
            with self.subTest(command=command):
                self.assertFalse(self._engine._interpreter_body(event("Bash", {"command": command}, self.root)))

    def test_floor_verbs_caught_inside_compounds(self):
        # Replay finding (2026-10-10): floor verbs hid inside compound segments.
        commands = [
            "cd /repo && kill -TERM 30130",
            "cd /repo && rm -rf build && make",
            "cd /repo && git commit --amend --no-edit",
            "cd /repo && ssh honey date",
            "cd /repo && pkill -f worker",
            "cd /repo && git push origin main",
            "cd /repo && crontab -r",
            "cd /repo && chmod -R 777 dir",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self._classify_reason(event("Bash", {"command": command}, self.root), self.manifest()), "true_floor")

    def test_floor_verbs_caught_in_multiline(self):
        # Replay finding: _split_compound refuses raw newlines, so multi-line
        # commands escaped the segment scan ('cd X\nkill -TERM pid'). The
        # apostrophe-in-comment case ('job's') made the whole command
        # unparseable and used to skip the floor entirely.
        commands = [
            "cd /repo\n# stop the job\nkill -TERM 15943; sleep 2\nkill -KILL 15943",
            "cd /repo\n# the job's process group\nkill -TERM -15943 2>/dev/null; sleep 2",
            "cd /repo\ngit push origin master",
            "echo start; rm -rf build; echo done",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self._classify_reason(event("Bash", {"command": command}, self.root), self.manifest()), "true_floor")

    def test_write_capable_detection(self):
        writes = [
            "sed -i 's/a/b/' file.txt",
            "awk -i inplace '{print}' data.txt",
            "cp src dst",
            "mv a b",
            "touch marker",
            "tee out.txt",
            "echo hi > out.txt",
        ]
        self._classify_reason(event("Bash", {"command": "true"}, self.root), self.manifest())  # load engine
        for command in writes:
            with self.subTest(command=command):
                self.assertTrue(self._engine._write_capable(event("Bash", {"command": command}, self.root)))
        reads = ["cat README.md", "grep -n x file.txt", "ls -la", "git status"]
        for command in reads:
            with self.subTest(command=command):
                self.assertFalse(self._engine._write_capable(event("Bash", {"command": command}, self.root)))

    def test_git_apply_routes_dual(self):
        # Calibration finding 2026-10-10: 'git apply x.patch' is a worktree
        # write and must be dual-judged; --check/--stat dry runs stay single.
        self._classify_reason(event("Bash", {"command": "true"}, self.root), self.manifest())
        for command, expected in [
            ("cd /repo && git apply /tmp/x.patch", True),
            ("git apply --check /tmp/x.patch", False),
            ("git apply --stat /tmp/x.patch", False),
        ]:
            with self.subTest(command=command):
                self.assertEqual(self._engine._write_capable(event("Bash", {"command": command}, self.root)), expected)

    def test_write_capable_routes_dual_not_single(self):
        # A sed -i grey prompt must consult the destructive question, not just
        # sensitive: wire the fake decider to answer single-mode allow but dual
        # threshold-fail on the destructive half.
        url = self._fake_decider({
            "approval.sensitive_effect.v1": {"type": "noul", "noul": 0.02},
            "approval.needs_human.v1": {"type": "noul", "noul": 0.9},
        })
        manifest = self._decider_manifest(kikin=url)
        log = self.scratch / "write-dual.jsonl"
        run_hook(event("Bash", {"command": "sed -i 's/a/b/' file.txt"}, self.root), manifest, log)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(records[-1]["decision"], "ask")
        self.assertEqual(records[-1]["decider_status"], "threshold_failed")

    def test_r2d2d_wire_round_trip(self):
        self._classify_reason(event("Bash", {"command": "true"}, self.root), self.manifest())  # load engine
        envelope = self._engine._c1_envelope(event("Bash", {"command": "stat README.md"}, self.root), "req-1", 2200, mode="dual")
        envelope["r2d2d"] = True
        wire, ids = self._engine._r2d2d_body(envelope)
        self.assertEqual(ids, [self._engine.GREY_QUESTION_SINGLE, self._engine.GREY_QUESTION_DESTRUCTIVE])
        self.assertEqual(len(wire["questions"]), 2)
        self.assertTrue(all(q["type"] == "noul" for q in wire["questions"]))
        # responses adapt back into the gate answers shape
        answers = self._engine._r2d2d_answers({"answers": [{"p_yes": 0.02}, {"p_yes": 0.03}]}, ids)
        self.assertEqual(answers[self._engine.GREY_QUESTION_SINGLE]["noul"], 0.02)
        # shape failures are rejected
        self.assertIsNone(self._engine._r2d2d_answers({"answers": [{"p_yes": 0.5}]}, ids))
        self.assertIsNone(self._engine._r2d2d_answers({"answers": [{"p_yes": "x"}, {"p_yes": 0.5}]}, ids))
        self.assertIsNone(self._engine._r2d2d_answers({"answers": [{"p_yes": 1.5}, {"p_yes": 0.5}]}, ids))

    def test_decider_config_honey_api_validation(self):
        self._classify_reason(event("Bash", {"command": "true"}, self.root), self.manifest())  # load engine
        base = {"enabled": True, "honey_url": "http://honey.tailnet:8097/decide", "kikin_url": "http://127.0.0.1:8098/v1/systemone", "timeout_ms": 2200, "min_allow_confidence": 0.95, "questions": "single"}
        cfg = self._engine._decider_config({"decider": base})
        self.assertEqual(cfg["honey_api"], "kikin")
        cfg2 = self._engine._decider_config({"decider": {**base, "honey_api": "r2d2d"}})
        self.assertEqual(cfg2["honey_api"], "r2d2d")
        cfg3 = self._engine._decider_config({"decider": {**base, "honey_api": "weird"}})
        self.assertIsNone(cfg3)

    def test_r2d2d_endpoint_allows_and_denies(self):
        # A fake r2d2d server on loopback: honey endpoint with honey_api=r2d2d.
        import http.server
        import threading

        class FakeR2D2D(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                req = json.loads(self.rfile.read(n) or b"{}")
                n_questions = len(req.get("questions") or [])
                # benign p_yes values under the threshold for every question
                p = [0.02] * n_questions
                state = json.dumps(req.get("state", {}))
                if "rm -rf" in state or ">" in state:
                    p = [0.9] * n_questions
                answers = [{"choice": "yes" if v > 0.5 else "no", "confidence": 0.9, "probs": {"yes": v, "no": 1 - v}, "p_yes": v} for v in p]
                body = json.dumps({"answers": answers, "ms": 42}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), FakeR2D2D)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        manifest = self._decider_manifest(honey=f"http://127.0.0.1:{port}/decide", honey_api="r2d2d", kikin="http://127.0.0.1:1/v1/systemone")
        try:
            log = self.scratch / "r2d2d.jsonl"
            run_hook(event("Bash", {"command": "stat README.md extra.txt"}, self.root), manifest, log)
            records = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(records[-1]["decision"], "allow")
            self.assertEqual(records[-1]["decider_status"], "accepted")
            log2 = self.scratch / "r2d2d-deny.jsonl"
            run_hook(event("Bash", {"command": "echo hi > out.txt && stat x"}, self.root), manifest, log2)
            records2 = [json.loads(line) for line in log2.read_text().splitlines()]
            self.assertEqual(records2[-1]["decision"], "ask")
            self.assertEqual(records2[-1]["decider_status"], "threshold_failed")
        finally:
            server.shutdown()

    def test_dual_mode_requires_both_questions(self):
        url = self._fake_decider({
            "approval.sensitive_effect.v1": {"type": "noul", "noul": 0.02},
            "approval.needs_human.v1": {"type": "noul", "noul": 0.9},
        })
        manifest = self._decider_manifest(kikin=url)
        log = self.scratch / "dual.jsonl"
        run_hook(event("Bash", {"command": "python3 -c 'import os'"}, self.root), manifest, log)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(records[-1]["decision"], "ask")
        self.assertEqual(records[-1]["decider_status"], "threshold_failed")

    def test_dual_mode_allows_when_both_clear(self):
        url = self._fake_decider({
            "approval.sensitive_effect.v1": {"type": "noul", "noul": 0.02},
            "approval.needs_human.v1": {"type": "noul", "noul": 0.03},
        })
        manifest = self._decider_manifest(kikin=url)
        log = self.scratch / "dual-ok.jsonl"
        run_hook(event("Bash", {"command": "python3 -c 'print(1)'"}, self.root), manifest, log)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(records[-1]["decision"], "allow")
        self.assertEqual(records[-1]["reason"], "decider_allow")

    def test_v1_manifest_still_loads_without_decider(self):
        manifest = self.manifest("local_read")
        self.assert_decision(event("Read", {"file_path": str(self.root / "README.md")}, self.root), manifest, "allow")

    def test_malformed_input_asks(self):
        manifest = self.manifest("local_read")
        completed = subprocess.run([str(HOOK)], input="{not-json", text=True, capture_output=True, env={**os.environ, "SO_APPROVAL_KIKIN_MANIFEST": str(manifest), "SO_APPROVAL_KIKIN_LOG": os.devnull}, timeout=2, check=False)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(decision(completed), "ask")


if __name__ == "__main__":
    unittest.main()
