#!/usr/bin/env python3
import json
import importlib.util
import inspect
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[5]
HOOK = REPO / "all/.local/bin/claude-hook-permission-request"
MANIFEST = REPO / "all/.config/dotcortex/claude-approval-p3.json"
ENGINE = REPO / "all/.local/lib/dotcortex/claude_approval_p3.py"
ENGINE_SPEC = importlib.util.spec_from_file_location("dotcortex_approval_p3", ENGINE)
ENGINE_MODULE = importlib.util.module_from_spec(ENGINE_SPEC)
ENGINE_SPEC.loader.exec_module(ENGINE_MODULE)


def event(tool_name, tool_input, cwd=None):
    payload = {
        "hook_event_name": "PermissionRequest",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }
    if cwd is not None:
        payload["cwd"] = str(cwd)
    return payload


def run_hook(payload, manifest=None, cwd=None):
    env = os.environ.copy()
    if manifest is not None:
        env["SO_APPROVAL_P3_MANIFEST"] = str(manifest)
    completed = subprocess.run(
        [str(HOOK)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=cwd or REPO,
        env=env,
        timeout=2,
        check=False,
    )
    return completed


def decision(stdout):
    if not stdout.strip():
        return "ask"
    parsed = json.loads(stdout)
    return parsed["hookSpecificOutput"]["decision"]["behavior"]


class FakeRemotePathRunner:
    def __init__(self, *, stdout="", returncode=0, error=None):
        self.stdout = stdout
        self.returncode = returncode
        self.error = error
        self.calls = []

    def __call__(self, argv, timeout_seconds):
        self.calls.append((tuple(argv), timeout_seconds))
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, "")


def identity_remote_path_runner(argv, timeout_seconds):
    separator = list(argv).index("--")
    paths = [shlex.split(item)[0] for item in argv[separator + 1:]]
    return subprocess.CompletedProcess(argv, 0, "".join(path + "\n" for path in paths), "")


def engine_decision(payload, manifest, runner=identity_remote_path_runner):
    with mock.patch.dict(os.environ, {"SO_APPROVAL_P3_MANIFEST": str(manifest)}):
        loaded = ENGINE_MODULE._load_manifest()
    kwargs = {}
    if "remote_path_runner" in inspect.signature(ENGINE_MODULE.evaluate).parameters:
        kwargs["remote_path_runner"] = runner
    try:
        return "allow" if ENGINE_MODULE.evaluate(payload, loaded, **kwargs) else "ask"
    except Exception:
        return "ask"


class ApprovalHookHarness(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HOOK.is_file(), HOOK)
        self.assertTrue(MANIFEST.is_file(), MANIFEST)
        self.base = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def enabled_manifest(self, root, *classes):
        data = json.loads(json.dumps(self.base))
        data["local_test_roots"] = [str(root)]
        data["centre_roots"] = [str(root)]
        data["dotcortex_roots"] = [str(root)]
        data["readonly_host"] = "YOUR_READONLY_HOST"
        data["remote_home"] = "/home/metsatron"
        data["remote_path_roots"] = [
            "/home/metsatron/HelmCortex",
            "/home/metsatron/mnt/x230/HelmCortex",
            "/home/metsatron/DotCortex",
            "/home/metsatron/HelmCortex-wt-kikin",
            "/home/metsatron/DotCortex-wt-kikin",
        ]
        data["mailcortex_account"] = "bunta@kikin.helm"
        for item in data["classes"]:
            item["enabled"] = item["name"] in classes
        target = Path(self.tempdir.name) / "manifest.json"
        target.write_text(json.dumps(data), encoding="utf-8")
        return target

    def make_tree(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        root = Path(self.tempdir.name) / "DotCortex"
        (root / "tests").mkdir(parents=True)
        (root / "FORGE/bin").mkdir(parents=True)
        (root / "tests/test_gate.py").write_text("# synthetic\n", encoding="utf-8")
        (root / "FORGE/bin/pokemon-centre").write_text("# synthetic\n", encoding="utf-8")
        (root / "FORGE/bin/clubhouse-bosses-refresh").write_text("# synthetic\n", encoding="utf-8")
        (root / "message.txt").write_text("subject\n", encoding="utf-8")
        os.chmod(root / "message.txt", 0o600)
        return root

    def assert_ask(self, payload, manifest=None, cwd=None):
        completed = run_hook(payload, manifest=manifest, cwd=cwd)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(decision(completed.stdout), "ask", completed.stdout)

    def assert_allow(self, payload, manifest, cwd=None):
        completed = run_hook(payload, manifest=manifest, cwd=cwd)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(decision(completed.stdout), "allow", completed.stdout)

    def test_committed_manifest_matches_admiral_enablement_ruling(self):
        self.assertTrue(self.base["classes"])
        self.assertEqual(
            {item["name"]: item["enabled"] for item in self.base["classes"]},
            {
                "ssh-kikin-readonly": True,
                "local-test-run": False,
                "centre-render": True,
                "dotcortex-safe-commit": True,
                "outbound-tool-call": False,
            },
        )
        self.assert_ask(event("Bash", {"command": "python3 -m unittest FORGE.tests.test_gate"}, REPO))

    def test_ssh_readonly_exact_shape_and_smuggling(self):
        root = self.make_tree()
        manifest = self.enabled_manifest(root, "ssh-kikin-readonly")
        for good in (
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'git -C HelmCortex status --short | head -20'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'find HelmCortex/FORGE -maxdepth 2 -type f | grep approval | wc -l'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'cat HelmCortex/README.md'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'cat /home/metsatron/HelmCortex/README.md'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'cat ~/HelmCortex/README.md'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'cat DotCortex/../HelmCortex/README.md'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'cat //home/metsatron/HelmCortex/./README.md'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'mailcortex inbox bunta@kikin.helm'",
        ):
            with self.subTest(good=good):
                self.assertEqual(
                    engine_decision(event("Bash", {"command": good}, root), manifest),
                    "allow",
                )
        for command in (
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'cat /etc/hosts > /tmp/x'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'date; id'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'grep x f && rm f'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'cat $(date)'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'ssh other date'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'find . -exec cat {} +'",
            "ssh -o BatchMode=yes YOUR_READONLY_HOST 'cat .ssh/config'",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    engine_decision(event("Bash", {"command": command}, root), manifest),
                    "ask",
                )

    def test_ssh_readonly_credential_and_path_boundary(self):
        root = self.make_tree()
        manifest = self.enabled_manifest(root, "ssh-kikin-readonly")
        for leak, commands in {
            "nanobot_env": (
                "cat .config/nanobot-telegram/env",
                "cat /home/metsatron/.config/nanobot-telegram/env",
                "cat ~/.config/nanobot-telegram/env",
                "cat HelmCortex/../.config/nanobot-telegram/env",
            ),
            "mailcortex_private_token": (
                "cat .config/mailcortex/private/x.token",
                "cat /home/metsatron/.config/mailcortex/private/x.token",
                "cat ~/.config/mailcortex/private/x.token",
                "cat DotCortex/../.config/mailcortex/private/x.token",
            ),
            "nexus_secret_cookie": (
                "cat NEXUS/.secrets/mistral_cookies.jar",
                "cat /home/metsatron/HelmCortex/NEXUS/.secrets/mistral_cookies.jar",
                "cat ~/HelmCortex/NEXUS/.secrets/mistral_cookies.jar",
                "cat HelmCortex/./NEXUS/.secrets/mistral_cookies.jar",
                "cat HelmCortex/../HelmCortex/NEXUS/.secrets/mistral_cookies.jar",
            ),
            "foreign_mail_inbox": ("mailcortex inbox fable@kikin.helm",),
            "foreign_mail_read": ("mailcortex read fable@kikin.helm 1",),
            "path_boundary": (
                "git show HEAD:NEXUS/.secrets/x",
                "git -C HelmCortex show HEAD:NEXUS/.secrets/x",
                "find HelmCortex -name env",
                'find HelmCortex -name "*.env"',
                "find -name README.md",
                "grep TOKEN .config -r",
                "grep -r TOKEN",
                "ls",
                "git status --short",
                "cat HelmCortex/*.md",
                "cat HelmCortex/{README.md,AGENTS.md}",
                "cat HelmCortex/$FILE",
                "cat HelmCortex/NEXUS/private/x",
                "cat HelmCortex/NEXUS/secrets/x",
                "cat HelmCortex/NEXUS/keys/x",
                "cat HelmCortex/NEXUS/credentials/x",
                "cat HelmCortex/public/env",
                "cat HelmCortex/public/.env",
                "cat HelmCortex/public/dev.env",
                "cat HelmCortex/public/x.token",
                "cat HelmCortex/public/x.key",
                "cat HelmCortex/public/x.pem",
                "cat HelmCortex/public/auth.json",
                "cat HelmCortex/public/cookies.sqlite",
                "cat HelmCortex/public/archive.jar",
                "cat HelmCortex/public/session-token-cache",
                "cat HelmCortex/public/secret-notes",
                "cat /etc/passwd",
                "cat /proc/self/environ",
                "cat /var/lib/private/token",
            ),
        }.items():
            for remote in commands:
                command = f"ssh -o BatchMode=yes YOUR_READONLY_HOST '{remote}'"
                with self.subTest(leak=leak, command=command):
                    self.assertEqual(
                        engine_decision(event("Bash", {"command": command}, root), manifest),
                        "ask",
                    )

    def test_ssh_readonly_privacy_boundaries(self):
        root = self.make_tree()
        manifest = self.enabled_manifest(root, "ssh-kikin-readonly")
        privacy_cases = {
            "personal": {
                "paths": (
                    "HelmCortex/LOGS/Telegram/Personal/chat.md",
                    "/home/metsatron/HelmCortex/LOGS/Telegram/Personal/chat.md",
                    "~/HelmCortex/LOGS/Telegram/Personal/chat.md",
                    "HelmCortex/FORGE/../../HelmCortex/LOGS/Telegram/Personal/chat.md",
                ),
                "repos": (
                    "HelmCortex",
                    "/home/metsatron/HelmCortex",
                    "~/HelmCortex",
                    "HelmCortex/FORGE/..",
                ),
                "object": "LOGS/Telegram/Personal/chat.md",
            },
            "palmcortex": {
                "paths": (
                    "HelmCortex/CORTEX/PalmCortex/Diary.md",
                    "/home/metsatron/HelmCortex/CORTEX/PalmCortex/Diary.md",
                    "~/HelmCortex/CORTEX/PalmCortex/Diary.md",
                    "HelmCortex/FORGE/../../HelmCortex/CORTEX/PalmCortex/Diary.md",
                ),
                "repos": (
                    "HelmCortex",
                    "/home/metsatron/HelmCortex",
                    "~/HelmCortex",
                    "HelmCortex/FORGE/..",
                ),
                "object": "CORTEX/pAlMcOrTeX/Diary.md",
            },
        }
        for boundary, values in privacy_cases.items():
            commands = []
            for path in values["paths"]:
                commands.extend((
                    f"cat {path}",
                    f"grep private {path}",
                    f"ls {path}",
                    f"find {path} -maxdepth 1",
                    f"git -C HelmCortex log -- {path}",
                    f"git -C HelmCortex diff -- {path}",
                ))
            commands.extend(
                f"git -C {repo} show HEAD:{values['object']}"
                for repo in values["repos"]
            )
            for remote in commands:
                command = f"ssh -o BatchMode=yes YOUR_READONLY_HOST '{remote}'"
                with self.subTest(boundary=boundary, command=command):
                    self.assertEqual(
                        engine_decision(event("Bash", {"command": command}, root), manifest),
                        "ask",
                    )

    def test_ssh_remote_realpath_proof_is_fixed_argv_and_fail_ask(self):
        root = self.make_tree()
        manifest = self.enabled_manifest(root, "ssh-kikin-readonly")
        command = "ssh -o BatchMode=yes YOUR_READONLY_HOST 'cat HelmCortex/README.md'"
        payload = event("Bash", {"command": command}, root)
        allowed = "/home/metsatron/HelmCortex/README.md"
        runner = FakeRemotePathRunner(stdout=allowed + "\n")
        self.assertEqual(engine_decision(payload, manifest, runner), "allow")
        self.assertEqual(
            runner.calls,
            [
                (
                    (
                        "ssh",
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "ConnectTimeout=3",
                        "YOUR_READONLY_HOST",
                        "realpath",
                        "-e",
                        "--",
                        allowed,
                    ),
                    2.5,
                )
            ],
        )
        failures = (
            FakeRemotePathRunner(stdout="/home/metsatron/HelmCortex/NEXUS/.secrets/x\n"),
            FakeRemotePathRunner(stdout="/etc/passwd\n"),
            FakeRemotePathRunner(stdout="/home/metsatron/HelmCortex/LOGS/Telegram/Personal/chat.md\n"),
            FakeRemotePathRunner(returncode=1),
            FakeRemotePathRunner(stdout=allowed + "\n" + allowed + "\n"),
            FakeRemotePathRunner(stdout="not-an-absolute-path\n"),
        )
        for failed_runner in failures:
            with self.subTest(runner=failed_runner):
                self.assertEqual(engine_decision(payload, manifest, failed_runner), "ask")

    def test_timeout_budgets_are_pinned_and_remote_timeout_asks(self):
        self.assertEqual(ENGINE_MODULE.REMOTE_REALPATH_TIMEOUT_SECONDS, 2.5)
        self.assertEqual(ENGINE_MODULE.HARD_TIMEOUT_SECONDS, 3.0)
        root = self.make_tree()
        manifest = self.enabled_manifest(root, "ssh-kikin-readonly")
        payload = event(
            "Bash",
            {"command": "ssh -o BatchMode=yes YOUR_READONLY_HOST 'cat HelmCortex/README.md'"},
            root,
        )
        runner = FakeRemotePathRunner(
            error=subprocess.TimeoutExpired(["ssh"], 2.5)
        )
        self.assertEqual(engine_decision(payload, manifest, runner), "ask")
        self.assertEqual(runner.calls[0][1], 2.5)

    def test_git_show_object_path_stays_lexical_only(self):
        root = self.make_tree()
        manifest = self.enabled_manifest(root, "ssh-kikin-readonly")
        repo = "/home/metsatron/HelmCortex"
        runner = FakeRemotePathRunner(stdout=repo + "\n")
        payload = event(
            "Bash",
            {"command": "ssh -o BatchMode=yes YOUR_READONLY_HOST 'git -C HelmCortex show HEAD:README.md'"},
            root,
        )
        self.assertEqual(engine_decision(payload, manifest, runner), "allow")
        self.assertEqual(runner.calls[0][0][-1:], (repo,))

    def test_remote_realpath_mount_alias_is_allowed_but_privacy_still_asks(self):
        root = self.make_tree()
        manifest = self.enabled_manifest(root, "ssh-kikin-readonly")
        payload = event(
            "Bash",
            {"command": "ssh -o BatchMode=yes YOUR_READONLY_HOST 'cat HelmCortex/README.md'"},
            root,
        )
        mounted_readme = "/home/metsatron/mnt/x230/HelmCortex/README.md"
        allowed_runner = FakeRemotePathRunner(stdout=mounted_readme + "\n")
        self.assertEqual(engine_decision(payload, manifest, allowed_runner), "allow")

        mounted_personal = (
            "/home/metsatron/mnt/x230/HelmCortex/"
            "LOGS/Telegram/Personal/x"
        )
        private_runner = FakeRemotePathRunner(stdout=mounted_personal + "\n")
        self.assertEqual(engine_decision(payload, manifest, private_runner), "ask")

    def test_local_test_run_exact_shapes_and_paths(self):
        root = self.make_tree()
        manifest = self.enabled_manifest(root, "local-test-run")
        for command in (
            "python3 -m unittest FORGE.tests.test_gate",
            "/usr/bin/python3 -m unittest FORGE.tests.test_gate.TestGate.test_one",
            'pytest tests/test_gate.py -q -m "not live"',
        ):
            with self.subTest(command=command):
                self.assert_allow(event("Bash", {"command": command}, root), manifest, root)
        for command in (
            "python3 -m unittest ../../outside.test_gate",
            "python3 -m unittest FORGE.tests.test_gate; id",
            'pytest tests/test_gate.py -q -m "not live" > out',
            "pytest tests/test_gate.py -q",
        ):
            with self.subTest(command=command):
                self.assert_ask(event("Bash", {"command": command}, root), manifest, root)

    def test_centre_render_exact_commands_and_cwd(self):
        root = self.make_tree()
        manifest = self.enabled_manifest(root, "centre-render")
        for command in (
            "/usr/bin/python3 FORGE/bin/pokemon-centre render",
            "FORGE/bin/clubhouse-bosses-refresh",
        ):
            with self.subTest(command=command):
                self.assert_allow(event("Bash", {"command": command}, root), manifest, root)
        self.assert_ask(
            event("Bash", {"command": "/usr/bin/python3 FORGE/bin/pokemon-centre render --live"}, root),
            manifest,
            root,
        )
        self.assert_ask(
            event("Bash", {"command": "FORGE/bin/clubhouse-bosses-refresh"}, root / "tests"),
            manifest,
            root / "tests",
        )

    def test_safe_commit_requires_message_file_separator_and_safe_paths(self):
        root = self.make_tree()
        manifest = self.enabled_manifest(root, "dotcortex-safe-commit")
        message = root / "message.txt"
        good = f"git commit -F {message} -- tests/test_gate.py"
        self.assert_allow(event("Bash", {"command": good}, root), manifest, root)
        for command in (
            "git commit",
            f"git commit -F {message} tests/test_gate.py",
            f"git commit -F {message} -- .git/config",
            f"git commit -F {message} -- NEXUS/keys/token",
            f"git commit -F {message} -- /home/gille/file",
            f"git commit -F {message} -- tests/missing.py",
            f"git commit -F {message} -- tests",
            f"git commit -F {message} -- tests/test_gate.py && git push",
        ):
            with self.subTest(command=command):
                self.assert_ask(event("Bash", {"command": command}, root), manifest, root)

    def test_outbound_tools_are_name_routed_and_off_by_default(self):
        root = self.make_tree()
        telegram = "mcp__plugin_telegram_telegram__reply"
        mail = "mcp__mailcortex__send"
        self.assert_ask(event(telegram, {"text": "hello"}, root))
        manifest = self.enabled_manifest(root, "outbound-tool-call")
        self.assert_allow(event(telegram, {"text": "hello"}, root), manifest, root)
        self.assert_allow(event(mail, {"to": "seat", "body": "hello"}, root), manifest, root)
        self.assert_ask(event(telegram, {"text": "send NEXUS/keys/token"}, root), manifest, root)
        self.assert_ask(event("mcp__mailcortex__delete", {}, root), manifest, root)

    def test_hard_never_wins_over_enabled_classes(self):
        root = self.make_tree()
        manifest = self.enabled_manifest(
            root,
            "ssh-kikin-readonly",
            "local-test-run",
            "centre-render",
            "dotcortex-safe-commit",
            "outbound-tool-call",
        )
        for command in (
            "git push origin master",
            "git reset --keep HEAD^",
            "git revert HEAD",
            "git worktree prune",
            "rm -r tests",
            "sudo true",
            "systemctl status sshd",
            "tailscale status",
            "python3 -m pip install x",
            "crontab -l",
            "cat /home/gille/file",
            "cat 'Secret Vault/file'",
            "cat .env",
            "cat ~/.ssh/config",
            "cat NEXUS/keys/token",
        ):
            with self.subTest(command=command):
                self.assert_ask(event("Bash", {"command": command}, root), manifest, root)

    def test_malformed_and_unknown_ask(self):
        root = self.make_tree()
        manifest = self.enabled_manifest(root, "local-test-run")
        self.assert_ask(event("UnknownTool", {}, root), manifest, root)
        completed = subprocess.run(
            [str(HOOK)],
            input="{not-json",
            text=True,
            capture_output=True,
            env={**os.environ, "SO_APPROVAL_P3_MANIFEST": str(manifest)},
            timeout=2,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(decision(completed.stdout), "ask")

if __name__ == "__main__":
    unittest.main()
