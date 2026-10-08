#!/usr/bin/env python3
"""Tests for the Honey Telegram Claude bot launchers and services (agents-bots-honey.org)."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[5]
SHARE = ROOT / "all/.local/share/dotcortex/honey-claude"
BIN = SHARE / "bin"
OPENRC = SHARE / "openrc"
BOTS = {"opus": "claude-opus-5-5", "sonnet": "claude-sonnet-5-5", "haiku": "claude-haiku-4-5-20251001"}
PERSONAS = {"opus": "Bunta", "sonnet": "Sasuke", "haiku": "Shoukichi"}


class Home:
    def __init__(self, plugin_enabled=True, boundary=True, account=True, idle_hooks=True):
        self.plugin_enabled = plugin_enabled
        self.idle_hooks = idle_hooks
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.bin = Path(self.tmp.name) / "bin"
        self.xdg = Path(self.tmp.name) / "run"
        self.record = Path(self.tmp.name) / "record.json"
        for path in (self.home, self.bin, self.xdg):
            path.mkdir()
        (self.home / ".claude").mkdir()
        if account:
            (self.home / ".claude.json").write_text(json.dumps({"oauthAccount": {"accountUuid": "test-account"}}))
        # No ~/.claude/settings.json: the lane's claude-settings.json enables the plugin.
        # A disabled plugin, or settings without the idle hooks, is simulated by pointing the
        # preflights at a settings file that says so.
        self.settings = Path(self.tmp.name) / "settings.json"
        self.settings.write_text(json.dumps({"enabledPlugins": {"telegram@claude-plugins-official": plugin_enabled}}))
        plugin = self.home / ".claude/plugins/cache/claude-plugins-official/telegram/0.0.6"
        plugin.mkdir(parents=True)
        (plugin / ".mcp.json").write_text(json.dumps({"mcpServers": {"telegram": {"command": "bun"}}}))
        (plugin / "server.ts").write_text("")
        npm_bin = self.home / ".npm-global/bin"
        npm_bin.mkdir(parents=True)
        self.script(npm_bin / "bun", "exit 0\n")
        self.script(self.bin / "claude-warm", (
            "import json, os, sys\n"
            f"json.dump({{'argv': sys.argv[1:], 'cwd': os.getcwd(), 'pid': os.getpid(),"
            " 'agent': os.environ.get('CLAUDE_WARM_HERDR_AGENT'),"
            " 'state': os.environ.get('TELEGRAM_STATE_DIR'), 'path': os.environ['PATH'],"
            " 'guard': {k: v for k, v in os.environ.items() if k.startswith('CLAUDE_WARM_PRESERVATION_')}},"
            f" open({str(self.record)!r}, 'w'))\n"), shebang="#!/usr/bin/env python3\n")
        for bot in BOTS:
            state = self.home / f".claude/channels/telegram-{bot}"
            state.mkdir(parents=True)
            (state / ".env").write_text("TELEGRAM_BOT_TOKEN=dummy-test-value\n")
            work = self.home / "honey-work" / bot
            work.mkdir(parents=True)
            if boundary:
                (work / "CLAUDE.md").write_text((SHARE / f"CLAUDE.{bot}.md").read_text())

    @staticmethod
    def script(path, body, shebang="#!/bin/sh\n"):
        path.write_text(shebang + body)
        path.chmod(0o755)

    def run(self, bot, *args):
        env = {"HOME": str(self.home), "PATH": f"{self.bin}:/usr/bin:/bin",
               "XDG_RUNTIME_DIR": str(self.xdg)}
        if not self.plugin_enabled or not self.idle_hooks:
            env["CLAUDE_SETTINGS_FILE"] = str(self.settings)
        return subprocess.run([str(BIN / f"honey-{bot}"), *args], capture_output=True,
                              text=True, env=env)

    def recorded(self):
        return json.loads(self.record.read_text())

    def close(self):
        self.tmp.cleanup()


class LauncherTests(unittest.TestCase):
    def test_each_bot_launches_its_telegram_warm_session(self):
        box = Home()
        try:
            agents = set()
            for bot, model in BOTS.items():
                result = box.run(bot, "--telegram")
                self.assertEqual(result.returncode, 0, result.stderr)
                rec = box.recorded()
                self.assertEqual(rec["argv"], ["--model", model, "--permission-mode", "acceptEdits",
                                               "--allowedTools=mcp__plugin_telegram_telegram",
                                               "--settings=" + str(SHARE / "lib") + "/../claude-settings.json",
                                               "--channels", "plugin:telegram@claude-plugins-official"])
                self.assertEqual(rec["cwd"], str(box.home / "honey-work" / bot))
                self.assertEqual(rec["state"], str(box.home / f".claude/channels/telegram-{bot}"))
                self.assertEqual(rec["agent"], f"honey-{bot}-bot")
                self.assertIn(str(box.home / ".npm-global/bin"), rec["path"].split(":"))
                self.assertIn(str(ROOT / "all/.local/bin"), rec["path"].split(":"), "fleet bin of the lane checkout")
                self.assertTrue(rec["path"].startswith(str(box.bin)), "PATH must be appended to")
                pidfile = box.xdg / f"honey-{bot}.pid"
                self.assertEqual(pidfile.read_text().strip(), str(rec["pid"]))
                agents.add(rec["agent"])
            self.assertNotIn("honey-opus", agents, "collides with Honey's existing warm consort")
        finally:
            box.close()

    def test_gillean_usage_guard_is_bound(self):
        import hashlib
        box = Home()
        try:
            result = box.run("sonnet", "--telegram")
            self.assertEqual(result.returncode, 0, result.stderr)
            guard = box.recorded()["guard"]
            self.assertEqual(len(guard), 18, sorted(guard))
            digest = "sha256:" + hashlib.sha256(b"test-account").hexdigest()
            self.assertEqual(guard["CLAUDE_WARM_PRESERVATION_ACCOUNT_HASH"], digest)
            self.assertEqual(guard["CLAUDE_WARM_PRESERVATION_AUTHORITY_IDENTITY"], "kikin-kushi")
            self.assertEqual(guard["CLAUDE_WARM_PRESERVATION_TELEMETRY_HOST"], "honey-metsatron")
            self.assertTrue(guard["CLAUDE_WARM_PRESERVATION_LEDGER_ROOT"].endswith("/claude-gillean"))
            self.assertTrue(guard["CLAUDE_WARM_PRESERVATION_BRIDGE"].endswith(
                "/skills-mirror/FORGE/bin/fleet-preservation"))
            self.assertNotIn("test-account", json.dumps(guard))
        finally:
            box.close()

    def test_guard_is_inert_but_bot_runs_before_login(self):
        box = Home(account=False)
        try:
            result = box.run("haiku", "--telegram")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage guard inert", result.stderr)
            self.assertEqual(box.recorded()["guard"], {})
        finally:
            box.close()

    def test_personas_in_identity_files(self):
        for bot, name in PERSONAS.items():
            text = (SHARE / f"CLAUDE.{bot}.md").read_text()
            self.assertTrue(text.startswith(f"# CLAUDE.md - {name} (honey-{bot}, @honey_{bot}_bot, {BOTS[bot]})"))
            self.assertIn("## Identity", text)
            self.assertIn("# Honey boundary law", text)
            self.assertIn(name, (BIN / f"honey-{bot}").read_text())

    def test_plain_run_has_no_channel(self):
        box = Home()
        try:
            result = box.run("haiku")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(box.recorded()["argv"], ["--model", BOTS["haiku"]])
        finally:
            box.close()

    def test_model_override(self):
        box = Home()
        try:
            env_run = subprocess.run([str(BIN / "honey-sonnet")], capture_output=True, text=True,
                                     env={"HOME": str(box.home), "PATH": f"{box.bin}:/usr/bin:/bin",
                                          "HONEY_SONNET_MODEL": "claude-sonnet-x"})
            self.assertEqual(env_run.returncode, 0, env_run.stderr)
            self.assertEqual(box.recorded()["argv"], ["--model", "claude-sonnet-x"])
        finally:
            box.close()

    def test_refuses_without_boundary_law(self):
        box = Home(boundary=False)
        try:
            result = box.run("opus", "--telegram")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("boundary law", result.stderr)
            self.assertFalse(box.record.exists())
        finally:
            box.close()

    def test_refuses_without_enabled_plugin(self):
        box = Home(plugin_enabled=False)
        try:
            result = box.run("opus", "--telegram")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not enabled", result.stderr)
            self.assertNotIn("dummy-test-value", result.stdout + result.stderr)
            self.assertFalse(box.record.exists())
        finally:
            box.close()

    def test_refuses_without_idle_hooks(self):
        # 2026-09-30: a bot that cannot tell claude-warm its turns ended never compacts.
        box = Home(idle_hooks=False)
        try:
            result = box.run("sonnet", "--telegram")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("claude-hook-idle-event", result.stderr)
            self.assertFalse(box.record.exists())
        finally:
            box.close()


class ServiceTests(unittest.TestCase):
    def test_one_body_for_the_three_services(self):
        self.assertEqual(sorted(p.name for p in OPENRC.iterdir()), ["honey-bot", "honey-claude-install"])

    def test_script_rules(self):
        text = (OPENRC / "honey-bot").read_text()
        self.assertTrue(text.startswith("#!/sbin/openrc-run\n"))
        self.assertNotRegex(text, r"\bneed\s+net\b")
        self.assertIn("use net dns", text)
        self.assertNotRegex(text, r"(^|[\s;'\"])PATH=['\"]?/", "PATH must only be appended to")
        self.assertIn('PATH=\\"\\${PATH}:', text)
        self.assertIn(': "${bot_user:=agent-claude}"', text)
        self.assertIn(': "${honey_claude_checkout:=/usr/local/share/dotcortex/DotCortex}"', text)
        self.assertIn('bot_launcher="${bot_lane}/bin/${RC_SVCNAME}"', text)
        self.assertIn("-perm /022", text, "must refuse a checkout the bot could edit")
        self.assertNotIn("${bot_home}/DotCortex", text, "never the bot's own checkout")
        self.assertNotIn("/home/gille", text)
        result = subprocess.run(["sh", "-n", str(OPENRC / "honey-bot")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_installer_dry_run_changes_nothing_and_refuses_a_user_checkout(self):
        result = subprocess.run([str(OPENRC / "honey-claude-install"), "--dry-run"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("a real run would refuse", result.stderr)
        for bot in BOTS:
            self.assertRegex(result.stdout, rf"(would: install -m 0755 -o root -g root \S+/openrc/honey-bot /etc/init.d/honey-{bot}|unchanged /etc/init.d/honey-{bot})")
        if os.getuid() != 0:
            real = subprocess.run([str(OPENRC / "honey-claude-install")], capture_output=True, text=True)
            self.assertNotEqual(real.returncode, 0)


class LaneTests(unittest.TestCase):
    """The lane is a host service: never stowed, never on anyone's PATH."""

    def test_no_honey_overlay_launchers(self):
        self.assertFalse((ROOT / "honey/.local/bin").exists())
        self.assertFalse((ROOT / "honey/.local/share/honey-claude").exists())

    def test_lane_is_stow_ignored(self):
        self.assertIn("^/\\.local/share/dotcortex/honey-claude(/|$)",
                      (ROOT / "all/.stow-local-ignore").read_text().splitlines())

    @unittest.skipUnless(shutil.which("stow"), "GNU Stow is not installed")
    def test_no_active_stack_links_the_lane(self):
        layers = ROOT / "all/.local/bin/dotcortex-layers"
        for host in ("beelink", "x230", "t480s", "t480", "kikin-kushi"):
            pkgs = subprocess.run([str(layers), "resolve", "--host", host, "--user", "metsatron"],
                                  capture_output=True, text=True, check=True).stdout.split()
            with tempfile.TemporaryDirectory() as target:
                out = subprocess.run(["stow", "-n", "-v", f"--target={target}", "--ignore=\\.bak\\.", *pkgs],
                                     cwd=ROOT, capture_output=True, text=True)
            planned = out.stdout + out.stderr
            self.assertNotIn("All operations aborted", planned, host)
            links = {}  # replay the plan: stow reverts a fold with UNLINK when it must unfold
            for line in planned.splitlines():
                if m := re.match(r"UNLINK: (\S+)", line):
                    links.pop(m.group(1), None)
                elif m := re.match(r"LINK: (\S+) => (\S+)", line):
                    links[m.group(1)] = m.group(2)
            for rel, dest in links.items():
                self.assertNotIn("/dotcortex/honey-claude", dest, (host, rel))
                self.assertNotIn(rel, (".local", ".local/share", ".local/share/dotcortex"),
                                 (host, "a folded parent would expose the lane", dest))

    def test_boundary_law_names_the_vault_and_no_addresses(self):
        text = "".join((SHARE / f"CLAUDE.{bot}.md").read_text() for bot in BOTS)
        self.assertIn("Secret Vault", text)
        self.assertIsNone(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text))


class SparseTests(unittest.TestCase):
    """The sparse system checkout carries everything the lane runs from DotCortex."""

    PROSE_WORDS = {"agent", "launch"}  # all/.local/bin names that occur here only as English

    def patterns(self):
        return [l.strip() for l in (SHARE / "SPARSE").read_text().splitlines() if l.strip()]

    def covered(self, rel):
        for pat in self.patterns():
            pat = pat.lstrip("/")
            if rel == pat.rstrip("/") or (pat.endswith("/") and rel.startswith(pat)):
                return True
        return False

    def carried_files(self):
        files = [p for p in SHARE.rglob("*") if p.is_file()]
        for pat in self.patterns():
            path = ROOT / pat.strip("/")
            if path.is_file():
                files.append(path)
        return files

    def test_every_pattern_exists(self):
        for pat in self.patterns():
            self.assertTrue(pat.startswith("/"), pat)
            self.assertTrue((ROOT / pat.strip("/")).exists(), pat)
        self.assertIn("/all/.local/share/dotcortex/honey-claude/", self.patterns())

    def test_no_fleet_command_outside_the_sparse_set(self):
        fleet = {p.name for p in (ROOT / "all/.local/bin").iterdir()}
        for path in self.carried_files():
            tokens = set(re.findall(r"[A-Za-z0-9][A-Za-z0-9._+-]*", path.read_text(errors="replace")))
            for name in sorted((tokens & fleet) - self.PROSE_WORDS):
                self.assertTrue(self.covered(f"all/.local/bin/{name}"),
                                f"{path.relative_to(ROOT)} names all/.local/bin/{name}, which SPARSE does not carry")

    def test_no_repo_path_outside_the_sparse_set(self):
        for path in self.carried_files():
            for ref in re.findall(r"\ball/\.local/[A-Za-z0-9._/-]+", path.read_text(errors="replace")):
                ref = ref.rstrip("/.")
                if (ROOT / ref).is_dir():
                    ok = any(p.lstrip("/").startswith(ref + "/") for p in self.patterns()) or self.covered(ref + "/")
                else:
                    ok = self.covered(ref)
                self.assertTrue(ok, f"{path.relative_to(ROOT)} names {ref}, which SPARSE does not carry")

    def test_launcher_fleet_bin_is_the_sparse_bin(self):
        text = (SHARE / "lib/launch.bash").read_text()
        rel = re.search(r'repo_bin="\$\(cd -- "\$LIB_DIR/([./]+bin)"', text).group(1)
        self.assertEqual((SHARE / "lib" / rel).resolve(), (ROOT / "all/.local/bin").resolve())

    def test_settings_hooks_resolve_inside_the_set(self):
        settings = json.loads((SHARE / "claude-settings.json").read_text())
        for groups in settings["hooks"].values():
            for group in groups:
                for hook in group["hooks"]:
                    name = hook["command"].split()[0]
                    self.assertTrue((BIN / name).is_file() or self.covered(f"all/.local/bin/{name}"), name)

    def test_settings_carry_the_telegram_delivery_guard(self):
        # The bots are unstowed: --settings is their only hook source, so the guard must live here.
        settings = json.loads((SHARE / "claude-settings.json").read_text())
        stop = [h["command"] for g in settings["hooks"].get("Stop", []) for h in g["hooks"]]
        self.assertIn("claude-hook-telegram-delivery-guard", stop)

    def test_settings_register_the_idle_hook_wherever_the_fleet_does(self):
        # 2026-09-30: the lane shipped without it and no bot ever compacted.  The bots are
        # unstowed, so the fleet's ~/.claude/settings.json never reaches them: mirror it here.
        # The fleet's settings are a gitignored tangle output: read their org source block.
        org = (ROOT / "agents-hooks.org").read_text()
        block = re.search(r"#\+BEGIN_SRC json :tangle all/\.claude/settings\.shared\.json[^\n]*\n(.*?)\n#\+END_SRC",
                          org, re.S)
        fleet = json.loads(block.group(1))
        lane = json.loads((SHARE / "claude-settings.json").read_text())

        def idle_matchers(settings, event):
            return {g.get("matcher") for g in settings["hooks"].get(event, [])
                    if any(h["command"].split()[0] == "claude-hook-idle-event" for h in g["hooks"])}

        events = [e for e in fleet["hooks"] if idle_matchers(fleet, e)]
        self.assertTrue({"SessionStart", "Stop", "PostCompact"} <= set(events), events)
        for event in events:
            lane_matchers = idle_matchers(lane, event)
            if None in lane_matchers:
                continue  # an unmatched group sees every occurrence of the event
            self.assertTrue(idle_matchers(fleet, event) <= lane_matchers,
                            f"{event}: the lane does not register claude-hook-idle-event where the fleet does")

    def test_settings_enable_the_telegram_plugin(self):
        # The preflight reads this file, not the agent account's ~/.claude/settings.json.
        settings = json.loads((SHARE / "claude-settings.json").read_text())
        self.assertIs(settings["enabledPlugins"]["telegram@claude-plugins-official"], True)
        self.assertEqual(settings["extraKnownMarketplaces"]["claude-plugins-official"]["source"],
                         {"source": "github", "repo": "anthropics/claude-plugins-official"})

    def test_sync_dry_run_is_sparse_blobless_and_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "DotCortex"
            out = subprocess.run([str(OPENRC / "honey-claude-install"), "--dry-run", "sync"], capture_output=True,
                                 text=True, env=dict(os.environ, HONEY_CLAUDE_CHECKOUT=str(dest)))
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("--filter=blob:none --no-checkout", out.stdout)
            self.assertIn("sparse-checkout init --no-cone", out.stdout)
            self.assertIn("config index.version 4", out.stdout)
            for pat in self.patterns():
                self.assertIn(pat, out.stdout)
            self.assertFalse(dest.exists())
            self.assertEqual(os.listdir(tmp), [])


if __name__ == "__main__":
    unittest.main()
