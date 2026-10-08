from __future__ import annotations

import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time
import unittest


HERE = Path(__file__).resolve()
MANAGER = HERE.parents[3] / "bin" / "telegram-agent-host"
HOST = subprocess.check_output(["hostname"], text=True).strip().lower()


class TelegramAgentHostColdStartTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.state = self.root / "state"
        self.agents = self.root / "agents"
        self.bin = self.home / ".local/bin"
        self.forge_bin = self.home / "HelmCortex/FORGE/bin"
        self.core_bin = self.home / ".guix-extra-profiles/core/core/bin"
        for directory in (self.home, self.state, self.agents, self.bin, self.forge_bin, self.core_bin):
            directory.mkdir(parents=True)
        self.write_executable("ductor", "#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n")
        self.write_executable("node", "#!/bin/sh\nexit 0\n", directory=self.core_bin)

    def tearDown(self) -> None:
        for pid_file in (
            self.state / "telegram-agents/ductor-supervise.pid",
            self.state / "telegram-agents/codex-helmastra-telegram.pid",
            self.state / "gemma-pi-telegram/adapter.pid",
        ):
            if pid_file.exists():
                try:
                    os.killpg(int(pid_file.read_text()), signal.SIGTERM)
                except (ProcessLookupError, PermissionError, ValueError):
                    pass
        self.temp.cleanup()

    def read_start_ticks(self, pid: int) -> str:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
        return fields[19]

    def write_dsh_marker(
        self,
        pid: int,
        *,
        start_ticks: str | None = None,
        profile: str = "helmcortex-telegram",
        generation: str = "0123456789abcdef0123456789abcdef",
        expected_generation: str | None = None,
    ) -> None:
        marker_base = self.state / "telegram-agents/deepseek-harness.ready"
        marker = marker_base.with_name(f"{marker_base.name}.{generation}")
        marker.parent.mkdir(parents=True, exist_ok=True)
        (marker.parent / "deepseek-harness.generation").write_text(
            expected_generation if expected_generation is not None else generation,
            encoding="utf-8",
        )
        marker.write_text(json.dumps({
            "schema": 1,
            "component": "dsh-telegram",
            "pid": pid,
            "start_ticks": start_ticks if start_ticks is not None else self.read_start_ticks(pid),
            "profile": profile,
            "generation": generation,
            "provider": "helmcortex-opencode-go",
            "model": "deepseek-v4.1-flash",
            "telegram_bot_identity_validated": True,
            "long_polling_owned": True,
            "ready_at": "2026-09-17T00:00:00Z",
        }), encoding="utf-8")

    def write_executable(self, name: str, body: str, directory: Path | None = None) -> None:
        path = (directory or self.bin) / name
        path.write_text(body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def environment(self, timeout: int) -> dict[str, str]:
        env = {
            "HOME": str(self.home),
            "XDG_STATE_HOME": str(self.state),
            "DOTCORTEX_AGENTS_DIR": str(self.agents),
            "PATH": str(self.bin) + os.pathsep + "/usr/local/bin:/usr/bin:/bin",
            "DUCTOR_HOME_DIR": str(self.root / "ductor-home"),
            "DUCTOR_READY_TIMEOUT": str(timeout),
            "DSH_TELEGRAM_ENV_FILE": str(self.home / ".config/deepseek-harness-telegram/env"),
            "DSH_HOME": str(self.home / ".local/share/deepseek-harness-telegram/dsh-home"),
        }
        return env

    def run_manager(self, *args: str, timeout: int = 10) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(MANAGER), *args], text=True, capture_output=True,
                              env=self.environment(timeout), timeout=timeout + 5)

    def prepare_codex_supervisor(self, stop_delay: float = 1.5) -> subprocess.Popen[bytes]:
        scripts = self.home / "HelmCortex/FORGE/scripts"
        scripts.mkdir(parents=True)
        adapter = scripts / "codex_telegram.py"
        adapter.write_text(
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, lambda *_: exit(0))\n"
            "while True: time.sleep(1)\n",
            encoding="utf-8",
        )
        supervisor = scripts / "codex_supervisor.py"
        supervisor.write_text(
            "import fcntl, os, pathlib, signal, subprocess, sys, time\n"
            "state = pathlib.Path(os.environ['XDG_STATE_HOME']) / 'telegram-agents'\n"
            "state.mkdir(parents=True, exist_ok=True)\n"
            "pid_file = state / 'codex-helmastra-telegram.pid'\n"
            "ready_file = state / 'codex-helmastra-telegram.ready'\n"
            "child_file = state / 'codex-helmastra-telegram.child.ready'\n"
            "lock = (state / 'codex-helmastra-telegram.supervisor.lock').open('a+')\n"
            "fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "child = subprocess.Popen([sys.executable, str(pathlib.Path(__file__).with_name('codex_telegram.py'))])\n"
            "pid_file.write_text(str(os.getpid()) + '\\n')\n"
            "ready_file.write_text(str(os.getpid()) + '\\n')\n"
            "child_file.write_text(str(child.pid) + '\\n')\n"
            "def stop(*_):\n"
            "    ready_file.unlink(missing_ok=True)\n"
            "    child_file.unlink(missing_ok=True)\n"
            "    child.terminate()\n"
            "    time.sleep(float(os.environ.get('CODEX_TEST_STOP_DELAY', '0.1')))\n"
            "    raise SystemExit(0)\n"
            "signal.signal(signal.SIGTERM, stop)\n"
            "while child.poll() is None: time.sleep(0.1)\n",
            encoding="utf-8",
        )
        wrapper = self.forge_bin / "codex-helmastra"
        wrapper.write_text(
            "#!/usr/bin/env python3\n"
            "import fcntl, os, pathlib, subprocess, sys, time\n"
            "state = pathlib.Path(os.environ['XDG_STATE_HOME']) / 'telegram-agents'\n"
            "lock_path = state / 'codex-helmastra-telegram.supervisor.lock'\n"
            "with lock_path.open('a+') as lock:\n"
            "    try: fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "    except BlockingIOError:\n"
            "        print('supervisor lock is still held', file=sys.stderr)\n"
            "        raise SystemExit(73)\n"
            f"supervisor = {str(supervisor)!r}\n"
            "process = subprocess.Popen([sys.executable, supervisor], stdin=subprocess.DEVNULL, "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)\n"
            "pid_file = state / 'codex-helmastra-telegram.pid'\n"
            "ready_file = state / 'codex-helmastra-telegram.ready'\n"
            "child_file = state / 'codex-helmastra-telegram.child.ready'\n"
            "for _ in range(100):\n"
            "    if (pid_file.exists() and ready_file.exists() and child_file.exists() "
            "and pid_file.read_text().strip() == str(process.pid) "
            "and ready_file.read_text().strip() == str(process.pid)):\n"
            "        raise SystemExit(0)\n"
            "    if process.poll() is not None: break\n"
            "    time.sleep(0.02)\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        env = self.environment(2)
        env["CODEX_TEST_STOP_DELAY"] = str(stop_delay)
        process = subprocess.Popen(
            ["python3", str(supervisor)], env=env, start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        ready_file = self.state / "telegram-agents/codex-helmastra-telegram.ready"
        child_file = self.state / "telegram-agents/codex-helmastra-telegram.child.ready"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not (ready_file.exists() and child_file.exists()):
            time.sleep(0.02)
        self.assertTrue(ready_file.exists() and child_file.exists(), "fixture supervisor did not become ready")
        return process

    def test_codex_stop_waits_for_supervisor_after_readiness_disappears(self) -> None:
        old_supervisor = self.prepare_codex_supervisor()
        try:
            stopped = self.run_manager("stop", "codex", timeout=4)
            self.assertEqual(stopped.returncode, 0, stopped.stderr)

            # The supervisor removes readiness immediately on TERM but deliberately
            # retains its exclusive launch lock while winding down. A correct stop
            # must wait for that exact process, so an immediate start can acquire it.
            started = self.run_manager("start", "codex", timeout=4)
            self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
            old_supervisor.wait(timeout=2)
            replacement = int(
                (self.state / "telegram-agents/codex-helmastra-telegram.pid").read_text()
            )
            self.assertNotEqual(replacement, old_supervisor.pid)
        finally:
            if old_supervisor.poll() is None:
                os.killpg(old_supervisor.pid, signal.SIGKILL)
                old_supervisor.wait(timeout=5)

    def test_cold_supervisor_waits_for_delayed_child(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|ductor\n", encoding="utf-8")
        self.write_executable(
            "ductor-supervise",
            "#!/bin/sh\n"
            "d=$XDG_STATE_HOME/telegram-agents\nmkdir -p \"$d\"\n"
            "printf '%s\\n' $$ >\"$d/ductor-supervise.pid\"\n"
            "sleep 2\nductor & child=$!\nprintf '%s\\n' $child >\"$d/ductor-child.pid\"\nwait $child\n",
            directory=self.forge_bin,
        )
        result = self.run_manager("start", "ductor", timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ductor started", result.stdout)

    def test_start_all_attempts_later_agent_after_ductor_failure(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|ductor,pi-agent\n", encoding="utf-8")
        gemma_env = self.home / ".config/gemma-pi-telegram/.env"
        gemma_env.parent.mkdir(parents=True)
        gemma_env.write_text("TELEGRAM_BOT_TOKEN=fake\nTELEGRAM_ALLOWED_USER_ID=1\n", encoding="utf-8")
        gemma_env.chmod(0o600)
        fake_adapter = self.home / "gemma_telegram.py"
        fake_adapter.write_text("import time\nwhile True: time.sleep(1)\n", encoding="utf-8")
        self.write_executable(
            "gemma-pi-telegram",
            f"#!/bin/sh\n"
            "d=$XDG_STATE_HOME/gemma-pi-telegram\nmkdir -p \"$d\"\n"
            "printf '%s\\n' $$ >\"$d/adapter.pid\"\n"
            f"exec python3 {str(fake_adapter)!r}\n",
            directory=self.forge_bin,
        )
        self.write_executable(
            "ductor-supervise",
            "#!/bin/sh\n"
            "d=$XDG_STATE_HOME/telegram-agents\nmkdir -p \"$d\"\n"
            "printf '%s\\n' $$ >\"$d/ductor-supervise.pid\"\n"
            "trap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n",
            directory=self.forge_bin,
        )
        result = self.run_manager("start", timeout=1)
        self.assertEqual(result.returncode, 1)
        self.assertIn("pi-agent started", result.stdout)
        self.assertIn("Failed to start enabled agent: ductor", result.stderr)

    def test_targeted_pi_agent_status_is_parseable_without_other_agents(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|pi-agent\n", encoding="utf-8")
        gemma_env = self.home / ".config/gemma-pi-telegram/.env"
        gemma_env.parent.mkdir(parents=True)
        gemma_env.write_text("TELEGRAM_BOT_TOKEN=fake\nTELEGRAM_ALLOWED_USER_ID=1\n", encoding="utf-8")
        gemma_env.chmod(0o600)
        fake_adapter = self.home / "gemma_telegram.py"
        fake_adapter.write_text("import time\nwhile True: time.sleep(1)\n", encoding="utf-8")
        self.write_executable(
            "gemma-pi-telegram",
            f"#!/bin/sh\n"
            "d=$XDG_STATE_HOME/gemma-pi-telegram\nmkdir -p \"$d\"\n"
            "printf '%s\\n' $$ >\"$d/adapter.pid\"\n"
            f"exec python3 {str(fake_adapter)!r}\n",
            directory=self.forge_bin,
        )

        started = self.run_manager("start", "pi-agent", timeout=2)
        self.assertEqual(started.returncode, 0, started.stderr)
        status = self.run_manager("status", "pi-agent", timeout=2)

        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertRegex(status.stdout, r"^pi-agent: RUNNING pid=\d+ \(gemma-pi-telegram\)\n$")
        self.assertNotIn("opencode", status.stdout)

    def prepare_nanobot_wrapper(self, *, emit_ready: bool = True, stale_ready: bool = False) -> None:
        workspace = self.home / "HelmCortex/FORGE/brain/nanobot"
        workspace.mkdir(parents=True)
        config_dir = self.home / ".config/nanobot-telegram"
        config_dir.mkdir(parents=True)
        config_dir.joinpath("config.json").write_text("{}\n", encoding="utf-8")
        config_dir.joinpath("env").write_text(
            "TELEGRAM_BOT_TOKEN=123456789:abcdefghijklmnopqrstuvwxyzABCDE\n",
            encoding="utf-8",
        )
        log_file = config_dir / "gateway.log"
        if stale_ready:
            log_file.write_text(
                "telegram | bot @helmcortex_nano_bot connected\n", encoding="utf-8"
            )
        running = config_dir / "running"
        ready_command = (
            "printf '%s\\n' 'telegram | bot @helmcortex_nano_bot connected' >>\"$log\""
            if emit_ready else ":"
        )
        self.write_executable(
            "nanobot-telegram",
            "#!/bin/sh\n"
            f"running={str(running)!r}\n"
            f"log={str(log_file)!r}\n"
            "case \"$1:$2\" in\n"
            "  gateway:status)\n"
            "    if [ -f \"$running\" ]; then printf 'Running: yes\\nPID: 4242\\n'; else printf 'Running: no\\n'; fi\n"
            # Nanobot's rich renderer wraps long paths beneath the label in a
            # narrow terminal; reproduce that real output shape here.
            "    printf 'Logs:\\n%s\\n' \"$log\"\n"
            "    ;;\n"
            "  gateway:--background)\n"
            "    : >\"$running\"\n"
            f"    {ready_command}\n"
            "    ;;\n"
            "  gateway:stop) rm -f \"$running\" ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
        )

    def test_nanobot_targeted_lifecycle_uses_scoped_wrapper(self) -> None:
        self.prepare_nanobot_wrapper()
        started = self.run_manager("start", "nanobot", timeout=2)
        self.assertEqual(started.returncode, 0, started.stderr)
        self.assertIn("connected as @helmcortex_nano_bot", started.stdout)

        status = self.run_manager("status", "nanobot", timeout=2)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(
            status.stdout,
            "nanobot: RUNNING pid=4242 (@helmcortex_nano_bot)\n",
        )

        stopped = self.run_manager("stop", "nanobot", timeout=2)
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        status = self.run_manager("status", "nanobot", timeout=2)
        self.assertEqual(status.returncode, 1)
        self.assertIn("nanobot: STOPPED", status.stdout)

    def start_gateway_stand_in(self, *, ticks: str | None = None, record: bool = True) -> subprocess.Popen[bytes]:
        gateway = subprocess.Popen(["sleep", "60"])
        self.addCleanup(lambda: (gateway.poll() is None and gateway.kill(), gateway.wait()))
        if record:
            hermes_home = self.home / ".hermes"
            hermes_home.mkdir(exist_ok=True)
            (hermes_home / "gateway.pid").write_text(json.dumps({
                "pid": gateway.pid,
                "kind": "hermes-gateway",
                "argv": ["hermes_cli/main.py", "gateway", "run"],
                "start_time": ticks if ticks is not None else self.read_start_ticks(gateway.pid),
            }), encoding="utf-8")
        return gateway

    def start_process_named_hermes(self) -> subprocess.Popen[bytes]:
        impostor = self.bin / "hermes"
        impostor.write_bytes(Path("/bin/sleep").read_bytes())
        impostor.chmod(0o755)
        process = subprocess.Popen([str(impostor), "60"])
        self.addCleanup(lambda: (process.poll() is None and process.kill(), process.wait()))
        return process

    def hermes_status_line(self) -> str:
        result = self.run_manager("status", timeout=20)
        return next(line for line in result.stdout.splitlines() if "hermes gateway run" in line)

    def test_hermes_status_trusts_the_gateway_pid_record(self) -> None:
        self.start_gateway_stand_in()
        self.assertEqual(self.hermes_status_line().strip(), "hermes gateway run: RUNNING")

    def test_hermes_status_rejects_a_recycled_pid(self) -> None:
        self.start_gateway_stand_in(ticks="1")
        self.assertEqual(self.hermes_status_line().strip(), "hermes gateway run: STOPPED")

    def test_hermes_status_ignores_other_processes_named_hermes(self) -> None:
        self.start_process_named_hermes()
        self.assertEqual(self.hermes_status_line().strip(), "hermes gateway run: STOPPED")

    def test_hermes_stop_signals_only_the_recorded_gateway(self) -> None:
        gateway = self.start_gateway_stand_in()
        session = self.start_process_named_hermes()
        stopped = self.run_manager("stop", "hermes", timeout=20)
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        gateway.wait(timeout=5)
        self.assertIsNone(session.poll(), "an interactive hermes process must survive a gateway stop")

    def test_nanobot_wrapper_imports_only_allowlisted_env_keys(self) -> None:
        workspace = self.home / "HelmCortex/FORGE/brain/nanobot"
        venv_bin = workspace / ".venv/bin"
        venv_bin.mkdir(parents=True)
        config_dir = self.home / ".config/nanobot-telegram"
        config_dir.mkdir(parents=True)
        (config_dir / "config.json").write_text("{}\n", encoding="utf-8")
        expected = {
            "NANOBOT_RECALL_MCP_URL": "synthetic recall URL",
            "NANOBOT_TOOLS__SSRF_WHITELIST": json.dumps(["synthetic SSRF marker"]),
            "NANOBOT_GATEWAY__HOST": "synthetic host value",
            "NANOBOT_GATEWAY__PORT": str(len("synthetic port value")),
        }
        probe = venv_bin / "nanobot"
        probe.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os\n"
            "print(json.dumps({key: value for key, value in os.environ.items() "
            "if key.startswith('NANOBOT_') and key in "
            + repr([*expected, "NANOBOT_UNLISTED"]) + "}))\n",
            encoding="utf-8",
        )
        probe.chmod(0o755)
        (config_dir / "env").write_text(
            "".join(f"{key}={value}\n" for key, value in expected.items())
            + "NANOBOT_UNLISTED=synthetic unlisted value\n",
            encoding="utf-8",
        )
        wrapper = HERE.parents[3] / "bin/nanobot-telegram"
        result = subprocess.run(
            [str(wrapper), "--help"],
            env={"PATH": os.environ["PATH"], "HOME": str(self.home)},
            text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), expected)

    def test_managed_nanobot_template_holds_no_network_addresses(self) -> None:
        templates = HERE.parents[4] / ".bots/templates"
        def strict_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result
        def invalid_constant(value):
            raise ValueError("nonfinite JSON constant")
        config = json.loads(
            (templates / "nanobot-config.json").read_text(encoding="utf-8"),
            object_pairs_hook=strict_pairs, parse_constant=invalid_constant,
        )
        self.assertNotIn("ssrfWhitelist", config["tools"])
        self.assertNotIn("host", config["gateway"])
        self.assertNotIn("port", config["gateway"])
        self.assertEqual(config["tools"]["mcpServers"]["recall"]["url"],
                         "${NANOBOT_RECALL_MCP_URL}")
        env_lines = (templates / "nanobot-telegram.env").read_text(encoding="utf-8").splitlines()
        for key in ("NANOBOT_RECALL_MCP_URL", "NANOBOT_TOOLS__SSRF_WHITELIST",
                    "NANOBOT_GATEWAY__HOST", "NANOBOT_GATEWAY__PORT"):
            self.assertIn(f"# {key}=", env_lines)
            self.assertFalse(any(line.startswith(key + "=") for line in env_lines))

    def test_nanobot_refuses_unprovisioned_token(self) -> None:
        self.prepare_nanobot_wrapper()
        (self.home / ".config/nanobot-telegram/env").write_text(
            "# TELEGRAM_BOT_TOKEN=\n", encoding="utf-8"
        )
        result = self.run_manager("start", "nanobot", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("TELEGRAM_BOT_TOKEN is not provisioned", result.stderr)

    def test_nanobot_rejects_stale_readiness_from_an_earlier_launch(self) -> None:
        self.prepare_nanobot_wrapper(emit_ready=False, stale_ready=True)
        self.write_executable("sleep", "#!/bin/sh\nexit 0\n")
        result = self.run_manager("start", "nanobot", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("failed Telegram readiness", result.stderr)
        self.assertFalse((self.home / ".config/nanobot-telegram/running").exists())

    def test_nanobot_run_as_missing_user_refuses(self) -> None:
        self.prepare_nanobot_wrapper()
        run_as = self.home / ".config/nanobot-telegram/run-as"
        run_as.write_text("agent-does-not-exist-2999\n", encoding="utf-8")
        result = self.run_manager("start", "nanobot", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("nanobot run-as user is missing", result.stderr)

    def test_nanobot_run_as_self_runs_locally(self) -> None:
        import getpass
        self.prepare_nanobot_wrapper()
        run_as = self.home / ".config/nanobot-telegram/run-as"
        run_as.write_text(getpass.getuser() + "\n", encoding="utf-8")
        result = self.run_manager("status", "nanobot", timeout=2)
        self.assertIn("nanobot: STOPPED", result.stdout)
        self.assertNotIn("run-as user is missing", result.stderr)

    def test_sanitized_boot_binds_core_node_before_opencode_preflight(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|opencode\n", encoding="utf-8")
        marker = self.root / "resolved-node"
        self.write_executable(
            "opencode-telegram-patch-apply",
            f"#!/bin/sh\ncommand -v node > {str(marker)!r}\nexit 23\n",
            directory=self.forge_bin,
        )
        result = self.run_manager("start", "opencode", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(marker.read_text().strip(), str(self.core_bin / "node"))

    def prepare_deepseek_harness(self, allowed_chat_ids: list[int]) -> None:
        plugin = self.home / "HelmCortex/NEXUS/git/dsh-telegram"
        plugin.mkdir(parents=True)
        plugin.joinpath("package.json").write_text(json.dumps({"name": "dsh-telegram"}), encoding="utf-8")
        plugin.joinpath("package-lock.json").write_text("{}", encoding="utf-8")
        plugin.joinpath("cordis.patch.yml").write_text(
            "- insert:\n    - id: dsh-telegram\n      name: dsh-telegram\n",
            encoding="utf-8",
        )
        plugin.joinpath("dist").mkdir()
        plugin.joinpath("dist/index.js").write_text("", encoding="utf-8")
        workspace = self.home / ".local/share/deepseek-harness-telegram/workspace"
        workspace.joinpath(".pi").mkdir(parents=True)
        workspace.joinpath(".pi/telegram.json").write_text(
            json.dumps(
                {
                    "security": {"allowedChatIds": allowed_chat_ids},
                    "model": {
                        "provider": "helmcortex-opencode-go",
                        "model": "deepseek-v4.1-flash",
                    },
                }
            ),
            encoding="utf-8",
        )
        token = self.home / ".config/deepseek-harness-telegram/token"
        token.parent.mkdir(parents=True)
        token.write_text("fake-token\n", encoding="utf-8")
        token.chmod(0o600)
        key = self.home / ".config/helmcortex/opencode-go.key"
        key.parent.mkdir(parents=True)
        key.write_text("fake-key\n", encoding="utf-8")
        key.chmod(0o600)
        settings_text = "\n".join(
            [
                "llm-pi-ai:",
                "  providers:",
                "    helmcortex-opencode-go:",
                "      displayName: HelmCortex OpenCode Go",
                "      apiKeyEnv: OPENCODE_GO_API_KEY",
                "      api: openai-completions",
                "      baseURL: https://opencode.ai/zen/go/v1",
                "      models:",
                "        - id: deepseek-v4.1-flash",
                "          contextWindow: 1048576",
                "          compat:",
                "            thinkingFormat: deepseek",
                "",
            ]
        )
        dsh_home = self.home / ".local/share/deepseek-harness-telegram/dsh-home"
        dsh_home.mkdir(parents=True)
        dsh_home.joinpath("settings.yaml").write_text(settings_text, encoding="utf-8")
        templates = self.agents / "templates"
        templates.mkdir()
        templates.joinpath("deepseek-harness-settings.yaml").write_text(settings_text, encoding="utf-8")
        profile_patch_text = "\n".join(
            [
                "- id: agent-default-model",
                "  config:",
                "    provider: helmcortex-opencode-go",
                "    model: deepseek-v4.1-flash",
                "",
                "- id: llm-deepseek",
                "  disabled: true",
                "",
                "- id: web-search-deepseek",
                "  disabled: true",
                "",
                "- id: tool-web",
                "  disabled: true",
                "",
            ]
        )
        templates.joinpath("deepseek-harness-cordis.patch.yml").write_text(
            profile_patch_text, encoding="utf-8"
        )
        profile_dir = dsh_home / "profiles/helmcortex-telegram"
        profile_dir.mkdir(parents=True)
        profile_dir.joinpath("cordis.patch.yml").write_text(profile_patch_text, encoding="utf-8")
        env_file = self.home / ".config/deepseek-harness-telegram/env"
        env_file.write_text(
            "\n".join(
                [
                    f"TELEGRAM_BOT_TOKEN_FILE={token}",
                    f"OPENCODE_GO_API_KEY_FILE={key}",
                    f"DSH_HOME={self.home / '.local/share/deepseek-harness-telegram/dsh-home'}",
                    "DSH_TELEGRAM_PROFILE=helmcortex-telegram",
                    f"DSH_TELEGRAM_WORKSPACE={workspace}",
                    f"DSH_TELEGRAM_PLUGIN_ROOT={plugin}",
                    "DSH_TELEGRAM_MODEL_PROVIDER=helmcortex-opencode-go",
                    "DSH_TELEGRAM_MODEL=deepseek-v4.1-flash",
                    "DSH_TELEGRAM_PROVIDER_BASE_URL=https://opencode.ai/zen/go/v1",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        env_file.chmod(0o600)
        self.write_executable(
            "dsh",
            "#!/bin/sh\n"
            "if [ \"$1\" = plugin ] && [ \"$2\" = --profile ] && [ \"$4\" = list ]; then\n"
            f"  printf '%s\\n' 'link:{plugin}'\n"
            "  exit 0\n"
            "fi\n"
            "trap 'exit 0' TERM INT\n"
            "while :; do sleep 1; done\n",
        )

    def test_deepseek_harness_refuses_missing_private_env(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|deepseek-harness\n", encoding="utf-8")
        result = self.run_manager("start", "deepseek-harness", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("private env file is missing", result.stderr)

    def test_deepseek_harness_sync_refreshes_only_managed_profile_patch(self) -> None:
        self.prepare_deepseek_harness([123])
        template = self.agents / "templates/deepseek-harness-cordis.patch.yml"
        template.write_text(template.read_text(encoding="utf-8") + "# refreshed\n", encoding="utf-8")

        result = self.run_manager("sync", "deepseek-harness", timeout=2)

        self.assertEqual(result.returncode, 0, result.stderr)
        profile = (
            self.home
            / ".local/share/deepseek-harness-telegram/dsh-home/profiles/helmcortex-telegram/cordis.patch.yml"
        )
        self.assertEqual(profile.read_text(encoding="utf-8"), template.read_text(encoding="utf-8"))
        self.assertEqual(profile.stat().st_mode & 0o777, 0o600)

    def test_deepseek_harness_refuses_empty_allowlist(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|deepseek-harness\n", encoding="utf-8")
        self.prepare_deepseek_harness([])
        result = self.run_manager("start", "deepseek-harness", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("allowedChatIds is empty", result.stderr)

    def test_deepseek_harness_rejects_inline_telegram_token(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|deepseek-harness\n", encoding="utf-8")
        self.prepare_deepseek_harness([123])
        env_file = self.home / ".config/deepseek-harness-telegram/env"
        lines = [
            line for line in env_file.read_text(encoding="utf-8").splitlines()
            if not line.startswith("TELEGRAM_BOT_TOKEN_FILE=")
        ]
        lines.insert(0, "TELEGRAM_BOT_TOKEN=fake-inline-token")
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = self.run_manager("start", "deepseek-harness", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Telegram token file is missing", result.stderr)

    def test_deepseek_harness_status_rejects_pid_only_health(self) -> None:
        self.prepare_deepseek_harness([123])
        proc = subprocess.Popen(
            [str(self.bin / "dsh"), "--profile", "helmcortex-telegram"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.environment(2),
        )
        try:
            state_dir = self.state / "telegram-agents"
            state_dir.mkdir(parents=True)
            state_dir.joinpath("deepseek-harness.pid").write_text(str(proc.pid), encoding="utf-8")
            result = self.run_manager("status", "deepseek-harness", timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertIn("readiness owner state not verified", result.stdout)
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_deepseek_harness_status_rejects_stale_marker(self) -> None:
        self.prepare_deepseek_harness([123])
        proc = subprocess.Popen(
            [str(self.bin / "dsh"), "--profile", "helmcortex-telegram"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.environment(2),
        )
        try:
            state_dir = self.state / "telegram-agents"
            state_dir.mkdir(parents=True)
            state_dir.joinpath("deepseek-harness.pid").write_text(str(proc.pid), encoding="utf-8")
            self.write_dsh_marker(proc.pid, start_ticks="0")
            result = self.run_manager("status", "deepseek-harness", timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertIn("readiness owner state not verified", result.stdout)
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_deepseek_harness_status_rejects_wrong_launch_generation(self) -> None:
        self.prepare_deepseek_harness([123])
        proc = subprocess.Popen(
            [str(self.bin / "dsh"), "--profile", "helmcortex-telegram"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.environment(2),
        )
        try:
            state_dir = self.state / "telegram-agents"
            state_dir.mkdir(parents=True)
            state_dir.joinpath("deepseek-harness.pid").write_text(str(proc.pid), encoding="utf-8")
            self.write_dsh_marker(
                proc.pid,
                generation="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                expected_generation="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            result = self.run_manager("status", "deepseek-harness", timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertIn("readiness owner state not verified", result.stdout)
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_deepseek_harness_status_rejects_wrong_profile(self) -> None:
        self.prepare_deepseek_harness([123])
        proc = subprocess.Popen(
            [str(self.bin / "dsh"), "--profile", "helmcortex-telegram"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.environment(2),
        )
        try:
            state_dir = self.state / "telegram-agents"
            state_dir.mkdir(parents=True)
            state_dir.joinpath("deepseek-harness.pid").write_text(str(proc.pid), encoding="utf-8")
            self.write_dsh_marker(proc.pid, profile="other-profile")
            result = self.run_manager("status", "deepseek-harness", timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertIn("readiness owner state not verified", result.stdout)
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_deepseek_harness_status_rejects_child_that_exited_after_marker(self) -> None:
        self.prepare_deepseek_harness([123])
        generation = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        state_dir = self.state / "telegram-agents"
        state_dir.mkdir(parents=True)
        state_dir.joinpath("deepseek-harness.generation").write_text(generation, encoding="utf-8")
        marker = state_dir / f"deepseek-harness.ready.{generation}"
        self.write_executable(
            "dsh",
            "#!/bin/sh\n"
            "pid=$$\n"
            "ticks=$(python3 -c 'from pathlib import Path; import sys; s=Path(f\"/proc/{sys.argv[1]}/stat\").read_text(); print(s[s.rfind(\")\") + 2:].split()[19])' \"$pid\")\n"
            "python3 - \"$DSH_TELEGRAM_READY_MARKER\" \"$pid\" \"$ticks\" <<'PY'\n"
            "import json, sys\n"
            "from pathlib import Path\n"
            "Path(sys.argv[1]).write_text(json.dumps({'schema': 1, 'component': 'dsh-telegram', 'pid': int(sys.argv[2]), 'start_ticks': sys.argv[3], 'profile': 'helmcortex-telegram', 'provider': 'helmcortex-opencode-go', 'model': 'deepseek-v4.1-flash', 'telegram_bot_identity_validated': True, 'long_polling_owned': True}), encoding='utf-8')\n"
            "PY\n"
            "exit 0\n",
        )
        proc = subprocess.Popen(
            [str(self.bin / "dsh"), "--profile", "helmcortex-telegram"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**self.environment(2), "DSH_TELEGRAM_READY_MARKER": str(marker)},
        )
        proc.wait(timeout=5)
        state_dir.joinpath("deepseek-harness.pid").write_text(str(proc.pid), encoding="utf-8")
        result = self.run_manager("status", "deepseek-harness", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("readiness owner state not verified", result.stdout)

    def test_deepseek_harness_start_refuses_markerless_lookalike_process(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|deepseek-harness\n", encoding="utf-8")
        self.prepare_deepseek_harness([123])
        (self.home / ".local/share/deepseek-harness-telegram/dsh-home/profiles/helmcortex-telegram/package.json").write_text(
            json.dumps({"dependencies": {"dsh-telegram": f"link:{self.home / 'HelmCortex/NEXUS/git/dsh-telegram'}"}}), encoding="utf-8"
        )
        proc = subprocess.Popen(
            [str(self.bin / "dsh"), "--profile", "helmcortex-telegram"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.environment(2),
        )
        try:
            result = self.run_manager("start", "deepseek-harness", timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertIn("another dsh poller already uses profile", result.stderr)
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_deepseek_harness_second_starter_refuses_while_first_holds_lock(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|deepseek-harness\n", encoding="utf-8")
        self.prepare_deepseek_harness([123])
        lock_path = self.state / "telegram-agents/deepseek-harness.start.lock"
        holder = subprocess.Popen(
            [
                "python3",
                "-c",
                "import fcntl, pathlib, sys, time; p = pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True, exist_ok=True); f = p.open('w'); fcntl.flock(f, fcntl.LOCK_EX); time.sleep(5)",
                str(lock_path),
            ],
        )
        try:
            time.sleep(0.2)
            result = self.run_manager("start", "deepseek-harness", timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertIn("another DeepSeek Harness starter holds the launch lock", result.stderr)
        finally:
            holder.terminate()
            holder.wait(timeout=5)

    def test_deepseek_harness_status_accepts_matching_marker(self) -> None:
        self.prepare_deepseek_harness([123])
        proc = subprocess.Popen(
            [str(self.bin / "dsh"), "--profile", "helmcortex-telegram"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.environment(2),
        )
        try:
            state_dir = self.state / "telegram-agents"
            state_dir.mkdir(parents=True)
            state_dir.joinpath("deepseek-harness.pid").write_text(str(proc.pid), encoding="utf-8")
            self.write_dsh_marker(proc.pid)
            result = self.run_manager("status", "deepseek-harness", timeout=2)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("deepseek-harness: RUNNING", result.stdout)
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_deepseek_harness_stop_migrates_verified_legacy_pid_only_owner(self) -> None:
        self.prepare_deepseek_harness([123])
        proc = subprocess.Popen(
            [str(self.bin / "dsh"), "--profile", "helmcortex-telegram"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.environment(2),
        )
        state_dir = self.state / "telegram-agents"
        state_dir.mkdir(parents=True)
        state_dir.joinpath("deepseek-harness.pid").write_text(str(proc.pid), encoding="utf-8")
        result = self.run_manager("stop", "deepseek-harness", timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        proc.wait(timeout=5)
        self.assertFalse(state_dir.joinpath("deepseek-harness.pid").exists())

    def test_deepseek_harness_stop_clears_stale_state_without_a_matching_process(self) -> None:
        self.prepare_deepseek_harness([123])
        state_dir = self.state / "telegram-agents"
        state_dir.mkdir(parents=True)
        state_dir.joinpath("deepseek-harness.pid").write_text("99999999", encoding="utf-8")
        state_dir.joinpath("deepseek-harness.ready").write_text("{}", encoding="utf-8")
        env = self.environment(2)
        env["DSH_TELEGRAM_PROFILE"] = "stale-test-profile"
        result = subprocess.run(
            [str(MANAGER), "stop", "deepseek-harness"],
            text=True,
            capture_output=True,
            env=env,
            timeout=7,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(state_dir.joinpath("deepseek-harness.pid").exists())
        self.assertFalse(state_dir.joinpath("deepseek-harness.ready").exists())

    def test_deepseek_harness_start_retires_dead_owner_before_model_preflight(self) -> None:
        manager_text = MANAGER.read_text(encoding="utf-8")
        start = manager_text.index("        deepseek-harness)\n")
        clear_marker = manager_text.index(
            "deepseek_harness_clear_stale_marker ||", start
        )
        retire_owner = manager_text.index(
            "deepseek_harness_retire_stale_owner ||", clear_marker
        )
        model_preflight = manager_text.index(
            "deepseek_harness_preflight_model ||", retire_owner
        )
        self.assertLess(clear_marker, retire_owner)
        self.assertLess(retire_owner, model_preflight)
        retire_function = manager_text[
            manager_text.index("deepseek_harness_retire_stale_owner()"):
            manager_text.index("deepseek_harness_kill_owned()")
        ]
        self.assertIn("deepseek_harness_find_unowned", retire_function)
        self.assertIn("refusing cleanup", retire_function)
        self.assertIn('rm -f "$DSH_TELEGRAM_PID_FILE"', retire_function)

    def test_deepseek_harness_rejects_model_fallback_in_private_config(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|deepseek-harness\n", encoding="utf-8")
        self.prepare_deepseek_harness([123])
        config = self.home / ".local/share/deepseek-harness-telegram/workspace/.pi/telegram.json"
        data = json.loads(config.read_text(encoding="utf-8"))
        data["model"] = {"provider": "helmcortex-opencode-go", "model": "deepseek-v4-flash"}
        config.write_text(json.dumps(data), encoding="utf-8")
        result = self.run_manager("start", "deepseek-harness", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no fallback is permitted", result.stderr)

    def test_deepseek_harness_rejects_native_deepseek_credential_route(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|deepseek-harness\n", encoding="utf-8")
        self.prepare_deepseek_harness([123])
        profile_patch = (
            self.home
            / ".local/share/deepseek-harness-telegram/dsh-home/profiles/helmcortex-telegram/cordis.patch.yml"
        )
        profile_patch.write_text(
            "- id: agent-default-model\n"
            "  config:\n"
            "    provider: helmcortex-opencode-go\n"
            "    model: deepseek-v4.1-flash\n",
            encoding="utf-8",
        )
        result = self.run_manager("start", "deepseek-harness", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("refusing credential egress", result.stderr)

    def test_deepseek_harness_scrubs_ambient_deepseek_credentials(self) -> None:
        manager_text = MANAGER.read_text(encoding="utf-8")
        provider_scrub = "-u DEEPSEEK_API_KEY -u DEEPSEEK_API_KEY_FILE -u NEURALWATT_API_KEY -u OPENCODE_API_KEY -u OPENCODE_GO_API_KEY"
        self.assertGreaterEqual(manager_text.count(provider_scrub), 2)
        self.assertIn("env -u TELEGRAM_BOT_TOKEN " + provider_scrub, manager_text)
        self.assertNotIn('DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY"', manager_text)
        self.assertNotIn('OPENCODE_GO_API_KEY="$OPENCODE_GO_API_KEY"', manager_text)
        self.assertNotIn('TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN"', manager_text)

    def test_deepseek_harness_log_redactor_lives_in_detached_session(self) -> None:
        manager_text = MANAGER.read_text(encoding="utf-8")
        detached = manager_text.index('exec nohup setsid env -u TELEGRAM_BOT_TOKEN')
        detached_shell = manager_text.index("bash -c '", detached)
        redactor = manager_text.index("sed -u -E", detached_shell)
        launch = manager_text.index('exec dsh --profile "$DSH_TELEGRAM_PROFILE"', detached_shell)
        pid_publish = manager_text.index('printf \'%s\\n\' "$launched_pid" > "$DSH_TELEGRAM_PID_FILE"', launch)
        self.assertLess(detached_shell, launch)
        self.assertLess(launch, redactor)
        self.assertLess(redactor, pid_publish)
        self.assertIn('OPENCODE_GO_API_KEY_FILE="$OPENCODE_GO_API_KEY_FILE"', manager_text)

    def test_deepseek_harness_readiness_marker_contract_excludes_secrets_and_ids(self) -> None:
        manager_text = MANAGER.read_text(encoding="utf-8")
        self.assertIn('DSH_TELEGRAM_READY_MARKER=', manager_text)
        self.assertIn('DSH_TELEGRAM_GENERATION_FILE=', manager_text)
        self.assertIn('launch_generation', manager_text)
        self.assertIn('launch_marker="${DSH_TELEGRAM_READY_MARKER}.${launch_generation}"', manager_text)
        self.assertIn('data.get("generation") != sys.argv[5]', manager_text)
        self.assertIn('DSH_TELEGRAM_READY_TIMEOUT="${DSH_TELEGRAM_READY_TIMEOUT:-120}"', manager_text)
        self.assertIn('telegram_bot_identity_validated', manager_text)
        self.assertIn('long_polling_owned', manager_text)
        self.assertNotIn('TELEGRAM_BOT_TOKEN', manager_text[manager_text.index('deepseek_harness_marker_matches'):manager_text.index('deepseek_harness_wait_ready')])
        self.assertNotIn('chatId', manager_text[manager_text.index('deepseek_harness_marker_matches'):manager_text.index('deepseek_harness_wait_ready')])

    def test_deepseek_harness_uses_canonical_recall_endpoint(self) -> None:
        profile = HERE.parents[3] / "../.bots/templates/deepseek-harness-cordis.patch.yml"
        profile_text = profile.resolve().read_text(encoding="utf-8")
        self.assertIn("url: @DSH_RECALL_MCP_URL@", profile_text)
        # Rule 21: the public template never carries a tailnet or private address.
        self.assertIsNone(re.search(r"\b(100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])|10\.[0-9]{1,3}|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b", profile_text))

    def test_deepseek_harness_renders_recall_url_before_comparing(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|deepseek-harness\n", encoding="utf-8")
        self.prepare_deepseek_harness([123])
        template = self.agents / "templates/deepseek-harness-cordis.patch.yml"
        template.write_text(template.read_text(encoding="utf-8") + "url: @DSH_RECALL_MCP_URL@\n", encoding="utf-8")
        profile_patch = (
            self.home
            / ".local/share/deepseek-harness-telegram/dsh-home/profiles/helmcortex-telegram/cordis.patch.yml"
        )
        rendered = template.read_text(encoding="utf-8").replace("@DSH_RECALL_MCP_URL@", "http://recall.invalid:3004/mcp")
        profile_patch.write_text(rendered, encoding="utf-8")
        env_file = self.home / ".config/deepseek-harness-telegram/env"
        env_file.write_text(env_file.read_text(encoding="utf-8") + "DSH_RECALL_MCP_URL=http://recall.invalid:3004/mcp\n", encoding="utf-8")
        result = self.run_manager("start", "deepseek-harness", timeout=2)
        self.assertNotIn("refusing credential egress", result.stderr)
        self.assertNotIn("cannot resolve the Recall MCP URL", result.stderr)
        # A profile that keeps the unrendered placeholder is refused.
        profile_patch.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
        result = self.run_manager("start", "deepseek-harness", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("refusing credential egress", result.stderr)

    def test_deepseek_harness_run_as_missing_user_refuses(self) -> None:
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|deepseek-harness\n", encoding="utf-8")
        run_as = self.home / ".config/deepseek-harness-telegram/run-as"
        run_as.parent.mkdir(parents=True, exist_ok=True)
        run_as.write_text("agent-does-not-exist-2999\n", encoding="utf-8")
        result = self.run_manager("start", "deepseek-harness", timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("run-as user is missing", result.stderr)

    def test_deepseek_harness_run_as_self_runs_locally(self) -> None:
        import getpass
        self.agents.joinpath("hosts.conf").write_text(f"{HOST}|deepseek-harness\n", encoding="utf-8")
        run_as = self.home / ".config/deepseek-harness-telegram/run-as"
        run_as.parent.mkdir(parents=True, exist_ok=True)
        run_as.write_text(getpass.getuser() + "\n", encoding="utf-8")
        result = self.run_manager("status", "deepseek-harness", timeout=2)
        self.assertIn("deepseek-harness:", result.stdout)
        self.assertNotIn("run-as user is missing", result.stderr)

    def test_codex_managed_start_clears_inherited_runtime_policy(self) -> None:
        source = MANAGER.read_text(encoding="utf-8")
        codex_start = source.split("        codex)\n", 1)[1].split(
            "        deepseek-harness)", 1
        )[0]
        for name in (
            "CODEX_HELMASTRA_MODEL",
            "CODEX_TELEGRAM_MODEL",
            "CODEX_HELMASTRA_EFFORT",
            "CODEX_TELEGRAM_EFFORT",
            "CODEX_TELEGRAM_APPROVAL_POLICY",
            "CODEX_TELEGRAM_APPROVALS_REVIEWER",
        ):
            self.assertIn(f"-u {name}", codex_start)


if __name__ == "__main__":
    unittest.main()
