#!/usr/bin/env python3
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

REPO = Path(os.environ.get('APPROVAL_TEST_REPO') or Path(__file__).resolve().parents[5])
SPEC = importlib.util.spec_from_file_location('widen_engine', REPO / 'all/.local/lib/dotcortex/claude_approval_kikin.py')
e = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(e)


class DeciderWideningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='approval-widen.')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'DotCortex'
        self.root.mkdir()
        (self.root / 'README.org').write_text('synthetic\n')
        (self.root / 'notes.txt').write_text('synthetic\n')
        (self.root / 'CORE' / 'alpha').mkdir(parents=True)
        (self.root / 'CORE' / 'alpha' / 'probe.txt').write_text('synthetic\n')
        (self.root / 'FORGE' / 'bin').mkdir(parents=True)
        (self.root / 'FORGE' / 'bin' / 'agent-session').write_text('synthetic\n')
        self.scratch = self.base / 'scratch'
        self.scratch.mkdir()
        self.outside = self.base / 'outside'
        self.outside.mkdir()
        self.escape = self.scratch / 'escape'
        self.escape.symlink_to(self.outside, target_is_directory=True)
        self.manifest_path = self.base / 'manifest.json'
        self.ledger = self.base / 'ledger.jsonl'
        self.queue = self.base / 'queue.jsonl'
        self.manifest = json.loads((REPO / 'all/.config/dotcortex/claude-approval-canary.kikin.v1.json').read_text())
        self.manifest['roots'] = [str(self.root)]
        self.manifest['scratch_roots'] = [str(self.scratch)]
        self.manifest['gate_inversion'] = {'enabled': True, 'present_refusal': 'deny'}
        self.manifest['decider'].update(enabled=False)
        self.manifest['unattended'] = {'enabled': True, 'away_flag': str(self.base / 'away'), 'quiet_hours': {'enabled': False}}
        for item in self.manifest['classes']:
            item['enabled'] = False

    def event(self, command):
        return {'hook_event_name': 'PermissionRequest', 'tool_name': 'Bash',
                'tool_input': {'command': command}, 'cwd': str(self.root),
                'session_id': 'SYNTHETIC_SESSION'}

    def run_hook(self, command):
        self.manifest_path.write_text(json.dumps(self.manifest))
        env = {'SO_APPROVAL_KIKIN_MANIFEST': str(self.manifest_path),
               'SO_APPROVAL_KIKIN_LOG': str(self.ledger),
               'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
        out = io.StringIO()
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(e.sys, 'stdin', io.StringIO(json.dumps(self.event(command)))), \
                contextlib.redirect_stdout(out):
            self.assertEqual(e.main(), 0)
        if not out.getvalue().strip():
            return 'ask'
        return json.loads(out.getvalue())['hookSpecificOutput']['decision']['behavior']

    def test_segments_are_judged_independently(self):
        command = 'cat README.org && export PATH=~/.local/bin:$PATH && cat notes.txt'
        self.assertEqual(self.run_hook(command), 'allow')

    def test_scratch_redirect_is_inert_but_escape_is_not(self):
        self.assertEqual(self.run_hook(f'cat README.org > {self.scratch}/session.log && cat notes.txt'), 'allow')
        self.assertEqual(self.run_hook('cat README.org > /tmp/claude-1000/../../etc/x && cat notes.txt'), 'deny')
        self.assertEqual(self.run_hook(f'cat README.org > {self.escape}/session.log && cat notes.txt'), 'deny')

    def test_fleet_exports_are_data_and_other_exports_stay_floor(self):
        self.assertEqual(self.run_hook('export PATH=~/.npm-global/bin:~/.local/bin:$PATH && cat README.org'), 'allow')
        self.assertEqual(self.run_hook('export PATH=~/.guix-extra-profiles/core/core/bin:$PATH && cat README.org'), 'allow')
        self.assertEqual(self.run_hook('export PATH=HelmCortex/FORGE/bin:$PATH && cat README.org'), 'allow')
        self.assertEqual(self.run_hook('export PATH=/etc:$PATH && cat README.org'), 'deny')

    def test_read_only_loop_requires_every_body_segment_and_no_list_substitution(self):
        self.manifest['classes'][0]['enabled'] = True
        self.manifest['classes'][1]['enabled'] = True
        self.assertEqual(self.run_hook('for f in README.org notes.txt; do cat "$f" && head -1 "$f"; done'), 'allow')
        self.assertEqual(self.run_hook('for f in README.org notes.txt; do env -u CLAUDE_IDLE_CHANNEL timeout 5 cat "$f" | head -1; done'), 'allow')
        self.assertEqual(self.run_hook('for f in README.org; do kill -TERM 123; done'), 'deny')
        self.assertEqual(self.run_hook('for f in $(printf README.org); do cat "$f"; done'), 'deny')

    def test_replay_read_chains_keep_literal_assignments_and_wrappers(self):
        self.manifest['classes'][0]['enabled'] = True
        self.manifest['classes'][1]['enabled'] = True
        cases = [
            'cd ' + str(self.root) + ' && f=README.org; wc -l $f; grep -n "^#" $f | head -40',
            'cd ' + str(self.root) + ' && sed -n 1,2p README.org; grep -n -E synthetic README.org',
            'cd ' + str(self.root) + ' && env -u CLAUDE_IDLE_CHANNEL timeout 5 cat README.org 2>&1 | cut -c1-80 | tail -1',
        ]
        for command in cases:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'allow')

    def test_round_three_read_command_shapes(self):
        self.manifest['classes'][0]['enabled'] = True
        self.manifest['classes'][1]['enabled'] = True
        allowed = [
            'cd ' + str(self.root) + ' && grep -rIn -E synthetic CORE/*/ FORGE/bin',
            'mailcortex provision --help',
            'some-fleet-tool --version',
            'tmux ls', 'tmux has-session -t probe',
            'tmux capture-pane -p -t probe', 'tmux list-panes -t probe',
            'export XDG_RUNTIME_DIR=/run/user/1000 && cat README.org',
            'for i in $(seq 1 3); do ps -p "$i"; done',
        ]
        for command in allowed:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'allow')
        denied = [
            'tmux new-session -d probe',
            'tmux ls && kill -TERM 123',
            'export XDG_RUNTIME_DIR=/run/user/1000 && env -u X cat .env',
            'for i in $(seq 1 3); do kill -TERM "$i"; done',
            'for i in $(seq 1 3); do cat .env; done',
            'cd ' + str(self.root) + ' && grep -rIn . .ssh/',
        ]
        for command in denied:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'deny')
        escaped = self.root / 'CORE' / 'escape'
        escaped.symlink_to(self.outside, target_is_directory=True)
        self.assertEqual(self.run_hook('grep -rIn synthetic CORE/*/'), 'deny')

    def test_git_readers_name_protected_branch_but_writes_still_floor(self):
        self.manifest['classes'][1]['enabled'] = True
        (self.root / '.git').mkdir()
        allowed = [
            'git -C ' + str(self.root) + ' status',
            'git -C ' + str(self.root) + ' log master --oneline',
            'git -C ' + str(self.root) + ' diff master...topic',
            'git -C ' + str(self.root) + ' show master:README.org',
            'git -C ' + str(self.root) + ' merge-base --is-ancestor master topic',
        ]
        for command in allowed:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'allow')
        for command in [
            'git -C ' + str(self.root) + ' merge master',
            'git -C ' + str(self.root) + ' branch master',
            'git -C ' + str(self.root) + ' commit -m x -- README.org',
        ]:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'deny')

    def test_round_three_shapes_cannot_hide_the_absolute_floor(self):
        cases = [
            'cd ' + str(self.root) + ' && grep -rIn synthetic CORE/*/ && ssh -i ~/.ssh/id_ed25519 YOUR_HOST date',
            'some-fleet-tool --help && kill -TERM 123',
            'tmux ls && python3 -c "print(1)"',
            'export XDG_RUNTIME_DIR=/run/user/1000 && cat README.org && rm README.org',
            'for i in $(seq 1 3); do cat .env; done',
            'printf "%s" "$(cat README.org)" && git add README.org',
        ]
        for command in cases:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'deny')

    def test_read_substitutions_are_proven_and_effect_limited(self):
        self.manifest['classes'][0]['enabled'] = True
        self.manifest['classes'][1]['enabled'] = True
        (self.root / '.git').mkdir()
        allowed = [
            'printf "%s" "$(ps -o ppid= -p 1)"',
            'grep -n "$(cat README.org)" README.org',
            'printf "%s" "$(git -C ' + str(self.root) + ' rev-parse --show-toplevel)"',
            'printf "%s" "$(ss -H -ltn)"',
            'printf "%s" "$(pgrep -f claude)"',
            'printf "%s" "$(stat -c %s README.org)"',
            '[ "$(stat -c %s README.org)" = 0 ]',
        ]
        for command in allowed:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'allow')
        denied = [
            '$(cat README.org) README.org',
            'eval "$(cat README.org)"',
            'python3 -c "$(cat README.org)"',
            'printf x > "$(cat README.org)"',
        ]
        for command in denied:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'deny')

    def test_new_read_shapes_do_not_hide_absolute_floor_cases(self):
        cases = [
            'cd ' + str(self.root) + ' && f=README.org; cat .env; wc -l $f',
            'cd ' + str(self.root) + ' && cat README.org | kill -TERM 123',
            'cd ' + str(self.root) + ' && env -u CLAUDE_IDLE_CHANNEL timeout 5 ssh -i ~/.ssh/id_ed25519 YOUR_HOST date',
            'cat README.org > ' + str(self.scratch / 'safe') + ' <<EOF\nOPENROUTER_API_KEY=SYNTHETIC_VALUE_12345\nEOF',
            'grep "$(cat .env)" README.org',
            'cat README.org > ' + str(self.scratch / 'safe') + ' && python3 - <<EOF\nprint(1)\nEOF',
            'd=' + str(self.outside) + '; cat README.org > $d/out.txt',
        ]
        for command in cases:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'deny')

    def test_full_text_protected_credential_and_ssh_scans_survive_widening(self):
        cases = [
            'cat .env > ' + str(self.scratch / 'report'),
            'ssh -i ~/.ssh/id_ed25519 YOUR_HOST date > ' + str(self.scratch / 'report'),
            'cat README.org && kill -TERM 123',
            'export API_KEY=SYNTHETIC_VALUE_12345 > ' + str(self.scratch / 'report'),
            'for f in README.org; do cat .env; done',
            'cat README.org > ' + str(self.scratch / 'report') + ' <<EOF\nOPENROUTER_API_KEY=SYNTHETIC_VALUE_12345\nEOF',
        ]
        for command in cases:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'deny')

    def test_ambiguous_split_keeps_whole_command_redirect_floor(self):
        command = f'cat README.org && (cat notes.txt > {self.scratch}/x)'
        self.assertIsNone(e._split_approval_compound(command))
        self.assertEqual(self.run_hook(command), 'deny')

    def test_floor_rule_is_recorded_without_request_text(self):
        cases = [
            ('cat README.org && kill -TERM 123', 'kill'),
            ('cat .env > ' + str(self.scratch / 'report'), 'protected'),
            ('ssh -i ~/.ssh/id_ed25519 YOUR_HOST date', 'ssh-identity'),
            ('export API_KEY=SYNTHETIC_VALUE_12345 > ' + str(self.scratch / 'report'), 'credential'),
            ('git add README.org', 'git-write'),
            ('python3 -c "print(1)"', 'interpreter'),
        ]
        for command, rule in cases:
            with self.subTest(rule=rule):
                self.assertEqual(self.run_hook(command), 'deny')
                record = json.loads(self.ledger.read_text().splitlines()[-1])
                self.assertEqual(record['floor_rule'], rule)
                self.assertNotIn(record['floor_rule'], {'true-floor', None})
                self.assertNotIn(command, json.dumps(record))

    def test_ssh_identity_floor_is_scoped_to_ssh_family(self):
        self.manifest['classes'][0]['enabled'] = True
        for command in [
            'grep -n -i "honey.badger|honeybadger" FORGE/bin/agent-session',
            'grep -n -i "identityfile" README.org',
        ]:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'allow')
        for command in [
            'ssh -i ~/.ssh/id_ed25519 YOUR_HOST date',
            'ssh -o IdentityFile=~/.ssh/id_ed25519 YOUR_HOST date',
            'scp -i /tmp/synthetic-key README.org YOUR_HOST:/tmp/report',
            'sftp -i /tmp/synthetic-key YOUR_HOST',
            'rsync -e "ssh -i /tmp/synthetic-key" README.org YOUR_HOST:/tmp/report',
            'cat ~/.ssh/config',
        ]:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command), 'deny')
                record = json.loads(self.ledger.read_text().splitlines()[-1])
                expected = 'protected' if command.startswith('cat ') else 'ssh-identity'
                self.assertEqual(record['floor_rule'], expected)
        self.assertEqual(self.run_hook('rsync -i /tmp/synthetic-key README.org YOUR_HOST:/tmp/report'), 'deny')
        self.assertNotEqual(json.loads(self.ledger.read_text().splitlines()[-1])['floor_rule'], 'ssh-identity')


if __name__ == '__main__':
    unittest.main()
