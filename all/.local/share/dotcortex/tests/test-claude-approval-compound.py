#!/usr/bin/env python3
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('compound_fixture', HERE / 'test-claude-approval-unattended.py')
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
e = fixture.e


class CompoundApprovalTests(fixture.UnattendedCoordinatorTests):
    def setUp(self):
        super().setUp()
        self.manifest['gate_inversion'] = {'enabled': True, 'present_refusal': 'deny'}

    def in_process(self, command, *, verdict=None, **extra):
        self.manifest['decider'].update(enabled=True, honey_url=None,
            kikin_url='https://YOUR_DECIDER.invalid/decide', timeout_ms=500)
        self.loaded()
        env = {'SO_APPROVAL_KIKIN_MANIFEST': str(self.path),
               'SO_APPROVAL_KIKIN_LOG': str(self.ledger), 'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
        out = io.StringIO()
        verdict = verdict or (lambda event, config: (True, 'accepted', 1, 'allow'))
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(e.sys, 'stdin', io.StringIO(json.dumps(self.event(command, **extra)))), \
                contextlib.redirect_stdout(out), mock.patch.object(e, '_decider_decide', side_effect=verdict) as decider:
            self.assertEqual(e.main(), 0)
        result = json.loads(out.getvalue())['hookSpecificOutput']['decision'] if out.getvalue().strip() else {'behavior': 'ask'}
        return result, json.loads(self.ledger.read_text().splitlines()[-1]), decider

    def test_compound_brief_commit_mail_with_every_separator(self):
        commit = f'git -C {self.repo} commit -q -m "test: scoped" -- README.org'
        for separator in (' && ', '; ', '\n'):
            with self.subTest(separator=separator):
                header = f"cat > {self.prompt} <<'EOF'"
                body = 'inert brief: rm -rf x; $(sudo true); .env\nEOF\n'
                command = (header + '\n' + body + commit + separator + self.mail()
                           if separator == '\n' else header + separator + commit + separator + self.mail() + '\n' + body)
                result, record, _ = self.in_process(command)
                self.assertEqual(result['behavior'], 'allow', record)

    def test_compound_exact_coordinator_carveouts_are_local_to_segments(self):
        commands = [f'git worktree add {self.wt}/worker -b worker master', self.mail(),
                    f'git -C {self.repo} merge --ff-only topic']
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook('git status && ' + command)['behavior'], 'allow')
        with mock.patch.object(e, '_coordinator_remote_proof', return_value=True):
            result, _record, _ = self.in_process(f'git status; scp {self.prompt} YOUR_BUILD_HOST:/tmp/YOUR_SEAT/prompt.txt')
            self.assertEqual(result['behavior'], 'allow')

    def test_compound_brief_can_create_the_mail_body(self):
        self.prompt.unlink()
        command = f"cat > {self.prompt} <<'EOF'\nnew brief\nEOF\n" + self.mail()
        self.assertEqual(self.run_hook(command)['behavior'], 'allow')
        self.assertFalse(self.prompt.exists(), 'approval must not execute the write')
        self.assertEqual(self.run_hook(self.mail())['behavior'], 'deny')

    def test_compound_floor_every_position_beats_always_allow(self):
        bad = ['rm -rf README.org', 'git push --force', 'sudo true',
               'cat .env', 'echo x > /etc/YOUR_FILE', "python3 <<'PY'\nprint(1)\nPY"]
        for separator in (' && ', '; ', '\n'):
            for danger in bad:
                for before, after, index in [('', separator + self.mail(), 1),
                                             (self.mail() + separator, '', 2)]:
                    with self.subTest(separator=separator, danger=danger, index=index):
                        # Heredoc payload must start on a physical newline.
                        if '\n' in danger and after:
                            after = '\n' + self.mail()
                        result, record, decider = self.in_process(before + danger + after)
                        self.assertEqual(result['behavior'], 'deny', record)
                        self.assertIn(f'segment_{index}', record['reason'])
                        self.assertIn('true_floor', record['reason'])
                        decider.assert_not_called()

    def test_compound_coordinator_near_match_is_named(self):
        result, record, _ = self.in_process('git status && ' + self.mail().replace('YOUR_SEAT@', 'YOUR_OTHER@'))
        self.assertEqual(result['behavior'], 'deny')
        self.assertIn('segment_2', record['reason'])
        self.assertIn('coordinator_refused', record['reason'])
        self.assertNotIn(str(self.prompt), json.dumps(record))

    def test_compound_decider_sees_each_default_segment(self):
        seen = []
        def decide(event, config):
            command = event['tool_input']['command']
            seen.append(command)
            return (False, 'risky', 1, 'risky') if command == 'make risky' else (True, 'no_risk_veto', 1, 'allow')
        result, record, _ = self.in_process('make safe && make risky && make last', verdict=decide)
        self.assertEqual(result['behavior'], 'deny')
        self.assertEqual(seen, ['make safe', 'make risky'])
        self.assertIn('segment_2', record['reason'])
        self.assertIn('decider_risky', record['reason'])

    def test_compound_echo_is_checked_like_a_standalone_segment(self):
        def risky(event, config):
            return False, 'risky', 1, 'risky'
        self.assertEqual(self.in_process('echo hi', verdict=risky)[0]['behavior'], 'deny')
        result, record, _ = self.in_process('echo hi && ' + self.mail(), verdict=risky)
        self.assertEqual(result['behavior'], 'deny')
        self.assertIn('segment_1', record['reason'])

    def test_compound_legacy_decider_is_called_per_segment(self):
        self.manifest['gate_inversion']['enabled'] = False
        seen = []
        def decide(event, config):
            command = event['tool_input']['command']
            seen.append(command)
            return (command != 'printf risky', 'accepted', 1, 'ask' if command == 'printf risky' else 'allow')
        result, record, _ = self.in_process('printf safe; printf risky', verdict=decide)
        self.assertEqual(result['behavior'], 'deny')
        self.assertEqual(seen, ['printf safe', 'printf risky'])
        self.assertIn('segment_2', record['reason'])

    def test_compound_pipeline_remains_one_segment(self):
        self.manifest['classes'][0]['enabled'] = True
        command = 'cat README.org | wc -l && ' + self.mail()
        self.assertEqual(self.run_hook(command)['behavior'], 'allow')
        result, record, _ = self.in_process('cat README.org | rm README.org && ' + self.mail())
        self.assertEqual(result['behavior'], 'deny')
        self.assertIn('segment_1', record['reason'])

    def test_compound_heredoc_cat_tee_roots_and_symlinks(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.scratch / 'escape').symlink_to(outside, target_is_directory=True)
        for verb in ('cat >', 'tee'):
            for path, expected in [(self.scratch / 'new.txt', 'allow'),
                                   (self.repo / 'new.txt', 'allow'),
                                   (outside / 'new.txt', 'deny'),
                                   (self.scratch / 'escape/new.txt', 'deny')]:
                command = f"{verb} {path} <<'END'\nrm -rf x\n$(sudo true)\nEND\n"
                with self.subTest(verb=verb, path=path):
                    self.assertEqual(self.run_hook(command)['behavior'], expected)

    def test_compound_heredoc_quoted_marker_cannot_hide_following_command(self):
        # The apparent heredoc operator is a quoted printf argument.
        command = "printf '%s' '<<EOF'\nrm -rf README.org\nEOF"
        self.assertEqual(self.run_hook(command)['behavior'], 'deny')

    def test_compound_multiple_heredocs_and_tab_stripping(self):
        command = f"cat > {self.prompt} <<'FIRST' <<-'SECOND'\ninert first\nFIRST\n\trm -rf x\n\tSECOND\n" + self.mail()
        self.assertEqual(self.run_hook(command)['behavior'], 'allow')
        self.assertEqual(self.run_hook(f"cat > {self.prompt} <<'EOF'\nmissing terminator")['behavior'], 'deny')

    def test_compound_blank_lines_comments_and_continuation(self):
        for command in ['git status\n\n# a comment\n' + self.mail(),
                        'git status &&\n' + self.mail(), 'git status;\n' + self.mail() + ';\n']:
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(command)['behavior'], 'allow')
        for command in ['git status &&', 'git status ||', 'git status ;; ' + self.mail()]:
            self.assertEqual(self.run_hook(command)['behavior'], 'deny', command)

    def test_compound_preserves_request_kind_and_payload_keys(self):
        command = self.mail() + ' && ' + self.mail()
        self.assertFalse(e.classify(self.event(command, hook_event_name='PreToolUse'), self.loaded())[0])
        payload = self.event(command)
        payload['tool_input']['unknown'] = True
        self.assertEqual(self.in_process(command, tool_input=payload['tool_input'])[0]['behavior'], 'deny')

    def test_compound_cd_must_control_the_following_command(self):
        self.assertEqual(self.run_hook(f'cd {self.scratch} && echo hi > relative.txt')['behavior'], 'allow')
        # A fallible cd followed by ; or a newline cannot prove a later relative target.
        for separator in ('; ', '\n', ' || '):
            command = f'cd {self.scratch}' + separator + 'echo hi > relative.txt'
            self.assertEqual(self.run_hook(command)['behavior'], 'deny', command)
        # A pipeline cd does not change the parent shell's cwd.
        outside = self.base / 'outside'
        outside.mkdir()
        result, _record, _ = self.in_process(f'cd {self.scratch} | cat; touch file', cwd=str(outside))
        self.assertEqual(result['behavior'], 'deny')
        for wrapper in ('command ', 'builtin ', ''):
            result, record, _ = self.in_process(wrapper + 'cd /etc && touch relative.txt')
            self.assertEqual(result['behavior'], 'deny')
            self.assertIn('true_floor', record['reason'])

    def test_compound_deadline_is_shared_by_all_decider_calls(self):
        import time
        elapsed = 0.0
        calls = []
        previous_handler = object()
        def slow(event, config):
            nonlocal elapsed
            calls.append((event['tool_input']['command'], config['timeout_ms']))
            # Simulate work consuming the one timer installed by main. Invoke
            # its real handler at expiry without depending on OS scheduling.
            seconds = timer.call_args_list[0].args[1]
            if elapsed + 1.375 >= seconds:
                elapsed = seconds
                handler.call_args_list[0].args[1](e.signal.SIGALRM, None)
            elapsed += 1.375
            return True, 'no_risk_veto', 1, 'allow'
        with mock.patch.object(time, 'monotonic', side_effect=lambda: elapsed), \
                mock.patch.object(e.signal, 'signal', return_value=previous_handler) as handler, \
                mock.patch.object(e.signal, 'setitimer') as timer:
            result, record, _ = self.in_process('make one; make two; make three; make four', verdict=slow)
        self.assertEqual(elapsed, 3.0)
        self.assertEqual(calls[:2], [('make one', 500), ('make two', 500)])
        self.assertEqual(calls[2][0], 'make three')
        self.assertEqual(calls[2][1], 250)
        self.assertEqual(len(calls), 3)
        self.assertEqual(timer.call_args_list, [mock.call(e.signal.ITIMER_REAL, 3.0),
                                               mock.call(e.signal.ITIMER_REAL, 0)])
        self.assertEqual(handler.call_args_list, [mock.call(e.signal.SIGALRM, e._deadline),
                                                 mock.call(e.signal.SIGALRM, previous_handler)])
        self.assertEqual(result['behavior'], 'deny')
        self.assertIn('segment_3', record['reason'])
        self.assertIn('TimeoutError', record['reason'])

    def test_compound_cd_uses_the_same_veto_as_standalone(self):
        def risky(event, config):
            return False, 'risky', 1, 'risky'
        self.assertEqual(self.in_process(f'cd {self.scratch}', verdict=risky)[0]['behavior'], 'deny')
        result, record, _ = self.in_process(f'cd {self.scratch} && ' + self.mail(), verdict=risky)
        self.assertEqual(result['behavior'], 'deny')
        self.assertIn('segment_1', record['reason'])

    def test_compound_pipeline_cd_cannot_authorize_a_relative_writer(self):
        outside = self.base / 'outside'
        outside.mkdir()
        for command in [f'cd {self.scratch} | tee relative.txt',
                        f'cat README.org | cd {self.scratch} | tee relative.txt']:
            result, record, decider = self.in_process(command, cwd=str(outside))
            self.assertEqual(result['behavior'], 'deny', record)
            self.assertIn('true_floor', record['reason'])
            decider.assert_not_called()

    def test_substitution_nested_commands_use_full_policy(self):
        for command in ['printf "%s" "$(git status)"', 'printf "%s" "`git status`"',
                        'printf "%s" "$(printf "%s" "$(git status)")"']:
            self.assertEqual(self.run_hook(command)['behavior'], 'allow', command)
        for inner in ['rm -rf README.org', 'git commit -m x --', self.mail().replace('YOUR_SEAT@', 'YOUR_OTHER@')]:
            for command in [f'printf "%s" "$({inner})"', f'printf "%s" "`{inner}`"']:
                result, record, _ = self.in_process(command)
                self.assertEqual(result['behavior'], 'deny', record)
                self.assertIn('substitution_', record['reason'])

    def test_substitution_decider_veto_is_applied_to_the_inner_command(self):
        def decide(event, config):
            return (False, 'risky', 1, 'risky') if event['tool_input']['command'] == 'make risky' else (True, 'no_risk_veto', 1, 'allow')
        result, record, _ = self.in_process('printf "%s" "$(make risky)"', verdict=decide)
        self.assertEqual(result['behavior'], 'deny')
        self.assertIn('substitution_1', record['reason'])
        self.assertIn('decider_risky', record['reason'])

    def test_substitution_unquoted_heredoc_expansion_cannot_bypass_floor(self):
        command = f'cat > {self.prompt} <<EOF\n$(rm -rf README.org)\nEOF'
        self.assertEqual(self.run_hook(command)['behavior'], 'deny')

    def test_substitution_dynamic_write_destination_stays_on_floor(self):
        for command in ['printf x > "$(printf /etc/YOUR_FILE)"', 'tee "$(printf /etc/YOUR_FILE)"']:
            self.assertEqual(self.run_hook(command)['behavior'], 'deny', command)

    def test_substitution_cannot_supply_an_executable_or_unproven_path(self):
        for command in ['"$(printf rm)" README.org', '$(printf rm) README.org',
                        'cat "$(printf .env)"', 'cat `printf .env`',
                        'printf x > "$(printf README.org)"']:
            self.assertEqual(self.run_hook(command)['behavior'], 'deny', command)


def load_tests(loader, tests, pattern):
    # Reuse fixture setup without rerunning the inherited unattended suite.
    return unittest.TestSuite(CompoundApprovalTests(name) for name in CompoundApprovalTests.__dict__ if name.startswith('test_'))


if __name__ == '__main__':
    unittest.main()
