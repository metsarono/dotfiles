#!/usr/bin/env python3
"""Synthetic requests only; no live manifest, Telegram or fleet mutation."""
import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import selectors
import shlex
import subprocess
import time
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('seat_fixture', HERE / 'test-claude-approval-unattended.py')
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
e = fixture.e
REPO = fixture.REPO
SUBPROCESS_TIMEOUT = fixture.SUBPROCESS_TIMEOUT


class RemotePresenceTests(unittest.TestCase):
    setUp = fixture.UnattendedCoordinatorTests.setUp
    git = fixture.UnattendedCoordinatorTests.git
    loaded = fixture.UnattendedCoordinatorTests.loaded
    event = fixture.UnattendedCoordinatorTests.event

    def configure(self):
        self.stamp = self.base / 'last-seen'
        self.manifest['gate_inversion'] = {'enabled': True, 'present_refusal': 'ask'}
        self.manifest['unattended'].update(presence_file=str(self.stamp), presence_window_minutes=20,
            hold_timeout_minutes=0.001, admiral_telegram_user_id='123456')
        self.manifest['coordinator_ops']['peer_host'] = 'YOUR_PEER_HOST'
        self.manifest['classes'][0]['enabled'] = True

    def hook(self, event, hold=None):
        self.path.write_text(json.dumps(self.manifest))
        out = io.StringIO()
        env = {'SO_APPROVAL_KIKIN_MANIFEST': str(self.path), 'SO_APPROVAL_KIKIN_LOG': str(self.ledger),
               'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}
        with mock.patch.dict(os.environ, env), mock.patch.object(e.sys, 'stdin', io.StringIO(json.dumps(event))), \
                contextlib.redirect_stdout(out), mock.patch.object(e, '_notify_admiral', return_value='sent'), \
                mock.patch.object(e, '_hold_admiral', return_value=hold or ('timeout', None)):
            self.assertEqual(e.main(), 0)
        return json.loads(out.getvalue())['hookSpecificOutput']['decision'] if out.getvalue().strip() else {'behavior': 'ask'}

    @contextlib.contextmanager
    def queue_env(self):
        with mock.patch.dict(os.environ, {'SO_APPROVAL_MORNING_QUEUE': str(self.queue)}):
            yield

    def records(self):
        with self.queue.open() as file:
            return e._queue_read(file)

    def test_inert_verbs_and_plain_variables(self):
        self.configure()
        for command in ['command -v claude', 'type claude', 'which claude',
                        'readlink -f /usr/bin/claude', 'echo "XDG=$XDG_RUNTIME_DIR"',
                        'printf "%s" "${XDG_RUNTIME_DIR}"',
                        'ps aux | grep claude; echo "XDG=$XDG_RUNTIME_DIR"; ls . | grep org',
                        'command -v claude; readlink -f "$(command -v claude)"; claude --version']:
            with self.subTest(command=command):
                self.assertTrue(e._decide_request(self.event(command), self.loaded())[0])

    def test_unsafe_expansions_and_output_destinations(self):
        self.configure()
        for command in ['echo ${VAR:-$(kill 123)}', 'echo ${VAR@P}', 'echo $((1+2))',
                        'printf -v VAR text', 'echo $VAR > /outside/report',
                        'readlink -f "$(echo /outside/report)"', 'command -v "$(kill 123)"']:
            with self.subTest(command=command), mock.patch.object(e, '_decider_decide', return_value=(True, 'accepted', 0, 'allow')):
                self.assertFalse(e._decide_request(self.event(command), self.loaded())[0])

    def test_content_names_and_scratch_only_root_default(self):
        self.configure()
        self.manifest['coordinator_ops']['classes'] = {name: False for name in fixture.NAMES}
        for tool in ['Write', 'Edit', 'MultiEdit', 'NotebookEdit']:
            key = 'notebook_path' if tool == 'NotebookEdit' else 'file_path'
            for target in [self.scratch / 'athanor-evidence.md', self.repo / 'agents-example.org']:
                with self.subTest(tool=tool, target=target):
                    event = self.event('', tool_name=tool, tool_input={key: str(target),
                        'content': '# Evidence\nOPENROUTER_API_KEY is a variable NAME; no value.\n'})
                    self.assertEqual(e._decide_request(event, self.loaded()), (True, 'root_default_allow'))

    def test_write_floor_includes_git_gate_and_secrets(self):
        self.configure()
        for target in [self.repo / '.git/config', self.repo / '.env', self.scratch / 'approval-morning-queue.jsonl',
                       self.repo / 'agents-approval.org', self.repo / 'agents-hooks.org',
                       self.scratch / 'approval-presence', self.scratch / 'claude-hook-admiral-presence',
                       self.scratch / 'claude-hook-approval-inverted', self.scratch / 'claude-approval.local.json',
                       self.base / 'outside.md']:
            event = self.event('', tool_name='Write', tool_input={'file_path': str(target), 'content': 'x'})
            with self.subTest(target=target), mock.patch.object(e, '_decider_decide') as decider:
                self.assertFalse(e._decide_request(event, self.loaded())[0])
                decider.assert_not_called()

    def test_actual_credential_assignments_stay_floor(self):
        self.configure()
        for content in ['OPENROUTER_API_KEY=SYNTHETIC_VALUE_12345',
                        'OPENROUTER_API_KEY="SYNTHETIC_VALUE_12345"',
                        '{"OPENROUTER_API_KEY": "SYNTHETIC_VALUE_12345"}',
                        "{'OPENROUTER_API_KEY': 'SYNTHETIC_VALUE_12345'}"]:
            event=self.event('', tool_name='Write', tool_input={'file_path':str(self.scratch/'report.md'), 'content':content})
            with self.subTest(content=content), mock.patch.object(e, '_decider_decide') as decider:
                self.assertEqual(e._decide_request(event,self.loaded()),(False,'true_floor'))
                decider.assert_not_called()

    def test_remote_mail_copy_and_both_dispatch_shapes(self):
        self.configure()
        dispatch = 'nohup codex exec --model YOUR_MODEL --approve-for-me --skip-git-repo-check "$(cat /tmp/YOUR_SEAT/prompt.txt)" < /dev/null > /tmp/YOUR_SEAT/worker.log 2>&1 &'
        commands = [f'scp {self.prompt} YOUR_PEER_HOST:/tmp/YOUR_SEAT/report.md',
            'ssh YOUR_PEER_HOST mailcortex send --from YOUR_SEAT@YOUR_HOST.helm --to YOUR_REVIEWER@YOUR_HOST.helm --subject review-ready --body-file /tmp/YOUR_SEAT/report.md',
            'ssh YOUR_PEER_HOST ' + shlex.quote(dispatch),
            'ssh YOUR_PEER_HOST ' + shlex.quote('ssh YOUR_BUILD_HOST ' + shlex.quote(dispatch))]
        with mock.patch.object(e, '_coordinator_remote_proof', return_value=True) as proof:
            for command in commands:
                with self.subTest(command=command):
                    allow, reason = e._decide_request(self.event(command), self.loaded())
                    self.assertTrue(allow, reason)
                    self.assertTrue(reason.startswith('coordinator_'), reason)
            self.assertTrue(proof.called)

    def test_heredoc_copy_mail_compound(self):
        self.configure()
        path = self.scratch / 'YOUR_SEAT-evidence.md'
        command = f"cat > {path} <<'EOF'\nOPENROUTER_API_KEY (name only)\nEOF\nscp {path} YOUR_PEER_HOST:/tmp/YOUR_SEAT/evidence.md\nssh YOUR_PEER_HOST mailcortex send --from YOUR_SEAT@YOUR_HOST.helm --to YOUR_REVIEWER@YOUR_HOST.helm --subject evidence --body-file /tmp/YOUR_SEAT/evidence.md"
        with mock.patch.object(e, '_coordinator_remote_proof', return_value=True):
            self.assertFalse(e._decide_request(self.event(command), self.loaded())[0])

    def test_remote_floor_every_position_even_with_allow_decider(self):
        self.configure()
        bad = ["ssh YOUR_PEER_HOST 'rm -rf x'", "ssh YOUR_PEER_HOST 'echo x\ncat <<EOF\nx\nEOF'",
               'ssh YOUR_PEER_HOST mailcortex send --from SOMEONE_ELSE@YOUR_HOST.helm --to X@Y.helm --subject x --body-file /tmp/YOUR_SEAT/x.md',
               f'scp {self.prompt} YOUR_PEER_HOST:/tmp/OTHER_SEAT/x.md',
               f'scp {self.prompt} YOUR_PEER_HOST:/tmp/YOUR_SEAT/.git/config']
        with mock.patch.object(e, '_decider_decide', return_value=(True, 'accepted', 0, 'allow')) as decider, \
                mock.patch.object(e, '_coordinator_remote_proof', return_value=True):
            for command in bad:
                for compound in [command, 'true; ' + command, command + '; true']:
                    self.assertFalse(e._decide_request(self.event(compound), self.loaded())[0], compound)
            decider.assert_not_called()

    def test_presence_quiet_fresh_stale_flag_and_missing_daytime(self):
        self.configure()
        self.manifest['unattended']['quiet_hours']['enabled'] = True
        now = dt.datetime(2026, 1, 2, 14, tzinfo=dt.timezone.utc)
        self.stamp.touch()
        os.utime(self.stamp, (now.timestamp(), now.timestamp()))
        self.assertEqual(e._away_status(self.loaded(), now=now), (False, 'presence'))
        os.utime(self.stamp, (now.timestamp()-1201, now.timestamp()-1201))
        self.assertEqual(e._away_status(self.loaded(), now=now), (True, 'quiet_hours'))
        self.stamp.unlink()
        self.assertEqual(e._away_status(self.loaded(), now=now + dt.timedelta(hours=12)), (False, 'present'))
        self.stamp.touch()
        self.flag.touch()
        self.assertEqual(e._away_status(self.loaded(), now=now), (True, 'away_flag'))

    def test_present_hold_timeout_queues_and_note_has_id(self):
        # pty-hold-20261012: the Telegram plugin hold is gone. When the
        # Admiral is present the gate returns the NATIVE ask exactly as
        # today (the harness relay shows it; nothing is queued at the gate).
        # The PTY owner (claude-warm) owns the timeout and writes the queue
        # item with reason hold_timeout when the prompt outlives the
        # deadline (covered by test-approval-pty-hold.py).
        self.configure()
        self.stamp.touch()
        self.manifest['unattended'].pop('hold_notify_argv', None)
        result = self.hook(self.event('rm report'))
        self.assertEqual(result['behavior'], 'ask')
        self.assertFalse(self.queue.exists(),
                         'the present gate must not write the queue')

    def test_later_policy_allow_resolves_same_request(self):
        self.configure()
        self.flag.touch()
        request = self.event('make test', tool_input={'command': 'make test', 'description': 'verify build'})
        self.manifest['gate_inversion']['enabled'] = False
        self.hook(request)
        self.flag.unlink()
        self.manifest['gate_inversion']['enabled'] = True
        self.assertEqual(self.hook(request)['behavior'], 'allow')
        self.assertEqual(self.records()[0]['status'], 'resolved')
        self.assertTrue(self.records()[0]['resolution'].startswith('approved live at '))
        self.assertEqual(json.loads(self.ledger.read_text().splitlines()[-1])['decision'], 'allow')

    def test_queue_dedupe_by_hash_intent_and_seat(self):
        self.configure()
        with self.queue_env():
            a = self.event('command-one', approval_intent='deliver evidence')
            b = self.event('command-two', approval_intent='deliver evidence')
            first = e._queue_upsert(a, 'true_floor', 'away_flag', self.loaded())
            second = e._queue_upsert(a, 'true_floor', 'away_flag', self.loaded())
            third = e._queue_upsert(b, 'true_floor', 'away_flag', self.loaded())
            self.assertEqual(first, second)
            self.assertEqual(first, third)
            records = self.records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]['count'], 3)
            self.assertEqual(records[0]['intent'], 'deliver evidence')
            self.assertLessEqual(records[0]['first_seen'], records[0]['last_seen'])
            other = self.loaded(); other['coordinator_ops']['seat_account'] = 'OTHER_SEAT@YOUR_HOST.helm'
            self.assertNotEqual(e._queue_upsert(a, 'true_floor', 'away_flag', other), first)

    def test_queue_resolution_and_automatic_same_intent(self):
        self.configure()
        with self.queue_env():
            request = self.event('old', approval_intent='deliver evidence')
            item = e._queue_upsert(request, 'true_floor', 'away_flag', self.loaded())
            e._queue_resolve(item, 'sent via reviewed local mail')
            self.assertEqual(self.records()[0]['status'], 'resolved')
            self.assertEqual(e._queue_live_allow(self.event('new', approval_intent='deliver evidence'), self.loaded()), [])
            item = e._queue_upsert(request, 'true_floor', 'away_flag', self.loaded())
            self.assertEqual(e._queue_live_allow(self.event('new', approval_intent='deliver evidence'), self.loaded()), [item])
            self.assertEqual(self.records()[-1]['status'], 'resolved')

    def test_sweep_missing_worktree_and_uncertain_items(self):
        self.configure()
        with self.queue_env():
            gone = self.event('old', cwd=str(self.base / 'DotCortex-wt-test/gone'))
            gone['approval_context'] = {'worktree': gone['cwd']}
            item = e._queue_upsert(gone, 'true_floor', 'away_flag', self.loaded())
            keep = e._queue_upsert(self.event('uncertain'), 'true_floor', 'away_flag', self.loaded())
            e._queue_sweep()
            self.assertEqual(next(x for x in self.records() if x['id'] == item)['status'], 'obsolete')
            self.assertEqual(next(x for x in self.records() if x['id'] == keep)['status'], 'open')

    def test_replay_rechecks_open_needed_confirmation_and_honours_once(self):
        self.configure()
        with self.queue_env():
            item = e._queue_upsert(self.event('unknown'), 'true_floor', 'away_flag', self.loaded())
            self.assertFalse(e._queue_claim(item, 'no-confirmation')[0])
            token = e._queue_confirm(item, True, 'YOUR_SESSION')
            self.assertFalse(e._queue_claim(item, token)[0])
            self.assertTrue(e._queue_authorize(item,'123456',self.loaded()))
            self.assertTrue(e._queue_claim(item, token)[0])
            self.assertFalse(e._queue_claim(item, token)[0])

    def test_same_intent_duplicate_cannot_replace_held_preview(self):
        self.configure()
        with self.queue_env():
            original=self.event('first command',approval_intent='deliver evidence')
            duplicate=self.event('second command',approval_intent='deliver evidence',session_id='SECOND_SESSION')
            item=e._queue_upsert(original,'true_floor','presence',self.loaded(),status='held')
            nonce=e._queue_begin_hold(item,self.loaded())
            self.assertEqual(e._queue_upsert(duplicate,'true_floor','presence',self.loaded(),status='held'),item)
            record=self.records()[0]
            self.assertEqual(record['request'],original)
            self.assertEqual(record['session'],original['session_id'])
            self.assertEqual(record['hold_nonce'],nonce)
            self.assertEqual(record['count'],2)
            self.assertEqual(record['requests'],[original,duplicate])

    def test_hold_one_use_authenticated_callback_and_timeout(self):
        self.configure()
        self.manifest['unattended']['hold_timeout_minutes']=1
        with self.queue_env(), mock.patch.object(e.time, 'time', return_value=1000) as wall_clock:
            item = e._queue_upsert(self.event('rm report'), 'true_floor', 'presence', self.loaded(), status='held')
            nonce = e._queue_begin_hold(item, self.loaded())
            self.assertFalse(e._queue_answer(item, nonce, 'allow', '999', self.loaded()))
            self.assertTrue(e._queue_answer(item, nonce, 'allow', '123456', self.loaded()))
            self.assertFalse(e._queue_answer(item, nonce, 'deny', '123456', self.loaded()))
            self.assertEqual(e._queue_hold_result(item, nonce), 'allow')
            another = e._queue_upsert(self.event('different'), 'true_floor', 'presence', self.loaded(), status='held')
            token = e._queue_begin_hold(another, self.loaded())
            self.assertEqual(self.records()[-1]['hold_deadline'], 1060)
            wall_clock.return_value = 1060
            self.assertFalse(e._queue_answer(another, token, 'allow', '123456', self.loaded()))

    def test_hold_timeout_exact_deadline_and_queue_transition(self):
        self.configure()
        elapsed = 0.0
        sleeps = []
        def sleep(seconds):
            nonlocal elapsed
            self.assertGreater(seconds, 0)
            self.assertLessEqual(seconds, 0.05)
            # The record must stay held until the complete timeout is consumed.
            self.assertEqual(self.records()[0]['status'], 'held')
            sleeps.append(seconds)
            elapsed += seconds
        clock = SimpleNamespace(monotonic=lambda: elapsed, time=lambda: 1000 + elapsed, sleep=sleep)
        manifest = self.loaded()
        with self.queue_env(), mock.patch.object(e, 'time', clock), \
                mock.patch.object(e, '_notify_hold', return_value='sent'), \
                mock.patch.object(e, '_queue_context', return_value={}):
            result, item = e._hold_admiral(self.event('rm report'), 'true_floor', manifest)
        self.assertEqual(result, 'timeout')
        self.assertEqual(elapsed, e._hold_seconds(manifest))
        self.assertEqual(len(sleeps), 2)
        record = self.records()[0]
        self.assertEqual(record['status'], 'open')
        self.assertEqual(record['away_reason'], 'hold_timeout')
        self.assertEqual(record['id'], item)
        self.assertNotIn('hold_nonce', record)

    def test_real_hold_timeout_elapsed_and_queue_transition(self):
        self.configure()
        manifest = self.loaded()
        with self.queue_env(), mock.patch.object(e, '_notify_hold', return_value='sent'), mock.patch.object(e,'_queue_context',return_value={}):
            started = time.monotonic()
            result, item = e._hold_admiral(self.event('rm report'), 'true_floor', manifest)
            elapsed = time.monotonic()-started
            self.assertEqual(result, 'timeout')
            self.assertGreaterEqual(elapsed, e._hold_seconds(manifest))
            self.assertLess(elapsed, SUBPROCESS_TIMEOUT)
            self.assertEqual(self.records()[0]['status'], 'open')
            self.assertEqual(self.records()[0]['id'], item)


    def test_presence_authentication_and_future_stamp(self):
        self.configure()
        for event in [self.event('',hook_event_name='UserPromptSubmit',prompt='<channel source="telegram" user_id="999">hi</channel>'),
                      self.event('',hook_event_name='UserPromptSubmit',prompt='scheduled work',source='scheduler'),
                      self.event('',hook_event_name='UserPromptSubmit',prompt='<task-notification>peer result</task-notification>')]:
            self.assertFalse(e._presence_prompt(event,self.loaded()))
            self.assertFalse(self.stamp.exists())
        for prompt in ['terminal input','<channel source="plugin:telegram:telegram" user_id="123456">hi</channel>']:
            self.assertTrue(e._presence_prompt(self.event('',hook_event_name='UserPromptSubmit',prompt=prompt),self.loaded()))
        self.manifest['unattended']['quiet_hours']['enabled']=True
        now=dt.datetime(2026,1,2,14,tzinfo=dt.timezone.utc)
        os.utime(self.stamp,(now.timestamp()+60,now.timestamp()+60))
        self.assertEqual(e._away_status(self.loaded(),now=now),(True,'quiet_hours'))

    def test_presence_peer_uses_one_authority_for_read_and_stamp(self):
        self.configure()
        self.manifest['unattended'].update(presence_host='example.invalid',quiet_hours={'enabled':True})
        now=dt.datetime(2026,1,2,14,tzinfo=dt.timezone.utc)
        with mock.patch.object(e.subprocess,'run',return_value=subprocess.CompletedProcess([],0,str(now.timestamp())+'\n','')) as run:
            self.assertEqual(e._away_status(self.loaded(),now=now),(False,'presence'))
            self.assertEqual(run.call_args.args[0][-2:],['example.invalid','approval-presence status'])
            self.assertTrue(e._presence_stamp(self.loaded()))
            self.assertEqual(run.call_args.args[0][-2:],['example.invalid','approval-presence stamp'])
        with mock.patch.object(e.subprocess,'run',side_effect=subprocess.TimeoutExpired('ssh',.7)):
            self.assertEqual(e._away_status(self.loaded(),now=now),(True,'quiet_hours'))

    def test_first_human_allow_auto_clears_away_with_receipt(self):
        self.configure()
        self.flag.touch()
        receipt = self.base / 'away-receipts.jsonl'
        with mock.patch.dict(os.environ, {'SO_APPROVAL_AWAY_RECEIPT': str(receipt)}):
            self.assertTrue(e._clear_away_flag(self.loaded(), 'human_allow_hold'))
        self.assertFalse(self.flag.exists())
        record = json.loads(receipt.read_text().splitlines()[-1])
        self.assertEqual(record['action'], 'away_auto_cleared')
        self.assertEqual(record['reason'], 'human_allow_hold')

    def test_remote_local_expansion_and_wrong_nested_quoting_are_floor(self):
        self.configure()
        dispatch='nohup codex exec --model YOUR_MODEL --approve-for-me --skip-git-repo-check "$(cat /tmp/YOUR_SEAT/prompt.txt)" < /dev/null > /tmp/YOUR_SEAT/log.txt 2>&1 &'
        commands=[
          'ssh YOUR_PEER_HOST mailcortex send --from YOUR_SEAT@YOUR_HOST.helm --to X@Y.helm --subject "$SUBJECT" --body-file /tmp/YOUR_SEAT/report.md',
          'ssh YOUR_PEER_HOST "mailcortex send --from YOUR_SEAT@YOUR_HOST.helm --to X@Y.helm --subject \'$SUBJECT\' --body-file /tmp/YOUR_SEAT/report.md"',
          'ssh YOUR_PEER_HOST '+shlex.quote('ssh YOUR_BUILD_HOST "'+dispatch.replace('"','\\"')+'"'),
        ]
        with mock.patch.object(e,'_coordinator_remote_proof',return_value=True), mock.patch.object(e,'_decider_decide') as decider:
            for command in commands:
                self.assertFalse(e._decide_request(self.event(command),self.loaded())[0],command)
            decider.assert_not_called()

    def test_remote_proof_routes_to_peer_or_build_through_peer(self):
        self.configure()
        config=self.loaded()['coordinator_ops']
        paths=['/tmp/YOUR_SEAT/prompt.txt','/tmp/YOUR_SEAT/worker.log']
        good=subprocess.CompletedProcess([],0,'\n'.join(paths)+'\n','')
        with mock.patch.object(e.subprocess,'run',return_value=good) as run:
            self.assertTrue(e._coordinator_remote_proof(config,paths,regular_input=paths[0],host='YOUR_PEER_HOST'))
            self.assertEqual(run.call_args.args[0][-2],'YOUR_PEER_HOST')
            self.assertTrue(e._coordinator_remote_proof(config,paths,regular_input=paths[0],host='YOUR_BUILD_HOST',via='YOUR_PEER_HOST'))
            self.assertEqual(run.call_args.args[0][-2],'YOUR_PEER_HOST')
            self.assertIn('YOUR_BUILD_HOST',run.call_args.args[0][-1])
        with mock.patch.object(e.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'/etc/passwd\n'+paths[1]+'\n','')):
            self.assertFalse(e._coordinator_remote_proof(config,paths,host='YOUR_PEER_HOST'))

    def test_queue_sweep_landed_branch_and_session_intent_evidence(self):
        self.configure()
        self.git('checkout','topic')
        (self.repo/'README.org').write_text('topic changes')
        self.git('commit','-am','test: topic change')
        with self.queue_env():
            item=e._queue_upsert(self.event('blocked'), 'true_floor','away_flag',self.loaded())
            tip=self.git('rev-parse','HEAD')
            self.git('update-ref','refs/heads/master',tip)
            self.assertEqual(e._queue_sweep(),[item])
            ended=e._queue_upsert(self.event('other',cwd=str(self.scratch)),'true_floor','away_flag',self.loaded())
            e._queue_update(ended,lambda x:x.update(context={'session_ended':True,'intent_met':False}))
            self.assertEqual(e._queue_sweep(),[])
            e._queue_update(ended,lambda x:x.update(context={'session_ended':True,'intent_met':True}))
            self.assertEqual(e._queue_sweep(),[ended])

    def test_queue_obsolete_approval_is_audited_and_cannot_replay(self):
        self.configure()
        with self.queue_env():
            item=e._queue_upsert(self.event('old'),'true_floor','away_flag',self.loaded())
            token=e._queue_confirm(item,True,'YOUR_SESSION')
            self.assertTrue(e._queue_authorize(item,'123456',self.loaded()))
            e._queue_resolve(item,'done through reviewed method')
            self.assertFalse(e._queue_claim(item,token)[0])
            self.assertIn('ignored_approval_at',self.records()[0])
            self.assertFalse(e._queue_authorize(item,'123456',self.loaded()))

    def test_queue_old_rows_are_deduped_and_live_allow_resolves_them(self):
        self.configure()
        event=self.event('old')
        old={'timestamp':e._utc(),'tool':'Bash','command':'old','cwd':str(self.repo),'session':'YOUR_SESSION','request':event}
        self.queue.write_text(json.dumps(old)+'\n'+json.dumps(old)+'\n')
        self.loaded()
        with self.queue_env(), mock.patch.dict(os.environ,{'SO_APPROVAL_KIKIN_MANIFEST':str(self.path)}):
            records=self.records()
            self.assertEqual(len(records),1)
            self.assertEqual(records[0]['count'],2)
            self.assertEqual(e._queue_live_allow(event,self.loaded()),[records[0]['id']])
            self.assertEqual(self.records()[0]['status'],'resolved')

    def test_post_tool_live_allow_resolves_native_prompt(self):
        self.configure();self.loaded();self.stamp.touch()
        with self.queue_env(),mock.patch.dict(os.environ,{'SO_APPROVAL_KIKIN_MANIFEST':str(self.path),'SO_APPROVAL_KIKIN_LOG':str(self.ledger)}):
            event=self.event('old')
            e._queue_upsert(event,'true_floor','away_flag',self.loaded())
            executed={**event,'hook_event_name':'PostToolUse','tool_response':'success'}
            with mock.patch.object(e.sys,'stdin',io.StringIO(json.dumps(executed))):
                self.assertEqual(e.observe_main(),0)
            self.assertEqual(self.records()[0]['status'],'resolved')
            self.assertEqual(json.loads(self.ledger.read_text())['decision'],'allow')

    def test_queue_cli_live_view_and_resolve(self):
        self.configure();self.loaded()
        with self.queue_env():item=e._queue_upsert(self.event('old'),'true_floor','away_flag',self.loaded())
        env={**os.environ,'SO_APPROVAL_MORNING_QUEUE':str(self.queue),'SO_APPROVAL_KIKIN_MANIFEST':str(self.path)}
        cli=REPO/'all/.local/bin/approval-queue'
        listed=subprocess.run([str(cli),'list','--json'],env=env,capture_output=True,text=True,check=True,timeout=SUBPROCESS_TIMEOUT)
        self.assertEqual(json.loads(listed.stdout)[0]['id'],item)
        subprocess.run([str(cli),'resolve',item,'--how','done in policy'],env=env,capture_output=True,check=True,timeout=SUBPROCESS_TIMEOUT)
        listed=subprocess.run([str(cli),'list'],env=env,capture_output=True,text=True,check=True,timeout=SUBPROCESS_TIMEOUT)
        self.assertIn('Done while you were away',listed.stdout)
        self.assertNotIn('Awaiting the Admiral',listed.stdout)

    def test_tools_cannot_stamp_presence_or_fake_callback_or_claim(self):
        self.configure()
        for command in ['approval-presence stamp','approval-telegram-verdict','approval-telegram-presence',
                        'approval-queue approve abc --sender 123456','approval-queue claim abc --confirmation abc']:
            self.assertFalse(e._decide_request(self.event(command),self.loaded())[0],command)

    def test_fable_absolute_scratch_write_from_protected_cwd(self):
        self.configure()
        event=self.event('',cwd=str(self.repo/'PalmCortex'),tool_name='Write',tool_input={'file_path':str(self.scratch/'lane-brief.md'),'content':'non-secret report mentions /home/YOUR_OTHER_USER/work'})
        self.assertEqual(e._decide_request(event,self.loaded()),(True,'root_default_allow'))
        event['tool_input']['file_path']=str(self.repo/'PalmCortex/brief.md')
        self.assertFalse(e._decide_request(event,self.loaded())[0])

    def test_intent_declared_after_deferral_merges_open_items(self):
        self.configure()
        with self.queue_env():
            first=e._queue_upsert(self.event('one'),'true_floor','away_flag',self.loaded())
            second=e._queue_upsert(self.event('two'),'true_floor','away_flag',self.loaded())
            self.assertTrue(e._queue_intent(first,'deliver evidence'))
            self.assertTrue(e._queue_intent(second,'deliver evidence'))
            open_items=[x for x in self.records() if x['status']=='open']
            self.assertEqual(len(open_items),1)
            self.assertEqual(open_items[0]['count'],2)
            self.assertEqual(len(open_items[0]['requests']),2)



    def test_compound_future_remote_body_is_proved_without_existing_file(self):
        self.configure()
        local=self.scratch/'YOUR_SEAT-new.md'
        remote='/tmp/YOUR_SEAT/new.md'
        command=f"cat > {local} <<'EOF'\nnew evidence\nEOF\nscp {local} YOUR_PEER_HOST:{remote}\nssh YOUR_PEER_HOST mailcortex send --from YOUR_SEAT@YOUR_HOST.helm --to X@Y.helm --subject evidence --body-file {remote}"
        def proof(config,paths,regular_input=None,**kwargs):
            # No remote body exists yet: only the proved copy may supply it.
            return regular_input is None
        with mock.patch.object(e,'_coordinator_remote_proof',side_effect=proof):
            self.assertFalse(e._decide_request(self.event(command),self.loaded())[0])
            self.assertFalse(e._decide_request(self.event(command.split('EOF\n')[-1].split('\n')[-1]),self.loaded())[0])
        manifest=self.manifest.copy();manifest['_compound_remote_created_files']=[('YOUR_PEER_HOST',remote)]
        with self.assertRaises(ValueError):e._load_manifest(manifest)

    def test_remote_proof_cache_is_request_local_and_copy_rejects_symlink_directory(self):
        self.configure()
        config=self.loaded()['coordinator_ops'];path='/tmp/YOUR_SEAT/new.md'
        good=subprocess.CompletedProcess([],0,path+'\n','')
        e._coordinator_proof_cache={}
        try:
            with mock.patch.object(e.subprocess,'run',return_value=good) as run:
                for _ in range(3):self.assertTrue(e._coordinator_remote_proof(config,[path],host='YOUR_PEER_HOST',copied_output=path))
                self.assertEqual(run.call_count,1)
                self.assertIn('test ! -d',run.call_args.args[0][-1])
                self.assertIn('test ! -L',run.call_args.args[0][-1])
        finally:e._coordinator_proof_cache=None
        with mock.patch.object(e.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','')):
            self.assertFalse(e._coordinator_remote_proof(config,[path],host='YOUR_PEER_HOST',copied_output=path))



if __name__ == '__main__':
    unittest.main()
