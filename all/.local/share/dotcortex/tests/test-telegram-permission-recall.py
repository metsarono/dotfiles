#!/usr/bin/env python3
"""Recall deletes only windowed permission prompts, against a loopback fake Telegram."""
import datetime
import http.server
import importlib.util
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parents[3] / 'lib/dotcortex/telegram_permission_recall.py'
spec = importlib.util.spec_from_file_location('recall', LIB)
recall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recall)

CHAT = '111'
PERM = '\U0001f510 Permission: Bash'


class FakeTelegram:
    """Messages: id -> dict(kind=user|bot, text, buttons, date)."""

    def __init__(self, messages):
        self.messages = messages
        self.deleted = []
        self.stripped = []
        self.edited = []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))) or b'{}')
                method = self.path.rsplit('/', 1)[-1]
                reply = fake.handle(method, body)
                data = json.dumps(reply).encode()
                self.send_response(200 if reply.get('ok') else 400)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f'http://127.0.0.1:{self.server.server_address[1]}'

    def handle(self, method, body):
        message = self.messages.get(body.get('message_id'))
        if str(body.get('chat_id')) != CHAT:
            return {'ok': False, 'description': 'Bad Request: chat not found'}
        if message is None:
            return {'ok': False, 'description': 'Bad Request: message to edit not found'}
        if method == 'editMessageReplyMarkup':
            if message['kind'] == 'user':
                return {'ok': False, 'description': "Bad Request: message can't be edited"}
            if not message['buttons']:
                return {'ok': False, 'description': 'Bad Request: message is not modified'}
            message['buttons'] = False
            self.stripped.append(body['message_id'])
            return {'ok': True, 'result': {'message_id': body['message_id'], 'text': message['text'], 'date': message['date']}}
        if method == 'editMessageText':
            if message['kind'] == 'user':
                return {'ok': False, 'description': "Bad Request: message can't be edited"}
            message['buttons'] = False
            message['text'] = body['text']
            self.edited.append((body['message_id'], body['text']))
            return {'ok': True, 'result': True}
        if method == 'deleteMessage':
            self.deleted.append(body['message_id'])
            del self.messages[body['message_id']]
            return {'ok': True, 'result': True}
        return {'ok': False, 'description': 'unknown method'}


class RecallTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='recall-test-'))
        self.state = self.dir / 'state'
        self.state.mkdir()
        (self.state / '.env').write_text('TELEGRAM_BOT_TOKEN=123:abc\n')
        (self.state / 'access.json').write_text(json.dumps({'allowFrom': [CHAT]}))
        self.now = int(time.time())
        recall.LOG = self.dir / 'recall.jsonl'  # never write the live log
        self.sweep_args = {}

    def transcript(self, *, anchor=100, tools=('Bash',)):
        rows = [{'message': {'content': [{'type': 'text', 'text': f'<channel source="telegram" chat_id="{CHAT}" message_id="{anchor - 1}">hi</channel>'}]}},
                {'message': {'content': [{'type': 'tool_result', 'tool_use_id': 'old', 'content': f'sent (id: {anchor})'}]}},
                {'message': {'content': [{'type': 'tool_use', 'id': 'old', 'name': 'x', 'input': {}}]}}]
        for index, name in enumerate(tools):
            rows.append({'message': {'content': [{'type': 'tool_use', 'id': f'open{index}', 'name': name, 'input': {}}]}})
        path = self.dir / 'transcript.jsonl'
        path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n')
        return str(path)

    def run_sweep(self, fake, tool='Bash', **kwargs):
        event = {'session_id': 's', 'tool_name': tool, 'transcript_path': self.transcript(**kwargs)}
        return recall.sweep(event, self.now, state_dir=self.state, base=fake.base, sweep_seconds=2.2, **self.sweep_args)  # self.now is truncated to the second

    def test_deletes_only_the_windowed_permission_prompt(self):
        fake = FakeTelegram({
            101: {'kind': 'user', 'text': 'Admiral words', 'buttons': False, 'date': self.now},
            102: {'kind': 'bot', 'text': 'my plain reply', 'buttons': False, 'date': self.now},
            103: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now},
        })
        self.assertEqual(self.run_sweep(fake), [103])
        self.assertEqual(sorted(fake.messages), [101, 102])
        self.assertEqual(fake.stripped, [103])

    def test_never_touches_messages_at_or_below_the_anchor(self):
        fake = FakeTelegram({100: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now}})
        self.assertEqual(self.run_sweep(fake), [])
        self.assertEqual(fake.stripped, [])

    def test_permission_prompt_outside_the_window_is_kept(self):
        fake = FakeTelegram({101: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now - 600}})
        self.assertEqual(self.run_sweep(fake), [])
        self.assertIn(101, fake.messages)

    def test_buttoned_non_permission_message_is_kept(self):
        fake = FakeTelegram({101: {'kind': 'bot', 'text': 'something else', 'buttons': True, 'date': self.now}})
        self.assertEqual(self.run_sweep(fake), [])
        self.assertIn(101, fake.messages)

    def test_a_long_dead_unresolved_call_does_not_block_the_sweep(self):
        # Admiral 7409: an interrupted call from an earlier turn never gets a
        # tool_result; only the newest message's batch can hold a live request.
        path = self.transcript()
        rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
        rows.insert(0, {'message': {'id': 'old-turn', 'content': [{'type': 'tool_use', 'id': 'dead', 'name': 'Bash', 'input': {}}]}})
        Path(path).write_text('\n'.join(json.dumps(row) for row in rows) + '\n')
        fake = FakeTelegram({101: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now}})
        event = {'session_id': 's', 'tool_name': 'Bash', 'transcript_path': path}
        self.assertEqual(recall.sweep(event, self.now, state_dir=self.state, base=fake.base, sweep_seconds=2.2), [101])

    def test_two_same_tool_calls_pending_at_once_are_never_touched(self):
        # Two Bash calls unresolved in one batch: either card could be the
        # other request's live floor ask, so the sweep refuses to guess.
        fake = FakeTelegram({101: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now}})
        self.assertEqual(self.run_sweep(fake, tools=('Bash', 'Bash')), [])
        self.assertEqual(fake.stripped, [])

    def test_parallel_prompts_of_different_tools_are_each_cleaned_by_their_own_sweep(self):
        # Telegram 7862/7865: Bash and WebFetch asked at once, both allowed;
        # the old blanket guard skipped both sweeps and a card stayed live.
        fake = FakeTelegram({
            101: {'kind': 'bot', 'text': '\U0001f510 Permission: Bash', 'buttons': True, 'date': self.now},
            102: {'kind': 'bot', 'text': '\U0001f510 Permission: WebFetch', 'buttons': True, 'date': self.now},
        })
        self.assertEqual(self.run_sweep(fake, tool='Bash', tools=('Bash', 'WebFetch')), [101])
        self.assertEqual(self.run_sweep(fake, tool='WebFetch', tools=('Bash', 'WebFetch')), [102])
        self.assertEqual(sorted(fake.messages), [])

    def test_prompt_that_arrives_late_is_still_caught(self):
        fake = FakeTelegram({})
        timer = threading.Timer(0.4, lambda: fake.messages.__setitem__(101, {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now}))
        timer.start()
        self.assertEqual(self.run_sweep(fake), [101])

    def test_two_same_tool_prompts_in_one_window_are_never_touched(self):
        # The old sweep deleted the first of two same-tool prompts; two prompts
        # this close cannot be told apart, so now neither is touched.
        fake = FakeTelegram({
            101: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now},
            102: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now},
        })
        self.assertEqual(self.run_sweep(fake), [])
        self.assertIn(101, fake.messages)
        self.assertIn(102, fake.messages)

    def test_next_request_prompt_after_the_decision_is_never_touched(self):
        # Telegram 7224: the next request's live floor prompt arrived seconds
        # after this allow and was deleted. Now the sweep has ended by then.
        self.sweep_args = {'settle_seconds': 0.3}
        fake = FakeTelegram({})
        timer = threading.Timer(0.7, lambda: fake.messages.__setitem__(101, {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now}))
        timer.start()
        self.assertEqual(self.run_sweep(fake), [])
        timer.join()
        self.assertEqual(fake.stripped, [])
        self.assertIn(101, fake.messages)

    def test_prompt_dated_after_the_decision_stops_the_sweep(self):
        fake = FakeTelegram({
            101: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now + 30},
            102: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now + 30},
        })
        self.assertEqual(self.run_sweep(fake), [])
        self.assertEqual(sorted(fake.stripped), [101, 102])
        self.assertIn(101, fake.messages)
        self.assertIn(102, fake.messages)

    def test_earlier_sweeps_move_the_anchor_past_a_long_run_of_prompts(self):
        # Admiral 7316: with no new chat text the transcript anchor stayed at
        # 100 while prompts climbed past 112, out of probe range.
        recall.LOG.write_text(json.dumps({'session': 's', 'action': 'swept', 'anchor': 100, 'deleted': [], 'seen': 140}) + '\n')
        fake = FakeTelegram({141: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now}})
        self.assertEqual(self.run_sweep(fake), [141])
        rows = [json.loads(line) for line in recall.LOG.read_text().splitlines()]
        self.assertEqual(rows[-1]['seen'], 141)

    def test_another_sessions_log_never_moves_the_anchor(self):
        recall.LOG.write_text(json.dumps({'session': 'other', 'action': 'swept', 'anchor': 100, 'deleted': [], 'seen': 140}) + '\n')
        fake = FakeTelegram({141: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now}})
        self.assertEqual(self.run_sweep(fake), [])

    def test_no_state_or_ambiguous_chat_does_nothing(self):
        fake = FakeTelegram({101: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now}})
        (self.state / 'access.json').write_text(json.dumps({'allowFrom': [CHAT, '222']}))
        self.assertEqual(self.run_sweep(fake), [])
        self.assertEqual(fake.stripped, [])

    def test_settle_uses_first_seen_when_no_hold_window_and_edits_the_desk_outcome(self):
        # A Desk approval settles a hook-queued item long after the request; the
        # card was posted when the request first hit the gate, so first_seen
        # bounds the window and the outcome names the Desk.
        first = datetime.datetime.now(datetime.timezone.utc)
        item = {'session': 's', 'first_seen': first.isoformat(),
                'request': {'tool_name': 'Bash', 'session_id': 's', 'transcript_path': self.transcript(),
                            'tool_input': {'command': 'printf hello'}}}
        fake = FakeTelegram({101: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': int(first.timestamp())}})
        os.environ['TELEGRAM_STATE_DIR'] = str(self.state)
        os.environ['TELEGRAM_API_BASE'] = fake.base
        try:
            self.assertTrue(recall.settle(item, 'desk_approved'))
        finally:
            del os.environ['TELEGRAM_STATE_DIR']
            del os.environ['TELEGRAM_API_BASE']
        self.assertEqual(fake.edited, [(101, '✅ Approved from the Desk')])

    def test_settle_never_touches_another_tools_card(self):
        first = datetime.datetime.now(datetime.timezone.utc)
        item = {'session': 's', 'first_seen': first.isoformat(),
                'request': {'tool_name': 'Bash', 'session_id': 's', 'transcript_path': self.transcript(tools=('Bash', 'WebFetch')),
                            'tool_input': {'command': 'printf hello'}}}
        fake = FakeTelegram({
            101: {'kind': 'bot', 'text': '\U0001f510 Permission: WebFetch', 'buttons': True, 'date': int(first.timestamp())},
        })
        os.environ['TELEGRAM_STATE_DIR'] = str(self.state)
        os.environ['TELEGRAM_API_BASE'] = fake.base
        try:
            self.assertFalse(recall.settle(item, 'desk_approved'))
        finally:
            del os.environ['TELEGRAM_STATE_DIR']
            del os.environ['TELEGRAM_API_BASE']
        self.assertEqual(fake.edited, [])
        self.assertIn(101, fake.messages)


if __name__ == '__main__':
    unittest.main()
