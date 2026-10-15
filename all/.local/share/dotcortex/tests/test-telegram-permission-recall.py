#!/usr/bin/env python3
"""Recall deletes only windowed permission prompts, against a loopback fake Telegram."""
import http.server
import importlib.util
import json
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

    def transcript(self, *, anchor=100, unresolved=1):
        rows = [{'message': {'content': [{'type': 'text', 'text': f'<channel source="telegram" chat_id="{CHAT}" message_id="{anchor - 1}">hi</channel>'}]}},
                {'message': {'content': [{'type': 'tool_result', 'tool_use_id': 'old', 'content': f'sent (id: {anchor})'}]}},
                {'message': {'content': [{'type': 'tool_use', 'id': 'old', 'name': 'x', 'input': {}}]}}]
        for index in range(unresolved):
            rows.append({'message': {'content': [{'type': 'tool_use', 'id': f'open{index}', 'name': 'Bash', 'input': {}}]}})
        path = self.dir / 'transcript.jsonl'
        path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n')
        return str(path)

    def run_sweep(self, fake, **kwargs):
        event = {'session_id': 's', 'transcript_path': self.transcript(**kwargs)}
        return recall.sweep(event, self.now, state_dir=self.state, base=fake.base, sweep_seconds=1.2)

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

    def test_skips_entirely_while_another_request_is_pending(self):
        fake = FakeTelegram({101: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now}})
        self.assertEqual(self.run_sweep(fake, unresolved=2), [])
        self.assertEqual(fake.stripped, [])

    def test_prompt_that_arrives_late_is_still_caught(self):
        fake = FakeTelegram({})
        timer = threading.Timer(0.4, lambda: fake.messages.__setitem__(101, {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now}))
        timer.start()
        self.assertEqual(self.run_sweep(fake), [101])

    def test_no_state_or_ambiguous_chat_does_nothing(self):
        fake = FakeTelegram({101: {'kind': 'bot', 'text': PERM, 'buttons': True, 'date': self.now}})
        (self.state / 'access.json').write_text(json.dumps({'allowFrom': [CHAT, '222']}))
        self.assertEqual(self.run_sweep(fake), [])
        self.assertEqual(fake.stripped, [])


if __name__ == '__main__':
    unittest.main()
