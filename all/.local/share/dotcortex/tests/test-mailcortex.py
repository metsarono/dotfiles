#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
COMMAND = ROOT / "all/.local/bin/mailcortex"


class MailCortexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "Mail"
        self.registry = self.base / "seats.json"
        seats = {
            name: {"host": "fixture-host", "mailbox": f"seats/{name}"}
            for name in ("leader", "coordinator", "quota-monitor", "outsider")
        }
        self.registry.write_text(json.dumps({
            "schema": "mailcortex.seats.v1",
            "host": "fixture-host",
            "seats": seats,
            "bbs_alerts": {
                "admiral": "leader",
                "coordinator": "coordinator",
                "emitters": ["quota-monitor"],
            },
        }))
        self.registry.chmod(0o600)
        self.usage_cache = self.base / "codex-v2.json"
        self.env = os.environ | {
            "MAILCORTEX_ROOT": str(self.root),
            "MAILCORTEX_SEAT_REGISTRY": str(self.registry),
            "MAILCORTEX_CODEX_USAGE_CACHE": str(self.usage_cache),
        }
        self.address = "reader@node-b.helm"
        self.maildir = self.root / "consorts/reader"
        for leaf in ("tmp", "new", "cur"):
            (self.maildir / leaf).mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_command(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(COMMAND), *args],
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def post_alert(
        self,
        level: str,
        title: str,
        *,
        body: str = "fixture body",
        expires_at: str = "2999-01-01T00:00:00Z",
        issued_by: str = "coordinator",
        scope: str = "fleet",
        supersedes: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = [
            "bbs", "alert", "post", "--issued-by", issued_by,
            "--level", level, "--title", title, "--body", body,
            "--expires-at", expires_at, "--scope", scope,
        ]
        if supersedes:
            args.extend(("--supersedes", supersedes))
        return self.run_command(*args)

    def write_alert_fixture(self, **changes: object) -> dict[str, object]:
        alert: dict[str, object] = {
            "schema": "mailcortex.bbs-alert.v1",
            "level": "notice",
            "title": "Fixture alert",
            "body": "fixture body",
            "issued_by": "coordinator",
            "issued_at": "1999-01-01T00:00:00Z",
            "expires_at": "2000-01-01T00:00:00Z",
            "scope": {"kind": "fleet"},
        }
        alert.update(changes)
        encoded = json.dumps(alert, sort_keys=True, separators=(",", ":")).encode()
        alert_id = hashlib.sha256(encoded).hexdigest()
        alert["id"] = alert_id
        directory = self.root / ".bbs/alerts"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{alert_id}.json").write_text(
            json.dumps(alert, sort_keys=True, separators=(",", ":")) + "\n"
        )
        return alert

    def test_help_is_side_effect_free(self) -> None:
        empty_root = self.base / "absent"
        result = subprocess.run(
            [str(COMMAND), "--help"],
            env=self.env | {"MAILCORTEX_ROOT": str(empty_root)},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(empty_root.exists())

    def test_provision_is_private_idempotent_and_validates_before_writing(self) -> None:
        root = self.base / "fresh-mail"
        self.env["MAILCORTEX_ROOT"] = str(root)
        invalid = self.run_command("provision", "reader@node-b.helm", "../../escape")
        self.assertEqual(invalid.returncode, 2)
        self.assertFalse(root.exists())
        for _ in range(2):
            result = self.run_command(
                "provision", "reader@node-b.helm", "seat+builder@node-a.helm"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        for directory in (
            root, root / "consorts", root / "consorts/reader",
            root / "seats", root / "seats/builder",
            *(root / "consorts/reader" / leaf for leaf in ("tmp", "new", "cur")),
            *(root / "seats/builder" / leaf for leaf in ("tmp", "new", "cur")),
        ):
            self.assertTrue(directory.is_dir(), directory)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700, directory)
        self.assertEqual(list((root / "consorts/reader/new").iterdir()), [])
        sent = self.run_command(
            "send", "--from", "writer@node-a.helm", "--to", "reader@node-b.helm",
            "--subject", "Provisioned", "--body", "hello",
        )
        self.assertEqual(sent.returncode, 0, sent.stderr)
        self.assertEqual(len(list((root / "consorts/reader/new").iterdir())), 1)

    def test_provision_refuses_symlink_address(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        for leaf in ("tmp", "new", "cur"):
            (self.maildir / leaf).rmdir()
        self.maildir.rmdir()
        self.maildir.symlink_to(outside, target_is_directory=True)
        result = self.run_command("provision", self.address)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(list(outside.iterdir()), [])

    def test_send_is_atomic_rfc822_delivery(self) -> None:
        result = self.run_command(
            "send",
            "--from", "sender@node-a.helm",
            "--to", self.address,
            "--subject", "First post",
            "--body", "Read LOGS/handoffs/example.md\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list((self.maildir / "tmp").iterdir()), [])
        delivered = list((self.maildir / "new").iterdir())
        self.assertEqual(len(delivered), 1)
        self.assertEqual(delivered[0].name, result.stdout.strip())
        self.assertEqual(delivered[0].stat().st_mode & 0o777, 0o600)
        message = BytesParser(policy=policy.default).parsebytes(delivered[0].read_bytes())
        self.assertEqual(message["From"], "sender@node-a.helm")
        self.assertEqual(message["To"], self.address)
        self.assertEqual(message["Subject"], "First post")
        self.assertTrue(message["Message-ID"])
        self.assertEqual(message.get_content().strip(), "Read LOGS/handoffs/example.md")
        self.assertFalse(message.is_multipart())
        legacy = type(message)(policy=policy.SMTP)
        for key in ("Date", "From", "To", "Subject", "Message-ID"):
            legacy[key] = message[key]
        legacy.set_content("Read LOGS/handoffs/example.md\n")
        self.assertEqual(delivered[0].read_bytes(), legacy.as_bytes())

    def test_attachments_roundtrip_and_plain_body_remains_readable(self) -> None:
        audio = self.base / "note.ogg"
        unknown = self.base / "raw.unknown-mailcortex"
        audio.write_bytes(b"OggS\x00original")
        unknown.write_bytes(b"\x00\xffraw")
        sent = self.run_command("send", "--from", "sender@node-a.helm",
                                "--to", self.address, "--subject", "voice",
                                "--body", "transcript", "--attach", str(audio),
                                "--attach", str(unknown))
        self.assertEqual(sent.returncode, 0, sent.stderr)
        path = self.maildir / "new" / sent.stdout.strip()
        msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
        self.assertEqual(msg.get_content_type(), "multipart/mixed")
        self.assertEqual(list(msg.iter_parts())[0].get_content_type(), "text/plain")
        parts = list(msg.iter_attachments())
        self.assertEqual([p.get_filename() for p in parts], [audio.name, unknown.name])
        self.assertEqual(parts[0].get_payload(decode=True), audio.read_bytes())
        self.assertEqual(parts[1].get_payload(decode=True), unknown.read_bytes())
        self.assertEqual(parts[1].get_content_type(), "application/octet-stream")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list((self.maildir / "tmp").iterdir()), [])
        read = self.run_command("read", self.address, path.name)
        self.assertIn("\n\ntranscript\n", read.stdout)

    def test_attachment_refusals_never_deliver_partial_mail(self) -> None:
        regular = self.base / "small"
        regular.write_bytes(b"a")
        link = self.base / "link"
        link.symlink_to(regular)
        fifo = self.base / "fifo"
        os.mkfifo(fifo)
        huge = self.base / "huge"
        with huge.open("wb") as stream:
            stream.truncate(25 * 1024 * 1024)
        for bad in (self.base / "absent", link, self.base, fifo, huge):
            sent = self.run_command("send", "--from", "sender@node-a.helm",
                                    "--to", self.address, "--subject", "bad",
                                    "--body", "hello", "--attach", str(regular),
                                    "--attach", str(bad))
            self.assertEqual(sent.returncode, 2, (bad, sent.stderr))
            for leaf in ("tmp", "new"):
                self.assertEqual(list((self.maildir / leaf).iterdir()), [])

    def test_inbox_lists_and_read_moves_to_cur(self) -> None:
        sent = self.run_command(
            "send",
            "--from", "sender@node-a.helm",
            "--to", self.address,
            "--subject", "Move me",
            "--body", "hello",
        )
        name = sent.stdout.strip()
        listing = self.run_command("inbox", self.address)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertIn(f"new\t{name}\t", listing.stdout)
        read = self.run_command("read", self.address, name)
        self.assertEqual(read.returncode, 0, read.stderr)
        self.assertIn("Subject: Move me", read.stdout)
        self.assertIn("\n\nhello\n", read.stdout)
        self.assertFalse((self.maildir / "new" / name).exists())
        self.assertTrue((self.maildir / "cur" / (name + ":2,S")).exists())

    def test_inbox_skips_in_flight_sync_temp_files(self) -> None:
        (self.maildir / "new" / ".syncthing.123.host.tmp").write_bytes(b"Subject: partial\n\n")
        listing = self.run_command("inbox", self.address)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertNotIn(".syncthing", listing.stdout)

    def test_namespaces_and_input_guards(self) -> None:
        for address, expected in (
            ("writer@node-a.helm", "consorts/writer"),
            ("consort+writer@node-a.helm", "consorts/writer"),
            ("seat+builder@node-a.helm", "seats/builder"),
            ("machine+node-b@node-a.helm", "machines/node-b"),
            ("sanctuary+cde@node-a.helm", "sanctuaries/cde"),
        ):
            target = self.root / expected
            for leaf in ("tmp", "new", "cur"):
                (target / leaf).mkdir(parents=True, exist_ok=True)
            result = self.run_command("inbox", address)
            self.assertEqual(result.returncode, 0, (address, result.stderr))
        bad = self.run_command("inbox", "../../escape")
        self.assertEqual(bad.returncode, 2)
        missing = self.run_command("inbox", "unknown@node-a.helm")
        self.assertEqual(missing.returncode, 2)
        traversal = self.run_command("read", self.address, "../message")
        self.assertEqual(traversal.returncode, 2)

    def test_bbs_alert_schema_enum_and_required_expiry(self) -> None:
        posted = self.post_alert("pain", "Transport failed", scope="squadron:forge")
        self.assertEqual(posted.returncode, 0, posted.stderr)
        files = list((self.root / ".bbs/alerts").glob("*.json"))
        self.assertEqual(len(files), 1)
        alert = json.loads(files[0].read_text())
        self.assertEqual(alert, {
            "body": "fixture body",
            "expires_at": "2999-01-01T00:00:00Z",
            "id": posted.stdout.strip(),
            "issued_at": alert["issued_at"],
            "issued_by": "coordinator",
            "level": "pain",
            "schema": "mailcortex.bbs-alert.v1",
            "scope": {"kind": "squadron", "name": "forge"},
            "title": "Transport failed",
        })
        invalid = self.post_alert("emergency", "Unknown level")
        self.assertEqual(invalid.returncode, 2)
        missing_expiry = self.run_command(
            "bbs", "alert", "post", "--issued-by", "coordinator",
            "--level", "notice", "--title", "Missing", "--body", "expiry",
        )
        self.assertEqual(missing_expiry.returncode, 2)
        self.assertEqual(len(list((self.root / ".bbs/alerts").glob("*.json"))), 1)

    def test_bbs_alert_unauthorised_posts_are_refused(self) -> None:
        for seat in ("outsider", "unknown"):
            with self.subTest(seat=seat):
                result = self.post_alert("notice", "Refused", issued_by=seat)
                self.assertEqual(result.returncode, 2)
                self.assertIn("not authorised", result.stderr)
        self.assertFalse((self.root / ".bbs/alerts").exists())

    def test_bbs_alert_current_orders_levels_and_omits_expired(self) -> None:
        for level in ("calm", "notice", "pain", "adrenaline"):
            result = self.post_alert(level, level.title())
            self.assertEqual(result.returncode, 0, result.stderr)
        self.write_alert_fixture(level="pain", title="Old pain")
        current = self.run_command("bbs", "alert", "current", "--json")
        self.assertEqual(current.returncode, 0, current.stderr)
        alerts = json.loads(current.stdout)
        self.assertEqual([item["level"] for item in alerts],
                         ["pain", "adrenaline", "notice", "calm"])
        compact = self.run_command("bbs", "alert", "current")
        self.assertEqual(compact.returncode, 0, compact.stderr)
        self.assertEqual(len(compact.stdout.splitlines()), 4)
        self.assertNotIn("Old pain", compact.stdout)

    def test_bbs_alert_supersession_is_computed_without_mutation(self) -> None:
        original = self.post_alert("notice", "First state")
        self.assertEqual(original.returncode, 0, original.stderr)
        original_id = original.stdout.strip()
        original_path = self.root / ".bbs/alerts" / f"{original_id}.json"
        original_bytes = original_path.read_bytes()
        replacement = self.post_alert(
            "calm", "All clear", body="recovered", supersedes=original_id
        )
        self.assertEqual(replacement.returncode, 0, replacement.stderr)
        current = json.loads(self.run_command("bbs", "alert", "current", "--json").stdout)
        self.assertEqual([item["title"] for item in current], ["All clear"])
        self.assertEqual(original_path.read_bytes(), original_bytes)
        listed = json.loads(self.run_command("bbs", "alert", "list", "--json").stdout)
        self.assertEqual(len(listed), 2)

        future = self.write_alert_fixture(
            title="Future state", issued_at="2998-01-01T00:00:00Z",
            expires_at="2999-01-01T00:00:00Z",
        )
        refused = self.post_alert(
            "calm", "Impossible all clear", supersedes=str(future["id"])
        )
        self.assertEqual(refused.returncode, 2)
        self.assertIn("later record", refused.stderr)
        self.assertEqual(len(list((self.root / ".bbs/alerts").glob("*.json"))), 3)

    def test_reset_emitter_refuses_untrustworthy_signal_without_posting(self) -> None:
        result = self.run_command(
            "bbs", "alert", "emit-reset", "--issued-by", "quota-monitor"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("trustworthy Codex quota signal unavailable", result.stderr)
        self.assertFalse((self.root / ".bbs/alerts").exists())

        self.usage_cache.write_text(json.dumps({
            "ts": 1,
            "result": {"provider": "codex", "state": "ok", "raw": {}},
        }))
        result = self.run_command(
            "bbs", "alert", "emit-reset", "--issued-by", "quota-monitor"
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / ".bbs/alerts").exists())

    def test_reset_emitter_posts_once_from_fresh_absolute_quota_signal(self) -> None:
        observed = datetime.now(timezone.utc).replace(microsecond=0)
        reset = observed + timedelta(minutes=45)
        self.usage_cache.write_text(json.dumps({
            "ts": observed.timestamp(),
            "result": {
                "provider": "codex", "state": "ok", "source": "codex-native",
                "raw": {"provider": "codex", "source": "codex-native",
                        "usage": {"primary": {
                    "usedPercent": 35, "resetsAt": reset.isoformat(),
                }}},
            },
            "backoff_until": 0,
            "backoff_step": 0,
        }))
        args = ("bbs", "alert", "emit-reset", "--issued-by", "quota-monitor")
        first = self.run_command(*args)
        second = self.run_command(*args)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)
        files = list((self.root / ".bbs/alerts").glob("*.json"))
        self.assertEqual(len(files), 1)
        alert = json.loads(files[0].read_text())
        self.assertEqual(alert["level"], "adrenaline")
        self.assertEqual(alert["expires_at"], reset.isoformat().replace("+00:00", "Z"))
        self.assertIn("65% remains", alert["body"])


if __name__ == "__main__":
    unittest.main()
