#!/usr/bin/env python3
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[3] / "bin" / "ai-usage"


def load_ai_usage():
    loader = importlib.machinery.SourceFileLoader("dotcortex_ai_usage", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class CodexAllowanceWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ai_usage = load_ai_usage()

    def test_monthly_window_uses_monthly_summary(self):
        reset_at = datetime.now(timezone.utc) + timedelta(days=25, hours=12)
        result = self.ai_usage.build_codex_native_result(
            next(spec for spec in self.ai_usage.PROVIDERS if spec.key == "codex"),
            {
                "plan_type": "go",
                "rate_limit": {
                    "secondary_window": {
                        "used_percent": 7,
                        "limit_window_seconds": 30 * 24 * 60 * 60,
                        "reset_at": reset_at.timestamp(),
                    }
                },
            },
        )

        self.assertEqual(result["summary"], "30d 7%; plan=go")
        self.assertEqual(result["raw"]["usage"]["secondary"]["windowMinutes"], 43200)

    def test_monthly_pacing_scales_over_full_cycle(self):
        now = datetime(2026, 9, 15, tzinfo=timezone.utc)
        reset_at = now + timedelta(days=25)
        line = self.ai_usage.format_window_left_line("pace", reset_at.isoformat(), 43200, now)
        plain = self.ai_usage.ANSI_ESCAPE_RE.sub("", line)

        self.assertRegex(plain, re.compile(r"pace\s+.*83% of 30d cycle"))

    def test_weekly_pacing_uses_pace_label_and_keeps_week_semantics(self):
        now = datetime(2026, 9, 15, tzinfo=timezone.utc)
        reset_at = now + timedelta(days=3, hours=12)
        line = self.ai_usage.format_window_left_line("pace", reset_at.isoformat(), 10080, now)
        plain = self.ai_usage.ANSI_ESCAPE_RE.sub("", line)

        self.assertRegex(plain, re.compile(r"pace\s+.*50% of week \d+"))
        fallback = self.ai_usage.format_window_left_line("pace", reset_at.isoformat(), now=now)
        fallback_plain = self.ai_usage.ANSI_ESCAPE_RE.sub("", fallback)
        self.assertRegex(fallback_plain, re.compile(r"pace\s+.*50% of week \d+"))

        result = self.ai_usage.build_codex_native_result(
            next(spec for spec in self.ai_usage.PROVIDERS if spec.key == "codex"),
            {
                "rate_limit": {
                    "secondary_window": {
                        "used_percent": 7,
                        "limit_window_seconds": 7 * 24 * 60 * 60,
                        "reset_at": reset_at.timestamp(),
                    }
                },
            },
        )
        self.assertEqual(result["summary"], "weekly 7%")

        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now if tz else now.replace(tzinfo=None)

        output = io.StringIO()
        with patch.object(self.ai_usage, "datetime", FixedDateTime), redirect_stdout(output):
            self.ai_usage.render_text([result])
        rendered = self.ai_usage.ANSI_ESCAPE_RE.sub("", output.getvalue())
        self.assertRegex(rendered, re.compile(r"1w\s+.*93%"))
        self.assertRegex(rendered, re.compile(r"pace\s+.*50% of week \d+"))

    def test_renderer_never_calls_monthly_allowance_a_week(self):
        fixed_now = datetime(2026, 9, 15, tzinfo=timezone.utc)

        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed_now if tz else fixed_now.replace(tzinfo=None)

        item = {
            "provider": "codex",
            "label": "Codex",
            "state": "ok",
            "source": "codex-native",
            "summary": "30d 7%; plan=go",
            "raw": {
                "usage": {
                    "secondary": {
                        "usedPercent": 7,
                        "windowMinutes": 43200,
                        "resetsAt": (fixed_now + timedelta(days=25)).isoformat(),
                    },
                    "identity": {"plan": "go"},
                },
                "resetCredits": {"availableCount": 0, "credits": []},
            },
        }

        output = io.StringIO()
        with patch.object(self.ai_usage, "datetime", FixedDateTime), redirect_stdout(output):
            self.ai_usage.render_text([item])
        plain = self.ai_usage.ANSI_ESCAPE_RE.sub("", output.getvalue())

        self.assertRegex(plain, re.compile(r"30d\s+.*93%"))
        self.assertRegex(plain, re.compile(r"pace\s+.*83% of 30d cycle"))
        self.assertNotRegex(plain, re.compile(r"wk\s+.*100%"))


# Redacted fixture: the real 2026-09-25 /v1/quota shape (including the
# undocumented legacy/new credit fields), synthetic values, key name removed.
NEURALWATT_FIXTURE = {
    "snapshot_at": "2026-09-25T02:50:00Z",
    "balance": {
        "credits_remaining_usd": 12.5,
        "total_credits_usd": 20.0,
        "credits_used_usd": 7.5,
        "accounting_method": "token",
        "legacy_credits_usd": 0.0,
        "new_credits_usd": 12.5,
    },
    "usage": {
        "lifetime": {"cost_usd": 7.5, "requests": 900, "tokens": 4000000, "energy_kwh": 1.2},
        "current_month": {"cost_usd": 1.25, "requests": 100, "tokens": 500000, "energy_kwh": 0.2},
    },
    "limits": {"overage_limit_usd": None, "rate_limit_tier": "standard"},
    "subscription": None,
    "key": {"name": "REDACTED", "allowance": None},
}


class NeuralWattObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ai_usage = load_ai_usage()
        cls.now = datetime(2026, 9, 25, 3, 0, tzinfo=timezone.utc)

    def ok(self, raw):
        return {"provider": "neuralwatt", "label": "NeuralWatt", "state": "ok", "source": "api", "summary": "", "raw": raw}

    def test_credit_account_fixture(self):
        result = self.ai_usage.apply_neuralwatt_observation(self.ok(NEURALWATT_FIXTURE), self.now)
        self.assertEqual(result["state"], "ok")
        obs = result["observation"]
        self.assertEqual(obs["schema"], "neuralwatt.quota.v1")
        self.assertEqual(obs["observed_at"], "2026-09-25T02:50:00Z")
        self.assertEqual(obs["collected_at"], "2026-09-25T03:00:00+00:00")
        self.assertEqual(obs["balance"]["remaining_usd"], 12.5)
        self.assertIsNone(obs["subscription"])
        self.assertIsNone(obs["key_allowance"])
        self.assertEqual(result["summary"], "balance $12.50; month $1.25; no subscription")

    def test_subscription_and_key_allowance_stay_separate(self):
        raw = dict(NEURALWATT_FIXTURE)
        raw["subscription"] = {
            "plan": "pro", "status": "active", "billing_interval": "month",
            "current_period_start": "2026-09-01T00:00:00Z", "current_period_end": "2026-10-01T00:00:00Z",
            "auto_renew": True, "kwh_included": 10.0, "kwh_used": 4.0, "kwh_remaining": 6.0, "in_overage": False,
        }
        raw["key"] = {"name": "REDACTED", "allowance": {
            "limit_usd": 5.0, "period": "daily", "spent_usd": 1.0, "remaining_usd": 4.0, "blocked": False}}
        result = self.ai_usage.apply_neuralwatt_observation(self.ok(raw), self.now)
        obs = result["observation"]
        self.assertEqual(obs["subscription"]["kwh_remaining"], 6.0)
        self.assertEqual(obs["key_allowance"]["remaining_usd"], 4.0)
        self.assertEqual(obs["balance"]["remaining_usd"], 12.5)
        self.assertEqual(result["summary"], "balance $12.50; month $1.25; pro active 4/10 kWh; key daily $4.00 left")

    def test_schema_drift_is_an_error_not_a_guess(self):
        raw = {k: v for k, v in NEURALWATT_FIXTURE.items() if k != "balance"}
        result = self.ai_usage.apply_neuralwatt_observation(self.ok(raw), self.now)
        self.assertEqual(result["state"], "error")
        self.assertIn("missing balance", result["summary"])
        self.assertNotIn("observation", result)

    def test_non_ok_probe_passes_through(self):
        failed = {"provider": "neuralwatt", "label": "NeuralWatt", "state": "error", "source": "api",
                  "summary": "https://api.neuralwatt.com/v1/quota returned HTTP 429", "raw": None}
        self.assertIs(self.ai_usage.apply_neuralwatt_observation(failed, self.now), failed)


# Redacted fixture: the real 2026-09-25 GET /zen/go/v1/usage shape (keys/types
# confirmed live), synthetic values, no identifiers. There is no per-model or
# dollar field in this API: each window is percent used + ISO reset + status.
OPENCODE_GO_FIXTURE = {
    "usage": {
        "rolling": {"percent": 17, "resetsAt": "2026-09-25T07:30:00Z", "status": "ok"},
        "weekly": {"percent": 75, "resetsAt": "2026-09-28T00:00:00Z", "status": "ok"},
        "monthly": {"percent": 91, "resetsAt": "2026-10-01T00:00:00Z", "status": "ok"},
    }
}


class OpenCodeGoObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ai_usage = load_ai_usage()
        cls.now = datetime(2026, 9, 25, 3, 0, tzinfo=timezone.utc)

    def ok(self, raw):
        return {"provider": "opencode-go", "label": "OpenCode Go", "state": "ok",
                "source": "api", "summary": "", "raw": raw}

    def test_window_fixture(self):
        result = self.ai_usage.apply_opencode_go_observation(self.ok(OPENCODE_GO_FIXTURE), self.now)
        self.assertEqual(result["state"], "ok")
        obs = result["observation"]
        self.assertEqual(obs["schema"], "opencode-go.usage.v1")
        self.assertEqual(obs["collected_at"], "2026-09-25T03:00:00+00:00")
        self.assertEqual(obs["windows"]["rolling"]["used_percent"], 17)
        self.assertEqual(obs["windows"]["rolling"]["remaining_percent"], 83)
        self.assertEqual(obs["windows"]["monthly"]["resets_at"], "2026-10-01T00:00:00Z")
        self.assertEqual(result["summary"], "tightest 30d 91% used")

    def test_window_at_limit(self):
        raw = json.loads(json.dumps(OPENCODE_GO_FIXTURE))
        raw["usage"]["rolling"] = {"percent": 100, "resetsAt": "2026-09-25T07:30:00Z", "status": "ok"}
        result = self.ai_usage.apply_opencode_go_observation(self.ok(raw), self.now)
        self.assertEqual(result["state"], "ok")
        self.assertEqual(result["observation"]["windows"]["rolling"]["remaining_percent"], 0)
        self.assertEqual(result["summary"], "tightest 5h 100% used")

    def test_non_ok_status_is_surfaced(self):
        raw = json.loads(json.dumps(OPENCODE_GO_FIXTURE))
        raw["usage"]["monthly"]["status"] = "blocked"
        result = self.ai_usage.apply_opencode_go_observation(self.ok(raw), self.now)
        self.assertEqual(result["summary"], "tightest 30d 91% used; 30d status=blocked")

    def test_schema_drift_missing_window_is_an_error(self):
        raw = json.loads(json.dumps(OPENCODE_GO_FIXTURE))
        del raw["usage"]["weekly"]
        result = self.ai_usage.apply_opencode_go_observation(self.ok(raw), self.now)
        self.assertEqual(result["state"], "error")
        self.assertIn("missing usage.weekly", result["summary"])
        self.assertNotIn("observation", result)

    def test_out_of_range_percent_is_an_error(self):
        raw = json.loads(json.dumps(OPENCODE_GO_FIXTURE))
        raw["usage"]["rolling"]["percent"] = 170
        result = self.ai_usage.apply_opencode_go_observation(self.ok(raw), self.now)
        self.assertEqual(result["state"], "error")
        self.assertIn("outside 0-100", result["summary"])

    def test_non_ok_probe_passes_through(self):
        failed = {"provider": "opencode-go", "label": "OpenCode Go", "state": "error",
                  "source": "api", "summary": "HTTP 429", "raw": None}
        self.assertIs(self.ai_usage.apply_opencode_go_observation(failed, self.now), failed)

    def test_renderer_draws_all_three_windows(self):
        fixed_now = datetime(2026, 9, 25, 3, 0, tzinfo=timezone.utc)

        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed_now if tz else fixed_now.replace(tzinfo=None)

        result = self.ai_usage.apply_opencode_go_observation(self.ok(OPENCODE_GO_FIXTURE), fixed_now)
        output = io.StringIO()
        with patch.object(self.ai_usage, "datetime", FixedDateTime), redirect_stdout(output):
            self.ai_usage.render_text([result])
        plain = self.ai_usage.ANSI_ESCAPE_RE.sub("", output.getvalue())

        self.assertRegex(plain, re.compile(r"5h\s+.*83%"))
        self.assertRegex(plain, re.compile(r"wk\s+.*25%"))
        self.assertRegex(plain, re.compile(r"wk pace\s+.*41% of week \d+"))
        self.assertRegex(plain, re.compile(r"30d\s+.*9%"))
        self.assertRegex(plain, re.compile(r"30d pace\s+.*20% of 30d cycle"))


class OpenCodeGoCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ai_usage = load_ai_usage()

    def test_env_key_wins_over_auth_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = Path(tmp) / "auth.json"
            auth.write_text(json.dumps({"opencode-go": {"type": "api", "key": "file-key"}}), encoding="utf-8")
            captured = {}

            def fake_probe(provider, label, url, token, timeout_seconds, summarize=None):
                captured["provider"] = provider
                captured["token"] = token
                captured["url"] = url
                return {"provider": provider, "label": label, "state": "error", "source": "api",
                        "summary": "stub", "raw": None}

            with patch.dict(os.environ, {"OPENCODE_API_KEY": "env-key"}), \
                 patch.object(self.ai_usage, "OPENCODE_AUTH_FILE", auth), \
                 patch.object(self.ai_usage, "_bearer_json_probe", side_effect=fake_probe):
                result = self.ai_usage.fetch_opencode_go(1.0)

            self.assertEqual(captured["token"], "env-key")
            self.assertEqual(captured["provider"], "opencode-go")
            self.assertEqual(result["state"], "error")

    def test_auth_file_key_used_when_env_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = Path(tmp) / "auth.json"
            auth.write_text(
                json.dumps({"openai": {}, "opencode-go": {"type": "api", "key": "file-key"}}),
                encoding="utf-8",
            )
            captured = {}

            def fake_probe(provider, label, url, token, timeout_seconds, summarize=None):
                captured["token"] = token
                return {"provider": provider, "label": label, "state": "ok", "source": "api",
                        "summary": "", "raw": json.loads(json.dumps(OPENCODE_GO_FIXTURE))}

            with patch.dict(os.environ, {"OPENCODE_API_KEY": ""}), \
                 patch.object(self.ai_usage, "OPENCODE_AUTH_FILE", auth), \
                 patch.object(self.ai_usage, "_bearer_json_probe", side_effect=fake_probe):
                result = self.ai_usage.fetch_opencode_go(1.0)

            self.assertEqual(captured["token"], "file-key")
            self.assertEqual(result["state"], "ok")

    def test_no_credential_reports_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "auth.json"
            with patch.dict(os.environ, {"OPENCODE_API_KEY": ""}), \
                 patch.object(self.ai_usage, "OPENCODE_AUTH_FILE", missing):
                result = self.ai_usage.fetch_opencode_go(1.0)
        self.assertEqual(result["state"], "missing")
        self.assertNotIn("token", result)


class ResultOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ai_usage = load_ai_usage()

    def test_provider_grouping_puts_local_before_remote(self):
        items = [
            {"provider": "codex", "label": "Codex"},
            {"provider": "claude", "label": "Claude Code"},
            {"provider": "opencode-go", "label": "OpenCode Go"},
            {"provider": "openrouter", "label": "OpenRouter"},
            {"provider": "mistral", "label": "Mistral"},
            {"provider": "neuralwatt", "label": "NeuralWatt"},
            {"provider": "codex", "label": "Gillean · Codex", "remote": "Gillean"},
            {"provider": "claude", "label": "Gillean · Claude Code", "remote": "Gillean"},
        ]
        # 2026-10-09: mistral above the reserve tank, which groups openrouter +
        # neuralwatt beneath the subscription gauges (Admiral's panel order).
        self.assertEqual(
            [item["label"] for item in self.ai_usage.order_results(items)],
            ["Codex", "Gillean · Codex", "Claude Code", "Gillean · Claude Code",
             "OpenCode Go", "Mistral", "OpenRouter", "NeuralWatt"],
        )

    def test_remote_panels_keep_file_order_and_unknowns_go_last(self):
        items = [
            {"provider": "neuralwatt", "label": "NeuralWatt"},
            {"provider": "codex", "label": "Gillean · Codex", "remote": "Gillean"},
            {"provider": "codex", "label": "X230 · Codex", "remote": "X230"},
            {"provider": "codex", "label": "Codex"},
        ]
        self.assertEqual(
            [item["label"] for item in self.ai_usage.order_results(items)],
            ["Codex", "Gillean · Codex", "X230 · Codex", "NeuralWatt"],
        )


MISTRAL_WHOAMI_FIXTURE = {
    "plan_type": "API",
    "plan_name": "FREE",
    "prompt_switching_to_pro_plan": True,
    "organization_kind": "S",
    "customer_id": "25587b01-3447-483d-b6ac-7bc2caf053f3",
    "api_base": "https://api.mistral.ai",
    "vibe_base": "https://chat.mistral.ai",
    "primitive_access_scope": "personal_and_shared",
}

MISTRAL_BUDGET_FIXTURE = {
    "usage_percentage": 61.051076,
    "initial_budget": 30,
    "currency": "USD",
    "reset_at": "2026-11-01T00:00:00Z",
    "api_budget": {
        "usage_percentage": 61.051076,
        "initial_budget": 30,
        "currency": "USD",
        "reset_at": "2026-11-01T00:00:00Z",
    },
    "vibe_budget": {
        "usage_percentage": 0.53698893,
        "initial_budget": 300,
        "currency": "USD",
        "reset_at": "2026-11-01T00:00:00Z",
    },
}


def _no_cookie_jar(ai_usage):
    """Patch helper: disable the admin-trpc cookie path for whoami-era tests."""
    return patch.object(ai_usage, "_mistral_cookie_header", return_value="")


class MistralProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ai_usage = load_ai_usage()

    def test_no_credential_reports_missing(self):
        with patch.dict(os.environ, {"MISTRAL_API_KEY": "", "MISTRAL_VIBE_API_KEY": ""}), \
             patch.object(self.ai_usage, "load_dotenv_exports", return_value={}), \
             _no_cookie_jar(self.ai_usage):
            result = self.ai_usage.fetch_mistral(1.0)
        self.assertEqual(result["state"], "missing")
        self.assertEqual(result["provider"], "mistral")
        self.assertIn("MISTRAL_API_KEY", result["summary"])

    def test_whoami_success_reports_plan_and_never_fabricates_percentage(self):
        captured = {}

        def fake_probe(provider, label, url, token, timeout_seconds, summarize=None):
            captured["token"] = token
            captured["url"] = url
            payload = json.loads(json.dumps(MISTRAL_WHOAMI_FIXTURE))
            summary = summarize(payload) if summarize else ""
            return {"provider": provider, "label": label, "state": "ok", "source": "api",
                    "summary": summary, "raw": payload}

        with patch.dict(os.environ, {"MISTRAL_API_KEY": "test-key", "MISTRAL_VIBE_API_KEY": ""}), \
             patch.object(self.ai_usage, "_bearer_json_probe", side_effect=fake_probe), \
             _no_cookie_jar(self.ai_usage):
            result = self.ai_usage.fetch_mistral(1.0)

        self.assertEqual(captured["token"], "test-key")
        self.assertEqual(result["state"], "ok")
        self.assertEqual(result["identity"]["plan_name"], "FREE")
        self.assertEqual(result["identity"]["customer_id"], "25587b01-3447-483d-b6ac-7bc2caf053f3")
        # The fallback summary must stay truthful: no percentage number, explicit
        # pointer to the console/Admin API for the actual usage figure.
        self.assertIn("plan=FREE", result["summary"])
        self.assertIn("usage % needs console session or Admin API key", result["summary"])
        self.assertNotRegex(result["summary"], r"\d+(\.\d+)?%")

    def test_budget_from_cookie_jar_reports_real_percentages(self):
        """The admin-trpc path reports the console's real budget numbers."""
        captured = {}

        def fake_trpc(endpoint, params, timeout_seconds):
            captured["endpoint"] = endpoint
            return json.loads(json.dumps(MISTRAL_BUDGET_FIXTURE))

        with patch.object(self.ai_usage, "_mistral_trpc", side_effect=fake_trpc):
            result = self.ai_usage.fetch_mistral(1.0)

        self.assertEqual(captured["endpoint"], "billing.budget")
        self.assertEqual(result["state"], "ok")
        self.assertEqual(result["source"], "admin-trpc")
        self.assertEqual(result["identity"]["plan_name"], "Pro")
        # Standard quota shape (2026-10-09): budgets render as gauges like every
        # other panel — primary=Vibe, secondary=API, each with usedPercent,
        # windowMinutes (30d), resetsAt, label.
        primary = result["usage"]["primary"]
        secondary = result["usage"]["secondary"]
        self.assertAlmostEqual(primary["usedPercent"], 0.53698893)
        self.assertAlmostEqual(secondary["usedPercent"], 61.051076)
        self.assertEqual(primary["label"], "Vibe")
        self.assertEqual(secondary["label"], "API")
        self.assertEqual(primary["windowMinutes"], 30 * 24 * 60)
        self.assertEqual(secondary["resetsAt"], "2026-11-01T00:00:00Z")
        self.assertIn("$18.32/$30", result["summary"])
        self.assertIn("61.1%", result["summary"])
        self.assertIn("Vibe", result["summary"])
        self.assertIn("resets 2026-11-01", result["summary"])

    def test_budget_trpc_failure_falls_back_to_whoami(self):
        """No cookie session -> whoami identity only, never a fabricated number."""
        def fake_probe(provider, label, url, token, timeout_seconds, summarize=None):
            payload = json.loads(json.dumps(MISTRAL_WHOAMI_FIXTURE))
            summary = summarize(payload) if summarize else ""
            return {"provider": provider, "label": label, "state": "ok", "source": "api",
                    "summary": summary, "raw": payload}

        with patch.dict(os.environ, {"MISTRAL_API_KEY": "test-key", "MISTRAL_VIBE_API_KEY": ""}), \
             patch.object(self.ai_usage, "_bearer_json_probe", side_effect=fake_probe), \
             _no_cookie_jar(self.ai_usage):
            result = self.ai_usage.fetch_mistral(1.0)

        self.assertEqual(result["state"], "ok")
        self.assertEqual(result["identity"]["plan_name"], "FREE")
        self.assertNotIn("usage", result)

    def test_no_jar_configured_skips_budget_probe_and_says_so(self):
        """MISTRAL_COOKIE_JAR unset => budget probe skipped, output says why,
        and the fallback never fabricates a budget number."""
        def fake_probe(provider, label, url, token, timeout_seconds, summarize=None):
            payload = json.loads(json.dumps(MISTRAL_WHOAMI_FIXTURE))
            summary = summarize(payload) if summarize else ""
            return {"provider": provider, "label": label, "state": "ok", "source": "api",
                    "summary": summary, "raw": payload}

        def fail_http(*args, **kwargs):
            raise AssertionError("budget probe must not touch the network when the jar is unset")

        # Empty cookie header => real _mistral_trpc returns None before any HTTP,
        # so urlopen staying untouched proves the probe was skipped.
        # load_dotenv_exports patched empty + vibe key cleared: the jar path is
        # resolved at call time (2026-10-09), so host env must not leak in.
        with patch.dict(os.environ, {"MISTRAL_COOKIE_JAR": "", "MISTRAL_API_KEY": "test-key", "MISTRAL_VIBE_API_KEY": ""}), \
             patch.object(self.ai_usage, "load_dotenv_exports", return_value={}), \
             patch.object(self.ai_usage, "_mistral_cookie_header", return_value=""), \
             patch.object(self.ai_usage.urllib.request, "urlopen", side_effect=fail_http), \
             patch.object(self.ai_usage, "_bearer_json_probe", side_effect=fake_probe):
            result = self.ai_usage.fetch_mistral(1.0)

        self.assertEqual(result["state"], "ok")
        self.assertIn("MISTRAL_COOKIE_JAR not set", result["summary"])
        # Plan identity still surfaces; no budget percentage is invented.
        self.assertEqual(result["identity"]["plan_name"], "FREE")
        self.assertNotIn("usage", result)

    def test_tangled_script_has_no_home_paths(self):
        """DotCortex is public: no username/host path may leak into the tangled
        script. Fails if any '/home/' literal appears in ai-usage source."""
        script = Path(self.ai_usage.__file__).read_text()
        self.assertNotIn("/home/", script)

    def test_http_error_surfaces_status_without_crashing(self):
        def fake_probe(provider, label, url, token, timeout_seconds, summarize=None):
            return {"provider": provider, "label": label, "state": "error", "source": "api",
                    "summary": f"{url} returned HTTP 401", "raw": None}

        with patch.dict(os.environ, {"MISTRAL_API_KEY": "bad-key", "MISTRAL_VIBE_API_KEY": ""}), \
             patch.object(self.ai_usage, "_bearer_json_probe", side_effect=fake_probe), \
             _no_cookie_jar(self.ai_usage):
            result = self.ai_usage.fetch_mistral(1.0)

        self.assertEqual(result["state"], "error")
        self.assertIn("HTTP 401", result["summary"])
        self.assertNotIn("identity", result)

    def test_mistral_is_registered_and_default_visible(self):
        keys = [spec.key for spec in self.ai_usage.PROVIDERS]
        self.assertIn("mistral", keys)
        self.assertIn("mistral", self.ai_usage.DEFAULT_PROVIDER_KEYS)
        self.assertIn("mistral", self.ai_usage.PROVIDER_DISPLAY_ORDER)

    def test_renderer_shows_mistral_plan_line(self):
        result = {
            "provider": "mistral",
            "label": "Mistral",
            "state": "ok",
            "source": "api",
            "summary": "plan=FREE; type=API; usage % needs console session or Admin API key",
            "raw": dict(MISTRAL_WHOAMI_FIXTURE),
            "identity": {"plan_name": "FREE", "organization_kind": "S"},
        }
        output = io.StringIO()
        with redirect_stdout(output):
            self.ai_usage.render_text([result])
        plain = self.ai_usage.ANSI_ESCAPE_RE.sub("", output.getvalue())
        self.assertIn("Mistral", plain)
        self.assertIn("Plan: FREE", plain)
        self.assertIn("usage % needs console session or Admin API key", plain)

    def test_whoami_prefers_vibe_key_over_api_key(self):
        """Fix 2026-10-09: whoami must report the Vibe subscription, so
        MISTRAL_VIBE_API_KEY wins when both keys exist. The Studio
        MISTRAL_API_KEY reports the free API plan and masks the sub."""
        captured = {}

        def fake_probe(provider, label, url, token, timeout_seconds, summarize=None):
            captured["token"] = token
            payload = json.loads(json.dumps(MISTRAL_WHOAMI_FIXTURE))
            payload["plan_name"] = "INDIVIDUAL"
            payload["plan_type"] = "CHAT"
            summary = summarize(payload) if summarize else ""
            return {"provider": provider, "label": label, "state": "ok", "source": "api",
                    "summary": summary, "raw": payload}

        with patch.dict(os.environ, {"MISTRAL_VIBE_API_KEY": "vibe-key", "MISTRAL_API_KEY": ""}), \
             patch.object(self.ai_usage, "_bearer_json_probe", side_effect=fake_probe), \
             _no_cookie_jar(self.ai_usage):
            result = self.ai_usage.fetch_mistral(1.0)

        self.assertEqual(captured["token"], "vibe-key")
        self.assertEqual(result["identity"]["plan_name"], "INDIVIDUAL")

    def test_mistral_budgets_render_as_standard_quotas(self):
        """Admiral pattern conformance (2026-10-09): the budget dicts must land
        in raw.usage.primary/secondary in the same shape _codex_window_to_quota
        emits ({usedPercent, windowMinutes, resetsAt ISO}), so the existing
        format_compact_quota_line renderer draws bars and countdowns with no
        bespoke Mistral path."""
        def fake_trpc(endpoint, params, timeout_seconds):
            return json.loads(json.dumps(MISTRAL_BUDGET_FIXTURE))

        with patch.object(self.ai_usage, "_mistral_trpc", side_effect=fake_trpc):
            result = self.ai_usage.fetch_mistral(1.0)

        for slot in ("primary", "secondary"):
            quota = result["usage"][slot]
            self.assertIn("usedPercent", quota)
            self.assertIsInstance(quota["windowMinutes"], int)
            self.assertIn("resetsAt", quota)
            self.assertIn(quota["resetsAt"], "2026-11-01T00:00:00Z")
            # The existing renderer must produce a bar line from it.
            label = quota.get("label") or ("Vibe" if slot == "primary" else "API")
            line = self.ai_usage.format_compact_quota_line(label, quota)
            self.assertIsNotNone(line, f"{slot} quota did not render")
            self.assertIn("%", line)

    def test_cookie_jar_resolved_from_dotenv_at_call_time(self):
        """Fix 2026-10-09: the jar path used to be baked in at import time, so a
        MISTRAL_COOKIE_JAR deployed only in ~/.env (untracked env file, not
        exported by shells since 2026-09-25) was invisible outside login
        shells. Call-time resolution must see the dotenv value."""
        with patch.dict(os.environ, {"MISTRAL_COOKIE_JAR": ""}, clear=False), \
             patch.object(self.ai_usage, "load_dotenv_exports",
                          return_value={"MISTRAL_COOKIE_JAR": "/tmp/fake-jar.path"}):
            path = self.ai_usage._mistral_cookie_jar_path()
        self.assertEqual(path, "/tmp/fake-jar.path")


class OpenRouterProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ai_usage = load_ai_usage()

    def test_openrouter_spec_is_native_not_codexbar(self):
        """Fix 2026-10-09: codexbar's openrouter fetch needs cookie auth (web
        session), which no Linux host has. The spec must be the native kind."""
        spec = next(s for s in self.ai_usage.PROVIDERS if s.key == "openrouter")
        self.assertEqual(spec.kind, "openrouter")

    def test_openrouter_native_reads_credits_and_key_endpoints(self):
        """The native probe hits OpenRouter's own /credits and /auth/key with
        the OPENROUTER_API_KEY bearer and reports the real balance."""
        captured = []

        def fake_probe(provider, label, url, token, timeout_seconds, summarize=None):
            captured.append(url)
            if url.endswith("/credits"):
                return {"provider": provider, "label": label, "state": "ok", "source": "api",
                        "summary": "", "raw": {"data": {"total_credits": 50, "total_usage": 0.5}}}
            return {"provider": provider, "label": label, "state": "ok", "source": "api",
                    "summary": "", "raw": {"data": {"usage": 0.000413, "label": "sk-or-v1-test"}}}

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "or-key"}), \
             patch.object(self.ai_usage, "_bearer_json_probe", side_effect=fake_probe):
            result = self.ai_usage.fetch_openrouter(1.0)

        self.assertIn("https://openrouter.ai/api/v1/credits", captured)
        self.assertIn("https://openrouter.ai/api/v1/auth/key", captured)
        self.assertEqual(result["state"], "ok")
        self.assertEqual(result["summary"], "balance=$49.5; keyUsage=$0.000413; loginMethod=Balance: $49.5")
        self.assertEqual(result["raw"]["usage"]["openRouterUsage"]["balance"], 49.5)

    def test_openrouter_missing_key_reports_missing(self):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": ""}), \
             patch.object(self.ai_usage, "load_dotenv_exports", return_value={}):
            result = self.ai_usage.fetch_openrouter(1.0)
        self.assertEqual(result["state"], "missing")
        self.assertIn("OPENROUTER_API_KEY", result["summary"])


class NeuralWattAddendumTests(unittest.TestCase):
    """2026-10-09 addendum: console session, 7-day burn, reserve grouping,
    offer alert from the coordinator feed."""

    @classmethod
    def setUpClass(cls):
        cls.ai_usage = load_ai_usage()

    def test_console_session_unset_falls_back_to_api_key(self):
        """NEURALWATT_COOKIE_JAR unset -> API-key numbers, no console note."""
        with patch.dict(os.environ, {"NEURALWATT_COOKIE_JAR": ""}, clear=False), \
             patch.object(self.ai_usage, "load_dotenv_exports", return_value={}), \
             patch.object(self.ai_usage, "_neuralwatt_console_usage", return_value=None), \
             patch.object(self.ai_usage, "_neuralwatt_seven_day_burn", return_value=None), \
             patch.object(self.ai_usage, "_neuralwatt_active_offer", return_value=None):
            # _env_token must find no key -> patch it too, plus the bearer probe
            with patch.dict(os.environ, {"NEURALWATT_API_KEY": "nw-key"}), \
                 patch.object(self.ai_usage, "_bearer_json_probe", side_effect=lambda *a, **k: {
                     "provider": "neuralwatt", "label": "NeuralWatt", "state": "ok",
                     "source": "api", "summary": "", "raw": NEURALWATT_FIXTURE}):
                result = self.ai_usage.fetch_neuralwatt(1.0)
        self.assertEqual(result["state"], "ok")
        self.assertNotIn("console session", result["summary"])

    def test_console_session_failure_says_so(self):
        """Jar set but session fails -> summary says so, numbers stay API-key."""
        raw = json.loads(json.dumps(NEURALWATT_FIXTURE))
        with patch.dict(os.environ, {"NEURALWATT_COOKIE_JAR": "/tmp/nw.jar", "NEURALWATT_API_KEY": "nw-key"}), \
             patch.object(self.ai_usage, "load_dotenv_exports", return_value={}), \
             patch.object(self.ai_usage, "_neuralwatt_console_usage", return_value=None), \
             patch.object(self.ai_usage, "_neuralwatt_seven_day_burn", return_value=None), \
             patch.object(self.ai_usage, "_neuralwatt_active_offer", return_value=None), \
             patch.object(self.ai_usage, "_bearer_json_probe", side_effect=lambda *a, **k: {
                 "provider": "neuralwatt", "label": "NeuralWatt", "state": "ok",
                 "source": "api", "summary": "", "raw": raw}):
            result = self.ai_usage.fetch_neuralwatt(1.0)
        self.assertEqual(result["state"], "ok")
        self.assertIn("console session failed (NEURALWATT_COOKIE_JAR set)", result["summary"])

    def test_console_session_live_is_reported(self):
        raw = json.loads(json.dumps(NEURALWATT_FIXTURE))
        console_payload = {"balance_usd": 141.59, "spend_usd": 34.41}
        with patch.dict(os.environ, {"NEURALWATT_COOKIE_JAR": "/tmp/nw.jar", "NEURALWATT_API_KEY": "nw-key"}), \
             patch.object(self.ai_usage, "load_dotenv_exports", return_value={}), \
             patch.object(self.ai_usage, "_neuralwatt_console_usage", return_value=console_payload), \
             patch.object(self.ai_usage, "_neuralwatt_seven_day_burn", return_value=None), \
             patch.object(self.ai_usage, "_neuralwatt_active_offer", return_value=None), \
             patch.object(self.ai_usage, "_bearer_json_probe", side_effect=lambda *a, **k: {
                 "provider": "neuralwatt", "label": "NeuralWatt", "state": "ok",
                 "source": "api", "summary": "", "raw": raw}):
            result = self.ai_usage.fetch_neuralwatt(1.0)
        self.assertEqual(result["console"], console_payload)
        self.assertIn("console session live", result["summary"])

    def test_seven_day_burn_surfaces(self):
        raw = json.loads(json.dumps(NEURALWATT_FIXTURE))
        with patch.dict(os.environ, {"NEURALWATT_API_KEY": "nw-key"}), \
             patch.object(self.ai_usage, "load_dotenv_exports", return_value={}), \
             patch.object(self.ai_usage, "_neuralwatt_console_usage", return_value=None), \
             patch.object(self.ai_usage, "_neuralwatt_seven_day_burn", return_value=1.267258), \
             patch.object(self.ai_usage, "_neuralwatt_active_offer", return_value=None), \
             patch.object(self.ai_usage, "_bearer_json_probe", side_effect=lambda *a, **k: {
                 "provider": "neuralwatt", "label": "NeuralWatt", "state": "ok",
                 "source": "api", "summary": "", "raw": raw}):
            result = self.ai_usage.fetch_neuralwatt(1.0)
        self.assertAlmostEqual(result["seven_day_burn_usd"], 1.267258)

    def test_active_offer_surfaces_from_coordinator_feed(self):
        raw = json.loads(json.dumps(NEURALWATT_FIXTURE))
        offer = {
            "id": "neuralwatt:x:payasyougo", "provider": "neuralwatt",
            "title": "Free Flash weekend", "starts_at": "2026-10-09T00:00:00Z",
            "expires_at": "2026-10-12T00:00:00Z", "amount_wh": 250.0,
            "next_reset_at": "2026-10-10T00:00:00Z",
        }
        with patch.dict(os.environ, {"NEURALWATT_API_KEY": "nw-key"}), \
             patch.object(self.ai_usage, "load_dotenv_exports", return_value={}), \
             patch.object(self.ai_usage, "_neuralwatt_console_usage", return_value=None), \
             patch.object(self.ai_usage, "_neuralwatt_seven_day_burn", return_value=None), \
             patch.object(self.ai_usage, "_neuralwatt_active_offer", return_value=offer), \
             patch.object(self.ai_usage, "_bearer_json_probe", side_effect=lambda *a, **k: {
                 "provider": "neuralwatt", "label": "NeuralWatt", "state": "ok",
                 "source": "api", "summary": "", "raw": raw}):
            result = self.ai_usage.fetch_neuralwatt(1.0)
        self.assertEqual(result["active_offer"]["title"], "Free Flash weekend")
        self.assertEqual(result["active_offer"]["amount_wh"], 250.0)

    ["Codex", "Gillean · Codex", "Claude Code", "Gillean · Claude Code",
             "OpenCode Go", "Mistral", "OpenRouter", "NeuralWatt"],

    def test_offer_feed_reader_validates_format_and_window(self):
        """The feed reader only accepts centre-provider-bonuses.v1 offers whose
        window covers now, from the env-var path only."""
        import tempfile as _tempfile
        now_iso = datetime.now(timezone.utc).isoformat()
        expired = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        feed = {
            "format": "centre-provider-bonuses.v1",
            "offers": [
                {"provider": "neuralwatt", "title": "expired one",
                 "starts_at": expired, "expires_at": expired, "amount_wh": 1.0},
                {"provider": "neuralwatt", "title": "live one",
                 "starts_at": "2026-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z",
                 "amount_wh": 250.0},
                {"provider": "other", "title": "wrong provider",
                 "starts_at": "2026-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z"},
            ],
        }
        with _tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(feed, fh)
            feed_path = fh.name
        try:
            with patch.dict(os.environ, {"NEURALWATT_OFFERS_FEED": feed_path}), \
                 patch.object(self.ai_usage, "load_dotenv_exports", return_value={}):
                offer = self.ai_usage._neuralwatt_active_offer(1.0)
        finally:
            os.unlink(feed_path)
        self.assertIsNotNone(offer)
        self.assertEqual(offer["title"], "live one")

    def test_no_host_paths_in_new_console_code(self):
        """Tracked source may not hardcode jar or feed paths — env only."""
        script = Path(self.ai_usage.__file__).read_text()
        self.assertNotIn("NEURALWATT_COOKIE_JAR = os.path.expanduser(", script)
        self.assertNotIn("NEURALWATT_OFFERS_FEED = os.path.expanduser(", script)


if __name__ == "__main__":
    unittest.main()
