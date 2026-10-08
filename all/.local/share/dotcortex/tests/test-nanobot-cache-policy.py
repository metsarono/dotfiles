"""Fail-closed behavior checks for Nano's runtime cache-policy consumer."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import json
from types import SimpleNamespace
import unittest
from unittest import mock

from nanobot.agent.autocompact import AutoCompact


class FakeSession:
    def __init__(self) -> None:
        self.key = "telegram:approved"
        self.updated_at = datetime.now() - timedelta(hours=3)
        self.messages = [{"role": "user", "content": "durable context"}]
        self.last_archived = 0
        self.metadata = {}


class FakeSessions:
    def __init__(self, session: FakeSession) -> None:
        self.session = session

    def list_sessions(self):
        return [{"key": self.session.key, "updated_at": self.session.updated_at}]

    def get_or_create(self, _key: str):
        return self.session


class FakeConsolidator:
    def __init__(self, estimated_tokens: int) -> None:
        self.estimated_tokens = estimated_tokens

    def estimate_session_prompt_tokens(self, _session, *, runtime):
        return self.estimated_tokens, getattr(self, "source", "tiktoken")


class NanoCachePolicyTest(unittest.TestCase):
    def run_scan(self, estimated_tokens, *, minimum="70000", source="tiktoken",
                 mode="enforce", key="telegram:approved", active=(), archiving=False) -> int:
        session = FakeSession()
        session.key = key
        counter = FakeConsolidator(estimated_tokens)
        counter.source = source
        compact = AutoCompact(FakeSessions(session), counter)
        if archiving:
            compact._archiving.add(key)
        scheduled = []
        runtime = object()
        with mock.patch.object(AutoCompact, "_policy_ttl_seconds", return_value=60), \
             mock.patch.dict(os.environ, {"NANOBOT_CACHE_POLICY_MIN_TOKENS": minimum,
                                          "NANOBOT_CACHE_POLICY_MODE": mode}):
            compact.check_expired(scheduled.append, lambda _session: runtime, active)
        for coroutine in scheduled:
            coroutine.close()
        return len(scheduled)

    def test_expiry_below_token_gate_does_not_compact(self) -> None:
        self.assertEqual(self.run_scan(69999), 0)

    def test_expiry_at_token_gate_forces_compaction(self) -> None:
        self.assertEqual(self.run_scan(70000), 1)


    def test_floor_cannot_be_lowered(self):
        for minimum in ("1", "0", "69999"):
            with self.subTest(minimum=minimum):
                self.assertEqual(self.run_scan(69999, minimum=minimum), 0)
                self.assertEqual(self.run_scan(70000, minimum=minimum), 1)

    def test_floor_can_be_raised(self):
        self.assertEqual(self.run_scan(70000, minimum="80000"), 0)
        self.assertEqual(self.run_scan(80000, minimum="80000"), 1)

    def test_bad_minimum_disables_without_scan_crash(self):
        for minimum in ("", "NaN", "Infinity", "true", "70000.0", "-1", " 70000", "７００００"):
            with self.subTest(minimum=minimum):
                self.assertEqual(self.run_scan(90000, minimum=minimum), 0)

    def test_bad_estimates_disable_without_scan_crash(self):
        for tokens in (None, True, False, "90000", [], {}, float("nan"), float("inf"), -1, 0):
            with self.subTest(tokens=tokens):
                self.assertEqual(self.run_scan(tokens), 0)

    def test_unknown_sources_disable(self):
        for source in (None, "", "none", "unknown", "invented", [], True):
            with self.subTest(source=source):
                self.assertEqual(self.run_scan(90000, source=source), 0)

    def test_shadow_and_invalid_modes_do_not_archive(self):
        for mode in ("shadow", "", "typo"):
            self.assertEqual(self.run_scan(90000, mode=mode), 0)

    def test_active_dream_and_archiving_sessions_remain_excluded(self):
        self.assertEqual(self.run_scan(90000, active=("telegram:approved",)), 0)
        self.assertEqual(self.run_scan(90000, key="dream:probe"), 0)
        self.assertEqual(self.run_scan(90000, archiving=True), 0)


class PolicyDecisionTest(unittest.TestCase):
    def setUp(self):
        from nanobot.providers.openai_compat_provider import OpenAICompatProvider
        self.provider = OpenAICompatProvider(api_key="fixture", api_base="https://fixture.invalid/v1",
                                             provider_name="custom")
        from nanobot.utils.llm_runtime import LLMRuntime
        self.runtime = LLMRuntime.capture(self.provider, "fixture-model", context_window_tokens=100000)
        self.decision = dict(mode="measured", confidence="supported", compact_before_seconds=60,
                             cache_expires_seconds=120, provider="custom",
                             endpoint_id="https://fixture.invalid/v1", model="fixture-model",
                             observed_at=datetime.now(timezone.utc).isoformat(), source_harness="nanobot")

    def resolve(self, decision=None, *, raw=None, runtime=None, env=None, evidence=None):
        output = json.dumps(self.decision if decision is None else decision) if raw is None else raw
        entry = dict(self.decision if decision is None else decision)
        entry.update(harness=entry.get("source_harness"),
                     fresh_until=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
        policy = evidence if evidence is not None else dict(format="cache-policy.v1",
                     fresh_until=entry["fresh_until"], entries=[entry])
        with mock.patch("nanobot.agent.autocompact.subprocess.run",
                        return_value=SimpleNamespace(stdout=output)) as run, \
             mock.patch.dict(os.environ, env or {}, clear=True), \
             mock.patch("nanobot.agent.autocompact.Path.read_text", return_value=json.dumps(policy)):
            result = AutoCompact._policy_ttl_seconds(runtime or self.runtime)
        return result, run

    def test_supported_and_observed_accept_exact_route(self):
        for mode, confidence in (("measured", "supported"), ("observed", "observed")):
            decision = self.decision | dict(mode=mode, confidence=confidence)
            result, run = self.resolve(decision)
            self.assertEqual(result, 60)
            args = run.call_args.args[0]
            self.assertEqual(args[args.index("--endpoint") + 1], "https://fixture.invalid/v1")
            self.assertEqual(args[args.index("--model") + 1], "fixture-model")
            self.assertIn("--allow-observed", args)

    def test_confidence_and_fallback_fail_closed(self):
        for mode, confidence in (("measured", "observed"), ("observed", "supported"),
                                 ("fallback", "supported"), ("measured", None),
                                 ("unsupported", "supported"), ([], "supported")):
            with self.subTest(mode=mode, confidence=confidence):
                self.assertIsNone(self.resolve(self.decision | dict(mode=mode, confidence=confidence))[0])

    def test_nonobjects_and_bad_json_fail_closed(self):
        for raw in ("[]", "null", "true", '"string"', "1", "garbage"):
            with self.subTest(raw=raw):
                self.assertIsNone(self.resolve(raw=raw)[0])

    def test_bad_or_unordered_durations_fail_closed(self):
        for field in ("compact_before_seconds", "cache_expires_seconds"):
            for value in (None, True, "60", float("nan"), float("inf"), -1, 0, []):
                with self.subTest(field=field, value=value):
                    self.assertIsNone(self.resolve(self.decision | {field: value})[0])
        for expiry in (59, 60):
            self.assertIsNone(self.resolve(self.decision | dict(cache_expires_seconds=expiry))[0])

    def test_missing_fields_fail_closed(self):
        for field in self.decision:
            decision = self.decision.copy()
            del decision[field]
            with self.subTest(field=field):
                self.assertIsNone(self.resolve(decision)[0])

    def test_mismatched_route_model_provider_fail_closed(self):
        for field in ("provider", "endpoint_id", "model"):
            self.assertIsNone(self.resolve(self.decision | {field: "other"})[0])

    def test_stale_future_and_bad_evidence_dates_fail_closed(self):
        for stamp in (None, "", "invalid", datetime.now().isoformat(),
                      (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(),
                      (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()):
            with self.subTest(stamp=stamp):
                self.assertIsNone(self.resolve(self.decision | dict(observed_at=stamp))[0])

    def test_environment_validation_fail_closed(self):
        for env in ({"NANOBOT_CACHE_POLICY_FALLBACK_COMPACT_SECONDS": "bad"},
                    {"NANOBOT_CACHE_POLICY_FALLBACK_CACHE_SECONDS": "NaN"},
                    {"NANOBOT_CACHE_POLICY_FALLBACK_COMPACT_SECONDS": "1800"},
                    {"NANOBOT_CACHE_POLICY_FALLBACK_CACHE_SECONDS": "0"},
                    {"FLEET_CACHE_POLICY_HELPER": ""}, {"FLEET_CACHE_POLICY_PATH": ""}):
            with self.subTest(env=env):
                self.assertIsNone(self.resolve(env=env)[0])

    def test_helper_errors_fail_closed(self):
        import subprocess
        for error in (OSError(), subprocess.TimeoutExpired("fixture", 5),
                      subprocess.CalledProcessError(1, "fixture")):
            with mock.patch("nanobot.agent.autocompact.subprocess.run", side_effect=error):
                self.assertIsNone(AutoCompact._policy_ttl_seconds(self.runtime))

    def test_oauth_actual_class_and_wire_model(self):
        from nanobot.providers.openai_codex_provider import OpenAICodexProvider
        provider = OpenAICodexProvider(default_model="openai-codex/fixture-model")
        from nanobot.utils.llm_runtime import LLMRuntime
        runtime = LLMRuntime.capture(provider, "openai-codex/fixture-model", context_window_tokens=100000)
        decision = self.decision | dict(provider="openai", endpoint_id="openai-codex-oauth")
        result, run = self.resolve(decision, runtime=runtime)
        self.assertEqual(result, 60)
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--endpoint") + 1], "openai-codex-oauth")
        self.assertEqual(args[args.index("--model") + 1], "fixture-model")

    def test_provider_label_cannot_impersonate_oauth(self):
        runtime = SimpleNamespace(provider=SimpleNamespace(provider_name="openai_codex", api_base=None),
                                  model="fixture-model")
        result, run = self.resolve(runtime=runtime)
        self.assertIsNone(result)
        run.assert_not_called()

    def test_model_override_and_unresolved_endpoint_disable(self):
        self.provider._extra_body = {"model": "other"}
        self.assertIsNone(self.resolve()[0])
        self.provider._extra_body = {}
        self.provider._effective_base = None
        self.assertIsNone(self.resolve()[0])


    def test_initialized_client_route_is_authoritative(self):
        self.provider._client = SimpleNamespace(base_url="https://other.invalid/v1/")
        self.assertIsNone(self.resolve()[0])
        decision = self.decision | dict(endpoint_id="https://other.invalid/v1")
        result, run = self.resolve(decision)
        self.assertEqual(result, 60)
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--endpoint") + 1], "https://other.invalid/v1")

    def test_case_underscore_and_percent_routes_preserve_identity(self):
        from openai import AsyncOpenAI
        for endpoint, canonical in (
            ("HTTPS://Fixture.Invalid/Route_A/%2fValue",
             "https://fixture.invalid/Route_A/%2fValue"),
            ("https://fixture.invalid/Route_A/%2FValue/",
             "https://fixture.invalid/Route_A/%2FValue"),
        ):
            for initialized in (False, True):
                with self.subTest(endpoint=endpoint, initialized=initialized):
                    self.provider._effective_base = endpoint
                    self.provider._client = (
                        AsyncOpenAI(api_key="fixture", base_url=endpoint) if initialized else None
                    )
                    identity = AutoCompact._policy_identity(self.runtime)
                    self.assertEqual(identity, ("custom", canonical, "fixture-model"))
                    decision = self.decision | dict(endpoint_id=canonical)
                    self.assertEqual(self.resolve(decision)[0], 60)

    def test_distinct_path_and_percent_spellings_cannot_cross_arm(self):
        endpoint = "https://fixture.invalid/Route_A/%2fValue"
        self.provider._effective_base = endpoint
        for other in (
            "https://fixture.invalid/route_A/%2fValue",
            "https://fixture.invalid/Route-A/%2fValue",
            "https://fixture.invalid/Route_A/%2FValue",
        ):
            with self.subTest(other=other):
                result, run = self.resolve(self.decision | dict(endpoint_id=other))
                self.assertIsNone(result)
                run.assert_called_once()

    def test_malformed_physical_routes_fail_before_resolver(self):
        for endpoint in (
            "https://fixture.invalid/route/v1//",
            "https://fixture.invalid/path?",
            "https://fixture.invalid/path#",
            "https://fixture.invalid/%ZZ",
            "https://fixture.invalid/%2",
            "https://fixture.invalid\\other/path",
            "https://fixture.invalid:bad/path",
            "https:///path",
            "ftp://fixture.invalid/path",
        ):
            with self.subTest(endpoint=endpoint):
                self.provider._effective_base = endpoint
                result, run = self.resolve()
                self.assertIsNone(result)
                run.assert_not_called()
                self.assertIsNone(AutoCompact._policy_identity(self.runtime))

    def test_bare_root_slash_matches_no_slash(self):
        from openai import AsyncOpenAI
        canonical = "https://fixture.invalid"
        for endpoint in (canonical, canonical + "/"):
            for initialized in (False, True):
                with self.subTest(endpoint=endpoint, initialized=initialized):
                    self.provider._effective_base = endpoint
                    self.provider._client = (
                        AsyncOpenAI(api_key="fixture", base_url=endpoint) if initialized else None
                    )
                    self.assertEqual(
                        AutoCompact._policy_identity(self.runtime),
                        ("custom", canonical, "fixture-model"),
                    )
                    self.assertEqual(
                        self.resolve(self.decision | dict(endpoint_id=canonical))[0], 60,
                    )

    def test_unchanged_lowercase_sdk_route_remains_supported(self):
        from openai import AsyncOpenAI
        endpoint = "https://fixture.invalid/route-a/v1"
        for initialized in (False, True):
            self.provider._effective_base = endpoint
            self.provider._client = AsyncOpenAI(api_key="fixture", base_url=endpoint) if initialized else None
            decision = self.decision | dict(endpoint_id=endpoint)
            self.assertEqual(self.resolve(decision)[0], 60)

    def test_duplicate_keys_fail_closed(self):
        raw = json.dumps(self.decision)[:-1] + ', "mode": "measured"}'
        self.assertIsNone(self.resolve(raw=raw)[0])

    def test_route_secrets_and_ambiguous_wrappers_disable(self):
        for endpoint in ("https://name:password@fixture.invalid/v1", "https://fixture.invalid/v1?key=fixture",
                         "https://fixture.invalid/v1#other", "relative-path"):
            self.provider._effective_base = endpoint
            result, run = self.resolve()
            self.assertIsNone(result)
            run.assert_not_called()
        runtime = SimpleNamespace(provider=SimpleNamespace(provider_name="custom", primary=self.provider),
                                  model="fixture-model")
        self.assertIsNone(self.resolve(runtime=runtime)[0])


    def test_raw_evidence_coercion_cannot_arm_timer(self):
        fresh = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        entry = self.decision | dict(harness="nanobot", fresh_until=fresh)
        for field in ("compact_before_seconds", "cache_expires_seconds"):
            for value in (True, "60", "120", None, float("nan"), float("inf")):
                evidence = dict(format="cache-policy.v1", fresh_until=fresh,
                                entries=[entry | {field: value}])
                with self.subTest(field=field, value=value):
                    self.assertIsNone(self.resolve(evidence=evidence)[0])

    def test_raw_evidence_missing_stale_and_mismatched_disable(self):
        fresh = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        stale = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        entry = self.decision | dict(harness="nanobot", fresh_until=fresh)
        policy = dict(format="cache-policy.v1", fresh_until=fresh, entries=[entry])
        for evidence in ([], {}, policy | dict(fresh_until=stale),
                         policy | dict(entries=[entry | dict(fresh_until=stale)]),
                         policy | dict(entries=[entry | dict(endpoint_id="other")]),
                         policy | dict(entries=[entry | dict(compact_before_seconds=59)]),
                         policy | dict(entries=[entry | dict(mode="fallback")]),
                         policy | dict(entries=[entry | dict(mode=None)])):
            self.assertIsNone(self.resolve(evidence=evidence)[0])


if __name__ == "__main__":
    unittest.main()
