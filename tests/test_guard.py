import copy
from datetime import timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ransomware_guard.agent import deterministic_result, tool_call, triage, validate_result
from ransomware_guard.detector import analyze, validated_baseline, validated_rules
from ransomware_guard.events import load_jsonl, normalize, parse_time, validate_event
from ransomware_guard.fixtures import BASE_TIME, benign_events, demo_events, event, impact_events, precursor_events
from ransomware_guard.llm import NoRedirect, Ollama
from ransomware_guard.reports import html_report, save_report
from ransomware_guard.response import approve, make_plan, simulate
from ransomware_guard.__main__ import build_report, main

BASELINE = {"hosts": {"LAB-OFFICE-01": {"known_destinations": ["backup.internal.example"]}}, "canary_ids": ["canary-finance-01"]}


def case():
    return analyze(precursor_events(), baseline=BASELINE)["cases"][0]


class SequenceModel:
    model = "mock-model"

    def __init__(self, decisions):
        self.decisions = iter(decisions)

    def decide(self, context, schema):
        return next(self.decisions)


class DetectorTests(unittest.TestCase):
    def test_precursor_warning_precedes_file_impact(self):
        result = analyze(impact_events(), baseline=BASELINE)["cases"][0]
        self.assertEqual(parse_time(result["first_warning_at"]), BASE_TIME + timedelta(seconds=60))
        self.assertEqual(parse_time(result["first_impact_at"]), BASE_TIME + timedelta(seconds=180))
        self.assertEqual(result["classification"], "possible_impact")

    def test_precursor_only_is_not_impact(self):
        result = case()
        self.assertEqual(result["classification"], "elevated_precursors")
        self.assertIsNone(result["first_impact_at"])

    def test_benign_fixture_has_zero_score(self):
        result = analyze(benign_events(), baseline=BASELINE)
        self.assertEqual(result["cases"][0]["risk_score"], 0)

    def test_duplicated_telemetry_does_not_inflate_score(self):
        data = precursor_events()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicates.jsonl"
            path.write_text("".join(json.dumps(e) + "\n" for e in data + copy.deepcopy(data)))
            result = analyze(load_jsonl(path), baseline=BASELINE)
        self.assertEqual(result["duplicates_removed"], len(data))
        self.assertEqual(result["cases"][0]["risk_score"], case()["risk_score"])

    def test_conflicting_duplicate_ids_are_rejected(self):
        data = precursor_events()
        duplicate = copy.deepcopy(data[0])
        duplicate["host"] = "OTHER"
        with self.assertRaises(ValueError):
            analyze(data + [duplicate])

    def test_hosts_do_not_share_detection_evidence(self):
        data = [event("one", 0, "backup_change", {"action": "disable_backup"}, "A"),
                event("two", 10, "security_change", {"action": "stop_sensor"}, "B")]
        result = analyze(data)
        self.assertTrue(all(c["first_warning_at"] is None for c in result["cases"]))

    def test_old_events_expire_from_correlation_window(self):
        data = [event("one", 0, "backup_change", {"action": "disable_backup"}),
                event("two", 301, "security_change", {"action": "stop_sensor"})]
        self.assertIsNone(analyze(data)["cases"][0]["first_warning_at"])

    def test_single_category_does_not_become_precursor_warning(self):
        data = [event("one", 0, "credential_alert", {"category": "credential_store_access"})]
        data += [event("f" + str(i), i + 1, "auth", {"status": "failure"}) for i in range(5)]
        rules = validated_rules()
        rules["weights"]["EW03"] = 60
        self.assertIsNone(analyze(data, rules)["cases"][0]["first_warning_at"])

    def test_score_is_not_inflated_by_repeating_one_rule(self):
        data = [event(str(i), i, "backup_change", {"action": "disable_backup"}) for i in range(20)]
        self.assertEqual(analyze(data)["cases"][0]["risk_score"], 35)

    def test_score_is_capped(self):
        self.assertEqual(case()["risk_score"], 100)

    def test_unconfigured_canary_is_not_trusted(self):
        data = [event("x", 0, "canary", {"file_id": "arbitrary", "action": "write"})]
        self.assertEqual(analyze(data)["cases"][0]["risk_score"], 0)

    def test_canary_read_alone_is_ignored(self):
        data = [event("x", 0, "canary", {"file_id": "canary-finance-01", "action": "read"})]
        self.assertEqual(analyze(data)["cases"][0]["risk_score"], 0)

    def test_remote_fanout_counts_distinct_destinations(self):
        data = [event(str(i), i, "auth", {"status": "success", "destination": "same"}) for i in range(6)]
        self.assertEqual(analyze(data)["cases"][0]["risk_score"], 0)
        for i, item in enumerate(data):
            item["details"]["destination"] = "host-" + str(i)
        self.assertEqual(analyze(data)["cases"][0]["risk_score"], 25)

    def test_remote_fanout_does_not_combine_actors(self):
        data = [event(str(i), i, "auth", {"status": "success", "destination": str(i)}, actor="actor-" + str(i)) for i in range(6)]
        self.assertEqual(analyze(data)["cases"][0]["risk_score"], 0)

    def test_legitimate_high_volume_profile_reduces_file_burst(self):
        data = [event("x", 0, "file_activity", {"operation": "write", "count": 100})]
        baseline = {"hosts": {"LAB-FINANCE-01": {"file_write_threshold": 200}}, "canary_ids": []}
        self.assertEqual(analyze(data, baseline=baseline)["cases"][0]["risk_score"], 0)

    def test_unknown_egress_is_review_signal_not_attribution(self):
        data = [event("x", 0, "network_transfer", {"destination": "outside.example", "bytes": 60000000})]
        result = analyze(data)["cases"][0]
        self.assertEqual(result["risk_score"], 25)
        self.assertIsNone(result["first_warning_at"])

    def test_out_of_order_input_produces_same_cases(self):
        self.assertEqual(analyze(precursor_events())["cases"], analyze(list(reversed(precursor_events())))["cases"])

    def test_input_is_not_mutated(self):
        data = precursor_events()
        before = copy.deepcopy(data)
        analyze(data)
        self.assertEqual(data, before)

    def test_dense_host_window_fails_explicitly(self):
        data = [event(str(i), 0, "auth", {"status": "success", "destination": "one"}) for i in range(1001)]
        with self.assertRaisesRegex(ValueError, "1000 events"):
            analyze(data)

    def test_empty_input_is_valid(self):
        self.assertEqual(analyze([])["cases"], [])


class IngestionTests(unittest.TestCase):
    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            parse_time("2026-10-01T10:00:00")

    def test_timezone_normalization(self):
        self.assertEqual(parse_time("2026-10-01T15:00:00+05:00"), BASE_TIME)

    def test_boolean_count_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_event(event("x", 0, "file_activity", {"count": True}))

    def test_negative_byte_count_rejected(self):
        with self.assertRaises(ValueError):
            validate_event(event("x", 0, "network_transfer", {"bytes": -1}))

    def test_nested_prompt_or_object_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_event(event("x", 0, "auth", {"destination": {"tool": "execute"}}))

    def test_non_string_event_type_is_rejected(self):
        data = event("x", 0, "auth", {})
        data["type"] = []
        with self.assertRaises(ValueError):
            validate_event(data)

    def test_extra_top_level_fields_rejected(self):
        data = event("x", 0, "auth", {})
        data["trusted"] = True
        with self.assertRaises(ValueError):
            validate_event(data)

    def test_malformed_jsonl_has_line_context(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text("{broken}")
            with self.assertRaisesRegex(ValueError, "line 1"):
                load_jsonl(path)

    def test_rule_config_cannot_disable_validation(self):
        config = validated_rules()
        config["weights"]["EW01"] = -30
        with self.assertRaises(ValueError):
            validated_rules(config)

    def test_baseline_threshold_cannot_be_boolean(self):
        with self.assertRaises(ValueError):
            validated_baseline({"hosts": {"A": {"file_write_threshold": True}}, "canary_ids": []})


class AgentTests(unittest.TestCase):
    def test_offline_agent_inspects_and_finishes(self):
        output = triage(case(), precursor_events(), BASELINE)
        self.assertFalse(output["fallback_used"])
        self.assertEqual(output["trace"][-1]["kind"], "finish")
        self.assertEqual(len(output["trace"]), 4)

    def test_local_model_can_select_tools_and_finish(self):
        model = SequenceModel([{"kind": "tool", "tool": "inspect_timeline", "args": {"limit": 5}},
                               {"kind": "finish", "result": deterministic_result(case())}])
        output = triage(case(), precursor_events(), BASELINE, model)
        self.assertEqual(output["mode"], "local_generative_agent")
        self.assertFalse(output["fallback_used"])
        self.assertTrue(output["narrative_untrusted"])

    def test_unknown_model_tool_is_rejected(self):
        model = SequenceModel([{"kind": "tool", "tool": "run_shell", "args": {"command": "arbitrary"}}])
        output = triage(case(), precursor_events(), BASELINE, model)
        self.assertTrue(output["fallback_used"])
        self.assertEqual(output["trace"][0]["kind"], "rejected")

    def test_hallucinated_evidence_is_rejected(self):
        result = deterministic_result(case())
        result["evidence_ids"] = ["not-in-this-case"]
        with self.assertRaises(ValueError):
            validate_result(result, case())

    def test_out_of_scope_endpoint_action_rejected(self):
        result = deterministic_result(case())
        result["requested_actions"] = ["delete_files"]
        with self.assertRaises(ValueError):
            validate_result(result, case())

    def test_timeline_tool_is_host_and_case_scoped(self):
        other = event("P01", 0, "auth", {"status": "success"}, "OTHER")
        observed = tool_call("inspect_timeline", {"limit": 20}, case(), [other] + precursor_events(), BASELINE)
        self.assertTrue(all(e["host"] == "LAB-FINANCE-01" for e in observed["events"]))

    def test_model_cannot_choose_arbitrary_path_or_url(self):
        with self.assertRaises(ValueError):
            tool_call("inspect_timeline", {"limit": 20, "url": "https://example.com"}, case(), [], BASELINE)

    def test_model_cannot_finish_without_evidence_tool(self):
        model = SequenceModel([{"kind": "finish", "result": deterministic_result(case())}])
        self.assertTrue(triage(case(), precursor_events(), BASELINE, model)["fallback_used"])

    def test_repeated_tool_calls_stop_the_loop(self):
        decision = {"kind": "tool", "tool": "compare_baseline", "args": {}}
        output = triage(case(), precursor_events(), BASELINE, SequenceModel([decision, decision]))
        self.assertTrue(output["fallback_used"])
        self.assertIn("duplicate", output["model_error"])

    def test_budget_exhaustion_retains_deterministic_plan(self):
        output = triage(case(), precursor_events(), BASELINE, max_steps=1)
        self.assertTrue(output["fallback_used"])
        self.assertIn("budget", output["model_error"])

    def test_model_failure_does_not_change_risk_or_evidence(self):
        model = Mock(model="mock")
        model.decide.side_effect = ValueError("offline")
        output = build_report(precursor_events(), validated_rules(), BASELINE, model)
        self.assertEqual(output["cases"][0]["risk_score"], case()["risk_score"])
        self.assertTrue(output["warnings"])


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.case = build_report(precursor_events(), validated_rules(), BASELINE)["cases"][0]
        self.plan = make_plan(self.case)
        self.approval = approve(self.plan, "test-reviewer", True, now=BASE_TIME)

    def test_review_acknowledgement_required(self):
        with self.assertRaises(ValueError):
            approve(self.plan, "analyst", False)

    def test_expired_review_record_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "expired"):
                simulate(self.plan, self.approval, Path(directory) / "ledger.json", BASE_TIME + timedelta(seconds=900))

    def test_case_scope_mismatch_rejected(self):
        record = copy.deepcopy(self.approval)
        record["host"] = "OTHER"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                simulate(self.plan, record, Path(directory) / "ledger.json", BASE_TIME)

    def test_plan_changes_invalidate_review_record(self):
        changed = copy.deepcopy(self.case)
        changed["evidence_ids"].append("new")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                simulate(make_plan(changed), self.approval, Path(directory) / "ledger.json", BASE_TIME)

    def test_replay_rejected_without_endpoint_action(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            result = simulate(self.plan, self.approval, ledger, BASE_TIME)
            self.assertFalse(result["external_systems_modified"])
            with self.assertRaisesRegex(ValueError, "already consumed"):
                simulate(self.plan, self.approval, ledger, BASE_TIME)

    def test_future_review_record_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                simulate(self.plan, self.approval, Path(directory) / "ledger.json", BASE_TIME - timedelta(seconds=1))

    def test_lock_conflict_does_not_overwrite_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            Path(str(path) + ".lock").write_text("another run")
            with self.assertRaisesRegex(ValueError, "locked"):
                simulate(self.plan, self.approval, path, BASE_TIME)
            self.assertFalse(path.exists())


class IntegrationTests(unittest.TestCase):
    def test_html_escapes_event_and_ai_text(self):
        report = build_report(demo_events(), validated_rules(), BASELINE)
        report["cases"][0]["agent"]["result"]["summary"] = '<script>alert("x")</script>'
        html = html_report(report)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Content-Security-Policy", html)

    def test_json_and_html_report_are_written(self):
        with tempfile.TemporaryDirectory() as directory:
            save_report(directory, build_report(demo_events(), validated_rules(), BASELINE))
            self.assertTrue((Path(directory) / "report.html").exists())
            self.assertEqual(json.loads((Path(directory) / "report.json").read_text())["event_count"], 10)

    def test_ollama_transport_sends_json_schema_to_loopback(self):
        model = Ollama("installed-model")
        response = io.BytesIO(json.dumps({"done": True, "response": '{"kind":"tool"}'}).encode())
        model.opener = Mock()
        model.opener.open.return_value = response
        self.assertEqual(model.decide({"case": "synthetic"}, {"type": "object"}), {"kind": "tool"})
        request = model.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/api/generate")
        body = json.loads(request.data)
        self.assertFalse(body["stream"])
        self.assertEqual(body["format"], {"type": "object"})

    def test_redirects_are_rejected(self):
        with self.assertRaises(ValueError):
            NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://outside.example")

    def test_incomplete_model_response_rejected(self):
        model = Ollama("installed-model")
        model.opener = Mock()
        model.opener.open.return_value = io.BytesIO(b'{"done":false,"response":"{}"}')
        with self.assertRaises(ValueError):
            model.decide({}, {})

    def test_invalid_model_name_rejected(self):
        with self.assertRaises(ValueError):
            Ollama("a model with spaces")

    def test_demo_cli_runs_without_optional_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("ransomware_guard.__main__.ROOT", Path(directory) / "missing-config-root"):
                self.assertEqual(main(["demo", "--out", directory]), 0)
            self.assertTrue((Path(directory) / "report.html").exists())


if __name__ == "__main__":
    unittest.main()
