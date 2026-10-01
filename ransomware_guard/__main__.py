"""Run from the repository root: python -m ransomware_guard --help."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .agent import triage
from .detector import analyze, validated_baseline, validated_rules
from .events import load_json, load_jsonl
from .fixtures import demo_events, write_fixtures
from .llm import Ollama
from .reports import save_json, save_report
from .response import approve, make_plan, simulate

ROOT = Path(__file__).resolve().parents[1]


def build_report(events, rules, baseline, model=None, max_ai_cases=3):
    report = analyze(events, rules, baseline)
    report["version"], report["warnings"] = __version__, []
    ai_count = 0
    for case in report["cases"]:
        use_model = model if model is not None and case["risk_score"] >= rules["alert_threshold"] and ai_count < max_ai_cases else None
        if use_model is not None:
            ai_count += 1
        case["agent"] = triage(case, events, baseline, use_model)
        case["response_plan"] = make_plan(case)
        if case["agent"]["model_error"]:
            report["warnings"].append(case["host"] + ": " + case["agent"]["model_error"] + "; deterministic triage retained.")
    report["ai_cases_requested"] = ai_count
    return report


def get_case(report, identity):
    for case in report["cases"]:
        if case["case_id"] == identity or case["host"] == identity:
            return case
    raise ValueError("case ID or host was not found in this report")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Cyber Legends ransomware early warning reference lab")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("demo", "analyze"):
        command = commands.add_parser(name, help="Analyze synthetic demo data" if name == "demo" else "Analyze normalized JSONL telemetry")
        if name == "analyze":
            command.add_argument("--input", required=True)
        command.add_argument("--rules", help="Rules JSON; defaults to the repository config or built-in lab defaults")
        command.add_argument("--baseline", help="Baseline JSON; defaults to the repository config or built-in lab defaults")
        command.add_argument("--out", default="output")
        command.add_argument("--model", help="Opt in to an installed local Ollama model")
        command.add_argument("--max-ai-cases", type=int, default=3)
    fixtures = commands.add_parser("export-demo", help="Write synthetic JSONL fixtures")
    fixtures.add_argument("--out", default="data")
    review = commands.add_parser("approve", help="Record a human review for a simulation-only plan")
    review.add_argument("--report", required=True)
    review.add_argument("--case", required=True, help="Case ID or host")
    review.add_argument("--reviewer", required=True, help="Reviewer label, not a credential")
    review.add_argument("--reviewed", action="store_true")
    review.add_argument("--ttl", type=int, default=900)
    review.add_argument("--out", default="output/approval.json")
    response = commands.add_parser("simulate-response", help="Consume a reviewed plan without changing endpoints")
    response.add_argument("--report", required=True)
    response.add_argument("--approval", required=True)
    response.add_argument("--ledger", default="output/simulation-ledger.json")
    response.add_argument("--out", default="output/simulation.json")
    args = parser.parse_args(argv)
    try:
        if args.command in {"demo", "analyze"}:
            if not 1 <= args.max_ai_cases <= 10:
                raise ValueError("AI case budget must be 1..10")
            rules_path = Path(args.rules) if args.rules else ROOT / "config" / "rules.json"
            baseline_path = Path(args.baseline) if args.baseline else ROOT / "config" / "baseline.json"
            rules = validated_rules(load_json(rules_path) if args.rules or rules_path.exists() else None)
            baseline = validated_baseline(load_json(baseline_path) if args.baseline or baseline_path.exists() else None)
            events = demo_events() if args.command == "demo" else load_jsonl(args.input)
            report = build_report(events, rules, baseline, Ollama(args.model) if args.model else None, args.max_ai_cases)
            save_report(args.out, report)
            for case in report["cases"]:
                print(f"{case['host']}: {case['risk_score']}/100 {case['severity']} | {case['classification']} | {case['case_id']}")
            print("Saved " + str(Path(args.out) / "report.html") + " and report.json")
            for warning in report["warnings"]:
                print("WARNING: " + warning, file=sys.stderr)
        elif args.command == "export-demo":
            write_fixtures(args.out)
            print("Synthetic fixtures saved to " + args.out)
        else:
            report = load_json(args.report)
            if args.command == "approve":
                case = get_case(report, args.case)
                save_json(args.out, approve(make_plan(case), args.reviewer, args.reviewed, args.ttl))
                print("Simulation-only review record saved to " + args.out)
            else:
                approval_record = load_json(args.approval, 16384)
                case = get_case(report, approval_record["case_id"])
                result = simulate(make_plan(case), approval_record, args.ledger)
                save_json(args.out, result)
                print("Simulation complete. External systems modified: false")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
