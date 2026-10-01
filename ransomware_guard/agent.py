"""Bounded observe/tool/observe triage loop; model output cannot execute response."""
from __future__ import annotations

import json
from .events import parse_time

ACTIONS = {"isolate_endpoint", "review_account_sessions", "protect_backups"}
PLAYBOOKS = {
    "precursor": ["Confirm the event source, affected host and approved maintenance context.",
                  "Correlate the event IDs with EDR and identity audit evidence.",
                  "Ask the incident owner to review containment and backup protection."],
    "impact": ["Escalate to the incident commander; file bursts alone do not prove encryption.",
               "Preserve evidence using the organization's approved incident procedure.",
               "Review affected-host containment and backup integrity through trusted tooling."],
    "identity": ["Verify the actor and destinations in the identity provider's audit trail.",
                 "Compare the activity with approved administrator workflows.",
                 "Review active account sessions with the identity owner."],
}
TOOLS = ["inspect_timeline", "compare_baseline", "read_playbook"]
RESULT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {"summary": {"type": "string"}, "uncertainty": {"type": "string"},
                   "evidence_ids": {"type": "array", "items": {"type": "string"}},
                   "next_steps": {"type": "array", "items": {"type": "string"}},
                   "requested_actions": {"type": "array", "items": {"type": "string", "enum": sorted(ACTIONS)}}},
    "required": ["summary", "uncertainty", "evidence_ids", "next_steps", "requested_actions"],
}
DECISION_SCHEMA = {"oneOf": [
    {"type": "object", "additionalProperties": False,
     "properties": {"kind": {"const": "tool"}, "tool": {"type": "string", "enum": TOOLS},
                    "args": {"type": "object"}}, "required": ["kind", "tool", "args"]},
    {"type": "object", "additionalProperties": False,
     "properties": {"kind": {"const": "finish"}, "result": RESULT_SCHEMA}, "required": ["kind", "result"]}
]}


def tool_call(name: str, args: dict, case: dict, events: list[dict], baseline: dict) -> dict:
    if not isinstance(args, dict) or name not in TOOLS:
        raise ValueError("unknown tool or invalid arguments")
    scoped = [event for event in events if event["host"] == case["host"] and event["id"] in case["evidence_ids"]]
    if name == "inspect_timeline":
        if set(args) != {"limit"} or type(args["limit"]) is not int or not 1 <= args["limit"] <= 20:
            raise ValueError("timeline limit must be an integer from 1 to 20")
        scoped = sorted(scoped, key=lambda event: (parse_time(event["timestamp"]), event["id"]))
        return {"events": scoped[:args["limit"]], "total_evidence_events": len(scoped),
                "truncated": len(scoped) > args["limit"]}
    if name == "compare_baseline":
        if args:
            raise ValueError("baseline tool accepts no arguments")
        profile = baseline.get("hosts", {}).get(case["host"])
        return {"host_profile": profile, "profile_status": "configured" if profile else "default_thresholds",
                "note": "Administrator-supplied baseline; not learned or authenticated by this tool."}
    if set(args) != {"topic"} or not isinstance(args["topic"], str) or args["topic"] not in PLAYBOOKS:
        raise ValueError("unknown playbook topic")
    return {"topic": args["topic"], "steps": PLAYBOOKS[args["topic"]]}


def validate_result(result: dict, case: dict) -> dict:
    if not isinstance(result, dict) or set(result) != set(RESULT_SCHEMA["required"]):
        raise ValueError("invalid final result fields")
    for key in ("summary", "uncertainty"):
        if not isinstance(result[key], str) or not result[key].strip() or len(result[key]) > 1500:
            raise ValueError("invalid narrative length")
    for key in ("evidence_ids", "next_steps", "requested_actions"):
        if not isinstance(result[key], list) or len(result[key]) > 20 or any(not isinstance(v, str) or len(v) > 500 for v in result[key]):
            raise ValueError("invalid result list")
    if not set(result["evidence_ids"]) <= set(case["evidence_ids"]):
        raise ValueError("model cited evidence outside the case")
    if case["evidence_ids"] and not result["evidence_ids"]:
        raise ValueError("model must cite at least one case evidence id")
    if not set(result["requested_actions"]) <= ACTIONS:
        raise ValueError("response action outside the allowed catalogue")
    if case["risk_score"] < 60 and result["requested_actions"]:
        raise ValueError("response proposals require a high-risk case")
    return json.loads(json.dumps(result))


def deterministic_result(case: dict) -> dict:
    names = ", ".join(finding["name"] for finding in case["findings"]) or "no configured rule signals"
    topic = "impact" if case["classification"] == "possible_impact" else "precursor"
    return {"summary": f"{case['host']}: score {case['risk_score']}/100. Observed: {names}.",
            "uncertainty": "Synthetic/reference heuristics. Legitimate maintenance and unrelated host activity can resemble these signals. Ransomware attribution and future compromise are unproven.",
            "evidence_ids": case["evidence_ids"][:20], "next_steps": PLAYBOOKS[topic],
            "requested_actions": ["isolate_endpoint", "review_account_sessions", "protect_backups"] if case["risk_score"] >= 60 else []}


def triage(case: dict, events: list[dict], baseline: dict, model=None, max_steps: int = 6) -> dict:
    if type(max_steps) is not int or not 1 <= max_steps <= 8:
        raise ValueError("agent step budget must be 1 to 8")
    history, seen = [], set()
    fallback, model_error, result = False, None, None
    for step in range(max_steps):
        try:
            if model is None:
                decisions = [
                    {"kind": "tool", "tool": "inspect_timeline", "args": {"limit": 20}},
                    {"kind": "tool", "tool": "compare_baseline", "args": {}},
                    {"kind": "tool", "tool": "read_playbook", "args": {"topic": "impact" if case["classification"] == "possible_impact" else "precursor"}},
                    {"kind": "finish", "result": deterministic_result(case)},
                ]
                decision = decisions[min(step, 3)]
            else:
                compact_case = {k: v for k, v in case.items() if k not in {"evidence_ids", "agent", "response_plan"}}
                compact_case["evidence_ids"] = case["evidence_ids"][:50]
                compact_case = json.loads(json.dumps(compact_case))
                for finding in compact_case.get("findings", []):
                    finding["evidence_ids"] = finding["evidence_ids"][:50]
                decision = model.decide({"case": compact_case, "tools": {
                    "inspect_timeline": {"args": {"limit": "integer 1..20"}},
                    "compare_baseline": {"args": {}},
                    "read_playbook": {"args": {"topic": "precursor|impact|identity"}}},
                    "history": history, "steps_remaining": max_steps - step}, DECISION_SCHEMA)
            if not isinstance(decision, dict):
                raise ValueError("decision must be an object")
            if decision.get("kind") == "finish":
                if set(decision) != {"kind", "result"}:
                    raise ValueError("unknown finish fields")
                if not any(item.get("tool") == "inspect_timeline" for item in history):
                    raise ValueError("agent must inspect evidence before finishing")
                result = validate_result(decision["result"], case)
                history.append({"step": step + 1, "kind": "finish"})
                break
            if set(decision) != {"kind", "tool", "args"} or decision.get("kind") != "tool":
                raise ValueError("invalid tool decision")
            signature = json.dumps(decision, sort_keys=True)
            if signature in seen:
                raise ValueError("duplicate tool call stopped")
            seen.add(signature)
            observation = tool_call(decision["tool"], decision["args"], case, events, baseline)
            history.append({"step": step + 1, "kind": "tool", "tool": decision["tool"],
                            "args": decision["args"], "observation": observation})
        except (ValueError, TypeError, KeyError) as exc:
            model_error, fallback = str(exc), True
            history.append({"step": step + 1, "kind": "rejected", "reason": model_error})
            break
    if result is None:
        result, fallback = deterministic_result(case), True
        model_error = model_error or "step budget exhausted before a valid finish"
    return {"mode": "local_generative_agent" if model is not None else "offline_rule_agent",
            "model": getattr(model, "model", None), "fallback_used": fallback,
            "model_error": model_error, "narrative_untrusted": model is not None and not fallback,
            "trace": history, "result": result,
            "permissions": "Read-only case tools; all consequential response remains a human-reviewed proposal."}
