"""Sliding-window heuristics with evidence identifiers and explicit impact stages."""
from __future__ import annotations

from collections import defaultdict, deque
from hashlib import sha256
import json
from .events import normalize, parse_time

DEFAULT_RULES = {
    "window_seconds": 300, "alert_threshold": 60,
    "failed_auth_threshold": 5, "remote_destinations_threshold": 4,
    "file_write_threshold": 80, "file_rename_threshold": 30,
    "egress_bytes_threshold": 52428800,
    "weights": {"EW01": 35, "EW02": 30, "EW03": 30, "EW04": 20,
                "EW05": 25, "EW06": 50, "EW07": 40, "EW08": 25, "EW09": 15},
}
CATALOG = {
    "EW01": ("Recovery interference", "recovery", "precursor", "T1490"),
    "EW02": ("Security control change", "defense", "precursor", None),
    "EW03": ("Credential access indicator", "identity", "precursor", "T1003"),
    "EW04": ("Office application spawned a shell", "execution", "precursor", "T1059"),
    "EW05": ("Remote authentication fan-out", "movement", "precursor", "T1021"),
    "EW06": ("Configured canary was modified", "canary", "precursor", None),
    "EW07": ("High-volume file modifications", "files", "impact", "T1486"),
    "EW08": ("Large transfer outside known destinations", "egress", "precursor", None),
    "EW09": ("Authentication failure burst", "identity", "precursor", None),
}
DEFAULT_BASELINE = {"hosts": {"LAB-OFFICE-01": {"known_destinations": ["backup.internal.example"]},
                             "LAB-FINANCE-01": {"known_destinations": ["backup.internal.example"]}},
                    "canary_ids": ["canary-finance-01"]}


def validated_rules(value: dict | None = None) -> dict:
    rules = json.loads(json.dumps(DEFAULT_RULES if value is None else value))
    if set(rules) != set(DEFAULT_RULES) or not isinstance(rules["weights"], dict):
        raise ValueError("rules configuration has missing or unknown fields")
    if set(rules["weights"]) != set(CATALOG):
        raise ValueError("weights must include exactly EW01 through EW09")
    for key, number in rules.items():
        if key != "weights" and (type(number) is not int or not 1 <= number <= 10**12):
            raise ValueError("rule thresholds must be positive integers")
    if rules["window_seconds"] > 3600 or rules["alert_threshold"] > 100:
        raise ValueError("window must be <= 3600 seconds and alert threshold <= 100")
    if any(type(w) is not int or not 0 <= w <= 100 for w in rules["weights"].values()):
        raise ValueError("weights must be integers between 0 and 100")
    return rules


def validated_baseline(value: dict | None = None) -> dict:
    baseline = DEFAULT_BASELINE if value is None else value
    if not isinstance(baseline, dict) or set(baseline) != {"hosts", "canary_ids"}:
        raise ValueError("baseline requires hosts and canary_ids")
    if not isinstance(baseline["hosts"], dict) or len(baseline["hosts"]) > 10000:
        raise ValueError("invalid baseline hosts")
    if (not isinstance(baseline["canary_ids"], list) or len(baseline["canary_ids"]) > 1000
            or any(not isinstance(v, str) or not v or len(v) > 200 for v in baseline["canary_ids"])):
        raise ValueError("invalid canary identifiers")
    for host, profile in baseline["hosts"].items():
        if not isinstance(host, str) or not isinstance(profile, dict):
            raise ValueError("invalid baseline host profile")
        if set(profile) - {"known_destinations", "remote_destinations_threshold", "file_write_threshold", "file_rename_threshold"}:
            raise ValueError("unknown baseline setting")
        destinations = profile.get("known_destinations", [])
        if not isinstance(destinations, list) or any(not isinstance(d, str) for d in destinations):
            raise ValueError("known destinations must be strings")
        for key in set(profile) - {"known_destinations"}:
            if type(profile[key]) is not int or not 1 <= profile[key] <= 10**9:
                raise ValueError("baseline thresholds must be positive integers")
    return json.loads(json.dumps(baseline))


def _process_name(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def signals(window: list[dict], rules: dict, baseline: dict, host: str) -> list[dict]:
    buckets: dict[str, list[str]] = defaultdict(list)
    remote: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    failures: dict[str, list[str]] = defaultdict(list)
    transfers: dict[tuple[str, str], list[dict]] = defaultdict(list)
    files: dict[tuple[str, str], list[dict]] = defaultdict(list)
    profile = baseline["hosts"].get(host, {})
    for event in window:
        detail, kind, identity = event["details"], event["type"], event["id"]
        action = detail.get("action", "")
        if kind == "backup_change" and action in {"delete_snapshot", "disable_backup", "delete_backup_catalog"}:
            buckets["EW01"].append(identity)
        if kind == "security_change" and action in {"disable_protection", "stop_sensor", "tamper_protection"}:
            buckets["EW02"].append(identity)
        if kind == "credential_alert" and detail.get("category") in {"protected_process_access", "credential_store_access"}:
            buckets["EW03"].append(identity)
        if kind == "process_start":
            if (_process_name(detail.get("parent", "")) in {"winword.exe", "excel.exe", "outlook.exe"}
                    and _process_name(detail.get("process", "")) in {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"}):
                buckets["EW04"].append(identity)
        if kind == "auth":
            if detail.get("status") == "failure":
                failures[event["actor"]].append(identity)
            if detail.get("status") == "success" and detail.get("destination"):
                remote[event["actor"]][detail["destination"]].append(identity)
        if kind == "canary" and detail.get("file_id") in baseline["canary_ids"] and action in {"write", "delete", "rename"}:
            buckets["EW06"].append(identity)
        if kind == "file_activity" and detail.get("operation") in {"write", "rename"}:
            files[(event["actor"], detail["operation"])].append(event)
        if kind == "network_transfer" and detail.get("destination") not in profile.get("known_destinations", []):
            transfers[(event["actor"], detail.get("destination", ""))].append(event)
    threshold = profile.get("remote_destinations_threshold", rules["remote_destinations_threshold"])
    for destinations in remote.values():
        if len(destinations) >= threshold:
            buckets["EW05"].extend(i for ids in destinations.values() for i in ids)
    for ids in failures.values():
        if len(ids) >= rules["failed_auth_threshold"]:
            buckets["EW09"].extend(ids)
    for (_, operation), events in files.items():
        key = "file_write_threshold" if operation == "write" else "file_rename_threshold"
        if sum(e["details"].get("count", 1) for e in events) >= profile.get(key, rules[key]):
            buckets["EW07"].extend(e["id"] for e in events)
    for (_, destination), events in transfers.items():
        if destination and sum(e["details"].get("bytes", 0) for e in events) >= rules["egress_bytes_threshold"]:
            buckets["EW08"].extend(e["id"] for e in events)
    result = []
    for rule_id, ids in sorted(buckets.items()):
        name, category, stage, technique = CATALOG[rule_id]
        if ids and rules["weights"][rule_id]:
            result.append({"rule_id": rule_id, "name": name, "category": category, "stage": stage,
                           "weight": rules["weights"][rule_id], "reference_technique": technique,
                           "evidence_ids": sorted(set(ids))})
    return result


def analyze(events: list[dict], rules: dict | None = None, baseline: dict | None = None) -> dict:
    rules, baseline = validated_rules(rules), validated_baseline(baseline)
    events, duplicate_count = normalize(events)
    windows: dict[str, deque] = defaultdict(deque)
    cases: dict[str, dict] = {}
    for event in events:
        host, current_time = event["host"], parse_time(event["timestamp"])
        window = windows[host]
        window.append(event)
        while window and (current_time - parse_time(window[0]["timestamp"])).total_seconds() > rules["window_seconds"]:
            window.popleft()
        if len(window) > 1000:
            raise ValueError("more than 1000 events in a host window; narrow the batch or aggregate telemetry")
        hits = signals(list(window), rules, baseline, host)
        score = min(100, sum(h["weight"] for h in hits))
        precursor_categories = {h["category"] for h in hits if h["stage"] == "precursor"}
        impact = any(h["stage"] == "impact" for h in hits)
        early = score >= rules["alert_threshold"] and len(precursor_categories) >= 2 and not impact
        if host not in cases:
            case_id = "CL-RW-" + sha256((host + "|" + event["timestamp"]).encode()).hexdigest()[:12]
            cases[host] = {"case_id": case_id, "host": host, "risk_score": 0, "severity": "info",
                           "classification": "no_signal", "first_warning_at": None, "first_impact_at": None,
                           "peak_at": event["timestamp"], "findings": [], "evidence_ids": []}
        case = cases[host]
        if early and case["first_warning_at"] is None:
            case["first_warning_at"] = event["timestamp"]
        if impact and case["first_impact_at"] is None:
            case["first_impact_at"] = event["timestamp"]
        if score > case["risk_score"] or (score == case["risk_score"] and impact):
            case.update(risk_score=score, peak_at=event["timestamp"], findings=hits,
                        evidence_ids=sorted({identity for hit in hits for identity in hit["evidence_ids"]}),
                        classification="possible_impact" if impact else "elevated_precursors" if early else "review_signal")
        case["severity"] = ("critical" if case["risk_score"] >= 85 else "high" if case["risk_score"] >= 60
                            else "medium" if case["risk_score"] >= 30 else "low" if case["risk_score"] else "info")
    return {"schema_version": 1, "project": "Ransomware Early Warning AI", "mode": "reference_lab",
            "window_seconds": rules["window_seconds"], "alert_threshold": rules["alert_threshold"],
            "event_count": len(events), "duplicates_removed": duplicate_count,
            "cases": sorted(cases.values(), key=lambda c: (-c["risk_score"], c["host"])),
            "limitations": ["Heuristic score, not a calibrated probability or prediction of a future attack.",
                            "Batch telemetry analysis; no live sensor, ransomware execution or endpoint response.",
                            "Host-level correlation can combine unrelated activities; analyst verification is required.",
                            "Absence of a warning does not establish that the environment is safe."]}
