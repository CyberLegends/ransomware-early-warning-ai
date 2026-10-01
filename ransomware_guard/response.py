"""Local human-review records and one-use simulation. No containment API exists."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import uuid

from .agent import ACTIONS
from .events import load_json, parse_time


def make_plan(case: dict) -> dict:
    requested = sorted(set(case["agent"]["result"]["requested_actions"]))
    if not set(requested) <= ACTIONS or (case["risk_score"] < 60 and requested):
        raise ValueError("invalid response proposal")
    plan = {"case_id": case["case_id"], "host": case["host"], "risk_score": case["risk_score"],
            "evidence_ids": sorted(case["evidence_ids"]), "actions": requested,
            "execution_mode": "simulation_only", "requires_human_review": True}
    plan["plan_hash"] = sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return plan


def approve(plan: dict, reviewer: str, reviewed: bool, ttl: int = 900, now: datetime | None = None) -> dict:
    if reviewed is not True:
        raise ValueError("explicit --reviewed acknowledgement is required")
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 120:
        raise ValueError("a reviewer label of at most 120 characters is required")
    if type(ttl) is not int or not 1 <= ttl <= 3600:
        raise ValueError("approval lifetime must be 1..3600 seconds")
    if not plan["actions"]:
        raise ValueError("case has no response proposals")
    now = now or datetime.now(timezone.utc)
    return {"approval_id": str(uuid.uuid4()), "case_id": plan["case_id"], "host": plan["host"],
            "plan_hash": plan["plan_hash"], "reviewer": reviewer, "actions": plan["actions"],
            "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=ttl)).isoformat(),
            "scope": "simulation_only", "notice": "Local editable review record; not authenticated or signed authorization."}


def simulate(plan: dict, approval: dict, ledger_path: str | Path, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    required = {"approval_id", "case_id", "host", "plan_hash", "reviewer", "actions", "issued_at", "expires_at", "scope", "notice"}
    if not isinstance(approval, dict) or set(approval) != required:
        raise ValueError("invalid review record")
    if any(approval[key] != plan[key] for key in ("case_id", "host", "plan_hash", "actions")):
        raise ValueError("review record does not match this exact plan")
    if approval["scope"] != "simulation_only" or not plan["actions"] or not set(plan["actions"]) <= ACTIONS:
        raise ValueError("invalid simulation scope")
    issued, expires = parse_time(approval["issued_at"]), parse_time(approval["expires_at"])
    if not issued <= now < expires or (expires - issued).total_seconds() > 3600:
        raise ValueError("review record is expired, future-dated or too long-lived")
    try:
        uuid.UUID(approval["approval_id"])
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("invalid approval id") from exc
    ledger_path = Path(ledger_path)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    lock = ledger_path.with_name(ledger_path.name + ".lock")
    try:
        handle = lock.open("x", encoding="utf-8")
    except FileExistsError as exc:
        raise ValueError("simulation ledger is locked by another run; inspect stale locks manually") from exc
    try:
        with handle:
            ledger = load_json(ledger_path, 2 * 1024 * 1024) if ledger_path.exists() else {"used_approval_ids": []}
            if (not isinstance(ledger, dict) or set(ledger) != {"used_approval_ids"}
                    or not isinstance(ledger["used_approval_ids"], list)):
                raise ValueError("invalid simulation ledger")
            if approval["approval_id"] in ledger["used_approval_ids"]:
                raise ValueError("review record was already consumed")
            if len(ledger["used_approval_ids"]) >= 10000:
                raise ValueError("simulation ledger limit reached")
            ledger["used_approval_ids"].append(approval["approval_id"])
            temporary = ledger_path.with_name(ledger_path.name + ".pending")
            temporary.write_text(json.dumps(ledger, indent=2), encoding="utf-8")
            temporary.replace(ledger_path)
    finally:
        lock.unlink(missing_ok=True)
    return {"case_id": plan["case_id"], "host": plan["host"], "mode": "simulation_only",
            "reviewer": approval["reviewer"], "actions": [{"name": action, "status": "simulated_no_endpoint_change"} for action in plan["actions"]],
            "completed_at": now.isoformat(), "external_systems_modified": False}
