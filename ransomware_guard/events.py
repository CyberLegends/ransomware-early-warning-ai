"""Strict normalized telemetry ingestion; no endpoint collection or execution."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

EVENT_TYPES = {"process_start", "backup_change", "security_change", "credential_alert",
               "auth", "canary", "file_activity", "network_transfer"}
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_EVENTS = 20000


def parse_time(value: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("timestamp must be an ISO 8601 string")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid ISO 8601 timestamp") from exc
    if timestamp.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return timestamp.astimezone(timezone.utc)


def validate_event(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("event must be an object")
    required = {"id", "timestamp", "host", "type", "actor", "details"}
    if set(raw) != required:
        raise ValueError("event fields must be exactly: " + ", ".join(sorted(required)))
    for field in ("id", "host", "actor"):
        if not isinstance(raw[field], str) or not raw[field].strip() or len(raw[field]) > 200:
            raise ValueError(f"{field} must be a non-empty string of at most 200 characters")
    parse_time(raw["timestamp"])
    if not isinstance(raw["type"], str) or raw["type"] not in EVENT_TYPES:
        raise ValueError("unsupported event type")
    details = raw["details"]
    if not isinstance(details, dict) or len(details) > 20:
        raise ValueError("details must be an object with at most 20 scalar fields")
    for key, value in details.items():
        if not isinstance(key, str) or len(key) > 100:
            raise ValueError("invalid detail key")
        if type(value) not in (str, int, bool) or (isinstance(value, str) and len(value) > 2000):
            raise ValueError("details accept only bounded strings, integers and booleans")
        if isinstance(value, int) and not isinstance(value, bool) and not 0 <= value <= 10**12:
            raise ValueError("detail integers must be between zero and 10^12")
    string_fields = {"action", "process", "parent", "category", "destination", "status", "file_id", "operation"}
    for field in string_fields & details.keys():
        if not isinstance(details[field], str):
            raise ValueError(f"details.{field} must be a string")
    for field in {"count", "bytes"} & details.keys():
        if type(details[field]) is not int:
            raise ValueError(f"details.{field} must be an integer, not a boolean")
    return json.loads(json.dumps(raw))


def normalize(events: list[dict]) -> tuple[list[dict], int]:
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError(f"at most {MAX_EVENTS} events are accepted")
    unique: dict[str, dict] = {}
    duplicates = 0
    for raw in events:
        event = validate_event(raw)
        existing = unique.get(event["id"])
        if existing is not None:
            if existing != event:
                raise ValueError("conflicting duplicate event id: " + event["id"])
            duplicates += 1
        else:
            unique[event["id"]] = event
    return sorted(unique.values(), key=lambda e: (parse_time(e["timestamp"]), e["id"])), duplicates


def load_json(path: str | Path, limit: int = MAX_FILE_BYTES):
    with Path(path).open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("input file exceeds size limit")
    return json.loads(payload.decode("utf-8"))


def load_jsonl(path: str | Path) -> list[dict]:
    with Path(path).open("rb") as stream:
        payload = stream.read(MAX_FILE_BYTES + 1)
    if len(payload) > MAX_FILE_BYTES:
        raise ValueError("telemetry file exceeds 10 MiB")
    events = []
    for number, line in enumerate(payload.decode("utf-8").splitlines(), 1):
        if line.strip():
            if len(line) > 16000:
                raise ValueError(f"line {number} exceeds 16000 characters")
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {number}: invalid JSON") from exc
            if len(events) > MAX_EVENTS:
                raise ValueError("too many telemetry events")
    normalize(events)  # Validate conflicts here, but preserve duplicates for report accounting.
    return events
