"""Synthetic telemetry only. This module does not produce or execute malware."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

BASE_TIME = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)


def event(identity, offset, kind, details, host="LAB-FINANCE-01", actor="lab-analyst"):
    return {"id": identity, "timestamp": (BASE_TIME + timedelta(seconds=offset)).isoformat(),
            "host": host, "type": kind, "actor": actor, "details": details}


def precursor_events():
    return [event("P01", 0, "process_start", {"parent": "WINWORD.EXE", "process": "powershell.exe"}),
            event("P02", 30, "credential_alert", {"category": "protected_process_access"}),
            event("P03", 60, "security_change", {"action": "stop_sensor"}),
            event("P04", 90, "backup_change", {"action": "disable_backup"}),
            event("P05", 120, "canary", {"file_id": "canary-finance-01", "action": "write"})]


def benign_events():
    return [event("B01", 0, "process_start", {"parent": "explorer.exe", "process": "notepad.exe"}, "LAB-OFFICE-01"),
            event("B02", 20, "backup_change", {"action": "backup_completed"}, "LAB-OFFICE-01"),
            event("B03", 40, "file_activity", {"operation": "write", "count": 8}, "LAB-OFFICE-01"),
            event("B04", 50, "auth", {"status": "success", "destination": "LAB-SHARE-01"}, "LAB-OFFICE-01"),
            event("B05", 60, "network_transfer", {"destination": "backup.internal.example", "bytes": 70000000}, "LAB-OFFICE-01")]


def impact_events():
    return precursor_events() + [event("I01", 180, "file_activity", {"operation": "rename", "count": 40}),
                                 event("I02", 190, "file_activity", {"operation": "write", "count": 100})]


def demo_events():
    return precursor_events() + benign_events()


def write_fixtures(directory: str | Path):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for name, events in (("demo_precursors.jsonl", precursor_events()), ("demo_benign.jsonl", benign_events()),
                         ("demo_impact.jsonl", impact_events()), ("demo_combined.jsonl", demo_events())):
        (directory / name).write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in events), encoding="utf-8")
