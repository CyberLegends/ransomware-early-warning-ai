"""Self-contained static report. All telemetry and generated prose are HTML-escaped."""
from __future__ import annotations

from html import escape
import json
from pathlib import Path


def save_json(path: str | Path, value: dict):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def html_report(report: dict) -> str:
    cards = []
    for case in report["cases"]:
        agent = case["agent"]
        result = agent["result"]
        findings = "".join("<tr><td>" + escape(f["rule_id"]) + "</td><td>" + escape(f["name"]) + "</td><td>" + str(f["weight"]) + "</td><td>" + escape(", ".join(f["evidence_ids"])) + "</td></tr>" for f in case["findings"])
        steps = "".join("<li>" + escape(step) + "</li>" for step in result["next_steps"])
        actions = ", ".join(case["response_plan"]["actions"]) or "No response proposal"
        cards.append(f'''<section class="case"><div class="row"><div><small>{escape(case['case_id'])}</small><h2>{escape(case['host'])}</h2></div><div class="score {escape(case['severity'])}">{case['risk_score']}<small>/100 · {escape(case['severity'])}</small></div></div>
<p class="pill">{escape(case['classification'])}</p><p>{escape(result['summary'])}</p>
<div class="times"><span>First precursor warning<br><b>{escape(str(case['first_warning_at'] or 'Not observed'))}</b></span><span>First file-burst signal<br><b>{escape(str(case['first_impact_at'] or 'Not observed'))}</b></span></div>
<table><thead><tr><th>Rule</th><th>Observed signal</th><th>Weight</th><th>Evidence</th></tr></thead><tbody>{findings or '<tr><td colspan="4">No configured rule matched</td></tr>'}</tbody></table>
<h3>Investigation plan</h3><ol>{steps}</ol><p><b>Uncertainty:</b> {escape(result['uncertainty'])}</p>
<p><b>Response proposal:</b> {escape(actions)} · HUMAN REVIEW · SIMULATION ONLY</p>
<details><summary>Agent audit trail · {escape(agent['mode'])}</summary><pre>{escape(json.dumps(agent, indent=2))}</pre></details>
</section>''')
    high = sum(case["risk_score"] >= report["alert_threshold"] for case in report["cases"])
    warnings = "".join("<li>" + escape(w) + "</li>" for w in report.get("warnings", []))
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Cyber Legends | Ransomware Early Warning AI</title><style>
body{margin:0;background:#0a1323;color:#dce7f3;font:16px/1.6 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:40px 24px}header{border-bottom:1px solid #2c3e55;padding-bottom:24px}small,.muted{color:#a5b7cc}h1{font-size:40px;line-height:1.15;margin:12px 0}h2{margin:4px 0}h3{color:#72ded2}.brand{color:#67e3cf;letter-spacing:.16em;font-size:13px;font-weight:700}.metrics{display:flex;gap:16px;margin:24px 0;flex-wrap:wrap}.metric{background:#14233a;border:1px solid #2c3e55;padding:18px 24px;flex:1}.metric strong{display:block;font-size:30px}.case{background:#101e32;border:1px solid #2c3e55;padding:28px;margin:24px 0;border-radius:10px}.row,.times{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap}.score{font-size:38px;font-weight:bold;text-align:right}.score small{display:block;font-size:13px}.high,.critical{color:#ffb38c}.pill{display:inline-block;background:#234354;padding:3px 12px;border-radius:12px}.times{background:#192b44;padding:16px;margin:16px 0;font-size:13px}table{width:100%;border-collapse:collapse;font-size:13px;overflow-wrap:anywhere}td,th{text-align:left;padding:10px;border-bottom:1px solid #2c3e55}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0a1323;padding:16px;font-size:12px}footer{font-size:13px;color:#a5b7cc}.notice{border-left:3px solid #67e3cf;padding:12px 16px;background:#14233a}summary{cursor:pointer;color:#72ded2}@media(max-width:600px){h1{font-size:30px}.case{padding:16px}td,th{padding:6px}}
</style></head><body><main><header><div class="brand">CYBER LEGENDS · CYBERLEGENDS.ORG</div><h1>Ransomware Early Warning AI</h1><p>Evidence first. Bounded investigation. Human-reviewed response.</p><div class="notice">Reference lab · Heuristic scores are not attack probabilities. Offline analysis does not prevent an attack or change endpoints.</div></header>
''' + f'''<div class="metrics"><div class="metric"><small>Normalized events</small><strong>{report['event_count']}</strong></div><div class="metric"><small>Hosts reviewed</small><strong>{len(report['cases'])}</strong></div><div class="metric"><small>Cases above threshold</small><strong>{high}</strong></div></div>''' + ("<ul>" + warnings + "</ul>" if warnings else "") + "".join(cards) + '<footer>All narratives require analyst verification. Evidence IDs refer to the supplied telemetry batch. This report may contain operational information; share it through an approved channel.</footer></main></body></html>'


def save_report(directory: str | Path, report: dict):
    directory = Path(directory)
    save_json(directory / "report.json", report)
    (directory / "report.html").write_text(html_report(report), encoding="utf-8")
