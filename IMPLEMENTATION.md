# Step-by-step implementation

This guide takes you from the reproducible lab to a scoped read-only pilot. The shipped release implements batch detection, optional local generative triage, a bounded investigation agent and approval-gated response simulation.

## 1. Prepare your workstation

Use Python 3.11 or newer from [python.org](https://www.python.org/downloads/) and optionally Git from [git-scm.com](https://git-scm.com/downloads). Confirm your interpreter in a terminal:

```bash
python --version
```

On Windows, `py -3 --version` can be used. On Linux/macOS, `python3 --version` can be used. The project needs no administrator/root session and no third-party Python dependencies for offline mode.

## 2. Get the source

```bash
git clone https://github.com/CyberLegends/ransomware-early-warning-ai.git
cd ransomware-early-warning-ai
```

Alternatively, open the repository, select **Code → Download ZIP**, extract the archive, then open PowerShell/Terminal in the extracted folder containing `README.md` and `ransomware_guard`.

An optional virtual environment keeps future integrations separate:

```bash
python -m venv .venv
```

Use `.venv\Scripts\python.exe` on Windows or `.venv/bin/python` on Linux/macOS instead of `python`. Activation is optional; changing PowerShell execution policy is unnecessary. Running from the repository root is sufficient; installation with pip is not required.

## 3. Run the offline demonstration

```bash
python -m ransomware_guard demo --out output/demo
```

Expected output contains two hosts: finance scores 100/100 and office scores 0/100 with the included configuration. Open `output/demo/report.html` by double-clicking it. Inspect:

1. Case severity and classification.
2. First precursor-warning and first file-burst timestamps.
3. Rule findings and their event IDs.
4. Investigation plan, uncertainty and proposed actions.
5. The expandable agent audit trail.

The default agent is an offline rule agent. This makes the demo reproducible without falsely presenting static output as generative inference.

## 4. Reproduce the stage distinction

```bash
python -m ransomware_guard analyze --input data/demo_precursors.jsonl --out output/precursors
python -m ransomware_guard analyze --input data/demo_benign.jsonl --out output/benign
python -m ransomware_guard analyze --input data/demo_impact.jsonl --out output/impact
```

| Fixture | Expected result with default rules/baseline |
| --- | --- |
| Precursors | Finance: 100/100, `elevated_precursors`, first warning 10:01:00 UTC, no file-burst time. |
| Benign | Office: 0/100, `no_signal`, no precursor warning or impact signal. |
| Impact | Finance: 100/100, `possible_impact`, warning 10:01:00 UTC, file burst 10:03:00 UTC. |
| Combined | Both the precursor finance host and benign office host appear. |

To regenerate editable fixtures:

```bash
python -m ransomware_guard export-demo --out output/fixtures
```

All fixtures are JSON descriptions of events. They do not perform the described activities, create ransomware, encrypt files or change system protections.

## 5. Verify the release

```bash
python -m unittest discover -s tests -v
```

The initial authoring run passed 55 tests. Inspect [VALIDATION.md](VALIDATION.md) for the environment and scope. The GitHub Actions workflow reruns the suite on pushes and pull requests. A configured workflow is not itself proof that a run passed; inspect the **Actions** tab.

## 6. Understand and normalize your own telemetry

The CLI accepts **one JSON object per line** using this exact top-level schema:

```json
{"id":"export-0001","timestamp":"2026-10-01T10:00:00Z","host":"LAB-HOST-01","type":"auth","actor":"lab-user","details":{"status":"success","destination":"LAB-SHARE-01"}}
```

| Field | Required meaning |
| --- | --- |
| `id` | Stable unique identifier from the source/export. Exact duplicates are removed; conflicting duplicates stop analysis. |
| `timestamp` | Event time in ISO 8601 with timezone. Ingestion time is not a substitute unless explicitly documented. |
| `host` | Host on which activity originated. Use a stable pseudonym for a lab; avoid merging distinct hosts. |
| `type` | One of the eight supported event types listed below. |
| `actor` | Account/principal responsible for the event, normalized consistently. |
| `details` | At most 20 scalar fields. Strings, nonnegative integers and booleans only; nested structures are rejected. |

| Event type | Fields used by the detector | Mapping requirement |
| --- | --- | --- |
| `process_start` | `parent`, `process` | Executable names or paths; process creation source. Command lines are not required. |
| `backup_change` | `action` | Map verified source operations to `delete_snapshot`, `disable_backup`, `delete_backup_catalog`, or a benign label. |
| `security_change` | `action` | Map verified audit operations to `disable_protection`, `stop_sensor`, `tamper_protection`, or a benign label. |
| `credential_alert` | `category` | Existing EDR/audit indicators mapped to `protected_process_access` or `credential_store_access`; this tool does not discover them itself. |
| `auth` | `status`, `destination` | `success`/`failure`; destination identifies the distinct remote target for a successful authentication. |
| `canary` | `file_id`, `action` | A monitored decoy identifier in the separate baseline configuration; `write`/`delete`/`rename` are scored. |
| `file_activity` | `operation`, `count` | Non-overlapping counts of `write` or `rename` events. Overlapping exported counters inflate totals. |
| `network_transfer` | `destination`, `bytes` | Non-overlapping outbound byte totals to a destination. An unknown destination does not prove exfiltration. |

Start with a small sanitized export from systems you administer. Implement and test the mapping in your own adapter; no vendor collector is included. Preserve source timestamps and IDs, monitor dropped events and schema failures, and validate counters against source evidence. The code cannot authenticate labels supplied in a file.

```bash
python -m ransomware_guard analyze --input your-normalized-export.jsonl --out output/your-lab
```

The file limit is 10 MiB, the event cap is 20,000 and a single host window accepts at most 1,000 events. Aggregate non-overlapping counters or narrow the batch if needed. State resets on every invocation; splitting a batch can lose correlations crossing the split.

## 7. Configure rules and host baselines

Copy `config/rules.json` and `config/baseline.json` to a working configuration. Supply them explicitly:

```bash
python -m ransomware_guard analyze --input your-normalized-export.jsonl --rules config/rules.json --baseline config/baseline.json --out output/tuned
```

The window is inclusive: events exactly 300 seconds apart can correlate. Weights contribute once per rule per window; scores are capped at 100. Baselines can change file-volume and fan-out thresholds by host, list known outbound destinations, and identify monitored canaries. They are administrator-supplied assumptions, not learned behavioral profiles.

A precursor warning requires the configured alert threshold, at least two precursor categories, and no file-burst signal in that window. Scores displayed per case are the maximum observed in the batch. The fixed severity bands are 0/info, 1–29/low, 30–59/medium, 60–84/high and 85–100/critical. Response proposals require at least 60 regardless of a customized alert threshold.

Tune using a development dataset containing ordinary office activity, maintenance, backup windows, software deployment and file migrations. Keep a separate held-out validation dataset. Record rule/config versions; review broad exclusions because legitimate tools can be abused.

## 8. Add real generative AI triage

Use the [official Ollama documentation](https://docs.ollama.com/) to prepare a local service and install a model suitable for your hardware. This repository never downloads models or provisions paid APIs. With your installed local model and service running:

```bash
python -m ransomware_guard demo --model YOUR_INSTALLED_LOCAL_MODEL --max-ai-cases 3 --out output/ai-demo
```

Expected behavior: the model chooses `inspect_timeline`, `compare_baseline` or `read_playbook`, sees the returned observation, and finishes with evidence IDs, narrative, uncertainty, next steps and allowed response proposals. Tool arguments are validated independently. Six steps are allowed by default; evidence inspection is required before a valid finish. A repeated tool call, invalid result or unavailable model triggers deterministic fallback and a visible report warning.

Verify the local model's behavior against the supplied fixtures before supplying operational evidence. Loopback is the only HTTP destination, but the local service/model configuration may itself use cloud inference. Confirm its deployment and privacy settings. The authoring environment did not run live Ollama inference; mocked model/transport tests validate the protocol and boundaries.

## 9. Review and simulate a response

The report contains a hashed response plan for each host. Read the relevant evidence and confirm the proposal, then:

```bash
python -m ransomware_guard approve --report output/demo/report.json --case LAB-FINANCE-01 --reviewer lab-reviewer --reviewed --ttl 900 --out output/approval.json
python -m ransomware_guard simulate-response --report output/demo/report.json --approval output/approval.json --ledger output/simulation-ledger.json --out output/simulation.json
```

Review records expire after 15 minutes by default, at most one hour. Changes to the host, evidence, score or proposed actions invalidate the plan hash. The same ledger rejects repeat use. If a crashed run leaves `simulation-ledger.json.lock`, inspect that run before manually removing its stale lock.

The simulation makes no endpoint or identity changes. Review records and the ledger are editable local files without authenticated identities, signatures or tamper-resistant storage. Do not reuse this mechanism as a production authorization system.

## 10. Build an authorized read-only pilot

| Workstream | Required implementation and acceptance evidence |
| --- | --- |
| Telemetry | Authenticated collection, vendor-specific adapters, stable IDs, reliable clocks, coverage/drop monitoring and protected transport/storage. |
| Correlation | Durable streaming state, late-event policy, process/session linkage, bounded retention and replay/reprocessing semantics. |
| Detection | Versioned rules and a separately labeled evaluation set; false positives per host-day, review workload, time-to-alert and coverage by telemetry source. |
| AI | Reviewed model/deployment record, prompt-injection tests, repeatability evaluation, cost/latency limits and grounded citation checks. |
| Agent | Tenant- and case-scoped tools, authenticated users, independent permission checks and tamper-resistant audit storage. |
| Response | A separately designed authenticated approval service, signed scope, distributed replay protection, independently checked asset scope and a documented rollback. |
| Operations | Incident ownership, escalation, backups, change control, monitoring, support and a retention/privacy agreement. |

A real pilot should initially run in shadow mode against sanitized exports, with analysts comparing findings to source evidence. Use authorized simulated telemetry rather than destructive payloads. Promote a detector only after environment-specific evaluation. Any live containment adapter is separate future engineering work requiring explicit operating authorization and tested recovery procedures.

## Troubleshooting

| Message / symptom | Next check |
| --- | --- |
| `No module named ransomware_guard` | Run from the repository root; confirm the package folder exists and the ZIP was extracted. |
| Timestamp timezone error | Add the true source timezone or convert to UTC; do not invent event time. |
| Conflicting duplicate ID | Fix the source/export ID mapping; preserve a unique event identity. |
| Dense host window error | Reduce the batch or export non-overlapping aggregate counters; record the resulting coverage limit. |
| Local model unavailable | Check the installed model name and the operator-controlled service at port 11434; review report warnings. |
| Agent result rejected | Inspect the audit trail; unsupported tools/evidence/actions are intentionally rejected. |
| Review expired or mismatched | Re-review the current report and create a new simulation record; never bypass the validation. |

See [AI_SECURITY.md](AI_SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md) and [VALIDATION.md](VALIDATION.md) for the remaining boundaries.
