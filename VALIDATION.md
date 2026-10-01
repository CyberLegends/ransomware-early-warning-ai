# Validation record — initial 0.1.0 release

**Authoring date:** 1 October 2026. **Local environment:** Python 3.12.14 on Linux. Results below apply to the published initial code and synthetic fixtures, not to later edits or an operational deployment.

| Check | Observed outcome |
| --- | --- |
| `python -m unittest discover -s tests -v` | 55 tests passed. |
| CLI smoke matrix | 10 scenarios passed: demo, four fixture analyses, export, reviewed approval, response simulation, rejected replay and help. |
| Combined demo | 10 events; finance 100/100 with elevated precursors, office 0/100 with the lab baseline. |
| Impact fixture | Precursor warning at 10:01:00 UTC, file-burst signal at 10:03:00 UTC; classified `possible_impact`. |
| Response simulation | `external_systems_modified: false`; consumed review record rejected on reuse with the same ledger. |
| Generative adapter | Mocked HTTP response verified the fixed loopback destination, nonstreaming JSON schema request and completed-response handling. |
| Agent loop | Mocked model selected a read-only tool and returned a validated result; forbidden tools/actions/evidence, loops and failures produced rejection/fallback. |
| Output safety | HTML escaping and the restrictive content-security policy verified in regression tests. |

## Test coverage areas

- Window expiration, precursor/impact ordering, distinct categories, bounded scores, host/actor separation and baseline thresholds.
- Exact/conflicting duplicate events, malformed inputs, booleans used as counts, timezone handling, overly dense host windows and nonmutation of inputs.
- Agent scope, fabricated evidence, unexpected tool parameters/actions, budget exhaustion, duplicate calls and unavailable-model fallback.
- Explicit review acknowledgment, plan changes, expiry, future-dated records, replay and ledger lock conflicts.
- JSON/HTML reports, escaped generated prose, redirect rejection and optional-model request structure.

## Not validated here

No live Ollama model inference, Windows/macOS runtime execution, production telemetry adapter, live endpoint collector or live response API was tested in the authoring environment. The workflow includes Python 3.11, 3.12 and 3.13 CI jobs, but their status must be read from GitHub Actions after publication rather than inferred from the YAML file.

The synthetic 120-second warning-to-file-burst gap is deliberately authored fixture timing. The fixtures do not establish production precision, recall, false-positive rate, attribution, lead time or prevention effectiveness. A real pilot needs separate labeled data, source authentication, collection-coverage measurements and environment-specific acceptance criteria.
