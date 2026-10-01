# Generative and agentic AI security

## Implemented controls

| Threat | Current control | Remaining limitation |
| --- | --- | --- |
| Prompt injection in log text | Untrusted-data system instruction, fixed read-only tool catalogue and independent argument validation. | Prompt text can still influence or distort a narrative; no claim of injection-proof reasoning. |
| Unsupported tools | Only timeline, baseline comparison and reviewed playbook retrieval. | New tools need their own permission and input validation. |
| Cross-case access | Tool scope is supplied by deterministic code; model arguments cannot select another host or path. | Batch code has no multi-user/tenant authentication. |
| Hallucinated evidence | Final evidence IDs must be a subset of the current case; at least one ID is required for a case with evidence. | A valid ID does not prove the surrounding generated prose is correct. |
| Autonomous containment | Response names are allowlisted and only generate proposals; live execution has no adapter. | A real response integration needs independently verified authenticated approval and scope. |
| Unbounded loops | Six steps by default, at most eight through the library, repeated calls rejected, bounded context/response and generation tokens. | Model latency and reliability depend on hardware/service behavior. |
| Data egress | Fixed loopback request, environment proxies disabled, redirects rejected. | Operator-controlled model service can forward data depending on its configuration. |
| Model failure | Invalid JSON, unsupported actions or failed calls preserve deterministic scoring and trigger visible fallback warnings. | Analyst narrative quality may be limited in fallback mode. |
| Report injection | All event/model text is escaped; HTML contains no JavaScript/remote assets and has a restrictive CSP. | JSON and reports may still contain sensitive source information. |

## Data handling

The default fixtures use fictional hosts and accounts. Before opting into AI with operational data, review exactly which normalized events will be sent to your model service and confirm its deployment, access controls and retention. The tool trace stores excerpts of evidence; generated reports must use an approved sharing/retention process. No API keys or credentials are required by this release.

## Human review model

The local `approve` command records an explicit `--reviewed` acknowledgment. Its record is bound to a plan hash, host, evidence, actions and expiry. The simulation ledger rejects a consumed review ID and uses a local lock to avoid concurrent consumption. These files are editable and unsigned; the reviewer label is not authentication. The design demonstrates a review boundary without claiming production authorization security.

## Validation and next work

The test suite exercises tool rejection, scope isolation, unsupported actions, fabricated evidence, fallback, replay and expiry. Model-driven behavior is verified with fixtures/mocks; real model inference, vendor adapters, cross-tenant services, secrets management and tamper-resistant audit storage remain future pilot work. Separate instruction/data in any future tools and validate every permission outside the language model.
