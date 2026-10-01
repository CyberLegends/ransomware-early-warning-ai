# Detection catalogue

The following are **original reference heuristics**, not vendor-certified ransomware signatures. Thresholds are starting values for synthetic fixtures. Normalize source telemetry correctly and tune against legitimate activity before a pilot.

| ID | Signal and default condition inside a 300-second host window | Weight | Stage | Typical benign confounder |
| --- | --- | --- | --- | --- |
| EW01 | Backup/recovery event labeled snapshot deletion, backup disablement or catalogue deletion. | 35 | Precursor | Approved recovery maintenance or retention cleanup. |
| EW02 | Security-control audit event labeled protection disablement, sensor stop or tampering. | 30 | Precursor | Authorized security-agent maintenance. |
| EW03 | Existing EDR/audit indicator labeled protected-process or credential-store access. | 30 | Precursor | Legitimate diagnostic or security software. |
| EW04 | Office executable launches a supported shell/script-engine executable. | 20 | Precursor | Authorized macros or integration workflows. |
| EW05 | One actor successfully authenticates to at least four distinct destinations. | 25 | Precursor | Administration, patching or inventory operations. |
| EW06 | A separately configured monitored canary identifier is written, deleted or renamed. | 50 | Precursor | Authorized decoy testing or accidental interaction. |
| EW07 | One actor causes at least 80 writes or 30 renames, using non-overlapping event counts. | 40 | Possible impact | File migration, build activity or bulk editing. |
| EW08 | One actor/destination pair transfers at least 50 MiB outside known destinations. | 25 | Precursor | Legitimate file sharing or an unconfigured backup target. |
| EW09 | One actor accumulates at least five authentication failures. | 15 | Precursor | Expired credentials or misconfigured services. |

Repeated events for one rule contribute its weight once per window. The score is capped at 100. A precursor warning additionally needs at least two distinct precursor categories and no EW07 signal in that window. EW03 and EW09 share the identity category; their combination alone does not satisfy that diversity requirement.

## Reference mappings

These links describe related adversary behavior. A reference mapping is not proof that an observed event implements that technique, and MITRE does not endorse this project.

- [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/): context for EW01, including backup/recovery interference. Here the detector consumes normalized audit labels rather than executing or collecting recovery commands.
- [MITRE ATT&CK T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/): context for investigating EW03. A protected-process access alert alone does not establish credential dumping.
- [MITRE ATT&CK T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/): context for EW04; a shell executable name alone does not establish malicious intent.
- [MITRE ATT&CK T1021 — Remote Services](https://attack.mitre.org/techniques/T1021/): context for EW05. Authentication fan-out alone does not prove lateral movement.
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/): context for investigating EW07. File-volume metadata does not confirm encryption.

## Telemetry quality and assessment

Every finding links to supplied event IDs. Independently verify the event source and operation before escalation. The input file can contain incorrect or adversary-influenced labels; schema validation cannot authenticate them. Presence of a rule signal can be a false positive, and missing or evaded telemetry can create a false negative.

The four fixtures validate constructed cases only. Operational evaluation needs labeled held-out examples, maintenance/backup confounders, collection coverage measurements, alert latency, false positives per host-day and analyst review workload. Report both missed incidents and unexplained alerts; do not report synthetic fixture scores as accuracy percentages.
