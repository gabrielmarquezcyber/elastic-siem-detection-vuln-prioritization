# Portfolio Section — Detection Engineering Evidence
**Date:** 2025-11-11  
**Owner:** Gabriel Marquez

This section consolidates the dual-purpose artifacts (interview + Capstone) for two validated detections in Elastic.

## Detection 1 — Suspicious PowerShell Flags (EQL)
- **MITRE:** T1059.001 (PowerShell) — Execution
- **Rule type:** EQL (process) — Schedule 5m, look-back 1m
- **Risk score:** 75 (High)
- **Query (EQL):** See playbook
- **Evidence:** 12–18 (rule run, telemetry verified, alerts and details)
- **Interview angle:** Obfuscated execution detection; command-line analysis; endpoint telemetry validation; `kibana.alert.rule.name` filtering gotchas.

## Detection 2 — Failed Logon Burst (4625)
- **MITRE:** T1110 (Brute Force) — Credential Access
- **Rule type:** Threshold on KQL (per host or user) — Schedule 5m, look-back 1m
- **Risk score:** 75 (High)
- **Query (base KQL):** `data_stream.dataset: "system.security" and winlog.event_id: 4625`
- **Evidence:** 19–21 (ingestion verified); 22–23 if/when threshold rule is enabled and fires.
- **Interview angle:** Windows Security ingestion via System integration; threshold tuning; false-positive management.

## Capstone Mapping (WGU D490)
- **Task 2B (Framework Alignment):** MITRE T1059.001 and T1110 cited; ATT&CK alignment narrative
- **Task 2F (Validation):** Rule preview runs, manual execution tests, telemetry checks
- **Task 2H (Portfolio Presentation):** Playbooks and screenshots assembled for reviewers
- **Task 3 (Evidence/Artifacts):** Rule definitions, screenshots, and test commands

## Notes
- All alert filtering performed with `kibana.alert.rule.name` (Elastic 8/9.x field convention).
- Index scope includes `logs-*` and `endpoint.events.*` to cover both System and Elastic Defend sources.
