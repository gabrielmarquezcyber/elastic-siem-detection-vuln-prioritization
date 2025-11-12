# Elastic Detection Portfolio – Combined Validation Summary

## Executive Overview
This portfolio section demonstrates the successful implementation and validation of two core Windows-based detection scenarios within Elastic Security: 
1. **Suspicious PowerShell Flags (EQL)** – indicative of potential script-based attack execution.
2. **Failed Logon Burst (Event ID 4625)** – representing repeated authentication failures and potential brute-force attempts.

These detections collectively validate Elastic Security’s capability to detect and respond to both execution-based and authentication-based attack surfaces using the Elastic Defend and System integrations. The artifacts produced confirm telemetry flow, rule execution, and alert generation across the Elastic Stack 9.2.0 environment.

## Environment Summary
- **Platform:** Elastic Stack 9.2.0 (Kibana, Fleet, Elastic Agent)
- **Host OS:** Windows 11 (Endpoint with Elastic Agent 9.2.0)
- **Integrations:**
  - Elastic Defend (Endpoint telemetry, process events)
  - System Integration (Windows Security event collection)
- **Agent Status:** Enrolled and healthy in Fleet
- **Data Streams:** `logs-endpoint.events.*`, `system.security`

## Detection 1: Suspicious PowerShell Flags (EQL)

### Objective
Detect potential malicious PowerShell usage characterized by suspicious flags such as `-enc`, `-nop`, or `-NoProfile`.

### Methodology
1. **Telemetry Verification:** Validated ingestion of PowerShell process events through the Elastic Defend integration.
2. **Rule Creation:** Configured a custom EQL rule matching PowerShell command-line arguments containing known obfuscation or evasion flags.
3. **Rule Execution:** Triggered rule manually and verified matches in Discover using KQL queries referencing `kibana.alert.rule.name`.
4. **Alert Validation:** Confirmed detection of PowerShell executions with encoded or no-profile flags.

### Result
Elastic Security correctly identified suspicious PowerShell command executions, producing alerts associated with the EQL rule “Suspicious PowerShell Flags (EQL).” This validates detection for T1059.001 (PowerShell) per the MITRE ATT&CK framework.

### Key Artifacts
- 12_rule_manual_run.png – Manual rule execution screen
- 13_agent_reenrolled_healthy.png – Agent verification post-rule deployment
- 14_discover_verified_powershell.png – Process telemetry verified in Discover
- 15_discover_cmdline_flags.png – Command-line flags verified
- 16_rule_manual_run_success.png – Rule executed successfully

---

## Detection 2: Failed Logon Burst (Event ID 4625)

### Objective
Detect excessive failed Windows logon attempts (Event ID 4625), simulating a brute-force or credential-stuffing attack.

### Methodology
1. **Enable Security Log Collection:** Configured the System integration to include the `security` channel for Windows Event Logs.
2. **Verify Ingestion:** Confirmed appearance of 4625 events in `system.security` using KQL (`winlog.event_id: 4625 OR event.code: 4625`).
3. **Detection Rule Creation:** Implemented a threshold rule alerting on 5+ failed logons within 5 minutes.
4. **Simulation:** Generated repeated failed logons via Windows login interface and command-line `runas.exe` executions.
5. **Validation:** Verified alert generation in Elastic Security, confirming proper telemetry and rule execution.

### Result
The rule successfully triggered on multiple failed logon attempts, validating both event ingestion and detection correlation between GUI and command-line sources.

### Key Artifacts
- 19_system_integration_security_enabled.png – System integration configuration with Security logs enabled
- 20_discover_system_security_hits.png – Confirmation of 4625 events in Discover
- 21_rule_4625_threshold_definition.png – Custom detection rule configuration
- 22_4625_alerts_triggered.png – Alert generation following simulated brute-force attempts

---

## Verification and Outcome
Both detections were validated through manual event simulation, telemetry confirmation, and alert generation. The tests demonstrate full end-to-end visibility—from data collection to detection logic execution—in Elastic Security.

| Detection | Technique | Data Source | Result |
|------------|------------|--------------|---------|
| Suspicious PowerShell Flags | MITRE ATT&CK T1059.001 | Endpoint Process Events | ✅ Alerted successfully |
| Failed Logon Burst (4625) | MITRE ATT&CK T1110 | Windows Security Logs | ✅ Alerted successfully |

---

## Conclusion
These validated detections confirm the organization’s ability to identify critical Windows-based attack behaviors using Elastic Security. The integration of both endpoint and system telemetry enables detection coverage for execution abuse and credential attacks—providing a foundation for future SOC automation and threat-hunting initiatives.

**Artifacts 01–22** collectively evidence the design, implementation, and validation of both detections. All playbooks, configurations, and results are reproducible for inclusion in professional and academic portfolio contexts.
