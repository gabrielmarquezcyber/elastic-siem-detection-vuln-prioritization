# Detection Playbook: Failed Logon Burst (Event ID 4625)

## Objective
Validate Elastic Security’s capability to detect and alert on excessive failed Windows logon attempts, represented by Event ID 4625 in the Windows Security channel. This scenario simulates a brute-force or credential-stuffing pattern by repeatedly triggering authentication failures.

## Environment
- **Platform:** Elastic Stack 9.2.0 (Kibana + Fleet + Agent)
- **Agent Host:** Windows 11 workstation (`laptop-7vmepubk`)
- **Integrations:** 
  - Elastic Defend (Endpoint telemetry)
  - System Integration (Windows Security log collection enabled)
- **Dataset:** `system.security`

## Procedure

### Step 1 – Enable Windows Security Log Collection
The System integration was configured to ingest Windows Security events. Under the **System → Edit Integration** screen, the `security` channel was enabled to capture Event ID 4625.
  
**Artifact:** `19_system_integration_security_enabled.png`

### Step 2 – Verify Security Log Ingestion
Confirmed visibility of `system.security` events in **Discover** using the following KQL query:
```
data_stream.dataset: "system.security"
```
To confirm failed logon telemetry specifically:
```
winlog.event_id: 4625 OR event.code: 4625
```
Results showed multiple failed logon events associated with user attempts from the Windows login screen and command-line `runas.exe` executions.

**Artifact:** `20_discover_system_security_hits.png`

### Step 3 – Create Detection Rule
A new threshold-based detection rule was defined to trigger an alert when more than five failed logons (Event ID 4625) occur within a short time window.

**Rule Parameters:**
- **Index pattern:** `logs-*`
- **KQL query:**
  ```
  event.code: 4625 OR winlog.event_id: 4625
  ```
- **Threshold:** `count >= 5` within `5 minutes`
- **Severity:** High
- **Risk score:** 75
- **Rule type:** Custom (Threshold)
- **Tags:** Authentication, Brute-force, Windows Security

**Artifact:** `21_rule_4625_threshold_definition.png`

### Step 4 – Generate Failed Logons and Validate Alert
Repeated invalid logon attempts were simulated locally using both GUI login and command-line attempts (`runas /user:WrongUser cmd`).

After several attempts, Elastic Security successfully generated an alert corresponding to the threshold conditions.

**Artifact:** `22_4625_alerts_triggered.png`

## Verification
- **Rule execution:** Succeeded
- **Alerts generated:** Yes (Threshold exceeded for Event ID 4625)
- **Telemetry confirmed:** `system.security` events ingested properly
- **Correlation:** Failed logon events from both login interface and PowerShell `runas.exe` detected

## Artifacts
| # | File | Description |
|---|------|--------------|
| 19 | system_integration_security_enabled.png | Windows System integration with Security log collection enabled |
| 20 | discover_system_security_hits.png | Security log ingestion confirmed via KQL in Discover |
| 21 | rule_4625_threshold_definition.png | Custom detection rule created for excessive failed logons |
| 22 | 4625_alerts_triggered.png | Alert triggered after multiple failed logons |

## Conclusion
Elastic Security successfully identified and alerted on repeated failed authentication attempts, validating proper ingestion of Windows Security logs and functional detection logic for Event ID 4625. This confirms readiness for production deployment of brute-force and account compromise detection rules.
