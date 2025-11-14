# Elastic Rule Exports

This folder contains **detections-as-code** that can be imported into any Elastic Security environment.

## Rules

### `Suspicious_PowerShell_Flags_EQL.ndjson`
- **Type:** EQL  
- **ATT&CK:** T1059.001  
- **Goal:** Detect obfuscated/headless PowerShell using flags like `-EncodedCommand`, `-NoProfile`, `-nop`  
- **Playbook:** `artifacts/playbooks/playbook_suspicious_powershell_flags.md`

### `failed_logon_burst.ndjson`
- **Type:** Threshold KQL  
- **ATT&CK:** T1110 (Brute Force)  
- **Goal:** Detect Event ID 4625 bursts  
- **Playbook:** `artifacts/playbooks/playbook_failed_logon_burst_4625.md`

## How to Import

1. Kibana → **Security → Rules → Import**
2. Select `.ndjson` rule file
3. Confirm settings (index patterns, schedule, severity)
4. Enable the rule
5. Validate using the associated playbook steps

These exports show how detections can be version-controlled instead of living only in the UI.
