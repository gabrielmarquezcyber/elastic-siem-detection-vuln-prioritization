# Playbook: Suspicious PowerShell Flags (EQL)

## Objective
Detect and validate obfuscated or encoded PowerShell executions using Elastic Security’s EQL-based detection rules aligned with MITRE ATT&CK Technique T1059.001.

## 1.0 Environment Overview
- Platform: Elastic Cloud 9.2.0 (Security solution)
- Integrations: Windows, Elastic Defend
- Host System: Windows 11 Pro x64
- Agent Policy: “My First Agent Policy”
- Repository Path: `C:\gm-interview-capstone`

## 2.0 Detection Rule Definition
**Rule Name:** Suspicious PowerShell Flags (EQL)  
**Index Patterns:** logs-*, endpoint.events.*, winlogbeat-*  

**EQL Query:**
```eql
process
  where event.type in ("start", "process_started")
    and process.name : ("powershell.exe", "pwsh.exe")
    and (
      process.command_line : "*-enc*" or
      process.command_line : "*-nop*" or
      process.command_line : "*-NoProfile*" or
      process.command_line : "*-EncodedCommand*" or
      process.command_line : "*-ExecutionPolicy*Bypass*" or
      process.command_line : "*FromBase64String*" or
      process.command_line : "*iex (*"
    )
```

## 3.0 Validation & Testing
Telemetry verified after enabling Elastic Defend and process auditing. Alerts confirmed using `kibana.alert.rule.name` in Security → Alerts.

## 4.0 Results
Rule detected PowerShell executions with suspicious flags. Alert latency under 2 minutes. Full process telemetry achieved.

## 5.0 Lessons Learned
1. Process telemetry requires Elastic Defend or Windows audit policy.  
2. Correct alert field is `kibana.alert.rule.name`.  
3. Expanded index patterns prevent omission.  
4. Validation mirrors SOC detection QA workflows.

## 6.0 Evidence and Artifacts
All stored under `C:\gm-interview-capstone\artifacts\figures\`.

| # | Description | Filename |
|---|--------------|-----------|
| 01 | Workspace created | 01_workspace_created.png |
| 02 | Elastic Cloud deployment | 02_elastic_cloud_deployment.png |
| 03 | Fleet enrollment token | 03_fleet_enrollment_token.png |
| 04 | Windows integration added | 04_windows_integration_added.png |
| 05 | Agent healthy | 05_agent_healthy_initial.png |
| 06 | Rule definition | 06_rule_definition_eql.png |
| 07 | Rule schedule and MITRE mapping | 07_rule_schedule_mitre.png |
| 08 | Telemetry gap | 08_discover_no_results_telemetry_gap.png |
| 09 | Elastic Defend added | 09_elastic_defend_added.png |
| 10 | Rule updated indices | 10_rule_index_patterns_updated.png |
| 11 | Rule preview no hits | 11_rule_preview_no_hits.png |
| 12 | Manual rule run | 12_rule_manual_run.png |
| 13 | Agent re-enrolled healthy | 13_agent_reenrolled_healthy.png |
| 14 | Discover PowerShell verified | 14_discover_verified_powershell.png |
| 15 | Command-line flags confirmed | 15_discover_cmdline_flags.png |
| 16 | Rule run success | 16_rule_manual_run_success.png |
| 17 | Alerts filtered by rule | 17_alerts_filtered_by_rule.png |
| 18 | Alert details expanded | 18_alert_details_panel.png |

## 7.0 Conclusion
Validated Elastic Security detection lifecycle from data ingestion to alert generation. The rule fulfills WGU Capstone Task 3 evidence and professional SOC detection engineering documentation standards.
