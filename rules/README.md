# Elastic Rule Exports (NDJSON) — Replacement Instructions

Purpose
-------
These files are *placeholders* so your portfolio/capstone has a reproducible slot for rule exports.
Replace each *.ndjson file with the real export from Kibana before submission.

Why keep them?
--------------
- Reviewers/interviewers can import the rules in one click.
- Shows good engineering hygiene (versioned detections-as-code).

How to export from Kibana
-------------------------
1) Kibana → Security → Alerts → Rules → Manage rules.
2) Search for each rule by **Name**:
   - "Suspicious PowerShell Flags (EQL)"
   - "Failed Logon Burst (4625)"
3) Check the boxes for the rules you want to export.
4) Click **Export** → *Export selected rules* (creates a single `.ndjson`).
5) Save the file(s) here, replacing the placeholders:
   - `powershell_eql_rule_export.ndjson`
   - `failed_logon_burst_4625_rule_export.ndjson`

Notes
-----
- NDJSON is line-delimited JSON. Do not edit by hand.
- Keep filenames identical so cross-references in your playbooks/portfolio remain valid.
