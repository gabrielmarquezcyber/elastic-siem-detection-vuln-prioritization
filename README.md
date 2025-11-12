# gm-interview-capstone

Detection engineering + portfolio artifacts (Elastic). Includes:
- Two validated detections with rule exports and playbooks
- Evidence screenshots
- A CVE prioritization script (EPSS + KEV + CVSS) with chart output
- Interview narratives/briefs

## Contents

gm-interview-capstone/
├─ README.md ← you are here
├─ artifacts/
│ ├─ playbooks/
│ │ ├─ powershell_flags_eql.md
│ │ └─ failed_logon_burst_4625.md
│ ├─ elastic/
│ │ └─ rules/
│ │ ├─ powershell_eql_rule_export.ndjson
│ │ ├─ failed_logon_4625_rule_export.ndjson
│ │ └─ README.md
│ ├─ screenshots/ ← numbered PNGs used by playbooks
│ └─ docs/
│ └─ interview_narratives_combined.pdf
├─ rules/ ← optional mirror of rule exports
│ ├─ powershell_eql_rule_export.ndjson
│ └─ failed_logon_4625_rule_export.ndjson
└─ artifacts/scripts/
├─ cve_prioritizer.py
└─ README.md

## Reproduce the detections

**Import rules in Elastic Security**  
Security → Rules → Manage rules → *Export/Import* → Import the `.ndjson` in `artifacts/elastic/rules/`.

**Run the rules**  
Ensure your Windows + System integrations are active and ingesting:
- PowerShell Operational, PowerShell
- System/Security (4625 failures)

Use the playbooks in `artifacts/playbooks/` for generation steps, Discover KQL, and expected alert screenshots.

## CVE Prioritizer

- Script: `artifacts/scripts/cve_prioritizer.py`  
- Output: `artifacts/figures/priority.csv` + `priority_chart.png`  

Usage (PowerShell):

```powershell
cd C:\gm-interview-capstone\artifacts\scripts
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install requests pandas matplotlib
python .\cve_prioritizer.py
Rule exports
See artifacts/elastic/rules/README.md for one-click re-import instructions.

Notes
No secrets are committed. If you add a .env, keep it out of Git.

Screenshots are numbered to match the playbooks’ Evidence sections.

sql
Copy code

Commit it:

```powershell
git add README.md
git commit -m "Add top-level README with structure and instructions"
git push
3) Interview one-pager (paste this, optional but helpful)
Create C:\gm-interview-capstone\artifacts\docs\interview_onepager.md:

markdown
Copy code
# Detection Engineering One-Pager

**Environment:** Elastic Security (Fleet-managed Endpoint), Windows + System integrations

## Detection 1 — Suspicious PowerShell Flags (T1059.001)
- **Signal:** PowerShell with `-enc`, `-nop`, `-NoProfile`, or `-w hidden`
- **Why it matters:** Common in obfuscated/LOLBAS tradecraft
- **Validation:** Generated events, verified in Discover, rule fired; alert triage captured
- **Artifacts:** Rule export NDJSON, playbook, numbered screenshots

## Detection 2 — Repeated Failed Logons (4625 Burst)
- **Signal:** Multiple `4625` in short window per host/user
- **Why it matters:** Spray/guessing; early brute-force indicator
- **Validation:** Enabled System/Security stream → generated interactive/`runas` failures → rule fired
- **Artifacts:** Rule export NDJSON, playbook, numbered screenshots

## Enrichment/Analytics — CVE Prioritizer
- **Inputs:** NVD (last 30d), CISA KEV, EPSS
- **Logic:** Balanced score (KEV, exploit likelihood, severity), chart for comms
- **Outcome:** CSV + visualization for backlog slicing

## What I’d do next in a SOC
- Promote rules to prod policy with suppression/tuning
- Add exceptions for known admin tasks
- Add dashboards for 4625 + MFA correlation
- Wire rule action → case mgmt/webhook
