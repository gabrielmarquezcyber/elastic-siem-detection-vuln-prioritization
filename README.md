# 🧠 gm-interview-capstone  
**Detection Engineering & Vulnerability Risk Portfolio (Elastic + Python)**  

Author: **Gabriel Marquez**  
GitHub: [github.com/gabrielmarquezcyber](https://github.com/gabrielmarquezcyber)  
LinkedIn: [linkedin.com/in/gabrielmarquezcyber](https://linkedin.com/in/gabrielmarquezcyber)

This repository showcases **end-to-end detection engineering** and **vulnerability risk automation** work, built and validated in a real Elastic lab.

It is intentionally small and focused so an interviewer can quickly see **how I think, what I build, and how I validate it**—not just that I can follow a lab.

---

## 📂 Repository Overview

```text
gm-interview-capstone/
├─ README.md                     ← this file
├─ artifacts/
│  ├─ playbooks/                 ← human-readable detection runbooks
│  │   ├─ playbook_powershell_eql.md
│  │   ├─ playbook_powershell_eql.pdf
│  │   ├─ playbook_failed_logon_burst_4625.md
│  │   └─ playbook_failed_logon_burst_4625.pdf
│  ├─ playbooks/Old/             ← earlier drafts, kept for history
│  ├─ screenshots/               ← numbered evidence used in playbooks
│  ├─ docs/
│  │   └─ CVE_Prioritization_Automation_OnePager.pdf
│  ├─ figures/
│  │   ├─ priority.csv
│  │   └─ priority_chart.png
│  └─ scripts/
│      ├─ cve_prioritizer.py
│      ├─ README_CVE_Prioritizer.md
│      ├─ requirements-extra.txt
│      └─ cve_prioritizer.old.txt
├─ rules/                        ← Elastic rule exports (detections-as-code)
│  ├─ Suspicious_PowerShell_Flags_EQL.ndjson
│  ├─ failed_logon_burst.ndjson
│  └─ README.md
└─ .env.example                  ← sample config for NVD API key
```

**Primary artifacts:**

- Two validated Elastic detections + playbooks  
- A CVE risk prioritization engine (EPSS + CISA KEV + NVD)  
- Evidence (screenshots, charts, one-pagers) showing how these would run in a real environment  

---

## 🚨 Detection Engineering (Elastic)

### 1️⃣ Suspicious PowerShell Flags (EQL) — MITRE ATT&CK T1059.001

**Goal:** Detect potentially obfuscated or headless PowerShell commonly used in attacks (e.g., `-EncodedCommand`, `-nop`, `-NoProfile`).  

**Data sources**  
- Elastic Defend endpoint telemetry  
- Indices: `logs-*`, `endpoint.events.*`  

**Core EQL logic (simplified):**

```eql
process
  where process.name : ("powershell.exe", "pwsh.exe")
    and (
      process.command_line : "*-enc*" or
      process.command_line : "*-EncodedCommand*" or
      process.command_line : "*-NoProfile*" or
      process.command_line : "*-nop*"
    )
```

**Artifacts**  

- Playbook: `artifacts/playbooks/playbook_powershell_eql.md`  
- Rule export: `rules/Suspicious_PowerShell_Flags_EQL.ndjson`  
- Evidence screenshots: `artifacts/screenshots/` (14–18 in my local numbering)  

**What it demonstrates**  

- Practical, ATT&CK-mapped detection for a very common attacker technique  
- End-to-end validation: manual simulations, Discover queries, and alert verification  
- A clear triage/response flow documented in the playbook  

---

### 2️⃣ Failed Logon Burst (Windows Event ID 4625) — MITRE ATT&CK T1110 (Brute Force)

**Goal:** Detect bursts of failed Windows logons that may indicate password spraying or brute force.  

**Data sources**  

- Windows Security logs via Elastic System integration  
- Data stream: `system.security` (indices `logs-*`)  

**Base KQL filter:**

```kql
data_stream.dataset: "system.security"
and winlog.event_id: 4625
```

The rule is implemented as a **threshold rule** (for example: ≥ 10 events per `user.name` or `host.name` in 10 minutes).

**Artifacts**  

- Playbook: `artifacts/playbooks/playbook_failed_logon_burst_4625.md`  
- Rule export: `rules/failed_logon_burst.ndjson`  
- Evidence screenshots: `artifacts/screenshots/` (19–22 in my local numbering)  

**What it demonstrates**  

- Threshold-based brute force detection mapped to ATT&CK T1110  
- Telemetry enablement and validation steps in Elastic  
- Tuning and response considerations for noisy environments  

---

## 📊 CVE Prioritization Automation (EPSS + KEV + CVSS)

**Script:** `artifacts/scripts/cve_prioritizer.py`  
**Docs:** `artifacts/scripts/README_CVE_Prioritizer.md`, `artifacts/docs/CVE_Prioritization_Automation_OnePager.pdf`  

**Purpose:**  
Ingest public vulnerability intelligence (NVD, CISA KEV, EPSS), normalize it, and produce a ranked list of CVEs suitable for vulnerability management and detection engineering.

**Data sources**  

- EPSS: `https://epss.cyentia.com/epss_scores-current.csv.gz`  
- CISA KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`  
- NVD CVEs: NVD 2.0 API for a configurable lookback window (e.g., last 30 days)  

**Scoring model (example):**

```python
df["Priority"] = (df["KEV"] * 40) + (df["EPSS"] * 50) + (df["CVSS"] * 10)
```

**Outputs**  

- Ranked CSV: `artifacts/figures/priority.csv`  
- Chart: `artifacts/figures/priority_chart.png` (top KEV vs non‑KEV CVEs)  

**Local usage (Windows example):**

```powershell
cd artifacts\scripts
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-extra.txt
python .\cve_prioritizer.py
```

You can optionally set an `NVD_API_KEY` in a `.env` file at the repo root to avoid rate limits.

In a real environment, this script would be integrated with an **asset inventory** so that prioritization focuses on CVEs affecting critical systems, not just “highest scores.”

---

## 🧪 Reproducing the Elastic Detections

**1. Import rules**  

1. In Kibana, go to **Security → Rules → Import**.  
2. Select the appropriate `.ndjson` file from the `rules/` folder.  
3. Review index patterns, schedule, and severity, then enable the rule.

**2. Validate telemetry**  

- Confirm Windows/System and Elastic Defend integrations are active.  
- In **Discover**, validate that data is present:  
  - PowerShell: `process.name : "powershell.exe"` with command‑line flags.  
  - 4625 events: `data_stream.dataset:"system.security" AND winlog.event_id:4625`.

**3. Generate test events**  

_PowerShell (encoded/headless examples):_

```powershell
powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAB0AGUAcwB0AA==
powershell.exe -NoProfile -nop -Command "Write-Output test"
```

_Failed logons:_

- Intentionally log on with a wrong password at the Windows logon screen.  
- Or use:

```powershell
runas.exe /user:.\WrongUser cmd
```

with incorrect credentials.

**4. Confirm alerts**  

- Go to **Security → Alerts** in Kibana.  
- Filter by rule name and confirm that alert details match what is documented in each playbook.

---

## 🎯 Using This Repo in Interviews

This repository is structured so I can quickly demonstrate and explain:

- A concrete detection I built end‑to‑end (rule → validation → playbook).  
- How I validate and tune detections (manual simulations, alert review, threshold tuning).  
- How I think about vulnerability risk (KEV/EPSS/CVSS) and what I would automate next (e.g., joining to asset inventory or ticketing).  
- How these artifacts relate to roles like **Detection Engineer**, **Vulnerability Management Engineer**, or **Threat Hunter / Purple Team**.

Everything uses **public data + my own lab telemetry**—no proprietary information.

---

## 📝 License

This project is released under the **MIT License**. See `LICENSE` for details.