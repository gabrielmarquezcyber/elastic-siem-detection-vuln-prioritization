# 🧠 GM Interview Capstone

Detection Engineering + Portfolio Artifacts (Elastic)

This repository contains the end-to-end portfolio artifacts built for the **WGU Cybersecurity Master’s Capstone** and professional interviews.
It includes validated Elastic detections, playbooks, rule exports, a CVE risk prioritization engine, and supporting documentation.

---

## 📂 Repository Structure

```
gm-interview-capstone/
├─ README.md                        ← this file
├─ artifacts/
│  ├─ playbooks/
│  │  ├─ powershell_flags_eql.md
│  │  └─ failed_logon_burst_4625.md
│  ├─ screenshots/                  ← numbered evidence used in playbooks
│  └─ docs/
│     ├─ interview_onepager.md
│     └─ interview_narratives_combined.pdf
├─ rules/
│  ├─ powershell_eql_rule_export.ndjson
│  ├─ failed_logon_4625_rule_export.ndjson
|  └─ README.md
└─ artifacts/scripts/
   ├─ cve_prioritizer.py
   └─ README.md
```

---

## ⚙️ Environment & Tools

**Platform:** Elastic Security (Fleet-Managed Endpoint)
**Integrations:** Windows + System
**Language:** Python 3.11+
**Libraries:** `requests`, `pandas`, `matplotlib`, `python-dotenv`

---

## 🚨 Detections Overview

### 1️⃣ Suspicious PowerShell Flags — *MITRE ATT&CK T1059.001*

**Signal:** PowerShell processes containing `-enc`, `-nop`, `-NoProfile`, or `-w hidden`
**Why it matters:** Indicates script obfuscation or LOLBAS execution
**Artifacts:**

* `artifacts/playbooks/powershell_flags_eql.md`
* `artifacts/elastic/rules/powershell_eql_rule_export.ndjson`
* Screenshots: `artifacts/screenshots/` (10–18)

### 2️⃣ Failed Logon Burst (Event ID 4625)

**Signal:** Multiple failed logon attempts in a short window
**Why it matters:** Early brute-force or spray attempt indicator
**Artifacts:**

* `artifacts/playbooks/failed_logon_burst_4625.md`
* `artifacts/elastic/rules/failed_logon_4625_rule_export.ndjson`
* Screenshots: `artifacts/screenshots/` (19–23)

---

## 📊 CVE Prioritization Engine

**Script:** [`artifacts/scripts/cve_prioritizer.py`](artifacts/scripts/cve_prioritizer.py)
**Purpose:** Merge EPSS, CISA KEV, and NVD CVSS into a unified prioritization model for patch management.
**Output:**

* `artifacts/figures/priority.csv`
* `artifacts/figures/priority_chart.png`

**Balanced scoring model:**

```python
df["Priority"] = (df["KEV"] * 40) + (df["EPSS"] * 50) + (df["CVSS"] * 10)
```

**Usage:**

```powershell
cd artifacts\scripts
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install requests pandas matplotlib python-dotenv
python .\cve_prioritizer.py
```

Outputs are automatically written to `artifacts\figures\`.

---

## 📘 Reproducing the Detections in Elastic

1. **Import rules:**

   * Kibana → Security → Rules → Manage rules → Import
   * Select `.ndjson` files from `artifacts/elastic/rules/`

2. **Validate telemetry:**

   * Confirm `Windows` and `System` integrations are active
   * Verify data streams for:

     * `windows.powershell`
     * `windows.powershell_operational`
     * `system.security`

3. **Trigger events:**

   * Run PowerShell with suspicious flags
   * Generate failed logons via `runas /user:wronguser` or switch-user screen

4. **Confirm alerts:**

   * Check Discover and Security → Alerts
   * Capture screenshots as numbered in each playbook

---

## 🧩 Rule Export Reference

**Folder:** `artifacts/elastic/rules/`
Contains the exported `.ndjson` files for reproducibility and “detections-as-code.”
These can be imported directly into any Elastic Security environment.

Each rule file is accompanied by a short `README.md` explaining import steps.

---

## 🔐 Environment Variables (for CVE Script)

Create a `.env` file at the repo root:

```bash
# NVD API Configuration
NVD_API_KEY=your-actual-api-key-here
```

`.env` is already ignored via `.gitignore`.
For collaborators, include `.env.example` without secrets.

---

## 🗾 License

This project is released under the [MIT License](LICENSE).

---

## ✉️ Contact

**Author:** Gabriel Marquez
**LinkedIn:** [linkedin.com/in/gabrielmarquezcyber](https://linkedin.com/in/gabrielmarquezcyber)
**GitHub:** [github.com/gabrielmarquezcyber](https://github.com/gabrielmarquezcyber)

---

```
📘 Tip: Reviewers can reproduce all detections, rule imports, and prioritization outputs from this README alone.
```
