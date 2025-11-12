# CVE Prioritizer (KEV + EPSS + CVSS)

**Purpose:** Pull recent CVEs from NVD, enrich with **EPSS** (exploit likelihood) and **CISA KEV** (known exploited), score them by practical risk, and output a CSV + a chart for quick triage.

---

## What it uses
- **NVD API** (`/rest/json/cves/2.0`) — last N days of modified CVEs
- **EPSS** daily feed — exploit probability per CVE
- **CISA KEV** JSON — binary “exploited in the wild” flag

---

## Scoring (balanced weights)
```
Priority = (KEV * 40) + (EPSS * 50) + (CVSS * 10)
```
- **KEV (0/1)** → +40 (exploitation evidence gets a strong boost)
- **EPSS (0–1)** → up to +50 (likelihood matters most)
- **CVSS v3 (0–10)** → up to +100 (impact differentiator)

This keeps KEV items near the top **without** flattening all KEV CVEs to the same score.

---

## Outputs
- `C:\gm-interview-capstone\artifacts\figures\priority.csv`
- `C:\gm-interview-capstone\artifacts\figures\priority_chart.png` (horizontal bar chart; longer bar = higher priority)

---

## How to run (Windows + venv)
```powershell
cd C:\gm-interview-capstone\artifacts\scripts
.\.venv\Scripts\Activate.ps1
python .\cve_prioritizer.py
```

**Accept:** script prints progress and saves CSV + PNG to `artifacts\figures\`.

---

## Configuration
- Lookback window: `LOOKBACK_DAYS` (default 30)
- NVD page size: `PAGE_SIZE` (default 2000)
- Output path: `C:\gm-interview-capstone\artifacts\figures`

---

## NVD API key (secure, via .env)
Create a `.env` at the repo root:
```env
# C:\gm-interview-capstone\.env
NVD_API_KEY=your-key-here
```
`.env` is **git-ignored**; include a public template:
```text
C:\gm-interview-capstone\.env.example
NVD_API_KEY=
```

---

## Dependencies
Within the venv:
```powershell
pip install requests pandas matplotlib python-dotenv
```

---

## Troubleshooting
- **Lots of identical scores / flat chart** → check the scoring line in the script; ensure the balanced weights above are in use.
- **NVD 429/403 or 5xx** → ensure `NVD_API_KEY` is loaded; re-run (script has retries with backoff).
- **Empty NVD results** → try a larger `LOOKBACK_DAYS` or re-run later (NVD occasionally rate-limits).
- **Chart looks “reversed”** → bars are sorted descending; longer = higher priority.

---

## Notes & future extensions
- Add vendor/product filters for your environment (e.g., only Microsoft or only Linux).
- Add age-decay or asset exposure to tailor risk to your org.
- Push results into Elastic for dashboards and alerting.
