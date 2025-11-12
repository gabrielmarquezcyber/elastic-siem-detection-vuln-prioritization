# CVE Prioritization Automation

This folder contains the `cve_prioritizer.py` script used to automate vulnerability prioritization for the GM Interview Capstone project.
The tool aggregates and correlates three authoritative data sources to produce an actionable risk ranking:

- **EPSS (Exploit Prediction Scoring System)** – Probability of exploitation in the wild  
- **CISA KEV Catalog** – Government-verified list of known exploited vulnerabilities  
- **NVD CVSS** – Base severity score from the National Vulnerability Database

## Output
The script generates two outputs for inclusion in the portfolio:
- `priority.csv` – Combined CVE dataset with computed `Priority` scores  
- `priority_chart.png` – Visualization of the top 15 CVEs by risk weighting

Files are saved to:
```
C:\gm-interview-capstone\artifacts\figures\
```

## Usage
Run inside the virtual environment (`.venv`):
```powershell
Set-Location "C:\gm-interview-capstone\artifacts\scripts"
.\.venv\Scripts\Activate.ps1
python .\cve_prioritizer.py
```

## API key (optional but recommended)
To avoid NVD rate limits, set an API key as an environment variable before running:
```powershell
$env:NVD_API_KEY = "<your-key-here>"
```
If no key is set, the script will still run, but may fall back to a smaller recent window.

## Priority formula (transparent / explainable)
```
Priority = (KEV * 100) + (EPSS * 50) + (CVSS * 5)
```
- **KEV** is `1` if the CVE is in the CISA KEV Catalog, else `0`
- **EPSS** is the current probability (0.0–1.0)
- **CVSS** is the NVD base score (0–10)

## Notes
- Designed for reproducibility and clarity; no external configuration required  
- Demonstrates automation of risk-based vulnerability management workflows  
- CSV can be joined with asset inventories to focus on **exposed & relevant** CVEs
