# CVE Prioritization Engine (`cve_prioritizer.py`)

This script automates vulnerability risk scoring by combining:

- **NVD CVE data** (CVSS base scores, last N days)
- **CISA Known Exploited Vulnerabilities (KEV)** list
- **EPSS** (Exploit Prediction Scoring System) probabilities

The goal is to produce a **ranked list of CVEs** that help a Vulnerability Management or Detection Engineering team decide what to patch or monitor first.

## What It Does

1. Downloads EPSS feed  
2. Downloads CISA KEV JSON  
3. Calls NVD 2.0 API for CVEs modified within the lookback window  
4. Normalizes into a single DataFrame  
5. Applies a weighted scoring model:

```
Priority = (KEV * 40) + (EPSS * 50) + (CVSS * 10)
```

## Outputs

- `artifacts/figures/priority.csv`
- `artifacts/figures/priority_chart.png`

## How to Run

```
cd artifacts/scripts
python -m venv .venv
.\.venv\Scripts ctivate
pip install -r requirements-extra.txt
python .\cve_prioritizer.py
```

Set an optional `.env` at repo root:

```
NVD_API_KEY=your-api-key
```

## Production Use

In a real environment this script would join vulnerability intelligence with asset inventory to surface:

- CVEs affecting internet-facing systems  
- CVEs with critical business impact  
- Alerts requiring new detections  

