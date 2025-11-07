# gm-interview-capstone

**Goal (demo-ready today):** Vulnerability → EPSS/KEV enrichment → Detect → Validate → Respond.

**Components you will produce now:**
- Python CVE prioritizer (EPSS/KEV/CVSS), 30-day window with NVD pagination (API key optional)
- 2 Elastic detections (Suspicious PowerShell flags, Failed Logon Burst) using ECS fields
- ATT&CK coverage snapshot (T1059.001, T1110)
- Two 1-page executive playbooks (PDF)
- 5-min demo script + pre-demo checklist

**Safety:** Elastic Agent only sends outbound logs; uninstall anytime with elastic-agent uninstall.
