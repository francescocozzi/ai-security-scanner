# 🛡️ AI Security Scanner

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-active-success.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![CI](https://github.com/francescocozzi/ai-security-scanner/actions/workflows/ci.yml/badge.svg)

**AI Security Scanner** is an open-source tool for automated vulnerability analysis in DevSecOps environments, CI/CD pipelines, and application infrastructures.  
It integrates ML-based analysis, normalized risk scoring, NVD enrichment, and interactive reporting.

✅ Ideal for penetration testers, SOC analysts, DevOps, security engineers  
✅ Ingests and parses Nmap XML scans  
✅ Assigns normalized ML-driven risk scores  
✅ Produces interactive HTML dashboards + charts

---

## 🔍 Key Capabilities

- Advanced parsing of vulnerabilities (Nmap XML)
- Optional enrichment via NVD API (CVSS v3/v3.1)
- Normalization of **risk_score**
- Automatic **priority** calculation for triage
- Visualization plots:
  - Severity distribution
  - Priority distribution
  - Risk score histogram
  - Top vulnerabilities (deduplicated by CVE)
- Responsive HTML dashboard
- Full JSON export for system integration

---

## 🧠 How It Works

Processing pipeline:

1. Vulnerabilities are extracted from the scan report
2. (Optional) NVD CVSS data is fetched
3. A lightweight ML model generates risk signals
4. Scores are normalized using:
   - ML risk score  
   - CVSS  
   - Severity fallback  
   - Priority mapping
5. An **interactive HTML dashboard** is generated
6. Plots and JSON metadata are saved for auditing

---

## 📦 Installation

```bash
git clone https://github.com/francescocozzi/ai-security-scanner.git
cd ai-security-scanner
pip install -r requirements.txt
```

Requires Python ≥ 3.10.

---

## 🚀 Quick Usage

Generate a full report from an Nmap XML file:

```bash
python examples/generate_report.py scan_full.xml --nvd
```

Open the dashboard:

```bash
xdg-open reports/dashboard_*.html
```

---

## 📤 Example Output (CLI)

```
[STEP 1/5] Parsing and ML Analysis...
✓ 51 vulnerabilities found
✓ CVSS enriched (NVD)

[STEP 2/5] Security Analysis...
- Attack Surface Score: 293 (CRITICAL)
- Entry Points: 4

[STEP 3/5] Visualizations...
✓ severity_dist.png
✓ priority_dist.png
✓ risk_dist.png
✓ top_vulns.png

[STEP 4/5] Dashboard generated

[STEP 5/5] Saved JSON Report: scan_full_complete_report.json
```

---

## ⚙️ Configuration

Enable/disable checks:

```yaml
nvd:
  enable: true

analysis:
  ml: true
  risk_normalization: true
```

---

## 📁 Project Structure

```
ai-security-scanner/
├── examples/
│   └── generate_report.py        # Reporting pipeline entry point
├── reports/                      # Generated output
├── src/
│   ├── parser/
│   │   └── xml_parser.py         # Nmap XML ingestion
│   ├── security/
│   │   ├── attack_surface.py
│   │   ├── threat_model.py
│   │   └── recommendations.py
│   └── visualization/
│       ├── plotter.py            # Matplotlib visualizations
│       └── dashboard.py          # HTML rendering
├── requirements.txt
├── README.md
├── LICENSE
└── ...
```

---

## 🧮 Risk Score Normalization

The pipeline takes the **maximum** score across:

- ML risk
- CVSS baseScore
- Severity mapping
- Priority mapping

Simplified formula:

```
risk_normalized = max(
    ml_risk_score,
    cvss_score,
    severity_mapping,
    priority_mapping
)
```

Priority thresholds:

| Risk score | Priority | Action |
|------------|----------|--------|
| ≥ 9.0      | P1       | Immediate mitigation |
| ≥ 7.0      | P2       | High priority |
| ≥ 4.0      | P3       | Planned fix |
| < 4.0      | P4       | Monitor |

---

## 📊 Generated Charts

- **Severity Distribution**
- **Priority Distribution**
- **Risk Score Histogram**
- **Top Vulnerabilities** *(deduplicated by CVE)*

---

## 🖥️ Dashboard

Interactive, printable, structured into:

- High-level KPIs
- Visual charts
- Priority/Severity breakdown
- Top 10 highest-risk vulnerabilities
- Mitigation recommendations

---

## 🔌 CI/CD Integration

Example pipeline step that fails on P1 findings:

```bash
grep '"priority": 1' scan_full_complete_report.json \
  | wc -l | awk '$1 > 0 { exit 1 }'
```

---

## 🧪 Tests

```bash
pytest
```

---

## 🔐 Security Notes

If you discover an issue:

- **Do not** open a public GitHub issue
- Reach out privately

Responsible disclosure is appreciated.

---

## ⚠️ Disclaimer

This tool does **not** replace human security review.  
It accelerates triage—but expert analysis is still required.

---

## 📍 Roadmap

- Native PDF export
- Plugin architecture (OWASP checks)
- Container image scanning
- SBOM ingestion
- ML-based secret detection
- Trend / delta history

---

## 🤝 Contributing

1. Fork
2. `git checkout -b feature/...`
3. Commit
4. Push
5. Open a PR

Please ensure tests pass ✅

---

## 📜 License

MIT — free for commercial use.

---

## 👤 Maintainer

**Francesco Cozzi**  
GitHub: https://github.com/francescocozzi

---

## 🔖 Tags

security, cybersecurity, devsecops, ml-security, cve, scanner, dashboard, nmap, vulnerability-management, pentesting, CI/CD, risk-scoring, CVSS
