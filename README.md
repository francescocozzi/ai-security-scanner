# 🛡️ AI Security Scanner

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-active-success.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![CI](https://github.com/francescocozzi/ai-security-scanner/actions/workflows/ci.yml/badge.svg)

**AI Security Scanner** è uno strumento open-source per l’analisi automatizzata delle vulnerabilità in ambienti DevSecOps, pipeline CI/CD e infrastrutture applicative.  
Integra analisi ML, punteggi di rischio normalizzati, correlazione con dati NVD e generazione di report interattivi.

✅ Ideale per penetration tester, SOC, DevOps, analisti sicurezza  
✅ Esegue ingest di scansioni Nmap XML  
✅ Assegna risk score ML-driven  
✅ Produce report HTML interattivi + grafici

---

## 🔍 Funzionalità principali

- Parsing avanzato di vulnerabilità (Nmap XML)
- Integrazione facoltativa con NVD API (CVSS v3/v3.1)
- Normalizzazione del **risk_score**
- Calcolo della **priority** per triage operativo
- Rappresentazione grafica:
  - Severity distribution
  - Priority distribution
  - Risk score distribution
  - Top vulnerabilities (deduplicate by CVE)
- Dashboard HTML responsive e stampabile
- JSON completo per integrazioni esterne

---

## 🧠 Come funziona

Durante l’elaborazione:

1. Le vulnerabilità vengono estratte dal report
2. Se richiesto, vengono arricchite con dati **NVD** (CVSS)
3. Si applica un modello ML (lightweight) per scoring
4. Si normalizza il punteggio combinando:
   - ML risk score  
   - CVSS  
   - Severity fallback  
   - Priority map
5. Viene generato un **dashboard HTML interattivo**
6. Si salvano grafici PNG e report JSON completi

---

## 📦 Installazione

```bash
git clone https://github.com/francescocozzi/ai-security-scanner.git
cd ai-security-scanner
pip install -r requirements.txt
```

Richiede Python ≥ 3.10.

---

## 🚀 Utilizzo rapido

Generazione report completo da scan Nmap XML:

```bash
python examples/generate_report.py scan_full.xml --nvd
```

Apri subito il dashboard:

```bash
xdg-open reports/dashboard_*.html
```

---

## 📤 Esempio output (CLI)

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

## ⚙️ Configurazione

Puoi abilitare/disabilitare controlli:

```yaml
nvd:
  enable: true

analysis:
  ml: true
  risk_normalization: true
```

---

## 📁 Struttura del progetto

```
ai-security-scanner/
├── examples/
│   └── generate_report.py        # Entry per report pipeline
├── reports/                      # Output generati
├── src/
│   ├── parser/
│   │   └── xml_parser.py         # Ingest Nmap XML
│   ├── security/
│   │   ├── attack_surface.py
│   │   ├── threat_model.py
│   │   └── recommendations.py
│   └── visualization/
│       ├── plotter.py            # Grafici (matplotlib)
│       └── dashboard.py          # Dashboard HTML
├── requirements.txt
├── README.md
├── LICENSE
└── ...
```

---

## 🧮 Risk Score Normalization

La pipeline massimizza il punteggio fra:

- ML risk
- CVSS baseScore
- Severity mapping
- Priority mapping

Formula (semplificata):

```
risk_normalized = max(
    ml_risk_score,
    cvss_score,
    severity_mapping,
    priority_mapping
)
```

Priorità assegnata automaticamente:

| Risk score | Priority | Azione |
|------------|----------|--------|
| ≥ 9.0      | P1       | Immediata |
| ≥ 7.0      | P2       | Rapida |
| ≥ 4.0      | P3       | Pianificata |
| < 4.0      | P4       | Monitoraggio |

---

## 📊 Grafici generati

- **Severity Distribution**
- **Priority Distribution**
- **Risk Score Histogram**
- **Top Vulnerabilities** *(deduplicate by CVE)*

---

## 🖥️ Dashboard

Interattivo, exportabile come PDF, sezioni:

- KPI
- Charts
- Riepilogo Priority/Severity
- Top 10 Highest-Risk (dedup)
- Raccomandazioni

---

## 🔌 Integrazione CI/CD

Esempio di fail della pipeline se presenti P1:

```bash
grep '"priority": 1' scan_full_complete_report.json \
  | wc -l | awk '$1 > 0 { exit 1 }'
```

---

## 🧪 Test

```bash
pytest
```

---

## 🔐 Security Notes

Se trovi una vulnerabilità nella repo:

- **Non** aprire un issue pubblico
- Contatta privatamente il maintainer

Responsible disclosure welcome.

---

## ⚠️ Disclaimer

Questo tool **non sostituisce**
un’analisi di sicurezza umana.  
È un acceleratore di triage e prioritizzazione.

---

## 📍 Roadmap

- Export PDF nativo
- Plugin architecture (OWASP checks)
- Container image scanning
- SBOM ingestion
- Secret-detection ML
- Delta scan (trend history)

---

## 🤝 Contributing

1. Fork
2. `git checkout -b feature/...`
3. Commit
4. Push
5. PR

Con test verdi 😉

---

## 📜 License

MIT — libero utilizzo anche commerciale.

---

## 👤 Maintainer

**Francesco Cozzi**  
GitHub: https://github.com/francescocozzi

---

## 🔖 Tags

security, cybersecurity, devsecops, ml-security, cve, scanner, dashboard, nmap, vulnerability-management, pentesting, CI/CD, risk-scoring, CVSS
