# AI Security Scanner

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-active-success.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![CI](https://github.com/francescocozzi/ai-security-scanner/actions/workflows/ci.yml/badge.svg)

## 🔐 Overview

**AI Security Scanner** is an open-source tool designed to automatically analyze AI/ML projects for potential security risks, dependency vulnerabilities, data leakage concerns, and bad practices.  
It is useful for DevOps, ML Engineers, security teams, and auditors who want to **detect risks early** in the machine learning pipeline—before deployment.

The tool scans the project structure, dependencies, datasets, and configuration artifacts, and then generates an HTML dashboard with actionable insights.

## 🧠 What It Can Detect

- Security-related patterns and anti-patterns in Python code
- Vulnerable Python library versions (CVE-based)
- Dangerous configuration files
- Indicators of data exposure or leakage
- ML pipeline hygiene issues (bias, imbalance, drift metadata)
- Unsafe handling of secrets, tokens, credentials
- Deprecated cryptographic libraries

## 🖥️ HTML Dashboard Generator

The repository includes a dashboard generator capable of producing:

- Vulnerability summaries
- Visual charts
- Severity scores
- Fix recommendations

Ideal for:

- Security reviews
- CI/CD pipelines
- Compliance reports

## 🚀 Getting Started

### Prerequisites

- Python **3.8+**
- `pip` package manager
- Basic knowledge of CLI usage

### Installation

Clone the repository:

```bash
git clone https://github.com/francescocozzi/ai-security-scanner.git
cd ai-security-scanner
pip install -r requirements.txt
````

### Usage Example

```bash
python scanner.py \
    --target ./project_to_analyze \
    --output ./reports/security_report.html \
    --config ./config/scanner_config.yaml
```

Get full CLI help:

```bash
python scanner.py --help
```

## ⚙️ Configuration

You can customize behavior through a YAML configuration file:

```yaml
checks:
  code_analysis: true
  dependency_vulnerabilities: true
  data_exposure: true

thresholds:
  max_high_issues: 10

report:
  format: html
  save_path: ./reports
```

## 📂 Project Structure

```
ai-security-scanner/
├── __pycache__/                 # Python bytecode cache (auto-generated)
├── data/
│   └── example_scan.json        # Example vulnerability scan results
├── reports/
│   ├── dashboard_example.html   # Example generated HTML report
│   └── plots/                   # Matplotlib charts used in dashboards
├── utils/
│   ├── parser.py                # Scan results parser with ML-driven scoring
│   └── security_scores.py       # Logic for severity classification
├── dashboard_generator.py       # HTML dashboard builder
├── scanner.py                   # Entry point for the security scan
├── requirements.txt             # Python dependencies
├── README.md                    # Project documentation
└── LICENSE                      # Project license
```

## ✅ Features

* Static code analysis (Python)
* Dependency vulnerability auditing
* HTML dashboard reporting
* Severity scoring
* Easy CI/CD integration
* Modular architecture (plug-in friendly)

## 🧪 Tests

Run unit tests:

```bash
pytest
```

## 📸 Dashboard Preview

![Dashboard Example](./docs/dashboard_preview.png)


## 📝 Sample Report Snippet

```json
{
  "vulnerabilities": [
    {"name": "insecure_dependency", "severity": "high"},
    {"name": "weak_credentials", "severity": "medium"}
  ],
  "summary": {
    "high": 3,
    "medium": 5,
    "low": 2
  }
}

## 🔍 Current Checks

- Deprecated / risky Python functions
- Weak cryptographic algorithms
- Hard-coded credentials
- Vulnerable dependencies (CVE-based)
- Suspicious network-related constants


## 💡 Roadmap

Planned improvements include:

* AI-assisted code suggestion engine
* Container image scanning
* Secret-leak pattern classification
* CLI interactive mode
* Export to PDF

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch:
   `git checkout -b feature/my-check`
3. Commit your changes
   `git commit -m "Add new scanning plugin"`
4. Push the branch
   `git push origin feature/my-check`
5. Open a Pull Request

Please ensure that all tests pass before submitting.

## 🔒 Security Notice

If you discover a security vulnerability:

* **Do not** open a public issue
* Please contact the maintainer privately

Responsible disclosure is appreciated.

## 📄 License

Distributed under the **MIT** License.
See the `LICENSE` file for more information.

## 👤 Maintainer

**Francesco Cozzi**
GitHub: [https://github.com/francescocozzi](https://github.com/francescocozzi)

For inquiries, open an Issue or Discussion.

⚠️ This tool does *not* replace manual security review.
It is meant to support—not replace—expert analysis.

## 🔖 Tags

security, cybersecurity, machine-learning, auditing, scanning, CVE, MLOps, DevSecOps
