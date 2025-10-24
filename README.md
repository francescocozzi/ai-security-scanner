TITOLO: AI Security Scanner

# AI Security Scanner

![CI/CD](https://github.com/davidedellisanti90/ai-security-scanner-cyber-sentinel-group/workflows/CI%2FCD%20Pipeline/badge.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

![Coverage](https://img.shields.io/codecov/c/github/davidedellisanti90/ai-security-scanner-cyber-sentinel-group)
![Issues](https://img.shields.io/github/issues/davidedellisanti90/ai-security-scanner-cyber-sentinel-group)
![Stars](https://img.shields.io/github/stars/davidedellisanti90/ai-security-scanner-cyber-sentinel-group)

AI-powered security scanner using Nmap...

--------------------------------------------------------------
Team Cyber Sentinel

Il progetto AI Security Scanner è sviluppato da un gruppo di appassionati di cybersecurity e intelligenza artificiale che credono in un futuro in cui la sicurezza sia automatizzata, trasparente e accessibile a tutti.

Membri del team:

- Ivan Robert D’Arcangelo

- Davide Delli Santi

- Salvatore Scaramuzzi

- Rosita Lavarra

- Nicola Marella

- Lorenzo Misino

- Sonia Rendina

- Vinicius Tadeu Anselmo Leite

-----------------------------------------------------------------

AI Security Scanner è un progetto open-source che combina la potenza dell’intelligenza artificiale con strumenti di network scanning come Nmap, per rendere le analisi di sicurezza più intelligenti, leggibili e automatizzate.

🚀 Obiettivi del progetto

L’obiettivo è creare un sistema capace di:

Eseguire scansioni automatiche su reti e host.
Interpretare i risultati delle scansioni attraverso un parser intelligente.

Fornire report chiari e sintetici, supportati da modelli AI.

Automatizzare test e validazioni per garantire affidabilità e scalabilità.

🧩 Struttura del progetto
ai-security-scanner/
.
├── comandi_git.md\
├── examples\
│   ├── basic_scan.py\
│   └── complete_scan.py
├── htmlcov
│   ├── coverage_html.js
│   ├── d_145eef247bfb46b6___init___py.html
│   ├── d_980325688ee7b2ed___init___py.html
│   ├── d_980325688ee7b2ed_json_converter_py.html
│   ├── d_980325688ee7b2ed_xml_parser_py.html
│   ├── d_e05799d1961e1e02___init___py.html
│   ├── d_e05799d1961e1e02_nmap_wrapper_py.html
│   ├── d_f1b38b22aeb65474___init___py.html
│   ├── favicon_32.png
│   ├── index.html
│   ├── keybd_closed.png
│   ├── keybd_open.png
│   ├── status.json
│   └── style.css
├── README.md
├── requirements.txt
├── scan_results
│   ├── 192_168_1_0_24_scan.xml
│   ├── 192_168_178_36_scan.json
│   ├── 192_168_178_36_scan.xml
│   ├── 192_168_56_1_scan.json
│   ├── 192_168_56_1_scan.xml
│   ├── git rm test_scan_json test_scan_xml_scan.json
│   ├── git rm test_scan_json test_scan_xml_scan.xml
│   ├── IvanRobD_scan.json
│   ├── IvanRobD_scan.xml
│   ├── scanme_nmap_org_scan.json
│   └── scanme_nmap_org_scan.xml
├── src
│   ├── __init__.py
│   ├── parser
│   │   ├── __init__.py
│   │   ├── json_converter.py
│   │   ├── __pycache__
│   │   │   ├── __init__.cpython-312.pyc
│   │   │   ├── json_converter.cpython-312.pyc
│   │   │   └── xml_parser.cpython-312.pyc
│   │   └── xml_parser.py
│   ├── __pycache__
│   │   └── __init__.cpython-312.pyc
│   ├── scanner
│   │   ├── __init__.py
│   │   ├── nmap_wrapper.py
│   │   └── __pycache__
│   │       ├── __init__.cpython-312.pyc
│   │       └── nmap_wrapper.cpython-312.pyc
│   └── utils
│       └── __init__.py
├── tests
│   ├── __init__.py
│   ├── __pycache__
│   │   ├── __init__.cpython-312.pyc
│   │   ├── test_converter.cpython-312-pytest-7.4.4.pyc
│   │   ├── test_demo.cpython-312-pytest-7.4.4.pyc
│   │   ├── test_parser.cpython-312-pytest-7.4.4.pyc
│   │   └── test_scanner.cpython-312-pytest-7.4.4.pyc
│   ├── test_converter.py
│   ├── test_demo.py
│   ├── test_parser.py
│   └── test_scanner.py
├── test_scan.json
└── test_scan.xml

⚙️ Setup e dipendenze

Il progetto utilizza Python 3.x e strumenti di sicurezza come Nmap.
Assicurati di avere entrambi installati.

Installazione su Ubuntu
sudo apt update
sudo apt install nmap python3 python3-pip -y

Clona il progetto
git clone https://github.com/davidedellisanti90/ai-security-scanner-cyber-sentinel-group
cd ai-security-scanner

🧠 Come funziona

Lo script scanner.py avvia la scansione della rete.

I risultati vengono interpretati dal modulo parser/.

I dati elaborati vengono forniti in formato leggibile o pronti per essere analizzati da un modello AI.

Esempio d’uso:


python3 ai-security-scanner-cyber-sentinel-group/examples/complete_scan.py --target 192.168.1.0/24


📘 Documentazione

La documentazione completa e la bozza dell’architettura del progetto sono disponibili nella cartella /docs.
Qui vengono descritti:

Documenti

- 🔍 **Automated Network Scanning** - Nmap wrapper with Python
- 📊 **XML Parsing** - Extract structured data from scan results
- 🔄 **JSON Conversion** - AI-ready data format
- 📈 **Summary Generation** - Key metrics and statistics
- 🧪 **Comprehensive Testing** - 80%+ code coverage with pytest
- 🚀 **CI/CD Pipeline** - Automated testing with GitHub Actions
- 📚 **Professional Documentation** - Complete usage guides

Il flusso logico interno del sistema.

commit ccb91035193761149d3cdfe59ff699470278c9d0 (HEAD -> main, origin/main)
Author: Davide <davide90.oria@gmail.com>
Date:   Fri Oct 24 13:18:18 2025 +0200

    Add CI/CD status badges

commit b874af0f6fb65df6759ecc2e34a9ed679af081b4
Author: Davide <davide90.oria@gmail.com>
Date:   Fri Oct 24 12:59:22 2025 +0200

    Aggiunto automatismo Workflows

commit 41f29968c3026d3893ef026d1c4c1ac38cef22cd
Author: Davide <davide90.oria@gmail.com>
Date:   Fri Oct 24 11:39:12 2025 +0200

    Add coverage configuration

commit c01179f3c6f246c9a4f8f419f09be403f079c85f
Author: Lorenzo <lorenzoloris81@gmail.com>
Date:   Fri Oct 24 10:58:00 2025 +0200

    Add comprehensive test suite with pytest

commit 46608e07d0437c8003c8c4777cd9d97606ec4b93
Author: Davide <davide90.oria@gmail.com>
Date:   Wed Oct 22 13:23:11 2025 +0200

    removed test_scan files

commit d4a4611305dfa83c50da2af2b110c1c81cd6a199
Author: Davide <davide90.oria@gmail.com>
Date:   Wed Oct 22 13:09:21 2025 +0200

    Aggiunto file complete_scan


Le integrazioni AI previste.

Le prossime fasi di sviluppo.

🔮 Prossimi sviluppi

Integrazione di modelli AI per l’analisi dei risultati.

Generazione automatica di report.

Dashboard web per visualizzare le scansioni in tempo reale.

Automazione dei test di sicurezza.

🤝 Contribuire

Le pull request sono benvenute!
Per idee, suggerimenti o collaborazioni, apri una issue o contatta il team.

🧾 Licenza

Distribuito sotto licenza MIT — libero di esplorare, modificare e migliorare.
