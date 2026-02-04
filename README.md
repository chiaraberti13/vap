# 🛡️ Vulnerability Assessment Platform

Professional, modular **Vulnerability Assessment** platform with advanced scanning capabilities and full PDF reporting.

## ✨ Features

- **Multi-Scanner Integration**: Nuclei, Nmap, WhatWeb, Subfinder, Nikto, Dirsearch, SQLMap, XSStrike, ZAP, Burp, Wapiti, Commix
- **Scanner Enterprise (opzionali)**: Acunetix, Nessus via API
- **Vulnerability Correlation Engine**: deduplica e collega i findings multi-tool
- **False Positive ML Model**: modello logistico per stimare falsi positivi
- **CVE Enrichment**: integrazione NVD + ExploitDB per verifica CVE
- **MITRE ATT&CK Mapping**: mappatura automatica tecnica/tattica
- **Scans Parallele**: Esecuzione concorrente dei tool con limite configurabile
- **Professional PDF Reports**: Executive summary, charts, OWASP Top 10 mapping
- **Web Dashboard**: Modern UI with Tailwind CSS
- **REST API**: Full API for automation and integrations
- **SQLite Database**: Persistent storage for scans and findings

## ✅ Supported Platforms

- **Linux**: Ubuntu/Debian (fully supported by `installer.sh`)
- **macOS**: Supported on macOS 11+ via Homebrew or MacPorts (`installer.sh`)
- **Windows**: Supported via PowerShell (`installer.ps1`)

## 🚀 Quick Start (Linux/macOS)

```bash
# 1. Extract the archive
tar -xzf vulnerability-assessment-platform.tar.gz
cd vulnerability-assessment-platform

# 2. Run the installer
chmod +x installer.sh
./installer.sh

# 3. Activate the virtual environment
source venv/bin/activate

# 4. Start the server
python3 app.py
```

The server will be available at `http://localhost:8000`.

### 📖 Documentazione (MkDocs)

```bash
pip install mkdocs-material
mkdocs serve
```

Documentazione locale: `http://127.0.0.1:8000/`
Spec OpenAPI: `http://localhost:8000/openapi.json`
Swagger UI: `http://localhost:8000/docs`

### ⚙️ Avvio Celery worker (scansioni asincrone)

Le scansioni parallele richiedono Redis e un worker Celery attivo.

```bash
# Avvia Redis (esempio Ubuntu/Debian)
sudo systemctl start redis-server

# Avvia il worker Celery (usa la coda configurata in VAP_CELERY_DEFAULT_QUEUE)
celery -A celery_app.celery_app worker -l info -Q scans -c 4
```

> Suggerimento: personalizza la concorrenza con `VAP_CELERY_WORKER_CONCURRENCY`.

## 🚀 Quick Start (Windows)

Open PowerShell and run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1
```

Then start the server:

```powershell
.\venv\Scripts\Activate.ps1
python app.py
```

## 📋 Requirements

- **Python**: 3.10 - 3.12 (3.13+ not yet supported)
- **Go**: 1.19+ (for external tools)
- **External Tools**: Nmap, Nikto (installed by the installer when possible)

## 🎯 Usage

### Web UI

1. Open `http://localhost:8000` in your browser
2. Enter a target (URL or IP)
3. Select a scan type
4. Start the scan
5. Review findings and generate the PDF report

### API

```bash
# Create a new scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_type": "full"}'

# Check status
curl http://localhost:8000/api/v1/scans/{scan_id}/status

# Download report
curl -O http://localhost:8000/api/v1/scans/{scan_id}/report/download
```

### CLI

```bash
python3 scanner_engine.py --target https://example.com --output results.json
```

## 🏗️ Architecture

```
vulnerability-assessment-platform/
├── app.py                      # FastAPI server
├── scanner_engine.py           # Scan orchestration engine
├── report_generator.py         # PDF report generator
├── database.py                 # ORM models
├── config.py                   # Configuration
├── installer.sh                # Linux/macOS installer
├── installer.ps1               # Windows installer
├── requirements.txt            # Python dependencies
├── scanners/                   # Scanner modules
│   ├── nuclei_scanner.py
│   ├── nmap_scanner.py
│   ├── whatweb_scanner.py
│   ├── subfinder_scanner.py
│   ├── nikto_scanner.py
│   ├── dirsearch_scanner.py
│   ├── sqlmap_scanner.py
│   ├── xsstrike_scanner.py
│   ├── zap_scanner.py
│   ├── burp_scanner.py
│   ├── wapiti_scanner.py
│   ├── commix_scanner.py
│   ├── acunetix_scanner.py
│   └── nessus_scanner.py
├── templates/                  # HTML templates
└── reports/                    # Generated PDF reports
```

## 🔧 Configuration

Per un setup completo **copia `.env.example` in `.env`**: include tutte le variabili lette da `config.py` (JWT, CORS, rate limit, header di sicurezza, integrazioni API, Celery/Redis, NVD/ExploitDB, ecc.).  
Se preferisci, puoi continuare a modificare direttamente `config.py`.

📌 **Mappa completa variabili (.env ↔ config.py)**: vedi `docs/configuration.md` per la tabella con *tutte* le variabili, i default e l’hardening minimo.

Edit `config.py` to customize:
- Scanner timeouts
- Max scanner concurrency (`VAP_MAX_CONCURRENT_SCANNERS`)
- External tool paths
- PDF report settings
- Database configuration
- Redis API response caching (`VAP_API_CACHE_ENABLED`, `VAP_API_CACHE_REDIS_URL`, `VAP_API_CACHE_TTL`, `VAP_API_CACHE_PREFIX`)

### ✅ Configurazione completa (.env)

```bash
# 1) Duplica il file di esempio completo
cp .env.example .env

# 2) Modifica le variabili necessarie
nano .env
```

> Suggerimento: lascia vuote le API key che non usi (es. Acunetix/Nessus) e abilita solo i tool realmente installati.

## 🧪 Testing

```bash
# Esegue tutti i test automatici
pytest

# (Opzionale) test singolo modulo
pytest tests/test_api.py -k "scan"
```

> Consiglio: esegui i test in un virtualenv pulito e con Redis attivo se vuoi validare anche la parte Celery/async.

## 🛡️ Checklist hardening produzione

Per un deploy sicuro in produzione, imposta almeno:

1. **Autenticazione**: imposta `VAP_API_KEY` (o `VAP_API_KEY_HASH`) e abilita JWT con `VAP_JWT_REQUIRED=true`.
2. **Segreti**: imposta `VAP_JWT_SECRET` e `VAP_CSRF_SECRET` con valori strong/rotabili.
3. **HTTPS**: abilita `VAP_REQUIRE_HTTPS=true` e configura `VAP_TLS_CERTFILE`/`VAP_TLS_KEYFILE`.
4. **CORS**: limita `VAP_CORS_ALLOWED_ORIGINS` ai soli domini consentiti.
5. **Rate limiting**: rivedi `VAP_RATE_LIMIT_*` per proteggere endpoint critici.
6. **Security headers**: lascia `VAP_SECURITY_HEADERS=true` e verifica `VAP_CSP_POLICY`.
7. **Audit & retention**: configura `VAP_AUDIT_LOGGING`, `VAP_AUDIT_RETENTION_DAYS` e `VAP_CONSENT_RETENTION_DAYS`.

> Nota: in produzione evita credenziali di demo (`VAP_JWT_DEMO_PASSWORD`) e ruota periodicamente le chiavi.

Per dettagli operativi e ulteriori best practice di sicurezza: `docs/security.md`.

## 📊 Report Features

PDF reports include:
- **Executive summary** with risk level
- **Charts** (pie chart, bar chart)
- **Technical details** for every vulnerability
- **CVE** and **CVSS score**
- **OWASP Top 10 mapping**
- **Remediation recommendations**

## 🔒 Security Notice

This tool is intended **ONLY** for:
- Authorized penetration testing
- Professional security auditing
- Security research

Unauthorized use may violate local and international laws. You are responsible for appropriate usage.

## 📚 Official Documentation

- **FastAPI**: https://fastapi.tiangolo.com/
- **Uvicorn**: https://www.uvicorn.org/
- **SQLAlchemy**: https://docs.sqlalchemy.org/
- **ReportLab**: https://www.reportlab.com/documentation/
- **Tailwind CSS**: https://tailwindcss.com/docs
- **Redis (redis-py)**: https://redis-py.readthedocs.io/
- **SQLMap**: http://sqlmap.org/
- **XSStrike**: https://github.com/s0md3v/XSStrike
- **OWASP ZAP**: https://www.zaproxy.org/docs/
- **Burp Suite**: https://portswigger.net/burp/documentation
- **Wapiti**: https://wapiti-scanner.github.io/
- **Commix**: https://github.com/commixproject/commix
- **NVD API**: https://nvd.nist.gov/developers/vulnerabilities
- **MITRE ATT&CK**: https://attack.mitre.org/
- **ExploitDB / Searchsploit**: https://www.exploit-db.com/searchsploit

## 🧰 OpenAPI generation

```bash
python scripts/generate_openapi.py
```

## 📝 License

This project is provided for educational and research purposes.

## 👨‍💻 Author

Chiara Berti

---

**⭐ If you find this useful, please star the project!**
