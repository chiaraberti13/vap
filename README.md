# 🛡️ Vulnerability Assessment Platform

Professional, modular **Vulnerability Assessment** platform with advanced scanning capabilities and full PDF reporting.

## ✨ Features

- **Multi-Scanner Integration**: Nuclei, Nmap, WhatWeb, Subfinder, Nikto
- **Scans Parallele**: Esecuzione concorrente dei tool con limite configurabile
- **Professional PDF Reports**: Executive summary, charts, OWASP Top 10 mapping
- **Web Dashboard**: Modern UI with Tailwind CSS
- **REST API**: Full API for automation and integrations
- **SQLite Database**: Persistent storage for scans and findings

## ✅ Supported Platforms

- **Linux**: Ubuntu/Debian (fully supported by `installer.sh`)
- **macOS**: Supported via Homebrew (`installer.sh`)
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
│   └── nikto_scanner.py
├── templates/                  # HTML templates
└── reports/                    # Generated PDF reports
```

## 🔧 Configuration

Edit `config.py` to customize:
- Scanner timeouts
- Max scanner concurrency (`VAP_MAX_CONCURRENT_SCANNERS`)
- External tool paths
- PDF report settings
- Database configuration

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

## 📝 License

This project is provided for educational and research purposes.

## 👨‍💻 Author

Chiara Berti

---

**⭐ If you find this useful, please star the project!**
