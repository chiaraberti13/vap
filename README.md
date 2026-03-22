# VAP — Vulnerability Assessment Platform

> **Disclaimer:** This tool is intended **exclusively** for authorized security testing on systems you own or have explicit written permission to test. Unauthorized use is illegal.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Installation — Linux / macOS](#installation--linux--macos)
- [Installation — Windows](#installation--windows)
- [Configuration](#configuration)
- [Starting the Platform](#starting-the-platform)
- [Usage](#usage)
- [Security Hardening](#security-hardening)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [License](#license)

---

## Features

- **Multi-Scanner Integration**: Nuclei, Nmap, WhatWeb, Subfinder, Nikto, Dirsearch, SQLMap, XSStrike, ZAP, Burp Suite, Wapiti, Commix
- **Enterprise Scanners (optional)**: Acunetix, Nessus via API
- **Vulnerability Correlation Engine**: deduplication and linking of multi-tool findings
- **False Positive ML Model**: logistic regression model to estimate false positives
- **CVE Enrichment**: NVD + ExploitDB integration
- **MITRE ATT&CK Mapping**: automatic tactic/technique classification
- **Parallel Scans**: concurrent execution with configurable concurrency limit
- **Professional PDF Reports**: executive summary, charts, OWASP Top 10 mapping
- **Web Dashboard**: modern UI with Tailwind CSS
- **REST API**: full API for automation and integrations
- **SQLite Database**: persistent storage for scans and findings

---

## Quick Start

### Linux / macOS

```bash
# 1. Run the installer (do NOT run as root)
chmod +x installer.sh
./installer.sh

# 2. Activate the virtual environment
source venv/bin/activate

# 3. Copy and configure the environment file
cp .env.example .env
# Edit .env — at minimum set: VAP_CSRF_SECRET, VAP_JWT_SECRET, VAP_API_KEY

# 4. Start the server
python3 app.py
```

Open the dashboard at `http://localhost:8000`.

### Windows

```powershell
# 1. Run the PowerShell installer (as Administrator)
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1

# 2. Activate the virtual environment
.\venv\Scripts\Activate.ps1

# 3. Copy and configure the environment file
copy .env.example .env

# 4. Start the server
python app.py
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10 – 3.12 | Python 3.13+ not yet supported (pydantic-core build issues) |
| Go | ≥ 1.19 | Required for Nuclei and Subfinder |
| Redis | 6 or 7 | Required for Celery async scans — not needed for simulated mode |
| nmap | any recent | Optional — scanner falls back to simulated mode if missing |
| nikto | any recent | Optional |

**Supported operating systems:**
- **Linux**: Ubuntu 20.04+, Debian 11+, Kali, Linux Mint, Pop!\_OS, Fedora, RHEL/CentOS/Rocky/AlmaLinux 8+, Arch, Manjaro, openSUSE
- **macOS**: 11 (Big Sur) or later — Homebrew or MacPorts required
- **Windows**: 10/11 — PowerShell 5+ required; Redis must be installed separately

---

## Installation — Linux / macOS

```bash
chmod +x installer.sh
./installer.sh
```

The installer will:
1. Detect your OS and install system packages (apt / dnf / pacman / zypper / Homebrew)
2. Install Go tools: Nuclei, Subfinder, Assetfinder
3. Clone and configure WhatWeb and Dirsearch
4. Create a Python virtual environment (`venv/`)
5. Install Python dependencies from `requirements.txt`
6. Initialise the SQLite database

**macOS notes:**
- Requires macOS 11+ and Homebrew (`https://brew.sh`) or MacPorts
- WhatWeb `make install` may fail due to Ruby gem build issues — the installer automatically falls back to a local wrapper (fully functional)

**If an error occurs**, an error log is saved to `installer_errors_YYYYMMDD_HHMMSS.log` in the project directory.

---

## Installation — Windows

### Option A: WSL2 (Recommended)

WSL2 provides a full Linux environment including Redis.

```powershell
# Enable WSL2 (run as Administrator)
wsl --install -d Ubuntu
# Then follow the Linux installation steps inside WSL2
```

### Option B: Native PowerShell

> **Important:** Redis is not available via winget. Install it via Docker or WSL2 before enabling live scans.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1
```

**Install Redis (required for async scanning):**

```powershell
# Option 1: Docker (recommended)
docker run -d -p 6379:6379 --name vap-redis redis:7

# Option 2: WSL2
wsl sudo apt install redis && wsl redis-server --daemonize yes
```

---

## Configuration

Copy `.env.example` to `.env` and set the values below. All others have sensible defaults.

```env
# REQUIRED in production
VAP_CSRF_SECRET=        # run: openssl rand -hex 32
VAP_JWT_SECRET=         # run: openssl rand -hex 32
VAP_API_KEY=            # your strong API key

# RECOMMENDED
VAP_ENV=production
VAP_HOST=127.0.0.1      # bind only to localhost when behind a proxy
VAP_ENABLE_LIVE_SCANS=false   # set to true only when live scanning is needed
VAP_REQUIRE_HTTPS=true

# Redis (required for Celery)
VAP_CELERY_BROKER_URL=redis://localhost:6379/0
VAP_CELERY_RESULT_BACKEND=redis://localhost:6379/1
```

Generate secrets:
```bash
openssl rand -hex 32
# or: python3 -c "import secrets; print(secrets.token_hex(32))"
```

Full variable reference: `docs/configuration.md`

---

## Starting the Platform

### Development (simulated scans — no Redis needed)

```bash
source venv/bin/activate      # Linux/macOS
# .\venv\Scripts\Activate.ps1  # Windows

python3 app.py
# Dashboard: http://localhost:8000
```

### Production (live scans + async Celery workers)

```bash
# Terminal 1: Redis
redis-server

# Terminal 2: Celery worker
source venv/bin/activate
celery -A celery_app worker --loglevel=info -Q scans -c 4

# Terminal 3: FastAPI server
source venv/bin/activate
python3 app.py
```

---

## Usage

### Web UI

1. Open `http://localhost:8000`
2. Enter a target (URL or IP address)
3. Select a scan type
4. Start the scan
5. Review findings and download the PDF report

### REST API

```bash
# Create a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"target": "https://example.com", "scan_type": "full"}'

# Check status
curl http://localhost:8000/api/v1/scans/{scan_id}

# Download PDF report
curl -O http://localhost:8000/api/v1/scans/{scan_id}/report/download
```

Swagger UI: `http://localhost:8000/docs`

### CLI

```bash
python3 scanner_engine.py --target https://example.com --output results.json
```

---

## Security Hardening

| Setting | Development | Production |
|---|---|---|
| `VAP_ENV` | `development` | **`production`** |
| `VAP_HOST` | `0.0.0.0` | **`127.0.0.1`** |
| `VAP_REQUIRE_HTTPS` | `false` | **`true`** |
| `VAP_CSRF_SECRET` | (auto) | **Set explicitly** |
| `VAP_JWT_SECRET` | empty | **Set explicitly** |
| `VAP_API_KEY` | empty | **Set explicitly** |
| `VAP_ENABLE_LIVE_SCANS` | `false` | `true` only if needed |

**Production checklist:**
- [ ] Set `VAP_CSRF_SECRET`, `VAP_JWT_SECRET`, `VAP_API_KEY`
- [ ] Bind to `127.0.0.1` behind nginx/Caddy with TLS
- [ ] Enable `VAP_REQUIRE_HTTPS=true`
- [ ] Restrict CORS: `VAP_CORS_ALLOWED_ORIGINS=https://your-domain.com`
- [ ] Review `reports/` directory permissions (contains sensitive scan data)
- [ ] Keep dependencies updated: `pip install --upgrade -r requirements.txt`

Full security guide: `docs/security.md`

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'fastapi'`**
You ran `python3 app.py` without activating the virtual environment first.
```bash
source venv/bin/activate   # then: python3 app.py
```

**`ValueError: Duplicated timeseries in CollectorRegistry`**
Fixed in this version. If you still see it, ensure you are running `python3 app.py` from within an activated venv and not importing the module multiple times.

**`RequestsDependencyWarning: urllib3 ... doesn't match a supported version`**
Cosmetic warning from the `requests` library — does not affect functionality. Resolved by pinning `urllib3` or upgrading: `pip install --upgrade requests urllib3`.

**Scan stuck in `running` / Celery tasks not executing**
Redis is not running or not reachable.
```bash
redis-cli ping   # should return PONG
redis-server --daemonize yes
```

**Scanner shows `simulated` status**
The external tool (nmap, nuclei, etc.) is not installed or not in PATH.
```bash
which nuclei      # should print a path
nuclei -version
```
Set `VAP_ENABLE_LIVE_SCANS=true` in `.env` after installing the tools.

**macOS: WhatWeb make install fails**
Expected — Ruby gem `psych` build issue on macOS. The installer automatically installs a local wrapper that is fully functional. No action needed.

**Windows: execution policy error**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Python 3.13+ build failures**
Python 3.13+ is not yet supported. Install Python 3.12:
```bash
# macOS
brew install python@3.12
# Ubuntu/Debian
sudo apt install python3.12 python3.12-venv
```
Then recreate the venv: `python3.12 -m venv venv`

---

## Architecture

```
VAP/
├── app.py                  # FastAPI server + web dashboard
├── scanner_engine.py       # Scan orchestration engine
├── report_generator.py     # PDF report generator
├── enrichment_engine.py    # CVE / MITRE ATT&CK enrichment
├── false_positive_model.py # ML false positive detection
├── database.py             # SQLAlchemy ORM
├── config.py               # Centralised settings (172 options)
├── security.py             # JWT, API key, CSRF, audit logging
├── tasks.py                # Celery async tasks
├── celery_app.py           # Celery configuration
├── background_jobs.py      # Scheduled maintenance jobs
├── compliance.py           # GDPR / privacy utilities
├── installer.sh            # Linux/macOS installer
├── installer.ps1           # Windows installer
├── requirements.txt        # Python dependencies
├── .env.example            # Configuration template
├── scanners/               # Scanner modules (14 tools)
├── templates/              # HTML templates
├── static/                 # CSS / JS
├── reports/                # Generated PDF reports
├── docs/                   # Full documentation
└── tests/                  # Pytest test suite
```

---

## License

This project is provided for educational and research purposes.

**Author:** Chiara Berti

---
---

# VAP — Vulnerability Assessment Platform *(Italiano)*

> **Avvertenza:** Questo strumento è destinato **esclusivamente** a test di sicurezza autorizzati su sistemi di propria proprietà o per i quali si dispone di autorizzazione scritta esplicita. L'uso non autorizzato è illegale.

---

## Indice

- [Funzionalità](#funzionalità)
- [Avvio rapido](#avvio-rapido)
- [Prerequisiti](#prerequisiti)
- [Installazione — Linux / macOS](#installazione--linux--macos)
- [Installazione — Windows](#installazione--windows)
- [Configurazione](#configurazione)
- [Avvio della piattaforma](#avvio-della-piattaforma)
- [Utilizzo](#utilizzo)
- [Hardening di sicurezza](#hardening-di-sicurezza)
- [Risoluzione dei problemi](#risoluzione-dei-problemi)

---

## Funzionalità

- **Integrazione Multi-Scanner**: Nuclei, Nmap, WhatWeb, Subfinder, Nikto, Dirsearch, SQLMap, XSStrike, ZAP, Burp Suite, Wapiti, Commix
- **Scanner Enterprise (opzionali)**: Acunetix, Nessus via API
- **Motore di correlazione vulnerabilità**: deduplica e collega i finding multi-tool
- **Modello ML per falsi positivi**: regressione logistica per stimare i falsi positivi
- **Arricchimento CVE**: integrazione NVD + ExploitDB
- **Mappatura MITRE ATT&CK**: classificazione automatica tattica/tecnica
- **Scansioni parallele**: esecuzione concorrente con limite configurabile
- **Report PDF professionali**: executive summary, grafici, mapping OWASP Top 10
- **Web Dashboard**: UI moderna con Tailwind CSS
- **REST API**: API completa per automazione e integrazioni
- **Database SQLite**: archiviazione persistente di scansioni e finding

---

## Avvio rapido

### Linux / macOS

```bash
# 1. Esegui l'installer (NON come root)
chmod +x installer.sh
./installer.sh

# 2. Attiva il virtual environment
source venv/bin/activate

# 3. Copia e configura il file di ambiente
cp .env.example .env
# Modifica .env — imposta almeno: VAP_CSRF_SECRET, VAP_JWT_SECRET, VAP_API_KEY

# 4. Avvia il server
python3 app.py
```

Apri la dashboard su `http://localhost:8000`.

### Windows

```powershell
# 1. Esegui l'installer PowerShell (come Amministratore)
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1

# 2. Attiva il virtual environment
.\venv\Scripts\Activate.ps1

# 3. Copia e configura il file di ambiente
copy .env.example .env

# 4. Avvia il server
python app.py
```

---

## Prerequisiti

| Requisito | Versione | Note |
|---|---|---|
| Python | 3.10 – 3.12 | Python 3.13+ non ancora supportato |
| Go | ≥ 1.19 | Necessario per Nuclei e Subfinder |
| Redis | 6 o 7 | Necessario per le scansioni asincrone Celery |
| nmap | qualsiasi recente | Opzionale — usa modalità simulata se assente |
| nikto | qualsiasi recente | Opzionale |

**Sistemi operativi supportati:**
- **Linux**: Ubuntu 20.04+, Debian 11+, Kali, Linux Mint, Pop!\_OS, Fedora, RHEL/CentOS/Rocky/AlmaLinux 8+, Arch, Manjaro, openSUSE
- **macOS**: 11 (Big Sur) o versioni successive — Homebrew o MacPorts richiesto
- **Windows**: 10/11 — PowerShell 5+ richiesto; Redis da installare separatamente

---

## Installazione — Linux / macOS

```bash
chmod +x installer.sh
./installer.sh
```

L'installer:
1. Rileva il sistema operativo e installa i pacchetti di sistema
2. Installa i tool Go: Nuclei, Subfinder, Assetfinder
3. Clona e configura WhatWeb e Dirsearch
4. Crea un virtual environment Python (`venv/`)
5. Installa le dipendenze Python da `requirements.txt`
6. Inizializza il database SQLite

**Note per macOS:**
- Richiede macOS 11+ e Homebrew (`https://brew.sh`) o MacPorts
- L'installazione di WhatWeb via `make install` può fallire per problemi con le gem Ruby — l'installer installa automaticamente un wrapper locale pienamente funzionale

**In caso di errore**, un log degli errori viene salvato in `installer_errors_YYYYMMDD_HHMMSS.log` nella directory del progetto.

---

## Installazione — Windows

### Opzione A: WSL2 (Raccomandato)

WSL2 fornisce un ambiente Linux completo, incluso Redis.

```powershell
# Abilita WSL2 (come Amministratore)
wsl --install -d Ubuntu
# Poi segui i passi di installazione Linux all'interno di WSL2
```

### Opzione B: PowerShell Nativo

> **Importante:** Redis non è disponibile tramite winget. Installalo tramite Docker o WSL2 prima di abilitare le scansioni live.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1
```

**Installa Redis (necessario per le scansioni asincrone):**

```powershell
# Opzione 1: Docker (raccomandato)
docker run -d -p 6379:6379 --name vap-redis redis:7

# Opzione 2: WSL2
wsl sudo apt install redis && wsl redis-server --daemonize yes
```

---

## Configurazione

Copia `.env.example` in `.env` e imposta i valori seguenti. Gli altri hanno valori predefiniti ragionevoli.

```env
# OBBLIGATORI in produzione
VAP_CSRF_SECRET=        # esegui: openssl rand -hex 32
VAP_JWT_SECRET=         # esegui: openssl rand -hex 32
VAP_API_KEY=            # la tua API key sicura

# RACCOMANDATI
VAP_ENV=production
VAP_HOST=127.0.0.1      # lega solo al localhost quando dietro un proxy
VAP_ENABLE_LIVE_SCANS=false   # imposta true solo quando necessario
VAP_REQUIRE_HTTPS=true

# Redis (necessario per Celery)
VAP_CELERY_BROKER_URL=redis://localhost:6379/0
VAP_CELERY_RESULT_BACKEND=redis://localhost:6379/1
```

Genera i secret:
```bash
openssl rand -hex 32
# oppure: python3 -c "import secrets; print(secrets.token_hex(32))"
```

Riferimento completo delle variabili: `docs/configuration.md`

---

## Avvio della piattaforma

### Sviluppo (scansioni simulate — Redis non necessario)

```bash
source venv/bin/activate      # Linux/macOS
# .\venv\Scripts\Activate.ps1  # Windows

python3 app.py
# Dashboard: http://localhost:8000
```

### Produzione (scansioni live + worker Celery asincroni)

```bash
# Terminale 1: Redis
redis-server

# Terminale 2: Worker Celery
source venv/bin/activate
celery -A celery_app worker --loglevel=info -Q scans -c 4

# Terminale 3: Server FastAPI
source venv/bin/activate
python3 app.py
```

---

## Utilizzo

### Web UI

1. Apri `http://localhost:8000`
2. Inserisci un target (URL o indirizzo IP)
3. Seleziona il tipo di scansione
4. Avvia la scansione
5. Esamina i finding e scarica il report PDF

### REST API

```bash
# Crea una scansione
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: la-tua-api-key" \
  -d '{"target": "https://example.com", "scan_type": "full"}'

# Controlla lo stato
curl http://localhost:8000/api/v1/scans/{scan_id}

# Scarica il report PDF
curl -O http://localhost:8000/api/v1/scans/{scan_id}/report/download
```

Swagger UI: `http://localhost:8000/docs`

### CLI

```bash
python3 scanner_engine.py --target https://example.com --output results.json
```

---

## Hardening di sicurezza

| Impostazione | Sviluppo | Produzione |
|---|---|---|
| `VAP_ENV` | `development` | **`production`** |
| `VAP_HOST` | `0.0.0.0` | **`127.0.0.1`** |
| `VAP_REQUIRE_HTTPS` | `false` | **`true`** |
| `VAP_CSRF_SECRET` | (automatico) | **Impostare esplicitamente** |
| `VAP_JWT_SECRET` | vuoto | **Impostare esplicitamente** |
| `VAP_API_KEY` | vuoto | **Impostare esplicitamente** |
| `VAP_ENABLE_LIVE_SCANS` | `false` | `true` solo se necessario |

**Checklist produzione:**
- [ ] Impostare `VAP_CSRF_SECRET`, `VAP_JWT_SECRET`, `VAP_API_KEY`
- [ ] Legare a `127.0.0.1` dietro nginx/Caddy con TLS
- [ ] Abilitare `VAP_REQUIRE_HTTPS=true`
- [ ] Restringere CORS: `VAP_CORS_ALLOWED_ORIGINS=https://tuo-dominio.com`
- [ ] Verificare i permessi di `reports/` (contiene dati di scansione sensibili)
- [ ] Mantenere le dipendenze aggiornate: `pip install --upgrade -r requirements.txt`

Guida completa alla sicurezza: `docs/security.md`

---

## Risoluzione dei problemi

**`ModuleNotFoundError: No module named 'fastapi'`**
Hai eseguito `python3 app.py` senza attivare il virtual environment.
```bash
source venv/bin/activate   # poi: python3 app.py
```

**`ValueError: Duplicated timeseries in CollectorRegistry`**
Risolto in questa versione. Assicurati di eseguire `python3 app.py` dall'interno di un venv attivato.

**`RequestsDependencyWarning: urllib3 ... doesn't match a supported version`**
Warning cosmetico della libreria `requests` — non influisce sulla funzionalità. Risolto con: `pip install --upgrade requests urllib3`.

**Scansione bloccata in `running` / task Celery non eseguiti**
Redis non è in esecuzione o non è raggiungibile.
```bash
redis-cli ping   # deve rispondere PONG
redis-server --daemonize yes
```

**Lo scanner mostra lo stato `simulated`**
Il tool esterno (nmap, nuclei, ecc.) non è installato o non è nel PATH.
```bash
which nuclei
nuclei -version
```
Imposta `VAP_ENABLE_LIVE_SCANS=true` in `.env` dopo aver installato i tool.

**macOS: WhatWeb make install fallisce**
Atteso — problema di build della gem Ruby `psych` su macOS. L'installer installa automaticamente un wrapper locale pienamente funzionale. Nessuna azione necessaria.

**Windows: errore di execution policy**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Python 3.13+ — errori di build**
Python 3.13+ non è ancora supportato. Installa Python 3.12:
```bash
# macOS
brew install python@3.12
# Ubuntu/Debian
sudo apt install python3.12 python3.12-venv
```
Poi ricrea il venv: `python3.12 -m venv venv`

---

**Autrice:** Chiara Berti
