# Vulnerability Assessment Platform (VAP)

Professional, modular security scanning platform with advanced vulnerability assessment capabilities and PDF reporting.

---

> **Disclaimer:** This tool is intended **exclusively** for authorized security testing on systems you own or have explicit written permission to test. Unauthorized use is illegal and may violate local and international laws.

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation — Linux / macOS](#installation--linux--macos)
- [Installation — Windows](#installation--windows)
- [Configuration](#configuration)
- [Starting the platform](#starting-the-platform)
- [Usage](#usage)
- [Security hardening](#security-hardening)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [License](#license)

---

## Features

- **Multi-Scanner Integration**: Nuclei, Nmap, WhatWeb, Subfinder, Nikto, Dirsearch, SQLMap, XSStrike, ZAP, Burp, Wapiti, Commix
- **Enterprise Scanners (optional)**: Acunetix, Nessus via API
- **Vulnerability Correlation Engine**: deduplication and cross-tool finding correlation
- **False Positive ML Model**: logistic model to estimate false positives
- **CVE Enrichment**: NVD + ExploitDB integration
- **MITRE ATT&CK Mapping**: automatic technique/tactic mapping
- **Parallel Scans**: concurrent tool execution with configurable limits
- **Professional PDF Reports**: executive summary, charts, OWASP Top 10 mapping
- **Web Dashboard**: modern UI with Tailwind CSS
- **REST API**: full API for automation and integrations
- **SQLite Database**: persistent storage for scans and findings

---

## Prerequisites

| Requirement | Version   | Notes                                          |
|-------------|-----------|------------------------------------------------|
| Python      | 3.10–3.12 | Python 3.13+ not yet supported (pydantic-core) |
| Go          | >= 1.19   | Required for Nuclei and Subfinder              |
| Redis       | 6 or 7    | Required for Celery (async scans)              |
| nmap        | any       | Optional — falls back to simulated mode        |
| nikto       | any       | Optional                                       |

**Supported operating systems:**
- Linux: Ubuntu 20.04+, Debian 11+, Kali, Fedora, RHEL/CentOS/Rocky 8+, Arch, openSUSE
- macOS: 11 (Big Sur) or later — Homebrew or MacPorts required
- Windows: 10/11 — PowerShell 5+; Redis via Docker or WSL2

---

## Installation — Linux / macOS

```bash
# 1. Clone or extract the repository
git clone <repository-url> VAP
cd VAP

# 2. Run the installer (do NOT run as root)
chmod +x installer.sh
./installer.sh
```

The installer will:
- Detect your OS and install system packages (apt / dnf / pacman / zypper / Homebrew)
- Install Go tools: Nuclei, Subfinder, Assetfinder
- Clone and configure WhatWeb and Dirsearch
- Create a Python virtual environment (`venv/`)
- Install Python dependencies from `requirements.txt`
- Initialise the SQLite database
- Create two log files: a full install log and an **errors-only log** (`installer_errors_<timestamp>.log`)

After installation:
```bash
source venv/bin/activate
cp .env.example .env
# Edit .env with your settings (see Configuration section)
python3 app.py
```

The server will be available at `http://localhost:8000`.

**macOS requirements:**
- macOS 11 (Big Sur) minimum
- Homebrew (`brew`) is used by default; MacPorts (`port`) is the fallback
- Install Homebrew: https://brew.sh

---

## Installation — Windows

### Option A: WSL2 (Recommended)

WSL2 provides a full Linux environment and supports all features including Redis.

```powershell
# 1. Enable WSL2 (run PowerShell as Administrator)
wsl --install -d Ubuntu

# 2. Inside WSL2, follow the Linux installation steps above
```

### Option B: Native Windows (PowerShell)

> **Note:** Redis is not natively available on Windows. Use Docker or WSL2.

```powershell
# Open PowerShell as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1
```

The installer will install Python 3.12, Git, Go, Nmap (via winget), create a virtual environment, install Python dependencies, and initialise the database.

**Install Redis (required for async scanning):**
```powershell
# Option 1: Docker
docker run -d -p 6379:6379 --name vap-redis redis:7

# Option 2: WSL2
wsl sudo apt install redis-server
wsl redis-server &
```

After installation:
```powershell
.\venv\Scripts\Activate.ps1
copy .env.example .env
python app.py
```

---

## Configuration

Copy `.env.example` to `.env` and set these values. All others have sensible defaults.

```env
# --- REQUIRED in production ---
VAP_CSRF_SECRET=<run: openssl rand -hex 32>
VAP_JWT_SECRET=<run: openssl rand -hex 32>
VAP_API_KEY=<your-strong-api-key>

# --- RECOMMENDED ---
VAP_ENV=production
VAP_HOST=127.0.0.1
VAP_ENABLE_LIVE_SCANS=false
VAP_REQUIRE_HTTPS=true
VAP_CELERY_BROKER_URL=redis://localhost:6379/0
VAP_CELERY_RESULT_BACKEND=redis://localhost:6379/1
```

Generate secrets:
```bash
openssl rand -hex 32
# or:
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## Starting the platform

### Development (simulated scans, no Redis required)

```bash
source venv/bin/activate
python3 app.py
# Dashboard: http://localhost:8000
```

### Production (live scans + async Celery workers)

```bash
# Terminal 1: start Redis
redis-server

# Terminal 2: start Celery worker
source venv/bin/activate
celery -A celery_app worker --loglevel=info

# Terminal 3: start the FastAPI server
source venv/bin/activate
python3 app.py
```

---

## Usage

### Web UI

1. Open `http://localhost:8000`
2. Enter a target (URL or IP)
3. Select a scan type and start the scan
4. Review findings and generate the PDF report

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

Verbose mode:
```bash
python3 app.py --debug
```

---

## Security hardening

| Setting                 | Development   | Production                 |
|-------------------------|---------------|----------------------------|
| `VAP_ENV`               | `development` | `production`               |
| `VAP_HOST`              | `0.0.0.0`     | `127.0.0.1` (behind proxy) |
| `VAP_REQUIRE_HTTPS`     | `false`       | `true`                     |
| `VAP_CSRF_SECRET`       | (auto)        | **Set explicitly**         |
| `VAP_JWT_SECRET`        | empty         | **Set explicitly**         |
| `VAP_API_KEY`           | empty         | **Set explicitly**         |
| `VAP_ENABLE_LIVE_SCANS` | `false`       | `true` (only if needed)    |

**Checklist:**
- [ ] Set `VAP_CSRF_SECRET`, `VAP_JWT_SECRET`, `VAP_API_KEY`
- [ ] Set `VAP_ENV=production`
- [ ] Bind to `127.0.0.1` and use nginx/Caddy as a TLS-terminating reverse proxy
- [ ] Enable `VAP_REQUIRE_HTTPS=true`
- [ ] Restrict CORS: `VAP_CORS_ALLOWED_ORIGINS=https://your-domain.com`
- [ ] Rotate secrets periodically
- [ ] Keep dependencies updated: `pip install --upgrade -r requirements.txt`
- [ ] Review permissions on `reports/` (contains sensitive scan data)

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'fastapi'`**
You ran `python3 app.py` without activating the virtual environment.
```bash
source venv/bin/activate
python3 app.py
```

**`ValueError: Duplicated timeseries in CollectorRegistry`**
Prometheus metrics registered twice (e.g., on uvicorn hot-reload). Fixed in the current version. If it persists, delete `__pycache__` and restart.

**`RequestsDependencyWarning: urllib3 ... doesn't match a supported version`**
Update dependencies: `pip install --upgrade -r requirements.txt`

**`csrf_secret` changes on every restart / session errors**
Set `VAP_CSRF_SECRET` in `.env`: `VAP_CSRF_SECRET=$(openssl rand -hex 32)`

**Celery tasks not running / scan stuck in `running` state**
Redis is not running. Check: `redis-cli ping` (should return `PONG`)

**Scanner shows `simulated` status**
The external tool is not installed or not in `PATH`. Verify: `which nuclei`

**`pydantic-core` build failure on Python 3.13+**
Python 3.13 is not supported. Install Python 3.12: `python3.12 -m venv venv`

**Windows: execution policy error on `Activate.ps1`**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**macOS: `brew install` fails on macOS 10.x**
Minimum is macOS 11 (Big Sur). Upgrade macOS or use Docker: `docker-compose up`

**WhatWeb installation fails (psych gem build error)**
Known issue with Ruby's psych gem on some macOS versions.
Try this before re-running the installer:
```bash
brew install libyaml
export CPPFLAGS="-I$(brew --prefix libyaml)/include"
export LDFLAGS="-L$(brew --prefix libyaml)/lib"
export PKG_CONFIG_PATH="$(brew --prefix libyaml)/lib/pkgconfig"
gem install psych -v '5.3.1' --source 'https://rubygems.org/'
```
The installer now attempts this psych preflight automatically on macOS; if it still fails, it falls back to a local WhatWeb wrapper.

---

## Architecture

```
VAP/
├── app.py                  # FastAPI server
├── scanner_engine.py       # Scan orchestration engine
├── report_generator.py     # PDF report generator
├── database.py             # ORM models
├── config.py               # Configuration
├── installer.sh            # Linux/macOS installer
├── installer.ps1           # Windows installer
├── requirements.txt        # Python dependencies
├── scanners/               # Scanner modules
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
├── templates/              # HTML templates
├── static/                 # CSS / JS assets
├── reports/                # Generated PDF reports
└── logs/                   # Application logs
```

---

## License

This project is provided for educational and research purposes.

**Author:** Chiara Berti

---

---

# Vulnerability Assessment Platform (VAP) — Guida in italiano

Piattaforma professionale e modulare per la valutazione delle vulnerabilità, con capacità avanzate di scansione e reportistica PDF.

---

> **Avvertenza:** Questo strumento è destinato **esclusivamente** a test di sicurezza autorizzati su sistemi di propria proprietà o per i quali si dispone di autorizzazione scritta esplicita. L'uso non autorizzato è illegale e può violare leggi locali e internazionali.

---

## Indice

- [Funzionalita](#funzionalita)
- [Prerequisiti](#prerequisiti)
- [Installazione — Linux / macOS](#installazione--linux--macos)
- [Installazione — Windows](#installazione--windows)
- [Configurazione](#configurazione)
- [Avvio della piattaforma](#avvio-della-piattaforma)
- [Utilizzo](#utilizzo)
- [Hardening di sicurezza](#hardening-di-sicurezza)
- [Risoluzione dei problemi](#risoluzione-dei-problemi)
- [Architettura](#architettura)

---

## Funzionalita

- **Integrazione multi-scanner**: Nuclei, Nmap, WhatWeb, Subfinder, Nikto, Dirsearch, SQLMap, XSStrike, ZAP, Burp, Wapiti, Commix
- **Scanner Enterprise (opzionali)**: Acunetix, Nessus via API
- **Motore di correlazione vulnerabilita**: deduplica e collega i findings multi-tool
- **Modello ML per falsi positivi**: modello logistico per stimare i falsi positivi
- **CVE Enrichment**: integrazione NVD + ExploitDB
- **Mappatura MITRE ATT&CK**: mappatura automatica tecnica/tattica
- **Scansioni parallele**: esecuzione concorrente con limite configurabile
- **Report PDF professionali**: executive summary, grafici, mappatura OWASP Top 10
- **Web Dashboard**: UI moderna con Tailwind CSS
- **REST API**: API completa per automazione e integrazioni
- **Database SQLite**: archiviazione persistente per scansioni e findings

---

## Prerequisiti

| Requisito | Versione  | Note                                                    |
|-----------|-----------|---------------------------------------------------------|
| Python    | 3.10–3.12 | Python 3.13+ non ancora supportato (pydantic-core)      |
| Go        | >= 1.19   | Necessario per Nuclei e Subfinder                       |
| Redis     | 6 o 7     | Necessario per Celery (scansioni asincrone)             |
| nmap      | qualsiasi | Opzionale — usa la modalita simulata se mancante        |
| nikto     | qualsiasi | Opzionale                                               |

**Sistemi operativi supportati:**
- Linux: Ubuntu 20.04+, Debian 11+, Kali, Fedora, RHEL/CentOS/Rocky 8+, Arch, openSUSE
- macOS: 11 (Big Sur) o versioni successive — richiede Homebrew o MacPorts
- Windows: 10/11 — PowerShell 5+; Redis tramite Docker o WSL2

---

## Installazione — Linux / macOS

```bash
# 1. Clona o estrai il repository
git clone <url-repository> VAP
cd VAP

# 2. Esegui l'installer (NON eseguire come root)
chmod +x installer.sh
./installer.sh
```

L'installer:
- Rileva il sistema operativo e installa i pacchetti di sistema (apt / dnf / pacman / zypper / Homebrew)
- Installa i tool Go: Nuclei, Subfinder, Assetfinder
- Clona e configura WhatWeb e Dirsearch
- Crea un virtual environment Python (`venv/`)
- Installa le dipendenze Python da `requirements.txt`
- Inizializza il database SQLite
- Crea due file di log: un log completo e un **log solo errori** (`installer_errors_<timestamp>.log`)

Dopo l'installazione:
```bash
source venv/bin/activate
cp .env.example .env
# Modifica .env con le tue impostazioni (vedi sezione Configurazione)
python3 app.py
```

Il server sara disponibile su `http://localhost:8000`.

**Requisiti macOS:**
- macOS 11 (Big Sur) come minimo
- Homebrew (`brew`) viene usato di default; MacPorts (`port`) e il fallback
- Installa Homebrew: https://brew.sh

---

## Installazione — Windows

### Opzione A: WSL2 (Raccomandato)

WSL2 fornisce un ambiente Linux completo e supporta tutte le funzionalita, incluso Redis.

```powershell
# 1. Abilita WSL2 (esegui PowerShell come Amministratore)
wsl --install -d Ubuntu

# 2. All'interno di WSL2, segui le istruzioni di installazione Linux sopra
```

### Opzione B: Windows Nativo (PowerShell)

> **Nota:** Redis non e disponibile nativamente su Windows. Usa Docker o WSL2.

```powershell
# Apri PowerShell come Amministratore
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1
```

L'installer installa Python 3.12, Git, Go, Nmap (tramite winget), crea un virtual environment, installa le dipendenze Python e inizializza il database.

**Installa Redis (necessario per scansioni asincrone):**
```powershell
# Opzione 1: Docker
docker run -d -p 6379:6379 --name vap-redis redis:7

# Opzione 2: WSL2
wsl sudo apt install redis-server
wsl redis-server &
```

Dopo l'installazione:
```powershell
.\venv\Scripts\Activate.ps1
copy .env.example .env
python app.py
```

---

## Configurazione

Copia `.env.example` in `.env` e imposta questi valori. Gli altri hanno valori predefiniti ragionevoli.

```env
# --- OBBLIGATORI in produzione ---
VAP_CSRF_SECRET=<esegui: openssl rand -hex 32>
VAP_JWT_SECRET=<esegui: openssl rand -hex 32>
VAP_API_KEY=<la-tua-api-key-sicura>

# --- RACCOMANDATI ---
VAP_ENV=production
VAP_HOST=127.0.0.1
VAP_ENABLE_LIVE_SCANS=false
VAP_REQUIRE_HTTPS=true
VAP_CELERY_BROKER_URL=redis://localhost:6379/0
VAP_CELERY_RESULT_BACKEND=redis://localhost:6379/1
```

Genera i secret:
```bash
openssl rand -hex 32
# oppure:
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## Avvio della piattaforma

### Sviluppo (scansioni simulate, Redis non necessario)

```bash
source venv/bin/activate
python3 app.py
# Dashboard: http://localhost:8000
```

### Produzione (scansioni live + worker Celery asincroni)

```bash
# Terminale 1: avvia Redis
redis-server

# Terminale 2: avvia il worker Celery
source venv/bin/activate
celery -A celery_app worker --loglevel=info

# Terminale 3: avvia il server FastAPI
source venv/bin/activate
python3 app.py
```

---

## Utilizzo

### Web UI

1. Apri `http://localhost:8000`
2. Inserisci un target (URL o IP)
3. Seleziona il tipo di scansione e avviala
4. Esamina i findings e genera il report PDF

### API

```bash
# Crea una nuova scansione
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_type": "full"}'

# Controlla lo stato
curl http://localhost:8000/api/v1/scans/{scan_id}/status

# Scarica il report
curl -O http://localhost:8000/api/v1/scans/{scan_id}/report/download
```

### CLI

```bash
python3 scanner_engine.py --target https://example.com --output results.json
```

Modalita verbose:
```bash
python3 app.py --debug
```

---

## Hardening di sicurezza

| Impostazione            | Sviluppo      | Produzione                    |
|-------------------------|---------------|-------------------------------|
| `VAP_ENV`               | `development` | `production`                  |
| `VAP_HOST`              | `0.0.0.0`     | `127.0.0.1` (dietro proxy)    |
| `VAP_REQUIRE_HTTPS`     | `false`       | `true`                        |
| `VAP_CSRF_SECRET`       | (automatico)  | **Impostare esplicitamente**  |
| `VAP_JWT_SECRET`        | vuoto         | **Impostare esplicitamente**  |
| `VAP_API_KEY`           | vuoto         | **Impostare esplicitamente**  |
| `VAP_ENABLE_LIVE_SCANS` | `false`       | `true` (solo se necessario)   |

**Checklist:**
- [ ] Imposta `VAP_CSRF_SECRET`, `VAP_JWT_SECRET`, `VAP_API_KEY`
- [ ] Imposta `VAP_ENV=production`
- [ ] Lega a `127.0.0.1` e usa nginx/Caddy come reverse proxy con TLS
- [ ] Abilita `VAP_REQUIRE_HTTPS=true`
- [ ] Limita CORS: `VAP_CORS_ALLOWED_ORIGINS=https://tuo-dominio.com`
- [ ] Ruota periodicamente i secret
- [ ] Mantieni le dipendenze aggiornate: `pip install --upgrade -r requirements.txt`
- [ ] Verifica i permessi della directory `reports/` (contiene dati di scansione sensibili)

---

## Risoluzione dei problemi

**`ModuleNotFoundError: No module named 'fastapi'`**
Hai eseguito `python3 app.py` senza attivare il virtual environment.
```bash
source venv/bin/activate
python3 app.py
```

**`ValueError: Duplicated timeseries in CollectorRegistry`**
Le metriche Prometheus sono state registrate due volte (es. hot-reload di uvicorn). Il problema e corretto nella versione attuale. Se persiste, elimina `__pycache__` e riavvia.

**`RequestsDependencyWarning: urllib3 ... doesn't match a supported version`**
Aggiorna le dipendenze: `pip install --upgrade -r requirements.txt`

**`csrf_secret` cambia a ogni riavvio / errori di sessione**
Imposta `VAP_CSRF_SECRET` nel file `.env`: `VAP_CSRF_SECRET=$(openssl rand -hex 32)`

**I task Celery non vengono eseguiti / la scansione rimane in stato `running`**
Redis non e in esecuzione. Verifica: `redis-cli ping` (deve rispondere `PONG`)

**Lo scanner mostra stato `simulated`**
Il tool esterno non e installato o non e nel `PATH`. Verifica: `which nuclei`

**Errore di build di `pydantic-core` su Python 3.13+**
Python 3.13 non e supportato. Installa Python 3.12: `python3.12 -m venv venv`

**Windows: errore di execution policy con `Activate.ps1`**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**macOS: `brew install` fallisce su macOS 10.x**
Il minimo supportato e macOS 11 (Big Sur). Aggiorna macOS oppure usa Docker: `docker-compose up`

**L'installazione di WhatWeb fallisce (errore di build gem psych)**
Problema noto con il gem Ruby psych su alcune versioni di macOS.
Prima di rilanciare l'installer, prova:
```bash
brew install libyaml
export CPPFLAGS="-I$(brew --prefix libyaml)/include"
export LDFLAGS="-L$(brew --prefix libyaml)/lib"
export PKG_CONFIG_PATH="$(brew --prefix libyaml)/lib/pkgconfig"
gem install psych -v '5.3.1' --source 'https://rubygems.org/'
```
L'installer ora prova automaticamente questo preflight su macOS; se fallisce ancora, passa al wrapper locale di WhatWeb.

---

## Architettura

```
VAP/
├── app.py                  # Server FastAPI
├── scanner_engine.py       # Motore di orchestrazione scansioni
├── report_generator.py     # Generatore report PDF
├── database.py             # Modelli ORM
├── config.py               # Configurazione
├── installer.sh            # Installer Linux/macOS
├── installer.ps1           # Installer Windows
├── requirements.txt        # Dipendenze Python
├── scanners/               # Moduli scanner
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
├── templates/              # Template HTML
├── static/                 # Asset CSS / JS
├── reports/                # Report PDF generati
└── logs/                   # Log applicazione
```
