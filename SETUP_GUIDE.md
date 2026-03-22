# VAP — Vulnerability Assessment Platform
## Setup & Security Guide  |  Guida all'installazione e alla sicurezza

---

> **Disclaimer / Avvertenza**
> This tool is intended **exclusively** for authorized security testing on systems you own or have explicit written permission to test.
> Unauthorized use is illegal and may violate local and international laws.
>
> Questo strumento è destinato **esclusivamente** a test di sicurezza autorizzati su sistemi di propria proprietà o per i quali si dispone di autorizzazione scritta esplicita.
> L'uso non autorizzato è illegale e può violare leggi locali e internazionali.

---

## Table of Contents / Indice

1. [Prerequisites / Prerequisiti](#1-prerequisites--prerequisiti)
2. [Installation — Linux / macOS](#2-installation--linux--macos)
3. [Installation — Windows](#3-installation--windows)
4. [Configuration / Configurazione](#4-configuration--configurazione)
5. [Starting the platform / Avvio della piattaforma](#5-starting-the-platform--avvio-della-piattaforma)
6. [Security hardening / Hardening di sicurezza](#6-security-hardening--hardening-di-sicurezza)
7. [Troubleshooting / Risoluzione dei problemi](#7-troubleshooting--risoluzione-dei-problemi)
8. [Known security notes / Note di sicurezza note](#8-known-security-notes--note-di-sicurezza-note)

---

## 1. Prerequisites / Prerequisiti

### English

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10 – 3.12 | Python 3.13+ not yet supported (pydantic-core build issues) |
| Go | ≥ 1.19 | Required for Nuclei and Subfinder |
| Redis | 6 or 7 | Required for Celery (async scans) |
| nmap | any recent | Optional — scanner falls back to simulated mode |
| nikto | any recent | Optional |

**Supported operating systems:**
- Linux: Ubuntu 20.04+, Debian 11+, Kali, Fedora, RHEL/CentOS/Rocky 8+, Arch, openSUSE
- macOS: 11 (Big Sur) or later — Homebrew or MacPorts required
- Windows: 10/11 — PowerShell 5+ required; Redis must be installed separately (WSL2 recommended)

### Italiano

| Requisito | Versione | Note |
|---|---|---|
| Python | 3.10 – 3.12 | Python 3.13+ non ancora supportato (problemi di build con pydantic-core) |
| Go | ≥ 1.19 | Necessario per Nuclei e Subfinder |
| Redis | 6 o 7 | Necessario per Celery (scansioni asincrone) |
| nmap | qualsiasi recente | Opzionale — lo scanner usa la modalità simulata se mancante |
| nikto | qualsiasi recente | Opzionale |

**Sistemi operativi supportati:**
- Linux: Ubuntu 20.04+, Debian 11+, Kali, Fedora, RHEL/CentOS/Rocky 8+, Arch, openSUSE
- macOS: 11 (Big Sur) o versioni successive — Homebrew o MacPorts richiesto
- Windows: 10/11 — PowerShell 5+ richiesto; Redis da installare separatamente (WSL2 raccomandato)

---

## 2. Installation — Linux / macOS

### English

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
- Create a Python virtual environment
- Install Python dependencies from `requirements.txt`
- Initialise the SQLite database

**Supported Linux distributions:** Ubuntu, Debian, Kali, Linux Mint, Pop!_OS, Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux, Arch, Manjaro, EndeavourOS, openSUSE.

**macOS requirements:**
- macOS 11 (Big Sur) minimum
- Homebrew (`brew`) is used by default; MacPorts (`port`) is the fallback
- Install Homebrew: `https://brew.sh`

After installation:
```bash
source venv/bin/activate
cp .env.example .env
# Edit .env with your settings (see Section 4)
python3 app.py
```

### Italiano

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
- Crea un virtual environment Python
- Installa le dipendenze Python da `requirements.txt`
- Inizializza il database SQLite

**Distribuzioni Linux supportate:** Ubuntu, Debian, Kali, Linux Mint, Pop!_OS, Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux, Arch, Manjaro, EndeavourOS, openSUSE.

**Requisiti macOS:**
- macOS 11 (Big Sur) come minimo
- Homebrew (`brew`) viene usato di default; MacPorts (`port`) è il fallback
- Installa Homebrew: `https://brew.sh`

Dopo l'installazione:
```bash
source venv/bin/activate
cp .env.example .env
# Modifica .env con le tue impostazioni (vedi Sezione 4)
python3 app.py
```

---

## 3. Installation — Windows

### English

#### Option A: WSL2 (Recommended)

WSL2 provides a full Linux environment and is the easiest way to run VAP on Windows with all features, including Redis.

```powershell
# 1. Enable WSL2 (run in PowerShell as Administrator)
wsl --install -d Ubuntu

# 2. Inside WSL2, follow the Linux installation steps (Section 2)
```

#### Option B: Native Windows (PowerShell)

> **Important:** Redis is not natively available on Windows. You must install it via Docker or use WSL2.

```powershell
# 1. Open PowerShell as Administrator
# 2. Run the PowerShell installer
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1
```

The installer will:
- Install Python 3.12, Git, and Go via winget
- Install Nmap via winget
- Create a Python virtual environment
- Install Python dependencies
- Initialise the database
- Verify the installation

**Install Redis (required for async scanning):**

```powershell
# Option 1: Docker (recommended)
docker run -d -p 6379:6379 --name vap-redis redis:7

# Option 2: WSL2
wsl sudo apt install redis
wsl redis-server &
```

After installation:
```powershell
.\venv\Scripts\Activate.ps1
copy .env.example .env
# Edit .env with your settings (see Section 4)
python app.py
```

### Italiano

#### Opzione A: WSL2 (Raccomandato)

WSL2 fornisce un ambiente Linux completo ed è il modo più semplice per eseguire VAP su Windows con tutte le funzionalità, incluso Redis.

```powershell
# 1. Abilita WSL2 (esegui in PowerShell come Amministratore)
wsl --install -d Ubuntu

# 2. All'interno di WSL2, segui le istruzioni di installazione Linux (Sezione 2)
```

#### Opzione B: Windows Nativo (PowerShell)

> **Importante:** Redis non è disponibile nativamente su Windows. Devi installarlo tramite Docker o usare WSL2.

```powershell
# 1. Apri PowerShell come Amministratore
# 2. Esegui l'installer PowerShell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1
```

L'installer:
- Installa Python 3.12, Git e Go tramite winget
- Installa Nmap tramite winget
- Crea un virtual environment Python
- Installa le dipendenze Python
- Inizializza il database
- Verifica l'installazione

**Installa Redis (necessario per scansioni asincrone):**

```powershell
# Opzione 1: Docker (raccomandato)
docker run -d -p 6379:6379 --name vap-redis redis:7

# Opzione 2: WSL2
wsl sudo apt install redis
wsl redis-server &
```

Dopo l'installazione:
```powershell
.\venv\Scripts\Activate.ps1
copy .env.example .env
# Modifica .env con le tue impostazioni (vedi Sezione 4)
python app.py
```

---

## 4. Configuration / Configurazione

### English

Copy `.env.example` to `.env` and set the following values. All others have sensible defaults.

```env
# --- REQUIRED in production ---

# A stable random secret for CSRF tokens (regenerated on restart if empty!)
VAP_CSRF_SECRET=<run: openssl rand -hex 32>

# JWT signing secret (required if VAP_JWT_REQUIRED=true)
VAP_JWT_SECRET=<run: openssl rand -hex 32>

# API key for protecting endpoints (plain or pre-hashed with bcrypt)
VAP_API_KEY=<your-strong-api-key>

# --- RECOMMENDED ---

# Set to 'production' to activate security warnings on startup
VAP_ENV=production

# Bind only to localhost if not using a reverse proxy
VAP_HOST=127.0.0.1

# Enable live scans (false = simulated mode, safe for development)
VAP_ENABLE_LIVE_SCANS=false

# Force HTTPS (set to true when running behind a TLS-terminating proxy)
VAP_REQUIRE_HTTPS=true

# Redis URL for Celery
VAP_CELERY_BROKER_URL=redis://localhost:6379/0
VAP_CELERY_RESULT_BACKEND=redis://localhost:6379/1
```

Generate secrets with:
```bash
openssl rand -hex 32
# or in Python:
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Italiano

Copia `.env.example` in `.env` e imposta i seguenti valori. Gli altri hanno valori predefiniti ragionevoli.

```env
# --- OBBLIGATORI in produzione ---

# Secret stabile per i token CSRF (viene rigenerato a ogni riavvio se vuoto!)
VAP_CSRF_SECRET=<esegui: openssl rand -hex 32>

# Secret per la firma JWT (richiesto se VAP_JWT_REQUIRED=true)
VAP_JWT_SECRET=<esegui: openssl rand -hex 32>

# API key per proteggere gli endpoint (in chiaro o pre-hashata con bcrypt)
VAP_API_KEY=<la-tua-api-key-sicura>

# --- RACCOMANDATI ---

# Imposta 'production' per attivare i warning di sicurezza all'avvio
VAP_ENV=production

# Lega solo al localhost se non si usa un reverse proxy
VAP_HOST=127.0.0.1

# Abilita scansioni live (false = modalità simulata, sicura per sviluppo)
VAP_ENABLE_LIVE_SCANS=false

# Forza HTTPS (impostare a true quando si usa un proxy TLS)
VAP_REQUIRE_HTTPS=true

# URL Redis per Celery
VAP_CELERY_BROKER_URL=redis://localhost:6379/0
VAP_CELERY_RESULT_BACKEND=redis://localhost:6379/1
```

Genera i secret con:
```bash
openssl rand -hex 32
# oppure in Python:
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## 5. Starting the platform / Avvio della piattaforma

### English

#### Development (simulated scans, no Redis required)

```bash
source venv/bin/activate   # macOS/Linux
# .\venv\Scripts\Activate.ps1  # Windows

python3 app.py
# Dashboard: http://localhost:8000
```

#### Production (live scans + async Celery workers)

```bash
# Terminal 1: start Redis (if not already running)
redis-server

# Terminal 2: start Celery worker
source venv/bin/activate
celery -A celery_app worker --loglevel=info

# Terminal 3: start the FastAPI server
source venv/bin/activate
python3 app.py
```

### Italiano

#### Sviluppo (scansioni simulate, Redis non necessario)

```bash
source venv/bin/activate   # macOS/Linux
# .\venv\Scripts\Activate.ps1  # Windows

python3 app.py
# Dashboard: http://localhost:8000
```

#### Produzione (scansioni live + worker Celery asincroni)

```bash
# Terminale 1: avvia Redis (se non già in esecuzione)
redis-server

# Terminale 2: avvia il worker Celery
source venv/bin/activate
celery -A celery_app worker --loglevel=info

# Terminale 3: avvia il server FastAPI
source venv/bin/activate
python3 app.py
```

---

## 6. Security hardening / Hardening di sicurezza

### English

| Setting | Development | Production |
|---|---|---|
| `VAP_ENV` | `development` | `production` |
| `VAP_HOST` | `0.0.0.0` | `127.0.0.1` (behind proxy) |
| `VAP_REQUIRE_HTTPS` | `false` | `true` |
| `VAP_CSRF_SECRET` | (auto) | **Set explicitly** |
| `VAP_JWT_SECRET` | empty | **Set explicitly** |
| `VAP_API_KEY` | empty | **Set explicitly** |
| `VAP_ENABLE_LIVE_SCANS` | `false` | `true` (only if needed) |

**Checklist:**
- [ ] Set all three secrets: `VAP_CSRF_SECRET`, `VAP_JWT_SECRET`, `VAP_API_KEY`
- [ ] Set `VAP_ENV=production`
- [ ] Bind to `127.0.0.1` and use nginx/Caddy as a reverse proxy with TLS
- [ ] Enable `VAP_REQUIRE_HTTPS=true`
- [ ] Restrict CORS: `VAP_CORS_ALLOWED_ORIGINS=https://your-domain.com`
- [ ] Set `VAP_ENABLE_LIVE_SCANS=true` only when needed
- [ ] Rotate secrets periodically
- [ ] Keep Python dependencies updated: `pip install --upgrade -r requirements.txt`
- [ ] Review `reports/` directory permissions (contains sensitive scan data)

### Italiano

| Impostazione | Sviluppo | Produzione |
|---|---|---|
| `VAP_ENV` | `development` | `production` |
| `VAP_HOST` | `0.0.0.0` | `127.0.0.1` (dietro proxy) |
| `VAP_REQUIRE_HTTPS` | `false` | `true` |
| `VAP_CSRF_SECRET` | (automatico) | **Impostare esplicitamente** |
| `VAP_JWT_SECRET` | vuoto | **Impostare esplicitamente** |
| `VAP_API_KEY` | vuoto | **Impostare esplicitamente** |
| `VAP_ENABLE_LIVE_SCANS` | `false` | `true` (solo se necessario) |

**Checklist:**
- [ ] Impostare tutti e tre i secret: `VAP_CSRF_SECRET`, `VAP_JWT_SECRET`, `VAP_API_KEY`
- [ ] Impostare `VAP_ENV=production`
- [ ] Legare a `127.0.0.1` e usare nginx/Caddy come reverse proxy con TLS
- [ ] Abilitare `VAP_REQUIRE_HTTPS=true`
- [ ] Restringere CORS: `VAP_CORS_ALLOWED_ORIGINS=https://tuo-dominio.com`
- [ ] Impostare `VAP_ENABLE_LIVE_SCANS=true` solo quando necessario
- [ ] Ruotare periodicamente i secret
- [ ] Mantenere le dipendenze Python aggiornate: `pip install --upgrade -r requirements.txt`
- [ ] Verificare i permessi della directory `reports/` (contiene dati di scansione sensibili)

---

## 7. Troubleshooting / Risoluzione dei problemi

### English

#### `csrf_secret` changes on every restart / session errors
**Cause:** `VAP_CSRF_SECRET` is not set in `.env`.
**Fix:** Generate a secret and set it: `VAP_CSRF_SECRET=$(openssl rand -hex 32)` in `.env`.

#### "Celery tasks not running" / "Scan stuck in running state"
**Cause:** Redis is not running or not reachable.
**Fix:**
```bash
# Check Redis
redis-cli ping   # should return PONG
# Start Redis if needed
redis-server --daemonize yes
```

#### "Scanner not found" / scan shows `simulated` status
**Cause:** The external tool (nmap, nuclei, etc.) is not installed or not in `PATH`.
**Fix:** Install the tool or enable it for your OS (see Section 2), then verify: `which nuclei`.

#### `pydantic-core` build failure on Python 3.13+
**Cause:** Python 3.13 is not yet supported.
**Fix:** Install Python 3.12 and recreate the virtual environment: `python3.12 -m venv venv`.

#### Windows: `venv\Scripts\Activate.ps1` execution policy error
**Fix:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### macOS: `brew install` fails on macOS 10.x
**Cause:** macOS 10.x is not supported. Minimum is macOS 11 (Big Sur).
**Fix:** Upgrade macOS or use Docker: `docker-compose up`.

### Italiano

#### `csrf_secret` cambia a ogni riavvio / errori di sessione
**Causa:** `VAP_CSRF_SECRET` non è impostato nel file `.env`.
**Fix:** Genera un secret e impostalo: `VAP_CSRF_SECRET=$(openssl rand -hex 32)` in `.env`.

#### "I task Celery non vengono eseguiti" / "La scansione rimane in stato running"
**Causa:** Redis non è in esecuzione o non raggiungibile.
**Fix:**
```bash
# Verifica Redis
redis-cli ping   # deve rispondere PONG
# Avvia Redis se necessario
redis-server --daemonize yes
```

#### "Scanner not found" / la scansione mostra stato `simulated`
**Causa:** Il tool esterno (nmap, nuclei, ecc.) non è installato o non è nel `PATH`.
**Fix:** Installa il tool o abilitalo per il tuo OS (vedi Sezione 2), poi verifica: `which nuclei`.

#### Errore di build di `pydantic-core` su Python 3.13+
**Causa:** Python 3.13 non è ancora supportato.
**Fix:** Installa Python 3.12 e ricrea il virtual environment: `python3.12 -m venv venv`.

#### Windows: errore di execution policy con `venv\Scripts\Activate.ps1`
**Fix:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### macOS: `brew install` fallisce su macOS 10.x
**Causa:** macOS 10.x non è supportato. Il minimo è macOS 11 (Big Sur).
**Fix:** Aggiorna macOS oppure usa Docker: `docker-compose up`.

---

## 8. Known security notes / Note di sicurezza note

### English

The following known issues are documented. They do not represent immediate risks in development/simulated mode but should be addressed before production deployment.

| Issue | Severity | Status | Recommended action |
|---|---|---|---|
| `python-jose` 3.3.0 — CVE-2022-29217 (algorithm confusion) | Medium | Known | Migrate to `PyJWT>=2.8` or `joserfc` in a future update |
| `bleach` 6.1.0 — library unmaintained | Low | Known | Replace with `nh3` when bleach is removed from pip ecosystem |
| `passlib` — maintenance-only mode | Low | Known | Migrate to `pwdlib` or `argon2-cffi` directly |
| CSRF secret auto-generated on restart if unset | High (production) | Fixed in config | **Set `VAP_CSRF_SECRET` in `.env`** |
| API accessible without auth if `VAP_API_KEY` unset | High (production) | By design (dev) | **Set `VAP_API_KEY` in production** |
| Default host `0.0.0.0` binds to all interfaces | Medium | By design (dev) | **Set `VAP_HOST=127.0.0.1` in production** |
| PDF content injection via finding data | Fixed | Resolved (html.escape) | No action needed |

### Italiano

I seguenti problemi noti sono documentati. Non rappresentano rischi immediati in modalità sviluppo/simulata, ma devono essere affrontati prima del deployment in produzione.

| Problema | Severità | Stato | Azione raccomandata |
|---|---|---|---|
| `python-jose` 3.3.0 — CVE-2022-29217 (algorithm confusion) | Media | Noto | Migrare a `PyJWT>=2.8` o `joserfc` in un aggiornamento futuro |
| `bleach` 6.1.0 — libreria non più mantenuta | Bassa | Noto | Sostituire con `nh3` quando bleach verrà rimosso dall'ecosistema pip |
| `passlib` — solo manutenzione | Bassa | Noto | Migrare a `pwdlib` o direttamente ad `argon2-cffi` |
| CSRF secret auto-generato al riavvio se non impostato | Alta (produzione) | Corretto in config | **Impostare `VAP_CSRF_SECRET` nel file `.env`** |
| API accessibile senza autenticazione se `VAP_API_KEY` non impostato | Alta (produzione) | Design (sviluppo) | **Impostare `VAP_API_KEY` in produzione** |
| Host di default `0.0.0.0` espone su tutte le interfacce | Media | Design (sviluppo) | **Impostare `VAP_HOST=127.0.0.1` in produzione** |
| Injection di contenuto PDF tramite dati di finding | Corretta | Risolto (html.escape) | Nessuna azione necessaria |
