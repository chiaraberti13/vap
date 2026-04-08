# Vulnerability Assessment Platform (VAP)

> **English** | [Italiano](#-vulnerability-assessment-platform-vap-italiano)

Professional, modular web platform to orchestrate security scans, correlate findings, and generate actionable reports from a single dashboard.

---

> **Legal Disclaimer:** Use this platform only on systems you own or for which you have explicit written authorization. Unauthorized scanning is illegal.

---

## COMPLETE PACKAGE

This repository includes:

- **`app.py`** - FastAPI web app (UI + REST API)
- **`scanner_engine.py`** - scan orchestration and validation runtime
- **`scanners/`** - tool-specific scanner plugins
- **`templates/` + `static/`** - dashboard UI
- **`report_generator.py`** - PDF reporting pipeline
- **`tests/`** - regression and security-focused automated tests
- **`installer.sh` / `installer.ps1`** - guided installers
- **`docker-compose.yml`** - Redis helper service for async workers
- **`docs/`** - architecture, security, operations, and playbooks
- **`README.md`** - setup and usage documentation

---

## ✅ INSTALLATION

This project is **not** a single-file app: installation is required once, then normal usage is straightforward.

### Linux / macOS (recommended)

```bash
# 1) Clone repository
git clone <repository-url> VAP
cd VAP

# 2) Run installer
chmod +x installer.sh
./installer.sh

# 3) Activate virtual environment
source venv/bin/activate

# 4) Create env file
cp .env.example .env
```

### Windows (PowerShell)

```powershell
# 1) Open PowerShell (Administrator recommended)
Set-ExecutionPolicy Bypass -Scope Process -Force

# 2) Run installer
.\installer.ps1

# 3) Activate virtual environment
.\venv\Scripts\Activate.ps1

# 4) Create env file
copy .env.example .env
```

---

## HOW TO USE IN 3 STEPS

### Step 1: Configure secure defaults

Edit `.env` and set at least:

```env
VAP_ENV=production
VAP_CSRF_SECRET=<hex-32-bytes>
VAP_JWT_SECRET=<hex-32-bytes>
VAP_API_KEY=<strong-random-key>
VAP_REQUIRE_HTTPS=true
```

Generate secrets with:

```bash
openssl rand -hex 32
```

### Step 2: Start services

#### Minimal local mode (simulated scans)

```bash
source venv/bin/activate
python3 app.py
```

#### Full async mode (Redis + Celery)

```bash
# Terminal A
redis-server

# Terminal B
source venv/bin/activate
celery -A celery_app worker --loglevel=info

# Terminal C
source venv/bin/activate
python3 app.py
```

Open: `http://localhost:8000`

### Step 3: Run your first scan

1. Open the dashboard at `http://localhost:8000`
2. Insert target URL/IP and select scan type (`light`, `full`, `wordpress`)
3. Start scan and monitor progress in real time
4. Review findings and download PDF report

---

## TECHNICAL LIMITS

### Scanner availability

Results depend on installed tools and permissions:

- Some scanners require external binaries (e.g., Nmap, Nuclei, WhatWeb)
- Enterprise scanners (Acunetix/Nessus) require valid API credentials
- Without optional tools, VAP may run fallback or reduced coverage flows

### Concurrency and workload

- Async processing requires Redis + Celery
- Very large scans can increase RAM/CPU usage significantly
- Recommended: run heavy scans on dedicated hosts and avoid shared production nodes

### Report size

- PDF output scales with findings volume
- Large engagements may produce multi-megabyte reports

---

## FEATURES

✅ Multi-scanner orchestration from one interface  
✅ Scan profiles (`light`, `full`, `wordpress`)  
✅ Security controls (CSRF, JWT/API key, security headers, rate limiting, audit logging)  
✅ Finding enrichment (CVE context and correlation engine)  
✅ False-positive scoring support  
✅ Realtime scan progress UX  
✅ PDF report generation and historical tracking  
✅ REST API for automation  
✅ Extensible plugin architecture for new scanner adapters

---

## SYSTEM REQUIREMENTS

### Runtime requirements

- **Python:** 3.10–3.12
- **Redis:** 6/7 (required for async workers)
- **Go:** >= 1.19 (for selected tools)
- **Node.js/npm:** required only for frontend utility workflows/tests

### Supported OS

- ✅ Linux (Ubuntu/Debian/Kali/Fedora/RHEL-like/Arch/openSUSE)
- ✅ macOS 11+
- ✅ Windows 10/11 (native PowerShell or WSL2)

### Minimum recommended resources

- **CPU:** 2 cores (4+ recommended for concurrent scans)
- **RAM:** 4 GB minimum (8+ GB recommended for heavy scans)
- **Disk:** 2 GB for base setup + scan/report artifacts

---

## TROUBLESHOOTING

### `ModuleNotFoundError` or missing packages

**Cause:** virtual environment not active or dependencies not installed.

**Fix:**

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Celery jobs not starting

**Cause:** Redis not running or invalid broker URL.

**Fix:**

1. Start Redis: `redis-server`
2. Verify `.env` broker/backend values
3. Restart worker:

```bash
celery -A celery_app worker --loglevel=info
```

### Scanner returns empty/partial findings

**Cause:** tool missing, target unreachable, permission/network constraints.

**Fix:**

1. Check scanner binary installation
2. Validate target reachability/DNS
3. Run with reduced profile (`light`) to isolate failures

### UI loads but static assets are broken

**Cause:** incorrect working directory or deployment proxy/static mapping.

**Fix:** run app from repository root and verify `static/` path exposure.

---

## GENERATED OUTPUT STRUCTURE

Typical artifacts:

```text
scans/                     # raw scan data and execution artifacts
reports/                   # generated PDF reports
reports/<scan_id>.pdf      # per-scan output file
```

Database and logs capture scan history and operational telemetry for auditing.

---

## SECURITY AND PRIVACY

✅ Secrets managed via environment variables (`.env`)  
✅ Security middleware and hardened response headers  
✅ Input validation and target sanitation  
✅ Optional JWT/API-key protections for API usage  
✅ Audit logging for security-relevant actions

⚠️ Sensitive scan data may include infrastructure details. Protect backups, reports, and DB files with strict access controls.

---

## TEAM SHARING

To share with teammates:

1. Share repository access
2. Share a sanitized `.env` template (**never** commit real secrets)
3. Provide role-based credentials and onboarding runbook from `docs/`

---

## CHANGELOG (HIGH LEVEL)

### Current line

- FastAPI dashboard + API
- Scanner orchestration and plugin ecosystem
- Async background jobs with Celery/Redis
- Security hardening controls and audit trails
- PDF reporting + knowledge and operations docs

For detailed evolution and operational notes, see `docs/`.

---

## SUPPORT

- Open an issue in the repository for bugs or feature requests.
- Read operations/security docs in `docs/` before production rollout.

---

## LICENSE

Distributed under the terms of the license in [`LICENSE`](LICENSE).

---

---

# Vulnerability Assessment Platform (VAP) Italiano

> [English](#vulnerability-assessment-platform-vap) | **Italiano**

Piattaforma web professionale e modulare per orchestrare scansioni di sicurezza, correlare vulnerabilità e produrre report operativi da un’unica dashboard.

---

> **Disclaimer legale:** usa la piattaforma solo su sistemi di tua proprietà o con autorizzazione scritta esplicita. Le scansioni non autorizzate sono illegali.

---

## PACCHETTO COMPLETO

Questo repository contiene:

- **`app.py`** - applicazione FastAPI (UI + API REST)
- **`scanner_engine.py`** - orchestrazione scansioni e validazione target
- **`scanners/`** - plugin scanner per singolo strumento
- **`templates/` + `static/`** - interfaccia dashboard
- **`report_generator.py`** - pipeline report PDF
- **`tests/`** - test automatici di regressione e sicurezza
- **`installer.sh` / `installer.ps1`** - installazione guidata
- **`docker-compose.yml`** - servizio Redis di supporto ai worker async
- **`docs/`** - documentazione tecnica, sicurezza e operativa
- **`README.md`** - guida installazione e utilizzo

---

## ✅ INSTALLAZIONE

Questa applicazione **richiede installazione iniziale** (non è un file standalone).

### Linux / macOS (consigliato)

```bash
git clone <repository-url> VAP
cd VAP
chmod +x installer.sh
./installer.sh
source venv/bin/activate
cp .env.example .env
```

### Windows (PowerShell)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1
.\venv\Scripts\Activate.ps1
copy .env.example .env
```

---

## COME USARE IN 3 PASSI

### Passo 1: Configura i parametri di sicurezza

Nel file `.env` imposta almeno:

```env
VAP_ENV=production
VAP_CSRF_SECRET=<hex-32-byte>
VAP_JWT_SECRET=<hex-32-byte>
VAP_API_KEY=<chiave-random-forte>
VAP_REQUIRE_HTTPS=true
```

### Passo 2: Avvia i servizi

Modalità locale minima:

```bash
source venv/bin/activate
python3 app.py
```

Modalità completa asincrona:

```bash
# Terminale A
redis-server

# Terminale B
source venv/bin/activate
celery -A celery_app worker --loglevel=info

# Terminale C
source venv/bin/activate
python3 app.py
```

Apri `http://localhost:8000`.

### Passo 3: Esegui la prima scansione

1. Apri la dashboard
2. Inserisci target (URL/IP) e tipo scansione (`light`, `full`, `wordpress`)
3. Avvia la scansione e monitora il progresso realtime
4. Analizza i findings e scarica il PDF

---

## LIMITI TECNICI

### Disponibilità scanner

La copertura dipende dai tool installati e dai permessi:

- alcuni scanner necessitano binari esterni (Nmap, Nuclei, WhatWeb, ecc.)
- scanner enterprise (Acunetix/Nessus) richiedono API key valide
- in assenza di componenti opzionali, VAP può operare con copertura ridotta

### Concorrenza e carico

- l’asincrono richiede Redis + Celery
- scansioni grandi possono saturare CPU/RAM
- consigliato dedicare host separati per carichi elevati

### Dimensione report

- i PDF crescono con il numero di findings
- engagement grandi possono generare file multipli o molto pesanti

---

## CARATTERISTICHE

✅ Orchestrazione multi-scanner da un’unica interfaccia  
✅ Profili scansione (`light`, `full`, `wordpress`)  
✅ Controlli sicurezza applicativa (CSRF, JWT/API key, header hardening, rate limiting, audit log)  
✅ Correlazione findings ed enrichment CVE  
✅ Supporto scoring falsi positivi  
✅ Avanzamento scansione realtime  
✅ Generazione report PDF e storico scan  
✅ API REST per automazione  
✅ Architettura estendibile a nuovi plugin scanner

---

## REQUISITI DI SISTEMA

### Runtime

- **Python:** 3.10–3.12
- **Redis:** 6/7 (obbligatorio per worker async)
- **Go:** >= 1.19 (tool specifici)
- **Node.js/npm:** solo per workflow/test frontend

### Sistemi operativi

- ✅ Linux
- ✅ macOS 11+
- ✅ Windows 10/11 (nativo o WSL2)

### Risorse minime consigliate

- **CPU:** 2 core (4+ raccomandati)
- **RAM:** 4 GB (8+ per carichi pesanti)
- **Disco:** 2 GB + spazio per artefatti di scansione/report

---

## RISOLUZIONE PROBLEMI

### Errore `ModuleNotFoundError`

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Job Celery non partono

1. Avvia Redis (`redis-server`)
2. Controlla broker/backend in `.env`
3. Riavvia worker:

```bash
celery -A celery_app worker --loglevel=info
```

### Findings vuoti/parziali

- verifica installazione binari scanner
- verifica raggiungibilità target
- prova profilo `light` per isolare problemi

### Asset statici non caricati

Esegui l’app dalla root del repository e verifica mapping di `static/`.

---

## STRUTTURA OUTPUT GENERATI

```text
scans/                     # artefatti scansione
reports/                   # report PDF
reports/<scan_id>.pdf      # report per scansione
```

Storico e telemetria operativa sono tracciati nel database/log applicativi.

---

## PRIVACY E SICUREZZA

✅ Segreti in variabili ambiente (`.env`)  
✅ Middleware e security headers hardenizzati  
✅ Validazione input e sanitizzazione target  
✅ Protezioni API opzionali (JWT/API key)  
✅ Audit logging per azioni sensibili

⚠️ I dati di scansione possono essere sensibili: proteggi report, DB e backup con controlli d’accesso rigorosi.

---

## CONDIVISIONE TEAM

1. Condividi accesso al repository
2. Condividi template `.env` sanificato (mai segreti reali)
3. Definisci onboarding con runbook in `docs/`

---

## CHANGELOG (ALTO LIVELLO)

### Linea corrente

- Dashboard + API FastAPI
- Orchestrazione scanner e plugin estendibili
- Background jobs con Celery/Redis
- Hardening sicurezza applicativa e audit trail
- Report PDF + documentazione operativa completa

---

## SUPPORTO

- Apri issue nel repository per bug/richieste.
- Consulta prima la documentazione in `docs/`.

---

## LICENZA

Distribuito secondo la licenza indicata in [`LICENSE`](LICENSE).
