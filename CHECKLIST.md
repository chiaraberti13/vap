# VAP – Checklist Miglioramenti

Analisi comparativa tra i PDF di riferimento (stile Pentest Tools) e il report attuale generato da VAP.

---

## A. LAYOUT E VISUAL DEL REPORT (`report_generator.py`)

- [ ] **A6 – Campo "Tests performed"**: aggiungere nel panel Scan information il conteggio dei test eseguiti
- [ ] **A7 – Flag icon nei finding**: sostituire il quadratino `■` con icona flag `▶` / `⚑` prima del titolo
- [ ] **A8 – OWASP multi-versione**: mostrare mapping per OWASP **2017, 2021 e 2025** nella classificazione (non solo 2021)
- [ ] **A9 – CISA KEV**: aggiungere campo "CISA KEV: True/False" nella sezione Classification
- [ ] **A10 – EPSS score**: aggiungere EPSS score e EPSS percentile nella tabella CVE dei finding
- [ ] **A11 – Campo "Found by"**: aggiungere metodo di detection per ogni finding
  - es. "Passive Detection", "Aggressive Detection", "Active Testing"
- [ ] **A12 – Tabella evidence estesa**: aggiungere colonne "Method" (GET/POST) e "Parameters" alla tabella URL/Evidence quando disponibili
- [ ] **A13 – Technology table**: per finding di tipo "tecnologie rilevate" (WhatWeb), tabella con colonne Software/Version + Category (con icone se possibile)
- [ ] **A14 – CVE table strutturata**: per finding con CVE, tabella con colonne CVE | CVSS | EPSS score | EPSS percentile | Summary (incluso "Fixed in version" e reference URLs)
- [ ] **A15 – Sezione "Scan coverage information"**: lista completa in fondo al report dei test eseguiti con ✓, raggruppati per porta/categoria
- [ ] **A16 – Sezione "Scan parameters"**: sezione con parametri usati (target, scan_type, authentication, detection_mode, enumerate_*)
- [ ] **A17 – Sezione "Scan stats"**: statistiche di scan (URLs spidered, unique injection points, total HTTP requests, average response time)
- [ ] **A18 – Logo/branding**: migliorare il logo VAP nell'header (da badge testo a icona più professionale)

---

## B. PROCESSO DI SCAN (`scanner_engine.py`, `tasks.py`)

- [ ] **B1 – Redirect detection**: rilevare e registrare redirect HTTP→HTTPS durante la validazione del target, salvarlo come metadata
- [ ] **B2 – Tracking "tests_performed"**: ogni scanner restituisce il conteggio dei test eseguiti; aggregare il totale nel `ScanResult`
- [ ] **B3 – Tracking "urls_spidered"**: raccogliere e sommare gli URL analizzati dai vari scanner
- [ ] **B4 – Tracking "unique_injection_points"**: raccogliere il conteggio dei parametri/injection point trovati
- [ ] **B5 – Tracking "total_http_requests"**: sommare le richieste HTTP effettuate da tutti gli scanner
- [ ] **B6 – Tracking "avg_response_time"**: calcolare e salvare il tempo medio di risposta del target
- [ ] **B7 – Campo "found_by" nei finding**: ogni scanner popola `found_by` nel finding dict
  - es. "Nikto – Passive Detection", "Nuclei – Active Testing"
- [ ] **B8 – Campo "method" e "parameters"**: i finding includono metodo HTTP e parametri usati nell'evidence dove applicabile
- [ ] **B10 – Passaggio metadata al report generator**: `generate_report()` riceve le nuove stats per le sezioni A15/A16/A17

---

## C. NUOVI SCANNER DA AGGIUNGERE (`scanners/`)

### Priorità Alta

- [ ] **C2 – wafw00f** (`scanners/wafw00f_scanner.py`)
  - WAF detection e fingerprinting
  - Output: tipo di WAF rilevato, bypass hints
  - Tool: `wafw00f {target} -o json`

- [ ] **C3 – testssl.sh** (`scanners/testssl_scanner.py`)
  - Analisi SSL/TLS approfondita
  - Rileva: cipher deboli, protocolli obsoleti (SSLv3/TLS1.0/1.1), cert scaduti/self-signed, HSTS mancante
  - Tool: `testssl.sh --jsonfile {output} {target}`

- [ ] **C4 – theHarvester** (`scanners/theharvester_scanner.py`)
  - OSINT: raccoglie email, subdomain, IP, hostname da fonti pubbliche
  - Tool: `theHarvester -d {domain} -b all -f {output}`

- [ ] **C5 – Arjun** (`scanners/arjun_scanner.py`)
  - HTTP parameter discovery: trova parametri nascosti/non documentati
  - Tool: `arjun -u {target} --json -o {output}`

### Priorità Media

- [ ] **C6 – DalFox** (`scanners/dalfox_scanner.py`)
  - XSS scanner più avanzato di XSStrike: DOM XSS, reflected XSS, parametri complessi
  - Tool: `dalfox url {target} --format json`

- [ ] **C7 – httpx** (`scanners/httpx_scanner.py`)
  - Web probing avanzato: fingerprinting headers, status codes, redirect chains, tech detection
  - Tool: `httpx -u {target} -json`

- [ ] **C8 – Katana** (`scanners/katana_scanner.py`)
  - Web crawler per mappare tutti gli endpoint e URL del target
  - Fornisce i dati per la stat "URLs spidered"
  - Tool: `katana -u {target} -json`

- [ ] **C9 – NoSQLMap** (`scanners/nosqlmap_scanner.py`)
  - NoSQL injection detection (MongoDB, CouchDB, Redis)
  - Tool: `nosqlmap` via subprocess

---

## D. ENRICHMENT E CLASSIFICAZIONE (`enrichment_engine.py`)

- [ ] **D1 – OWASP 2025 mapping**: aggiungere dizionario `OWASP_2025_MAPPING` con categorie A01-A10 2025 e popolare il campo nei finding
- [ ] **D2 – OWASP 2017 mapping**: aggiungere dizionario `OWASP_2017_MAPPING` per retrocompatibilità
- [ ] **D3 – EPSS score lookup**: integrare chiamata all'API FIRST EPSS (`https://api.first.org/data/v1/epss?cve={cve_id}`) per ogni CVE trovato
- [ ] **D4 – CISA KEV lookup**: verificare le CVE nel catalogo CISA KEV (JSON pubblico) e flaggarle come "Known Exploited"
- [ ] **D5 – "Fixed in version" enrichment**: per CVE legate a componenti (WP theme, plugin, library), aggiungere `fixed_in_version` dai dati NVD/WPVulnDB

---

## E. SCAN TYPES E CONFIGURAZIONE (`config.py`)

- [ ] **E1 – Scan type "wordpress"**: definire scan type specifico che attiva WPScan + WhatWeb + Nikto + Nuclei (template WP) + Nmap + wafw00f
- [ ] **E2 – Scan type "light"**: scan limitato a WhatWeb + Nikto (headers only) + Nmap (top ports) + httpx, con banner nel report sui limiti
- [ ] **E3 – Parametri WPScan in config**: aggiungere `VAP_WPSCAN_API_TOKEN`, `VAP_WPSCAN_ENUMERATE` (plugins, themes, users, timthumbs, config_backups, db_exports)
- [ ] **E4 – Scan type label nel report**: il campo `scan_type` nel panel mostra info aggiuntive (es. "Light", "Deep", "WordPress – Passive")

---

## File da modificare

| File | Sezioni |
|------|---------|
| `report_generator.py` | A1–A18 |
| `scanner_engine.py` | B1–B8 |
| `tasks.py` | B10 |
| `database.py` | B9 |
| `enrichment_engine.py` | D1–D5 |
| `config.py` | E3 |
| `scanners/wpscan_scanner.py` | C1 (nuovo) |
| `scanners/wafw00f_scanner.py` | C2 (nuovo) |
| `scanners/testssl_scanner.py` | C3 (nuovo) |
| `scanners/theharvester_scanner.py` | C4 (nuovo) |
| `scanners/arjun_scanner.py` | C5 (nuovo) |
| `scanners/dalfox_scanner.py` | C6 (nuovo) |
| `scanners/httpx_scanner.py` | C7 (nuovo) |
| `scanners/katana_scanner.py` | C8 (nuovo) |
| `scanners/nosqlmap_scanner.py` | C9 (nuovo) |

---

## Ordine di implementazione consigliato
