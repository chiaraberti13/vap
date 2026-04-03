# VAP – Checklist Miglioramenti

Analisi comparativa tra i PDF di riferimento (stile Pentest Tools) e il report attuale generato da VAP.

---

## A. LAYOUT E VISUAL DEL REPORT (`report_generator.py`)


---

## B. PROCESSO DI SCAN (`scanner_engine.py`, `tasks.py`)

---

## C. NUOVI SCANNER DA AGGIUNGERE (`scanners/`)

### Priorità Alta

### Priorità Media

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
