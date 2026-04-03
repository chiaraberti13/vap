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

---

## D. ENRICHMENT E CLASSIFICAZIONE (`enrichment_engine.py`)

---

## E. SCAN TYPES E CONFIGURAZIONE (`config.py`)

---

## File da modificare

| File | Sezioni |
|------|---------|
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
