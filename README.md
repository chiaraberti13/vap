# 🛡️ Vulnerability Assessment Platform

Piattaforma professionale di **Vulnerability Assessment** modulare con capacità di scansione avanzate e reportistica PDF completa.

## ✨ Caratteristiche

- **Multi-Scanner Integration**: Nuclei, Nmap, WhatWeb, Subfinder, Nikto
- **Scansione Asincrona**: Esecuzione parallela per performance ottimali
- **Report PDF Professionali**: Executive summary, grafici, mappatura OWASP Top 10
- **Web Dashboard**: Interfaccia moderna con Tailwind CSS
- **REST API**: API completa per integrazione
- **Database SQLite**: Storage persistente di scansioni e vulnerabilità

## 🚀 Installazione Rapida

```bash
# 1. Estrai l'archivio
tar -xzf vulnerability-assessment-platform.tar.gz
cd vulnerability-assessment-platform

# 2. Esegui l'installer automatico
chmod +x installer.sh
./installer.sh

# 3. Attiva l'ambiente virtuale
source venv/bin/activate

# 4. Avvia il server
python3 app.py
```

Il server sarà disponibile su `http://localhost:8000`

## 📋 Requisiti

- **Sistema Operativo**: Linux (Debian, Ubuntu, Kali, Arch)
- **Python**: 3.9+
- **Go**: 1.19+ (per tool esterni)
- **Tool Esterni**: Nmap, Nikto (installati automaticamente)

## 🎯 Utilizzo

### Via Web UI

1. Apri `http://localhost:8000` nel browser
2. Inserisci il target (URL o IP)
3. Seleziona il tipo di scansione
4. Avvia la scansione
5. Visualizza i risultati e genera il report PDF

### Via API

```bash
# Crea una nuova scansione
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_type": "full"}'

# Controlla lo status
curl http://localhost:8000/api/v1/scans/{scan_id}/status

# Scarica il report
curl -O http://localhost:8000/api/v1/scans/{scan_id}/report/download
```

### Via CLI

```bash
python3 scanner_engine.py --target https://example.com --output results.json
```

## 🏗️ Architettura

```
vulnerability-assessment-platform/
├── app.py                      # FastAPI server
├── scanner_engine.py           # Motore orchestrazione
├── report_generator.py         # Generatore PDF
├── database.py                 # Modelli ORM
├── config.py                   # Configurazioni
├── installer.sh                # Auto-installer
├── requirements.txt            # Dipendenze Python
├── scanners/                   # Moduli scanner
│   ├── nuclei_scanner.py
│   ├── nmap_scanner.py
│   ├── whatweb_scanner.py
│   ├── subfinder_scanner.py
│   └── nikto_scanner.py
├── templates/                  # Template HTML
└── reports/                    # Report PDF generati
```

## 🔧 Configurazione

Modifica `config.py` per personalizzare:
- Timeout scanner
- Percorsi tool
- Parametri report PDF
- Configurazione database

## 📊 Report Features

I report PDF includono:
- **Executive Summary** con risk level
- **Grafici** (pie chart, bar chart)
- **Dettaglio tecnico** di ogni vulnerabilità
- **CVE** e **CVSS score**
- **Mappatura OWASP Top 10**
- **Raccomandazioni** di remediation

## ⚠️ Disclaimer

Questo tool è destinato **ESCLUSIVAMENTE** a:
- Test di penetrazione autorizzati
- Auditing di sicurezza professionale
- Ricerca in ambito cybersecurity

L'uso non autorizzato può violare leggi locali e internazionali. L'utente è responsabile dell'uso appropriato del software.

## 📝 Licenza

Questo progetto è fornito a scopo educativo e di ricerca.

## 👨‍💻 Autore

Developed by DevSecOps Team

---

**⭐ Se trovi utile questo progetto, lascia una stella!**
