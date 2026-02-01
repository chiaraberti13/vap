# 🚀 Guida Completa all'Installazione

## 📦 Contenuto del Pacchetto

Questo archivio contiene:
- ✅ Struttura directory completa
- ✅ File di configurazione (installer.sh, requirements.txt, .env.example)
- ✅ File CSS e struttura web
- ✅ README e documentazione

## ⚠️ IMPORTANTE: Completamento dei File Python

I file Python nella struttura sono **placeholder vuoti**. 
Per completare l'installazione, devi copiare il codice completo 
dalla conversazione precedente.

### File da Completare:

#### 1. **config.py** (Configurazioni)
Copia il contenuto completo fornito nella conversazione.

#### 2. **database.py** (Database ORM)
Copia il contenuto completo con tutti i modelli SQLAlchemy.

#### 3. **scanner_engine.py** (Motore Scansione)
Copia il motore principale di orchestrazione.

#### 4. **report_generator.py** (Generatore PDF)
Copia il generatore completo di report PDF.

#### 5. **app.py** (Server FastAPI)
Copia l'applicazione FastAPI completa.

#### 6. Scanner Modules (scanners/)
- `nuclei_scanner.py`
- `nmap_scanner.py`
- `whatweb_scanner.py`
- `subfinder_scanner.py`
- `nikto_scanner.py`

#### 7. Templates HTML (templates/)
- `index.html`
- `scan_detail.html`
- `scans_list.html`

## 🔧 Procedura di Installazione

### Passo 1: Estrai l'Archivio
```bash
tar -xzf vulnerability-assessment-platform-COMPLETE.tar.gz
cd vulnerability-assessment-platform
```

### Passo 2: Completa i File Python
Apri ciascun file .py e incolla il codice completo dalla conversazione:

```bash
# Esempio:
nano config.py
# Incolla il codice completo di config.py
# Salva e chiudi

# Ripeti per tutti i file Python
```

### Passo 3: Completa i Template HTML
Stessa procedura per i file HTML in `templates/`

### Passo 4: Esegui l'Installer
```bash
chmod +x installer.sh
./installer.sh
```

L'installer automaticamente:
- Rileva la tua distribuzione Linux
- Installa dipendenze di sistema
- Installa tool di sicurezza (Nuclei, Subfinder, etc.)
- Crea ambiente virtuale Python
- Installa dipendenze Python
- Inizializza il database

### Passo 5: Avvia la Piattaforma
```bash
# Attiva ambiente virtuale
source venv/bin/activate

# Avvia il server
python3 app.py
```

### Passo 6: Accedi alla Dashboard
Apri il browser su: `http://localhost:8000`

## 🎯 Verifica Installazione

Dopo l'installazione, verifica che tutto funzioni:

```bash
# 1. Verifica Python imports
python3 -c "from scanner_engine import ScannerEngine; print('✓ OK')"

# 2. Verifica database
python3 -c "from database import init_db; init_db(); print('✓ OK')"

# 3. Verifica tool esterni
nuclei -version
nmap --version
```

## 🐛 Risoluzione Problemi

### Errore: "Module not found"
```bash
# Assicurati che venv sia attivo
source venv/bin/activate

# Reinstalla dipendenze
pip install -r requirements.txt
```

### Errore: "Tool not found" (nuclei, nmap, etc.)
```bash
# Riesegui l'installer
./installer.sh
```

### Errore: "Permission denied"
```bash
# Dai permessi di esecuzione
chmod +x installer.sh app.py
```

## 📚 Utilizzo

### Via Web UI
1. Vai su http://localhost:8000
2. Inserisci target URL
3. Clicca "Start Scan"
4. Visualizza risultati

### Via CLI
```bash
python3 scanner_engine.py --target https://example.com
```

### Via API
```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_type": "full"}'
```

## ⚠️ Disclaimer

Questo tool è per **SOLO USO AUTORIZZATO**:
- Test di penetrazione autorizzati
- Security auditing professionale
- Ricerca in cybersecurity

L'uso non autorizzato può violare leggi locali e internazionali.

## 📞 Supporto

Per domande o problemi:
1. Consulta la conversazione completa
2. Verifica che tutti i file Python siano completi
3. Controlla i log in `logs/vuln_scanner.log`

---

**Buon Security Testing! 🛡️**
