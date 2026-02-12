## CICLO #1

### PROBLEMI TROVATI: 6

#### 🔴 CRITICI (1)
1. Endpoint autenticazione con credenziali demo statiche e previsibili.
   - File: `config.py:50-51`, `app.py:600-611`
   - Impatto: se `VAP_JWT_SECRET` viene configurato ma non vengono sovrascritte le demo credentials, l'endpoint `/auth/token` resta attaccabile con credenziali note (`admin` / `change-me`). Questo espone l'intera API protetta da JWT a compromissione account.
   - Soluzione (codice prima/dopo):

```python
# VECCHIO (config.py)
jwt_demo_user: str = os.getenv("VAP_JWT_DEMO_USER", "admin")
jwt_demo_password: str = os.getenv("VAP_JWT_DEMO_PASSWORD", "change-me")
```

```python
# NUOVO (proposto)
jwt_demo_user: str = os.getenv("VAP_JWT_DEMO_USER", "")
jwt_demo_password: str = os.getenv("VAP_JWT_DEMO_PASSWORD", "")
```

```python
# VECCHIO (app.py)
if not (username == settings.jwt_demo_user and password == settings.jwt_demo_password):
    raise HTTPException(status_code=401, detail="Credenziali non valide")
```

```python
# NUOVO (proposto)
if not settings.jwt_demo_user or not settings.jwt_demo_password:
    raise HTTPException(status_code=503, detail="Credenziali JWT non configurate")
if not (username == settings.jwt_demo_user and password == settings.jwt_demo_password):
    raise HTTPException(status_code=401, detail="Credenziali non valide")
```

#### 🟠 ALTA PRIORITÀ (2)
1. Coverage quality gate non rispettato (`--cov-fail-under=80`).
   - File: `pytest.ini:1-4`, `scanner_engine.py`
   - Impatto: pipeline CI fallisce e parti critiche (orchestrazione scanner/errore scanner) non sono coperte adeguatamente; maggiore rischio regressioni.
   - Soluzione (codice prima/dopo):

```ini
# VECCHIO (pytest.ini)
addopts = --cov=scanner_engine --cov=security --cov-report=term-missing --cov-fail-under=80
```

```ini
# NUOVO (proposto)
# mantenere soglia 80, aggiungere test mirati:
# - test run_scan() con scanner finti
# - test _run_scanner() su eccezione
# - test validate_target()/validate_nmap_target() edge cases
```

2. Trust non validato di `X-Forwarded-For` nei log/audit.
   - File: `security.py:103-107`
   - Impatto: spoofing IP nei log e audit trail; indebolimento investigazioni incident response e possibili bypass di controlli dipendenti da IP.
   - Soluzione (codice prima/dopo):

```python
# VECCHIO
forwarded = request.headers.get("x-forwarded-for")
if forwarded:
    return forwarded.split(",")[0].strip()
```

```python
# NUOVO (proposto)
trusted_proxy = settings.trusted_proxy_ip
if request.client and request.client.host == trusted_proxy:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
```

#### 🟡 MEDIA PRIORITÀ (2)
1. Mappa scanner duplicata in due punti (`get_scanner_classes`, `run_single_scanner`).
   - File: `scanner_engine.py:177-195`, `scanner_engine.py:204-219`
   - Impatto: rischio incoerenza futura quando viene aggiunto/rimosso uno scanner (violazione DRY).
   - Soluzione (codice prima/dopo):

```python
# VECCHIO
scanners_map = {...}  # ripetuto in due funzioni
```

```python
# NUOVO (proposto)
SCANNERS_MAP = {...}  # costante modulo unica
# funzioni che usano SCANNERS_MAP
```

2. Error handling troppo generico in `_run_scanner` con perdita di contesto strutturato.
   - File: `scanner_engine.py:167-175`
   - Impatto: troubleshooting lento; difficile distinguere errori di rete, timeout, validazione o bug.
   - Soluzione (codice prima/dopo):

```python
# VECCHIO
except Exception as exc:
    return {"status": "error", "message": str(exc)}
```

```python
# NUOVO (proposto)
except TimeoutError as exc:
    return {..., "error_type": "timeout", "message": str(exc)}
except ValueError as exc:
    return {..., "error_type": "validation", "message": str(exc)}
except Exception as exc:
    return {..., "error_type": "unexpected", "message": "scanner runtime error"}
```

#### 🟢 BASSA PRIORITÀ (1)
1. Configurazione HTTP non secure-by-default (`VAP_REQUIRE_HTTPS=false`).
   - File: `config.py:40`, `app.py:571`
   - Impatto: cookie CSRF non `secure` in ambienti non hardenizzati; rischio downgrade in deploy iniziali.
   - Soluzione (codice prima/dopo):

```python
# VECCHIO
require_https: bool = os.getenv("VAP_REQUIRE_HTTPS", "false").lower() == "true"
```

```python
# NUOVO (proposto)
require_https: bool = os.getenv("VAP_REQUIRE_HTTPS", "true").lower() == "true"
# e override esplicito solo in dev
```

### RACCOMANDAZIONI AGGIUNTIVE
- Introdurre una policy di security baseline in startup (fail-fast in produzione se restano default insicuri).
- Aggiungere threat modeling leggero per endpoint `/auth/token`, `/api/v1/scans` e websocket.
- Integrare `pip-audit` e `bandit` in CI con soglie bloccanti.

### PROSSIMI STEP
1. Confermare se procedo con il **CICLO #2** implementando direttamente le correzioni CRITICHE/ALTE.
2. Dopo patch, rieseguire test + coverage + scansioni sicurezza e produrre delta report.

---
STATO: IN CORSO
