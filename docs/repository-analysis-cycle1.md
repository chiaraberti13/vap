## CICLO #1

### PROBLEMI TROVATI: 5

#### 🔴 CRITICI (0)
Nessuno.

#### 🟠 ALTA PRIORITÀ (1)
1. Content Security Policy permissiva con `unsafe-inline` su script e stili.
   - File: `config.py:76-79`
   - Impatto: aumenta in modo significativo la superficie XSS lato browser, perché consente esecuzione di JavaScript inline.
   - Soluzione (codice prima/dopo):

```python
# VECCHIO
csp_policy: str = os.getenv(
    "VAP_CSP_POLICY",
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
    "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; connect-src 'self'; frame-ancestors 'none'",
)
```

```python
# NUOVO (proposto)
csp_policy: str = os.getenv(
    "VAP_CSP_POLICY",
    "default-src 'self'; img-src 'self' data:; style-src 'self' https://cdn.tailwindcss.com; "
    "script-src 'self' https://cdn.tailwindcss.com; connect-src 'self'; frame-ancestors 'none'",
)
# + migrazione script inline verso file statici e, se necessario, nonce-based CSP.
```

#### 🟡 MEDIA PRIORITÀ (2)
1. Mancanza di pipeline CI/CD versionata nel repository.
   - File: root repository (`.github/workflows` assente)
   - Impatto: nessuna garanzia automatica su linting, test, security scan e compatibilità Linux/Windows/macOS ad ogni commit.
   - Soluzione (codice prima/dopo):

```yaml
# VECCHIO
# (assente)
```

```yaml
# NUOVO (proposto) - .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python-version: ["3.11", "3.12"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -r requirements.txt
      - run: pytest -q
```

2. Security dependency scanning non integrato nel progetto.
   - File: `requirements.txt` (presenza dipendenze, ma assenza tooling SCA nel repo)
   - Impatto: vulnerabilità note su dipendenze possono arrivare in produzione senza blocco preventivo.
   - Soluzione (codice prima/dopo):

```yaml
# VECCHIO
# Nessun job SCA automatizzato
```

```yaml
# NUOVO (proposto) - estratto workflow
- run: pip install pip-audit
- run: pip-audit --strict
```

#### 🟢 BASSA PRIORITÀ (2)
1. Default HTTPS non secure-by-default.
   - File: `config.py:40`
   - Impatto: in setup iniziali è facile esporre cookie senza flag `Secure`.
   - Soluzione (codice prima/dopo):

```python
# VECCHIO
require_https: bool = os.getenv("VAP_REQUIRE_HTTPS", "false").lower() == "true"
```

```python
# NUOVO (proposto)
require_https: bool = os.getenv("VAP_REQUIRE_HTTPS", "true").lower() == "true"
# Override a false solo in ambiente development locale.
```

2. Warning di deprecazione su dipendenze transitive in test suite.
   - File: output runtime test (`passlib`, `python-jose`, `python-dateutil`, `reportlab`)
   - Impatto: nessun blocco immediato, ma rischio incompatibilità con Python 3.13/3.14.
   - Soluzione: pianificare upgrade progressivo e validare con matrice versioni Python in CI.

### RACCOMANDAZIONI AGGIUNTIVE
- Aggiungere un baseline di hardening in startup con fail-fast in produzione (es. bloccare `VAP_REQUIRE_HTTPS=false` quando `VAP_ENV=production`).
- Introdurre report periodico OWASP ASVS L1/L2 per endpoint principali (`/auth/token`, `/api/v1/scans`, websocket).
- Tracciare KPI di qualità (coverage, tempo medio test, findings SAST/SCA) come quality gates.

### PROSSIMI STEP
1. Conferma se procedo con il **CICLO #2** implementando direttamente le correzioni di priorità ALTA/MEDIA.
2. Dopo patch, rieseguo test e validazioni sicurezza per produrre un delta report.

---
STATO: IN CORSO
