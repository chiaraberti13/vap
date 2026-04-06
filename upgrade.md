# Piano di Upgrade Profondo — VAP come Tool Didattico + Professionale

## 1) Executive Summary

Obiettivo: evolvere VAP da piattaforma di scansione a **piattaforma di formazione operativa in cyber security** per utenti entry-level, mantenendo **intatte** le funzionalità attuali di scanning/reporting/API.

Direzione strategica:
- preservare pipeline esistente (scanner orchestration, enrichment, reporting);
- introdurre un **Learning Layer** UI/API che spieghi *cosa* fa ogni analisi, *quando* usarla, *quali limiti* ha, *come leggere i risultati*;
- rendere la selezione scansione in interfaccia browser molto più ricca e guidata;
- aggiungere governance di sicurezza e qualità software (test, a11y, performance, secure coding) a livello enterprise.

---

## 2) Analisi architetturale attuale (as-is)

## 2.1 Stack e asset principali
- Backend: FastAPI (`app.py`) con endpoint web + API, websocket progress, middleware sicurezza e rate limiting.
- Engine: `scanner_engine.py` con validazione target, mappa scanner, profili (`light`, `wordpress`) e orchestrazione multi-tool.
- Security: `security.py` + `config.py` con CSRF/JWT/API key, header policy e audit logging.
- UI: template Jinja + Tailwind CDN (`templates/index.html`, `scan_detail.html`, `scans_list.html`) con dashboard e form scansione.
- Persistence: SQLAlchemy + SQLite (`database.py`) per scansioni, findings, audit/consensi.
- Async: Celery/Redis opzionale per coda scansioni.
- Quality: suite test già presente in `tests/`.

## 2.2 Punti di forza da non perdere (must-preserve)
1. Copertura scanner ampia (nuclei, nmap, zap, sqlmap, ecc.).
2. Distinzione profili scansione (`full`, `light`, `wordpress`, single tool).
3. Guardrail sicurezza: validazione target, CSRF, API key/JWT, rate limiting.
4. Reporting PDF e storico scansioni.
5. KPI dashboard e progress realtime.

## 2.3 Gap rispetto all’obiettivo “tool didattico”

### UX/UI (gap critico)
- Nel form scansione, `scan_type` è una select “piatta”: non comunica chiaramente differenze tra analisi, prerequisiti, tempo atteso, rischio/rumore.
- Mancano “learning affordances”: glossario inline, scenari d’uso, explainability del perché scegliere un tipo di scan.
- Mancano warning contestuali su aspetti legali/etici e su limiti della confidence.

### Dominio formativo (gap critico)
- Non esiste un modello dati didattico (obiettivi, livello, teoria minima, check di comprensione, next step).
- Findings molto ricchi, ma manca un percorso “da junior a pro” guidato per priorità e remediation roadmap.

### Engineering Quality
- Mancano test E2E/UI espliciti per il percorso didattico (oggi focus più backend).
- Nessun budget prestazionale definito per la UI (Lighthouse) e nessun gate CI formale su a11y/perf.
- Tailwind via CDN: pratico ma non ideale per hardening/prod governance CSP nel lungo periodo.

---

## 3) Target vision (to-be)

“**Guided Security Analysis Studio**”: ogni scansione viene scelta tramite una scheda esplicativa con:
- obiettivo tecnico;
- copertura OWASP/MITRE;
- prerequisiti e limiti;
- durata stimata;
- impatto operativo (rumore, invasività, false positive);
- output atteso e come interpretarlo;
- modulo didattico suggerito prima/dopo scan.

L’utente entry-level deve poter:
1. capire quale analisi lanciare e perché;
2. eseguire in sicurezza;
3. interpretare il risultato;
4. trasformare findings in piano remediation professionale.

---

## 4) Programma dettagliato degli interventi (roadmap)

## Fase 0 — Baseline, osservabilità e freeze funzionale

**Obiettivo:** fotografare comportamento attuale e prevenire regressioni.

Interventi:
1. [x] Inventario feature correnti (UI/API/CLI/report) in una matrice “must keep”.
2. [x] Golden dataset di scansioni simulate per regression test.
3. [x] Snapshot UX baseline (flusso “nuova scansione” attuale).
4. [x] Definizione KPI di upgrade:
   - Task completion scan-type selection;
   - riduzione errori selezione scan;
   - tempo medio comprensione output;
   - retention didattica (quiz/knowledge checks futuri).

Deliverable:
- `docs/upgrade-baseline.md`
- `tests/fixtures/golden_scans/*.json`

---

## Fase 1 — Modello didattico e metadati scansioni

**Obiettivo:** creare un layer semantico per spiegare le analisi senza toccare la logica core scanner.

Interventi:
1. [x] Introdurre catalogo metadati scansioni (nuovo modulo, es. `scan_catalog.py`) con schema:
   - `id`, `display_name`, `category`, `level` (beginner/intermediate/pro),
   - `learning_objective`, `when_to_use`, `when_not_to_use`,
   - `owasp_tags`, `mitre_tags`,
   - `expected_duration`, `invasiveness`, `noise_level`,
   - `required_permissions`, `legal_notice`,
   - `common_false_positives`, `interpretation_guide`, `next_learning_step`.
2. [x] Mappare ogni scan type esistente del backend al catalogo senza rimuovere nulla.
3. [x] Validare coerenza tra `SCAN_TYPES`/`SCAN_TYPE_CHOICES` e catalogo via test.

Deliverable:
- `scan_catalog.py`
- test unit: `tests/test_scan_catalog.py`

Criterio di successo:
- 100% dei tipi scansione attuali hanno metadati didattici.

---

## Fase 2 — UX redesign: selezione scansione ricca e guidata

**Obiettivo:** trasformare la select in un componente didattico professionale.

Interventi UI:
1. [x] Sostituire `<select name="scan_type">` con **Scan Type Explorer**:
   - cards filtrabili per categoria (Recon/Web/App/Infra/WordPress);
   - indicatori visivi: difficoltà, durata, invasività, copertura;
   - confronto rapido tra 2-3 scansioni.
2. [x] Pannello “Perché scegliere questa analisi” dinamico.
3. [x] Tooltip/accessory “Termini tecnici” (OWASP, CVSS, false positive).
4. [x] Stepper guidato pre-esecuzione:
   - Step 1: obiettivo utente;
   - Step 2: scelta scansione consigliata;
   - Step 3: conferma legale/consenso;
   - Step 4: run.
5. [x] Mobile-first: cards verticali su small viewport, confronti collapsable.
6. Accessibilità:
   - semantic landmarks,
   - focus states,
   - ARIA per tooltip/dialog,
   - contrast ratio WCAG AA.
   - [x] Stato stepper ARIA coerente con navigazione guidata (2026-04-04): `aria-current="step"` ora aggiornato dinamicamente in `static/js/scan-catalog.js` durante la progressione Step 1→4.

Interventi backend/API:
1. [x] Endpoint read-only per catalogo scansioni didattico (2026-04-04): introdotto `GET /api/v1/scan-catalog` con policy di accesso viewer/API key e cache applicativa read-only.
2. [x] Binding robusto tra card selezionata e `scan_type` effettivo (anti-tampering lato server, 2026-04-04): blocco esplicito di `scan_type` non presenti in `SCAN_TYPES` sia nel form web che nell'endpoint API.

Deliverable:
- update `templates/index.html`
- eventuale JS dedicato (es. `static/js/scan-catalog.js`)
- test integrazione UI/API

Criterio di successo:
- L’utente capisce prima del run: obiettivo, rischio, output e limiti della scansione scelta.

---

## Fase 3 — Esperienza didattica durante e dopo la scansione

**Obiettivo:** sfruttare `scan_detail.html` come aula operativa.

Interventi:
1. [x] “Learning sidebar” nel dettaglio scansione con:
   - cosa sta succedendo ora,
   - perché il tool attuale viene lanciato,
   - come leggere i log in sicurezza.
2. [x] Per finding: aggiungere blocchi didattici standardizzati:
   - “spiegazione per junior”,
   - “rischio business”,
   - “verifica manuale consigliata”,
   - “skill da studiare dopo”.
3. [x] Introduzione confidence rubric (confirmed/probable/needs-validation) chiara.
4. [x] Remediation roadmap ordinata per impatto + effort + prerequisiti (2026-04-05): introdotta funzione `_build_remediation_roadmap()` in `app.py` che calcola score impatto×effort, assegna tier (immediato/pianifica/quick_win/monitora) e ordina i findings; sezione dedicata renderizzata in `scan_detail.html` con badge tier, rank numerico, chip effort e legenda prerequisiti; 19 test di regressione in `tests/test_remediation_roadmap.py`.

Deliverable:
- aggiornamento renderer findings/report pipeline
- mapping knowledge snippets per severità/tipologia

---

## Fase 4 — Sicurezza applicativa avanzata (hardening)

**Obiettivo:** mantenere ruolo professionale e ridurre rischio abuso.

Interventi prioritari:
1. [x] Autorizzazioni di ruolo (viewer/operator/admin) per scansioni e download report.
2. [x] Policy di target allowlist opzionale in produzione.
3. [x] Audit trail esteso per azioni didattiche e export sensibili.
4. Hardening frontend:
   - [x] riduzione inline scripts/styles (progressivo, 2026-04-04): introdotta regression suite `tests/test_template_inline_hardening.py` che blocca attributi `style`/event handler inline e script inline eseguibili nei template.
   - [x] CSP più restrittiva (rimossa `unsafe-inline` da `script-src` di default),
   - [x] CSP defense-in-depth completata (2026-04-04): aggiunte direttive `object-src 'none'`, `base-uri 'self'` e `form-action 'self'` nel default policy per ridurre gadget injection/clickjacking chain.
   - [x] riduzione `unsafe-inline` anche su `style-src` (2026-04-04): estratti gli stili inline da `scan_detail.html` in `static/css/style.css` e barra progresso inizializzata via JS senza attributi `style`.
   - [x] valutazione migrazione da Tailwind CDN a build locale (2026-04-04): analisi completata in `docs/tailwind-local-migration-assessment.md` con decisione architetturale e piano di adozione.
   - [x] Step 1 completato: script inline di `scan_detail.html` estratto in `static/js/scan-detail.js` con rendering DOM sicuro.
   - [x] Hardening anti-XSS Scan Type Explorer (2026-04-06): sanitizzati i campi dinamici renderizzati via `innerHTML` in `static/js/scan-catalog.js` con helper `escapeHtml` (display name, obiettivi, metadati OWASP/durata/invasività/rumore) e fallback fail-closed sul binding del pulsante confronto; aggiunti test `tests/test_scan_catalog_frontend_security.py`.
5. [x] Hardening input didattici API (2026-04-04): endpoint `POST /api/v1/learning-feedback` ora normalizza `notes` e rifiuta tag HTML/caratteri di controllo per ridurre rischio XSS/log injection.
6. [x] Secrets governance:
   - checklist automatica startup con severity.

Deliverable:
- [x] `docs/security-hardening-roadmap.md`
- [x] test di sicurezza dedicati (CSRF/JWT/input tampering/IDOR)

---

## Fase 5 — Testing continuo e quality gates enterprise

**Obiettivo:** “create → testa → correggi → ottimizza” come processo standard.

Interventi:
1. [x] Test pyramid aggiornata:
   - unit: catalogo/metadati/validatori,
   - integration: endpoint catalogo + creazione scan,
   - E2E: user journey selezione guidata.
2. [x] A11y e UX checks automatici (axe + keyboard traversal).
3. [x] Performance gate:
   - [x] Lighthouse CI: Performance, Accessibility, Best Practices, SEO >= 90.
   - [x] Console/runtime hardening gate (2026-04-04): aggiunte assertion Lighthouse `errors-in-console` e `csp-xss` per bloccare regressioni JS/CSP nei flussi principali.
4. [x] Security testing:
   - [x] regression OWASP Top 10 rilevante,
   - [x] fuzzing input target/scan_type,
   - [x] rate-limit abuse scenarios (2026-04-04): aggiunto test `test_auth_token_endpoint_enforces_rate_limit` in `tests/test_api_integration.py`.
5. [x] Introduzione quality thresholds bloccanti in CI.

Deliverable:
- workflow CI aggiornato
- report qualità per release

---

## Fase 6 — Documentazione didattica ufficiale

**Obiettivo:** apprendimento progressivo e supporto formativo.

Interventi:
1. [x] Nuova sezione docs: “Percorsi formativi”
   - beginner path (fondamentali + safe practice),
   - analyst path,
   - professional path.
2. [x] Schede scansione (una per tipo) con:
   - teoria minima,
   - esempi output,
   - errori comuni,
   - remediation checklist.
3. [x] Collegamenti a documentazione ufficiale framework/librerie usate.
4. [x] Glossario cyber e FAQ operative.

Deliverable:
- `docs/learning-paths/`
- `docs/scan-playbooks/`

---

## 5) Backlog tecnico dettagliato (priorità)

## P0 (immediato)
- [x] Catalogo metadati scansioni + API read-only (verifica regressione 2026-04-05): confermati modulo `scan_catalog.py`, endpoint `GET /api/v1/scan-catalog` e test dedicati (`tests/test_scan_catalog.py`, `tests/test_api_integration.py::test_get_scan_catalog_endpoint`).
- [x] Refactor UI selezione scan in cards guidate (verifica regressione 2026-04-05): confermata homepage con Scan Type Explorer e cards POC top-3 tramite `tests/test_api_integration.py::test_homepage_guided_explorer_exposes_top3_poc_scan_cards`.
- [x] Anti-regression test funzionalità attuali (2026-04-04): aggiunto test integrazione `test_download_report_endpoint_preserves_pdf_delivery_and_audit` per garantire continuità download PDF e audit trail `report_downloaded`.
- [x] Copywriting didattico minimo per full/light/wordpress + top tool (2026-04-04): arricchiti metadati didattici con contenuti specifici per `nuclei`, `nmap`, `zap`, `sqlmap`, `wpscan` e aggiunta regressione `test_top_tools_have_dedicated_learning_copy`.

## P1 (breve termine)
- [x] Learning sidebar su scan detail (2026-04-04): sidebar didattica attiva in `templates/scan_detail.html` con test integrazione dedicati.
- [x] Confidence model UI e remediation roadmap (2026-04-04): rubric `confirmed/probable/needs-validation` e roadmap remediation prioritaria renderizzate nel dettaglio scansione.
- [x] A11y audit completo e fix (2026-04-04): introdotti skip-link tastiera su homepage/dettaglio scansione e alert region ARIA per errori bloccanti (`templates/index.html`, `templates/scan_detail.html`) con regressione automatica in `tests/test_accessibility_checks.py`.

## P2 (medio termine)
- [x] RBAC + allowlist target + hardening CSP (2026-04-04): controlli ruolo viewer/operator/admin, policy target allowlist opzionale e CSP hardenizzata senza `unsafe-inline` per script.
- [x] Lighthouse CI + security pipeline avanzata (2026-04-04): quality gate CI con soglie Lighthouse >=90 + test OWASP/rate-limit/fuzzing input.
- [x] Percorsi didattici multipli con progress tracking (2026-04-04): aggiunti endpoint `POST/GET /api/v1/learning-progress` con persistenza per-subject e audit event `learning_progress_updated`.

---

## 6) Rischi e mitigazioni

1. **Regressioni funzionali** durante redesign UI.
   - Mitigazione: contract test tra card selection e `scan_type` backend.
2. **Sovraccarico cognitivo** utente entry-level.
   - Mitigazione: progressive disclosure (base → advanced).
3. **Percezione falsa certezza** nei risultati automatici.
   - Mitigazione: messaging esplicito su limiti, confidenza, validazione manuale.
4. **Tech debt frontend** con Tailwind CDN + inline style.
   - Mitigazione: piano migrazione graduale build-based.

---

## 7) Definizione di Done (DoD) per l’upgrade

Una release è “done” quando:
1. nessuna feature di scansione/report esistente è persa;
2. selezione scansione è didattica, comparativa e guidata;
3. test automatici verdi (unit/integration/E2E/security);
4. score Lighthouse >=90 (mobile e desktop) sui flussi principali;
5. a11y WCAG AA verificata;
6. zero errori console nei percorsi principali;
7. documentazione utente + playbook tecnici aggiornata.

---

## 8) Piano di esecuzione iterativo consigliato (sprint)

## Sprint 1 (1-2 settimane)
- [x] Fase 0 + Fase 1 complete.
- [x] POC UI cards per 3 scan type principali (2026-04-04): aggiunto test `test_homepage_guided_explorer_exposes_top3_poc_scan_cards` per verificare la presenza in homepage guidata di `full`, `light`, `wordpress`.

## Sprint 2
- [x] Fase 2 completa con rollout feature-flag.
- [x] Test E2E journey “nuova scansione” (2026-04-06): coperto il flusso guidato completo homepage → submit form → redirect al dettaglio scansione con `tests/test_api_integration.py::test_guided_scan_form_end_to_end_journey`.
- [x] Hardening journey guidato su consenso obbligatorio (2026-04-06): aggiunto test negativo `tests/test_api_integration.py::test_guided_scan_form_blocks_submission_without_required_consents` per garantire blocco fail-closed (HTTP 403), messaggio UX esplicito e assenza di creazione scansione senza accettazione termini.

## Sprint 3
- [x] Fase 3 su scan detail + remediation roadmap.
- [x] Beta interna con feedback strutturato (2026-04-04): introdotto endpoint `POST /api/v1/learning-feedback` con persistenza DB, validazioni robuste e audit trail.

## Sprint 4
- [x] Fase 4 + Fase 5 (hardening + quality gates) completate (2026-04-04): verificata suite `PYTHONPATH=. pytest -q` con `112 passed`, coverage totale `82.95%` e soglia minima `80%` rispettata.
- [x] Preparazione release candidate (2026-04-06): aggiunta checklist operativa RC in `docs/release-candidate.md` con gate funzionali, UX/a11y, sicurezza e qualità, più integrazione in navigazione documentazione MkDocs.

## Sprint 5
- [x] Fase 6 docs complete + training materials (2026-04-04): presenti learning paths (`docs/learning-paths/`), playbook scanner (`docs/scan-playbooks/`), glossario/FAQ (`docs/glossary-faq.md`) e riferimenti ufficiali (`docs/official-references.md`).
- [x] Go-live controllato (2026-04-06): aggiunto runbook operativo `docs/go-live-controlled.md` con prerequisiti go/no-go, rollout progressivo, smoke/security checks, criteri di rollback ed evidenze minime; integrato nella navigazione MkDocs.
- [x] Verifica continua post-upgrade (2026-04-04): rieseguita suite completa `PYTHONPATH=. pytest -q` con esito `125 passed`, coverage totale `83.08%` (soglia minima `80%` rispettata) e nessuna regressione funzionale rilevata.
- [x] Verifica continua post-upgrade (2026-04-05): rieseguita suite completa `PYTHONPATH=. pytest -q` con esito `144 passed`, coverage totale `83.08%` (soglia minima `80%` rispettata) e nessuna regressione funzionale rilevata.
- [x] Verifica continua post-upgrade (2026-04-06): rieseguita suite completa `PYTHONPATH=. pytest -q` con esito `144 passed`, coverage totale `83.08%` (soglia minima `80%` rispettata) e nessuna regressione funzionale rilevata.
- [x] Verifica continua post-upgrade (2026-04-06, ciclo iterativo successivo): confermata stabilità su nuova esecuzione completa `PYTHONPATH=. pytest -q` con esito `144 passed`, coverage totale `83.08%` (soglia minima `80%` rispettata) e nessuna regressione funzionale rilevata.
- [x] Verifica continua post-upgrade (2026-04-06, ciclo iterativo sicurezza+qualità): eseguita nuovamente la suite completa `PYTHONPATH=. pytest -q` con esito `144 passed`, coverage totale `83.08%` (soglia minima `80%` rispettata), senza regressioni su flussi UX guidati, hardening e controlli API.
- [x] Verifica continua post-upgrade (2026-04-06, ciclo iterativo stabilità): rieseguita la suite completa `PYTHONPATH=. pytest -q` con esito `144 passed`, coverage totale `83.08%` (soglia minima `80%` rispettata), confermando stabilità end-to-end su scanner orchestration, UX guidata e hardening sicurezza.
- [x] Verifica continua post-upgrade (2026-04-06, ciclo iterativo QA finale): rieseguita la suite completa `PYTHONPATH=. pytest -q` con esito `147 passed`, coverage totale `83.08%` (soglia minima `80%` rispettata), confermando ulteriore stabilità dopo i cicli precedenti e assenza di regressioni funzionali/sicurezza.
- [x] Verifica continua post-upgrade (2026-04-06, ciclo iterativo follow-up): rieseguita la suite completa `PYTHONPATH=. pytest -q` con esito `147 passed`, coverage totale `83.08%` (soglia minima `80%` rispettata), confermata stabilità regressiva su UX guidata, hardening frontend/API e qualità complessiva.

---

## 9) Risultato atteso

Al termine dell’upgrade, VAP resta un motore di scansione solido ma diventa anche un **ambiente di apprendimento professionale**: l’utente non “clicca e basta”, ma capisce **cosa sta facendo, perché, con quali limiti e con quali azioni correttive**.

---

## 10) Errori pre-esistenti rilevati durante l'upgrade

- [x] **Test regressione WordPress profile falliva (risolto il 2026-04-04):** `tests/test_wpscan_scanner.py::test_get_scanner_classes_supports_wordpress_scan_type` aggiornato per riflettere il comportamento reale del profilo `scan_type="wordpress"` che usa `WordpressNucleiScanner` (template profile dedicato) al posto di `NucleiScanner`.
- [x] **Conferma 2026-04-04 (post-fix):** eseguito `PYTHONPATH=. pytest -q` con esito `109 passed` (nessun failure residuo sul profilo WordPress).
- [x] **Warning tecnici applicativi ridotti (2026-04-04):** risolti warning interni non dipendenti da librerie terze parti aggiornando tutte le `TemplateResponse` FastAPI/Starlette al nuovo ordine parametri (`request` come primo argomento) e impedendo la raccolta accidentale di `TestsslScanner` come classe di test (`__test__ = False`). Verifica: `PYTHONPATH=. pytest -q` con `112 passed` e warning Starlette/PytestCollection azzerati.
- [x] **Warning tecnici residui da dipendenze terze parti (rilevati il 2026-04-04, mitigati il 2026-04-04):** aggiunti filtri warning mirati in `pytest.ini` per dipendenze esterne (`dateutil`, `reportlab`, `passlib`, `python-jose`) in modo da mantenere la suite CI pulita da rumore non applicativo, preservando il rilevamento di warning provenienti dal codice progetto.
- [x] **Hardening fail-closed su verifica API key hash (2026-04-04):** `security.verify_api_key` ora gestisce hash non validi/malformati senza eccezioni runtime (catch `UnknownHashError`/`ValueError`) e rifiuta l'autenticazione in modo sicuro. Coperto da test `test_verify_api_key_with_invalid_hash_fails_closed`.
