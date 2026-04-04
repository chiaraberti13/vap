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
2. Golden dataset di scansioni simulate per regression test.
3. Snapshot UX baseline (flusso “nuova scansione” attuale).
4. Definizione KPI di upgrade:
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
1. Introdurre catalogo metadati scansioni (nuovo modulo, es. `scan_catalog.py`) con schema:
   - `id`, `display_name`, `category`, `level` (beginner/intermediate/pro),
   - `learning_objective`, `when_to_use`, `when_not_to_use`,
   - `owasp_tags`, `mitre_tags`,
   - `expected_duration`, `invasiveness`, `noise_level`,
   - `required_permissions`, `legal_notice`,
   - `common_false_positives`, `interpretation_guide`, `next_learning_step`.
2. Mappare ogni scan type esistente del backend al catalogo senza rimuovere nulla.
3. Validare coerenza tra `SCAN_TYPES`/`SCAN_TYPE_CHOICES` e catalogo via test.

Deliverable:
- `scan_catalog.py`
- test unit: `tests/test_scan_catalog.py`

Criterio di successo:
- 100% dei tipi scansione attuali hanno metadati didattici.

---

## Fase 2 — UX redesign: selezione scansione ricca e guidata

**Obiettivo:** trasformare la select in un componente didattico professionale.

Interventi UI:
1. Sostituire `<select name="scan_type">` con **Scan Type Explorer**:
   - cards filtrabili per categoria (Recon/Web/App/Infra/WordPress);
   - indicatori visivi: difficoltà, durata, invasività, copertura;
   - confronto rapido tra 2-3 scansioni.
2. Pannello “Perché scegliere questa analisi” dinamico.
3. Tooltip/accessory “Termini tecnici” (OWASP, CVSS, false positive).
4. Stepper guidato pre-esecuzione:
   - Step 1: obiettivo utente;
   - Step 2: scelta scansione consigliata;
   - Step 3: conferma legale/consenso;
   - Step 4: run.
5. Mobile-first: cards verticali su small viewport, confronti collapsable.
6. Accessibilità:
   - semantic landmarks,
   - focus states,
   - ARIA per tooltip/dialog,
   - contrast ratio WCAG AA.

Interventi backend/API:
1. Endpoint read-only per catalogo scansioni didattico (es. `GET /api/v1/scan-catalog`).
2. Binding robusto tra card selezionata e `scan_type` effettivo (anti-tampering lato server).

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
1. “Learning sidebar” nel dettaglio scansione con:
   - cosa sta succedendo ora,
   - perché il tool attuale viene lanciato,
   - come leggere i log in sicurezza.
2. Per finding: aggiungere blocchi didattici standardizzati:
   - “spiegazione per junior”,
   - “rischio business”,
   - “verifica manuale consigliata”,
   - “skill da studiare dopo”.
3. Introduzione confidence rubric (confirmed/probable/needs-validation) chiara.
4. Remediation roadmap ordinata per impatto + effort + prerequisiti.

Deliverable:
- aggiornamento renderer findings/report pipeline
- mapping knowledge snippets per severità/tipologia

---

## Fase 4 — Sicurezza applicativa avanzata (hardening)

**Obiettivo:** mantenere ruolo professionale e ridurre rischio abuso.

Interventi prioritari:
1. Autorizzazioni di ruolo (viewer/operator/admin) per scansioni e download report.
2. Policy di target allowlist opzionale in produzione.
3. Audit trail esteso per azioni didattiche e export sensibili.
4. Hardening frontend:
   - riduzione inline scripts/styles (progressivo),
   - CSP più restrittiva,
   - valutazione migrazione da Tailwind CDN a build locale.
5. Secrets governance:
   - checklist automatica startup con severity.

Deliverable:
- `docs/security-hardening-roadmap.md`
- test di sicurezza dedicati (CSRF/JWT/input tampering/IDOR)

---

## Fase 5 — Testing continuo e quality gates enterprise

**Obiettivo:** “create → testa → correggi → ottimizza” come processo standard.

Interventi:
1. Test pyramid aggiornata:
   - unit: catalogo/metadati/validatori,
   - integration: endpoint catalogo + creazione scan,
   - E2E: user journey selezione guidata.
2. A11y e UX checks automatici (axe + keyboard traversal).
3. Performance gate:
   - Lighthouse CI: Performance, Accessibility, Best Practices, SEO >= 90.
4. Security testing:
   - regression OWASP Top 10 rilevante,
   - fuzzing input target/scan_type,
   - rate-limit abuse scenarios.
5. Introduzione quality thresholds bloccanti in CI.

Deliverable:
- workflow CI aggiornato
- report qualità per release

---

## Fase 6 — Documentazione didattica ufficiale

**Obiettivo:** apprendimento progressivo e supporto formativo.

Interventi:
1. Nuova sezione docs: “Percorsi formativi”
   - beginner path (fondamentali + safe practice),
   - analyst path,
   - professional path.
2. Schede scansione (una per tipo) con:
   - teoria minima,
   - esempi output,
   - errori comuni,
   - remediation checklist.
3. Collegamenti a documentazione ufficiale framework/librerie usate.
4. Glossario cyber e FAQ operative.

Deliverable:
- `docs/learning-paths/`
- `docs/scan-playbooks/`

---

## 5) Backlog tecnico dettagliato (priorità)

## P0 (immediato)
- Catalogo metadati scansioni + API read-only.
- Refactor UI selezione scan in cards guidate.
- Anti-regression test funzionalità attuali.
- Copywriting didattico minimo per full/light/wordpress + top tool.

## P1 (breve termine)
- Learning sidebar su scan detail.
- Confidence model UI e remediation roadmap.
- A11y audit completo e fix.

## P2 (medio termine)
- RBAC + allowlist target + hardening CSP.
- Lighthouse CI + security pipeline avanzata.
- Percorsi didattici multipli con progress tracking.

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
- Fase 0 + Fase 1 complete.
- POC UI cards per 3 scan type principali.

## Sprint 2
- Fase 2 completa con rollout feature-flag.
- Test E2E journey “nuova scansione”.

## Sprint 3
- Fase 3 su scan detail + remediation roadmap.
- Beta interna con feedback strutturato.

## Sprint 4
- Fase 4 + Fase 5 (hardening + quality gates).
- Preparazione release candidate.

## Sprint 5
- Fase 6 docs complete + training materials.
- Go-live controllato.

---

## 9) Risultato atteso

Al termine dell’upgrade, VAP resta un motore di scansione solido ma diventa anche un **ambiente di apprendimento professionale**: l’utente non “clicca e basta”, ma capisce **cosa sta facendo, perché, con quali limiti e con quali azioni correttive**.
