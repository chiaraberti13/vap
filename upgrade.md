# Upgrade Plan VAP — Sicurezza, UX didattica e scansioni configurabili

## 0) Obiettivo del ciclo corrente
Creare un piano operativo **didattico e incrementale** per trasformare VAP in una piattaforma:
- impeccabile sul piano sicurezza applicativa e operativa;
- altamente configurabile “voce per voce” dall’utente;
- efficace per apprendimento guidato (junior → professional);
- curata nel design UI/PDF con estetica minimale.

---

## 1) Analisi stato attuale (baseline reale repository)

### Punti forti già presenti
- Architettura solida con FastAPI + orchestrazione scanner modulare e plugin contract versionato.
- Validazioni target e controlli fail-closed per registrazione scanner.
- Hardening già avviato: CSRF, API key/JWT, rate limit, audit logging, allowlist target in produzione.
- UX già orientata alla didattica: wizard step-by-step, glossario, learning sidebar, guidance per scan type.
- Report PDF già strutturato con KPI, severità, dettaglio finding.
- Documentazione security e roadmap dedicate già presenti.

### Gap principali rispetto alla richiesta utente
1. **Personalizzazione scansione ancora “a profilo”**
   - L’utente sceglie scan type, ma non ha un **builder granulare per singolo modulo/opzione** (timeout, profondità crawler, payload policy, aggressività, esclusioni, thread, autenticazione, ecc.).
2. **Didattica non ancora “adattiva” per competenza**
   - Contenuti didattici presenti, ma non un vero tutor mode con prerequisiti, warning dinamici, quiz/validation checkpoint e percorsi personalizzati per ruolo.
3. **Sicurezza operativa da rafforzare lato execution safety**
   - Mancano ancora guardrail avanzati centralizzati per evitare configurazioni distruttive o non conformi (policy engine per scan config, budget di rischio, sandboxing per tool ad alta invasività, approval workflow).
4. **UX informativa molto ricca ma non sempre minimal**
   - Dashboard e dettaglio scansione hanno alta densità contenutistica; il rischio è overload cognitivo per studenti/junior.
5. **PDF professionale ma visivamente migliorabile**
   - Struttura valida, ma servono varianti template più “clean” e leggibili (gerarchia tipografica, whitespace, executive summary 1 pagina, remediation board più visiva).

---

## 2) Principi guida dell’upgrade

1. **Secure by default, expert by choice**
   - preset sicuri sempre attivi;
   - modalità avanzata disponibile con sblocco esplicito e spiegazioni rischio.

2. **Didattica contestuale, non separata**
   - ogni scelta tecnica deve mostrare “cosa fa”, “perché”, “rischi”, “quando evitarla”, “come validare il risultato”.

3. **Progressive disclosure UX**
   - interfaccia pulita iniziale;
   - dettagli avanzati solo quando richiesti.

4. **Tracciabilità completa**
   - ogni modifica ai parametri di scansione deve essere auditabile, ripetibile, esportabile.

---

## 3) Piano di miglioramento (checklist prioritaria)

## Fase A — Fondazioni per scansioni configurabili (P0)
- [x] **A1. Modello dati Scan Configuration v1**
  - JSON schema versionato per opzioni per-tool e globali.
  - Campi minimi: target scope, rate/timeout, depth, auth context, exclusions, severity threshold, evidenza minima.
  - Vincoli fail-closed e default sicuri.

- [x] **A2. Validation & Policy Engine**
  - Validazione server-side rigorosa di ogni opzione.
  - Regole di compatibilità tra tool (es. mutually exclusive settings).
  - Policy di sicurezza: blocco opzioni ad alto rischio in assenza autorizzazione/ruolo.

- [x] **A3. Execution Guardrails**
  - [x] Limiti runtime centralizzati lato API: max duration stimata, max requests/min, max concurrency e timeout tool.
  - [x] Safe mode obbligatorio per ruoli non admin (depth/payload cap).
  - [x] Kill switch globale su nuove scansioni + auto-abort su pattern anomali (alto tasso errori scanner).

- [x] **A4. Persistenza configurazioni e profili utente**
  - [x] Salvare preset personalizzati (“Baseline didattica”, “OWASP top focus”, “WordPress deep”).
  - [x] Versioning + checksum config per reproducibility (snapshot configurazione salvato per ogni scansione con endpoint dedicato di retrieval + verifica checksum server-side su snapshot/preset per intercettare tampering).

## Fase B — UX didattica e configurazione guidata (P0/P1)
- [x] **B1. Nuovo “Scan Builder” multi-step**
  - [x] Step 1 Scope legale/target.
  - [x] Step 2 Selezione moduli scanner.
  - [x] Step 3 Parametri avanzati per modulo.
  - [x] Step 4 Simulazione impatto (durata/rumore/rischio stimato).
  - [x] Step 5 Conferma con checklist compliance.

- [x] **B2. Didactic Mode (Beginner / Analyst / Expert)**
  - [x] Beginner: linguaggio semplificato + preset bloccati.
  - [x] Analyst: parametri intermedi con suggerimenti.
  - [x] Expert: pieno controllo con warning forti.

- [x] **B3. Explainability inline per ogni parametro**
  - Tooltip “cosa cambia”, “trade-off”, “false positive impact”.
  - Esempi pratici e anti-pattern.

- [x] **B4. UX minimal e accessibile**
  - [x] Stato errore più chiaro nel wizard: evidenziazione visuale coerente (`form-control-invalid`) per input/checkbox/fieldset invalidi + associazione ARIA esplicita tra campi e messaggi di errore inline.
  - [x] Riduzione densità visiva e migliori spaziature nelle viste principali (dashboard + dettagli scansione).
  - [x] Verifica WCAG AA completa (contrasto, tastiera, screen reader labels) con report dedicato.

## Fase C — Sicurezza avanzata applicativa e operativa (P0/P1)
- [x] **C1. RBAC fine-grained sulle capability di scansione**
  - [x] Permesso capability `create_scan_config` separato dal semplice ruolo viewer, applicato a creazione/cancellazione preset e creazione scansione API.
  - [x] Permesso capability `run_high_risk_scan` con enforcement esplicito (403) prima dell'orchestrazione per tool ad alto rischio.
  - [x] Permesso capability `export_sensitive_report` per download report classificati `confidential/restricted`.
  - [x] Permesso capability `override_scan_policy` con enforcement esplicito per richieste di eccezione policy in creazione scansione/preset (workflow approvativo avanzato resta in C2).

- [x] **C2. Approval workflow per scansioni ad alto rischio**
  - Double-confirmation + eventuale approvazione admin.

- [x] **C3. Secret management hardening**
  - [x] Nessun segreto in chiaro in output API di snapshot/preset configurazione (mascheramento server-side dei campi auth sensibili).
  - [x] Nessun segreto in chiaro in form/log/report.
  - [x] Mascheramento forte e rotazione chiavi guidata.

- [x] **C4. Security regression suite estesa**
  - [x] Fuzzing input config.
  - [x] Test anti-IDOR su risorse scansione/report.
  - [x] Test policy bypass e privilege escalation.

## Fase D — Reporting PDF/UI (P1)
- [x] **D1. Nuovo template PDF minimal/professional**
  - Copertina pulita, sommario executive 1 pagina, severity heatmap, remediation roadmap by priority.

- [x] **D2. Report didattico dual-layer**
  - [x] Layer 1: executive (manageriale) con sezione dedicata esplicita nel PDF.
  - [x] Layer 2: tecnico con evidenze complete e passi di validazione (checklist + validation steps per finding).

- [x] **D3. Design tokens condivisi UI/PDF**
  - [x] Introdotto catalogo token condiviso (`design_tokens.py`) per palette, tipografia, spacing e severity.
  - [x] UI aggiornata con stylesheet dedicato (`/static/css/design-tokens.css`) caricato in tutte le viste HTML prima di `style.css`.
  - [x] PDF generator allineato ai token condivisi (rimozione valori hardcoded duplicati).
  - [x] Copertura test dedicata per garantire coerenza token UI/PDF nel tempo.

## Fase E — Osservabilità e qualità continua (P1/P2)
- [x] **E1. Telemetria UX del funnel Scan Builder**
  - Drop-off per step, errori frequenti, tempo decisionale.

- [x] **E2. KPI didattici**
  - Accuratezza quiz, riduzione false positive confermati, miglioramento time-to-remediation.

- [x] **E3. Performance budget**
  - [x] SLA runtime scansioni (`VAP_SCAN_RUNTIME_SLA_SECONDS`) con tracciamento automatico nei log scan.
  - [x] SLA rendering report (`VAP_REPORT_RENDER_SLA_SECONDS`) con warning automatico su superamento soglia.
  - [x] Copertura test unitari dedicata al motore di valutazione performance budget.

---

## 4) Backlog bug/pre-esistenti da monitorare
- [ ] Possibile overload cognitivo nelle viste principali con molte informazioni contemporanee.
- [x] Uniformato il copywriting tecnico cross-canale su termini chiave di lettura finding/stato (UI dettaglio scansione + PDF report + catalogo didattico già allineato su lessico italiano operativo), riducendo mix IT/EN non necessario (completato il 2026-04-17).
- [x] Governance esplicita “scan config lifecycle” (draft/review/approved/deprecated) introdotta su preset configurazione con transizioni controllate e approvazione admin obbligatoria per lo stato `approved` (completato il 2026-04-17).
- [x] Test regressione CSP disallineato (`tests/test_security_headers.py::test_csp_disallows_inline_scripts_by_default`): expectation allineata alla policy CSP corrente con sole sorgenti locali (`'self'`) per `script-src`/`style-src` (completato il 2026-04-18).
- [ ] Test integrazione flakey su approval high-risk (`tests/test_api_integration.py::test_create_scan_non_admin_high_risk_requires_admin_approval_reference`): il secondo POST nello stesso test può ricevere `429 Too Many Requests` per interferenza del rate limiter condiviso (rilevato nel run completo del 2026-04-12).

---

## 5) Definizione “Done” per ogni task
Un task è completato solo se:
1. implementazione funzionante end-to-end;
2. test automatici e controlli sicurezza pertinenti passati;
3. UX verificata (inclusa accessibilità base);
4. documentazione aggiornata;
5. checklist aggiornata con evidenza reale.

---

## 6) Primo task consigliato (prossimo ciclo)
**Backlog — Ridurre overload cognitivo nelle viste principali (dashboard + dettaglio scansione)**.

Motivo: rimane l'ultimo gap aperto nel backlog pre-esistente; impatta direttamente usabilità, comprensione didattica e velocità decisionale.
