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

- [ ] **A3. Execution Guardrails**
  - Limiti runtime centralizzati: max duration, max requests, max concurrency, retry cap.
  - Safe mode obbligatorio per tenant/studenti.
  - Kill switch e auto-abort su pattern anomali.

- [ ] **A4. Persistenza configurazioni e profili utente**
  - Salvare preset personalizzati (“Baseline didattica”, “OWASP top focus”, “WordPress deep”).
  - Versioning + checksum config per reproducibility.

## Fase B — UX didattica e configurazione guidata (P0/P1)
- [ ] **B1. Nuovo “Scan Builder” multi-step**
  - Step 1 Scope legale/target.
  - Step 2 Selezione moduli scanner.
  - Step 3 Parametri avanzati per modulo.
  - Step 4 Simulazione impatto (durata/rumore/rischio stimato).
  - Step 5 Conferma con checklist compliance.

- [ ] **B2. Didactic Mode (Beginner / Analyst / Expert)**
  - Beginner: linguaggio semplificato + preset bloccati.
  - Analyst: parametri intermedi con suggerimenti.
  - Expert: pieno controllo con warning forti.

- [ ] **B3. Explainability inline per ogni parametro**
  - Tooltip “cosa cambia”, “trade-off”, “false positive impact”.
  - Esempi pratici e anti-pattern.

- [ ] **B4. UX minimal e accessibile**
  - Riduzione densità visiva, migliori spaziature, stato focus/errore più chiari.
  - Verifica WCAG AA (contrasto, tastiera, screen reader labels).

## Fase C — Sicurezza avanzata applicativa e operativa (P0/P1)
- [ ] **C1. RBAC fine-grained sulle capability di scansione**
  - Permessi separati per: create config, run high-risk scan, export report sensibili, override policy.

- [ ] **C2. Approval workflow per scansioni ad alto rischio**
  - Double-confirmation + eventuale approvazione admin.

- [ ] **C3. Secret management hardening**
  - Nessun segreto in chiaro in form/log/report.
  - Mascheramento forte e rotazione chiavi guidata.

- [ ] **C4. Security regression suite estesa**
  - Fuzzing input config.
  - Test anti-IDOR su risorse scansione/report.
  - Test policy bypass e privilege escalation.

## Fase D — Reporting PDF/UI (P1)
- [ ] **D1. Nuovo template PDF minimal/professional**
  - Copertina pulita, sommario executive 1 pagina, severity heatmap, remediation roadmap by priority.

- [ ] **D2. Report didattico dual-layer**
  - Layer 1: executive (manageriale).
  - Layer 2: tecnico con evidenze complete e passi di validazione.

- [ ] **D3. Design tokens condivisi UI/PDF**
  - Palette, tipografia, spacing coerenti in tutta la piattaforma.

## Fase E — Osservabilità e qualità continua (P1/P2)
- [ ] **E1. Telemetria UX del funnel Scan Builder**
  - Drop-off per step, errori frequenti, tempo decisionale.

- [ ] **E2. KPI didattici**
  - Accuratezza quiz, riduzione false positive confermati, miglioramento time-to-remediation.

- [ ] **E3. Performance budget**
  - SLA runtime scansioni e rendering report.

---

## 4) Backlog bug/pre-esistenti da monitorare
- [ ] Possibile overload cognitivo nelle viste principali con molte informazioni contemporanee.
- [ ] Necessità di uniformare ulteriormente copywriting tecnico tra UI, catalogo e PDF.
- [ ] Mancanza di una governance esplicita “scan config lifecycle” (draft/review/approved/deprecated).

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
**A2 — Validation & Policy Engine**.

Motivo: ora che lo schema configurazione v1 è disponibile e validato fail-closed, serve applicare regole server-side di compatibilità e policy di autorizzazione per impedire combinazioni rischiose.
