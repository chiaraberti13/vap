# Upgrade Plan — VAP (Vulnerability Assessment Platform)

## 1) Panoramica progetto

Questa repository contiene una web app **FastAPI + Jinja + Tailwind CSS** per vulnerability assessment con orchestrazione multi-scanner, dashboard web, API REST, reporting PDF e componente didattica guidata nella scelta/interpretazione delle scansioni.

**Obiettivo finale prodotto**

- Mantenere VAP come piattaforma professionale di scansione.
- Rafforzare l’esperienza didattica “guided” senza degradare il core operativo.
- Migliorare robustezza architetturale, UX (soprattutto homepage/form guided), sicurezza applicativa e governabilità CI/CD.

**Stack tecnologico rilevato (attuale)**

- Backend: `FastAPI`, `SQLAlchemy`, middleware sicurezza custom, rate limiting.
- Engine dominio: orchestrazione scanner in `scanner_engine.py` + moduli scanner dedicati.
- Frontend: `Jinja templates` + `Tailwind CDN` + JS vanilla (`static/js`).
- Persistenza: SQLite (con supporto runtime asincrono via Celery/Redis opzionale).
- Qualità: suite `pytest` con coverage gate, test sicurezza/accessibilità/layout e workflow CI.

**Ruolo del layout nel prodotto finale**

- La homepage (`templates/index.html`) è il principale punto di conversione e onboarding.
- Il layout deve restare leggibile, guidato e mobile-first, preservando il flusso “obiettivo → scelta scan → consensi → esecuzione”.

---

## 2) Stato attuale (analisi reale repository)

### ✅ Già implementato

- Motore scansioni multi-tool con profili (`full`, `light`, `wordpress`) e mapping scanner esteso.
- Catalogo didattico scansioni (`scan_catalog.py`) integrato in UI/API.
- Guided Scan Type Explorer con stepper UX e microcopy contestuale.
- Hardening sicurezza significativo (CSP, CSRF, JWT/API key, rate limit, audit trail, RBAC, allowlist opzionale target).
- Sezione dettaglio scansione con learning blocks, confidence rubric e roadmap remediation.
- Pipeline qualità con test automatici + coverage gate + Lighthouse CI.
- Documentazione estesa (architettura, hardening, playbook, learning paths, go-live).

### ⚠️ Parziale / da completare

- Tailwind in CDN ancora presente: hardening/controllo supply-chain migliorabile con build locale.
- Dependency hygiene con policy trimestrale formalizzata; mantenere monitoraggio warning/deprecazioni transitive.
- Osservabilità runtime centralizzata (metriche/alerting esterno) non completamente product-grade.

### ❌ Mancante (o non chiuso in modo definitivo)

- Migrazione completa a design system frontend self-hosted (CSS pipeline locale e policy CSP ancora più stringente).
- Gate CI security avanzato DAST autenticato in pre-release ancora da integrare stabilmente.

### 🐞 Debito tecnico pre-esistente monitorato

- Warnings/deprecazioni da dipendenze terze parti da monitorare con policy di upgrade.

### Focus UX layout home (stato reale)

**Già buono e da preservare**

- Hero + CTA primaria chiara.
- Stepper guided visibile e comprensibile.
- Hint contestuali su campi critici e fallback no-JS.

**Da rifinire ulteriormente**

- Ridurre dipendenza da utility class CDN per stabilità grafica long-term.
- Consolidare token design in un layer CSS più sistematico.
- Eseguire audit periodico su regressioni visuali cross-device.

---

## 3) Macro-aree di sviluppo

1. Setup / Configurazione
2. Core Scanning Engine
3. Backend API & Sicurezza
4. Frontend Guided UX
5. Layout / Design System
6. Learning Layer & Contenuti didattici
7. Scan Detail Explainability
8. Reporting e Remediation
9. Data & Persistenza
10. Governance sicurezza applicativa
11. Testing & CI/CD
12. Performance & Osservabilità
13. Documentazione prodotto
14. Rilascio e Operatività

---

## 4) Checklist operativa (CORE)

### A. Fondazioni prodotto

[x] Definire baseline funzionale da preservare  
Descrizione: Mappare capacità core scanner/API/report che non devono regredire.  
Done quando: Documento baseline presente e usato come riferimento regressivo.

[x] Definire direzione “professional + educational”  
Descrizione: Formalizzare obiettivi UX/didattici senza perdere affidabilità operativa.  
Done quando: Upgrade plan e documentazione learning risultano coerenti.

[x] Definire quality gate minimi  
Descrizione: Stabilire soglie test, coverage e controlli automatici.  
Done quando: CI blocca merge su regressioni.

[x] Formalizzare policy plugin scanner versionata  
Descrizione: Definire contratto ufficiale per aggiunta scanner dinamici e compatibilità.  
Done quando: Esiste specifica plugin + test contract. ✅ Completato con contratto `ScannerPluginSpec` versionato (`1.0.0`), funzione `register_scanner_plugin` fail-closed, test runtime e documento dedicato.

### B. Setup / Configurazione

[x] Configurare ambiente locale riproducibile  
Descrizione: Installer/documentazione per avvio coerente su Linux/macOS/Windows.  
Done quando: Setup documentato e verificabile.

[x] Configurare pipeline CI principale  
Descrizione: Esecuzione test suite + quality checks ad ogni push/PR.  
Done quando: Workflow `.github/workflows/ci-quality-gates.yml` operativo.

[x] Integrare security scanner CI aggiuntivi (Bandit/Pip-audit)  
Descrizione: Automatizzare controllo vulnerabilità dipendenze/codice Python.  
Done quando: Pipeline fallisce su finding critici.

### C. Core scanning engine

[x] Consolidare mappa scanner e profili principali  
Descrizione: Supportare full/light/wordpress + tool dedicati senza rotture.  
Done quando: Test engine e test scanner passano stabilmente.

[x] Validazione target e guardrail input  
Descrizione: Prevenire input malformati/abuso su endpoint scan.  
Done quando: Validazione coperta da test sicurezza.

[x] Ridurre rischio drift enum scan type  
Descrizione: Allineare dinamicamente choices e mappa scanner in modo robusto.  
Done quando: Nessuna divergenza possibile tra runtime map e API/form choices.

### D. Backend API & Sicurezza

[x] Fornire endpoint catalogo scansioni didattico  
Descrizione: Esposizione read-only metadati per UI guided explorer.  
Done quando: Endpoint pubblico autenticato disponibile e testato.

[x] Applicare hardening security headers  
Descrizione: CSP + policy browser restrittive + protezioni anti-mixed content.  
Done quando: Test header sicurezza passanti.

[x] Applicare RBAC + audit logging  
Descrizione: Tracciare azioni sensibili e limitare accesso per ruolo.  
Done quando: Controlli accesso e audit coperti da test.

[ ] Migliorare osservabilità API production-grade  
Descrizione: Aggiungere metriche strutturate e alerting centralizzato (non solo log locali).  
Done quando: Dashboard/alert esterni documentati e attivi.

### E. Frontend guided UX

[x] Implementare Scan Type Explorer a card  
Descrizione: Sostituire select piatta con scelta guidata contestuale.  
Done quando: Selezione scan comprensibile pre-submit.

[x] Implementare stepper UX con consenso esplicito  
Descrizione: Flusso guidato in step con validazioni e fallback no-JS.  
Done quando: Journey completo testato end-to-end.

[x] Migliorare accessibilità keyboard/ARIA  
Descrizione: Focus states, skip-link, navigazione tastiera e messaggi di errore accessibili.  
Done quando: Suite a11y automatica senza blocker.

[ ] Completare visual regression cross-breakpoint  
Descrizione: Rafforzare controllo regressioni layout su viewport chiave mobile/tablet/desktop.  
Done quando: Baseline visuali multi-breakpoint in CI.

### F. Layout / Design system

[x] Ripristinare gerarchia visiva homepage  
Descrizione: Hero, CTA, form e progressione guidata con priorità chiare.  
Done quando: Layout coerente e leggibile sopra la fold.

[x] Uniformare microcopy e feedback UI critici  
Descrizione: Hint su target/scan type, rischio/invasività esplicitati prima del run.  
Done quando: Riduzione ambiguità utente nel primo flusso.

[ ] Migrare da Tailwind CDN a pipeline locale  
Descrizione: Build CSS self-hosted per sicurezza, performance e controllo versioning.  
Done quando: Nessuna dipendenza runtime da CDN CSS/JS per UI core.

### G. Learning layer e contenuti didattici

[x] Introdurre metadati didattici per scan type  
Descrizione: Obiettivi, limiti, contesto uso/non-uso, interpretazione.  
Done quando: Copertura 100% scan type supportati.

[x] Aggiungere learning blocks nel dettaglio finding  
Descrizione: Spiegazioni junior, rischio business, verifica manuale e next step.  
Done quando: Sezione scan detail didatticamente completa.

[x] Pubblicare learning paths e playbook  
Descrizione: Percorsi beginner/analyst/pro + schede operative scanner.  
Done quando: Documentazione navigabile e coerente con UI.

### H. Reporting e remediation

[x] Introdurre remediation roadmap prioritaria  
Descrizione: Ordinamento interventi per impatto/effort/prerequisiti.  
Done quando: Roadmap visibile in scan detail e testata.

[x] Preservare pipeline reporting PDF  
Descrizione: Garantire export stabile e audit su download report.  
Done quando: Test regressione report passanti.

[x] Aggiungere confronto temporale report (trend)  
Descrizione: Evolvere report da snapshot a visione progressiva per target.  
Done quando: Disponibile timeline comparativa findings nel tempo. ✅ Completato con sezione trend in `scan_detail` (delta vs baseline precedente, KPI severità e timeline ultime scansioni target) + test di regressione.

### I. Data & Persistenza

[x] Persistenza scansioni/findings/audit su DB  
Descrizione: Memorizzare storico e metadati di esecuzione.  
Done quando: Flusso creazione-salvataggio-recupero verificato.

[x] Persistenza learning feedback/progress  
Descrizione: Salvare feedback educativo e stato apprendimento base.  
Done quando: Endpoint e storage attivi con test.

[x] Introdurre migrazioni DB formalizzate  
Descrizione: Passare da schema evolutivo implicito a workflow migration (es. Alembic).  
Done quando: Versionamento schema DB documentato e automatizzato. ✅ Completato con bootstrap Alembic (`alembic.ini`, `db_migrations/env.py`, revisione iniziale `20260406_0001`) integrato in `init_db()` + test dedicato su tabella `alembic_version`.

### J. Sicurezza applicativa

[x] Validazione input e fail-closed  
Descrizione: Normalizzazione payload e rifiuto input pericolosi.  
Done quando: Nessuna eccezione incontrollata su input malformati.

[x] Hardening CSP/XSS frontend  
Descrizione: Riduzione inline script/style e sanitizzazione rendering dinamico.  
Done quando: Test hardening template/JS passanti.

[x] Security checklist startup produzione  
Descrizione: Warning/config guardrail per ambienti reali.  
Done quando: Startup segnala configurazioni insicure.

[x] Piano aggiornamento dipendenze sicurezza  
Descrizione: Definire ciclo trimestrale patch + test compatibilità.  
Done quando: Documento policy + job automatico di verifica. ✅ Completato con workflow schedulato trimestrale e policy dedicata in docs.

### K. Testing e quality gates

[x] Suite pytest completa con coverage gate >=80%  
Descrizione: Test unit/integration/security/layout accessibilità con soglia minima coverage.  
Done quando: Esecuzione locale/CI stabile.

[x] Regressioni dedicate su journey guided  
Descrizione: Test endpoint/UI sul flusso di creazione scansione guidata.  
Done quando: Journey end-to-end protetto da test.

[x] Lighthouse CI con soglie bloccanti  
Descrizione: Gate performance/accessibilità/best-practice/SEO.  
Done quando: Pipeline interrompe regressioni sotto soglia.

[ ] Integrare DAST autenticato in pre-release  
Descrizione: Eseguire scansioni dinamiche su ambiente staging autenticato.  
Done quando: Report DAST incluso nei gate release.

### L. Performance e osservabilità

[x] Definire e monitorare budget qualità frontend in CI  
Descrizione: Imporre soglie misurabili tramite Lighthouse assertions.  
Done quando: Build bloccata su regressione.

[x] Preservare reattività dashboard e journey base  
Descrizione: Evitare frizioni durante creazione/monitor scansione.  
Done quando: Nessun blocker UX nei test principali.

[ ] Estendere telemetria runtime applicativa  
Descrizione: Esportare metriche a backend monitoraggio centralizzato.  
Done quando: Alert su error spike/latency attivi.

### M. Milestone esecutive

[x] Milestone 1 — Stabilizzazione baseline e hardening iniziale  
Descrizione: Preservare funzionalità core e rimuovere regressioni critiche.

[x] Milestone 2 — Guided UX + learning catalog  
Descrizione: Portare la home da selezione piatta a percorso didattico guidato.

[x] Milestone 3 — Scan detail didattico + remediation roadmap  
Descrizione: Rendere il post-scan più formativo e operativo.

[ ] Milestone 4 — Industrializzazione finale  
Descrizione: Chiudere gap residui su plugin contract, CSS self-hosted, security scanning CI avanzato, osservabilità centralizzata.

---

## 5) Priorità operative raccomandate (prossimo ciclo)

1. **Migrazione Tailwind da CDN a build locale** (impatto: sicurezza, performance, governance layout).
2. **Plugin contract scanner + allineamento scan-type runtime** (impatto: stabilità architetturale).
3. **Security CI avanzata (Bandit + Pip-audit + DAST staging)** (impatto: hardening continuo).
4. **Osservabilità centralizzata e alerting** (impatto: affidabilità operativa in produzione).
