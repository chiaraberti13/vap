# Upgrade Baseline — Inventario Feature Correnti (Must Keep)

Questo documento fotografa lo stato attuale della piattaforma VAP prima dell'upgrade didattico.

## Matrice feature "must keep"

| Area | Feature attuale | Stato baseline | Motivazione di preservazione |
| --- | --- | --- | --- |
| Backend API/Web | Applicazione FastAPI con endpoint web + API REST | ✅ Presente | Costituisce il piano di controllo unico per UI e integrazioni esterne |
| Scanner orchestration | Orchestrazione multi-tool e validazione target tramite `scanner_engine.py` | ✅ Presente | Core funzionale del prodotto; non deve subire regressioni |
| Profili scansione | Profili `full`, `light`, `wordpress` + selezione single-tool | ✅ Presente | Differenziazione d'uso per principianti e utenti esperti |
| Sicurezza applicativa | CSRF, API key/JWT, header security policy, rate limiting, audit logging | ✅ Presente | Guardrail essenziali per uso professionale e compliance |
| Persistenza dati | SQLAlchemy + SQLite per scansioni/findings/audit | ✅ Presente | Storico e tracciabilità necessari a reporting e analisi postuma |
| Realtime UX | Progress scansione via websocket | ✅ Presente | Trasparenza operativa durante run lunghi |
| Reporting | Export PDF e storico scansioni | ✅ Presente | Output professionale condivisibile verso stakeholder |
| Dashboard | KPI principali e lista scansioni | ✅ Presente | Supervisione operativa immediata |
| Async processing | Celery/Redis opzionale per code scansioni | ✅ Presente | Scalabilità operativa in ambienti multi-job |
| Quality gate base | Test suite Python in `tests/` | ✅ Presente | Punto di partenza per prevenire regressioni nell'upgrade |

## Scope di baseline

- Questo inventario copre i comportamenti correnti da mantenere invariati durante le fasi di redesign didattico.
- Le nuove funzionalità (catalogo didattico, UX guidata, learning layer) dovranno essere additive rispetto a questa baseline.

## Criterio di accettazione della baseline

Una modifica proposta in fase di upgrade è accettabile solo se non degrada nessuna feature marcata "must keep" nella matrice sopra.
