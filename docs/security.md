# Security Best Practices

## Autenticazione & autorizzazione

- **API key** per accesso alle API REST.
- **JWT** per sessioni temporanee (token bearer).
- **Rate limiting** attivo su endpoint sensibili.

## HTTPS

- Abilita `VAP_REQUIRE_HTTPS=true` in produzione.
- Configura certificati TLS (vedi `config.py`).

## OWASP Top 10 (mitigazioni)

- **Injection**: validazione input (Pydantic) e query parametrizzate.
- **Broken Auth**: JWT con secret e scadenza breve.
- **Sensitive Data Exposure**: HTTPS + HSTS.
- **Security Misconfiguration**: header di sicurezza e CSP.
- **Logging & Monitoring**: audit log e metriche.

## Hardening consigliato

- Ruota le API key periodicamente.
- Usa DB esterno con backup e cifratura.
- Segregazione dei secret (Vault, Secrets Manager).
- Esegui i tool esterni in ambienti isolati.

## Riferimenti ufficiali

- OWASP Top 10: https://owasp.org/Top10/
- JWT: https://jwt.io/introduction
- FastAPI Security: https://fastapi.tiangolo.com/tutorial/security/
