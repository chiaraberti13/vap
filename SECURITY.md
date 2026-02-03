# Security Policy

## Supported Versions

We support security fixes for the latest minor release on the main branch.

## Reporting a Vulnerability

Please report security issues privately.

1. Email: security@example.com
2. Include: affected version, reproduction steps, impact, and any suggested fixes.
3. We will acknowledge within 72 hours and provide a remediation timeline.

## Security Hardening Checklist

- Enforce HTTPS (VAP_REQUIRE_HTTPS=true) and configure TLS certs.
- Set strong JWT and CSRF secrets in environment variables.
- Enable audit logging and log aggregation.
- Restrict CORS origins to trusted domains.
- Rotate API keys and credentials regularly.
