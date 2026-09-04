# Troubleshooting

- Gateway not ready: inspect each dependency reported by `/health/ready`; validate DNS, credentials, TLS trust and schema 0034. Do not bypass readiness.
- Agent not enrolling: validate endpoint DNS/routing to 8443, CA trust, one-time token expiry/use/platform, protected config ACL, and service log. Never paste token secrets into tickets.
- Agent enrolled but stale: verify service, mTLS credential expiry, clock, policy retrieval and queue age. Preserve `state.dat`; deleting it creates a new installation identity.
- Projection mismatch: stop controlled writers, drain NATS/outbox, run the bounded projection repair/reconciliation workflow, and retain before/after counts. PostgreSQL is authoritative.
- Update failed: preserve update journal, verify signature/hash/version/architecture/maintenance authorization, pause rollout, and follow rollback compatibility—never substitute an unsigned package.
- Transfer stalled: inspect session/transfer expiry, chunk acknowledgement cursor, object-store readiness, isolation-safe allowlist and available disk; resume the same transfer rather than restarting from zero.
- Installer failure: retain verbose MSI log. Exit 1603 on uninstall without `MAINTENANCEAUTHORIZED=1` is expected. Validate `SHA256SUMS` and production signature before install.

User-facing API errors intentionally omit stack/DB/filesystem details and include `X-Request-ID`; use that ID to correlate protected server logs.
