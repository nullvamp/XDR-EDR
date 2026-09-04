# PostgreSQL backup and restore

## Backup

1. Confirm `/health/ready`, zero pending outbox work, and record the current schema version.
2. Record `backup.started` without secrets.
3. Run `pg_dump -Fc -Z3 -U platform -d platform -f /tmp/platform.dump` inside the existing PostgreSQL container.
4. Copy the archive to controlled backup storage, compute SHA-256 and byte length, protect it with backup-system encryption/ACLs, and record `backup.completed`.
5. Verify retention and a separate secret-recovery escrow. Database archives must not contain `.env`, runtime signing keys, CA private keys, service credentials, or object-store credentials.

The tested Sprint 28 archive is `artifacts/sprint28-dr/platform-sprint28.dump`, 408,134,262 bytes, SHA-256 `46de266feeaf686ffb65d084b979f39cda2f72b4a6ceaf7885449bfe17fbb350`. It is local qualification evidence, not the only production copy.

## Restore

1. Create a new isolated target database; never overwrite the production database during a drill.
2. Verify archive byte length and SHA-256 before invoking `pg_restore`; reject any mismatch.
3. Restore with `pg_restore --exit-on-error --no-owner --no-privileges -U platform -d <recovery_database> <archive>`.
4. Compare the schema fingerprint and every authoritative nonvolatile table count/content digest at the recorded RPO boundary.
5. Verify object inventory independently, restore externally escrowed secrets, and start a recovery-validator gateway against only the restored database.
6. Require healthy liveness/readiness, tenant isolation, and historical audit continuity before an approved cutover.

Production point-in-time recovery additionally requires PostgreSQL base backups plus continuous WAL archiving to independent protected storage. That cluster/backup service is an external deployment dependency and was not available for local qualification.

