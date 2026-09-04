# Retention and storage lifecycle operations

1. Review `/api/v1/retention/policies`, holds, storage usage, cleanup history, and archive jobs.
2. Create a new immutable policy version; never edit history. Authority retention must be at least projection retention.
3. Create and review a preview. Confirm tenant, category, cutoff, eligible rows/bytes, held rows, policy version, preview hash, and expiry.
4. Run dry-run with that exact preview hash. Re-preview if the policy, scope, holds, references, or expiry changes.
5. Execute only a supported bounded scope. Production arbitrary-table deletion is deliberately rejected; Sprint 29 destructive qualification is limited to `qualification-fixture`.
6. Verify the retention run, archive manifest/hash, cleanup audit, held objects, authoritative counts, projections, and queue/outbox/NATS drain.

Never remove evidence with an active incident, forensic, quarantine, legal/administrative, replay/backmatch, export, or investigation hold. OpenSearch age-out means “not in the current search projection,” not “authority deleted.” Rebuild or authority search must remain explicit.

Temporary cleanup is bounded and idempotent. Qualification deletes only an unheld hash-verified temporary MinIO object and preserves the held peer. Do not use filesystem wildcards or MinIO bucket-wide deletion. Investigate cleanup failures and inventory mismatches before retrying.

Reproduce the isolated lifecycle proof with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File testing/integration/sprint29-lifecycle.ps1
```
