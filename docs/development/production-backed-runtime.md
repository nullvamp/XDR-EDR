# Production-backed local runtime

## Process telemetry operations

Run `testing/integration/process-telemetry.ps1` after the stack and enrolled Linux agent are healthy. It generates a controlled process, verifies PostgreSQL events/entities/outbox, searches through the authenticated API, checks details/tree/health, and proves restart idempotency. Queue files below the protected agent data directory must remain `0600`; do not remove them to clear an incident. Projection recovery uses `POST /api/v1/processes/projections:rebuild` and switches the alias only after a count check. Alert on queue depth/age, drops, gaps, rejects, projection lag, and collector inactivity.

Sprint 1 has two explicit modes. `development` uses durable local files. `production` uses PostgreSQL, NATS JetStream, private MinIO storage, and an OpenSearch projection and never falls back to files.

Copy `.env.example` to `.env`, replace every placeholder, then run:

```powershell
.\scripts\docker.ps1 start
.\scripts\docker.ps1 status
.\scripts\docker.ps1 logs
Invoke-WebRequest http://localhost:8080/health/ready
```

New volumes apply all three versioned Sprint migrations in order. Use `.\scripts\docker.ps1 migrate`, `.\scripts\docker.ps1 rollback`, or the destructive `.\scripts\docker.ps1 reset` as required.

Authenticate and create a bounded token; its secret appears only in this response:

```powershell
$login=Invoke-RestMethod http://localhost:8080/api/v1/auth/token -Method Post -ContentType application/json -Body (@{username='admin';password=$env:PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json)
$headers=@{Authorization="Bearer $($login.access_token)"}
$token=Invoke-RestMethod http://localhost:8080/api/v1/enrollment-tokens -Method Post -Headers $headers -ContentType application/json -Body (@{expiresAt=(Get-Date).ToUniversalTime().AddHours(4).ToString('o');maximumUses=1;allowedPlatforms=@('windows','linux','macos');endpointGroupId=$null;policyId=$null}|ConvertTo-Json)
```

Set the agent token ID/secret from `$token.data`, start the agent, query `/api/v1/endpoints`, and open `http://localhost:8080/#/endpoints`.

PostgreSQL is authoritative. Timestamped `platform-endpoints-v*` indexes behind the atomic `platform-endpoints` alias are rebuilt with `POST /api/v1/endpoints/projections:rebuild`. MinIO keys are generated as `tenants/{tenant-uuid}/objects/{object-uuid}` in private bucket `platform-objects`. Outbox events are leased, delivered at least once, bounded-retried, and poison-marked after ten attempts.

If readiness is 503, inspect the reported dependency and logs. PostgreSQL, NATS, OpenSearch, and MinIO are mandatory. Enrollment remains committed if NATS/OpenSearch fail after its transaction; delivery resumes from the outbox.

```powershell
powershell -ExecutionPolicy Bypass -File testing/integration/run.ps1
powershell -ExecutionPolicy Bypass -File testing/integration/certificate-lifecycle.ps1
powershell -ExecutionPolicy Bypass -File testing/integration/nats-acceptance.ps1
powershell -ExecutionPolicy Bypass -File testing/integration/failure-recovery.ps1
powershell -ExecutionPolicy Bypass -File testing/performance/run.ps1 -Iterations 30
```

Projection rebuild progress is available to administrators at `GET /api/v1/endpoints/projections:rebuild` while the corresponding `POST` is running and after completion. It reports the versioned index, total and completed documents, start/update timestamps, running state, and a safe failure type.

The 2 August 2026 local 30-sample baseline measured readiness mean/p95 at 3.27/4.63 ms and endpoint search mean/p95 at 5.13/6.88 ms. Latest enrollment and heartbeat server times were 86.2694 ms and 8.4693 ms; heartbeat receive clock delta averaged 37.14 ms; outbox-to-published projection latency averaged 2235.98 ms with queue depth zero. Snapshot resource use was gateway 3.05% CPU/100.7 MiB, agent 0.01%/60.8 MiB, PostgreSQL 2.09%/59.32 MiB, and OpenSearch 0.71%/1.011 GiB. NATS reported 169 messages and 112085 bytes. These are local measured values, not capacity guarantees.
