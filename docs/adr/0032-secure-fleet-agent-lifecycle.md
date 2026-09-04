# ADR 0032: Secure fleet and agent lifecycle

Status: Accepted for Sprint 27

Fleet identity is `(tenant_id, endpoint_id, agent_installation_id)`; hostname is presentation data. Tenant-scoped metadata, deterministic bounded groups/tags, immutable deployment-ring versions, update policies, packages, rollouts, assignments and audit are PostgreSQL authoritative.

An update package is a controlled-storage object plus immutable `agent-update-manifest.v1`. The CA signature binds package/manifest SHA-256, package identity, version, platform, architecture, type, exact size, expiry and object identity. The endpoint revalidates the trusted chain, signature, manifest, downloaded bytes, current/target version and active installation. Only `platform-bundle-v1` and explicit `platform-rollback-bundle-v1` are registered. Bundles contain bounded relative paths and exact file hashes; no command line, URL, executable argument or script field exists.

Rollouts use ordered rings, per-ring and policy concurrency, delay/healthy-duration fields, sample-aware success/failure thresholds, explicit start/advance/pause/resume/cancel and exact durable endpoint assignments. `Succeeded` is accepted only when service, version, installation identity, mTLS, telemetry, policy, queues, self-protection, response and local integrity all pass. Offline assignments survive until expiry and are revalidated after reconnect. Rollback requires a separately signed compatible from/to manifest.

Sprint 26 maintenance authorization with exact `upgrade` scope remains a prerequisite at the endpoint. The managed bundle executor stages under platform data, journals every phase atomically, backs up replaced files, preserves installation ID, restores on install/health failure and never blocks telemetry while waiting or retrying.

Native Linux qualification remains an ENVIRONMENT BLOCKER. macOS and hosted CI remain EXTERNAL BLOCKERs.
