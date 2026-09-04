# Upgrade and rollback

Supported v1 path: 0.9.0 to 1.0.0. Take and verify an authoritative backup first. Validate package version, platform/architecture binding, manifest hash, content hash, signer chain, expiry/revocation, and rollout assignment. Use canary/ring rollout with maintenance authorization, telemetry/heartbeat/response/self-protection health gates, and pause on unexplained failure.

The endpoint updater accepts only CA-signed bounded platform bundles bound to the exact tenant, endpoint, installation, assignment, OS, architecture, current version, and maintenance capability. It does not execute an arbitrary installer, URL, or shell command. Production Authenticode signing of the MSI/PE files remains a separate prerequisite.

Approved rollback is 1.0.0 to 0.9.0 only with a signed rollback bundle whose `rollbackCompatible` and `rollbackFromVersion` bindings match. Normal monotonic version enforcement remains active. Restore the database only when the compatibility matrix specifically requires it; schema 0034 remains the v1 schema.

On interrupted download, corrupt/modified package, restart loss, or failed post-install health, preserve the durable journal, report Failed or RolledBack truthfully, restore the verified backup payload, keep telemetry independent, and pause the rollout. Never bypass signature/hash verification to recover.
