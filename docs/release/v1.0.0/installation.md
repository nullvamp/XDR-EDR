# Windows-first v1 installation

## Prerequisites

- Windows 10/11 or Windows Server x64 with Administrator access for the endpoint agent.
- A production PostgreSQL 16 service, NATS JetStream 2.10 service, S3-compatible object store, and OpenSearch 2.19-compatible service.
- DNS/routing from endpoints to the gateway; TCP 8443 with a server certificate trusted by the endpoint.
- Unique generated database/object-store credentials, a JWT signing key, enrollment pepper, offline-protected CA key, and gateway certificate. Do not use `.env` values from a development workstation.

## Platform

Apply migrations `0001` through `0034` in lexical order with `ON_ERROR_STOP`, one fenced migration owner, and a verified backup before upgrades. Deploy the gateway image by its release digest. Expose the browser/API only through an approved TLS reverse proxy; port 8080 is an internal HTTP listener. Port 8443 is the mTLS endpoint channel. Configure PostgreSQL, NATS, object storage, OpenSearch, certificates, and required secrets through deployment configuration—not source edits. Readiness is `GET /health/ready`; all dependencies must report healthy.

`deployment/docker-compose.yml` is a single-host development/qualification topology. It disables OpenSearch security and exposes local ports, so it is not the production architecture.

## Agent

1. Create a one-use Windows enrollment token in Administration.
2. Put the CA certificate and a protected `agent-config.json` in `C:\ProgramData\OpenSecurityPlatform\Agent`. Start from `release/windows/agent-config.example.json`; supply `controlPlaneUrl`, token ID/secret, CA path, and data directory.
3. Restrict the directory to SYSTEM and Administrators. Never put the token in an MSI command line or transform.
4. Run `msiexec /i OpenSecurityPlatform-Agent-1.0.0-x64.msi /qn /norestart /l*v install.log` from an elevated maintenance workflow.
5. Verify service `OpenSecurityPlatformAgent` is Automatic/Running as LocalSystem, the executable version begins `1.0.0`, `state.dat` exists, and the one-time secret has been removed from configuration.
6. Verify the endpoint is online in Fleet with version 1.0.0, a recent heartbeat, telemetry, effective policy, self-protection health, response channel, and update readiness.

The MSI and manifest SHA-256 must match `SHA256SUMS`. Production Authenticode signatures are a release prerequisite and are not supplied by the engineering qualification build.
