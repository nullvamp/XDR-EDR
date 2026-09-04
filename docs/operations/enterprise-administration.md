# Enterprise administration guide

Use **Administration & Governance** for health, principals/access, policy/configuration, API clients, and audit. Operations are tenant-bound and server-authorized.

## Safe procedure

1. Create a named principal with type, purpose, and applicable expiry.
2. Assign the narrowest built-in or allowlisted custom role; use endpoint/group scope or bounded temporary access.
3. Review effective permissions and their role/scope/expiry sources.
4. Preview setting changes, verify affected endpoints/security impact, and submit the exact confirmation hash. Use a separate approver for high-risk settings.
5. Watch `Pending`, `Stale`, `Drifted`, and `Unknown`; endpoint online state alone does not prove policy health.
6. Roll back by creating a new immutable version from the approved prior value.
7. Create credentials only for narrow non-human principals. Capture a secret once, rotate before expiry, and revoke when unused.
8. Search audit with bounded filters. Exports are limited to 90 days/1,000 rows and contain a tenant-bound manifest, SHA-256, row count, requester, and timestamp.

## Delegated boundaries

SOC delegation does not grant CA/signing, platform-global floors, tenant deletion, internal service registration, agent identity, credential-auth internals, or critical service credentials. Incident responders cannot self-approve high-risk response. DFIR collection and detection activation retain existing approval boundaries.

The deployment bootstrap principal supports recovery and initial administration. Rotate deployment secrets externally and migrate operators to named principals when a real identity provider exists. No SAML/OIDC/MFA certification or break-glass ceremony is claimed.

## Backup/recovery

The full PostgreSQL backup used by Sprint 28 contains all Sprint 33 state and audit tables. API secrets are never stored; only salted password hashes and metadata are backed up. Restore via the existing DR guide, recover deployment secrets using the protected environment mechanism, start two gateways, and compare configuration/effective policy before reopening administration.

