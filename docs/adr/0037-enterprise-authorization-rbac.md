# ADR 0037: Enterprise authorization and RBAC

Status: Accepted (Sprint 33)

## Decision

Use tenant-scoped immutable principal IDs, versioned roles, explicit role assignments, and exact server-side permissions. Human users, service accounts, API clients, and system principals are distinct types. Display names are never authoritative. Request authorization resolves current durable state; disablement, revocation, expiry, assignment expiry, and credential rotation invalidate later requests.

Unknown permissions fail closed. Custom roles reject unknown values plus `agent:*`, `system:admin`, `platform:admin`, `service:register`, and credential-authentication internals. Tenant Administrator excludes the same internal boundaries. The deployment bootstrap is a visible stable SystemPrincipal, not a hidden user. A break-glass workflow is deferred until a real external identity provider and strong activation ceremony exist.

Endpoint/group-scoped assignments are checked against tenant-owned endpoint and fleet-group authority. Sensitive actions retain requester/approver separation. UI visibility is never an authorization control.

## Consequences

- Built-in definition changes create a new active version and deactivate stale versions; stale assignments fail closed.
- Service/API identities require purpose, expiry, rotation, revocation, and one-time credentials.
- Platform/agent internal permissions cannot be delegated through tenant role editing.
- Existing routes are inventoried at runtime; any unclassified sensitive route fails release.

