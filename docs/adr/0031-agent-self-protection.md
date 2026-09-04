# ADR 0031: Supported agent self-protection

Status: Accepted for Sprint 26

## Decision

Windows self-protection uses documented user-mode controls: CA-signed, tenant/endpoint/installation-bound monotonic policies; bounded SHA-256 plus native file identity and ACL checks; SCM queries and narrowly registered service-startup repair; certificate/installation binding inherited from mTLS enrollment; bounded local-state parsing; and inspection of platform-owned firewall rules. PostgreSQL stores immutable policies, snapshots, tamper events, maintenance authorizations, repair requests, and audit evidence. Required-resource completeness and independently derived state prevent a report from falsely claiming `Protected`.

Maintenance is a separate signed authorization, not a policy disable switch. It binds exact installation, requester, different approver, capability set, reason, start and expiry. The agent relaxes only resources covered by that capability and resumes ordinary verification after expiry. Safe repair is allowlisted; executable replacement is never repaired from an unverified local source.

Tamper outcomes explicitly distinguish `Prevented`, `DetectedOnly`, `NotObservable`, `NotPreventableAtPrivilegeBoundary`, and `AuthorizedMaintenance`. Existing Sprint 19 structured response protections continue to reject agent/worker termination and suspension. An arbitrary Administrator or kernel actor is not claimed preventable. No driver, undocumented hook, stealth, retaliation, or hidden persistence is introduced.

## Durable queue consequence

An authenticated server rejection is terminal for that exact queue record. Such poison records move to the existing evidence-preserving quarantine with reason `server-rejected`; accepted and duplicate records are acknowledged normally. This prevents permanent queue starvation while retaining rejected bytes and reason evidence.

## Deferred driver track

Stronger protection from arbitrary privileged handle operations, kernel termination, offline disk mutation, and kernel-originated identity theft requires a separately designed, signed, supported driver track with Windows security review and is outside Sprint 26.
