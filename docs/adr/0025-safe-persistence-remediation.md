# ADR 0025: Safe Windows persistence remediation

Status: Accepted for Sprint 21 under Outcome B-Windows.

## Decision

Persistence remediation uses only predefined, versioned signed actions. The control plane resolves an authoritative tenant-scoped service, task, registry/persistence, or WMI entity and binds endpoint, installation, canonical native identity, lifecycle generation, expected state hash, evidence, policy, analyst, expiry, nonce, and approval hash. Names and paths alone cannot authorize mutation.

The elevated Windows executor re-reads native state, rejects replacements, protects critical/platform configuration, creates a bounded pre-mutation backup, mutates one exact object, verifies post-state, and records every stage. Restore is explicit and permitted only from a DPAPI LocalMachine-encrypted, ACL-restricted, SHA-256-verified, endpoint/installation/action-bound backup. Destination collisions fail closed. WMI removal and restore preserve dependency order and reject shared filters or consumers.

No generic shell wrapper, automatic remediation, broad cleanup, recursive deletion, driver removal, SOAR, or detection-triggered action is introduced. Historical telemetry and investigation evidence remain immutable.

## Qualification boundary

Native mutations ran only in the existing XDR-Victim-Sprint18 Hyper-V guest. Native Linux remains an ENVIRONMENT BLOCKER; macOS and hosted CI remain EXTERNAL BLOCKERs.
