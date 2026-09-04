# ADR 0024: Safe Windows file response

Status: Accepted for Sprint 20 under Outcome B-Windows.

## Decision

File quarantine and permanent deletion are predefined signed response actions, never generic shell commands. Every destructive request is resolved from authoritative tenant-scoped file telemetry and binds endpoint, installation, canonical file entity, Windows volume/file identity, canonical path, size, optional SHA-256, expiry, nonce, analyst and policy version. Path-only requests are structurally impossible.

The Windows agent opens the exact file with documented handle APIs, rejects reparse points and multi-link substitutions, compares native identity before acquisition, hashes bytes read through the validated handle, encrypts the verified copy with machine-bound DPAPI in an ACL-restricted non-user-writable store, and removes the source only after copy-hash verification. Identity or content changes fail closed. A verified copy is retained when source removal is incomplete.

Restore is explicit, integrity-verified, staged to a temporary destination and atomically placed without overwriting an occupied path. Permanent deletion is separately approved and accurately described as normal filesystem deletion, not secure erase. Windows, platform-agent, control-channel and quarantine-store paths are hard protected.

Storage is bounded to 8 MiB per file, 64 MiB and 64 records per endpoint store, with seven-day retention and restart discovery. Quarantine is reversible by default. Detection-driven, recursive, mass, kernel-forced and arbitrary shell remediation remain prohibited.

## Qualification boundary

Native destructive tests execute only in the existing `XDR-Victim-Sprint18` Hyper-V guest. The host is not a response target. Native Linux qualification remains an ENVIRONMENT BLOCKER; macOS and hosted CI remain EXTERNAL BLOCKERs.
