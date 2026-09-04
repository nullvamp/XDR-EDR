# ADR 0014: Windows identity telemetry

Status: accepted for Sprint 10 Outcome B-Windows.

## Decision

Windows identity evidence uses documented Security Event Log and Terminal Services LocalSessionManager records plus bounded read-only process-token snapshots. The canonical contract preserves exact provider/channel/event identifiers, raw-evidence hashes, native status, numeric logon type, provenance, uncertainty, and event/state distinction.

Logon identity is tenant + endpoint + installation + LUID + SID when the LUID exists. Unknown-LUID events include native observation time rather than collapsing by username. Windows session identity includes a generation to prevent session-ID reuse. Token identity is derived from endpoint + PID-reuse-protected process entity + token type + SID. A process relationship requires process start identity and token/session evidence; username and timing alone are insufficient.

Token snapshots are bounded and never dump credentials or token contents. Privilege `assigned`, `present`, `enabled`, and `used` states are distinct. Group data is bounded native context. Unknown data stays unknown; transport peer addresses are not asserted to identify users.

The existing crash-safe partitioned queue, mTLS/gzip transport, PostgreSQL authority, outbox, NATS, strict OpenSearch projection, authorization, policy, export and UI infrastructure are reused. A monotonic identity checkpoint survives a drained queue; server rejections retain evidence in quarantine.

## Consequences

- No password, ticket, credential hash, raw credential material, intent, compromise, privilege abuse, or token theft claim is collected or inferred.
- Missing logoff, late/out-of-order evidence and unavailable RDP state are explicit quality conditions.
- Identity policy is versioned and tenant-scoped; dangerous global disable and match-all exclusions require rejection/elevated confirmation.
- Windows is qualified locally. Native Linux remains an environment blocker; macOS and hosted CI remain external blockers.
