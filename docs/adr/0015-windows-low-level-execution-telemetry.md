# ADR 0015: Windows low-level execution telemetry

Status: accepted for Sprint 11 Outcome B-Windows.

## Decision

The existing platform-owned Windows kernel process session remains the sole kernel logger and enables Process, ImageLoad and Thread keywords. A bounded in-process hub publishes native ThreadStart records to the execution partition. Security 4656 is treated only as requested-access evidence when host auditing supplies it.

Thread observations preserve provider GUID, channel, native identity, TID, start address and PID-reuse-safe target process start identity. Process identity is snapshotted in the callback to survive termination before persistence. Without trustworthy start identity, the observation becomes a measured source drop, never invalid authority. Creator/source process is not inferred from timing.

Public sources on this host do not reliably expose arbitrary memory allocation/protection/write, general section, APC or context relationships. Those surfaces remain `NOT OBSERVABLE BY SOURCE`; no custom driver, arbitrary hook or memory-content read is introduced.

The existing crash-safe queue, gzip/mTLS, PostgreSQL, outbox, NATS, OpenSearch, tenant policy/export/UI paths are reused. Partitions drain in bounded quanta; corrupt records quarantine without stopping unrelated collectors. Policy enforcement is tenant-scoped, rate-bounded and applies safe process/path/access/operation/system exclusions.

## Consequences

- Target thread/start evidence is trustworthy; remote/injection semantics are not claimed.
- Requested handle rights remain distinct from completed operations.
- No memory contents, detection, scoring or response data exists.
- Windows is locally qualified; Linux remains an environment blocker and macOS/CI remain external blockers.
