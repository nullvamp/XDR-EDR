# ADR 0023: Safe Windows process response

Status: accepted and qualified for Windows under Sprint 19 Outcome B-Windows.

Sprint 19 adds only predefined signed actions for exact process terminate, suspend, resume, status, and pinned process-tree termination. Analysts cannot submit raw PIDs or arbitrary shell commands. The control plane resolves an authoritative process entity and binds its PID, native start identity, optional image path/hash, tenant, endpoint, agent installation, analyst, policy, expiry, nonce and immutable parameter hash into the existing separately approved CA-signed response envelope.

The Windows executor reopens the process with the minimum action-specific access, compares creation time and image identity, applies hard critical/agent/management protections, and verifies the post-state. Termination is not successful until the targeted identity exits. Suspension enumerates a bounded thread snapshot and records the increments owned by the response engine; resume removes only those increments. Tree requests pin an authoritative graph snapshot with depth/count limits and execute a deterministic deepest-first, root-last plan while retaining every node outcome. New descendants are never silently added.

Offline delivery, cancellation, expiry, backend/agent restart, replay and duplicate delivery remain governed by the existing durable response lifecycle. Source alert/incident/entity context is preserved in immutable audit and UI timelines. Live Response process commands are aliases for the same structured actions, never a `kill <pid>` bypass. Native qualification ran exclusively in the existing dedicated victim VM and did not mutate the host.
