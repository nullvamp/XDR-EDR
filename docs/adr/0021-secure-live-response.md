# ADR 0021: Secure Live Response / remote command line

Status: Accepted — 2026-08-09

## Decision

Live Response is a distinct, manually initiated, Windows-qualified control plane. A session is bound to tenant, authoritative endpoint, agent, installation, requester, approved capabilities, policy version, nonce, idle expiry and absolute expiry. Elevated cmd, PowerShell and upload capabilities require a different approver bound to the exact capability hash. Session and command envelopes are signed by the established platform CA and verified by the enrolled agent.

The endpoint exposes a compiled safe built-in set (`help`, `pwd`, `cd`, `ls`, `ps`, `services`, `connections`, `hash`, `stat`, `get`, `session-info`) plus explicit cmd and PowerShell executors only when authorized. PowerShell is no-profile and non-interactive. The executor is single-consumer and bounded; command length, rate, queue, timeout, output, transfer, artifact, root, UNC, reparse-point and lifetime limits fail closed. Upload is disabled by default, never overwrites and never executes. Cancellation targets only the process created for that command. A command interrupted across agent restart becomes `Uncertain` and is never replayed.

Output is streamed as sequenced SHA-256-bound stdout/stderr chunks, stripped of ANSI/control data at the agent, revalidated by the server and rendered through browser text content. File acquisition validates pre/post native identity and metadata and stores a tenant-bound artifact plus integrity manifest. PostgreSQL owns session, command, artifact and append-only transcript authority; transcript mutation is rejected by a database trigger. Downloads and transcript exports append audit events.

## Consequences

- Detection, alert and incident systems may only provide manual source context; they cannot automatically open sessions or submit commands.
- Arbitrary shell use is visible, explicitly capability-gated and separately approved. It is not part of the Sprint 16 predefined-action path.
- Windows is locally qualified. Native Linux remains an `ENVIRONMENT BLOCKER`; macOS and hosted CI remain `EXTERNAL BLOCKER`.
- Sprint 18 is conditionally ready for planning only and is not implemented by this decision.
