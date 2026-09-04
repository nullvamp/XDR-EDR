# Large-artifact RTR enhancement validation

Result: **PASS on Windows**. This separately authorized favor did not begin or complete Sprint 24.

Elevated native work ran only in the existing `XDR-Victim-Sprint18` Hyper-V guest. No new VM, checkpoint or per-sprint container image was created, and host firewall/network/security configuration was not changed. The reusable agent publish directory is 104 MiB; gateway transfer metadata is 36 KiB, MinIO test evidence is 47.7 MiB, and D: retained 109.56 GiB free after validation.

## Acceptance matrix

| Criterion | Result | Objective evidence |
|---|---|---|
| Binary large-artifact protocol | PASS | `artifact-transfer.v1`; raw 4 MiB chunks, no Base64; 12,582,912-byte native pull completed as exactly 3/3 chunks. |
| Identity and authorization binding | PASS | Transfer binds tenant, endpoint, agent, installation, owner command and artifact. Foreign-tenant status lookup returned 404. Inactive/mismatched owners fail closed. |
| Integrity and race handling | PASS | Per-chunk SHA-256, exact replay match, ordered cursor, final byte count/SHA-256, native file identity and before/after snapshot. Victim/source/download SHA-256 all `d10a1d58e826db86583cc0f08281a367cfb0d3e1ddd16fc9f8636e906f88adce`. |
| Retry/resume semantics | PASS | Four-attempt bounded transient retry and server acknowledgement cursor are implemented; duplicate chunks are idempotent only when bytes/hash match. Crash-interrupted interactive commands remain Uncertain and are not automatically replayed. |
| Bounds and resource control | PASS | 256 KiB–16 MiB chunk policy, default 4 MiB; 4 GiB artifact; two active transfers/endpoint; default 32 MiB/s; streaming file/object paths avoid whole-artifact memory buffering. |
| Isolated endpoint collection | PASS | Before: management/external true/true. Isolated: management true, external false. The 12 MiB 3-chunk pull succeeded with exact hash. Unisolation restored true/true. |
| Forensic collection integration | PASS | Stable-handle exact-file acquisition spools and hashes incrementally, then uses the same transfer protocol; local spool cleanup remains action-scoped. Existing forensic Profiles A–F remain reconciled. |
| Approved tool library | PASS | Raw upload, exact type/size/hash, tenant scope, approved/revoked state and agent-only content route. Controlled package `8ee2e3c9-dbea-4d9b-9654-108e2dab90fc` stored at 139,264 bytes. |
| Tool stage/signature/no-auto-execution | PASS | Explicit unsigned policy accepted; endpoint SHA-256 `1247342ba5b2f62ea551fe60af9fe077b12d03a02f0952df8390d881e01993b0`; signer state `unsigned`; `executed=false`; process count 0. Signed packages require local WinVerifyTrust plus exact thumbprint. |
| Tool cleanup boundary | PASS | `remove-tool` reported `ownedPathOnly=true`, removed only the exact package directory and verified it absent. |
| Analyst UI | PASS | Forensic Tools view supports raw package upload, policy metadata and package state; collection details hydrate transfer progress. No command auto-execution affordance exists. |
| Accessibility | PASS | Dark/light Forensic Tools screen: zero critical/serious Axe findings, zero semantic findings, keyboard operation PASS. |
| API failure behavior | PASS | Empty built-in now returns bounded 400 instead of indexing an empty token array; unbound agent transfer request returned 401 during negative qualification. |
| Durable deployment path | PASS | Gateway image creates `/data` owned by the unprivileged platform user; the exact existing named volume was corrected once. Gateway is unprivileged, ready 200, restart count 0. |
| Automated regression | PASS | Release build 0 errors / 0 warnings; 139/139 tests; format, JS syntax, Compose config and diff checks PASS. |
| Dependency/image security | PASS | NuGet direct/transitive scan found no vulnerable packages. Trivy final gateway image found 0 HIGH/CRITICAL vulnerabilities. |
| Reconciliation and drain | PASS | Eleven prior PostgreSQL/OpenSearch domains differ by zero; nine endpoint queues plus hash/forensic work are zero; response nonterminal 0; outbox 0/0; NATS pending/ACK-pending/redelivered 0/0/0. |
| Native Linux | ENVIRONMENT BLOCKER | No supported native Linux endpoint qualification environment. |
| macOS / hosted CI | EXTERNAL BLOCKER | Native macOS and hosted runners are unavailable. |

## Native evidence

- `artifacts/large-artifact-rtr.json`: direct multi-chunk pull, tenant boundary, approved unsigned package stage/no-execute/remove.
- `artifacts/isolated-artifact-rtr.json`: actual victim isolation, management survival, identical multi-chunk pull, exact unisolation/restoration.
- `artifacts/forensic-tools-accessibility.json`: dark/light and keyboard results.
- `artifacts/sprint22-final-reconciliation.json`: final exact prior-domain and transport drain snapshot.

## Honest support boundary

Direct exact-file retrieval and bounded structured forensic profiles are supported up to the documented limits. Raw MFT/USN, raw volume, VSS, memory images, locked application databases and arbitrary recursive collection are not claimed as native collectors. Approved tools can be staged and their bounded output retrieved, but tool execution remains separately authorized/audited and still requires source-specific validation. Analyst download becomes available after final object verification; upload progress is visible, but byte-range consumption while upload is still active is not implemented. The current transfer/catalog metadata store is single-gateway durable, not HA.

Reproduce with:

    dotnet build SecurityPlatform.sln -c Release --no-restore
    dotnet run --project testing/Platform.Tests/Platform.Tests.csproj -c Release --no-build
    dotnet format SecurityPlatform.sln --no-restore --verify-no-changes
    node --check frontend/app.js
    docker compose --env-file .env -f deployment/docker-compose.yml config --quiet
    powershell -NoProfile -ExecutionPolicy Bypass -File testing/integration/large-artifact-rtr.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File testing/integration/isolated-artifact-rtr.ps1
    node testing/accessibility/forensic-tools.js
    powershell -NoProfile -ExecutionPolicy Bypass -File testing/integration/sprint22-final-reconciliation.ps1
