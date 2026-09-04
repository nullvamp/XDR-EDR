# ADR 0028: Resumable artifact transfer and approved tool staging

Status: Accepted, 2026-08-10.

Large endpoint artifacts use `artifact-transfer.v1`, not JSON/Base64. The agent pre-hashes a stable file, creates a tenant/endpoint/agent/installation/owner-bound transfer, and sends ordered 4 MiB binary chunks. Every chunk has a SHA-256 acknowledgement cursor; duplicate acknowledged chunks must match exactly. Completion requires the declared byte count and final SHA-256, then stores the object in tenant-scoped object storage. Two concurrent transfers per endpoint, 4 GiB per artifact and configurable 32 MiB/s acquisition/transfer throttling are hard defaults. Completed chunks are removed immediately.

The protocol resumes from the server acknowledgement cursor during a live operation and retries transient chunk failures. Live Response still refuses automatic command replay after an agent crash, so a crash-interrupted interactive command remains `Uncertain` and must be reissued by an analyst. Response-action forensic collection retains its existing durable replay identity. This distinction prevents “resume” from weakening command replay safety.

Approved forensic tools are a separate tenant-scoped library. Upload is raw binary, bounded to 2 GiB and pinned to exact size, SHA-256, filename/type and either an expected Authenticode thumbprint or an explicit unsigned approval. `stage-tool` requires the session's separately approved `file-upload` capability, downloads only an approved package into the agent-owned data directory, rechecks size/hash/signature locally, and reports `executed=false`. `remove-tool` deletes only that exact package-owned directory. Execution remains a separate audited command and is never implicit.

The implementation does not claim native raw-volume, MFT, memory-image, VSS or browser-database acquisition. Such sources require a separately approved collector/tool with its own safety and legal review; this sprint supplies safe staging and large-result transport, not universal artifact acquisition. Transfer/catalog metadata is durable for the current single gateway but remains file-backed and is not an HA control-plane database.
