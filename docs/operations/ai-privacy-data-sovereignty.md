# AI privacy and data sovereignty

The default and only Sprint 30 qualified mode is `LOCAL_ONLY`: the local provider executes in the gateway and records `externalTransmission=false`. `REMOTE_REDACTED` requires both secret and personal-data redaction. `REMOTE_FULL` requires an explicit tenant policy version and still requires secret redaction. Neither remote mode implies that a remote adapter exists or is approved.

Administrators must version the tenant AI policy before changing provider, model, allowed evidence/use cases, transmission mode, redaction, retention or resource bounds. Routes require AI-specific RBAC; evidence lookup repeats tenant scope. Policy changes, rejections, requests, provider/mode/package/request hashes, completion/failure, citation rejection, draft and acceptance are audited. Analyst prompt text is hashed in audit; prompt/response bodies follow independent retention settings and may be stored as `[NOT RETAINED]`. Secrets/private keys must never be logged.

Before remote use, security/privacy owners must approve provider contract, region, subprocessors, retention/training behavior, transport/key controls, incident handling and deletion evidence; then qualify redaction bypass, tenant isolation, failure, latency, cost and citation behavior. Until that happens, remote provider qualification is `EXTERNAL BLOCKER` and local-only remains the release posture.
