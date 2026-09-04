# AI detection and correlation draft specification

`ai-rule-draft.v1` contains prompt/evidence/proposal hashes, provider/model identity, source citations, required telemetry, known gaps, false-positive considerations, an existing bounded detection or correlation definition, deterministic review, component scorecard and fixture proposals.

Detection drafts use only `DetectionDsl`; correlation drafts use only `CorrelationDsl` and identity-safe joins (`endpointId`, `processEntityId`, `entityId`, or `user`). ATT&CK IDs must be in the platform-verified inventory. Unknown fields, match-all logic, unsafe joins and unverified techniques fail closed. Correlation types remain the engine's existing ordered/unordered/cross-domain/parent-child/negative/accumulation constructs.

Each detection draft has positive, negative, boundary, benign, malformed, missing-field, duplicate/replay and tenant-isolation canonical fixtures. Schema, tenant, domain, IDs, time, field counts/lengths, evidence reference and expected evaluation are revalidated deterministically. The scorecard exposes telemetry completeness, field reliability, identity safety, false-positive validation, positive/negative coverage, replay determinism, historical volume, ATT&CK validation and cost separately.

Save requires an exact hash and explicit engineer reason. It creates only an inactive, unvalidated repository Draft. Tuning, exclusion and comparison results are advisory and audited; they do not mutate production content.
