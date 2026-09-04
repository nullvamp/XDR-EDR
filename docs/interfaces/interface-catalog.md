# Stable Interface Catalog

## Registry contracts

`IRegistryTelemetryRepository` owns authoritative event/entity/history/health transactions and same-transaction outbox creation. `IRegistryProjection` owns tenant-injected bounded search and versioned rebuild/alias switching. `IRegistryPolicyRepository` owns immutable policies, endpoint assignments, acknowledgements and audited exclusions. `IRegistryExportRepository` plus the shared object-storage boundary owns tenant-bound jobs, content, metadata, manifests and download audits. Agent transport is `/agent/v1/registry-event-batches` over the existing certificate-bound channel.

## Contract conventions

Interface descriptions are language-neutral. Requests carry `contract_version`, tenant context, principal/authorization proof, request/idempotency IDs, deadline and trace context. Results are typed; partial success is explicit. Providers publish capabilities and supported version ranges. Errors use the canonical codes plus provider-safe `cause_class`; raw provider errors remain restricted.

| Interface | Responsibilities and operations | Events | Contract errors / versioning |
|---|---|---|---|
| `IAuthentication` | `Authenticate`, `ExchangeAssertion`, `ValidateCredential`, `RevokeSession`, `GetPrincipal` | principal/session lifecycle | invalid/expired credential, factor required; v1 additive claims |
| `IAuthorization` | `Check`, `BatchCheck`, `Explain`, `ListAuthorizedScopes`; never returns data | policy/grant revision | denied, context invalid; decision schema v1 |
| `IAgentTransport` | `Register`, `CheckIn`, `PushEventBatch`, `LeaseJobs`, `SubmitJobTransition`, `UploadArtifact` | agent health/config/job ack | sequence gap, cert revoked, unsupported capability; protocol capability negotiation |
| `ICollector` | `DescribeArtifacts`, `PlanCollection`, `ExecuteCollection`, `Cancel`, `GetProgress` | collection/artifact lifecycle | artifact unavailable, budget exceeded, target offline; artifact schema independently versioned |
| `IDetectionEngine` | `ValidateRule`, `Compile`, `EvaluateStream`, `ExecuteBatch`, `Replay`, `ExplainMatch` | execution/finding candidate | mapping missing, rule invalid, budget exceeded; query IR v1 |
| `IThreatIntel` | `Lookup`, `Search`, `UpsertAssertions`, `SyncFeed`, `Publish`, `Health` | indicator/assertion/feed lifecycle | marking denied, provider throttled, conflict; STIX preserved, canonical CTI v1 |
| `IResponseProvider` | `Capabilities`, `ValidateAction`, `Execute`, `Status`, `Cancel`, `Compensate` | action/job transitions | unsupported, approval missing, target stale, irreversible, provider unavailable; action type/version pair |
| `IStorage` | `Put`, `Get`, `Head`, `DeleteByPolicy`, `ListByCursor`, `BeginTransaction`, `Health` | migration/health | conflict, unavailable, quota, integrity; provider types hidden |
| `IObjectStorage` | `InitiateMultipart`, `PutPart`, `Complete`, `Verify`, `GetLease`, `ApplyHold` | object verification/lifecycle | hash mismatch, hold conflict, lease expired |
| `ISearch` | `ValidateQuery`, `Execute`, `Continue`, `Cancel`, `Explain`, `Capabilities` | query lifecycle | invalid IR, cost limit, cursor expired; canonical query IR versioned |
| `IQueue` | `Publish`, `Subscribe`, `Ack`, `Nack`, `ExtendLease`, `DeadLetter`, `Replay` | transport health | unavailable, payload too large, lease lost; at-least-once semantics fixed in v1 |
| `IAudit` | `Append`, `AppendDecision`, `VerifyRange`, `ExportProof`; never update/delete | proof anchor | integrity failure, unavailable; audit event v1 immutable |
| `ILogging` | `Emit` structured redacted record, `WithContext` | pipeline health | classification violation, unavailable; log schema v1 |
| `IMetrics` | `Counter`, `Gauge`, `Histogram`, `ObserveSLO` with bounded labels | SLO breach | cardinality rejected; metric names versioned by semantic change |
| `IConnector` | `Manifest`, `Configure`, `Test`, `Start`, `Stop`, `Health`, `Ingest`, `HandleAction` | connector lifecycle/health | configuration invalid, permission denied, upstream throttled |
| `IPlugin` | `Manifest`, `Initialize`, `Activate`, `Deactivate`, `Migrate`, `Health` | install/upgrade/revoke | signature, compatibility, permission, migration failure |
| `IParser` | `DescribeSource`, `Validate`, `Normalize(raw, context)`, `GoldenFixtures` | parser health | unsupported version, malformed, partial mapping; deterministic parser version |
| `IArtifactProvider` | `Collect`, `InspectMetadata`, `Scan`, `DeleteByPolicy` | artifact lifecycle | dangerous content, size, integrity, legal hold |
| `IEvidenceProvider` | `AcceptArtifact`, `Seal`, `Verify`, `Export`, `ApplyLegalHold`, `CustodyHistory` | custody events | verification failed, hold conflict, classification denied |
| `IAIProvider` | `Capabilities`, `Complete`, `Stream`, `Embed`, `CountTokens`, `Health`; provider receives policy-filtered context | model invocation metrics | data policy denied, context limit, safety refusal, provider unavailable |
| `INotificationChannel` | `ValidateRecipient`, `RenderPreview`, `Send`, `DeliveryStatus` | delivery state | classification/channel denied, throttled |
| `IEntitlement` | `CheckFeature`, `ReserveQuota`, `CommitUsage`, `ReleaseReservation` | quota/entitlement changes | not entitled, quota exceeded, reservation expired |

## Interface invariants

- `Check` occurs at request entry and again at effect time for queued actions.
- Providers never authorize themselves; they receive an already bounded execution grant and still enforce tenant/target match.
- Cancellation is best-effort and returns whether side effects may already exist.
- A success result includes provider operation ID, canonical result, timestamps and provenance.
- Capability descriptors are signed/attested for agents and cached with expiry for services.
- Conformance suites are normative and published alongside each major interface version.
