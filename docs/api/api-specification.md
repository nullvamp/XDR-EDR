# API Specification

## Registry telemetry API v1

The registry surface includes `/api/v1/registry-events`, event details, endpoint key/value entities and histories, endpoint registry timeline, process-to-registry activity, endpoint registry health, synchronous export, asynchronous `/api/v1/registry-exports` jobs/content/metadata/manifest/bounded download URL, versioned registry policies/assignment/rollback/acknowledgement, audited exclusions, and system-admin projection rebuild/progress. Every data lookup injects tenant scope. Search/export range and result size are bounded. Captured preview is removed unless the principal has `registry:sensitive:read` or an administrative superset; asynchronous output cannot bypass collection/redaction policy.

## Contract style

Public HTTPS APIs use JSON over TLS 1.3, rooted at `/api/v1`. Agent traffic uses a separate mutually authenticated endpoint and a versioned binary-capable envelope; its semantic operations remain documented here. OpenAPI 3.1 describes HTTP, AsyncAPI describes streams/webhooks, and JSON Schema 2020-12 defines payloads. Bulk evidence transfer uses pre-authorized, time-bounded object URLs after authorization and audit.

### Common headers

| Header | Requirement |
|---|---|
| `Authorization: Bearer …` | Human/workload OAuth 2.1 token; never used by enrolled agents |
| `X-Tenant-ID` | Required when principal can access multiple tenants; checked against token grants |
| `X-Request-ID` | Client UUID accepted or generated; returned and audited |
| `Idempotency-Key` | Required for mutation commands and remote actions; retained at least 24 hours |
| `If-Match` | Required for updates/deletes of revisioned resources |
| `Accept-Version` | Optional contract minor preference; major stays in path |

Authentication supports OIDC authorization code + PKCE for users, client credentials/private-key JWT for services, and mTLS device certificates for agents. SAML is brokered through the identity service. Authorization is deny-by-default and evaluated on action, resource, tenant ancestry, classification, device group, risk, time and approval context.

### Collection conventions

- Cursor pagination: `page[size]` (default 50, max 500), `page[after]`; response includes opaque `next_cursor` and `has_more`. No offset pagination for mutable collections.
- Filter: `filter[field][op]=value`; operators `eq,ne,in,nin,gt,gte,lt,lte,contains,prefix,exists`. Each resource documents allowlisted fields.
- Sort: `sort=field,-other`; stable ID is appended as tie-breaker.
- Sparse fields/include: `fields[type]=a,b` and bounded `include=relationship`; maximum include depth 2.
- Search: resource `q` for safe text search; complex hunts use `/hunts/executions` and never overload CRUD lists.
- Dates: inclusive `gte`, exclusive `lt` is the standard range.

### Response and errors

Success envelopes contain `data`, `meta.request_id`, `meta.schema_version`, and optional `links`. Errors use `application/problem+json` with `type`, `title`, `status`, `code`, `detail`, `instance`, `request_id`, `retryable`, `violations[]`, and optional `retry_after_ms`. Stable codes include `AUTHENTICATION_REQUIRED`, `ACCESS_DENIED`, `TENANT_SCOPE_INVALID`, `RESOURCE_NOT_FOUND`, `REVISION_CONFLICT`, `VALIDATION_FAILED`, `IDEMPOTENCY_CONFLICT`, `APPROVAL_REQUIRED`, `CAPABILITY_UNAVAILABLE`, `RATE_LIMITED`, `QUOTA_EXCEEDED`, `PROVIDER_UNAVAILABLE`, and `INTERNAL_ERROR`. Details never reveal existence of unauthorized resources.

Rate limits are principal+tenant+route-class token buckets. Headers return `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`; 429 is retryable. Export, hunt, response and AI have separate concurrency/budget quotas.

## Endpoint catalog

The table is OpenAPI-ready: operation IDs are stable, nouns are plural, commands are explicit subresources, and each mutation declares permission/audit behavior.

### Identity, tenants and administration

| Method and path | Operation ID | Input → output | Permission / audit |
|---|---|---|---|
| `GET /session` | `getSession` | — → principal, grants, tenant choices | authenticated; login/read audit sampled |
| `GET /organizations/{id}` | `getOrganization` | ID → Organization | `organization:read` |
| `GET,POST /tenants` | `listTenants`, `createTenant` | filters / TenantCreate → Tenant | `tenant:read/create`; create audited |
| `GET,PATCH,DELETE /tenants/{id}` | `getTenant`, `updateTenant`, `scheduleTenantDeletion` | ID/patch → Tenant/operation | `tenant:read/update/delete`; all mutations audited |
| `GET,POST /workspaces` | `listWorkspaces`, `createWorkspace` | filter/create → Workspace | `workspace:read/create` |
| `GET,POST /users` | `listUsers`, `inviteUser` | filter/invite → User | `user:read/invite` |
| `PATCH /users/{id}` | `updateUser` | patch+ETag → User | `user:update`; audited |
| `GET,POST /groups` | `listGroups`, `createGroup` | —/create → Group | `group:*` |
| `GET,POST /roles` | `listRoles`, `createRole` | —/create → Role | `role:*`; audited |
| `GET,POST /role-grants` | `listRoleGrants`, `createRoleGrant` | filter/grant → RoleGrant | `grant:read/create`; high-risk approval |
| `DELETE /role-grants/{id}` | `revokeRoleGrant` | reason → RoleGrant | `grant:revoke`; audited |
| `GET,POST /service-accounts` | `listServiceAccounts`, `createServiceAccount` | —/create → account | `service_account:*` |
| `POST /service-accounts/{id}/credentials` | `issueServiceCredential` | constraints → reveal-once credential | `credential:issue`; audited |
| `POST /approvals/{id}/decision` | `decideApproval` | approve/reject+reason → Approval | `approval:decide`; audited |

### Agent protocol and endpoint inventory

| Method and path | Operation ID | Input → output | Permission / audit |
|---|---|---|---|
| `POST /agent/v1/register` | `registerAgent` | enrollment proof, CSR, hardware-bound identity, capabilities → agent ID, certificate, bootstrap config | Token-bound; always audited/rate-limited |
| `POST /agent/v1/checkins` | `agentCheckin` | health, inventory digest, capability set, config ack, job ack → config/job/update hints | mTLS agent-only |
| `POST /agent/v1/event-batches` | `ingestAgentEvents` | compressed signed batch with sequence → accepted/rejected ranges | mTLS; metered; raw receipt retained |
| `POST /agent/v1/job-results` | `submitAgentJobResult` | job transition/output manifests → acknowledgement | mTLS; transition verified |
| `POST /agent/v1/artifacts:initiate` | `initiateArtifactUpload` | job, manifest, size/hash → upload lease | mTLS; quota/custody enforced |
| `POST /agent/v1/artifacts/{id}:complete` | `completeArtifactUpload` | parts/hashes → verification status | mTLS; custody event |
| `GET /endpoints` | `listEndpoints` | filters/search/sort → Endpoint page | `endpoint:read` |
| `GET /endpoints/{id}` | `getEndpoint` | ID/include → Endpoint | `endpoint:read` |
| `GET /endpoints/{id}/agents` | `listEndpointAgents` | ID → agents | `agent:read` |
| `GET /endpoints/{id}/inventory/software` | `getSoftwareInventory` | as-of → snapshot/page | `inventory:read` |
| `GET /endpoints/{id}/inventory/hardware` | `getHardwareInventory` | as-of → snapshot | `inventory:read_sensitive` where needed |
| `GET,POST /endpoint-groups` | `listEndpointGroups`, `createEndpointGroup` | —/selector → group | `endpoint_group:*` |
| `POST /enrollment-tokens` | `createEnrollmentToken` | limits/scope → reveal-once token | `agent:enroll`; audited |
| `POST /agents/{id}:revoke` | `revokeAgent` | reason → operation | `agent:revoke`; approval configurable |

### Policy and update management

| Method and path | Operation ID | Input → output | Permission / audit |
|---|---|---|---|
| `GET,POST /policies` | `listPolicies`, `createPolicy` | filters/create → Policy | `policy:read/create` |
| `POST /policies/{id}/versions` | `createPolicyVersion` | content+compatibility → immutable draft | `policy:edit` |
| `POST /policy-versions/{id}:validate` | `validatePolicyVersion` | target sample → validation/explain plan | `policy:edit` |
| `POST /policy-versions/{id}:publish` | `publishPolicyVersion` | approval/release note → version | `policy:publish`; audited |
| `POST /policy-assignments` | `createPolicyAssignment` | target, rollout, version → assignment | `policy:assign`; audit/approval |
| `GET /endpoints/{id}/effective-configuration` | `getEffectiveConfiguration` | ID/version → snapshot+explanation | `configuration:read` |
| `GET,POST /agent-updates` | `listAgentUpdates`, `createAgentUpdate` | —/rings+gates → rollout | `update:read/create`; audited |
| `POST /agent-updates/{id}:pause` | `pauseAgentUpdate` | reason → rollout | `update:control` |
| `POST /agent-updates/{id}:rollback` | `rollbackAgentUpdate` | reason → rollout | `update:rollback`; approval/audit |

### Telemetry, detection, hunting and timeline

| Method and path | Operation ID | Input → output | Permission / audit |
|---|---|---|---|
| `POST /ingest/v1/events` | `ingestIntegrationEvents` | signed canonical/raw batches → receipts | connector principal + source scope |
| `GET /events` | `searchEvents` | bounded filters/cursor → events | `telemetry:read`; field masking |
| `GET /events/{id}` | `getEvent` | ID → canonical event+provenance | `telemetry:read` |
| `GET,POST /detection-rules` | `listDetectionRules`, `createDetectionRule` | filters/rule → rule | `detection_rule:read/create` |
| `POST /detection-rules/{id}/versions` | `createDetectionRuleVersion` | content/tests → version | `detection_rule:edit` |
| `POST /detection-rule-versions/{id}:validate` | `validateDetectionRule` | corpus/options → test/compile report | `detection_rule:edit` |
| `POST /detection-rule-versions/{id}:publish` | `publishDetectionRule` | approval → immutable active version | `detection_rule:publish`; audited |
| `POST /detection-rule-versions/{id}:replay` | `replayDetectionRule` | corpus/time range/budget → async execution | `detection_rule:test`; metered |
| `GET /findings` | `listFindings` | filters → page | `finding:read` |
| `PATCH /findings/{id}` | `triageFinding` | status/reason+ETag → Finding | `finding:triage`; audited |
| `GET /alerts` | `listAlerts` | queue filters → page | `alert:read` |
| `POST /hunts/executions` | `executeHunt` | language, query/saved hunt, scope, budget → execution | `hunt:execute`; always audited |
| `GET /hunts/executions/{id}` | `getHuntExecution` | ID → state/metrics/result link | `hunt:read` |
| `POST /hunts/executions/{id}:cancel` | `cancelHunt` | reason → execution | owner or `hunt:cancel` |
| `GET /timeline` | `getTimeline` | entity/case/time/source filters → ordered cursor page | `timeline:read` |
| `GET /entities/{id}/graph` | `getEntityGraph` | depth/types/time/budget → graph | `entity:read`; bounded |

### File telemetry acceptance surfaces

All routes below derive tenant scope from the authenticated principal. Foreign identifiers are non-enumerable, search is bounded by an allowlist and signed cursor, and no request body can select a tenant.

| Method and path | Purpose | Security and bounds |
|---|---|---|
| `GET /file-events/{eventId}` | File-event detail, provenance, identity, paths, process/user and quality state | `telemetry:read`; tenant-bound ID |
| `GET /files` | Search including previous path and native identity components | bounded time/page; safe exact/prefix filters |
| `GET /files/projections:progress` | Rebuild state and source/index/failure counts | tenant progress only; system progress requires platform admin |
| `POST /file-exports` | Create asynchronous JSONL/CSV export | approved fields/filters; 1-10,000 records |
| `GET /file-exports/{id}` | Job status and failure/expiry state | tenant-bound ID |
| `GET /file-exports/{id}/metadata` | Object metadata | tenant-bound ID |
| `GET /file-exports/{id}/manifest` | Integrity manifest | tenant-bound ID |
| `GET /file-exports/{id}/content` | Compatibility content retrieval | completed, unexpired jobs only |
| `POST /file-exports/{id}/download-url` | Issue short-lived exact-object URL | audited; signed and tenant-bound |
| `GET /file-telemetry/policies/{id}/versions/{version}` | Immutable policy version | policy read permission and tenant binding |
| `GET,POST /file-telemetry/policies/{id}/exclusions` | List/create exclusions | validated category, glob and scope; mutations audited |
| `PUT,DELETE /file-telemetry/policies/{id}/exclusions/{ruleId}` | Version-safe update/disable | tenant-bound policy/rule; mutations audited |

Export objects use server-generated UUID keys beneath a tenant prefix. Output, metadata and manifest are separate MinIO objects. Completed jobs expire after 15 minutes; the worker removes all three objects and changes state to `expired`. CSV cells beginning with spreadsheet formula characters are safely prefixed. The manifest records count, size, SHA-256, schema/application versions, query summary and immutable object identifiers.

### Incidents, cases and collaboration

| Method and path | Operation ID | Input → output | Permission / audit |
|---|---|---|---|
| `GET /incidents` | `listIncidents` | filters → page | `incident:read` |
| `GET,PATCH /incidents/{id}` | `getIncident`, `updateIncident` | ID/patch → Incident | `incident:read/update`; update audited |
| `GET,POST /cases` | `listCases`, `createCase` | filter/create → Case | `case:read/create` |
| `GET,PATCH /cases/{id}` | `getCase`, `updateCase` | include/patch+ETag → Case | classification-aware |
| `POST /cases/{id}/investigations` | `createInvestigation` | hypothesis/scope → Investigation | `investigation:create` |
| `POST /cases/{id}/tasks` | `createCaseTask` | task → Task | `case:collaborate` |
| `POST /cases/{id}/comments` | `createCaseComment` | body/marking → Comment | `case:comment`; audited |
| `POST /cases/{id}:export` | `exportCase` | format, evidence selection, redaction → async report | `case:export`; approval/audit |

### Response and DFIR

| Method and path | Operation ID | Input → output | Permission / audit |
|---|---|---|---|
| `POST /response-actions` | `createResponseAction` | type,target,parameters,justification,expiry → action/approval | type-specific; always audited |
| `POST /response-actions/{id}:dispatch` | `dispatchResponseAction` | approval token → ResponseJob | `response:dispatch`; idempotent |
| `POST /response-actions/{id}:reverse` | `reverseResponseAction` | reason → compensation job | `response:reverse`; audited |
| `POST /response/isolate` | `isolateEndpoint` | endpoint IDs, TTL, network exceptions, reason → actions | `response:isolate`; compatibility alias to generic action |
| `POST /response/release` | `releaseEndpoint` | endpoint IDs/reason → actions | `response:release` |
| `POST /response/scripts` | `runApprovedScript` | script version, targets, parameters, budget → actions | `response:script`; approval by risk |
| `GET /response-jobs/{id}` | `getResponseJob` | ID → transitions/results | `response:read` |
| `POST /collection-plans` | `createCollectionPlan` | artifacts,targets,budgets,custody → plan | `dfir:collect` |
| `POST /collection-plans/{id}:execute` | `executeCollectionPlan` | approval → jobs | `dfir:execute`; audited |
| `GET /artifacts` | `listArtifacts` | case/endpoint/kind filters → page | `artifact:read` |
| `POST /artifacts/{id}:promote-to-evidence` | `promoteArtifactToEvidence` | classification/case → Evidence | `evidence:create`; custody audit |
| `GET /evidence/{id}/manifest` | `getEvidenceManifest` | ID → signed manifest | `evidence:read` |
| `POST /evidence/{id}:export` | `exportEvidence` | format, recipient public key, redaction → export job | `evidence:export`; approval/audit |
| `POST /evidence/{id}:verify` | `verifyEvidence` | optional verifier profile → report | `evidence:verify` |

### Intelligence, integrations, plugins and AI

| Method and path | Operation ID | Input → output | Permission / audit |
|---|---|---|---|
| `GET,POST /indicators` | `listIndicators`, `createIndicator` | filter/create → Indicator | `intel:read/write`; markings enforced |
| `POST /indicators:bulk` | `bulkUpsertIndicators` | bounded batch → per-item result | `intel:bulk`; idempotent |
| `GET,POST /threat-feeds` | `listThreatFeeds`, `createThreatFeed` | —/config ref → feed | `intel_feed:*` |
| `POST /threat-feeds/{id}:sync` | `syncThreatFeed` | mode → job | `intel_feed:run`; metered |
| `GET,POST /connectors` | `listConnectors`, `createConnector` | —/package+secret refs → connector | `connector:*` |
| `POST /connectors/{id}:test` | `testConnector` | checks → report | `connector:test`; no secret echo |
| `GET /marketplace/packages` | `listMarketplacePackages` | filters → package page | `marketplace:read` |
| `POST /plugins/installations` | `installPlugin` | package digest, config, permission grants → installation/approval | `plugin:install`; audited |
| `POST /plugin-installations/{id}:upgrade` | `upgradePlugin` | target digest, rollout → installation | `plugin:upgrade`; audited |
| `POST /plugin-installations/{id}:disable` | `disablePlugin` | reason → installation | `plugin:disable` |
| `POST /ai/sessions` | `createAISession` | purpose, case, model, scope → session | `ai:use`; data policy evaluated |
| `POST /ai/sessions/{id}/messages` | `createAIMessage` | prompt/tool consent → async message | `ai:use`; prompt/tool trace audited |
| `GET /ai/messages/{id}/citations` | `listAICitations` | ID → citations | underlying source permission rechecked |

### Reporting, audit and operations

| Method and path | Operation ID | Input → output | Permission / audit |
|---|---|---|---|
| `GET,POST /report-definitions` | `listReportDefinitions`, `createReportDefinition` | —/definition → definition | `report:*` |
| `POST /report-runs` | `runReport` | definition/params/as-of → run | `report:run` |
| `GET /report-runs/{id}` | `getReportRun` | ID → status/artifact | `report:read` |
| `GET,POST /dashboards` | `listDashboards`, `createDashboard` | —/layout → Dashboard | `dashboard:*` |
| `GET /audit-events` | `listAuditEvents` | restricted filters → cursor page | `audit:read`; read itself audited |
| `POST /audit/exports` | `exportAudit` | range/format/signing → export job | `audit:export`; approval |
| `GET /usage` | `getUsage` | dimensions/range → meters | `usage:read` |
| `GET /health/integrations` | `getIntegrationHealth` | filters → health | `operations:read` |

## Streaming and webhooks

### Sprint 8 service and scheduled-task investigation

| Method and path | Purpose |
|---|---|
| `GET /api/v1/service-events`, `GET /api/v1/scheduled-task-events` | Tenant-scoped bounded search with opaque cursors |
| `GET /api/v1/service-events/{eventId}`, `GET /api/v1/scheduled-task-events/{eventId}` | Evidence, provenance, quality, and supported relationship detail |
| `GET /api/v1/services/{entityId}/history`, `GET /api/v1/tasks/{entityId}/history` | Lifecycle/configuration history without collapsing recreation |
| `GET /api/v1/tasks/{entityId}/executions` | Native task execution-instance history |
| `GET /api/v1/endpoints/{endpointId}/persistence-timeline` | Endpoint service/task activity timeline |
| `GET /api/v1/endpoints/{endpointId}/persistence-telemetry-health` | Bounded source/queue/loss/exclusion/policy health |
| `/api/v1/persistence-telemetry/policies...` | Immutable versions, assignment, acknowledgement, and audited exclusions |
| `/api/v1/persistence-telemetry/exports...` | Asynchronous JSONL/CSV export, manifest, SHA-256, expiry, and signed download |

All routes enforce the authenticated tenant. Ingestion additionally requires HTTPS, the enrolled endpoint/agent mTLS identity, bounded gzip, declared uncompressed length, content SHA-256, and idempotent sequence/event identity.

### Sprint 9 persistence-configuration investigation

| Method and path | Purpose |
|---|---|
| `GET /api/v1/persistence-configurations` | Tenant-scoped bounded search by endpoint, category, subtype, scope, name/path, WMI metadata, principal, state, time, and quality |
| `GET /api/v1/persistence-configurations/{eventId}` | Configuration, identity, provenance, quality, ambiguity, redaction, and raw evidence references |
| `GET /api/v1/persistence-configurations/{entityId}/history` | Lifecycle/configuration history with delete/recreate generations; requires endpoint ID |
| `GET /api/v1/endpoints/{endpointId}/wmi-subscriptions` | Filter, consumer, and binding relationship view without inventing complete chains |
| `GET /api/v1/endpoints/{endpointId}/persistence-timeline` | Combined endpoint service/task/configuration timeline |
| `GET /api/v1/endpoints/{endpointId}/persistence-telemetry-health` | WMI/configuration/raw-input/relationship and queue/policy health |
| `/api/v1/persistence-telemetry/policies...` | Immutable version, assignment, acknowledgement, redaction, exclusion, and resource controls |
| `/api/v1/persistence-telemetry/exports...` | Bounded async JSONL/CSV, manifest/SHA-256, expiry, and tenant-bound signed download |

All configuration routes preserve the distinction between raw evidence, derived configuration, configured action, execution, unavailable data, and source-non-observable data.

## Streaming and webhooks

- `GET /streams/v1/events` upgrades to WebSocket only for interactive, filtered, bounded streams; authorization is revalidated every five minutes. Clients acknowledge sequence numbers; gaps trigger REST backfill.
- Server-Sent Events are preferred for job/report/collection progress: `GET /response-jobs/{id}/events`, `/hunt-executions/{id}/events`.
- High-volume durable delivery uses webhooks or customer message-bus export, not browser WebSockets.
- Webhook subscriptions declare event types, tenant scope, endpoint, secret/certificate, filter and maximum classification. Deliveries use signed timestamped envelopes, monotonically increasing sequence per subscription, exponential retry, dead-letter visibility and replay endpoint.

Canonical event topics include `endpoint.lifecycle.v1`, `telemetry.accepted.v1`, `finding.lifecycle.v1`, `incident.lifecycle.v1`, `case.lifecycle.v1`, `response.job.v1`, `evidence.custody.v1`, `connector.health.v1`, `plugin.lifecycle.v1`, and `audit.security.v1`. Payloads contain no unbounded embedded artifacts.

## Validation and audit requirements

All inputs reject unknown security-sensitive enum values, normalize Unicode, bound nesting/string/array sizes and validate content type before parsing. Query languages have independent parsers, allowlists and budgets. API gateway records authentication outcome; domain service records authorization decision and mutation outcome. Secrets, tokens, raw script contents, evidence bytes and unnecessary PII are never logged.
