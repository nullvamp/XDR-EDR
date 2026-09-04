# Canonical Telemetry Schema

## Network event v1

The Sprint 5 endpoint network observation contains immutable event/batch/endpoint/agent identity; source/collector/native provenance; observed/received/ingested timestamps; canonical and native address bytes; local/remote ports; address family; TCP/UDP; direction/state/result; strong connection entity identity; optional evidence-backed process/user/container/namespace context; lifecycle completeness; evidence hash; late/out-of-order and quality flags. Unknown fields remain null or explicitly unattributed. It never contains packet bytes, payload, DNS domain, URL, TLS, or HTTP content. See ADR 0005.

## Registry event v1

`registry.event.v1` carries immutable event/schema/type, tenant, endpoint, installation, collector/source/version/platform, native source ID/operation/status, sequence, observed/received/ingested time, normalization, evidence hash/reference, correlation/trace, quality/gap context, hive/path/parent/previous path, key/value generation-aware entity IDs, operation/result/confidence, optional process/user evidence, and policy-bound value metadata. Unknown fields remain null or an explicit quality state.

Value metadata distinguishes presence, type, length, capture mode, captured length, truncation, redaction, SHA-256, encoding confidence, classification, capture time, policy version, and safe failure. Complete value content is not the default. Windows ETW SetValue cannot reliably distinguish creation from modification, and subscribed callbacks do not expose a trustworthy rename destination or security-change event; native semantics are retained.

## Process event v1

`process.event.v1` represents one observed process start or exit. Its envelope carries event, batch, endpoint, agent, installation, collector, source-platform, sequence, correlation, trace, normalization, observed-time, and quality fields. Execution identity is a 64-character SHA-256 derived from endpoint, PID, native start time, and platform start key; PID alone is never an entity key.

Start/exit facts, parent identity and lineage state, executable/user/session/container metadata, optional bounded hash/signature outcomes, and original source timestamps remain distinct. Unknown fields are null. Batches use protocol `1.2`, gzip, a SHA-256 over canonical event JSON, explicit sequence bounds, and per-event acknowledgement. PostgreSQL is authoritative and OpenSearch is rebuildable.

## Canonical envelope (`security.event/1.0`)

Every normalized event contains the following. Required fields are marked **R**.

| Field | Req. | Type | Meaning |
|---|:---:|---|---|
| `schema.name`, `schema.version` | R | string, semver | `security.event`, producer schema version |
| `event.id` | R | UUIDv7 | Stable normalized-event identity |
| `event.kind`, `event.category`, `event.type`, `event.action` | R | controlled strings/arrays | Broad kind, categories, semantic types and specific action |
| `event.outcome`, `event.severity`, `event.risk_score` | O | enum, 0–10, 0–100 | Observed outcome and source/normalized assessment |
| `event.created`, `event.start`, `event.end` | R/O | timestamp | Platform creation and observed interval |
| `event.sequence` | O | uint64 | Source ordering where available |
| `tenant.id` | R | typed ID | Hard data boundary |
| `observer.id`, `observer.type`, `observer.version` | R | strings | Agent/sensor/integration producing observation |
| `source.product`, `source.dataset`, `source.event_code` | R | strings | Original source identity |
| `source.received_at`, `source.original_time`, `source.timezone` | R/O | timestamp/string | Intake and original time context |
| `source.raw_ref`, `source.raw_hash` | R | URI-like ID, SHA-256 | Immutable original payload reference and integrity |
| `normalization.parser`, `normalization.version`, `normalization.mapping_id` | R | strings | Reproducibility metadata |
| `normalization.warnings` | O | bounded array | Loss, ambiguity or coercion warnings |
| `host`, `agent`, `user`, `process`, `file`, `registry`, `network`, `dns`, `cloud`, `container`, `email`, `identity`, `threat` | O | typed objects | Event-specific entities |
| `related.entity_ids`, `related.ip`, `related.hash`, `related.user` | O | deduplicated arrays | Bounded pivot indexes |
| `labels` | O | string map | Tenant-safe indexed labels, length bounded |
| `extensions` | O | namespaced object map | Registered extension schemas only |

Unknown input fields remain in raw evidence. Unknown canonical enum values map to `unknown`, while the original value is preserved in `extensions.<source>.original_*`. Null means unknown; absence means not applicable/not provided. Empty string is invalid. IPs use normalized textual form plus packed/index representation; MAC addresses lower-case colon form; hashes declare algorithm; paths preserve original and optional normalized variants.

## Common entity objects

| Object | Required | Important optional fields |
|---|---|---|
| `host` | `id` or `source_id`, `hostname?`, `os.type` | domain, IPs, architecture, OS version/build, boot ID, group IDs |
| `user` | `id` or `name`, `domain?` | SID/UID, email, effective/real identity, privilege, session ID |
| `process` | `entity_id`, `pid`, `start_time?`, `executable?` | args array, command line, parent entity/PID, working dir, hashes, signer, integrity, session, thread |
| `file` | `path` or artifact ID | name, size, hashes, type, MIME, owner, times, attributes, signer, zone, entropy |
| `network` | direction, transport? | protocol stack, community ID, bytes/packets, interface, VLAN, application |
| `source_endpoint` / `destination_endpoint` | IP or domain or service | port, NAT address/port, MAC, geo, ASN |
| `cloud` | provider, account/project/subscription | region, service, resource ID/type, availability zone |
| `container` | runtime ID | image/name, namespace, pod, labels, orchestrator, node |
| `identity` | provider, subject | tenant, session, auth method, device, application, conditional-access result |
| `email` | message ID | sender, recipients, subject hash/plain per policy, URLs, attachments, direction, mailbox action |

## Event families

Each family inherits the envelope. “Required” below is in addition to envelope requirements.

| Event schema | Required fields | Optional fields / relationships | Primary sources and normalization |
|---|---|---|---|
| `process.lifecycle/1.0` | action=`start|end|access|inject`, host, process PID/entity, event time | parent process, user, hashes, signer, exit code, target process, call trace | Sysmon 1/5/10, ETW, Linux audit/eBPF/Falco, macOS endpoint source, Velociraptor. Process entity key uses host+boot+PID+start time; absent start time lowers confidence. |
| `file.activity/1.0` | action=`create|modify|delete|rename|open|execute|quarantine`, host, file path/artifact | process, user, old path, bytes, hashes, signer | Sysmon 11/15/23/26, Wazuh FIM, Falco, agent. Never imply content hash if source supplies only path. |
| `registry.activity/1.0` | action, host, registry hive/key | value name/type/data hash, process, user | Sysmon 12–14, Wazuh, Velociraptor. Canonical hive names; retain original path. |
| `service.activity/1.0` | action=`install|start|stop|modify|delete`, host, service name | image path, start type, account, process | Windows SCM logs/Sysmon/Wazuh; Linux systemd normalized with `service.manager`. |
| `scheduled_task.activity/1.0` | action, host, task/job ID | trigger, command, principal, source manager | Windows Task Scheduler, cron/systemd timers, launchd; source-specific definition preserved. |
| `module.load/1.0` | host, process, module path/name | hashes, signer, base address, signature status | Sysmon 6/7, ETW, agent/eBPF. Driver loads set `module.kind=driver`. |
| `script.activity/1.0` | language/engine, action, host/user | process, content hash, script block ID, AMSI verdict, obfuscated flag | PowerShell logs/AMSI, shell audit; content stored by classification policy, often hash/reference only. |
| `network.flow/1.0` | event time, source/destination endpoints, direction | process, user, bytes/packets, community ID, protocol | Sysmon 3, Zeek conn, Suricata flow, Falco/eBPF, cloud flow logs. Zeek/Suricata community ID preferred for joins. |
| `dns.activity/1.0` | action=`query|response`, question name/type | answers, response code, resolver, client process/host, TTL | Sysmon 22, Zeek dns, Suricata DNS, cloud resolver. Domains lower-case/Punycode plus original. |
| `http.activity/1.0` | request/response action, endpoints, method or status | host, URI components, headers allowlist, user agent, bytes, TLS link | Zeek/Suricata/cloud proxy. Credentials and sensitive query values redacted at ingest. |
| `tls.session/1.0` | endpoints, negotiated version? | SNI, JA3/JA4-like fingerprints, certificate refs, cipher | Zeek ssl/x509, Suricata TLS, cloud/network tools. Fingerprint algorithm explicitly named. |
| `authentication.activity/1.0` | action=`logon|logoff|token|challenge`, outcome, subject, provider | target resource, source IP, device, factor, failure reason, session | Windows security logs, Linux auth/audit, cloud identity. Interactive/service/network logon mapped to `auth.type`; raw code retained. |
| `authorization.activity/1.0` | subject, resource, decision | policy, role, reason, session | Cloud audit/IAM/app audit. Do not infer authentication success from authorization alone. |
| `account.activity/1.0` | action=`create|modify|disable|delete|credential_change|role_change`, identity | actor, changed fields, group/role | Windows/Linux directory, Entra/Okta/cloud IAM. Before/after values policy-masked. |
| `device.activity/1.0` | action=`connect|disconnect|mount|block`, host, device class | vendor/product/serial hash, volume, user | Windows device events/Wazuh/osquery/agent. Serial values treated as sensitive. |
| `kernel.runtime/1.0` | action, host, subject | syscall/event name, args allowlist, process, container | Falco/eBPF/audit. High-volume args constrained and source rules preserve original. |
| `container.activity/1.0` | action, container and host/node | image, process, orchestrator, workload identity | Falco, Kubernetes/cloud audit, agent. Runtime and orchestrator identities kept separately. |
| `cloud.audit/1.0` | provider, account, service, action, actor, outcome | region, resource, request ID, source IP, user agent, changed fields | AWS CloudTrail, Azure activity, GCP audit. Provider event ID participates in dedupe. |
| `email.activity/1.0` | action=`send|receive|deliver|quarantine|click`, message ID/direction | sender/recipient, URLs, attachment hashes, auth results | Microsoft/Google/email gateway. Body is not telemetry by default; stored only as classified artifact. |
| `security.detection/1.0` | source detection ID, rule/signature ID, severity, outcome/time | MITRE techniques, evidence refs, flow/process/entities | Wazuh alerts, Suricata alerts, Falco rules, third-party alerts. Source severity and normalized severity both retained; source alert is not automatically a platform Finding. |
| `vulnerability.observation/1.0` | asset/package, vulnerability ID, observed time | version/fix, severity systems, exploitability, source | Wazuh vulnerability, OSV/scanners, cloud findings. CVSS vector retained; risk score separately computed. |
| `inventory.snapshot/1.0` | endpoint, inventory type, observed time, snapshot/delta mode | items and prior snapshot | osquery/Fleet, Wazuh, agent. Large items externalized; stable item identity enables deltas. |
| `evidence.collection/1.0` | collection/job ID, target, artifact manifest, custody action | tool/artifact version, errors, bytes, duration | Velociraptor/platform agent. Results become Evidence only after hash verification/sealing. |
| `agent.health/1.0` | agent/endpoint, status, observed time | queue depth, dropped events, collector health, config/update version, resource cost | Native agent/adapters. Dropped-event counters never sampled away. |

## Source adapters

| Source | Identity/deduplication | Mapping requirements | Source-specific caveat |
|---|---|---|---|
| Windows native/Sysmon | channel+record ID+computer+boot epoch; source GUID where present | Event ID/version-specific parser; SID resolution produces separate enrichment | Event Log overwrite/gaps represented by `telemetry.gap`; Sysmon is optional, not sole sensor |
| Linux audit/eBPF/Falco | boot ID+CPU/source sequence or source event ID | Correlate multipart audit records before normalize; preserve syscall architecture | Loss counters and kernel compatibility are mandatory health data |
| macOS | source sequence+boot ID+process audit token | Preserve signing/notarization, responsible process and user session | Authorization/privacy settings affect visibility and must be health state |
| Wazuh | manager/agent+alert/event ID+timestamp | Preserve decoder/rule IDs, groups and original severity; map only supported data | A Wazuh alert becomes `security.detection`, not a confirmed platform Finding |
| Velociraptor | client+flow+artifact+row ordinal | Artifact schema registered per version; file results map to manifests | VQL output is untrusted typed input; artifact version is compulsory |
| osquery/Fleet | host identifier+action/query+calendar time+row hash | Distinguish snapshot/differential/evented tables and query version | Query result is state at time, not proof of prior activity |
| Suricata | sensor+flow/event ID; community ID for flow joins | Map EVE type-specific payload; preserve signature metadata | Packet visibility and capture drops recorded separately |
| Zeek | sensor+UID+log type+timestamp | Log schema/version registered; UID and community ID retained | Zeek log represents analysis observation, not necessarily maliciousness |
| Falco | sensor+event sequence+rule/output hash | Map raw runtime fields and rule output independently | Rule message text is not parsed when typed fields exist |
| Cloud | provider event ID+account+region | Provider/account/resource IDs mandatory; ingest delay recorded | API backfill duplicates expected; eventual ordering handled |
| Identity | provider event ID+tenant | Normalize subject, session, device, factor and policy outcome | PII/classification and clock sources explicitly recorded |
| Email | provider event/message/trace IDs | Normalize envelope identities, links and attachments; body excluded by default | Message IDs may be rewritten across gateways; relationships carry confidence |

## Compatibility and evolution

1. Patch versions clarify validation without changing accepted data. Minor versions add optional fields/enums. Major versions change meaning, required fields or structure.
2. Producers declare exact version; consumers declare supported ranges. Ingestion retains unsupported raw events and routes them to quarantine instead of discarding.
3. Canonical schemas never remove a field within a major version. Deprecation lasts at least two minor releases and one year.
4. Normalizers are pure, reproducible transformations identified by parser version and mapping ID. Golden fixtures include raw input, expected canonical output and warnings.
5. Reprocessing writes a new projection linked through `event.supersedes`; it never mutates the prior normalized event.
6. Extension keys use reverse-domain namespaces, have registered schemas and cannot redefine canonical meaning.
7. Sensitive fields carry classification tags used by storage, API masking, export and AI retrieval.

## Sprint 8 persistence-event.v1 specialization

`persistence-event.v1` is the implemented Windows service/scheduled-task envelope. It requires tenant, endpoint, installation, event, schema, collector/source/version, native provider/channel/event identity, sequence, observed/received/ingested timestamps, normalization version, evidence SHA-256, and quality state. Exactly one typed `service` or `scheduledTask` object is present.

Service identity is tenant + endpoint + installation + case-normalized canonical service name + lifecycle generation. Task identity substitutes case-normalized full task path. A native deletion advances the durable generation; delayed/out-of-order flags preserve ordering uncertainty. Process relationships require native PID plus process-start identity and record source/confidence/mechanism. Task XML is never retained wholesale: only policy-approved, bounded, safely parsed/redacted action and trigger fields plus its SHA-256 are stored.

## Sprint 9 persistence-configuration specialization

`persistence-event.v1` additionally permits exactly one `configuration` object when `objectKind=PersistenceConfiguration`. It records category/subtype, native object identity, namespace/location, name, Registry/File/configured-action paths, policy-permitted arguments, principal, filter/consumer/binding metadata, lifecycle timestamps, generation, state, source scope, mapping rule/version, confidence, ambiguity, redaction, and authoritative raw Registry/File event references.

WMI filter, consumer, and binding identities are distinct. COM, autorun, startup-configuration, and Startup-folder observations are derived relationships; their Registry/File events remain authoritative. A configured action never implies execution, creator identity, intent, or maliciousness. Late raw evidence may complete a relationship idempotently without changing event identity or history.
