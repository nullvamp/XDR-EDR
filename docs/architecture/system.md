# System Architecture and Engineering Diagrams

## Endpoint network telemetry vertical

Windows kernel TCP/IP ETW or Linux Falco syscall JSON → evidence-preserving `network-event.v1` normalization → bounded crash-safe queue → gzip over endpoint-bound mTLS → gateway validation → PostgreSQL authority and transactional outbox → explicit-ACK NATS JetStream → versioned OpenSearch index/atomic alias → tenant-bound APIs, UI, and MinIO export. Collector-partition failures are isolated. Packets, payloads, DNS, URLs, TLS/HTTP content, detection, and response are outside this path.

## Trustworthy Windows Registry telemetry vertical

The elevated Windows agent consumes `Microsoft-Windows-Kernel-Registry` through the established owned ETW session model, preserves native callback semantics and resolution quality, and sends canonical registry observations through the shared crash-safe queue, gzip batch, and endpoint-bound mTLS channel. The gateway assigns tenant and server timestamps, validates source/schema/limits/policy, and commits event/entity/history plus `registry.changed` outbox state atomically. A durable explicit-ACK JetStream consumer projects into a versioned index behind the atomic `platform-registry-events` alias. Tenant-filtered APIs/UI provide search, detail, histories, endpoint timeline, process relationships, health, policy/exclusions, and policy-preserving MinIO exports.

PostgreSQL is authoritative. Projection rebuild is system-global and requires `system:admin`. Capture is metadata-only by default; hashes and bounded previews require explicit allowed path/type policy, and preview reads require sensitive-data permission. See [ADR 0004](../adr/0004-windows-registry-telemetry.md).

## Trustworthy process telemetry vertical

The enrolled agent normalizes platform collector observations, persists them to a bounded local queue, and sends integrity-protected gzip batches over its existing mTLS identity. The gateway binds certificate subject, active agent, endpoint, installation, and tenant before validation. One PostgreSQL transaction deduplicates events, merges the execution entity, records health/loss state, and creates versioned outbox messages. NATS carries `process.telemetry.v1`; durable idempotent consumers update the `platform-processes` OpenSearch alias. Analyst APIs and UI always apply tenant scope and expose provenance and missing-data states. See ADR 0003 for collector limitations.

## Context and component view

```mermaid
flowchart TB
  Analyst[Analyst / administrator] --> Web[Web application]
  Client[API / SIEM / SOAR client] --> Gateway[Public API gateway]
  Web --> Gateway
  Endpoint[Endpoint agent] <--> AgentEdge[Agent gateway]
  Sources[Cloud / identity / email / network] <--> Connectors[Connector runtime]
  Gateway --> Control[Control plane services]
  AgentEdge --> Ingest[Ingestion + normalization]
  Connectors --> Ingest
  Ingest --> Evidence[(Raw and evidence store)]
  Ingest --> Bus[Message bus]
  Bus --> Analytics[Detection / entity / correlation]
  Analytics --> Search[(Search + graph projections)]
  Control --> Jobs[Job / response orchestration]
  Jobs --> AgentEdge & Connectors
  Gateway --> Experience[Cases / hunt / timeline / reports / AI]
  Experience --> Search & Evidence
  Audit[Immutable audit] -. records .- Gateway & Control & Jobs & Connectors
```

## Module dependency graph

```mermaid
flowchart LR
  IAM[Authentication] --> AUTHZ[Authorization]
  TEN[Tenant] --> AUTHZ
  REG[Endpoint Registry] --> POL[Policy + Config]
  POL --> EDGE[Agent Gateway]
  EDGE --> ING[Ingest]
  ING --> NORM[Normalization]
  NORM --> DET[Detection]
  NORM --> RES[Entity Resolver]
  DET --> CORR[Correlation]
  RES --> CORR
  CTI[Threat Intelligence] --> DET & CORR
  CORR --> CASE[Cases / Investigation]
  NORM --> TL[Timeline / Hunt]
  CASE --> RESP[Response]
  RESP --> JOB[Job Orchestrator]
  JOB --> EDGE & CON[Connectors]
  EV[Evidence] --> CASE & TL
  AUTHZ -. guards .-> REG & POL & DET & CASE & RESP & EV
  AUD[Audit] -. records .-> AUTHZ & POL & RESP & EV
```

## Agent enrollment and telemetry sequence

```mermaid
sequenceDiagram
  participant A as Agent
  participant E as Agent Gateway
  participant R as Endpoint Registry/PKI
  participant P as Policy Service
  participant I as Ingestion
  participant B as Message Bus
  A->>E: Register(enrollment proof, CSR, capabilities)
  E->>R: Validate token and device identity
  R-->>E: Agent ID and signed certificate
  E->>P: Resolve bootstrap configuration
  E-->>A: Certificate, trust roots, config snapshot
  A->>E: Check-in(config ack, health, sequences)
  E-->>A: Job leases and update hints
  loop Signed batches
    A->>E: Event batch(sequence range, digest)
    E->>I: Authenticated tenant/source batch
    I->>I: Persist raw, validate, meter
    I->>B: Canonical events + receipt
    E-->>A: Accepted/rejected sequence ranges
  end
```

## Detection to governed response

```mermaid
sequenceDiagram
  participant D as Detection Engine
  participant C as Correlation/Case
  participant U as Analyst
  participant Z as Authorization
  participant R as Response Engine
  participant J as Job Orchestrator
  participant P as Provider/Agent
  D->>C: Finding(evidence refs, reason, rule version)
  C-->>U: Incident and evidence graph
  U->>R: Request isolate(target, TTL, justification)
  R->>Z: Check permission, scope, risk and approval
  alt Approval required
    Z-->>R: Approval required
    R-->>U: Pending approval
    U->>R: Approved by distinct principal
  end
  R->>J: Durable idempotent action
  J->>P: Execute typed provider command
  P-->>J: Transition and signed result
  J-->>C: Response result + audit/evidence refs
```

## Plugin installation

```mermaid
sequenceDiagram
  participant Pub as Publisher
  participant M as Marketplace
  participant S as Supply-chain scanner
  participant T as Tenant administrator
  participant P as Plugin Manager
  participant R as Isolated Runtime
  Pub->>M: Signed package + SBOM + provenance
  M->>S: Verify, scan, test and policy review
  S-->>M: Admission report
  M-->>T: Approved immutable digest
  T->>P: Request install with bounded permissions
  P->>P: Authorization, compatibility, revocation check
  P->>R: Configure dedicated identity, secrets and egress
  R-->>P: Health/conformance result
  P-->>T: Activate or rollback
```

## Repository dependency view

```mermaid
flowchart TD
  DOC[docs] --- CONTRACTS[api + schemas]
  CONTRACTS --> SDK[sdk + shared]
  SDK --> BE[backend services]
  SDK --> AG[agent]
  SDK --> INT[integrations + plugins]
  CONTRACTS --> FE[frontend]
  BE --> ADAPT[storage + search + messagebus adapters]
  TEST[testing conformance/replay/security] --> BE & AG & INT & ADAPT & FE
  DEP[deployment + infrastructure] --> BE & ADAPT
```

## Enterprise deployment

```mermaid
flowchart TB
  subgraph R1[Primary region]
    LB1[Public/agent load balancers]
    K1[Service clusters across 3 zones]
    DB1[(Transactional HA)]
    Q1[(Quorum bus)]
    S1[(Search hot/warm)]
    O1[(Object/evidence)]
    LB1 --> K1
    K1 --> DB1 & Q1 & S1 & O1
  end
  subgraph R2[Recovery region]
    LB2[Standby endpoints]
    K2[Warm service capacity]
    DB2[(Replicated/PITR)]
    Q2[(Mirrored critical topics)]
    S2[(Snapshots/rebuild target)]
    O2[(Replicated evidence)]
    LB2 --> K2
    K2 --> DB2 & Q2 & S2 & O2
  end
  DB1 -. replicate .-> DB2
  Q1 -. mirror .-> Q2
  S1 -. snapshot .-> S2
  O1 -. policy replication .-> O2
  KMS[Regional KMS with governed recovery] --> R1 & R2
```
