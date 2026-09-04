# Repository Architecture and Ownership

## Monorepo policy

Use one logical monorepo through v1.0 to keep contracts, conformance tests, release metadata and security review atomic. Components may build and deploy independently. A later repository split is allowed only if it preserves code ownership, dependency direction, reproducible releases and contract tests.

## Complete target tree

```text
/
├─ docs/                    # Normative architecture, operations, security and contributor docs
├─ api/                     # OpenAPI, AsyncAPI, agent protocol and webhook contracts
├─ schemas/                 # Canonical event/domain JSON schemas and compatibility fixtures
├─ shared/                  # Language-neutral IDs, errors, envelopes and generated-contract policy
├─ backend/                 # Deployable control/data/experience-plane services
│  ├─ auth/                 # Authentication federation and session services
│  ├─ authorization/        # Central policy decision and relationship service
│  ├─ tenants/              # Tenant hierarchy, quota and residency service
│  ├─ endpoints/            # Device registry and enrollment authority
│  ├─ policy/               # Desired-state policy and configuration resolution
│  ├─ ingest/               # Intake, validation, metering and routing
│  ├─ normalization/        # Parsers, canonical mapping and provenance
│  ├─ detection/            # Rule registry, compilation and execution
│  ├─ correlation/          # Finding aggregation and incident/entity graph
│  ├─ threat-intelligence/  # CTI gateway, cache, confidence and TLP enforcement
│  ├─ response/             # Action policy and provider-independent response
│  ├─ jobs/                 # Durable remote-job orchestration
│  ├─ evidence/             # Evidence manifests, custody and export
│  ├─ dfir/                 # Collection plans and forensic workflows
│  ├─ hunt/                 # Federated hunting and saved queries
│  ├─ timeline/             # Time-normalized investigation views
│  ├─ cases/                # Cases, investigations, tasks and collaboration
│  ├─ connectors/           # Connector registry and managed execution
│  ├─ plugins/              # Plugin catalog, trust and lifecycle
│  ├─ notifications/        # Routed notifications and preferences
│  ├─ reporting/            # Scheduled and on-demand reporting
│  ├─ ai/                   # Evidence-grounded model gateway and evaluations
│  ├─ audit/                # Append-only audit ingestion and verification
│  ├─ metering/             # Quotas, entitlements and usage reconciliation
│  └─ gateway/              # Public API edge, rate limits and request routing
├─ agent/                   # Cross-platform agent protocol, common core and packaging specs
│  ├─ core/                 # Identity, transport, spool, policy and job runtime
│  ├─ windows/              # Windows collectors/providers and installer
│  ├─ linux/                # Linux/eBPF/Falco integration and packages
│  ├─ macos/                # macOS endpoint integration and package
│  ├─ updater/              # Signed staged update and rollback subsystem
│  └─ test-harness/         # Host simulation and protocol conformance
├─ frontend/                # Web experience organized by stable domain boundary
│  ├─ shell/                # Navigation, tenant/workspace context and permissions
│  ├─ endpoints/            # Device inventory and health
│  ├─ detections/           # Alerts/findings/rules
│  ├─ investigations/       # Incidents, cases, timeline and graph
│  ├─ response/             # Jobs, approvals and live operations
│  ├─ threat-intelligence/  # CTI views
│  ├─ reports/              # Dashboards and reporting
│  ├─ marketplace/          # Plugins/integrations
│  └─ design-system/        # Accessible tokens and components
├─ integrations/            # Product-owned adapters to external systems
│  ├─ velociraptor/         # DFIR provider
│  ├─ osquery-fleet/        # Query/inventory provider
│  ├─ sysmon/               # Windows event source
│  ├─ wazuh/                # Wazuh event/rule bridge
│  ├─ zeek/                 # Network metadata source
│  ├─ suricata/             # NIDS event source
│  ├─ arkime/               # Packet evidence provider
│  ├─ falco/                # Runtime event source
│  ├─ opencti/              # CTI knowledge provider
│  ├─ misp/                 # CTI sharing provider
│  ├─ thehive/              # External case provider
│  └─ cortex/               # Analyzer/responder provider
├─ plugins/                 # First-party reference plugins and manifests
├─ sdk/                     # Connector, detection, collector, response, CTI, AI, UI, parser SDKs
├─ storage/                 # Storage adapters, migrations and conformance suites
├─ search/                  # Search adapters, query IR and conformance suites
├─ messagebus/              # Event catalog, queue adapters and AsyncAPI documents
├─ marketplace/             # Catalog metadata, admission policy and signatures
├─ testing/                 # Cross-component fixtures and test environments
│  ├─ conformance/          # Contract/provider replacement suites
│  ├─ replay/               # Versioned attack and telemetry corpora
│  ├─ performance/          # Endpoint/backend benchmark scenarios
│  ├─ security/             # Tenant, authz, fuzz and adversarial cases
│  ├─ chaos/                # Failure and recovery experiments
│  └─ e2e/                  # Supported user journeys
├─ deployment/              # Supported deployment profiles and release manifests
│  ├─ docker/               # Developer/single-node profile
│  ├─ helm/                 # Enterprise Kubernetes profile
│  ├─ airgap/               # Signed offline bundles and verifier metadata
│  └─ appliance/            # Optional managed appliance profile
├─ infrastructure/          # Declarative cloud/on-prem infrastructure modules
├─ tools/                   # Contract lint, schema migration, signing and release tools
├─ scripts/                 # Thin documented task entry points; no business logic
├─ .github/                 # CI policy, ownership, issues and PR workflows
├─ CODEOWNERS               # Path-based accountable reviewers
├─ SECURITY.md              # Disclosure and security support policy
├─ CONTRIBUTING.md          # Contribution workflow
└─ README.md                # Repository entry point
```

## Folder responsibility matrix

| Folder | Responsibility | Allowed dependencies | Accountable owner | Future expansion |
|---|---|---|---|---|
| `docs` | Normative decisions and runbooks | All public contracts; no runtime | Architecture Council | Generated portal and translations |
| `api` | Client-facing synchronous/streaming contracts | `schemas`, `shared` | API Council | Graph query endpoint only by ADR |
| `schemas` | Canonical portable data contracts | None except published standards | Data Architecture | Protobuf/Avro projections generated from canonical definitions |
| `shared` | Minimal cross-language conventions | `schemas` | Platform Foundations | Generated bindings; never business logic |
| `backend` | Independently deployable domain services | API/schema contracts and declared ports | Domain teams | Service extraction/merger via ADR |
| `agent` | Privileged endpoint execution | Agent protocol only; no backend internals | Endpoint Security | Mobile/OT collectors after Phase 3 |
| `frontend` | Browser experience | Public API SDK and design system | Product Experience | Desktop/offline investigation client |
| `integrations` | Anti-corruption adapters | SDKs and vendor public APIs | Integrations | Certified community providers |
| `plugins` | Reference extension packages | SDK only | Ecosystem | Community catalog |
| `sdk` | Stable extension contracts and harnesses | `api`, `schemas` | Developer Platform | More language bindings |
| `storage` | Persistence ports and adapters | Interface catalog | Data Platform | Sovereign/edge adapters |
| `search` | Query IR and search provider abstraction | Schema registry | Search Platform | Federated/local search |
| `messagebus` | Event envelope/catalog and transport adapters | Schemas | Platform Foundations | Cross-region federation |
| `marketplace` | Trust/catalog policy | Plugin manifests/signing | Ecosystem Security | Commercial settlement |
| `testing` | Shared verification assets | Public contracts only | Quality Engineering | Independent certification kit |
| `deployment` | Supported installation artifacts | Versioned release manifests | Release Engineering | Sovereign profiles |
| `infrastructure` | Provisioning composition | Deployment contracts | SRE | More providers without product semantics |
| `tools` | Build/release/contract automation | Repository metadata | Developer Productivity | External developer CLI |
| `scripts` | Discoverable task wrappers | `tools` | Developer Productivity | Must remain disposable |

## Dependency rules

1. Domain services never import another service's persistence model; they call a versioned API or consume a versioned event.
2. Integrations depend inward on SDK ports. Core domains never import integration implementations.
3. Frontend uses generated public API clients; it never queries databases.
4. Agent code does not share backend business libraries. The agent protocol is the boundary.
5. Storage/search/message-bus adapters implement provider-neutral conformance contracts. Provider-specific types do not escape adapters.
6. Every directory has an owner, threat model, README, API/schema links, SLO and test strategy before implementation begins.

