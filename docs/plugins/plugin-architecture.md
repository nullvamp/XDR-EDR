# Plugin Architecture and SDK Specifications

## Trust model

Plugins are untrusted supply-chain inputs. They run outside core service processes in isolated containers initially; a constrained WASM runtime may be added later without changing SDK semantics. Each installation gets a dedicated service account, network policy, filesystem, resource quota and short-lived secret leases. Tenant data never enters a shared plugin instance unless the manifest and tenant policy explicitly allow a platform-operated multi-tenant mode.

## Package manifest

A signed package contains metadata only plus immutable referenced layers: `manifest_version`, reverse-domain `package_id`, name/version/publisher, plugin types, entrypoints, supported platforms, requested permissions, data classes, network destinations, secret schemas, configuration schema, input/output contract ranges, resource budgets, health checks, upgrade/migration declarations, dependencies, license, SBOM digest, artifact digests and signature chain.

Lifecycle: `submitted → scanned → reviewed → signed → published → requested → permission-approved → installed → configured → activated → upgrading/disabled → removed`; any version can become `revoked`, which blocks new activation and invokes policy-defined quarantine. Upgrade runs preflight, backup, migration in an isolated transaction, canary, health gate and rollback. Plugins may pin a compatible minor version; security revocation overrides pins.

## SDK catalog

| SDK | Lifecycle and core contract | Permissions/security | Compatibility and testing |
|---|---|---|---|
| Connector SDK | configure/test/start/stop; ingest batches, poll/cursor, webhooks and typed actions | Declared upstream hosts, secret refs, event/action scopes | Contract fixtures, rate-limit/retry/dedupe certification |
| Detection SDK | validate/compile/evaluate/explain; emits finding candidates only | Rule/data-field scopes, cost budgets; cannot perform response | Query IR + finding candidate versions; replay/golden/FP tests |
| Collector SDK | describe/plan/collect/cancel; emits typed results and artifact manifests | Endpoint artifact and command scopes, bandwidth/CPU/deadline | Offline, partial, malicious target and custody tests |
| Response SDK | capabilities/validate/execute/status/compensate | Action-specific high-risk grants; no self-approval | Idempotency, failure, rollback and blast-radius certification |
| Threat Intel SDK | pull/push/search/lookup; assertions with provenance/TLP/license | Feed secrets, egress allowlist, marking limits | STIX/MISP fixtures, expiry/dedupe/conflict tests |
| AI SDK | model completion/embedding/tool adapter; citation callbacks | No direct datastore; receives preauthorized context and bounded tools | Injection/leakage/citation/evaluation suite; model data-policy declaration |
| Dashboard SDK | register navigation/widgets and use public API client | CSP, no arbitrary DOM/global styles, declared API permissions | Accessibility, localization, performance and permission tests |
| Marketplace SDK | package submission/status, entitlement hooks and usage events | Publisher identity/signing roles; no customer data by default | Signature/SBOM/reproducibility and settlement reconciliation |
| Parser SDK | deterministic raw→canonical mapping with warnings and fixtures | No network; bounded CPU/memory; read-only raw event | Schema range, fuzz, golden fixtures and loss accounting |

## Distribution and signing

- Build outputs must be reproducible, include provenance attestation and complete SBOM, and be scanned for vulnerabilities, secrets, malware and license policy.
- Publisher signs the digest; marketplace countersigns after admission. Air-gapped catalogs use an offline root and signed revocation bundle.
- Runtime verifies trust chain, digest, tenant approval, compatibility and revocation on every activation.
- Secrets are referenced by logical names; SDK requests a short-lived lease when needed. Values never appear in config exports, logs, crash dumps or plugin state.
- Egress is deny-by-default at DNS and network layers; redirects and resolved IP changes are revalidated.

## Compatibility policy

SDK major versions may coexist. Minor versions are backward compatible. A package declares `[min,max)` ranges for each contract. The platform supports the current and prior SDK major for at least one year after successor GA. Marketplace blocks packages without a supported range. Data migrations must be forward-only with a tested compensating export/import path; plugin-owned state must be exportable in a documented format.

## Kill and recovery controls

The platform can disable by tenant, publisher, package, version, permission, destination or indicator. Disable stops new jobs, revokes leases and credentials, freezes state for inspection and records audit/custody events. Running destructive response jobs are transferred to the orchestrator’s recovery policy rather than abruptly abandoned.

