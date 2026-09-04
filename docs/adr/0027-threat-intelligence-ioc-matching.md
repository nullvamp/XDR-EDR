# ADR 0027: Evidence-first threat intelligence and IOC matching

Status: Accepted, 2026-08-10.

Threat intelligence is tenant-scoped and PostgreSQL-authoritative. Sources, immutable indicator versions, imports, relationships, exact matches, bounded historical jobs, versioned exclusions, health and audit have separate persistence surfaces. Indicator and match outbox messages are projected through the existing NATS consumer into separate OpenSearch aliases.

Normalization is a security boundary. Each type has one canonical representation (`ioc-normalization.v1`); invalid IP families, CIDR prefixes, IDN labels, hash lengths, certificate thumbprints, URLs, Windows paths and Registry roots fail closed. Matching uses typed semantic adapters only—never generic text search. A match ID binds tenant, exact indicator version, evidence event, field and mode, and retains the authoritative evidence URI.

Live matching is bounded to 256 candidates and isolated from telemetry ingestion failures. Historical jobs pin the indicator version, require a positive range no longer than 31 days, cap candidates at 100,000, expose durable state/progress/cancellation, and produce deterministic IDs. Expired or revoked indicators retain history but leave the live active set. Exclusions annotate rather than delete matches.

IOC-match observations are valid detection/correlation primitives and evidence-backed investigation graph nodes/edges. Correlation and later alerting remain rule-driven; intelligence confidence is not opaque reputation, does not imply attribution, and never initiates response. STIX support is an explicitly bounded exact-pattern subset. TAXII is adapter-only and no full STIX/TAXII conformance is claimed.

