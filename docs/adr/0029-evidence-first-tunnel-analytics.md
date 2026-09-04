# ADR 0029: Evidence-first tunnel analytics

Status: Accepted for Sprint 24

## Decision

Tunnel analytics consumes canonical process, listener, connection, DNS, identity, module, and intelligence evidence. It stores immutable `tunnel-observation.v1` records and deterministic `TunnelFinding` records. Every relationship carries source event IDs and authoritative references. A relationship is omitted when an endpoint hop cannot be proven.

Chain traversal is capped at depth 4 and 64 observations. Queries are capped at 200 records and 31 days; ingest batches at 256 observations; DNS feature windows at 10 minutes and 10,000 samples. Cycles and already-visited observations terminate traversal. Tenant-bound cursors fail closed.

## Deterministic confidence

- Classified tunnel behavior: +25.
- Source-backed listener: +15.
- Source-backed remote connection: +15.
- Stable process attribution: +10.
- Three or more distinct clients: +20.
- Five or more remote destinations: +20.
- Five-minute duration: +10.
- DNS: volume plus unique-subdomain ratio +25; label length plus entropy +25; high-frequency low-jitter cadence +20; high NXDOMAIN ratio +10.
- Score is capped at 100: Low <60, Medium 60–79, High ≥80. Each rule also has a minimum threshold.

Tool presence alone never produces a finding. Port 443 does not prove HTTPS, UDP does not prove QUIC, and encrypted traffic does not prove tunneling. ICMP covert-channel semantics are `NOT OBSERVABLE BY SOURCE`. There is no packet capture, DPI, decryption, opaque ML, or automatic response.

## DNS feature formulas (`dns-tunnel-features.v1`)

- Query and label lengths are Unicode string lengths after lower-case/trailing-dot normalization.
- Unique-subdomain ratio = distinct subdomain strings / query count, using the supplied registered domain or the final two labels.
- Shannon entropy = `-Σ p(character) × log2(p(character))`, averaged across labels.
- Encoded-character ratio = alphanumeric characters / all label characters.
- NXDOMAIN ratio = negative responses / query count.
- Mean interval and population coefficient of variation use event-time-ordered adjacent query intervals.
- Record-type distribution is an exact, case-normalized count.

## Consequences

The model is explainable, replayable, bounded, and searchable. Endpoint-only evidence cannot prove remote downstream hops or payload semantics; those remain explicit gaps. Findings enter the existing investigation and alert lifecycle, and IOC matches add context without proving either tunneling or maliciousness.
