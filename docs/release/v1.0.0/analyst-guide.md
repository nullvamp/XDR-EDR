# SOC analyst guide

Start with Alerts/Incidents, confirm tenant and time range, review the evidence-backed attack story, process tree/entity graph and telemetry pivots, then preserve useful evidence in a case. Every claim should retain its PostgreSQL/OpenSearch/object reference and evidence hash.

Threat hunting uses bounded filters and result limits. Detection/correlation content is versioned; fixture validation and telemetry availability are distinct from ATT&CK mapping. Tune with simulation and review instead of broad exclusions. AI output is advisory and citation-bound; it cannot activate rules, modify policy, or execute response.

Response actions require the exact endpoint/agent/installation target, current evidence, policy, reason, and approvals. Isolation preserves the control/forensic channel by policy. Live Response commands, artifact transfers and staged tools remain bounded, audited, cancellable, hash-verified and subject to permissions. Escalate incomplete, ambiguous, source-limited, or stale evidence rather than inferring it.
