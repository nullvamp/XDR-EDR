# Backup and restore

The authoritative backup set contains PostgreSQL, object storage, configuration/version inventory, certificate/secret dependency references, and enough OpenSearch metadata to rebuild projections. NATS is transport, not the evidence authority. Before backup, record product 1.0.0/schema 0034, object counts/hashes, tenant inventory and active holds; use consistent snapshots or quiescence; hash the backup and protect encryption keys separately.

Restore only into an isolated environment first. Restore PostgreSQL and objects, supply external secrets/certificates, validate schema compatibility, start one gateway owner, rebuild/verify projections, and reconcile tenants, identities, policies, detections/correlations, alerts/incidents, response/audit, forensics, administration and objects exactly. Do not expose restored endpoints or enable response until validation passes.

Backup retention and encryption follow organizational policy. A backup is not valid until its hash and representative restore have passed.
