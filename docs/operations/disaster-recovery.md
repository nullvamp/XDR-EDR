# Disaster-recovery runbook

## Authority and roles

The incident commander authorizes recovery. A database operator restores PostgreSQL, a secrets custodian restores CA/signing/service secrets from external escrow, and a security verifier independently checks hashes and reconciliation. The application never prints secrets into drill evidence.

## Recovery sequence

1. Declare the incident, freeze writes or record the last defensible RPO boundary, and preserve logs/audit.
2. Recover PostgreSQL first and validate schema compatibility.
3. Restore external secrets and certificates without placing them in the database archive.
4. Verify/reconnect MinIO objects against `object_recovery_inventory`.
5. Start NATS, then gateways/workers, then OpenSearch.
6. Rebuild OpenSearch projections from PostgreSQL authority if counts/digests differ.
7. Reconcile every telemetry and control-plane domain, transfers, objects, response/playbook/update work, outbox, and NATS consumers.
8. Verify tenant isolation and health views, record `dr.completed`, and obtain release/incident-commander approval before traffic cutover.

## Tested drill

Backup `2df9dd2f-6b59-4717-b8f1-7bf6cb0d2ba5` restored into isolated database `platform_recovery_s28`. The recovery gateway became ready, 215 authoritative tables had zero differences, 334 point-in-time objects reconciled, and a post-backup marker was absent as expected. Restore time was 152.242 seconds; end-to-end measured RTO was 218.2 seconds. The tested RPO is the completed logical-backup boundary; post-backup writes are intentionally excluded. Recovery database/container and temporary in-container archive were removed after verification.

Automatic database leader election, clustered messaging/search/object storage, multi-region DNS/load balancing, and regional loss remain deployment-environment blockers and must not be represented as qualified.

