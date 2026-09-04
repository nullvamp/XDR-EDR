# Disaster recovery

Declare the incident and recovery point, isolate the recovery environment, retrieve the latest verified backup and external secret/certificate dependencies, restore authoritative PostgreSQL/object data, validate schema 0034, rebuild projections, and start services under a fenced recovery owner. Reconcile before redirecting endpoints/users. Resume NATS consumers only after authority and projection state are coherent.

Record measured recovery-point and recovery-time values for each rehearsal. Sprint 38 values describe the single-host test environment only and are not a production SLA. A real cluster/fleet and geographic failure exercise remains environment-blocked.
