# Capacity planning guide

Use `/api/v1/capacity/estimate` only with a retained measured sample for the same platform version and comparable topology. Inputs are endpoint count, events per endpoint/day, retention days, measured PostgreSQL/OpenSearch bytes per event, forensic bytes per endpoint/day, redundancy, and required margin.

The Sprint 29 local sample is one native Windows victim, zero simulated endpoint identities, two gateways, and single PostgreSQL/OpenSearch/NATS/MinIO services. The 60-second mixed interval accepted 3,835 canonical events (63.917/s) and allocated 12,369,920 PostgreSQL bytes, or 3,225.53 bytes/accepted event in that short allocation window. Its 5,522,429 events/endpoint/day and roughly 17.8 GB PostgreSQL/endpoint/day extrapolations are profile-derived stress estimates, not expected customer behavior or physical scale claims.

Always retain: platform version, CPU/RAM/disk/network, topology/configuration, native versus simulated endpoint counts, event mix/size, duration, dataset age, retention, total records/bytes, p50/p95/p99/max, rejection/duplicate/loss counters, peak backlog, and drain time. Repeat on target hardware. Size to the first measured saturation point plus margin; do not extrapolate past a profile that lost correctness or failed to drain.

Current local bottlenecks: PostgreSQL client saturation appeared first before pool bounds were reduced; projection slowdown accumulated bounded backlog and recovered exactly; analyst DNS hunts degraded above basic searches on the ~652k-message local data set. True clustered and large physical endpoint limits are unqualified.
