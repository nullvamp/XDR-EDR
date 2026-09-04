# Large-artifact transfer HA

Transfer authority is PostgreSQL, not gateway memory. The immutable start record binds tenant, endpoint, agent, installation, owner/evidence ID, artifact ID/name/type, expected size/hash, native identity, chunk size, and expiry. Each CAS version advances only monotonically and stores the verified ordered per-chunk hashes.

A reconnecting agent asks any gateway for the authoritative cursor, resends only the indicated chunk, and may safely repeat an already verified chunk. An exact duplicate is idempotent; different bytes for that chunk fail closed. Final assembly occurs only when chunk count, offsets, total size, per-chunk hashes, and overall SHA-256 all match. The object inventory then records expected size/hash in PostgreSQL.

Reproduce Profile D with:

`powershell -NoProfile -ExecutionPolicy Bypass -File testing/integration/sprint28-multi-gateway-transfer.ps1`

The 2026-08-11 run stopped gateway A after chunk 0; gateway B observed cursor 1, accepted the exact duplicate, rejected a conflicting duplicate with HTTP 400, completed 3/3 chunks, and returned 786,432 bytes with source/download SHA-256 `fd9a7ae150c5f400e64a3f092bf9c02b96e0ab42ad7af54faaa4e71fad1ea871`.

