# ADR-0002: Sprint 1 endpoint enrollment identity

Status: accepted and implemented (2026-08-02).

Protocol 1.1 compatibly adds separate token identity/secret, nonce, timestamp, and idempotency key to the Phase 2 opaque token contract. The agent emits 1.1. Tenant ownership is resolved only from stored token metadata.

Enrollment uses one PostgreSQL transaction for token locking/use, idempotency, endpoint and installation identity, credential metadata, audit, and outbox. Endpoint identity hashes installation identity and public key; hostname or IP never merges endpoints.

The agent generates an ECDSA P-256 private key locally and submits a PKCS#10 CSR. The platform CA issues a 24-hour client-auth certificate containing a private identity extension binding tenant, endpoint, and installation. Every authenticated request validates the CA chain, client-auth purpose, validity window, identity binding, and active PostgreSQL credential record.

Renewal creates a new key and CSR, revokes the old credential metadata, stores the replacement thumbprint and expiry, and replaces the local credential. Endpoint revocation invalidates all installation credentials. Rotation begins four hours before expiry.

Windows credentials use machine-scope DPAPI, Linux uses a service-owned `0700` directory and `0600` state, and macOS uses Keychain. The plaintext adapter is explicitly development-only and rejected in production.
