# Security guide

Trust boundaries are tenant-authenticated browser/API access, mTLS endpoint channels, separately authenticated infrastructure stores, response approval boundaries, signed update bundles, protected endpoint state, and hash-bound forensic objects. Tenant identity is taken from validated credentials, never request-supplied object ownership.

Conservative defaults: external AI disabled; destructive response and playbook actions require explicit authorization/approval; Live Response is bounded, expiring, capability-scoped, transcript-audited, and exact-installation-bound; forensic sensitivity is classified and permission-gated; update packages require CA signature/hash/version/platform/architecture bindings; retention holds protect incident/forensic/audit evidence; searches and exports are bounded; self-protection fails closed at the supported user-mode boundary.

The gateway emits CSP, frame denial, MIME sniffing denial, no-referrer and restrictive permissions policy; sensitive APIs are `no-store`. CORS is not permissive. Browser tokens are session-scoped. Production UI/API access must use TLS at the reverse proxy; internal HTTP 8080 is not an Internet endpoint.

CA private keys never enter the MSI or release bundle. Store them offline or in an HSM/approved secret manager, restrict filesystem permissions, monitor expiry, rotate agent/server certificates, revoke compromised agent credentials, and document recovery. Production Authenticode certificate custody and signing are external release prerequisites. Self-protection cannot honestly prevent a hostile kernel or fully privileged Administrator from direct disk/offline manipulation.

AI local/private mode is default. External providers are opt-in and policy/model allow-listed; sensitive evidence and PII must be minimized and sovereignty requirements reviewed before enabling transmission.
