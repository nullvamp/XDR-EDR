# Approved forensic tool operations

The Tools view is inventory only. It reports recorded name/version, publisher/signature facts, SHA-256, staged/revoked state, and honestly labels absent OS, architecture, security-scan, expiry, and last-use data as not recorded. It exposes no execute control.

Execution requires a registered acquisition action, exact approved package/version/hash, allowed acquisition type, endpoint and installation binding, bounded typed arguments, policy permission, separated approval when required, expiry/revocation checks, and immutable response/custody audit. Free-form tool command lines and library-triggered execution are prohibited.

Operators revoke stale packages rather than replacing bytes in place. Full disk and memory profiles remain `ToolRequired` until a matching registered tool and acquisition capability are genuinely available.

