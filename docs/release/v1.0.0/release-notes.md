# Open Security Platform 1.0.0 release notes

Version 1.0.0 is the first Windows-first engineering release candidate. It combines native Windows endpoint telemetry, evidence-backed detection/correlation and hunting, alert/incident investigation, safe response and Live Response, network isolation, reversible endpoint remediation, forensic collection with resumable large-artifact transfer, threat intelligence, playbooks, agent self-protection/update, fleet administration/RBAC/audit, backup/DR controls, capacity lifecycle, evidence-grounded AI and the unified SOC/DFIR interface.

The endpoint release is an x64 per-machine MSI/service. Enrollment is one-time-token plus certificate/mTLS based; sensitive state is protected at rest. Response and automation remain approval/policy bounded. External AI is off by default.

Upgrade is supported from 0.9.0 to 1.0.0 with backup, signed bounded update package, maintenance authorization and canary health gates. Compatible rollback is 1.0.0 to 0.9.0 only through explicit rollback policy.

Read `known-limitations.md` before deployment. This sign-off is Windows-first engineering qualification, not unrestricted production certification. Production Authenticode signing, native Linux, macOS, hosted CI, true cluster/fleet and external-model qualification are not claimed.
