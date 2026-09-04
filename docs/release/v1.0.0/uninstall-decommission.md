# Uninstall and decommission

Uninstall is an authorized maintenance operation. From an elevated approved workflow run `msiexec /x OpenSecurityPlatform-Agent-1.0.0-x64.msi MAINTENANCEAUTHORIZED=1 /qn /norestart /l*v uninstall.log`. Omitting the exact property fails before the MSI removal transaction. This is Administrator-mediated protection, not a claim that a hostile Administrator is impossible to bypass.

Authorized uninstall stops/removes the service and payload, removes active telemetry queues, update staging/cache, forensic work, protected enrollment state, endpoint key material held in that state, and platform-owned isolation firewall groups. It preserves quarantine/persistence evidence and logs according to retention policy. Server-side endpoint, telemetry, response, forensic, and audit history remains.

Afterward verify the service and executable are absent, no worker is active, owned isolation rules and temporary queues are absent, and the backend transitions the installation offline through lifecycle aging. Revoke the agent credential and decommission the endpoint in the control plane under change/audit policy. A later reinstall uses a new one-time token and must produce a new installation identity.
