# Windows-first v1 support matrix

| Capability | Classification | Boundary |
|---|---|---|
| Windows x64 agent install/enroll/repair/uninstall/reinstall | Qualified | Windows 11 Enterprise build 26200 Hyper-V VM |
| Process/file/registry/network/DNS/module/persistence/identity/execution telemetry | QualifiedWithLimitation | Native sources; documented loss/ambiguity fields apply |
| Detection/correlation, ATT&CK coverage and hunting | QualifiedWithLimitation | Frozen Windows production packs and evidence-backed coverage only |
| Alerts/incidents/investigation/entity graph | Qualified | Single-host qualified topology |
| Safe response, Live Response, playbooks, isolation | QualifiedWithLimitation | Approval/policy/source boundaries; no hostile-kernel guarantee |
| Forensic collection and resumable artifact transfer | QualifiedWithLimitation | Approved sources/tools/bounds; no arbitrary memory or packet payload |
| Fleet update/rollback/self-protection | QualifiedWithLimitation | Signed platform bundle engineering chain; production Authenticode prerequisite |
| RBAC/admin/audit/tenant isolation | Qualified | Tested built-in roles and route inventory |
| Backup/restore/DR | QualifiedWithLimitation | Single-host isolated rehearsal, not production SLA |
| Local evidence-grounded AI | QualifiedWithLimitation | Advisory/read-only/citation-bound |
| External AI | ExternalBlocked | No qualified remote provider |
| Linux agent | EnvironmentBlocked | No supported native Linux qualification environment |
| macOS agent | ExternalBlocked | No signing/notarization environment |
| Packet contents | NotObservableBySource | Metadata only |
| Arbitrary memory contents | NotObservableBySource | No memory acquisition capability |
| True cluster/fleet scale | EnvironmentBlocked | No physical enterprise topology |
| Hosted CI | ExternalBlocked | No hosted runner integration |
