# Known limitations

- Native Linux qualification and physical enterprise fleet/true-cluster scale are ENVIRONMENT BLOCKED.
- macOS signing/notarization, hosted CI and remote external-model qualification are EXTERNAL BLOCKED.
- Production Authenticode signing certificate/custody is unavailable. Current artifacts are hash-verified but do not claim publisher trust. Authenticode signing is required before distributing trusted Windows installers.
- Packet contents and arbitrary memory contents are not observable by current sources.
- Kernel-only visibility/prevention, unload events, source race/loss and some Windows native attribution fields have documented source-specific ambiguity.
- User-mode self-protection cannot guarantee resistance to a hostile kernel, offline disk access or a fully privileged Administrator.
- Performance/endpoint overhead numbers are from one Hyper-V Windows VM and a single-host Compose topology; they are not universal overhead or production SLA claims.
- Compose disables OpenSearch security and is development/qualification only.
- External AI is disabled by default and not qualified. Local evidence-grounded AI remains advisory and read-only.
- Falco/Linux collection is optional and not part of the Windows-first qualified package.
- MinIO Server is a deployment dependency under AGPLv3/dual licensing; it is not bundled, modified, or redistributed in the release artifacts, and production adopters must complete legal/procurement review or select a compatible S3 service.
