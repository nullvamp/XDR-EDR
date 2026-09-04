# macOS Endpoint Security process collector

This notification-only companion subscribes exclusively to `ES_EVENT_TYPE_NOTIFY_EXEC` and `ES_EVENT_TYPE_NOTIFY_EXIT`, writes bounded JSONL intermediate records, and never authorizes or blocks execution. Build with `./build.sh` on macOS 13+ using an Apple-issued signing identity carrying `com.apple.developer.endpoint-security.client`. Deployment additionally requires notarization, user approval, Full Disk Access where mandated by the target macOS release, a root launch daemon with protected output directory, and an entitled physical/virtual macOS runtime. Ad-hoc signing proves compilation only and cannot create an Endpoint Security client.

Runtime evidence must include `codesign -d --entitlements :-`, notarization output, successful `es_new_client`, observed exec/exit records, sequence-gap and restart tests, and the existing Keychain round-trip test.
