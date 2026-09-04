# Forensic evidence and provenance specification

An evidence record binds tenant, investigation, collection, endpoint, installation, evidence type, requested source, acquisition mechanism, native/source identity where reported, source/acquisition timestamps, byte/chunk counts, SHA-256, object abstraction, manifest identity, parser state, and relations. Internal object-store credentials are never returned.

Source artifacts are immutable. Verification compares downloaded object bytes, recorded SHA-256, object metadata, size, and source collection manifest. Results are `Verified`, `Mismatch`, `Missing`, or `VerificationFailed`; mismatches are surfaced as high severity. Tag, bookmark, note, relation, hold, and export operations do not alter source bytes.

Parser outputs are new evidence objects. Each binds `derivedFromEvidenceId`, parser ID/version, source hash, source record identity/offset when available, output hash, timing, warnings, and record count. Re-running a parser creates another output rather than overwriting history.

Unavailable and partial records remain visible with precise failure code/detail. Collection and parser support states are distinct and must use `CollectionSupported`, `ParsingSupported`, `CollectionAndParsingSupported`, `CollectionOnly`, `ToolRequired`, `NotSupported`, or `NotValidated`.

