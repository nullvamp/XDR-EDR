# Technical forensic chain of custody

Custody is an append-only tenant/investigation sequence. Events bind actor/system principal, UTC timestamp, investigation, related collection/evidence, operation, result, source/destination abstraction, SHA-256 when applicable, and bounded detail.

Recorded operations cover request/approval, acquisition/source access, hashing, transfer/chunk verification, object storage/final verification, parser and derived creation, view/download/range access, package export, and hold application/release. The workspace offers chronological and accessible table views.

Custody bindings must resolve to an existing investigation and related collection/evidence. No mutation endpoint exists. This is an engineering integrity record and does not claim legal admissibility. Hold release requires `forensics:hold`, remains tenant-bound, marks the retention hold inactive, and appends `hold.released`.

