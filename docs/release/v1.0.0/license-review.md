# Lightweight dependency/license traceability

This inventory supports dependency traceability. It is not legal approval or a
substitute for reviewing the licenses of the exact components being distributed.

Distributed .NET/NuGet components are under the .NET Library License, MIT, Apache-2.0, or PostgreSQL License. Required license/notices are emitted beside the release artifacts and hashes. No distributed dependency identified a non-commercial restriction, network copyleft, strong copyleft, trademark license, or source-offer obligation beyond upstream notices/source references.

MinIO Server is AGPLv3/commercial dual licensed. The release does not bundle, modify, or redistribute its server image; Compose names it as a development/qualification deployment dependency. Production adopters must obtain legal/procurement approval for their selected S3-compatible service and comply with that service's license. This is explicit and is not treated as permission to redistribute MinIO.

Falco is Apache-2.0, optional, not bundled and not qualified for Windows v1. PostgreSQL uses the PostgreSQL License, NATS/OpenSearch use Apache-2.0. WiX, Syft and Trivy are build/scan tools and are not product payloads.

Before distributing binaries or offering the platform commercially, review the
redistribution terms, required notices, trademarks, product naming, and the
selected S3 deployment.
