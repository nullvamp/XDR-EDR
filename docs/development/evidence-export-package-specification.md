# Investigation evidence package specification

An export selects 1-64 evidence IDs within one tenant investigation. The uncompressed ZIP contains selected immutable evidence objects and `investigation.json` with investigation metadata, bookmarks, accepted notes, custody, and request reason. Package size is bounded by policy; unavailable, failed, or over-bound items are never silently omitted.

The separate `investigation-evidence-package.v1` manifest binds package/tenant/investigation IDs, requested/included/excluded/failed/unavailable lists, per-artifact hashes, export timestamp/requester, package SHA-256, and byte size. Package and manifest are independent immutable MinIO objects with their own hashes.

Download requires server authorization and tenant lookup. Full and 1-8 MiB range/resume endpoints record custody; range responses include total size and exact package SHA-256. The caller verifies the reconstructed file against the manifest.

