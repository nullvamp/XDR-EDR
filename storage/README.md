# Database Migrations

Migrations are immutable paired `*.up.sql`/`*.down.sql` files with checksums recorded in `platform.schema_migrations`. Production rollback is allowed only when the release manifest marks a migration reversible and no incompatible writes occurred. Development seeds are never run automatically in production.

The Sprint Zero schema uses explicit high-value aggregates plus `domain_objects` for the remaining versioned Phase 2 objects until their owning service adds specialized indexes. This preserves the locked domain model without coupling every future aggregate to premature physical optimization.
