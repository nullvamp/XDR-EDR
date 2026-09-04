# Developer Setup, Build and Run Guide

## Requirements

- .NET SDK 8.0.423 or a compatible 8.0 patch.
- PowerShell 5.1+ for repository scripts.
- Docker with Compose v2 only for the complete infrastructure profile.

No global Node, Go, or JavaScript package-manager installation is required. The frontend uses browser-native modules.

## Build and verify

Run `powershell -ExecutionPolicy Bypass -File scripts/build.ps1`. The script uses the workspace SDK when present, restores only locked SDK/framework references, compiles Release with warnings as errors, and executes the dependency-free foundation tests.

Run `powershell -ExecutionPolicy Bypass -File testing/smoke.ps1` after a Release build to verify readiness, JWT login, authenticated tenant context, agent registration, heartbeat, and frontend delivery.

## Local run

`scripts/start.ps1` starts all bounded service processes on ports 5080–5092 and one agent. Gateway is 5080. The local bootstrap user is `admin` with password `local-development-password-change-before-use`; these values exist only in child-process environments and must never be used outside local development. Services write disposable state to `artifacts/run`.

Every service exposes `/health/live`, `/health/ready`, `/metrics`, and `/api/v1/openapi.json`. Registered instances are visible at gateway `/internal/v1/services`.

## Docker run

Copy `.env.example` to `.env`, replace all placeholders with independent secrets, and execute `scripts/start.ps1 -Docker`. Startup is fail-closed when required settings are absent, initializes fresh development storage, and keeps one-time enrollment credentials out of `.env`. Use `docker compose --env-file .env -f deployment/docker-compose.yml ps` and the gateway readiness endpoint to inspect health. The `distributed` Compose profile is a qualification surface, not the default local topology; see [Docker storage and topology maintenance](../operations/docker-storage-maintenance.md).

## Configuration and secrets

Configuration precedence is process environment over safe compiled defaults. Production deployment must inject secrets from an approved secret provider. Required names include `PLATFORM_JWT_SIGNING_KEY`, bootstrap credentials, database password, and MinIO password. Never commit `.env`.

## Migration and rollback

PostgreSQL migrations are paired in `storage/migrations`. A new database applies the up migration through its controlled runner/init profile. Rollback SQL exists for development and disaster recovery rehearsal; production rollback requires the release manifest and backup validation described in the standards.
