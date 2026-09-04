# Docker Desktop storage maintenance

## Workstation layout

- Repository: `D:\test\XDR-EDR`
- Docker Desktop application: `D:\DockerDesktop`
- Active Docker WSL data root: `D:\DockerDesktopDataFresh`
- Installer cache: `D:\Installers\Docker Desktop Installer.exe`
- Pre-reinstall recovery archive: `E:\DockerRecoveryArchive\docker_data.pre-reinstall-20260808.vhdx`

The recovery archive is not an active Docker disk. Do not attach, import, delete, or
overwrite it during normal development. Remove it only after the fresh platform has
been rebuilt, required data has been regenerated or recovered, and deletion is
explicitly approved.

## Storage policy

Keep at least 50 GB free on D:. Review Docker usage after large image rebuilds and at
the end of each sprint. PostgreSQL, OpenSearch, NATS, and MinIO volumes are project
data and must not be pruned as disposable cache.

## Stable local development topology

On this workstation, keep PostgreSQL, NATS, MinIO, OpenSearch, Falco, `gateway`, and
`agent` running. The gateway binary hosts the complete API and background-worker
surface. Leave the other twelve `Platform.ServiceHost` replicas stopped until their
database-pool ownership is refactored.

A measured single service-host process retained 88 idle PostgreSQL connections. The
thirteen-replica Compose topology therefore exhausted PostgreSQL's default 100-client
limit. Local PostgreSQL is capped at 200 server connections for headroom, but raising
it enough for thirteen duplicate hosts would waste memory and is not an acceptable
substitute for shared and bounded pool ownership.

Use `powershell.exe -ExecutionPolicy Bypass -File scripts/bootstrap-docker.ps1` for
a repeatable start. It waits for infrastructure, applies the idempotent development
seed, provisions the separate MinIO application identity and bucket, starts the
gateway, and enrolls an agent only when the database is fresh. One-time enrollment
credentials are held only in process memory and are not written to `.env`.

The twelve duplicate ServiceHost containers are gated by the Compose `distributed`
profile. Do not enable that profile for normal development. It remains an explicit
architecture qualification surface until service-specific hosting and
connection-pool ownership are implemented and validated.

Inspect usage before cleanup:

```powershell
docker system df -v
docker ps --all --size
docker image ls
docker volume ls
docker buildx du
Get-Volume -DriveLetter D | Select-Object DriveLetter, SizeRemaining, Size
```

## Safe routine cleanup

Stop the project without deleting volumes:

```powershell
Set-Location D:\test\XDR-EDR
docker compose down --remove-orphans
```

Remove only stopped containers, dangling images, and build cache older than seven
days:

```powershell
docker container prune --force
docker image prune --force
docker builder prune --force --filter "until=168h"
```

Run `docker system df -v` again and record the before/after totals. Restart the stack
and verify health before considering the cleanup complete.

## Prohibited unattended cleanup

Do not use any of these during normal maintenance:

```text
docker compose down --volumes
docker volume prune
docker system prune --volumes
wsl --unregister docker-desktop
```

Do not delete or move a Docker VHDX while Docker Desktop, WSL, or `vmmemWSL` is
running. Never replace Docker's configured data directory with a copied VHDX.

## VHDX compaction

Cleanup inside Docker does not automatically reduce the Windows VHDX file. Compact
only after the safe cleanup above, all containers are stopped, Docker Desktop is
fully exited, and `wsl --shutdown` has completed. Use Docker Desktop's supported disk
reclaim/compact control when available. Before any manual VHDX operation, verify the
exact configured disk path and create a tested backup; do not operate on the recovery
archive.

## Recovery archive retirement gate

The archive on E: may be deleted only when all of the following are true:

1. The clean Docker stack starts from the repository Compose files.
2. Database migrations complete successfully.
3. Required test data and acceptance evidence are present or reproducible.
4. PostgreSQL, OpenSearch, NATS, and MinIO checks pass.
5. The exact archive path and size are shown immediately before deletion.
6. The owner explicitly approves permanent deletion.
