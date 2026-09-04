<p align="center">
  <img src="docs/assets/logo-1677AD.svg" width="160" alt="Open Security Platform logo">
</p>

<h1 align="center">Open Security Platform</h1>

Open Security Platform is a Windows-first endpoint detection and response (EDR/XDR) project. It collects endpoint activity, detects suspicious behavior, helps analysts investigate incidents, and provides controlled response and forensic tools from one web interface.

> [!WARNING]
> This project is intended for labs, research, and controlled testing. Do not deploy it to production endpoints without reviewing the security settings, certificates, secrets, network exposure, and current limitations.

## What it provides

- Windows process, file, Registry, network, DNS, identity, persistence, service, scheduled-task, module, and execution telemetry
- Behavioral detections and stateful correlation mapped to MITRE ATT&CK
- Alert and incident investigation with timelines, process lineage, entity graphs, and threat hunting
- IOC matching and threat-intelligence management
- Audited Live Response with PowerShell, Command Prompt, and file transfer
- Endpoint isolation, process control, file quarantine, and persistence remediation
- Remote forensic collection with hashing, evidence manifests, and chain-of-custody records
- Role-based access control, client and endpoint management, policy control, and immutable audit history
- Signed agent update and rollback workflows
- Evidence-grounded AI assistance with citations and bounded permissions

## Current status

The qualified endpoint target is Windows 11 x64. The backend and web interface run locally with Docker Compose.

Linux endpoint support, macOS support, production code signing, physical fleet-scale testing, and true multi-node production deployment are not currently qualified. Some low-level Windows activity cannot be collected without a kernel component; unsupported evidence is reported as unavailable rather than invented.

See the [Windows support matrix](docs/release/v1.0.0/windows-support-matrix.md) and [known limitations](docs/release/v1.0.0/known-limitations.md) before testing the platform.

## Requirements

- Windows 11 x64 development host
- PowerShell 7 or Windows PowerShell 5.1
- .NET 8 SDK
- Docker Desktop with WSL 2 enabled
- Git

Administrative rights are required only for operations that need native Windows access, such as installing or qualifying the endpoint agent. Run endpoint tests inside a dedicated test VM, not on your daily-use computer.

## Quick start with Docker

Clone the repository and create a local environment file:

```powershell
git clone https://github.com/nullvamp/XDR-EDR.git
cd XDR-EDR
Copy-Item .env.example .env
```

Replace every placeholder in `.env` with a unique local value. Never commit this file.

Start the local stack:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start.ps1 -Docker
```

Open the web interface at [http://localhost:8080](http://localhost:8080).

To stop the Docker stack while keeping its stored data:

```powershell
docker compose -f deployment/docker-compose.yml down
```

The Docker profile is for local development. Do not expose PostgreSQL, NATS, MinIO, OpenSearch, port `8080`, or the endpoint-management listener directly to the Internet.

## Local development mode

The platform can also run directly with .NET for development:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start.ps1
```

The local UI/API is then available at [http://127.0.0.1:5080](http://127.0.0.1:5080). Stop it with:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/stop.ps1
```

This mode uses development-only settings and is not a production deployment.

## Install an endpoint agent

The Windows agent must be built, enrolled, and installed using credentials and certificates created for your environment. Do not reuse development enrollment values on another network.

Start with:

- [Installation guide](docs/release/v1.0.0/installation.md)
- [Deployment guide](docs/release/v1.0.0/deployment.md)
- [Upgrade and rollback](docs/release/v1.0.0/upgrade-rollback.md)
- [Security guide](docs/release/v1.0.0/security.md)

## Using the platform

- [Analyst guide](docs/release/v1.0.0/analyst-guide.md)
- [Administrator guide](docs/release/v1.0.0/administrator-guide.md)
- [DFIR guide](docs/release/v1.0.0/dfir-guide.md)
- [Backup and restore](docs/release/v1.0.0/backup-restore.md)
- [Troubleshooting](docs/release/v1.0.0/troubleshooting.md)

## Build and test

```powershell
dotnet restore SecurityPlatform.sln --locked-mode
dotnet build SecurityPlatform.sln -c Release --no-restore
dotnet run --project testing/Platform.Tests/Platform.Tests.csproj -c Release --no-build
```

Build warnings are treated as errors. Endpoint response and malicious-behavior simulations must be run only inside an isolated test VM.

## Architecture

The platform uses C#/.NET for the agent and backend, PostgreSQL for authoritative state, OpenSearch for search projections, NATS JetStream for messaging, MinIO for evidence objects, and a JavaScript/HTML/CSS web interface.

Important design rules include:

- All records and actions are scoped to a client and tenant.
- Raw evidence is immutable; searchable projections can be rebuilt.
- Endpoint actions require exact targets and produce audit records.
- Durable queues support offline buffering and controlled replay.
- Missing or unsupported telemetry is shown honestly.

See the [system architecture](docs/architecture/system.md), [API specification](docs/api/api-specification.md), and [telemetry schema](docs/schemas/telemetry.md) for more detail.

## Security

Do not report security vulnerabilities through a public issue. Follow [SECURITY.md](SECURITY.md) for private reporting instructions.

This repository does not include production credentials, private keys, endpoint certificates, collected evidence, malware samples, or customer data.
