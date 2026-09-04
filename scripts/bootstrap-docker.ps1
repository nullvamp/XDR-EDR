param(
    [int]$ReadyTimeoutSeconds = 180,
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $root "deployment\docker-compose.yml"
$envFile = Join-Path $root ".env"
$seedFile = Join-Path $root "storage\seeds\development.sql"
$temporaryAgent = "deployment-agent-bootstrap"

function Read-DotEnv([string]$Path) {
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\s*([^#=\s]+)=(.*)$') {
            $value = $matches[2].Trim()
            if ($value.Length -ge 2 -and (($value[0] -eq '"' -and $value[-1] -eq '"') -or ($value[0] -eq "'" -and $value[-1] -eq "'"))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            $values[$matches[1]] = $value
        }
    }
    return $values
}

function Invoke-Compose {
    & docker compose --env-file $envFile -f $composeFile @args
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed with exit code $LASTEXITCODE." }
}

function Wait-Until([string]$Description, [scriptblock]$Probe) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($ReadyTimeoutSeconds)
    do {
        try { if (& $Probe) { return } } catch { }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Timed out waiting for $Description."
}

if (-not (Test-Path -LiteralPath $envFile)) {
    throw "Copy .env.example to .env and replace every placeholder before Docker startup."
}

$settings = Read-DotEnv $envFile
$required = @(
    "PLATFORM_BOOTSTRAP_USER", "PLATFORM_BOOTSTRAP_PASSWORD", "POSTGRES_PASSWORD",
    "MINIO_ROOT_PASSWORD", "MINIO_APP_USER", "MINIO_APP_PASSWORD"
)
foreach ($name in $required) {
    if (-not $settings.ContainsKey($name) -or [string]::IsNullOrWhiteSpace($settings[$name]) -or $settings[$name] -like "replace-*") {
        throw "The required .env setting $name is missing or still contains a placeholder."
    }
}

$certificateDirectory = Join-Path $root "deployment\certificates"
$requiredCertificates = @("ca.crt", "ca.pfx", "gateway.pfx")
$missingCertificates = @($requiredCertificates | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $certificateDirectory $_))
})
if ($missingCertificates.Count -gt 0) {
    Write-Output "Generating certificates for this local environment..."
    & dotnet run --project (Join-Path $root "tools\Platform.Pki\Platform.Pki.csproj") -- $certificateDirectory $settings["POSTGRES_PASSWORD"]
    if ($LASTEXITCODE -ne 0) { throw "Local certificate generation failed with exit code $LASTEXITCODE." }
}

& docker info --format '{{.ServerVersion}}' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker Engine is not available." }

Write-Output "Starting local infrastructure..."
Invoke-Compose up -d postgres nats minio opensearch falco

Wait-Until "PostgreSQL readiness" {
    & docker compose --env-file $envFile -f $composeFile exec -T postgres pg_isready -U platform -d platform *> $null
    return $LASTEXITCODE -eq 0
}
Wait-Until "OpenSearch readiness" {
    & docker compose --env-file $envFile -f $composeFile exec -T opensearch curl -fs http://localhost:9200/_cluster/health *> $null
    return $LASTEXITCODE -eq 0
}

Write-Output "Applying idempotent development seed data..."
Get-Content -LiteralPath $seedFile -Raw | & docker compose --env-file $envFile -f $composeFile exec -T postgres psql -U platform -d platform -v ON_ERROR_STOP=1 *> $null
if ($LASTEXITCODE -ne 0) { throw "Development seed failed." }

Write-Output "Provisioning the MinIO application identity and bucket..."
$priorAppUser = [Environment]::GetEnvironmentVariable("MINIO_APP_USER", "Process")
$priorAppPassword = [Environment]::GetEnvironmentVariable("MINIO_APP_PASSWORD", "Process")
try {
    [Environment]::SetEnvironmentVariable("MINIO_APP_USER", $settings.MINIO_APP_USER, "Process")
    [Environment]::SetEnvironmentVariable("MINIO_APP_PASSWORD", $settings.MINIO_APP_PASSWORD, "Process")
    Invoke-Compose exec -T -e MINIO_APP_USER -e MINIO_APP_PASSWORD minio sh -ec @'
mc alias set local http://localhost:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
mc admin user add local "$MINIO_APP_USER" "$MINIO_APP_PASSWORD" >/dev/null
mc admin policy attach local readwrite --user "$MINIO_APP_USER" >/dev/null
mc mb --ignore-existing local/platform-objects >/dev/null
'@
}
finally {
    [Environment]::SetEnvironmentVariable("MINIO_APP_USER", $priorAppUser, "Process")
    [Environment]::SetEnvironmentVariable("MINIO_APP_PASSWORD", $priorAppPassword, "Process")
}

Write-Output "Starting the stable gateway topology..."
$gatewayArgs = @("up", "-d")
if (-not $NoBuild) { $gatewayArgs += "--build" }
$gatewayArgs += "gateway"
Invoke-Compose @gatewayArgs
Wait-Until "gateway readiness" {
    try { return (Invoke-WebRequest -Uri "http://127.0.0.1:8080/health/ready" -UseBasicParsing -TimeoutSec 5).StatusCode -eq 200 } catch { return $false }
}

$agentCount = (& docker compose --env-file $envFile -f $composeFile exec -T postgres psql -U platform -d platform -Atc "select count(*) from platform.agents where status='active';").Trim()
if ($LASTEXITCODE -ne 0) { throw "Could not inspect agent enrollment state." }

if ([int]$agentCount -eq 0) {
    Write-Output "No enrolled agent exists; performing one-time enrollment without persisting the token..."
    $login = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/api/v1/auth/token" -ContentType "application/json" -Body (@{
        username = $settings.PLATFORM_BOOTSTRAP_USER
        password = $settings.PLATFORM_BOOTSTRAP_PASSWORD
    } | ConvertTo-Json -Compress)
    $headers = @{ Authorization = "Bearer $($login.access_token)" }
    $created = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/api/v1/enrollment-tokens" -Headers $headers -ContentType "application/json" -Body (@{
        expiresAt = [DateTimeOffset]::UtcNow.AddHours(1).ToString("O")
        maximumUses = 1
        allowedPlatforms = @("linux")
        endpointGroupId = $null
        policyId = $null
    } | ConvertTo-Json -Compress)

    $tokenId = $created.data.metadata.id.ToString()
    $tokenSecret = $created.data.secret.ToString()
    $priorTokenId = [Environment]::GetEnvironmentVariable("PLATFORM_ENROLLMENT_TOKEN_ID", "Process")
    $priorTokenSecret = [Environment]::GetEnvironmentVariable("PLATFORM_ENROLLMENT_TOKEN_SECRET", "Process")
    try {
        [Environment]::SetEnvironmentVariable("PLATFORM_ENROLLMENT_TOKEN_ID", $tokenId, "Process")
        [Environment]::SetEnvironmentVariable("PLATFORM_ENROLLMENT_TOKEN_SECRET", $tokenSecret, "Process")
        $existingTemporary = & docker ps -a --filter "name=^/$temporaryAgent$" --format '{{.Names}}'
        if ($existingTemporary -eq $temporaryAgent) { & docker rm -f $temporaryAgent *> $null }
        Invoke-Compose run --detach --name $temporaryAgent --no-deps -e PLATFORM_ENROLLMENT_TOKEN_ID -e PLATFORM_ENROLLMENT_TOKEN_SECRET agent | Out-Null
        Wait-Until "agent enrollment and first heartbeat" {
            $count = (& docker compose --env-file $envFile -f $composeFile exec -T postgres psql -U platform -d platform -Atc "select count(*) from platform.agent_heartbeats;").Trim()
            return $LASTEXITCODE -eq 0 -and [int64]$count -gt 0
        }
    }
    finally {
        [Environment]::SetEnvironmentVariable("PLATFORM_ENROLLMENT_TOKEN_ID", $priorTokenId, "Process")
        [Environment]::SetEnvironmentVariable("PLATFORM_ENROLLMENT_TOKEN_SECRET", $priorTokenSecret, "Process")
        $existingTemporary = & docker ps -a --filter "name=^/$temporaryAgent$" --format '{{.Names}}'
        if ($existingTemporary -eq $temporaryAgent) { & docker rm -f $temporaryAgent *> $null }
        $tokenId = $null
        $tokenSecret = $null
    }
}

Invoke-Compose up -d agent
Wait-Until "normal agent heartbeat" {
    $recent = (& docker compose --env-file $envFile -f $composeFile exec -T postgres psql -U platform -d platform -Atc "select count(*) from platform.agent_heartbeats where received_at > now() - interval '2 minutes';").Trim()
    return $LASTEXITCODE -eq 0 -and [int64]$recent -gt 0
}

Write-Output "Local platform is ready at http://127.0.0.1:8080. Distributed ServiceHost replicas remain opt-in via --profile distributed."
