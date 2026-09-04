param(
    [string]$Agent = "sprint3g-linux-agent-8",
    [string]$Output = "artifacts/sprint3g-final-reconciliation.json"
)

$ErrorActionPreference = "Stop"
Set-Location (Resolve-Path (Join-Path $PSScriptRoot "..\.."))

function Pg([string]$sql) {
    $value = docker exec deployment-postgres-1 psql -U platform -d platform -AtF ',' -c $sql
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL query failed." }
    $value
}
function File-Count([string]$directory, [string]$name = "*") {
    $value = docker exec $Agent sh -c "find '$directory' -maxdepth 1 -type f -name '$name' 2>/dev/null | wc -l"
    if ($LASTEXITCODE -ne 0) { throw "Agent queue inspection failed for $directory." }
    [int]$value.Trim()
}
function Sha256([byte[]]$bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant() }
    finally { $sha.Dispose() }
}

$falcoWasRunning = (docker inspect -f "{{.State.Running}}" deployment-falco-1 2>$null) -eq "true"
$agentWasRunning = (docker inspect -f "{{.State.Running}}" $Agent 2>$null) -eq "true"
$collectorRestarted = $false
$temp = Join-Path ([IO.Path]::GetTempPath()) "sprint3g-reconcile-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temp | Out-Null

try {
    if ($falcoWasRunning) { docker stop deployment-falco-1 | Out-Null }
    Start-Sleep -Seconds 3
    $queueDeadline = (Get-Date).AddMinutes(1)
    do {
        $queueSnapshot = @{
            active = File-Count "/data/file-queue" "*.json"
            temporary = File-Count "/data/file-queue" "*.tmp"
            committing = File-Count "/data/file-queue" "*.committing"
            hashPending = File-Count "/data/file-hash-work" "*.json"
            hashTemporary = File-Count "/data/file-hash-work" "*.tmp"
            quarantine = File-Count "/data/file-queue/quarantine"
        }
        if ($queueSnapshot.active -eq 0 -and $queueSnapshot.temporary -eq 0 -and
            $queueSnapshot.committing -eq 0 -and $queueSnapshot.hashPending -eq 0 -and
            $queueSnapshot.hashTemporary -eq 0) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $queueDeadline)
    if ((Get-Date) -ge $queueDeadline) { throw "Agent queues did not drain within one minute." }
    if ($agentWasRunning) { docker stop $Agent | Out-Null }

    $deadline = (Get-Date).AddMinutes(2)
    do {
        $outbox = (Pg "select count(*) from platform.outbox where published_at is null and failed_at is null;").Trim()
        $nats = docker exec deployment-nats-1 wget -qO- "http://localhost:8222/jsz?streams=true&consumers=true" | ConvertFrom-Json
        $consumer = $nats.account_details[0].stream_detail[0].consumer_detail[0]
        if ([int]$outbox -eq 0 -and $consumer.num_pending -eq 0 -and $consumer.num_ack_pending -eq 0) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    if ((Get-Date) -ge $deadline) { throw "Outbox/NATS did not settle within two minutes." }

    $cfg = @{}
    Get-Content .env | Where-Object { $_ -match "^[^#].*=" } | ForEach-Object {
        $pair = $_.Split("=", 2); $cfg[$pair[0]] = $pair[1]
    }
    $login = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{
        username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD
    } | ConvertTo-Json)
    $headers = @{ Authorization = "Bearer $($login.access_token)" }
    $created = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/file-exports -Headers $headers -ContentType application/json -Body '{"format":"jsonl","query":{},"fields":[],"maximumRecords":20}'
    $exportId = [string]$created.data.id
    foreach ($attempt in 1..60) {
        $job = (Invoke-RestMethod -Uri "http://localhost:8080/api/v1/file-exports/$exportId" -Headers $headers).data
        if ($job.state -in @("Completed", "Failed")) { break }
        Start-Sleep -Milliseconds 250
    }
    if ($job.state -ne "Completed") { throw "Reconciliation export did not complete." }
    $contentPath = Join-Path $temp "export.jsonl"
    Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:8080/api/v1/file-exports/$exportId/content" -Headers $headers -OutFile $contentPath
    $bytes = [IO.File]::ReadAllBytes($contentPath)
    $manifest = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/file-exports/$exportId/manifest" -Headers $headers
    $contentHash = Sha256 $bytes
    $lineCount = @([IO.File]::ReadAllLines($contentPath) | Where-Object Length).Count
    $manifestIntegrity = $manifest.sha256 -eq $contentHash -and
        $manifest.objectSize -eq $bytes.Length -and
        $manifest.recordCount -eq $lineCount -and
        $manifest.exportId -eq $exportId

    $counts = (Pg "select (select count(*) from platform.file_events),(select count(*) from platform.file_entities),(select count(*) from platform.outbox where published_at is null and failed_at is null),(select count(*) from platform.outbox where failed_at is not null);").Trim().Split(',')
    docker exec deployment-opensearch-1 curl -fsS -X POST http://localhost:9200/platform-files/_refresh | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "OpenSearch refresh failed." }
    $search = docker exec deployment-opensearch-1 curl -fsS http://localhost:9200/platform-files/_count | ConvertFrom-Json
    $preRebuildDifference = [int64]$counts[1] - [int64]$search.count
    $rebuild = $null
    if ($preRebuildDifference -ne 0) {
        $rebuild = (Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/files/projections:rebuild -Headers $headers -TimeoutSec 300).data
        docker exec deployment-opensearch-1 curl -fsS -X POST http://localhost:9200/platform-files/_refresh | Out-Null
        $search = docker exec deployment-opensearch-1 curl -fsS http://localhost:9200/platform-files/_count | ConvertFrom-Json
    }
    $nats = docker exec deployment-nats-1 wget -qO- "http://localhost:8222/jsz?streams=true&consumers=true" | ConvertFrom-Json
    $consumer = $nats.account_details[0].stream_detail[0].consumer_detail[0]
    $exportStates = @{}
    Pg "select state,count(*) from platform.file_export_jobs group by state order by state;" | ForEach-Object {
        $parts = $_.Split(','); $exportStates[$parts[0]] = [int]$parts[1]
    }
    $objects = @(docker exec deployment-minio-1 sh -c 'mc alias set local http://127.0.0.1:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null && mc ls --recursive --json local' | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object type -eq "file")
    $ready = (Invoke-WebRequest -UseBasicParsing http://localhost:8080/health/ready).StatusCode
    $frontend = (Invoke-WebRequest -UseBasicParsing http://localhost:8080/).StatusCode
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $report = [ordered]@{
        schema = "platform.sprint3g.final-reconciliation.v1"
        executedAt = [DateTimeOffset]::UtcNow.ToString("O")
        workloadsStopped = $true
        windows = @{ status = if ($admin) { "available-not-run-by-this-script" } else { "blocked-non-elevated" }; queues = $null }
        linuxQueues = @{
            active = $queueSnapshot.active
            temporary = $queueSnapshot.temporary
            committing = $queueSnapshot.committing
        }
        hashQueue = @{ pending = $queueSnapshot.hashPending; temporary = $queueSnapshot.hashTemporary }
        controlledQuarantine = $queueSnapshot.quarantine
        exportJobsByState = $exportStates
        outbox = @{ pending = [int]$counts[2]; failed = [int]$counts[3] }
        nats = @{ pending = [int]$consumer.num_pending; ackPending = [int]$consumer.num_ack_pending; redelivered = [int]$consumer.num_redelivered }
        postgresql = @{ fileEvents = [int64]$counts[0]; fileEntities = [int64]$counts[1] }
        openSearch = @{
            fileEntities = [int64]$search.count
            projectionDifference = [int64]$counts[1] - [int64]$search.count
            preRebuildDifference = $preRebuildDifference
            rebuild = $rebuild
        }
        minio = @{ objects = $objects.Count; reconciliationExportObjects = 3 }
        manifestObjectIntegrity = @{ exportId = $exportId; recordCount = $lineCount; objectSize = $bytes.Length; sha256 = $contentHash; passed = $manifestIntegrity }
        readiness = @{ gateway = $ready; frontend = $frontend }
    }
    $report.passed = $report.linuxQueues.active -eq 0 -and $report.linuxQueues.temporary -eq 0 -and
        $report.linuxQueues.committing -eq 0 -and $report.hashQueue.pending -eq 0 -and
        $report.outbox.pending -eq 0 -and $report.outbox.failed -eq 0 -and
        $report.nats.pending -eq 0 -and $report.nats.ackPending -eq 0 -and
        $report.openSearch.projectionDifference -eq 0 -and $manifestIntegrity -and
        $ready -eq 200 -and $frontend -eq 200
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Output
    $report | ConvertTo-Json -Depth 10
    if (-not $report.passed) { throw "Final reconciliation has a discrepancy." }
}
finally {
    if ($agentWasRunning) { docker start $Agent | Out-Null }
    if ($falcoWasRunning) { docker start deployment-falco-1 | Out-Null }
    $collectorRestarted = $true
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}

if ($collectorRestarted) {
    $restartDeadline = (Get-Date).AddSeconds(30)
    do {
        $agentRunning = -not $agentWasRunning -or
            (docker inspect -f "{{.State.Running}}" $Agent) -eq "true"
        $falcoRunning = -not $falcoWasRunning -or
            (docker inspect -f "{{.State.Running}}" deployment-falco-1) -eq "true"
        if ($agentRunning -and $falcoRunning) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $restartDeadline)
    if (-not $agentRunning -or -not $falcoRunning) {
        throw "Collector restart verification failed."
    }
}
