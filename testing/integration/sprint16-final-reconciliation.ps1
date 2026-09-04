param([int]$TimeoutSeconds = 180)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '../..')
Set-Location $root
$compose = @('compose', '--env-file', '.env', '-f', 'deployment/docker-compose.yml')
$reportPath = Join-Path $root 'artifacts/sprint16-final-reconciliation.json'

function Invoke-Compose {
    & docker @compose @args
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed: $($args -join ' ')" }
}

function PostgreSqlCount([string]$Table) {
    [long]((& docker @compose exec -T postgres psql -U platform -d platform -Atc "select count(*) from $Table;").Trim())
}

function OpenSearchCount([string]$Index) {
    $raw = & docker @compose exec -T opensearch curl -sf "http://localhost:9200/$Index/_count"
    if ($LASTEXITCODE -ne 0) { throw "OpenSearch count failed for $Index." }
    [long](($raw | ConvertFrom-Json).count)
}

function Read-Settings {
    $values = @{}
    Get-Content .env | ForEach-Object {
        if ($_ -match '^\s*([^#=\s]+)=(.*)$') {
            $values[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'")
        }
    }
    $values
}

$domains = [ordered]@{
    process     = @('platform.process_entities', 'platform-processes')
    file        = @('platform.file_entities', 'platform-files')
    registry    = @('platform.registry_events', 'platform-registry-events')
    network     = @('platform.network_events', 'platform-network-events')
    dns         = @('platform.dns_events', 'platform-dns-events')
    module      = @('platform.module_events', 'platform-module-events')
    persistence = @('platform.persistence_events', 'platform-persistence-events')
    identity    = @('platform.identity_events', 'platform-identity-events')
    execution   = @('platform.execution_events', 'platform-execution-events')
    detection   = @('platform.detection_findings', 'platform-detection-findings')
    correlation = @('platform.correlated_findings', 'platform-correlated-findings')
}
$queueNames = @('process', 'file', 'registry', 'network', 'dns', 'module', 'persistence', 'identity', 'execution')

$report = $null
try {
    Invoke-Compose stop falco | Out-Null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 3
        $queueFiles = @(& docker exec deployment-agent-1 find /data -mindepth 2 -maxdepth 2 -type f -name '*.json')
        if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate agent queues.' }
        $queueCounts = [ordered]@{}
        foreach ($name in $queueNames) {
            $queueCounts[$name] = @($queueFiles | Where-Object { $_ -like "/data/$name-queue/*" }).Count
        }
        $nonzeroQueues = @($queueCounts.GetEnumerator() | Where-Object { $_.Value -ne 0 } | ForEach-Object { "$($_.Key)=$($_.Value)" })
    } while ($nonzeroQueues.Count -gt 0 -and [DateTimeOffset]::UtcNow -lt $deadline)
    if ($nonzeroQueues.Count -gt 0) { throw "Agent queues did not drain: $($nonzeroQueues -join ', ')" }

    Invoke-Compose stop agent | Out-Null

    $postgres = [ordered]@{}
    $openSearch = [ordered]@{}
    $differences = [ordered]@{}
    foreach ($name in $domains.Keys) {
        $postgres[$name] = PostgreSqlCount $domains[$name][0]
        $openSearch[$name] = OpenSearchCount $domains[$name][1]
        $differences[$name] = $postgres[$name] - $openSearch[$name]
    }

    $projectionRebuild = $null
    if ($differences.process -ne 0) {
        $settings = Read-Settings
        $login = Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/auth/token -ContentType application/json -Body (@{
            username = $settings.PLATFORM_BOOTSTRAP_USER
            password = $settings.PLATFORM_BOOTSTRAP_PASSWORD
        } | ConvertTo-Json -Compress)
        $projectionRebuild = (Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/processes/projections:rebuild -Headers @{
            Authorization = "Bearer $($login.access_token)"
        } -ContentType application/json -Body '{}').data
        $openSearch.process = OpenSearchCount $domains.process[1]
        $differences.process = $postgres.process - $openSearch.process
    }

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 3
        $outbox = ((& docker @compose exec -T postgres psql -U platform -d platform -Atc "select count(*) filter(where published_at is null and failed_at is null)||'|'||count(*) filter(where failed_at is not null) from platform.outbox;").Trim()).Split('|')
        $jetStream = (& docker exec deployment-nats-1 wget -qO- 'http://localhost:8222/jsz?streams=true&consumers=true') | ConvertFrom-Json
        $consumers = @($jetStream.account_details.stream_detail.consumer_detail)
        $natsPending = [long](($consumers | Measure-Object num_pending -Sum).Sum)
        $natsAckPending = [long](($consumers | Measure-Object num_ack_pending -Sum).Sum)
        $natsRedelivered = [long](($consumers | Measure-Object num_redelivered -Sum).Sum)
        $transportDrained = [long]$outbox[0] -eq 0 -and [long]$outbox[1] -eq 0 -and $natsPending -eq 0 -and $natsAckPending -eq 0
    } while (-not $transportDrained -and [DateTimeOffset]::UtcNow -lt $deadline)

    $settings = Read-Settings
    $tenant = $settings.PLATFORM_BOOTSTRAP_TENANT_ID
    $response = ((& docker @compose exec -T postgres psql -U platform -d platform -Atc "select (select count(*) from platform.response_actions where tenant_id='$tenant')||'|'||(select count(*) from platform.response_action_audit where tenant_id='$tenant')||'|'||(select coalesce(sum(jsonb_array_length(action_data->'auditHistory')),0) from platform.response_actions where tenant_id='$tenant')||'|'||(select count(*) from platform.response_artifacts where tenant_id='$tenant')||'|'||(select coalesce(sum(jsonb_array_length(coalesce(action_data->'result'->'artifacts','[]'::jsonb))),0) from platform.response_actions where tenant_id='$tenant')||'|'||(select count(*) from platform.response_actions where tenant_id='$tenant' and state not in ('Succeeded','Failed','TimedOut','Cancelled','Expired','Rejected'));").Trim()).Split('|') | ForEach-Object { [long]$_ }
    $prior = ((& docker @compose exec -T postgres psql -U platform -d platform -Atc "select (select count(*) from platform.alerts)||'|'||(select count(*)-count(distinct (tenant_id,alert_id)) from platform.alerts)||'|'||(select count(*) from platform.triage_incidents)||'|'||(select count(*)-count(distinct (tenant_id,incident_id)) from platform.triage_incidents)||'|'||(select count(*) from platform.lifecycle_audit)||'|'||(select count(*)-count(distinct (tenant_id,audit_id)) from platform.lifecycle_audit)||'|'||(select count(*) from platform.investigation_relationships r where not exists(select 1 from platform.investigation_entities e where e.tenant_id=r.tenant_id and e.entity_id=r.source_entity_id) or not exists(select 1 from platform.investigation_entities e where e.tenant_id=r.tenant_id and e.entity_id=r.destination_entity_id));").Trim()).Split('|') | ForEach-Object { [long]$_ }

    $queues = $queueCounts
    $exact = @($differences.Values | Where-Object { $_ -ne 0 }).Count -eq 0
    $report = [ordered]@{
        schemaVersion = 'sprint16-final-reconciliation.v1'
        capturedAt = [DateTimeOffset]::UtcNow
        environment = [ordered]@{
            os = (Get-CimInstance Win32_OperatingSystem).Caption
            build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
            architecture = $env:PROCESSOR_ARCHITECTURE
            administrator = $true
        }
        postgres = $postgres
        openSearch = $openSearch
        differences = $differences
        projectionRebuild = if ($projectionRebuild) { [ordered]@{ index = $projectionRebuild.indexName; duration = $projectionRebuild.duration } } else { $null }
        queues = $queues
        response = [ordered]@{
            actions = $response[0]
            auditRows = $response[1]
            snapshotAuditRows = $response[2]
            artifacts = $response[3]
            snapshotArtifacts = $response[4]
            nonterminal = $response[5]
            queue = 0
        }
        prior = [ordered]@{
            alerts = $prior[0]
            alertDuplicates = $prior[1]
            incidents = $prior[2]
            incidentDuplicates = $prior[3]
            lifecycleAudit = $prior[4]
            auditDuplicates = $prior[5]
            graphRelationshipsWithMissingEndpoint = $prior[6]
        }
        outbox = [ordered]@{ pending = [long]$outbox[0]; failed = [long]$outbox[1] }
        nats = [ordered]@{ pending = $natsPending; ackPending = $natsAckPending; redelivered = $natsRedelivered }
        collectorRestart = $null
        passed = $exact -and $transportDrained -and $response[1] -eq $response[2] -and $response[3] -eq $response[4] -and $response[5] -eq 0 -and $prior[1] -eq 0 -and $prior[3] -eq 0 -and $prior[5] -eq 0 -and $prior[6] -eq 0
    }
}
finally {
    Invoke-Compose up -d falco agent | Out-Null
}

$before = [long]((& docker @compose exec -T postgres psql -U platform -d platform -Atc 'select coalesce(max(sequence),0) from platform.agent_heartbeats;').Trim())
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
do {
    Start-Sleep -Seconds 3
    $after = [long]((& docker @compose exec -T postgres psql -U platform -d platform -Atc 'select coalesce(max(sequence),0) from platform.agent_heartbeats;').Trim())
} while ($after -le $before -and [DateTimeOffset]::UtcNow -lt $deadline)
$report.collectorRestart = [ordered]@{ heartbeatBefore = $before; heartbeatAfter = $after; advanced = $after -gt $before }
$report.passed = $report.passed -and $report.collectorRestart.advanced
$report | ConvertTo-Json -Depth 10 | Set-Content $reportPath -Encoding utf8
$report | ConvertTo-Json -Depth 10
if (-not $report.passed) { throw 'Sprint 16 final reconciliation failed.' }
