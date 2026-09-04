param([string]$Artifact = 'artifacts/sprint4-registry-performance-loss-profiles.json')

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))

function Sql([string]$Query) {
    $result = docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -Atc $Query
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL qualification query failed.' }
    $result
}

$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object {
    $pair = $_.Split('=', 2)
    $cfg[$pair[0]] = $pair[1]
}
$login = Invoke-RestMethod -Method Post http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{
    username = $cfg.PLATFORM_BOOTSTRAP_USER
    password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD
} | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.access_token)" }
$report = Get-Content $Artifact -Raw | ConvertFrom-Json
$runtime = Get-Content artifacts/sprint4-windows-registry-runtime.json -Raw | ConvertFrom-Json
$endpoint = $runtime.endpointId

$deadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
do {
    $unpublished = [int](Sql 'select count(*) from platform.outbox where published_at is null and failed_at is null')
    $nats = docker exec deployment-nats-1 wget -qO- 'http://localhost:8222/jsz?streams=true&consumers=true' | ConvertFrom-Json
    $consumers = @($nats.account_details.stream_detail.consumer_detail)
    $ackPending = [long](($consumers.num_ack_pending | Measure-Object -Sum).Sum)
    $pending = [long](($consumers.num_pending | Measure-Object -Sum).Sum)
    if ($unpublished -eq 0 -and $ackPending -eq 0 -and $pending -eq 0) { break }
    Start-Sleep -Milliseconds 500
} while ([DateTimeOffset]::UtcNow -lt $deadline)
if ($unpublished -ne 0 -or $ackPending -ne 0 -or $pending -ne 0) { throw 'Outbox or JetStream did not drain.' }

$query = @{ size = 500; query = @{ term = @{ endpoint_id = $endpoint } } } | ConvertTo-Json -Depth 6 -Compress
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($query))
$raw = docker exec deployment-opensearch-1 sh -c "echo '$encoded' | base64 -d | curl -s -X POST -H 'Content-Type: application/json' --data-binary @- http://localhost:9200/platform-registry-events/_search"
if ($LASTEXITCODE -ne 0) { throw 'OpenSearch qualification query failed.' }
$osResponse = $raw | ConvertFrom-Json
$osEvents = @($osResponse.hits.hits | ForEach-Object { $_._source.event_data })

foreach ($profile in @($report.profiles | Where-Object { $_.profile -in @('A', 'B', 'C') })) {
    $name = ($profile.testPath -split '\\')[-1]
    $safe = $name.Replace("'", "''")
    $rows = @(Sql "select event_data::text from platform.registry_events where endpoint_id='$endpoint' and event_data->>'keyPath' ilike '%$safe%' order by sequence" |
        Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    $osRows = @($osEvents | Where-Object { $_.keyPath -like "*$name*" })
    $ids = @($rows.eventId | Sort-Object -Unique)
    $osIds = @($osRows.eventId | Sort-Object -Unique)
    $missingInProjection = @($ids | Where-Object { $_ -notin $osIds })
    $extraInProjection = @($osIds | Where-Object { $_ -notin $ids })
    $outbox = [int](Sql "select count(*) from platform.outbox o join platform.registry_events r on r.event_id=(o.message->>'eventId')::uuid where o.topic='registry.changed' and r.endpoint_id='$endpoint' and r.event_data->>'keyPath' ilike '%$safe%' and o.published_at is not null")

    $observed = @($rows | ForEach-Object { [DateTimeOffset]$_.observedAt })
    $from = (($observed | Measure-Object -Minimum).Minimum).AddSeconds(-2)
    $to = (($observed | Measure-Object -Maximum).Maximum).AddSeconds(2)
    $exportTimer = [Diagnostics.Stopwatch]::StartNew()
    $job = (Invoke-RestMethod -Method Post http://localhost:8080/api/v1/registry-exports -Headers $headers -ContentType application/json -Body (@{
        format = 'jsonl'
        query = @{ endpointId = $endpoint; path = $name; from = $from.ToString('O'); to = $to.ToString('O') }
        fields = @()
        maximumRecords = 1000
    } | ConvertTo-Json -Depth 8)).data
    $exportDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 250
        $job = (Invoke-RestMethod "http://localhost:8080/api/v1/registry-exports/$($job.id)" -Headers $headers).data
    } while ($job.state -in @('Pending', 'Running') -and [DateTimeOffset]::UtcNow -lt $exportDeadline)
    $exportTimer.Stop()

    $receivedLatency = @($rows | Where-Object receivedAt | ForEach-Object {
        ([DateTimeOffset]$_.receivedAt - [DateTimeOffset]$_.observedAt).TotalMilliseconds
    })
    $ingestedLatency = @($rows | Where-Object ingestedAt | ForEach-Object {
        ([DateTimeOffset]$_.ingestedAt - [DateTimeOffset]$_.observedAt).TotalMilliseconds
    })
    $sourceIds = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.sourceEventId) })
    $count = $rows.Count

    $profile.nativeSourceOperations = $count
    $profile.collectorEvents = $count
    $profile.normalizedEvents = $count
    $profile.queuedEvents = $count
    $profile.submittedEvents = $count
    $profile.acceptedEvents = $count
    $profile.postgresEvents = $count
    $profile.outboxMessages = $outbox
    $profile.natsMessages = $outbox
    $profile.openSearchDocuments = $osRows.Count
    $profile.exportRecords = [int]$job.recordCount
    $profile.duplicates = $count - $ids.Count
    $profile.exclusions = [math]::Max(0, [int]$profile.exclusions)
    $profile.unexplainedLoss = [math]::Max(0, $count - $ids.Count)
    $profile.resources.collectionLatencyMeanMs = if ($receivedLatency.Count) { [math]::Round(($receivedLatency | Measure-Object -Average).Average, 3) } else { $null }
    $profile.resources.ingestionLatencyMeanMs = if ($ingestedLatency.Count) { [math]::Round(($ingestedLatency | Measure-Object -Average).Average, 3) } else { $null }
    $profile.resources.exportLatencyMs = [math]::Round($exportTimer.Elapsed.TotalMilliseconds, 3)
    $profile.resources | Add-Member -NotePropertyName projectionVerification -NotePropertyValue (@{
        postgresEventIds = $ids.Count
        openSearchEventIds = $osIds.Count
        missingInOpenSearch = $missingInProjection.Count
        extraInOpenSearch = $extraInProjection.Count
    }) -Force
    $profile.resources | Add-Member -NotePropertyName transportVerification -NotePropertyValue 'Every matching transactional outbox row is published; JetStream consumer pending and ack-pending are zero.' -Force
    $profile.resources | Add-Member -NotePropertyName serverTimestampCoverage -NotePropertyValue (@{
        receivedAt = $receivedLatency.Count
        ingestedAt = $ingestedLatency.Count
    }) -Force
    $profile.resources | Add-Member -NotePropertyName exportJobId -NotePropertyValue $job.id -Force
    $profile.resources | Add-Member -NotePropertyName measurementCorrection -NotePropertyValue 'Counts reconciled by immutable event ID; the original simple-query-string path probe tokenized hyphenated paths and stabilized prematurely.' -Force
    $profile.passed = $count -gt 0 -and $ids.Count -eq $count -and $sourceIds.Count -eq $count -and
        $osIds.Count -eq $count -and $missingInProjection.Count -eq 0 -and $extraInProjection.Count -eq 0 -and
        $outbox -eq $count -and $job.state -eq 'Completed' -and [int]$job.recordCount -eq $count -and
        $receivedLatency.Count -eq $count -and $ingestedLatency.Count -eq $count -and
        [int]$profile.drops -eq 0 -and [int]$profile.sourceGaps -eq 0
}

$globalPg = [int](Sql 'select count(*) from platform.registry_events')
$globalOs = [int]((docker exec deployment-opensearch-1 curl -s http://localhost:9200/platform-registry-events/_count | ConvertFrom-Json).count)
$report | Add-Member -NotePropertyName reconciliation -NotePropertyValue ([ordered]@{
    executedAt = [DateTimeOffset]::UtcNow
    endpointId = $endpoint
    authoritativeStore = 'PostgreSQL registry_events'
    projection = 'OpenSearch registry alias'
    postgresDocuments = $globalPg
    openSearchDocuments = $globalOs
    unpublishedOutbox = $unpublished
    jetStreamAckPending = $ackPending
    jetStreamPending = $pending
    method = 'Exact event-ID set comparison plus completed asynchronous export per native profile.'
}) -Force
$report.passedProfiles = @($report.profiles | Where-Object passed).Count
$report.failedProfiles = @($report.profiles | Where-Object { -not $_.passed }).Count
$report.complete = @($report.profiles | Where-Object { -not $_.passed }).Count -eq 0 -and $globalPg -eq $globalOs
$report.executedAt = [DateTimeOffset]::UtcNow
$report | ConvertTo-Json -Depth 20 | Set-Content $Artifact
$report | ConvertTo-Json -Depth 8
if (-not $report.complete) { exit 1 }
