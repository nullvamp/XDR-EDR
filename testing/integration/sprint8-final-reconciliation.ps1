param([string]$Output = 'artifacts/sprint8-final-reconciliation.json', [int]$TimeoutSeconds = 240)
$ErrorActionPreference = 'Stop'
function Sql([string]$query) { docker exec deployment-postgres-1 psql -U platform -d platform -Atc $query }
function Os([string]$alias) { [long]((docker exec deployment-opensearch-1 curl -sf "http://localhost:9200/$alias/_count" | ConvertFrom-Json).count) }
$names = @('process','file','registry','network','dns','module','persistence')
$aliases = @('platform-processes','platform-files','platform-registry-events','platform-network-events','platform-dns-events','platform-module-events','platform-persistence-events')
$sql = "select (select count(*) from platform.process_entities)||'|'||(select count(*) from platform.file_entities)||'|'||(select count(*) from platform.registry_events)||'|'||(select count(*) from platform.network_events)||'|'||(select count(*) from platform.dns_events)||'|'||(select count(*) from platform.module_events)||'|'||(select count(*) from platform.persistence_events)||'|'||(select count(*) from platform.outbox where published_at is null and failed_at is null)||'|'||(select count(*) from platform.outbox where failed_at is not null);"
$deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    Start-Sleep -Seconds 10
    $values = (Sql $sql).Trim().Split('|') | ForEach-Object { [long]$_ }
    $search = for ($i = 0; $i -lt $aliases.Count; $i++) { Os $aliases[$i] }
    $queues = [ordered]@{}
    for ($i = 0; $i -lt $names.Count; $i++) { $queues[$names[$i]] = @(Get-ChildItem "artifacts/sprint5-windows-20260807063045/$($names[$i])-queue" -File -Filter '*.json' -ErrorAction SilentlyContinue).Count }
    $js = docker exec deployment-nats-1 wget -qO- 'http://localhost:8222/jsz?streams=true&consumers=true' | ConvertFrom-Json
    $consumers = @($js.account_details.stream_detail.consumer_detail)
    $pending = [long](($consumers | Measure-Object num_pending -Sum).Sum)
    $ack = [long](($consumers | Measure-Object num_ack_pending -Sum).Sum)
    $redelivered = [long](($consumers | Measure-Object num_redelivered -Sum).Sum)
    $exact = $true
    for ($i = 0; $i -lt 7; $i++) { if ($values[$i] -ne $search[$i]) { $exact = $false } }
    $drained = @($queues.Values | Where-Object { $_ -ne 0 }).Count -eq 0 -and $values[7] -eq 0 -and $values[8] -eq 0 -and $pending -eq 0 -and $ack -eq 0
} while ((-not ($exact -and $drained)) -and [DateTimeOffset]::UtcNow -lt $deadline)
$postgres = [ordered]@{}; $openSearch = [ordered]@{}; for ($i = 0; $i -lt 7; $i++) { $postgres[$names[$i]] = $values[$i]; $openSearch[$names[$i]] = $search[$i] }
$report = [ordered]@{ schema='platform.sprint8.final-reconciliation.v1'; capturedAt=[DateTimeOffset]::UtcNow.ToString('o'); postgres=$postgres; openSearch=$openSearch; differences=[ordered]@{}; queues=$queues; outbox=[ordered]@{pending=$values[7];failed=$values[8]}; nats=[ordered]@{pending=$pending;ackPending=$ack;redelivered=$redelivered}; passed=($exact -and $drained) }
for ($i = 0; $i -lt 7; $i++) { $report.differences[$names[$i]] = $values[$i] - $search[$i] }
$report | ConvertTo-Json -Depth 6 | Set-Content $Output -Encoding utf8
$report | ConvertTo-Json -Depth 6
if (-not $report.passed) { throw 'Sprint 8 final reconciliation did not drain exactly.' }
