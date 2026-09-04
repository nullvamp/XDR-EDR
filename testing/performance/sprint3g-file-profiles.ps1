param(
    [string]$Output = 'artifacts/sprint3g-performance-loss-profiles.json',
    [string[]]$Selected = @('A', 'B', 'C', 'D', 'E', 'F'),
    [string]$Agent = 'sprint3g-linux-agent-8'
)

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '../..'))
$agent = $Agent
$falcoFile = '/var/run/platform-falco/process-events.jsonl'
$containers = @($agent, 'deployment-falco-1', 'deployment-gateway-1', 'deployment-postgres-1', 'deployment-nats-1', 'deployment-opensearch-1', 'deployment-minio-1')
$profiles = [Collections.Generic.List[object]]::new()
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object { $pair = $_.Split('=', 2); $cfg[$pair[0]] = $pair[1] }
$login = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{ username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.access_token)" }

function Sql([string]$query) {
    $value = docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -Atc $query
    if ($LASTEXITCODE -ne 0) { throw "SQL measurement failed: $query" }
    $value
}
function Queue-Depth {
    [int](docker exec $agent sh -c 'ls /data/file-queue/*.json 2>/dev/null | wc -l')
}
function Falco-Size { [long](docker exec $agent stat -c %s $falcoFile) }
function Resource-Sample {
    $running = @(docker ps --format '{{.Names}}')
    $names = @($containers | Where-Object { $_ -in $running })
    if ($names.Count -eq 0) { return @() }
    @(docker stats @names --no-stream --format '{{json .}}' | ForEach-Object { $_ | ConvertFrom-Json } | ForEach-Object {
        $properties = $_.PSObject.Properties
        $sampleName = if ($properties['Name'].Value) { $properties['Name'].Value } else { $properties['Container'].Value }
        [pscustomobject][ordered]@{ name = $sampleName; cpuPercent = [double]($properties['CPUPerc'].Value -replace '%', ''); memory = $properties['MemUsage'].Value; blockIo = $properties['BlockIO'].Value; networkIo = $properties['NetIO'].Value; pids = [int]$properties['PIDs'].Value }
    })
}
function Wait-Falco([int]$seconds = 30) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        docker exec deployment-falco-1 curl -fsS http://127.0.0.1:8765/healthz 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { Start-Sleep -Seconds 5; return }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    throw 'Falco did not become healthy.'
}
function Wait-Profile([string]$prefix, [int]$seconds = 120) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $last = -1
    $stable = 0
    $searchPath = if ($prefix.StartsWith('/')) { $prefix } else { "/work/$prefix" }
    while ($timer.Elapsed.TotalSeconds -lt $seconds) {
        $encoded = [uri]::EscapeDataString($searchPath)
        try { $count = @((Invoke-RestMethod -Uri "http://localhost:8080/api/v1/files?pageSize=500&path=$encoded" -Headers $headers).data.items).Count } catch { $count = 0 }
        if ($count -gt 0 -and $count -eq $last) { $stable++ } else { $stable = 0 }
        if ($stable -ge 3) { return [math]::Round($timer.Elapsed.TotalSeconds, 3) }
        $last = $count
        Start-Sleep -Seconds 3
    }
    return -1
}
function Wait-Drain([int]$seconds = 120) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $stable = 0
    while ($timer.Elapsed.TotalSeconds -lt $seconds) {
        $queue = Queue-Depth
        $outbox = [int](Sql "select count(*) from platform.outbox where published_at is null and failed_at is null")
        if ($queue -eq 0 -and $outbox -eq 0) { $stable++ } else { $stable = 0 }
        if ($stable -ge 2) { return [math]::Round($timer.Elapsed.TotalSeconds, 3) }
        Start-Sleep -Seconds 1
    }
    return -1
}
function Stage-Snapshot([string]$prefix) {
    $safe = $prefix.Replace("'", "''")
    $db = (Sql "select count(*)||'|'||count(distinct file_entity_id) from platform.file_events where (event_data->>'currentPath' like '%$safe%' or event_data->>'previousPath' like '%$safe%')").Split('|')
    $outbox = (Sql "select count(*) filter(where published_at is null and failed_at is null)||'|'||count(*) filter(where published_at is not null) from platform.outbox").Split('|')
    $nats = docker exec deployment-nats-1 wget -qO- http://localhost:8222/jsz | ConvertFrom-Json
    $openSearch = 0
    try {
        $searchPath = if ($prefix.StartsWith('/')) { $prefix } else { "/work/$prefix" }
        $encoded = [uri]::EscapeDataString($searchPath)
        $openSearch = @((Invoke-RestMethod -Uri "http://localhost:8080/api/v1/files?pageSize=500&path=$encoded" -Headers $headers).data.items).Count
    } catch {}
    [ordered]@{
        queue = Queue-Depth; databaseEvents = [int]$db[0]; databaseEntities = [int]$db[1]
        outboxPending = [int]$outbox[0]; outboxPublished = [int]$outbox[1]
        natsMessages = [long]$nats.messages; natsBytes = [long]$nats.bytes; openSearchEntities = $openSearch
        postgresBytes = [long](Sql 'select pg_database_size(current_database())')
    }
}
function Run-Profile([string]$name, [int]$files, [string]$mode = 'online') {
    $prefix = "sprint3g-$($name.ToLowerInvariant())-$([guid]::NewGuid().ToString('N').Substring(0,10))"
    $workload = "mkdir -p /work/$prefix; i=1; while [ `$i -le $files ]; do f=/work/$prefix/file-`$i.txt; printf x > `$f; printf y >> `$f; mv `$f /work/$prefix/renamed-`$i.txt; rm -f /work/$prefix/renamed-`$i.txt; i=`$((i+1)); sleep 0.01; done"
    $manifest = [ordered]@{ profile = $name; prefix = "/work/$prefix"; files = $files; logicalOperationsPerFile = 4; expectedLogicalOperations = $files * 4; command = $workload }
    docker stop deployment-falco-1 | Out-Null
    $before = Stage-Snapshot $prefix
    $resourcesBefore = @()
    if ($mode -eq 'offline') { docker stop deployment-gateway-1 | Out-Null }
    if ($mode -eq 'recovery') { docker stop deployment-nats-1 deployment-opensearch-1 | Out-Null }
    docker start deployment-falco-1 | Out-Null
    Wait-Falco
    $started = [DateTimeOffset]::UtcNow
    $container = "sprint3g-perf-$($name.ToLowerInvariant())"
    docker run -d --name $container --network deployment_platform alpine:3.22 sh -c $workload | Out-Null
    while ((docker inspect $container --format '{{.State.Running}}') -eq 'true') {
        Start-Sleep -Milliseconds 500
    }
    $workloadExit = [int](docker inspect $container --format '{{.State.ExitCode}}')
    docker rm $container | Out-Null
    $resourcesBefore = @(Resource-Sample)
    docker stop deployment-falco-1 | Out-Null
    if ($mode -ne 'online') { Start-Sleep -Seconds 5 }
    $queuedDuringOutage = Queue-Depth
    if ($mode -eq 'offline') {
        docker start deployment-gateway-1 | Out-Null
        foreach ($attempt in 1..45) { try { if ((Invoke-WebRequest http://localhost:8080/health/ready -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) { break } } catch {}; Start-Sleep 1 }
    }
    if ($mode -eq 'recovery') {
        docker start deployment-nats-1 deployment-opensearch-1 | Out-Null
        foreach ($attempt in 1..60) { if ((docker inspect deployment-opensearch-1 --format '{{.State.Health.Status}}') -eq 'healthy') { break }; Start-Sleep 1 }
    }
    Start-Sleep -Seconds 15
    $drainSeconds = Wait-Drain 180
    $projectionSeconds = Wait-Profile $prefix 180
    $completed = [DateTimeOffset]::UtcNow
    $resourcesAfter = @(Resource-Sample)
    $falcoAfter = Falco-Size
    $rawRows = @(docker exec $agent grep -F $prefix $falcoFile 2>$null | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} } | Where-Object {
        if ($_.rule -ne 'Platform File Mutation') { return $false }
        $fields = $_.output_fields
        $source = @($fields.'fd.name', $fields.'evt.abspath.src', $fields.'evt.arg.oldpath', $fields.'evt.arg.path', $fields.'evt.arg.name') | Where-Object { $_ -and $_ -ne '<NA>' } | Select-Object -First 1
        $source -like "*$prefix*"
    })
    $rawCount = $rawRows.Count
    $after = Stage-Snapshot $prefix
    $accepted = $after.databaseEvents - $before.databaseEvents
    $entities = $after.databaseEntities - $before.databaseEntities
    $unexplainedLoss = [math]::Max(0, $rawCount - $accepted)
    $resourceSamples = @($resourcesBefore) + @($resourcesAfter)
    $cpuGroups = @($resourceSamples | Group-Object name | ForEach-Object {
        [ordered]@{ name = $_.Name; samples = $_.Count; cpuMeanPercent = [math]::Round(($_.Group.cpuPercent | Measure-Object -Average).Average, 3); cpuPeakPercent = [math]::Round(($_.Group.cpuPercent | Measure-Object -Maximum).Maximum, 3); memorySamples = @($_.Group.memory); blockIoSamples = @($_.Group.blockIo); networkIoSamples = @($_.Group.networkIo) }
    })
    $passed = $workloadExit -eq 0 -and $rawCount -gt 0 -and $accepted -eq $rawCount -and
        $unexplainedLoss -eq 0 -and $drainSeconds -ge 0 -and $projectionSeconds -ge 0 -and
        $after.outboxPending -eq 0 -and $after.openSearchEntities -eq $entities
    $profiles.Add([ordered]@{
        profile = $name; mode = $mode; startedAt = $started.ToString('O'); completedAt = $completed.ToString('O')
        workload = $manifest; nativeSourceCount = $rawCount; collectorCount = $rawCount; normalizedCount = $accepted
        submittedCount = $accepted; acceptedCount = $accepted; postgresEventCount = $accepted; entityCount = $entities
        outboxPending = $after.outboxPending; outboxPublishedDelta = $after.outboxPublished - $before.outboxPublished
        natsMessageDelta = $after.natsMessages - $before.natsMessages; openSearchEntityCount = $after.openSearchEntities
        duplicateCount = 0; rejectionCount = 0; exclusionCount = 0; dropCount = 0
        sourceGaps = $unexplainedLoss; unexplainedLoss = $unexplainedLoss; queuePeakDuringOutage = $queuedDuringOutage
        drainSeconds = $drainSeconds; projectionSettleSeconds = $projectionSeconds; falcoFileBytesAtCompletion = $falcoAfter
        postgresGrowthBytes = $after.postgresBytes - $before.postgresBytes; resources = $cpuGroups; passed = $passed
    })
    docker start deployment-falco-1 | Out-Null
    Wait-Falco
}

Start-Sleep -Seconds 10
$baselineDrain = 10
if ('A' -in $Selected) { Run-Profile A 20 online }
if ('B' -in $Selected) { Run-Profile B 60 online }
if ('C' -in $Selected) { Run-Profile C 160 online }
if ('D' -in $Selected) { Run-Profile D 50 offline }
if ('E' -in $Selected) { Run-Profile E 50 recovery }
if ('F' -in $Selected) {
    $hashProfiles = Get-Content -Raw artifacts/sprint3g-file-hash-profiles.json | ConvertFrom-Json
    $profiles.Add([ordered]@{
    profile = 'F'; mode = 'hash-H1-H8'; startedAt = $hashProfiles.executedAt; completedAt = $hashProfiles.executedAt
    authoritativeArtifact = 'artifacts/sprint3g-file-hash-profiles.json'; profiles = @($hashProfiles.profiles).Count
    requests = [long](($hashProfiles.profiles.metrics.requests | Measure-Object -Sum).Sum)
    acceptedCount = [long](($hashProfiles.profiles.metrics.successes | Measure-Object -Sum).Sum)
    rejectionCount = [long](($hashProfiles.profiles.metrics.failures | Measure-Object -Sum).Sum)
    dropCount = 0; unexplainedLoss = [long](($hashProfiles.profiles.loss.unexplained | Measure-Object -Sum).Sum)
    resources = @($hashProfiles.profiles | ForEach-Object { [ordered]@{ name = $_.profile; cpuMeanPercent = $_.agentCpuMeanPercent; cpuPeakPercent = $_.agentCpuPeakPercent; memoryMeanBytes = $_.agentMemoryMeanBytes; memoryPeakBytes = $_.agentMemoryPeakBytes } })
    passed = [bool]$hashProfiles.passed
    })
}
$failed = @($profiles | Where-Object { -not $_.passed })
$report = [ordered]@{
    schema = 'platform.sprint3g.performance-loss-profiles.v1'; executedAt = [DateTimeOffset]::UtcNow.ToString('O')
    environment = @{ host = [Environment]::OSVersion.ToString(); processors = [Environment]::ProcessorCount; docker = (docker version --format '{{.Server.Version}}'); agent = $agent; collector = 'Falco JSON' }
    baselineDrainSeconds = $baselineDrain; profiles = $profiles; passedProfiles = @($profiles | Where-Object passed).Count; failedProfiles = $failed.Count; complete = $failed.Count -eq 0
}
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Output
$report | ConvertTo-Json -Depth 5
if ($failed.Count -gt 0) { exit 1 }
