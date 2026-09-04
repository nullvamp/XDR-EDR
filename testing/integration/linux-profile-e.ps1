param([string]$Output = 'artifacts/sprint2c/linux-profile-e.json')

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))
New-Item -ItemType Directory -Force (Split-Path $Output) | Out-Null
$results = [Collections.Generic.List[object]]::new()
$agentContainer = docker ps --filter ancestor=deployment-agent:latest --format '{{.Names}}' | Select-Object -First 1
if (-not $agentContainer) { throw 'No active production agent exists for Linux profile E.' }

function Wait-Ready([int]$Seconds = 90) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        try {
            if ((Invoke-RestMethod http://localhost:8080/health/ready -TimeoutSec 3).status -eq 'ready') { return }
        } catch {}
        Start-Sleep 1
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'Gateway readiness did not recover during Linux profile E.'
}

function Start-ControlledProcess([string]$Name) {
    $token = [guid]::NewGuid().ToString('N')
    $pidFile = "/data/profile-e-$Name-$token.pid"
    # procfs is an evaluation polling source. Keep the controlled process alive
    # across the dependency recovery window so at least one poll can observe it;
    # native event-driven Linux qualification remains a separate environment gate.
    $command = "echo `$`$ > $pidFile; exec sleep 20"
    docker exec -d $agentContainer sh -c $command | Out-Null
    if ($LASTEXITCODE) { throw "Unable to start controlled procfs workload for $Name." }
    Start-Sleep 2
    $processId = [int](docker exec $agentContainer sh -c "cat $pidFile")
    $sourceEventId = (docker exec $agentContainer sh -c "cut -d ' ' -f 22 /proc/$processId/stat").Trim()
    docker exec $agentContainer rm -f $pidFile | Out-Null
    if ($processId -le 0 -or -not $sourceEventId) { throw "Controlled procfs workload for $Name did not expose a stable PID/start key." }
    Start-Sleep 8
    return [pscustomobject]@{ ProcessId = $processId; SourceEventId = $sourceEventId }
}

function Wait-ProcessEvidence([string]$Name, [int]$ProcessId, [string]$SourceEventId, [int]$Seconds = 90) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    $starts = 0
    $exits = 0
    do {
        $rows = docker exec deployment-postgres-1 psql -U platform -d platform -AtF ',' -c "select event_type,count(*) from platform.process_events where (event_data->>'processId')::int=$ProcessId and event_data->>'sourceEventId'='$SourceEventId' group by event_type order by event_type"
        $starts = 0
        $exits = 0
        foreach ($row in $rows) {
            $parts = $row.Split(',')
            if ($parts[0] -eq 'started') { $starts = [int]$parts[1] }
            elseif ($parts[0] -eq 'exited') { $exits = [int]$parts[1] }
        }
        if ($starts -eq 1 -and $exits -eq 1) { break }
        Start-Sleep 1
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    $results.Add([ordered]@{name=$Name;processId=$ProcessId;sourceEventId=$SourceEventId;expectedStarts=1;expectedExits=1;databaseStarts=$starts;databaseExits=$exits;passed=($starts-eq1-and$exits-eq1)})
}

function Invoke-OutageProfile([string]$Name, [string[]]$Containers) {
    docker stop $Containers | Out-Null
    try {
        $process = Start-ControlledProcess $Name
    } finally {
        docker start $Containers | Out-Null
    }
    Wait-Ready
    Wait-ProcessEvidence $Name $process.ProcessId $process.SourceEventId
}

Invoke-OutageProfile nats @('deployment-nats-1')
Invoke-OutageProfile postgres @('deployment-postgres-1')
Invoke-OutageProfile opensearch @('deployment-opensearch-1')
Invoke-OutageProfile gateway @('deployment-gateway-1')
Invoke-OutageProfile combined-infrastructure @('deployment-postgres-1','deployment-nats-1','deployment-opensearch-1')

$reconcileDeadline = [DateTimeOffset]::UtcNow.AddSeconds(150)
do {
    $authoritative = [int](docker exec deployment-postgres-1 psql -U platform -d platform -Atc 'select count(*) from platform.process_entities')
    $projected = [int]((docker exec deployment-opensearch-1 curl -s http://localhost:9200/platform-processes/_count | ConvertFrom-Json).count)
    $outbox = [int](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.outbox where published_at is null and failed_at is null")
    $outboxFailed = [int](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.outbox where failed_at is not null")
    $jetStream = docker exec deployment-nats-1 wget -qO- 'http://localhost:8222/jsz?streams=true&consumers=true' | ConvertFrom-Json
    $consumers = @($jetStream.account_details.stream_detail.consumer_detail)
    $natsPending = [long](($consumers | Measure-Object num_pending -Sum).Sum)
    $natsAckPending = [long](($consumers | Measure-Object num_ack_pending -Sum).Sum)
    if ($authoritative -eq $projected -and $outbox -eq 0 -and $outboxFailed -eq 0 -and $natsPending -eq 0 -and $natsAckPending -eq 0) { break }
    Start-Sleep 1
} while ([DateTimeOffset]::UtcNow -lt $reconcileDeadline)

$report = [ordered]@{
    executedAt = [DateTimeOffset]::UtcNow.ToString('o')
    collector = 'procfs'
    agentContainer = $agentContainer
    passed = ($results.passed -notcontains $false -and $outbox -eq 0 -and $outboxFailed -eq 0 -and $natsPending -eq 0 -and $natsAckPending -eq 0 -and $authoritative -eq $projected)
    tests = $results
    authoritativeEntities = $authoritative
    projectedEntities = $projected
    outboxPending = $outbox
    outboxFailed = $outboxFailed
    natsPending = $natsPending
    natsAckPending = $natsAckPending
}
$report | ConvertTo-Json -Depth 8 | Set-Content $Output
$report | ConvertTo-Json -Depth 8
if (-not $report.passed) { exit 1 }
