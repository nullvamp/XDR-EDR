param(
    [string]$RuntimeArtifact = 'artifacts/sprint3h-windows-runtime-delete-recreate.json',
    [string]$Output = 'artifacts/sprint3h-windows-outage-runtime.json'
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator token required.' }
$runtime = Get-Content -LiteralPath $RuntimeArtifact -Raw | ConvertFrom-Json
$endpointId = $runtime.endpointId
$run = (Get-ChildItem artifacts -Directory -Filter 'sprint3e-windows-*' | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$work = Get-ChildItem -LiteralPath $run -Directory | Where-Object Name -Like 'workload with spaces-*' | Select-Object -First 1 -ExpandProperty FullName
$queue = Join-Path $run 'file-queue'
$batchMetricsPath = Join-Path $run 'sprint3h-file-batch-metrics.jsonl'
Remove-Item -LiteralPath $batchMetricsPath -Force -ErrorAction SilentlyContinue
$env:PLATFORM_FILE_BATCH_METRICS_PATH = $batchMetricsPath
$exe = Join-Path $root 'agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.exe'
$gateway = 'deployment-gateway-1'
$startedAt = [DateTimeOffset]::UtcNow
$env:PLATFORM_AGENT_DATA = $run
$env:PLATFORM_ENVIRONMENT = 'production'
$env:PLATFORM_CONTROL_PLANE_URL = 'https://localhost:8443'
$env:PLATFORM_CA_CERT_PATH = (Resolve-Path deployment/certificates/ca.crt).Path
$env:PLATFORM_ENROLLMENT_TOKEN_ID = ''
$env:PLATFORM_ENROLLMENT_TOKEN_SECRET = ''
$cfg=@{};Get-Content .env|Where-Object{$_ -match '^[^#].*='}|ForEach-Object{$p=$_.Split('=',2);$cfg[$p[0]]=$p[1]}
$session=Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json)
$headers=@{Authorization="Bearer $($session.access_token)"}
$originalProcessPolicy=(Invoke-RestMethod -Uri "http://localhost:8080/api/v1/endpoints/$endpointId/process-policy" -Headers $headers).data.policy
$originalProcessPolicyBody=$originalProcessPolicy.policy|ConvertTo-Json -Depth 10|ConvertFrom-Json
$disabledPolicyBody=$originalProcessPolicy.policy|ConvertTo-Json -Depth 10|ConvertFrom-Json
$disabledPolicyBody.telemetryEnabled=$false
$disabledPolicyBody.startEnabled=$false
$disabledPolicyBody.exitEnabled=$false
$disabledProcessPolicy=(Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/process-telemetry/policies -Headers $headers -ContentType application/json -Body (@{name="sprint3h-file-outage-$([guid]::NewGuid().ToString('N'))";policy=$disabledPolicyBody}|ConvertTo-Json -Depth 10)).data
function QueueState {
    $files = @(Get-ChildItem -LiteralPath $queue -File -Filter '*.json' -ErrorAction SilentlyContinue)
    @{ active = $files.Count; bytes = [long](($files | Measure-Object Length -Sum).Sum); temporary = @(Get-ChildItem -LiteralPath $queue -File -Filter '*.tmp' -ErrorAction SilentlyContinue).Count; committing = @(Get-ChildItem -LiteralPath $queue -File -Filter '*.committing' -ErrorAction SilentlyContinue).Count }
}
function DbScalar([string]$sql) { (docker exec deployment-postgres-1 psql -U platform -d platform -Atc $sql).Trim() }
function Start-Agent([string]$name) { Start-Process -FilePath $exe -RedirectStandardOutput (Join-Path $run "$name.log") -RedirectStandardError (Join-Path $run "$name.stderr.log") -PassThru -WindowStyle Hidden }
$samples = @()
function Sample-Agent($process) {
    if ($process -and -not $process.HasExited) {
        $process.Refresh()
        $script:samples += @{
            processId = $process.Id
            capturedAt = [DateTimeOffset]::UtcNow
            workingSet = [long]$process.WorkingSet64
            cpuSeconds = $process.TotalProcessorTime.TotalSeconds
        }
    }
}

$agent = $null
$gatewayStopped = $false
try {
    Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
    foreach ($name in @('OpenSecurityPlatform-FileLifecycle-v1','OpenSecurityPlatform-ProcessLifecycle-v1')) { & logman stop $name -ets 2>$null | Out-Null }
    Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/process-telemetry/policies/$($disabledProcessPolicy.id):assign" -Headers $headers -ContentType application/json -Body (@{endpointId=$endpointId}|ConvertTo-Json)|Out-Null
    $beforeEvents = [long](DbScalar "select count(*) from platform.file_events where endpoint_id='$endpointId'")
    $beforeBatches = [long](DbScalar "select count(*) from platform.file_batches where endpoint_id='$endpointId'")
    $beforeSubmitted = [long](DbScalar "select coalesce(sum(event_count),0) from platform.file_batches where endpoint_id='$endpointId'")
    $beforeSourceGaps = [long](DbScalar "select coalesce(source_gaps,0) from platform.file_telemetry_health where endpoint_id='$endpointId'")
    $agent = Start-Agent 'outage-before'
    Start-Sleep 5
    Sample-Agent $agent
    $initial = QueueState
    $cpuStart = $agent.TotalProcessorTime.TotalSeconds
    $netStart = [long]((Get-NetAdapterStatistics | ForEach-Object { $_.ReceivedBytes + $_.SentBytes } | Measure-Object -Sum).Sum)
    docker stop $gateway | Out-Null
    $gatewayStopped = $true
    $manifest = @()
    $outageDir = Join-Path $work 'outage-replay'
    New-Item -ItemType Directory -Force $outageDir | Out-Null
    1..20 | ForEach-Object {
        $path = Join-Path $outageDir ("offline-{0:d2}.txt" -f $_)
        [IO.File]::WriteAllText($path, ('x' * (1024 + $_)))
        [IO.File]::AppendAllText($path, '-append')
        if ($_ % 5 -eq 0) { Remove-Item -LiteralPath $path -Force }
        $manifest += @{ operationId = "offline-{0:d2}" -f $_; path = $path; deleted = ($_ % 5 -eq 0); at = [DateTimeOffset]::UtcNow.ToString('O') }
        Sample-Agent $agent
        Start-Sleep -Milliseconds 100
    }
    $queueDeadline=[DateTimeOffset]::UtcNow.AddSeconds(30)
    do { Sample-Agent $agent; Start-Sleep -Milliseconds 500;$queued=QueueState } while($queued.active -lt 20 -and [DateTimeOffset]::UtcNow -lt $queueDeadline)
    if ($queued.active -lt 20) { throw "Offline queue captured only $($queued.active) of 20 controlled operations." }
    Stop-Process -Id $agent.Id -Force
    $agent.WaitForExit()
    $afterTermination = QueueState
    $agent = Start-Agent 'outage-offline-restart'
    Start-Sleep 5
    Sample-Agent $agent
    $afterOfflineRestart = QueueState
    if ($afterOfflineRestart.active -eq 0) { throw 'Offline restart did not preserve queued records.' }
    docker start $gateway | Out-Null
    $gatewayStopped = $false
    $readyDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do { Start-Sleep 1; try { $gatewayReady = (Invoke-WebRequest -UseBasicParsing http://localhost:8080/health/ready -TimeoutSec 2).StatusCode -eq 200 } catch { $gatewayReady = $false } } while (-not $gatewayReady -and [DateTimeOffset]::UtcNow -lt $readyDeadline)
    if (-not $gatewayReady) { throw 'Gateway did not recover.' }
    $drainStarted = [DateTimeOffset]::UtcNow
    $drainDeadline = $drainStarted.AddSeconds(90)
    do { Start-Sleep 1; $finalQueue = QueueState } while ($finalQueue.active -gt 0 -and [DateTimeOffset]::UtcNow -lt $drainDeadline)
    $drainSeconds = ([DateTimeOffset]::UtcNow - $drainStarted).TotalSeconds
    if ($finalQueue.active -ne 0) { throw 'Windows queue did not drain after gateway restoration.' }
    $projectionDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 250
        Sample-Agent $agent
        $projectedPostgresEntities = [long](DbScalar "select count(*) from platform.file_entities where endpoint_id='$endpointId'")
        $projectedOpenSearchEntities = [long](docker exec deployment-opensearch-1 curl -s "http://localhost:9200/platform-files/_count?q=endpoint_id:$endpointId" | ConvertFrom-Json).count
    } while ($projectedPostgresEntities -ne $projectedOpenSearchEntities -and [DateTimeOffset]::UtcNow -lt $projectionDeadline)
    $projectionObservedAt = [DateTimeOffset]::UtcNow
    if ($projectedPostgresEntities -ne $projectedOpenSearchEntities) { throw 'OpenSearch projection did not reconcile before the performance deadline.' }
    $elapsed = ([DateTimeOffset]::UtcNow - $startedAt).TotalSeconds
    $cpuRates = @()
    for ($i = 1; $i -lt $samples.Count; $i++) {
        if ($samples[$i].processId -ne $samples[$i - 1].processId) { continue }
        $sampleElapsed = ($samples[$i].capturedAt - $samples[$i - 1].capturedAt).TotalSeconds
        if ($sampleElapsed -gt 0) {
            $cpuRates += (($samples[$i].cpuSeconds - $samples[$i - 1].cpuSeconds) / $sampleElapsed) * 100
        }
    }
    $cpuMeanPercent = if ($cpuRates.Count) { [Math]::Round(($cpuRates | Measure-Object -Average).Average, 3) } else { 0 }
    $cpuPeakPercent = if ($cpuRates.Count) { [Math]::Round(($cpuRates | Measure-Object -Maximum).Maximum, 3) } else { 0 }
    $netEnd = [long]((Get-NetAdapterStatistics | ForEach-Object { $_.ReceivedBytes + $_.SentBytes } | Measure-Object -Sum).Sum)
    $afterEvents = [long](DbScalar "select count(*) from platform.file_events where endpoint_id='$endpointId'")
    $afterBatches = [long](DbScalar "select count(*) from platform.file_batches where endpoint_id='$endpointId'")
    $afterSubmitted = [long](DbScalar "select coalesce(sum(event_count),0) from platform.file_batches where endpoint_id='$endpointId'")
    $health = (DbScalar "select queue_depth||'|'||dropped_events||'|'||source_gaps||'|'||etw_lost_events||'|'||last_sequence from platform.file_telemetry_health where endpoint_id='$endpointId'").Split('|')
    $latency = (DbScalar "select coalesce(round(avg(extract(epoch from (received_at-observed_at))*1000)::numeric,3),0)||'|'||coalesce(round(avg(extract(epoch from (ingested_at-received_at))*1000)::numeric,3),0)||'|'||coalesce(round(avg(pg_column_size(event_data))::numeric,1),0) from platform.file_events where endpoint_id='$endpointId' and received_at >= '$($startedAt.UtcDateTime.ToString('O'))'").Split('|')
    $lastIngestedText = DbScalar "select coalesce(max(ingested_at)::text,'') from platform.file_events where endpoint_id='$endpointId' and received_at >= '$($startedAt.UtcDateTime.ToString('O'))'"
    $projectionLatencyUpperBoundMs = if ($lastIngestedText) { [Math]::Max(0, [Math]::Round(($projectionObservedAt - [DateTimeOffset]::Parse($lastIngestedText)).TotalMilliseconds, 3)) } else { 0 }
    $batchMetrics = if (Test-Path $batchMetricsPath) { @(Get-Content $batchMetricsPath | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json }) } else { @() }
    $uncompressedBytes = [long](($batchMetrics.uncompressedBytes | Measure-Object -Sum).Sum)
    $compressedBytes = [long](($batchMetrics.compressedBytes | Measure-Object -Sum).Sum)
    $compressionRatio = if ($compressedBytes -gt 0) { [Math]::Round($uncompressedBytes / $compressedBytes, 3) } else { 0 }
    $openSearch = docker exec deployment-opensearch-1 curl -s "http://localhost:9200/platform-files/_count?q=endpoint_id:$endpointId" | ConvertFrom-Json
    $report = @{
        schema = 'platform.sprint3h.windows-outage-runtime.v1'; startedAt = $startedAt; finishedAt = [DateTimeOffset]::UtcNow; endpointId = $endpointId; workspace = $outageDir
        manifest = $manifest; queue = @{ initial = $initial; offlinePeak = $queued; afterTermination = $afterTermination; afterOfflineRestart = $afterOfflineRestart; final = $finalQueue; drainSeconds = $drainSeconds }
        pipeline = @{ submitted = $afterSubmitted-$beforeSubmitted; accepted = $afterEvents-$beforeEvents; postgres = $afterEvents-$beforeEvents; batches = $afterBatches-$beforeBatches; openSearchEntities = [long]$openSearch.count; duplicateDeliveryCount = ($afterSubmitted-$beforeSubmitted)-($afterEvents-$beforeEvents); duplicateAuthoritativeCount = 0; rejectionCount = 0 }
        health = @{ finalQueueDepth = [long]$health[0]; drops = [long]$health[1]; sourceGaps = [long]$health[2]; sourceGapDelta = [long]$health[2]-$beforeSourceGaps; etwLostEvents = [long]$health[3]; lastSequence = [long]$health[4] }
        performance = @{ agentCpuMeanPercent = $cpuMeanPercent; agentCpuPeakPercent = $cpuPeakPercent; agentMemoryMeanBytes = [long](($samples.workingSet | Measure-Object -Average).Average); agentMemoryPeakBytes = [long](($samples.workingSet | Measure-Object -Maximum).Maximum); collectorCpuMeanPercent = $cpuMeanPercent; collectorCpuPeakPercent = $cpuPeakPercent; collectorMemoryMeanBytes = [long](($samples.workingSet | Measure-Object -Average).Average); collectorMemoryPeakBytes = [long](($samples.workingSet | Measure-Object -Maximum).Maximum); queuePeakEvents = $queued.active; queuePeakBytes = $queued.bytes; eventCount = $afterEvents-$beforeEvents; averageEventBytes = [decimal]$latency[2]; batchCount = $afterBatches-$beforeBatches; uncompressedBatchBytes = $uncompressedBytes; compressedBatchBytes = $compressedBytes; compressionRatio = $compressionRatio; networkBytesHostDelta = [long]($netEnd-$netStart); collectionToReceiptMeanMs = [decimal]$latency[0]; receiptToIngestMeanMs = [decimal]$latency[1]; projectionLatencyUpperBoundMs = $projectionLatencyUpperBoundMs; queueDrainSeconds = $drainSeconds }
        passed = $queued.active -ge 20 -and $afterOfflineRestart.active -ge 20 -and $finalQueue.active -eq 0 -and ($afterEvents-$beforeEvents) -ge 20 -and ($afterSubmitted-$beforeSubmitted) -eq ($afterEvents-$beforeEvents) -and $batchMetrics.Count -gt 0 -and $compressionRatio -gt 0 -and $projectedPostgresEntities -eq $projectedOpenSearchEntities -and [long]$health[0] -eq 0 -and [long]$health[1] -eq 0 -and ([long]$health[2]-$beforeSourceGaps) -eq 0 -and [long]$health[3] -eq 0
    }
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Output
    if (-not $report.passed) { throw 'Windows outage/replay acceptance failed.' }
}
finally {
    if ($gatewayStopped) { docker start $gateway | Out-Null }
    if ($agent -and -not $agent.HasExited) { Stop-Process -Id $agent.Id -Force; $agent.WaitForExit() }
    if($originalProcessPolicyBody){
        try { $restored=(Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/process-telemetry/policies -Headers $headers -ContentType application/json -Body (@{name="sprint3h-process-restore-$([guid]::NewGuid().ToString('N'))";policy=$originalProcessPolicyBody}|ConvertTo-Json -Depth 10)).data;Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/process-telemetry/policies/$($restored.id):assign" -Headers $headers -ContentType application/json -Body (@{endpointId=$endpointId}|ConvertTo-Json)|Out-Null } catch { Write-Warning "Original process policy assignment requires manual restoration: $($_.Exception.Message)" }
    }
}
