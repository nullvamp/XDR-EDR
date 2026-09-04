param(
    [string]$DataDirectory = 'artifacts/sprint5-windows-20260807063045',
    [string]$Output = 'artifacts/sprint9-persistence-offline-pressure.json',
    [int]$ObservationSeconds = 6
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$compose = @('compose', '--env-file', (Join-Path $root '.env'), '-f', (Join-Path $root 'deployment\docker-compose.yml'))
$data = (Resolve-Path (Join-Path $root $DataDirectory)).Path
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$valuePrefix = 'OSP-Sprint9-Offline-Probe-'
$valueNames = 1..4 | ForEach-Object { "$valuePrefix$_" }
$started = [DateTimeOffset]::UtcNow

function Queue-Depths {
    $result = [ordered]@{}
    foreach ($name in @('persistence-queue','process-queue','file-queue','registry-queue','network-queue','dns-queue','module-queue')) {
        $result[$name] = @(Get-ChildItem (Join-Path $data $name) -Filter '*.json' -ErrorAction SilentlyContinue).Count
    }
    $result
}

function Wait-Gateway([int]$seconds = 120) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($seconds)
    do {
        try { if ((Invoke-WebRequest 'http://localhost:8080/health/ready' -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200) { return $true } } catch {}
        Start-Sleep 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    $false
}

$peak = 0
$during = $null
try {
    & docker @compose stop gateway | Out-Null
    New-Item -Path $runKey -Force | Out-Null
    foreach ($valueName in $valueNames) {
        New-ItemProperty -Path $runKey -Name $valueName -Value 'cmd.exe /c exit 0' -PropertyType String -Force | Out-Null
    }
    $queueDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        Start-Sleep 2
        $during = Queue-Depths
        $peak = [Math]::Max($peak, [int]$during['persistence-queue'])
    } while ($peak -eq 0 -and [DateTimeOffset]::UtcNow -lt $queueDeadline)
    & docker @compose up -d gateway | Out-Null
    if (-not (Wait-Gateway)) { throw 'Gateway did not recover.' }
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(180)
    do {
        Start-Sleep 2
        $final = Queue-Depths
    } while ((($final.Values | Measure-Object -Sum).Sum -gt 0) -and [DateTimeOffset]::UtcNow -lt $deadline)
    Start-Sleep 5
    $since = $started.UtcDateTime.ToString('o')
    $sql = "select count(*)||','||count(distinct event_id) from platform.persistence_events where observed_at >= '$since' and event_data#>>'{configuration,name}' like '$valuePrefix%'"
    $counts = (& docker exec deployment-postgres-1 psql -U platform -d platform -At -c $sql).Trim().Split(',')
    $total = [int]$counts[0]; $distinct = [int]$counts[1]
    $report = [ordered]@{
        schema = 'platform.sprint9.offline-pressure.v1'
        capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
        gatewayOffline = $true
        boundedOperations = $valueNames.Count
        persistenceQueuePeak = $peak
        queueDepthsDuringOffline = $during
        queueDepthsFinal = $final
        replayedPersistenceEvents = $total
        distinctPersistenceEvents = $distinct
        duplicateEvents = $total - $distinct
        passed = $peak -gt 0 -and (($final.Values | Measure-Object -Sum).Sum -eq 0) -and $total -ge $valueNames.Count -and $total -eq $distinct
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root $Output) -Encoding utf8
    $report | ConvertTo-Json -Depth 6
    if (-not $report.passed) { exit 1 }
}
finally {
    foreach ($valueName in $valueNames) { Remove-ItemProperty -Path $runKey -Name $valueName -ErrorAction SilentlyContinue }
    & docker @compose up -d gateway | Out-Null
    Wait-Gateway | Out-Null
}
