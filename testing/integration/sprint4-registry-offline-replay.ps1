param([string]$Output = 'artifacts/sprint4-registry-offline-replay.json')

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator token required.' }
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))
$runtime = Get-Content artifacts/sprint4-windows-registry-runtime.json -Raw | ConvertFrom-Json
$endpoint = $runtime.endpointId
$run = $runtime.run
$queue = Join-Path $run 'registry-queue'
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object { $p = $_.Split('=', 2); $cfg[$p[0]] = $p[1] }
$login = Invoke-RestMethod -Method Post http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{ username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.access_token)" }
$agentPath = (Resolve-Path agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.exe).Path
$env:PLATFORM_AGENT_DATA = $run
$env:PLATFORM_ENVIRONMENT = 'production'
$env:PLATFORM_CONTROL_PLANE_URL = 'https://localhost:8443'
$env:PLATFORM_CA_CERT_PATH = (Resolve-Path deployment/certificates/ca.crt).Path
$compose = @('-f', 'deployment/docker-compose.yml', '--env-file', '.env')
$testName = "offline-$([guid]::NewGuid().ToString('N'))"
$relative = "Software\OpenSecurityPlatform\Sprint4\$testName"
$native = "HKCU\$relative"
$agent = $null
$queued = @()
$started = [DateTimeOffset]::UtcNow

function Stop-OwnedSessions {
    $active = (& logman query -ets 2>$null | Out-String)
    @('OpenSecurityPlatform-RegistryLifecycle-v1', 'OpenSecurityPlatform-ProcessLifecycle-v1', 'OpenSecurityPlatform-FileLifecycle-v1') |
        Where-Object { $active.IndexOf($_, [StringComparison]::Ordinal) -ge 0 } |
        ForEach-Object { & logman stop $_ -ets | Out-Null }
}
function Stop-Agent {
    if ($script:agent -and -not $script:agent.HasExited) { Stop-Process $script:agent.Id -Force; $script:agent.WaitForExit() }
    $script:agent = $null
    Stop-OwnedSessions
}
function Start-Agent([string]$name) {
    $script:agent = Start-Process -FilePath $agentPath -RedirectStandardOutput (Join-Path $run "$name.log") -RedirectStandardError (Join-Path $run "$name.stderr.log") -PassThru -WindowStyle Hidden
}
function Wait-Gateway {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
    do { Start-Sleep 1; try { $ready = (Invoke-WebRequest http://localhost:8080/health/ready -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch { $ready = $false } } while (-not $ready -and [DateTimeOffset]::UtcNow -lt $deadline)
    if (-not $ready) { throw 'Gateway did not become ready.' }
}

try {
    Stop-OwnedSessions
    if (@(Get-ChildItem $queue -Filter '*.json' -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Registry queue was not drained before offline qualification.' }
    Start-Agent 'offline-initial'
    Start-Sleep 4
    & docker compose @compose stop gateway | Out-Null
    & reg.exe add $native /v Alpha /t REG_SZ /d one /f | Out-Null
    & reg.exe add $native /v Alpha /t REG_SZ /d two /f | Out-Null
    & reg.exe add $native /v Count /t REG_DWORD /d 7 /f | Out-Null
    & reg.exe delete $native /v Alpha /f | Out-Null
    & reg.exe delete $native /f | Out-Null
    Start-Sleep 6
    Stop-Agent
    $queued = @(Get-ChildItem $queue -Filter '*.json' | ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Json } | Where-Object { $_.keyPath -like "*$testName*" })
    if ($queued.Count -lt 5) { throw "Expected at least five controlled queued events; observed $($queued.Count)." }
    $queuedIds = @($queued.eventId | Sort-Object -Unique)
    $queueBeforeRestart = @(Get-ChildItem $queue -Filter '*.json').Count
    Start-Agent 'offline-restarted'
    Start-Sleep 4
    $queueAfterOfflineRestart = @(Get-ChildItem $queue -Filter '*.json').Count
    if ($queueAfterOfflineRestart -lt $queuedIds.Count) { throw 'Queue records disappeared while gateway remained unavailable.' }
    & docker compose @compose up -d gateway | Out-Null
    Wait-Gateway
    $drainStarted = [DateTimeOffset]::UtcNow
    $deadline = $drainStarted.AddSeconds(90)
    do { Start-Sleep 1; $depth = @(Get-ChildItem $queue -Filter '*.json' -ErrorAction SilentlyContinue).Count } while ($depth -gt 0 -and [DateTimeOffset]::UtcNow -lt $deadline)
    if ($depth -ne 0) { throw "Registry queue did not drain; depth $depth." }
    $drainSeconds = ([DateTimeOffset]::UtcNow - $drainStarted).TotalSeconds
    $from = [uri]::EscapeDataString($started.AddSeconds(-2).ToString('O'))
    $to = [uri]::EscapeDataString(([DateTimeOffset]::UtcNow.AddSeconds(2)).ToString('O'))
    $projectionDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 500
        $api = @((Invoke-RestMethod "http://localhost:8080/api/v1/registry-events?endpointId=$endpoint&from=$from&to=$to&path=$testName&pageSize=200" -Headers $headers).data.items)
        $apiIds = @($api.eventId | Sort-Object -Unique)
        $projected = @($queuedIds | Where-Object { $_ -in $apiIds }).Count
    } while ($projected -lt $queuedIds.Count -and [DateTimeOffset]::UtcNow -lt $projectionDeadline)
    $missing = @($queuedIds | Where-Object { $_ -notin $apiIds })
    $duplicates = @($api | Group-Object eventId | Where-Object Count -gt 1).Count
    $report = [ordered]@{
        schema = 'platform.sprint4.registry-offline-replay.v1'; executedAt = [DateTimeOffset]::UtcNow
        endpointId = $endpoint; testPath = $native
        queuedControlledEvents = $queued.Count; queuedUniqueEventIds = $queuedIds.Count
        queueBeforeAgentRestart = $queueBeforeRestart; queueAfterOfflineAgentRestart = $queueAfterOfflineRestart
        replayedEventIds = @($queuedIds | Where-Object { $_ -in $apiIds }).Count; missingEventIds = $missing
        duplicateEvents = $duplicates; finalQueueDepth = $depth; drainSeconds = [math]::Round($drainSeconds, 3)
        gatewayWasUnavailable = $true; agentRestartedWhileOffline = $true
        passed = $missing.Count -eq 0 -and $duplicates -eq 0 -and $depth -eq 0 -and $queueAfterOfflineRestart -ge $queuedIds.Count
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content $Output
    $report | ConvertTo-Json -Depth 8
    if (-not $report.passed) { exit 1 }
} finally {
    try { & docker compose @compose up -d gateway | Out-Null; Wait-Gateway } catch { }
    Stop-Agent
    Remove-Item -LiteralPath "HKCU:\$relative" -Recurse -Force -ErrorAction SilentlyContinue
}
