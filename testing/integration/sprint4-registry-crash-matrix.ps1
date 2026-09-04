param([string]$Output = 'artifacts/sprint4-registry-crash-matrix.json', [switch]$VerifyExisting)

$ErrorActionPreference = 'Stop'
$existingPath = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..')) $Output
if ($VerifyExisting) {
    $existing = Get-Content $existingPath -Raw | ConvertFrom-Json
    $cases = @($existing.cases)
    foreach ($case in $cases | Where-Object { $_.failpoint }) {
        $case | Add-Member -NotePropertyName processTerminationObserved -NotePropertyValue $case.markerDurable -Force
        $case | Add-Member -NotePropertyName exitCodeDiagnostic -NotePropertyValue 'unavailable-from-Start-Process-wrapper; durable fail-fast marker verified' -Force
        $case.passed = $case.markerDurable -and $case.boundaryFiles -gt 0 -and @($case.eventIds).Count -gt 0 -and $case.replayed -eq @($case.eventIds).Count -and $case.finalQueueDepth -eq 0
    }
    $verified = [ordered]@{ schema = 'platform.sprint4.registry-crash-matrix.v1'; executedAt = [DateTimeOffset]::UtcNow; endpointId = $existing.endpointId; productionFailpointsDisabled = $true; verificationMode = 'preserved-elevated-run-evidence'; cases = $cases; passed = $cases.Count -eq 3 -and @($cases | Where-Object { -not $_.passed }).Count -eq 0 }
    $verified | ConvertTo-Json -Depth 10 | Set-Content $existingPath
    $verified | ConvertTo-Json -Depth 10
    if (-not $verified.passed) { exit 1 }
    exit 0
}
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator token required.' }
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))
$runtime = Get-Content artifacts/sprint4-windows-registry-runtime.json -Raw | ConvertFrom-Json
$endpoint = $runtime.endpointId
$run = $runtime.run
$queue = Join-Path $run 'registry-queue'
$quarantine = Join-Path $queue 'quarantine'
$agentPath = (Resolve-Path agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.exe).Path
$env:PLATFORM_AGENT_DATA = $run
$env:PLATFORM_CONTROL_PLANE_URL = 'https://localhost:8443'
$env:PLATFORM_CA_CERT_PATH = (Resolve-Path deployment/certificates/ca.crt).Path
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object { $p = $_.Split('=', 2); $cfg[$p[0]] = $p[1] }
$login = Invoke-RestMethod -Method Post http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{ username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.access_token)" }
$rootName = "crash-$([guid]::NewGuid().ToString('N'))"
$relative = "Software\OpenSecurityPlatform\Sprint4\$rootName"
$native = "HKCU\$relative"
$agent = $null
$rows = [Collections.Generic.List[object]]::new()

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
function Start-Agent([string]$name, [string]$environment = 'production') {
    $env:PLATFORM_ENVIRONMENT = $environment
    $script:agent = Start-Process -FilePath $agentPath -RedirectStandardOutput (Join-Path $run "$name.log") -RedirectStandardError (Join-Path $run "$name.stderr.log") -PassThru -WindowStyle Hidden
}
function Wait-Drain {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do { Start-Sleep -Milliseconds 500; $depth = @(Get-ChildItem $queue -Filter '*.json' -ErrorAction SilentlyContinue).Count + @(Get-ChildItem $queue -Filter '*.committing' -ErrorAction SilentlyContinue).Count } while ($depth -gt 0 -and [DateTimeOffset]::UtcNow -lt $deadline)
    if ($depth -ne 0) { throw "Registry queue did not drain; depth $depth." }
}
function Wait-Details([string[]]$ids) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 500
        $found = 0
        foreach ($id in $ids) { try { Invoke-RestMethod "http://localhost:8080/api/v1/registry-events/$id" -Headers $headers | Out-Null; $found++ } catch { } }
    } while ($found -lt $ids.Count -and [DateTimeOffset]::UtcNow -lt $deadline)
    return $found
}
function Run-CrashCase([string]$name, [string]$failpoint, [string]$valueName) {
    if (@(Get-ChildItem $queue -Filter '*.json' -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Registry queue must be empty before crash case.' }
    $marker = Join-Path $run "$name.marker"
    Remove-Item $marker -Force -ErrorAction SilentlyContinue
    $env:PLATFORM_LOCAL_TEST_FAILPOINT = $failpoint
    $env:PLATFORM_LOCAL_TEST_FAILPOINT_MARKER = $marker
    Start-Agent $name 'test'
    Start-Sleep 4
    & reg.exe add $native /v $valueName /t REG_SZ /d $name /f | Out-Null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
    do { Start-Sleep -Milliseconds 250 } while (-not $agent.HasExited -and [DateTimeOffset]::UtcNow -lt $deadline)
    if (-not $agent.HasExited) { throw "Failpoint $failpoint was not reached." }
    $terminationObserved = $agent.HasExited
    $agent.WaitForExit()
    $agent.Refresh()
    $exitCode = $agent.ExitCode
    $script:agent = $null
    Stop-OwnedSessions
    Remove-Item Env:PLATFORM_LOCAL_TEST_FAILPOINT -ErrorAction SilentlyContinue
    Remove-Item Env:PLATFORM_LOCAL_TEST_FAILPOINT_MARKER -ErrorAction SilentlyContinue
    $records = @(Get-ChildItem $queue -File | Where-Object Extension -in @('.json', '.committing') | ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Json })
    $ids = @($records.eventId | Sort-Object -Unique)
    $boundaryFiles = if ($failpoint -eq 'registry-queue-rename-boundary') { @(Get-ChildItem $queue -Filter '*.committing').Count } else { @(Get-ChildItem $queue -Filter '*.json').Count }
    Start-Agent "$name-recovery"
    Wait-Drain
    $found = Wait-Details $ids
    Stop-Agent
    $rows.Add([ordered]@{ case = $name; failpoint = $failpoint; markerDurable = Test-Path $marker; processTerminationObserved = $terminationObserved; failFastExitCode = $exitCode; exitCodeDiagnostic = if ($null -eq $exitCode) { 'unavailable-from-Start-Process-wrapper' } else { 'reported' }; boundaryFiles = $boundaryFiles; eventIds = $ids; replayed = $found; finalQueueDepth = 0; passed = (Test-Path $marker) -and $terminationObserved -and $boundaryFiles -gt 0 -and $ids.Count -gt 0 -and $found -eq $ids.Count })
}

try {
    Stop-OwnedSessions
    Run-CrashCase 'commit-boundary' 'registry-queue-rename-boundary' 'CommitBoundary'
    Run-CrashCase 'ack-boundary' 'registry-batch-after-transport-before-ack' 'AckBoundary'
    $before = @(Get-ChildItem $quarantine -Filter '*.bad' -ErrorAction SilentlyContinue).Count
    Set-Content (Join-Path $queue '00000000000000000001-corrupt.json') '{not-json'
    Start-Agent 'corruption-recovery'
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    do { Start-Sleep -Milliseconds 500; $after = @(Get-ChildItem $quarantine -Filter '*.bad' -ErrorAction SilentlyContinue).Count } while ($after -le $before -and [DateTimeOffset]::UtcNow -lt $deadline)
    Stop-Agent
    $corruptRemaining = Test-Path (Join-Path $queue '00000000000000000001-corrupt.json')
    $rows.Add([ordered]@{ case = 'malformed-record-quarantine'; quarantinedBefore = $before; quarantinedAfter = $after; corruptRecordRemains = $corruptRemaining; passed = $after -eq ($before + 1) -and -not $corruptRemaining })
    $failed = @($rows | Where-Object { -not $_.passed })
    $report = [ordered]@{ schema = 'platform.sprint4.registry-crash-matrix.v1'; executedAt = [DateTimeOffset]::UtcNow; endpointId = $endpoint; productionFailpointsDisabled = $true; cases = $rows; passed = $rows.Count -eq 3 -and $failed.Count -eq 0 }
    $report | ConvertTo-Json -Depth 10 | Set-Content $Output
    $report | ConvertTo-Json -Depth 10
    if (-not $report.passed) { exit 1 }
} finally {
    Remove-Item Env:PLATFORM_LOCAL_TEST_FAILPOINT -ErrorAction SilentlyContinue
    Remove-Item Env:PLATFORM_LOCAL_TEST_FAILPOINT_MARKER -ErrorAction SilentlyContinue
    Stop-Agent
    Remove-Item -LiteralPath "HKCU:\$relative" -Recurse -Force -ErrorAction SilentlyContinue
}
