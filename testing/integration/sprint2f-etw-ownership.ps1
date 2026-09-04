param(
    [Parameter(Mandatory = $true)][string]$Workspace,
    [string]$Output = "artifacts/sprint2f-etw-ownership.json"
)

$ErrorActionPreference = "Stop"
$Workspace = (Resolve-Path $Workspace).Path
Set-Location $Workspace
$session = "OpenSecurityPlatform-ProcessLifecycle-v1"
$unrelated = "OpenSecurityPlatform-Sprint2F-Unrelated"
$provider = "{151F55DC-467D-471F-83B5-5F889D46FF66}"
$dotnet = Join-Path $Workspace ".tooling/dotnet/dotnet.exe"
$agentDll = Join-Path $Workspace "agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.dll"
$data = Join-Path $Workspace "artifacts/sprint2f-etw-owner-agent"
$log = Join-Path $data "agent.log"
$ca = Join-Path $Workspace "deployment/certificates/ca.crt"

if (Test-Path -LiteralPath $data) { Remove-Item -LiteralPath $data -Recurse -Force }
New-Item -ItemType Directory -Force $data | Out-Null
Copy-Item -LiteralPath (Join-Path $Workspace "artifacts/sprint2e-windows-agent/state.dat") -Destination (Join-Path $data "state.dat")

function Session-Exists([string]$name) {
    & logman query -ets $name *> $null
    return $LASTEXITCODE -eq 0
}
function Stop-Session([string]$name) {
    if (Session-Exists $name) { & logman stop $name -ets *> $null }
}
function Start-Agent([string]$output) {
    $env:PLATFORM_CONTROL_PLANE_URL = "https://localhost:8443"
    $env:PLATFORM_CA_CERT_PATH = $ca
    $env:PLATFORM_AGENT_DATA = $data
    $env:PLATFORM_ENVIRONMENT = "production"
    $env:PLATFORM_PROCESS_COLLECTOR = "etw"
    $env:PLATFORM_LOCAL_TEST_FAILPOINT = ""
    return Start-Process $dotnet -ArgumentList @($agentDll) -RedirectStandardOutput $output -RedirectStandardError ($output + ".stderr") -WindowStyle Hidden -PassThru
}
function Stop-Agent($process) {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
}
function Wait-Log([string]$path, [string]$pattern, [int]$seconds = 15) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($seconds)
    do {
        if ((Test-Path $path) -and (Get-Content $path -Raw) -match $pattern) { return $true }
        Start-Sleep -Milliseconds 200
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $false
}

Stop-Session $session
Stop-Session $unrelated
Remove-Item (Join-Path $data "etw-session-owner.json") -Force -ErrorAction SilentlyContinue

# Controlled external owner: same name, distinguishable configuration, no platform marker.
& logman create trace $session -p $provider 0x1 5 -nb 2 2 -bs 64 -ets *> $null
$thirdPartyBefore = Session-Exists $session
$agent = Start-Agent $log
$conflictReported = Wait-Log $log "not demonstrably owned" 12
$thirdPartyDuring = Session-Exists $session
$markerDuringConflict = Test-Path (Join-Path $data "etw-session-owner.json")

Stop-Session $session
$recovered = Wait-Log $log "health changed to healthy" 15
$platformSession = Session-Exists $session
$marker = if (Test-Path (Join-Path $data "etw-session-owner.json")) { Get-Content (Join-Path $data "etw-session-owner.json") -Raw | ConvertFrom-Json } else { $null }

# A second agent cannot evict a live demonstrably owned session.
$secondLog = Join-Path $data "second-agent.log"
$second = Start-Agent $secondLog
$liveOwnerConflict = Wait-Log $secondLog "not demonstrably owned" 8
$firstStillRunning = -not $agent.HasExited -and (Session-Exists $session)
Stop-Agent $second

# Abrupt owner death leaves a marker and session; restart reclaims only that proven stale owner.
Stop-Agent $agent
$orphanSession = Session-Exists $session
$orphanMarker = Test-Path (Join-Path $data "etw-session-owner.json")
$restartLog = Join-Path $data "restart-agent.log"
$restart = Start-Agent $restartLog
$staleRecovered = Wait-Log $restartLog "health changed to healthy" 15
$restartSession = Session-Exists $session
$restartCountEvidence = (Get-Content $restartLog -Raw) -notmatch "not demonstrably owned"

# A differently named external trace remains untouched.
& logman create trace $unrelated -p $provider 0x1 5 -nb 2 2 -bs 64 -ets *> $null
$unrelatedBefore = Session-Exists $unrelated
Start-Sleep -Seconds 2
$unrelatedDuring = Session-Exists $unrelated
Stop-Agent $restart
$unrelatedAfter = Session-Exists $unrelated
Stop-Session $unrelated
Stop-Session $session

$report = [ordered]@{
    schema = "platform.sprint2f.etw-ownership.v1"
    executedAt = [DateTimeOffset]::UtcNow.ToString("O")
    conflictingOwner = "controlled-logman-fixture"
    thirdPartyBefore = $thirdPartyBefore
    conflictReported = $conflictReported
    thirdPartyUnaffected = $thirdPartyDuring -and -not $markerDuringConflict
    recoveredWithoutEnrollment = $recovered -and $platformSession
    ownerMarkerPid = $marker.ownerPid
    livePlatformOwnerNotEvicted = $liveOwnerConflict -and $firstStillRunning
    orphanSession = $orphanSession
    orphanMarker = $orphanMarker
    staleOwnedRecovery = $staleRecovered -and $restartSession -and $restartCountEvidence
    unrelatedBefore = $unrelatedBefore
    unrelatedDuring = $unrelatedDuring
    unrelatedAfterAgentStop = $unrelatedAfter
    passed = $thirdPartyBefore -and $conflictReported -and $thirdPartyDuring -and -not $markerDuringConflict -and $recovered -and $platformSession -and $liveOwnerConflict -and $firstStillRunning -and $orphanSession -and $orphanMarker -and $staleRecovered -and $restartSession -and $unrelatedBefore -and $unrelatedDuring -and $unrelatedAfter
}
$target = if ([IO.Path]::IsPathRooted($Output)) { $Output } else { Join-Path $Workspace $Output }
$report | ConvertTo-Json -Depth 6 | Set-Content $target
$report | ConvertTo-Json -Depth 6
if (-not $report.passed) { exit 1 }
