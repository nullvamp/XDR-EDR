param(
    [Parameter(Mandatory = $true)][string]$Workspace,
    [string]$Output = "artifacts/sprint2f-crash-matrix.json"
)

$ErrorActionPreference = "Stop"
$Workspace = (Resolve-Path $Workspace).Path
Set-Location $Workspace
$dotnet = Join-Path $Workspace ".tooling/dotnet/dotnet.exe"
$agentDll = Join-Path $Workspace "agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.dll"
$generator = Join-Path $Workspace "tools/ProcessGenerator/bin/Release/net8.0/ProcessGenerator.exe"
$sourceState = Join-Path $Workspace "artifacts/sprint2e-windows-agent/state.dat"
$root = Join-Path $Workspace "artifacts/sprint2f-crash"
$ca = Join-Path $Workspace "deployment/certificates/ca.crt"

New-Item -ItemType Directory -Force $root | Out-Null
$baseState = Join-Path $root "evolving-state.dat"
Copy-Item -LiteralPath $sourceState -Destination $baseState -Force

function Reset-Case([string]$name) {
    $path = Join-Path $root $name
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
    New-Item -ItemType Directory -Force $path | Out-Null
    Copy-Item -LiteralPath $baseState -Destination (Join-Path $path "state.dat")
    return $path
}

function Set-AgentEnvironment([string]$data, [string]$control, [string]$failpoint, [string]$marker) {
    $env:PLATFORM_CONTROL_PLANE_URL = $control
    $env:PLATFORM_CA_CERT_PATH = $ca
    $env:PLATFORM_AGENT_DATA = $data
    $env:PLATFORM_ENVIRONMENT = "evaluation"
    $env:PLATFORM_PROCESS_COLLECTOR = "etw"
    $env:PLATFORM_LOCAL_TEST_FAILPOINT = $failpoint
    $env:PLATFORM_LOCAL_TEST_FAILPOINT_MARKER = $marker
    $env:PLATFORM_LOCAL_TEST_COMPRESSION_BYTES = "512"
}

function Start-Agent([string]$data, [string]$control, [string]$failpoint, [string]$marker, [string]$log) {
    Set-AgentEnvironment $data $control $failpoint $marker
    return Start-Process -FilePath $dotnet -ArgumentList @($agentDll) -RedirectStandardOutput $log -RedirectStandardError ($log + ".stderr") -PassThru -WindowStyle Hidden
}

function Wait-ExitOrMarker($process, [string]$marker, [int]$seconds = 25) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($seconds)
    while (-not $process.HasExited -and -not (Test-Path -LiteralPath $marker) -and [DateTimeOffset]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 100
        $process.Refresh()
    }
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
        $process.WaitForExit()
    }
    return (Test-Path -LiteralPath $marker)
}

function Stop-Agent($process) {
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
        $process.WaitForExit()
    }
}

function Queue-Files([string]$data) {
    $queue = Join-Path $data "process-queue"
    if (-not (Test-Path -LiteralPath $queue)) { return @() }
    return @(Get-ChildItem -LiteralPath $queue -File)
}

function Wait-Drain([string]$data, [int]$seconds = 45) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($seconds)
    do {
        $depth = @(Queue-Files $data | Where-Object Extension -eq ".json").Count
        if ($depth -eq 0) { return $true }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $false
}

# Advance the cloned identity beyond any sequence used by an earlier interrupted run.
$prime = Reset-Case "sequence-prime"
$primeProcess = Start-Agent $prime "https://localhost:9443" "" "" (Join-Path $prime "agent.log")
Start-Sleep -Seconds 3
& $generator --count 80 --concurrency 8 | Set-Content (Join-Path $prime "manifest.json")
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(25)
do {
    Start-Sleep -Milliseconds 250
    $primeDepth = @(Queue-Files $prime | Where-Object Extension -eq ".json").Count
} while ($primeDepth -lt 80 -and [DateTimeOffset]::UtcNow -lt $deadline)
Start-Sleep -Seconds 3
Stop-Agent $primeProcess
$primeRecovery = Start-Agent $prime "https://localhost:8443" "" "" (Join-Path $prime "recovery.log")
$null = Wait-Drain $prime 60
Stop-Agent $primeRecovery
Copy-Item -LiteralPath (Join-Path $prime "state.dat") -Destination $baseState -Force

$results = @()
$queuePoints = @("queue-before-rename", "queue-rename-boundary", "queue-after-rename")
foreach ($point in $queuePoints) {
    $data = Reset-Case $point
    $marker = Join-Path $data "failpoint.marker"
    $process = Start-Agent $data "https://localhost:8443" $point $marker (Join-Path $data "agent.log")
    $hit = Wait-ExitOrMarker $process $marker
    $afterCrash = @(Queue-Files $data)
    $recover = Start-Agent $data "https://localhost:8443" "" "" (Join-Path $data "recovery.log")
    $drained = Wait-Drain $data
    Stop-Agent $recover
    Copy-Item -LiteralPath (Join-Path $data "state.dat") -Destination $baseState -Force
    $afterRecovery = @(Queue-Files $data)
    $results += [ordered]@{
        category = "queue"
        failpoint = $point
        hit = $hit
        crashExitCode = $process.ExitCode
        afterCrash = @($afterCrash | Select-Object Name, Length)
        temp = @($afterCrash | Where-Object Name -Like "*.tmp").Count
        committing = @($afterCrash | Where-Object Name -Like "*.committing").Count
        final = @($afterCrash | Where-Object Extension -eq ".json").Count
        corrupt = @($afterRecovery | Where-Object Name -Like "*.corrupt").Count
        drained = $drained
        remainingFinal = @($afterRecovery | Where-Object Extension -eq ".json").Count
        passed = $hit -and $drained -and @($afterRecovery | Where-Object Name -Like "*.corrupt").Count -eq 0
    }
}

# Create one reusable, known offline queue snapshot for every batch boundary.
$seed = Reset-Case "batch-seed"
$seedProcess = Start-Agent $seed "https://localhost:9443" "" "" (Join-Path $seed "agent.log")
Start-Sleep -Seconds 3
& $generator --count 20 --concurrency 4 | Set-Content (Join-Path $seed "manifest.json")
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
do {
    Start-Sleep -Milliseconds 250
    $seedDepth = @(Queue-Files $seed | Where-Object Extension -eq ".json").Count
} while ($seedDepth -lt 20 -and [DateTimeOffset]::UtcNow -lt $deadline)
Start-Sleep -Seconds 3
Stop-Agent $seedProcess
$seedFiles = @(Queue-Files $seed | Where-Object Extension -eq ".json")
$seedEventIds = @($seedFiles | ForEach-Object { (Get-Content $_.FullName -Raw | ConvertFrom-Json).eventId })

$batchPoints = @(
    "batch-after-read",
    "batch-after-canonical",
    "batch-during-compression",
    "batch-after-compression",
    "batch-after-integrity",
    "batch-after-transport-before-ack"
)
foreach ($point in $batchPoints) {
    $data = Reset-Case $point
    $queue = Join-Path $data "process-queue"
    New-Item -ItemType Directory -Force $queue | Out-Null
    Copy-Item -LiteralPath $seedFiles.FullName -Destination $queue
    $marker = Join-Path $data "failpoint.marker"
    $process = Start-Agent $data "https://localhost:8443" $point $marker (Join-Path $data "agent.log")
    $hit = Wait-ExitOrMarker $process $marker
    $afterCrash = @(Queue-Files $data)
    $recover = Start-Agent $data "https://localhost:8443" "" "" (Join-Path $data "recovery.log")
    $drained = Wait-Drain $data
    Stop-Agent $recover
    $afterRecovery = @(Queue-Files $data)
    $results += [ordered]@{
        category = "batch"
        failpoint = $point
        hit = $hit
        crashExitCode = $process.ExitCode
        seedRecords = $seedFiles.Count
        recordsAfterCrash = @($afterCrash | Where-Object Extension -eq ".json").Count
        temporaryBatchArtifacts = @($afterCrash | Where-Object Name -Match "batch|gzip|gz").Count
        drained = $drained
        remainingFinal = @($afterRecovery | Where-Object Extension -eq ".json").Count
        corrupt = @($afterRecovery | Where-Object Name -Like "*.corrupt").Count
        passed = $hit -and $drained -and @($afterCrash | Where-Object Extension -eq ".json").Count -ge $seedFiles.Count -and @($afterRecovery | Where-Object Name -Like "*.corrupt").Count -eq 0
    }
}

$report = [ordered]@{
    schema = "platform.sprint2f.crash-matrix.v1"
    executedAt = [DateTimeOffset]::UtcNow.ToString("O")
    elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    seedRecords = $seedFiles.Count
    seedEventIds = $seedEventIds
    results = $results
    passed = @($results | Where-Object { -not $_.passed }).Count -eq 0
}
$target = if ([IO.Path]::IsPathRooted($Output)) { $Output } else { Join-Path $Workspace $Output }
$report | ConvertTo-Json -Depth 8 | Set-Content $target
$report | ConvertTo-Json -Depth 6
if (-not $report.passed) { exit 1 }
