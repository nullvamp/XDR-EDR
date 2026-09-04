param(
    [string]$Agent = 'sprint3g-linux-agent-8',
    [string]$Output = 'artifacts/sprint3h-final-reconciliation.json'
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root

$baseOutput = 'artifacts/sprint3h-final-reconciliation-base.json'
& (Join-Path $PSScriptRoot 'sprint3g-final-reconciliation.ps1') -Agent $Agent -Output $baseOutput | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Base reconciliation failed.' }
$report = Get-Content -LiteralPath $baseOutput -Raw | ConvertFrom-Json

$runtime = Get-Content artifacts/sprint3h-windows-runtime-delete-recreate.json -Raw | ConvertFrom-Json
$run = Get-ChildItem artifacts -Directory -Filter 'sprint3e-windows-*' |
    Where-Object { Select-String -Path (Join-Path $_.FullName 'agent.log') -SimpleMatch $runtime.endpointId -Quiet } |
    Select-Object -First 1
if (-not $run) { throw 'Windows qualification workspace was not found.' }

function Local-Count([string]$Directory, [string]$Filter) {
    if (-not (Test-Path -LiteralPath $Directory)) { return 0 }
    @(Get-ChildItem -LiteralPath $Directory -File -Filter $Filter -ErrorAction SilentlyContinue).Count
}
function Container-Count([string]$Directory, [string]$Pattern) {
    [int](docker exec $Agent sh -c "find '$Directory' -maxdepth 1 -type f -name '$Pattern' 2>/dev/null | wc -l")
}

$windowsQueue = Join-Path $run.FullName 'file-queue'
$windowsHash = Join-Path $run.FullName 'file-hash-work'
$windows = [ordered]@{
    endpointId = $runtime.endpointId
    activeQueue = Local-Count $windowsQueue '*.json'
    temporaryQueue = Local-Count $windowsQueue '*.tmp'
    committingQueue = Local-Count $windowsQueue '*.committing'
    hashPending = Local-Count $windowsHash '*.json'
    hashActive = Local-Count $windowsHash '*.active'
    controlledQuarantine = Local-Count (Join-Path $windowsQueue 'quarantine') '*'
}
$linuxHashActive = Container-Count '/data/file-hash-work' '*.active'
$linuxQuarantine = Container-Count '/data/file-queue/quarantine' '*'

$report.schema = 'platform.sprint3h.final-reconciliation.v1'
$report.executedAt = [DateTimeOffset]::UtcNow.ToString('O')
$report.windows = $windows
$report.hashQueue | Add-Member -Force NoteProperty linuxActive $linuxHashActive
$report.hashQueue | Add-Member -Force NoteProperty windowsPending $windows.hashPending
$report.hashQueue | Add-Member -Force NoteProperty windowsActive $windows.hashActive
$report.controlledQuarantine = @{ linux = $linuxQuarantine; windows = $windows.controlledQuarantine }
$report.passed = $report.passed -and
    $windows.activeQueue -eq 0 -and $windows.temporaryQueue -eq 0 -and
    $windows.committingQueue -eq 0 -and $windows.hashPending -eq 0 -and
    $windows.hashActive -eq 0 -and $windows.controlledQuarantine -eq 0 -and
    $linuxHashActive -eq 0 -and $linuxQuarantine -eq 0

$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Output
$report | ConvertTo-Json -Depth 12
if (-not $report.passed) { throw 'Sprint 3H final reconciliation has a discrepancy.' }
