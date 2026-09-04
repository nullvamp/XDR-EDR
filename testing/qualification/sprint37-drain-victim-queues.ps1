param(
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
    [string]$Output = 'artifacts/sprint37-victim-queue-drain.json',
    [int]$TimeoutSeconds = 900
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$credential = Import-Clixml -LiteralPath $CredentialPath
$result = Invoke-Command -VMName $VictimVmName -Credential $credential -ScriptBlock {
    param($Timeout)
    $queueNames = @('process','file','registry','network','dns','module','persistence','identity','execution')
    $dataRoots = @(
        'C:\Sprint19Qualification\runtime-data',
        'C:\Sprint20Qualification\runtime-data',
        'C:\Sprint21Qualification\runtime-data',
        'C:\Sprint22Qualification\runtime-data',
        'C:\Sprint24Qualification\runtime-data',
        'C:\Sprint34Qualification\runtime-data'
    ) | Where-Object { Test-Path $_ }
    function State([string]$DataRoot) {
        $active = 0L; $quarantine = 0L
        foreach ($name in $queueNames) {
            $path = Join-Path $DataRoot "$name-queue"
            $active += @(Get-ChildItem $path -File -Filter '*.json' -ErrorAction SilentlyContinue).Count
            $quarantine += @(Get-ChildItem (Join-Path $path 'quarantine') -File -Filter '*.json' -ErrorAction SilentlyContinue).Count
        }
        [pscustomobject]@{ active = $active; quarantine = $quarantine }
    }
    Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
    $rows = @()
    foreach ($dataRoot in $dataRoots) {
        $before = State $dataRoot
        if ($before.active -gt 0) {
            $env:PLATFORM_CONTROL_PLANE_URL = 'https://gateway:8443'
            $env:PLATFORM_AGENT_DATA = $dataRoot
            $env:PLATFORM_CA_CERT_PATH = 'C:\Sprint19Qualification\ca.crt'
            $env:PLATFORM_ENVIRONMENT = 'production'
            $env:PLATFORM_TELEMETRY_DRAIN_ONLY = 'true'
            $process = Start-Process 'C:\Sprint37Qualification\agent\Platform.Agent.exe' -WindowStyle Hidden -PassThru
            $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Timeout)
            do {
                Start-Sleep -Seconds 3
                $current = State $dataRoot
                if ($process.HasExited) { throw "Drain agent exited for $dataRoot" }
            } while ($current.active -gt 0 -and [DateTimeOffset]::UtcNow -lt $deadline)
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        $after = State $dataRoot
        $rows += [pscustomobject]@{
            dataRoot = $dataRoot
            activeBefore = $before.active
            activeAfter = $after.active
            quarantine = $after.quarantine
        }
    }
    Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
    [pscustomobject]@{ roots = $rows; activeTotal = [long](($rows.activeAfter | Measure-Object -Sum).Sum); runningAgents = @(Get-Process Platform.Agent -ErrorAction SilentlyContinue).Count }
} -ArgumentList $TimeoutSeconds
$report = [ordered]@{
    schemaVersion = 'sprint37-victim-queue-drain.v1'
    capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
    result = $result
    quarantineDisposition = 'Historical endpoint/installation-mismatched poison records remain intentionally quarantined with reasons; they are not active retry work.'
    passed = $result.activeTotal -eq 0 -and $result.runningAgents -eq 0
}
$report | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $root $Output) -Encoding utf8
$report | ConvertTo-Json -Depth 10
if (-not $report.passed) { exit 1 }
