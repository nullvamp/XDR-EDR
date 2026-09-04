param(
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
    [string]$Output = 'artifacts/sprint38-installed-agent-drain.json',
    [int]$TimeoutSeconds = 1800
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$credential = Import-Clixml -LiteralPath $CredentialPath
$result = Invoke-Command -VMName $VictimVmName -Credential $credential -ArgumentList $TimeoutSeconds -ScriptBlock {
    param($Timeout)
    $data = 'C:\ProgramData\OpenSecurityPlatform\Agent\data'
    $queueNames = @('process','file','registry','network','dns','module','persistence','identity','execution')
    function QueueState {
        $rows = @($queueNames | ForEach-Object {
            [pscustomobject]@{ name = $_; active = @(Get-ChildItem (Join-Path $data "$_-queue") -File -Filter '*.json' -ErrorAction SilentlyContinue).Count }
        })
        [pscustomobject]@{ rows = $rows; active = [long](($rows.active | Measure-Object -Sum).Sum) }
    }
    $before = QueueState
    $priorDrain = [Environment]::GetEnvironmentVariable('PLATFORM_TELEMETRY_DRAIN_ONLY', 'Machine')
    try {
        [Environment]::SetEnvironmentVariable('PLATFORM_TELEMETRY_DRAIN_ONLY', 'true', 'Machine')
        Stop-Service OpenSecurityPlatformAgent -Force -ErrorAction SilentlyContinue
        Start-Service OpenSecurityPlatformAgent
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Timeout)
        do {
            Start-Sleep 3
            $current = QueueState
            if ((Get-Service OpenSecurityPlatformAgent).Status -ne 'Running') { throw 'Drain-only service exited unexpectedly.' }
        } while ($current.active -gt 0 -and [DateTimeOffset]::UtcNow -lt $deadline)
    }
    finally {
        [Environment]::SetEnvironmentVariable('PLATFORM_TELEMETRY_DRAIN_ONLY', $priorDrain, 'Machine')
        Stop-Service OpenSecurityPlatformAgent -Force -ErrorAction SilentlyContinue
    }
    $after = QueueState
    [pscustomobject]@{
        before = $before
        after = $after
        service = (Get-Service OpenSecurityPlatformAgent).Status.ToString()
        timedOut = $after.active -gt 0
        errorTail = @()
    }
}
$report = [ordered]@{
    schemaVersion = 'sprint38-installed-agent-drain.v1'
    capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
    result = $result
    passed = $result.after.active -eq 0 -and $result.service -eq 'Stopped' -and -not $result.timedOut
}
$report | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $root $Output) -Encoding utf8
$report | ConvertTo-Json -Depth 10
if (-not $report.passed) { exit 1 }
