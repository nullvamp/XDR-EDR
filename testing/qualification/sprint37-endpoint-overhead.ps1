param(
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
    [string]$Output = 'artifacts/sprint37-endpoint-overhead.json'
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$control = Join-Path $PSScriptRoot 'sprint37-agent-control.ps1'
& $control -Action Start -VictimVmName $VictimVmName -CredentialPath $CredentialPath | Out-Null
$credential = Import-Clixml -LiteralPath $CredentialPath
try {
    $measurement = Invoke-Command -VMName $VictimVmName -Credential $credential -ScriptBlock {
        function QueueDepth {
            $names = @('process','file','registry','network','dns','module','persistence','identity','execution')
            [long](($names | ForEach-Object {
                @(Get-ChildItem "C:\Sprint34Qualification\runtime-data\$($_)-queue" -File -Filter '*.json' -ErrorAction SilentlyContinue).Count
            } | Measure-Object -Sum).Sum)
        }
        function Sample([string]$Profile, [bool]$GenerateActivity) {
            $rows = @()
            1..12 | ForEach-Object {
                if ($GenerateActivity) {
                    1..8 | ForEach-Object { Start-Process cmd.exe -ArgumentList '/d','/c','whoami >nul & ver >nul' -WindowStyle Hidden -Wait }
                }
                $process = Get-Process Platform.Agent -ErrorAction Stop
                $cpuBefore = $process.TotalProcessorTime.TotalMilliseconds
                Start-Sleep -Milliseconds 1000
                $process.Refresh()
                $cpu = (($process.TotalProcessorTime.TotalMilliseconds - $cpuBefore) / 1000 / [Environment]::ProcessorCount) * 100
                $rows += [pscustomobject]@{
                    cpuPercent = [math]::Round($cpu, 3)
                    workingSetBytes = [long]$process.WorkingSet64
                    privateBytes = [long]$process.PrivateMemorySize64
                    queueDepth = QueueDepth
                }
            }
            [pscustomobject]@{
                profile = $Profile
                samples = $rows.Count
                cpuMeanPercent = [math]::Round(($rows.cpuPercent | Measure-Object -Average).Average, 3)
                cpuPeakPercent = [math]::Round(($rows.cpuPercent | Measure-Object -Maximum).Maximum, 3)
                workingSetMeanBytes = [long](($rows.workingSetBytes | Measure-Object -Average).Average)
                workingSetPeakBytes = [long](($rows.workingSetBytes | Measure-Object -Maximum).Maximum)
                privateBytesPeak = [long](($rows.privateBytes | Measure-Object -Maximum).Maximum)
                queueStart = [long]$rows[0].queueDepth
                queueEnd = [long]$rows[-1].queueDepth
            }
        }
        $os = Get-CimInstance Win32_OperatingSystem
        [pscustomobject]@{
            environment = [ordered]@{
                os = $os.Caption
                build = $os.BuildNumber
                architecture = $os.OSArchitecture
                logicalProcessors = [Environment]::ProcessorCount
                memoryBytes = [long]$os.TotalVisibleMemorySize * 1KB
            }
            idle = Sample 'idle' $false
            active = Sample 'controlled-process-activity' $true
        }
    }
}
finally {
    & $control -Action Stop -VictimVmName $VictimVmName -CredentialPath $CredentialPath | Out-Null
}
$report = [ordered]@{
    schemaVersion = 'sprint37-endpoint-overhead.v1'
    capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
    scope = 'Single authorized Windows victim VM; results are not a universal fleet claim.'
    measurement = $measurement
    passed = $measurement.idle.samples -eq 12 -and $measurement.active.samples -eq 12
}
$report | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $root $Output) -Encoding utf8
$report | ConvertTo-Json -Depth 10
if (-not $report.passed) { exit 1 }
