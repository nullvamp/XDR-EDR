param(
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
    [string]$Output = 'artifacts/sprint38-endpoint-overhead.json'
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$credential = Import-Clixml -LiteralPath $CredentialPath
$measurement = Invoke-Command -VMName $VictimVmName -Credential $credential -ScriptBlock {
    function QueueDepth {
        $names = @('process','file','registry','network','dns','module','persistence','identity','execution')
        [long](($names | ForEach-Object {
            @(Get-ChildItem "C:\ProgramData\OpenSecurityPlatform\Agent\data\$($_)-queue" -File -Filter '*.json' -ErrorAction SilentlyContinue).Count
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
            Start-Sleep 1
            $process.Refresh()
            $rows += [pscustomobject]@{
                cpuPercent = [math]::Round((($process.TotalProcessorTime.TotalMilliseconds - $cpuBefore) / 1000 / [Environment]::ProcessorCount) * 100, 3)
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
            os = $os.Caption; build = $os.BuildNumber; architecture = $os.OSArchitecture
            logicalProcessors = [Environment]::ProcessorCount; memoryBytes = [long]$os.TotalVisibleMemorySize * 1KB
        }
        service = (Get-Service OpenSecurityPlatformAgent).Status.ToString()
        idle = Sample 'idle' $false
        active = Sample 'controlled-process-activity' $true
    }
}
$criteria = [ordered]@{
    serviceRunning = $measurement.service -eq 'Running'
    completeSamples = $measurement.idle.samples -eq 12 -and $measurement.active.samples -eq 12
    idlePrivateBelow512MiB = $measurement.idle.privateBytesPeak -lt 512MB
    activePrivateBelow768MiB = $measurement.active.privateBytesPeak -lt 768MB
    activeWorkingSetBelow1GiB = $measurement.active.workingSetPeakBytes -lt 1GB
    idleCpuMeanBelow25Percent = $measurement.idle.cpuMeanPercent -lt 25
}
$report = [ordered]@{
    schemaVersion = 'sprint38-endpoint-overhead.v1'
    capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
    scope = 'Single authorized 2 GiB Windows victim VM; engineering threshold, not a universal fleet claim.'
    measurement = $measurement
    criteria = $criteria
    passed = @($criteria.Values | Where-Object { -not $_ }).Count -eq 0
}
$report | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $root $Output) -Encoding utf8
$report | ConvertTo-Json -Depth 10
if (-not $report.passed) { exit 1 }
