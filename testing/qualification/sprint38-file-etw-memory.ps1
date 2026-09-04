param(
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
    [string]$Output = 'artifacts/sprint38-file-etw-memory-stress.json'
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$credential = Import-Clixml -LiteralPath $CredentialPath
$session = New-PSSession -VMName $VictimVmName -Credential $credential
try {
    $result = Invoke-Command $session {
        $stressRoot = 'C:\Sprint38Qualification\memory-stress'
        Remove-Item $stressRoot -Recurse -Force -ErrorAction SilentlyContinue
        New-Item $stressRoot -ItemType Directory | Out-Null
        $samples = @()
        1..12 | ForEach-Object {
            $batch = $_
            1..2000 | ForEach-Object {
                $path = Join-Path $stressRoot ("f-$batch-$_-$([guid]::NewGuid().ToString('N')).tmp")
                [IO.File]::WriteAllText($path, 'sprint38-memory-bound')
                [IO.File]::Move($path, "$path.renamed")
                [IO.File]::Delete("$path.renamed")
            }
            $process = Get-Process Platform.Agent -ErrorAction Stop
            $samples += [pscustomobject]@{
                batch = $batch
                operations = $batch * 6000
                workingSetBytes = [long]$process.WorkingSet64
                privateBytes = [long]$process.PrivateMemorySize64
                capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
            }
        }
        Start-Sleep 30
        $process = Get-Process Platform.Agent -ErrorAction Stop
        Remove-Item $stressRoot -Recurse -Force -ErrorAction SilentlyContinue
        [pscustomobject]@{
            samples = $samples
            postSettle = [pscustomobject]@{
                workingSetBytes = [long]$process.WorkingSet64
                privateBytes = [long]$process.PrivateMemorySize64
            }
            service = (Get-Service OpenSecurityPlatformAgent).Status.ToString()
            vmFreeMemoryKB = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory
        }
    }
}
finally {
    Remove-PSSession $session
}
$first = $result.samples[0]
$last = $result.samples[-1]
$report = [ordered]@{
    schemaVersion = 'sprint38-file-etw-memory-stress.v1'
    capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
    scope = 'Authorized isolated Windows victim VM; 72,000 create/rename/delete operations.'
    result = $result
    criteria = [ordered]@{
        serviceRunning = $result.service -eq 'Running'
        privateBytesBelow512MiB = $result.postSettle.privateBytes -lt 512MB
        workingSetBelow768MiB = $result.postSettle.workingSetBytes -lt 768MB
        noRunawayGrowth = ($last.privateBytes - $first.privateBytes) -lt 256MB
    }
}
$report.passed = @($report.criteria.Values | Where-Object { -not $_ }).Count -eq 0
$report | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $root $Output) -Encoding utf8
$report | ConvertTo-Json -Depth 10
if (-not $report.passed) { exit 1 }
