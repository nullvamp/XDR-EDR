param(
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
    [string]$Output = 'artifacts/sprint38-file-self-exclusion.json'
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$credential = Import-Clixml -LiteralPath $CredentialPath
$result = Invoke-Command -VMName $VictimVmName -Credential $credential -ScriptBlock {
    $queue = 'C:\ProgramData\OpenSecurityPlatform\Agent\data\file-queue'
    $marker = "self-exclusion-$([guid]::NewGuid().ToString('N'))"
    $test = Join-Path 'C:\ProgramData\OpenSecurityPlatform\Agent\data' $marker
    $testStartedAt = [DateTimeOffset]::UtcNow
    $before = @(Get-ChildItem $queue -File -Filter '*.json' -ErrorAction SilentlyContinue).Count
    New-Item $test -ItemType Directory -Force | Out-Null
    1..5000 | ForEach-Object {
        $path = Join-Path $test "$_.tmp"
        [IO.File]::WriteAllText($path, 'self-data-must-not-recurse')
        [IO.File]::Delete($path)
    }
    Remove-Item $test -Recurse -Force
    Start-Sleep 15
    $queued = @(Get-ChildItem $queue -File -Filter '*.json' -ErrorAction SilentlyContinue)
    $after = $queued.Count
    $matchingQueueEvents = @($queued | ForEach-Object {
        try {
            $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) { $content | ConvertFrom-Json } else { $null }
        } catch { $null }
    } | Where-Object {
        $_ -and $_.process.processId -eq $PID -and $_.observedAt -ge $testStartedAt -and (
            $_.originalPath -like "*$marker*" -or $_.currentPath -like "*$marker*" -or
            $_.previousPath -like "*$marker*" -or $_.destinationPath -like "*$marker*" -or
            $_.currentPath -eq '<unavailable>'
        )
    }).Count
    $process = Get-Process Platform.Agent -ErrorAction Stop
    [pscustomobject]@{
        marker = $marker
        testStartedAt = $testStartedAt.ToString('o')
        generatorProcessId = $PID
        operations = 10000
        queueBefore = $before
        queueAfter = $after
        queueDelta = $after - $before
        matchingQueueEvents = $matchingQueueEvents
        privateBytes = [long]$process.PrivateMemorySize64
        service = (Get-Service OpenSecurityPlatformAgent).Status.ToString()
    }
}
$databaseMatches = [long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.file_events where observed_at >= '$($result.testStartedAt)'::timestamptz and event_data #>> '{process,processId}' = '$($result.generatorProcessId)' and ((event_data->>'originalPath') like '%$($result.marker)%' or (event_data->>'currentPath') like '%$($result.marker)%' or (event_data->>'previousPath') like '%$($result.marker)%' or (event_data->>'destinationPath') like '%$($result.marker)%' or (event_data->>'currentPath') = '<unavailable>');")
$report = [ordered]@{
    schemaVersion = 'sprint38-file-self-exclusion.v1'
    capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
    result = $result
    databaseMatches = $databaseMatches
    passed = $result.service -eq 'Running' -and $result.matchingQueueEvents -eq 0 -and $databaseMatches -eq 0 -and $result.privateBytes -lt 512MB
}
$report | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $root $Output) -Encoding utf8
$report | ConvertTo-Json -Depth 8
if (-not $report.passed) { exit 1 }
