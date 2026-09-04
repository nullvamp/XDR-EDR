$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
$root = Resolve-Path (Join-Path $PSScriptRoot '../..')
Set-Location $root
$settings = @{}
Get-Content .env | Where-Object { $_ -match '^\s*([^#=\s]+)=(.*)$' } | ForEach-Object { $settings[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'") }
$login = Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/auth/token -ContentType application/json -Body (@{ username=$settings.PLATFORM_BOOTSTRAP_USER; password=$settings.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json -Compress)
$headers = @{ Authorization = "Bearer $($login.access_token)" }
$native = Get-Content artifacts/sprint22-windows-forensic-collection.json -Raw | ConvertFrom-Json
$collection = $native.profiles.A.collection
$client = [System.Net.Http.HttpClient]::new()
try {
    $client.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $login.access_token)
    $manifestBytes = $client.GetByteArrayAsync("http://127.0.0.1:8080/api/v1/forensic-collections/$($collection.collectionId)/manifest").GetAwaiter().GetResult()
}
finally { $client.Dispose() }
$sha = [Security.Cryptography.SHA256]::Create()
try { $manifestHash = ([BitConverter]::ToString($sha.ComputeHash($manifestBytes))).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
$manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
$custody = Invoke-RestMethod -Headers $headers "http://127.0.0.1:8080/api/v1/forensic-collections/$($collection.collectionId)/custody"
$healthPaths = @(
    '/health/live', '/health/ready', '/api/v1/forensic-collection-health', '/api/v1/response-health',
    '/api/v1/live-response/health', '/api/v1/isolation-health', '/api/v1/process-response-health',
    '/api/v1/file-response-health', '/api/v1/persistence-remediation-health', '/api/v1/detection-health',
    '/api/v1/correlation-health', '/api/v1/investigation-health', '/api/v1/triage-health'
)
$health = [ordered]@{}
foreach ($path in $healthPaths) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Headers $headers "http://127.0.0.1:8080$path"
        $health[$path] = [ordered]@{ statusCode=[int]$response.StatusCode; status='PASS' }
    }
    catch { $health[$path] = [ordered]@{ statusCode=[int]$_.Exception.Response.StatusCode; status='FAIL' } }
}
$itemHashesValid = @($manifest.evidenceItems | Where-Object { $_.sha256 -notmatch '^[0-9a-f]{64}$' }).Count -eq 0
$report = [ordered]@{
    schemaVersion = 'sprint22-integrity-health.v1'
    capturedAt = [DateTimeOffset]::UtcNow
    collectionId = $collection.collectionId
    manifest = [ordered]@{
        expectedSha256 = $collection.result.manifestHash
        actualSha256 = $manifestHash
        hashMatches = $manifestHash -eq $collection.result.manifestHash
        collectionBinding = $manifest.collectionId -eq $collection.collectionId
        tenantBinding = $manifest.tenantId -eq $collection.tenantId
        endpointBinding = $manifest.endpointId -eq $collection.endpointId
        installationBinding = $manifest.agentInstallationId -eq $collection.agentInstallationId
        itemCount = @($manifest.evidenceItems).Count
        itemHashesValid = $itemHashesValid
    }
    custody = [ordered]@{
        schemaVersion = $custody.data.schemaVersion
        legalAdmissibilityClaimed = $custody.data.legalAdmissibilityClaimed
        eventCount = @($custody.data.events).Count
        eventHashesValid = @($custody.data.events | Where-Object { $_.integrityHash -notmatch '^[0-9a-f]{64}$' }).Count -eq 0
    }
    health = $health
}
$report['passed'] = $report.manifest.hashMatches -and $report.manifest.collectionBinding -and $report.manifest.tenantBinding -and $report.manifest.endpointBinding -and $report.manifest.installationBinding -and $report.manifest.itemHashesValid -and -not $report.custody.legalAdmissibilityClaimed -and $report.custody.eventCount -gt 0 -and $report.custody.eventHashesValid -and @($health.Values | Where-Object status -eq 'FAIL').Count -eq 0
$report | ConvertTo-Json -Depth 30 | Set-Content artifacts/sprint22-integrity-health.json -Encoding utf8
$report | ConvertTo-Json -Depth 30
if (-not $report.passed) { exit 1 }
