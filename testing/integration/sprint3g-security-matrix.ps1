param(
    [string]$Output = 'artifacts/sprint3g-security-matrix.json',
    [string]$Agent = 'sprint3g-linux-agent-8'
)

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '../..'))
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object { $pair = $_.Split('=', 2); $cfg[$pair[0]] = $pair[1] }
$tests = [Collections.Generic.List[object]]::new()
function Add-Test([string]$name, [string]$expected, [string]$actual, [bool]$passed, [string]$evidence, [string]$residual = 'none') {
    $tests.Add([ordered]@{ test = $name; expected = $expected; actual = $actual; status = if ($passed) { 'PASS' } else { 'FAIL' }; evidence = $evidence; fix = if ($passed) { 'none' } else { 'required' }; residualRisk = $residual; passed = $passed })
}
function B64([byte[]]$bytes) { [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
function Agent-Jwt {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = B64 ([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
    $payload = B64 ([Text.Encoding]::UTF8.GetBytes((@{ iss = 'security-platform'; aud = 'security-platform-api'; sub = "$([guid]::NewGuid()):$([guid]::NewGuid())"; tid = $cfg.PLATFORM_BOOTSTRAP_TENANT_ID; per = @('agent:heartbeat'); pty = 'agent'; iat = $now; exp = $now + 600; jti = [guid]::NewGuid().ToString('N') } | ConvertTo-Json -Compress)))
    $hmac = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($cfg.PLATFORM_JWT_SIGNING_KEY))
    "$header.$payload.$(B64 ($hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$header.$payload"))))"
}

$hash = Get-Content -Raw artifacts/sprint3g-file-hash-race-matrix.json | ConvertFrom-Json
$symlink = $hash.cases | Where-Object name -eq 'symlink-escape-rejected'
$hardlink = $hash.cases | Where-Object name -eq 'hard-link-native-identity'
Add-Test 'symlink escape' 'symbolic link is not hashed' "$($symlink.actual)/$($symlink.failureReason)" ([bool]$symlink.passed) 'sprint3g-file-hash-race-matrix.json:symlink-escape-rejected'
Add-Test 'hard-link confusion' 'same native object; cache bound to identity' "$($hardlink.cache)" ([bool]$hardlink.passed) 'sprint3g-file-hash-race-matrix.json:hard-link-native-identity'

$apiExport = Get-Content -Raw artifacts/sprint3g-minio-api-export-matrix.json | ConvertFrom-Json
$directMinio = Get-Content -Raw artifacts/sprint3g-direct-minio-isolation.json | ConvertFrom-Json
$tenantApi = Get-Content -Raw artifacts/sprint3g-tenant-api-matrix.json | ConvertFrom-Json
foreach ($mapping in @(
    @('API-generated object-key injection', 'server-generated-object-identifiers'),
    @('tenant-prefix injection', 'server-generated-object-identifiers'),
    @('CSV formula injection', 'csv-formula-injection-protected'),
    @('export manifest integrity', 'manifest-integrity')
)) {
    $row = $apiExport.tests | Where-Object operation -eq $mapping[1]
    Add-Test $mapping[0] $row.expected $row.actual ([bool]$row.passed) "sprint3g-minio-api-export-matrix.json:$($mapping[1])"
}
$tamperRows = @($directMinio.tests | Where-Object operation -in @('overwrite', 'change-metadata', 'copy-into-a', 'delete'))
Add-Test 'manifest tampering' 'foreign tenant cannot overwrite, modify, copy into, or delete' "$(@($tamperRows | Where-Object passed).Count)/4 denied" (@($tamperRows | Where-Object passed).Count -eq 4) 'sprint3g-direct-minio-isolation.json'
$exclusionRows = @($tenantApi.tests | Where-Object operation -like 'exclusion-*-foreign')
Add-Test 'exclusion API authorization' 'all foreign mutations/reads safely denied' "$(@($exclusionRows | Where-Object passed).Count)/$($exclusionRows.Count)" ($exclusionRows.Count -ge 4 -and @($exclusionRows | Where-Object passed).Count -eq $exclusionRows.Count) 'sprint3g-tenant-api-matrix.json'

$profiles = Get-Content -Raw artifacts/sprint3g-file-hash-profiles.json | ConvertFrom-Json
$h7 = $profiles.profiles | Where-Object profile -eq 'H7'
$h8 = $profiles.profiles | Where-Object profile -eq 'H8'
Add-Test 'hash resource exhaustion' 'rate limit and race rejection bound work without loss' "H7 rateLimited=$($h7.metrics.rateLimited); H8 races=$($h8.raceDetections)" ($h7.passed -and $h8.passed -and $h7.metrics.pending -eq 0 -and $h8.metrics.pending -eq 0) 'sprint3g-file-hash-profiles.json:H7,H8'

$temp = Join-Path ([IO.Path]::GetTempPath()) "sprint3g-security-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $bomb = Join-Path $temp 'bomb.gz'
    $memory = [IO.MemoryStream]::new()
    $gzip = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionLevel]::Optimal, $true)
    $block = New-Object byte[] (1024 * 1024)
    $gzip.Write($block, 0, $block.Length); $gzip.Dispose()
    [IO.File]::WriteAllBytes($bomb, $memory.ToArray()); $memory.Dispose()
    $response = Join-Path $temp 'response.txt'
    $token = Agent-Jwt
    $status = & curl.exe -k -s -o $response -w '%{http_code}' -X POST https://localhost:8443/agent/v1/file-event-batches -H "Authorization: Bearer $token" -H 'Content-Encoding: gzip' -H 'Content-Type: application/json' -H 'X-Uncompressed-Length: 1' --data-binary "@$bomb"
    $body = [IO.File]::ReadAllText($response)
    Add-Test 'compression-bomb rejection' 'HTTP 413 before allocation beyond declared length' "HTTP $status" ([int]$status -eq 413 -and $body -match 'FILE_DECOMPRESSION_LIMIT') 'authenticated agent-type JWT; 1 MiB expands beyond declared byte'

    $oversized = Join-Path $temp 'oversized.bin'
    [IO.File]::WriteAllBytes($oversized, (New-Object byte[] (1024 * 1024 + 1)))
    $oversizedStatus = & curl.exe -k -s -o $response -w '%{http_code}' -X POST https://localhost:8443/agent/v1/file-event-batches -H "Authorization: Bearer $token" -H 'Content-Encoding: gzip' -H 'X-Uncompressed-Length: 1' --data-binary "@$oversized"
    Add-Test 'oversized compressed batch' 'HTTP 413 at compressed-size gate' "HTTP $oversizedStatus" ([int]$oversizedStatus -eq 413) 'authenticated request larger than 1 MiB'
} finally {
    if (Test-Path $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}

$permissions = docker exec $Agent sh -c "for d in /data/file-queue /data/file-hash-work /data/file-hash-cache; do stat -c '%a|%U|%G|%n' `$d; done"
$permissionRows = @($permissions | ForEach-Object { $parts = $_.Split('|'); [ordered]@{ mode = $parts[0]; user = $parts[1]; group = $parts[2]; path = $parts[3]; secure = $parts[0] -eq '700' -and $parts[1] -eq 'platform' } })
Add-Test 'queue/hash-work/hash-cache permissions' 'platform owner, mode 700' "$(@($permissionRows | Where-Object secure).Count)/3 secure" (@($permissionRows | Where-Object secure).Count -eq 3) "live $Agent" ($(if (@($permissionRows | Where-Object secure).Count -eq 3) { 'none' } else { 'volume root remains Docker-managed' }))

$gatewayLogs = docker logs --tail 500 deployment-gateway-1 2>&1 | Out-String
$agentLogs = docker logs --tail 500 $Agent 2>&1 | Out-String
$logText = $gatewayLogs + $agentLogs
$secretLeak = @($cfg.PLATFORM_BOOTSTRAP_PASSWORD, $cfg.POSTGRES_PASSWORD, $cfg.MINIO_APP_PASSWORD, $cfg.PLATFORM_JWT_SIGNING_KEY) | Where-Object { $_ -and $logText.Contains($_) }
Add-Test 'sensitive logging' 'configured secrets absent from recent production logs' "$($secretLeak.Count) matches" ($secretLeak.Count -eq 0) 'last 500 gateway and active-agent log lines'
$apiLeaks = @($tenantApi.tests | Where-Object { $_.secretLeak -or $_.serverError })
Add-Test 'error-response secret leakage' 'zero secrets and zero HTTP 500 in tenant matrix' "$($apiLeaks.Count) unsafe rows" ($apiLeaks.Count -eq 0) 'sprint3g-tenant-api-matrix.json'

$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$windowsStatus = if ($admin) { 'elevated execution required separately' } else { 'BLOCKED: current token is not Administrator' }
Add-Test 'Windows reparse-point behavior' 'execute only from elevated Windows session' $windowsStatus $false 'Windows elevation preflight' 'genuine environment blocker'
Add-Test 'Windows alternate data streams' 'execute only from elevated Windows session' $windowsStatus $false 'Windows elevation preflight' 'genuine environment blocker'

$failed = @($tests | Where-Object { -not $_.passed -and $_.residualRisk -ne 'genuine environment blocker' })
$blocked = @($tests | Where-Object { $_.residualRisk -eq 'genuine environment blocker' })
$report = [ordered]@{ schema = 'platform.sprint3g.security-matrix.v1'; executedAt = [DateTimeOffset]::UtcNow.ToString('O'); tests = $tests; passed = @($tests | Where-Object passed).Count; failed = $failed.Count; blocked = $blocked.Count; practicalLinuxAndApiComplete = $failed.Count -eq 0; complete = $failed.Count -eq 0 -and $blocked.Count -eq 0; disclaimer = 'Practical scoped security verification; not a penetration test.' }
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Output
$report | ConvertTo-Json -Depth 5
if ($failed.Count -gt 0) { exit 1 }
