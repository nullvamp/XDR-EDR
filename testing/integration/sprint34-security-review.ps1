param([string]$BaseUrl = 'http://127.0.0.1:8080')
$ErrorActionPreference = 'Stop'; $root = Resolve-Path (Join-Path $PSScriptRoot '../..'); Set-Location $root
$cfg = @{}; Get-Content .env | Where-Object { $_ -match '^([^#=]+)=(.*)$' } | ForEach-Object { $cfg[$matches[1]] = $matches[2] }
$login = Invoke-RestMethod -Method Post "$BaseUrl/api/v1/auth/token" -ContentType application/json -Body (@{ username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json); $admin = @{ Authorization = "Bearer $($login.access_token)" }
function B64([byte[]]$x) { [Convert]::ToBase64String($x).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
function Jwt([string]$tenant, [string[]]$permissions) { $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); $head = B64 ([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}')); $claims = B64 ([Text.Encoding]::UTF8.GetBytes((@{ iss = 'security-platform'; aud = 'security-platform-api'; sub = 'sprint34-security'; tid = $tenant; per = $permissions; pty = 'user'; iat = $now; exp = $now + 900; jti = [guid]::NewGuid().ToString('N') } | ConvertTo-Json -Compress))); $mac = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($cfg.PLATFORM_JWT_SIGNING_KEY)); try { $sig = B64 ($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$head.$claims"))) } finally { $mac.Dispose() }; @{ Authorization = "Bearer $head.$claims.$sig" } }
function Status([string]$method, [string]$path, $headers, $body = $null) { try { $args = @{ Method = $method; Uri = "$BaseUrl$path"; Headers = $headers; UseBasicParsing = $true }; if ($null -ne $body) { $args.ContentType = 'application/json'; $args.Body = $body | ConvertTo-Json -Depth 10 -Compress }; $response = Invoke-WebRequest @args; [int]$response.StatusCode } catch { [int]$_.Exception.Response.StatusCode } }
$investigation = (Invoke-RestMethod "$BaseUrl/api/v1/investigations?limit=500" -Headers $admin).data.items | Where-Object title -like 'Sprint 34*' | Select-Object -First 1
$evidence = (Invoke-RestMethod "$BaseUrl/api/v1/forensics/evidence?investigationId=$($investigation.investigationId)&limit=500" -Headers $admin).data.items | Where-Object integrity -ne 'Missing' | Select-Object -First 1
$foreign = Jwt ([guid]::NewGuid().ToString('D')) @('forensics:read', 'forensics:download', 'forensics:custody:read', 'forensics:export')
$checks = [ordered]@{
    foreignInvestigation = (Status GET "/api/v1/investigations/$($investigation.investigationId)" $foreign) -eq 404
    foreignArtifact = (Status GET "/api/v1/forensics/evidence/$($evidence.evidenceId)" $foreign) -eq 404
    foreignDownload = (Status GET "/api/v1/forensics/evidence/$($evidence.evidenceId)/download" $foreign) -eq 404
    guessedObject = (Status GET "/api/v1/forensics/evidence/$([guid]::NewGuid())/download" $admin) -eq 404
    parserSubstitution = (Status POST "/api/v1/forensics/evidence/$($evidence.evidenceId):parse" $admin @{ parserId = 'attacker-parser'; parserVersion = '999' }) -eq 409
    artifactOverwrite = (Status PUT "/api/v1/forensics/evidence/$($evidence.evidenceId)" $admin @{ sha256 = ('0' * 64) }) -notin 200..299
    custodyMutation = (Status PUT "/api/v1/investigations/$($investigation.investigationId)/custody" $admin @{ events = @() }) -notin 200..299
    maliciousTagRejected = (Status POST "/api/v1/investigations/$($investigation.investigationId)/evidence/$($evidence.evidenceId):tag" $admin @{ tags = @('<img src=x onerror=alert(1)>') }) -in @(400, 409)
    unboundedSearchRejected = (Status GET "/api/v1/forensics/evidence?investigationId=$($investigation.investigationId)&limit=999999" $admin) -in @(400, 409)
}
$report = [ordered]@{ schemaVersion = 'sprint34-security-review.v1'; capturedAt = [DateTimeOffset]::UtcNow.ToString('o'); apiChecks = $checks; inheritedUnitControls = @('path traversal and recursive collection bounds', 'tool exact-version/hash substitution', 'unapproved tool execution boundary', 'source hash and native identity binding', 'immutable derived provenance', 'hold-aware retention', 'bounded AI evidence and injection handling', 'sensitive collection approval and server RBAC'); passed = @($checks.Values | Where-Object { -not $_ }).Count -eq 0 }
$report | ConvertTo-Json -Depth 10 | Set-Content artifacts/sprint34-security-review.json -Encoding utf8; $report | ConvertTo-Json -Depth 10
if (-not $report.passed) { throw 'Sprint 34 security review failed.' }
