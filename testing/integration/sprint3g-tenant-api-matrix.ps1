param([string]$Output = 'artifacts/sprint3g-tenant-api-matrix.json')

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '../..'))

$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object {
    $pair = $_.Split('=', 2)
    $cfg[$pair[0]] = $pair[1]
}

function B64Url([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-TestJwt([string]$tenant, [string[]]$permissions, [string]$subject) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = B64Url ([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
    $payload = B64Url ([Text.Encoding]::UTF8.GetBytes((@{
        iss = 'security-platform'; aud = 'security-platform-api'; sub = $subject
        tid = $tenant; per = $permissions; pty = 'user'; iat = $now; exp = $now + 3600
        jti = [guid]::NewGuid().ToString('N')
    } | ConvertTo-Json -Compress)))
    $hmac = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($cfg.PLATFORM_JWT_SIGNING_KEY))
    "$header.$payload.$(B64Url ($hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$header.$payload"))))"
}

$login = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{
    username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD
} | ConvertTo-Json)
$tenantA = $cfg.PLATFORM_BOOTSTRAP_TENANT_ID
$headersA = @{ Authorization = "Bearer $($login.access_token)" }
$systemA = @{ Authorization = "Bearer $(New-TestJwt $tenantA @('system:admin') 'sprint3g-system-admin')" }
$tenantB = [guid]::NewGuid().ToString()
docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -c "insert into platform.tenants(id,organization_id,name,region,status) select '$tenantB',organization_id,'Sprint3G Tenant B','local','active' from platform.tenants limit 1" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Tenant B fixture creation failed.' }
$headersB = @{ Authorization = "Bearer $(New-TestJwt $tenantB @('platform:admin') 'sprint3g-tenant-b')" }

$tests = [Collections.Generic.List[object]]::new()
function Invoke-MatrixRequest {
    param(
        [string]$Name, [string]$Method, [string]$Uri, [hashtable]$Headers,
        [object]$Body = $null, [int[]]$Expected = @(200), [scriptblock]$Validate = $null
    )
    $status = 0
    $text = ''
    try {
        $args = @{ Method = $Method; Uri = $Uri; Headers = $Headers; UseBasicParsing = $true }
        if ($null -ne $Body) {
            $args.ContentType = 'application/json'
            $args.Body = $Body | ConvertTo-Json -Depth 20 -Compress
        }
        $response = Invoke-WebRequest @args
        $status = [int]$response.StatusCode
        $text = $response.Content
    } catch {
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        try {
            $reader = [IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            $text = $reader.ReadToEnd()
            $reader.Dispose()
        } catch {}
    }
    $secretLeak = $text -match [regex]::Escape($cfg.PLATFORM_BOOTSTRAP_PASSWORD) -or
        $text -match [regex]::Escape($cfg.POSTGRES_PASSWORD) -or
        $text -match [regex]::Escape($cfg.MINIO_APP_PASSWORD)
    $valid = $true
    if ($Validate) {
        try { $valid = [bool](& $Validate $status $text) } catch { $valid = $false }
    }
    $passed = $status -in $Expected -and $status -ne 500 -and -not $secretLeak -and $valid
    $tests.Add([ordered]@{
        operation = $Name; method = $Method; uri = $Uri; expected = $Expected
        actual = $status; responseBytes = $text.Length; validationPassed = $valid
        serverError = $status -eq 500; secretLeak = $secretLeak; passed = $passed
    })
    [pscustomobject]@{ Status = $status; Text = $text; Passed = $passed }
}

function DataItemsAreEmpty([int]$status, [string]$text) {
    if ($status -ne 200) { return $false }
    $json = $text | ConvertFrom-Json
    @($json.data.items).Count -eq 0
}

$sample = Invoke-MatrixRequest 'search-tenant-a-fixture' GET 'http://localhost:8080/api/v1/files?pageSize=2' $headersA $null @(200) {
    param($status, $text) @((ConvertFrom-Json $text).data.items).Count -gt 0
}
$sampleJson = $sample.Text | ConvertFrom-Json
$entity = $sampleJson.data.items[0]
$endpointId = [string]$entity.endpointId
$entityId = [string]$entity.fileEntityId
$cursor = [string]$sampleJson.data.nextCursor

$nativeRow = docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select event_id::text||'|'||endpoint_id::text||'|'||(event_data->>'fileEntityId')||'|'||(event_data->'nativeIdentity'->>'fileId')||'|'||(event_data->'nativeIdentity'->>'deviceId')||'|'||(event_data->'nativeIdentity'->>'inode') from platform.file_events where tenant_id='$tenantA' and event_data->'nativeIdentity'->>'fileId' is not null order by observed_at desc limit 1"
if ($LASTEXITCODE -ne 0 -or -not $nativeRow) { throw 'Native identity event fixture is unavailable.' }
$native = $nativeRow.Trim().Split('|')
$eventId = $native[0]
$nativeEndpoint = $native[1]
$nativeEntity = $native[2]
$nativeFileId = $native[3]
$deviceId = $native[4]
$inode = $native[5]
$previousRow = docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select p from platform.file_entities e cross join lateral unnest(e.previous_paths) p where tenant_id='$tenantA' order by last_observed desc limit 1"
$previousPath = $previousRow.Trim()

$foreignSearches = @(
    @('search', ''), @('path-search', 'path=..%2F..%2F'), @('encoded-path-search', 'path=%252e%252e%252f'),
    @('unicode-search', 'path=%CE%94'), @('case-search', 'path=C%3A%5CTEMP'), @('filename-search', 'filename=sample.txt'),
    @('hash-search', ('sha256=' + ('a' * 64))), @('user-search', 'user=root'), @('container-search', 'container=guess'),
    @('destination-path-search', 'path=destination-probe')
)
foreach ($entry in $foreignSearches) {
    $suffix = if ($entry[1]) { '&' + $entry[1] } else { '' }
    Invoke-MatrixRequest $entry[0] GET "http://localhost:8080/api/v1/files?pageSize=5$suffix" $headersB $null @(200) ${function:DataItemsAreEmpty} | Out-Null
}

Invoke-MatrixRequest 'event-details-tenant-a' GET "http://localhost:8080/api/v1/file-events/$eventId" $headersA $null @(200) {
    param($status, $text) (ConvertFrom-Json $text).data.eventId -eq $eventId
} | Out-Null
Invoke-MatrixRequest 'event-details-foreign' GET "http://localhost:8080/api/v1/file-events/$eventId" $headersB $null @(404) | Out-Null
Invoke-MatrixRequest 'entity-details-foreign' GET "http://localhost:8080/api/v1/endpoints/$nativeEndpoint/files/$nativeEntity" $headersB $null @(404) | Out-Null
Invoke-MatrixRequest 'file-history-foreign' GET "http://localhost:8080/api/v1/endpoints/$nativeEndpoint/files/$nativeEntity/history" $headersB $null @(200) ${function:DataItemsAreEmpty} | Out-Null
Invoke-MatrixRequest 'endpoint-timeline-foreign' GET "http://localhost:8080/api/v1/endpoints/$nativeEndpoint/file-timeline" $headersB $null @(200) ${function:DataItemsAreEmpty} | Out-Null
Invoke-MatrixRequest 'process-to-file-foreign' GET "http://localhost:8080/api/v1/endpoints/$nativeEndpoint/processes/$('a' * 64)/files" $headersB $null @(200) ${function:DataItemsAreEmpty} | Out-Null
Invoke-MatrixRequest 'telemetry-health-foreign' GET "http://localhost:8080/api/v1/endpoints/$nativeEndpoint/file-telemetry-health" $headersB $null @(404) | Out-Null

$encodedPrevious = [uri]::EscapeDataString($previousPath)
Invoke-MatrixRequest 'previous-path-search-tenant-a' GET "http://localhost:8080/api/v1/files?pageSize=5&previousPath=$encodedPrevious" $headersA $null @(200) {
    param($status, $text) @((ConvertFrom-Json $text).data.items).Count -gt 0
} | Out-Null
Invoke-MatrixRequest 'previous-path-search-foreign' GET "http://localhost:8080/api/v1/files?pageSize=5&previousPath=$encodedPrevious" $headersB $null @(200) ${function:DataItemsAreEmpty} | Out-Null
$encodedNative = [uri]::EscapeDataString($nativeFileId)
Invoke-MatrixRequest 'native-id-search-tenant-a' GET "http://localhost:8080/api/v1/files?pageSize=5&nativeFileId=$encodedNative&deviceId=$deviceId&inode=$inode" $headersA $null @(200) {
    param($status, $text) @((ConvertFrom-Json $text).data.items).Count -gt 0
} | Out-Null
Invoke-MatrixRequest 'native-id-search-foreign' GET "http://localhost:8080/api/v1/files?pageSize=5&nativeFileId=$encodedNative&deviceId=$deviceId&inode=$inode" $headersB $null @(200) ${function:DataItemsAreEmpty} | Out-Null

if ($cursor) {
    $encodedCursor = [uri]::EscapeDataString($cursor)
    Invoke-MatrixRequest 'cursor-cross-tenant-reuse' GET "http://localhost:8080/api/v1/files?pageSize=1&cursor=$encodedCursor" $headersB $null @(400) | Out-Null
    $last = if ($cursor.EndsWith('A')) { 'B' } else { 'A' }
    $tampered = $cursor.Substring(0, $cursor.Length - 1) + $last
    Invoke-MatrixRequest 'cursor-tampering' GET "http://localhost:8080/api/v1/files?pageSize=1&cursor=$([uri]::EscapeDataString($tampered))" $headersA $null @(400) | Out-Null
}

$policiesA = (Invoke-RestMethod -Uri http://localhost:8080/api/v1/file-telemetry/policies -Headers $headersA).data
$policyA = $policiesA | Sort-Object createdAt -Descending | Select-Object -First 1
Invoke-MatrixRequest 'policy-read-foreign' GET 'http://localhost:8080/api/v1/file-telemetry/policies' $headersB $null @(200) {
    param($status, $text) @((ConvertFrom-Json $text).data).Count -eq 0
} | Out-Null
Invoke-MatrixRequest 'policy-version-tenant-a' GET "http://localhost:8080/api/v1/file-telemetry/policies/$($policyA.id)/versions/$($policyA.version)" $headersA $null @(200) | Out-Null
Invoke-MatrixRequest 'policy-version-foreign' GET "http://localhost:8080/api/v1/file-telemetry/policies/$($policyA.id)/versions/$($policyA.version)" $headersB $null @(404) | Out-Null
Invoke-MatrixRequest 'policy-assignment-foreign' POST "http://localhost:8080/api/v1/file-telemetry/policies/$($policyA.id):assign" $headersB @{ endpointId = $endpointId } @(400, 404) | Out-Null
Invoke-MatrixRequest 'policy-rollback-foreign' POST "http://localhost:8080/api/v1/file-telemetry/policies/$($policyA.id):rollback" $headersB @{ version = $policyA.version } @(400, 404) | Out-Null
Invoke-MatrixRequest 'exclusion-list-foreign' GET "http://localhost:8080/api/v1/file-telemetry/policies/$($policyA.id)/exclusions" $headersB $null @(404) | Out-Null
Invoke-MatrixRequest 'exclusion-create-foreign' POST "http://localhost:8080/api/v1/file-telemetry/policies/$($policyA.id)/exclusions" $headersB @{ category = 'path'; pattern = '/foreign/*'; enabled = $true } @(404) | Out-Null

$createdExclusion = Invoke-MatrixRequest 'exclusion-create-tenant-a' POST "http://localhost:8080/api/v1/file-telemetry/policies/$($policyA.id)/exclusions" $headersA @{ category = 'path'; pattern = '/sprint3g-matrix/*'; enabled = $true } @(201)
$createdPolicy = ($createdExclusion.Text | ConvertFrom-Json).data
$ruleId = [string]($createdPolicy.policy.exclusionRules | Select-Object -Last 1).id
Invoke-MatrixRequest 'exclusion-list-tenant-a' GET "http://localhost:8080/api/v1/file-telemetry/policies/$($createdPolicy.id)/exclusions" $headersA $null @(200) {
    param($status, $text) @((ConvertFrom-Json $text).data).Count -gt 0
} | Out-Null
Invoke-MatrixRequest 'exclusion-update-tenant-a' PUT "http://localhost:8080/api/v1/file-telemetry/policies/$($createdPolicy.id)/exclusions/$ruleId" $headersA @{ category = 'path'; pattern = '/sprint3g-matrix-updated/*'; enabled = $true } @(200) | Out-Null
Invoke-MatrixRequest 'exclusion-update-foreign' PUT "http://localhost:8080/api/v1/file-telemetry/policies/$($createdPolicy.id)/exclusions/$ruleId" $headersB @{ category = 'path'; pattern = '/foreign/*'; enabled = $true } @(404) | Out-Null
Invoke-MatrixRequest 'exclusion-delete-tenant-a' DELETE "http://localhost:8080/api/v1/file-telemetry/policies/$($createdPolicy.id)/exclusions/$ruleId" $headersA $null @(200) | Out-Null
Invoke-MatrixRequest 'exclusion-delete-foreign' DELETE "http://localhost:8080/api/v1/file-telemetry/policies/$($createdPolicy.id)/exclusions/$ruleId" $headersB $null @(404) | Out-Null
Invoke-MatrixRequest 'exclusion-match-all-rejected' POST "http://localhost:8080/api/v1/file-telemetry/policies/$($policyA.id)/exclusions" $headersA @{ category = 'path'; pattern = '*'; enabled = $true } @(400) | Out-Null

Invoke-MatrixRequest 'projection-rebuild-platform-admin-denied' POST 'http://localhost:8080/api/v1/files/projections:rebuild' $headersB $null @(403) | Out-Null
Invoke-MatrixRequest 'projection-progress-platform-admin-denied' GET 'http://localhost:8080/api/v1/files/projections:progress' $headersB $null @(403) | Out-Null
Invoke-MatrixRequest 'projection-progress-system-admin' GET 'http://localhost:8080/api/v1/files/projections:progress' $systemA $null @(200) | Out-Null

$exportBody = @{ format = 'jsonl'; query = @{ endpointId = $nativeEndpoint }; fields = @(); maximumRecords = 10 }
$createdExport = Invoke-MatrixRequest 'export-create-tenant-a' POST 'http://localhost:8080/api/v1/file-exports' $headersA $exportBody @(202)
$exportId = [string](($createdExport.Text | ConvertFrom-Json).data.id)
$job = $null
foreach ($attempt in 1..40) {
    Start-Sleep -Milliseconds 250
    $job = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/file-exports/$exportId" -Headers $headersA
    if ($job.data.state -in @('Completed', 'Failed')) { break }
}
Invoke-MatrixRequest 'export-status-tenant-a' GET "http://localhost:8080/api/v1/file-exports/$exportId" $headersA $null @(200) {
    param($status, $text) (ConvertFrom-Json $text).data.state -eq 'Completed'
} | Out-Null
Invoke-MatrixRequest 'export-metadata-tenant-a' GET "http://localhost:8080/api/v1/file-exports/$exportId/metadata" $headersA $null @(200) | Out-Null
Invoke-MatrixRequest 'export-manifest-tenant-a' GET "http://localhost:8080/api/v1/file-exports/$exportId/manifest" $headersA $null @(200) | Out-Null
Invoke-MatrixRequest 'export-download-tenant-a' GET "http://localhost:8080/api/v1/file-exports/$exportId/content" $headersA $null @(200) | Out-Null
foreach ($surface in @('', '/metadata', '/manifest', '/content')) {
    Invoke-MatrixRequest "export-foreign$($surface.Replace('/', '-'))" GET "http://localhost:8080/api/v1/file-exports/$exportId$surface" $headersB $null @(404) | Out-Null
}
Invoke-MatrixRequest 'export-download-url-foreign' POST "http://localhost:8080/api/v1/file-exports/$exportId/download-url" $headersB @{ expiresInSeconds = 30 } @(404) | Out-Null
Invoke-MatrixRequest 'sync-export-foreign-endpoint' GET "http://localhost:8080/api/v1/files:export?endpointId=$nativeEndpoint" $headersB $null @(200) {
    param($status, $text) $text -notmatch [regex]::Escape($tenantA) -and $text.Length -le 2
} | Out-Null

Invoke-MatrixRequest 'identifier-guess-event' GET "http://localhost:8080/api/v1/file-events/$([guid]::NewGuid())" $headersB $null @(404) | Out-Null
Invoke-MatrixRequest 'identifier-guess-export' GET "http://localhost:8080/api/v1/file-exports/$([guid]::NewGuid())" $headersB $null @(404) | Out-Null
Invoke-MatrixRequest 'cached-query-first' GET 'http://localhost:8080/api/v1/files?pageSize=5&path=cache-probe' $headersB $null @(200) ${function:DataItemsAreEmpty} | Out-Null
Invoke-MatrixRequest 'cached-query-reuse' GET 'http://localhost:8080/api/v1/files?pageSize=5&path=cache-probe' $headersB $null @(200) ${function:DataItemsAreEmpty} | Out-Null

$failed = @($tests | Where-Object { -not $_.passed })
$report = [ordered]@{
    schema = 'platform.sprint3g.tenant-api-matrix.v1'
    executedAt = [DateTimeOffset]::UtcNow.ToString('O')
    tenantA = $tenantA; tenantB = $tenantB
    fixture = @{ endpointId = $nativeEndpoint; eventId = $eventId; entityId = $nativeEntity; nativeFileId = $nativeFileId; previousPath = $previousPath; exportId = $exportId }
    requiredOperations = 37
    executedRows = $tests.Count
    passedRows = @($tests | Where-Object passed).Count
    failedRows = $failed.Count
    complete = $failed.Count -eq 0
    tests = $tests
}
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Output
$report | ConvertTo-Json -Depth 5
if ($failed.Count -gt 0) { exit 1 }
