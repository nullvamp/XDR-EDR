param([string]$Output = 'artifacts/sprint3g-minio-api-export-matrix.json')

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '../..'))
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object {
    $pair = $_.Split('=', 2); $cfg[$pair[0]] = $pair[1]
}
$tenantA = $cfg.PLATFORM_BOOTSTRAP_TENANT_ID
$login = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{
    username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD
} | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.access_token)" }
$tests = [Collections.Generic.List[object]]::new()
function Add-Test([string]$name, [string]$expected, [string]$actual, [bool]$passed, [object]$evidence = $null) {
    $tests.Add([ordered]@{ operation = $name; expected = $expected; actual = $actual; passed = $passed; evidence = $evidence })
}
function Sha256([byte[]]$bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}
function Wait-Export([string]$id) {
    $states = [Collections.Generic.List[string]]::new()
    foreach ($attempt in 1..60) {
        $value = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/file-exports/$id" -Headers $headers
        $states.Add([string]$value.data.state)
        if ($value.data.state -in @('Completed', 'Failed')) { return [pscustomobject]@{ Job = $value.data; States = @($states) } }
        Start-Sleep -Milliseconds 250
    }
    throw "Export $id did not reach a terminal state."
}
function Create-Export([string]$format, [hashtable]$query, [int]$maximum = 20, [hashtable]$extra = @{}) {
    $body = @{ format = $format; query = $query; fields = @(); maximumRecords = $maximum }
    foreach ($key in $extra.Keys) { $body[$key] = $extra[$key] }
    Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/file-exports -Headers $headers -ContentType application/json -Body ($body | ConvertTo-Json -Depth 12)
}

$temp = Join-Path ([IO.Path]::GetTempPath()) "sprint3g-export-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temp | Out-Null
$fixtureEntity = ('f' * 63) + '1'
$fixtureEvent = [guid]::NewGuid().ToString()
try {
    $endpoint = docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select endpoint_id from platform.file_entities where tenant_id='$tenantA' order by last_observed desc limit 1"
    $endpoint = $endpoint.Trim()
    if (-not $endpoint) { throw 'No Tenant A file entity exists.' }

    # Production data is untrusted collector input. This fixture proves formula-leading
    # values are neutralized by the real asynchronous CSV exporter.
    docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -c "insert into platform.file_entities(tenant_id,endpoint_id,file_entity_id,native_identity,current_path,previous_paths,first_observed,last_observed,created_at,deleted_at,state,metadata,hash_metadata,latest_process,user_name,source_confidence,latest_event_id,data_quality_flags,collector_type,collector_version) select tenant_id,endpoint_id,'$fixtureEntity',native_identity,'=2+5',previous_paths,now(),now(),created_at,deleted_at,state,metadata,hash_metadata,latest_process,user_name,source_confidence,'$fixtureEvent','{}',collector_type,collector_version from platform.file_entities where tenant_id='$tenantA' and endpoint_id='$endpoint' limit 1" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'CSV injection fixture creation failed.' }

    $created = Create-Export 'jsonl' @{ endpointId = $endpoint } 20 @{ objectKey = '../../tenant-b/overwrite'; tenantPrefix = 'attacker-controlled' }
    $jsonId = [string]$created.data.id
    $jsonRun = Wait-Export $jsonId
    Add-Test 'status-transitions-jsonl' 'Pending/Running to Completed' ($jsonRun.States -join ',') ($created.data.state -eq 'Pending' -and $jsonRun.Job.state -eq 'Completed') $jsonRun.States
    $parsedObjectId = [guid]::Empty
    $serverIdValid = [guid]::TryParse([string]$jsonRun.Job.outputObjectId, [ref]$parsedObjectId)
    Add-Test 'server-generated-object-identifiers' 'three UUIDs; injected key ignored' "$($jsonRun.Job.outputObjectId),$($jsonRun.Job.manifestObjectId),$($jsonRun.Job.metadataObjectId)" ($serverIdValid -and ([string]$jsonRun.Job.outputObjectId -notmatch 'tenant-b|\.\.'))

    $jsonFile = Join-Path $temp 'export.jsonl'
    Invoke-WebRequest -Uri "http://localhost:8080/api/v1/file-exports/$jsonId/content" -Headers $headers -OutFile $jsonFile -UseBasicParsing
    $jsonBytes = [IO.File]::ReadAllBytes($jsonFile)
    $jsonHash = Sha256 $jsonBytes
    $manifest = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/file-exports/$jsonId/manifest" -Headers $headers
    $metadata = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/file-exports/$jsonId/metadata" -Headers $headers
    $lineCount = @([IO.File]::ReadAllLines($jsonFile) | Where-Object { $_.Length -gt 0 }).Count
    Add-Test 'jsonl-record-count' ([string]$jsonRun.Job.recordCount) ([string]$lineCount) ($lineCount -eq $jsonRun.Job.recordCount)
    Add-Test 'content-sha256' ([string]$jsonRun.Job.outputSha256) $jsonHash ($jsonHash -eq $jsonRun.Job.outputSha256)
    Add-Test 'manifest-integrity' 'job/hash/count/size/schema agree' "$($manifest.sha256)/$($manifest.recordCount)/$($manifest.objectSize)" (
        $manifest.exportId -eq $jsonId -and $manifest.sha256 -eq $jsonHash -and
        $manifest.recordCount -eq $lineCount -and $manifest.objectSize -eq $jsonBytes.Length -and
        $manifest.schemaVersion -eq 'file-export-manifest.v1' -and $manifest.fileEventSchemaVersion -eq 'file-event.v1'
    ) $manifest
    Add-Test 'metadata-integrity' 'completed/hash/count/object IDs agree' "$($metadata.state)/$($metadata.outputSha256)/$($metadata.recordCount)" (
        $metadata.exportId -eq $jsonId -and $metadata.state -eq 'completed' -and
        $metadata.outputSha256 -eq $jsonHash -and $metadata.recordCount -eq $lineCount -and
        $metadata.outputObjectId -eq $jsonRun.Job.outputObjectId -and $metadata.manifestObjectId -eq $jsonRun.Job.manifestObjectId
    ) $metadata

    $appHost = "http://$($cfg.MINIO_APP_USER):$($cfg.MINIO_APP_PASSWORD)@minio:9000"
    $prefix = "tenants/$($tenantA.Replace('-', ''))/objects"
    $objectChecks = @()
    foreach ($id in @($jsonRun.Job.outputObjectId, $jsonRun.Job.manifestObjectId, $jsonRun.Job.metadataObjectId)) {
        $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        $result = docker run --rm --network deployment_platform -e "MC_HOST_app=$appHost" minio/mc:latest stat "app/platform-objects/$prefix/$(([string]$id).Replace('-', ''))" 2>&1
        $code = $LASTEXITCODE; $ErrorActionPreference = $old
        $objectChecks += @{ id = $id; exitCode = $code; found = $code -eq 0 }
    }
    Add-Test 'minio-three-object-set' 'output, manifest, metadata exist' "found=$(@($objectChecks | Where-Object found).Count)/3" (@($objectChecks | Where-Object found).Count -eq 3) $objectChecks

    $urlResponse = Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/file-exports/$jsonId/download-url" -Headers $headers -ContentType application/json -Body '{"expiresInSeconds":5}'
    $signedUrl = [string]$urlResponse.data.url
    $before = (Invoke-WebRequest -Uri $signedUrl -UseBasicParsing).StatusCode
    $otherId = [guid]::NewGuid().ToString()
    $tamperedUrl = $signedUrl.Replace($jsonId, $otherId)
    $tamperedStatus = 0
    try { $tamperedStatus = (Invoke-WebRequest -Uri $tamperedUrl -UseBasicParsing).StatusCode } catch { $tamperedStatus = [int]$_.Exception.Response.StatusCode }
    Start-Sleep -Seconds 6
    $expiredStatus = 0
    try { $expiredStatus = (Invoke-WebRequest -Uri $signedUrl -UseBasicParsing).StatusCode } catch { $expiredStatus = [int]$_.Exception.Response.StatusCode }
    Add-Test 'presigned-exact-object' '200 original; 404 changed ID' "original=$before tampered=$tamperedStatus" ($before -eq 200 -and $tamperedStatus -eq 404)
    Add-Test 'presigned-expiry' '404 after five seconds' "HTTP $expiredStatus" ($expiredStatus -eq 404) @{ expiresAt = $urlResponse.data.expiresAt }

    $csvCreated = Create-Export 'csv' @{ endpointId = $endpoint; path = '=2+5' } 5
    $csvId = [string]$csvCreated.data.id
    $csvRun = Wait-Export $csvId
    $csvFile = Join-Path $temp 'export.csv'
    Invoke-WebRequest -Uri "http://localhost:8080/api/v1/file-exports/$csvId/content" -Headers $headers -OutFile $csvFile -UseBasicParsing
    $csvText = [IO.File]::ReadAllText($csvFile)
    $csvManifest = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/file-exports/$csvId/manifest" -Headers $headers
    Add-Test 'csv-export-completed' 'Completed with one record' "$($csvRun.Job.state)/$($csvRun.Job.recordCount)" ($csvRun.Job.state -eq 'Completed' -and $csvRun.Job.recordCount -eq 1)
    Add-Test 'csv-formula-injection-protected' 'formula-leading cell prefixed with apostrophe' ($csvText.Trim()) ($csvText.Contains('"''=2+5"'))
    Add-Test 'csv-manifest-integrity' 'CSV hash/count agree' "$($csvManifest.sha256)/$($csvManifest.recordCount)" ((Sha256 ([IO.File]::ReadAllBytes($csvFile))) -eq $csvManifest.sha256 -and $csvManifest.recordCount -eq 1)

    $audit = docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select action||'|'||count(*) from platform.audit_events where tenant_id='$tenantA' and resource->>'id' in ('$jsonId','$csvId') group by action order by action"
    $auditText = $audit -join "`n"
    Add-Test 'export-audit-records' 'create and download audited' $auditText ($auditText -match 'file.export.create' -and $auditText -match 'file.export.download')

    $invalidFormatStatus = 0
    try { Invoke-WebRequest -Method Post -Uri http://localhost:8080/api/v1/file-exports -Headers $headers -ContentType application/json -Body '{"format":"zip","query":{},"maximumRecords":1}' -UseBasicParsing | Out-Null } catch { $invalidFormatStatus = [int]$_.Exception.Response.StatusCode }
    Add-Test 'unsupported-format-rejected' 'HTTP 400' "HTTP $invalidFormatStatus" ($invalidFormatStatus -eq 400)
    $unboundedStatus = 0
    try { Invoke-WebRequest -Method Post -Uri http://localhost:8080/api/v1/file-exports -Headers $headers -ContentType application/json -Body '{"format":"jsonl","query":{},"maximumRecords":501}' -UseBasicParsing | Out-Null } catch { $unboundedStatus = [int]$_.Exception.Response.StatusCode }
    Add-Test 'unbounded-export-rejected' 'HTTP 400' "HTTP $unboundedStatus" ($unboundedStatus -eq 400)

    $failed = @($tests | Where-Object { -not $_.passed })
    $report = [ordered]@{
        schema = 'platform.sprint3g.minio-api-export-matrix.v1'; executedAt = [DateTimeOffset]::UtcNow.ToString('O')
        tenantA = $tenantA; jsonlExportId = $jsonId; csvExportId = $csvId
        tests = $tests; passedRows = @($tests | Where-Object passed).Count; failedRows = $failed.Count; complete = $failed.Count -eq 0
    }
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Output
    $report | ConvertTo-Json -Depth 5
    if ($failed.Count -gt 0) { exit 1 }
} finally {
    docker exec deployment-postgres-1 psql -U platform -d platform -c "delete from platform.file_entities where tenant_id='$tenantA' and file_entity_id='$fixtureEntity'" | Out-Null
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
