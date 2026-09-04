param([string]$Output = 'artifacts/sprint4-registry-api-matrix.json')

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object { $p = $_.Split('=', 2); $cfg[$p[0]] = $p[1] }
function B64([byte[]]$bytes) { [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
function Jwt([string]$tenant, [string[]]$permissions, [string]$subject) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $h = B64 ([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
    $p = B64 ([Text.Encoding]::UTF8.GetBytes((@{ iss = 'security-platform'; aud = 'security-platform-api'; sub = $subject; tid = $tenant; per = $permissions; pty = 'user'; iat = $now; exp = $now + 3600; jti = [guid]::NewGuid().ToString('N') } | ConvertTo-Json -Compress)))
    $mac = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($cfg.PLATFORM_JWT_SIGNING_KEY))
    "$h.$p.$(B64 ($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$h.$p"))))"
}
function Request([string]$method, [string]$uri, [hashtable]$headers, [object]$body = $null) {
    $args = @{ Method = $method; Uri = $uri; Headers = $headers; UseBasicParsing = $true }
    if ($null -ne $body) { $args.ContentType = 'application/json'; $args.Body = $body | ConvertTo-Json -Depth 20 -Compress }
    try { $r = Invoke-WebRequest @args; return [pscustomobject]@{ Status = [int]$r.StatusCode; Text = $r.Content; Headers = $r.Headers } }
    catch { $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }; $text = ''; try { $reader = [IO.StreamReader]::new($_.Exception.Response.GetResponseStream()); $text = $reader.ReadToEnd(); $reader.Dispose() } catch {}; return [pscustomobject]@{ Status = $status; Text = $text; Headers = @{} } }
}

$login = Invoke-RestMethod -Method Post http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{ username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json)
$a = @{ Authorization = "Bearer $($login.access_token)" }
$runtime = Get-Content artifacts/sprint4-windows-registry-runtime.json -Raw | ConvertFrom-Json
$endpoint = $runtime.endpointId
$tenantA = $cfg.PLATFORM_BOOTSTRAP_TENANT_ID
$system = @{ Authorization = "Bearer $(Jwt $tenantA @('system:admin') 'sprint4-system-rebuild')" }
$fromTime = ([DateTimeOffset]$runtime.manifest[0].at).AddMinutes(-5)
$from = [uri]::EscapeDataString($fromTime.ToString('O'))
$to = [uri]::EscapeDataString(([DateTimeOffset]::UtcNow.AddMinutes(2)).ToString('O'))
$search = (Invoke-RestMethod "http://localhost:8080/api/v1/registry-events?endpointId=$endpoint&from=$from&to=$to&pageSize=500" -Headers $a).data
$events = @($search.items)
if ($events.Count -lt 1) { throw 'Registry API fixture is missing.' }
$event = $events[0]
$valueEvent = $events | Where-Object registryValueEntityId | Select-Object -First 1
$relationshipEvent = $events | Where-Object { $_.process.processEntityId } | Select-Object -First 1
$tests = [Collections.Generic.List[object]]::new()
function Add([string]$name, [bool]$passed, [object]$evidence) { $tests.Add([ordered]@{ criterion = $name; passed = $passed; evidence = $evidence }) }

$detail = (Invoke-RestMethod "http://localhost:8080/api/v1/registry-events/$($event.eventId)" -Headers $a).data
Add 'event-details' ($detail.eventId -eq $event.eventId) $detail.eventId
$keyHistory = (Invoke-RestMethod "http://localhost:8080/api/v1/endpoints/$endpoint/registry-keys/$($event.registryKeyEntityId)/history?from=$from&to=$to&pageSize=500" -Headers $a).data
Add 'key-history' (@($keyHistory.items).Count -gt 0) @($keyHistory.items).Count
$valueHistory = (Invoke-RestMethod "http://localhost:8080/api/v1/endpoints/$endpoint/registry-values/$($valueEvent.registryValueEntityId)/history?from=$from&to=$to&pageSize=500" -Headers $a).data
Add 'value-history' (@($valueHistory.items).Count -gt 0) @($valueHistory.items).Count
$timeline = (Invoke-RestMethod "http://localhost:8080/api/v1/endpoints/$endpoint/registry-timeline?from=$from&to=$to&pageSize=500" -Headers $a).data
Add 'endpoint-timeline' (@($timeline.items).Count -ge $events.Count) @($timeline.items).Count
if ($relationshipEvent) {
    $relationships = (Invoke-RestMethod "http://localhost:8080/api/v1/endpoints/$endpoint/processes/$($relationshipEvent.process.processEntityId)/registry?from=$from&to=$to" -Headers $a).data
    Add 'process-relationship' (@($relationships.items).Count -gt 0) @($relationships.items).Count
} else { Add 'process-relationship' $false 'no stable process relationship fixture' }

$sync = Request GET "http://localhost:8080/api/v1/registry-events:export?endpointId=$endpoint&from=$from&to=$to&format=csv" $a
Add 'synchronous-export' ($sync.Status -eq 200 -and $sync.Text -match 'registry-export.v1' -and $sync.Text -notmatch 'must-never-leave-endpoint') @{ status = $sync.Status; bytes = $sync.Text.Length }
$job = (Invoke-RestMethod -Method Post http://localhost:8080/api/v1/registry-exports -Headers $a -ContentType application/json -Body (@{ format = 'jsonl'; query = @{ endpointId = $endpoint; from = $fromTime.ToString('O'); to = [DateTimeOffset]::UtcNow.AddMinutes(2).ToString('O') }; fields = @(); maximumRecords = 500 } | ConvertTo-Json -Depth 10)).data
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
do { Start-Sleep -Milliseconds 500; $job = (Invoke-RestMethod "http://localhost:8080/api/v1/registry-exports/$($job.id)" -Headers $a).data } while ($job.state -in @('Pending', 'Running') -and [DateTimeOffset]::UtcNow -lt $deadline)
$exportPath = Join-Path (Get-Location) 'artifacts/sprint4-registry-export-content.jsonl'
$download = Invoke-WebRequest -Method Get -Uri "http://localhost:8080/api/v1/registry-exports/$($job.id)/content" -Headers $a -OutFile $exportPath -PassThru -UseBasicParsing
$content = [pscustomobject]@{ Status = [int]$download.StatusCode; Text = [IO.File]::ReadAllText($exportPath) }
$manifest = Request GET "http://localhost:8080/api/v1/registry-exports/$($job.id)/manifest" $a
$metadata = Request GET "http://localhost:8080/api/v1/registry-exports/$($job.id)/metadata" $a
$hash = if ($content.Status -eq 200) { (Get-FileHash -Algorithm SHA256 $exportPath).Hash.ToLowerInvariant() } else { '' }
Add 'asynchronous-export' ($job.state -eq 'Completed' -and $job.recordCount -gt 0 -and $content.Status -eq 200 -and $manifest.Status -eq 200 -and $metadata.Status -eq 200 -and $hash -eq $job.outputSha256 -and $content.Text -notmatch 'must-never-leave-endpoint') @{ id = $job.id; state = $job.state; records = $job.recordCount; hashMatch = $hash -eq $job.outputSha256 }

$rebuild = (Invoke-RestMethod -Method Post http://localhost:8080/api/v1/registry-events/projections:rebuild -Headers $system).data
$progress = (Invoke-RestMethod http://localhost:8080/api/v1/registry-events/projections:progress -Headers $system).data
$pgCount = [int](docker exec deployment-postgres-1 psql -U platform -d platform -Atc 'select count(*) from platform.registry_events')
$osCount = [int]((docker exec deployment-opensearch-1 curl -s http://localhost:9200/platform-registry-events/_count | ConvertFrom-Json).count)
Add 'projection-rebuild' ($rebuild.aliasSwitched -and $rebuild.documents -eq $pgCount -and $progress.state -eq 'completed' -and $pgCount -eq $osCount) @{ postgres = $pgCount; openSearch = $osCount; state = $progress.state; aliasSwitched = $rebuild.aliasSwitched }

$tenantB = [guid]::NewGuid().ToString()
docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -c "insert into platform.tenants(id,organization_id,name,region,status) select '$tenantB',organization_id,'Sprint4 Tenant B','local','active' from platform.tenants limit 1" | Out-Null
$b = @{ Authorization = "Bearer $(Jwt $tenantB @('platform:admin') 'sprint4-tenant-b')" }
$bSearch = Request GET "http://localhost:8080/api/v1/registry-events?from=$from&to=$to&pageSize=500" $b
$bDetail = Request GET "http://localhost:8080/api/v1/registry-events/$($event.eventId)" $b
$bKey = Request GET "http://localhost:8080/api/v1/endpoints/$endpoint/registry-keys/$($event.registryKeyEntityId)/history?from=$from&to=$to" $b
$bValue = Request GET "http://localhost:8080/api/v1/endpoints/$endpoint/registry-values/$($valueEvent.registryValueEntityId)/history?from=$from&to=$to" $b
$bTimeline = Request GET "http://localhost:8080/api/v1/endpoints/$endpoint/registry-timeline?from=$from&to=$to" $b
$bExport = Request GET "http://localhost:8080/api/v1/registry-exports/$($job.id)/content" $b
$bManifest = Request GET "http://localhost:8080/api/v1/registry-exports/$($job.id)/manifest" $b
$bPolicy = Request POST "http://localhost:8080/api/v1/registry-telemetry/policies/$($runtime.policyId):assign" $b @{ endpointId = $endpoint }
$bExclusion = Request POST "http://localhost:8080/api/v1/registry-telemetry/policies/$($runtime.policyId)/exclusions" $b @{ category = 'key-exact'; pattern = 'HKCU\Software\Foreign'; enabled = $true; reason = 'foreign mutation probe' }
$bRebuild = Request POST "http://localhost:8080/api/v1/registry-events/projections:rebuild" $b
$bProgress = Request GET "http://localhost:8080/api/v1/registry-events/projections:progress" $b
$cursorTampered = Request GET "http://localhost:8080/api/v1/registry-events?from=$from&to=$to&cursor=invalid" $b
$isolationPassed = $bSearch.Status -eq 200 -and @((ConvertFrom-Json $bSearch.Text).data.items).Count -eq 0 -and $bDetail.Status -eq 404 -and @($bKey.Status, $bValue.Status, $bTimeline.Status) -notcontains 500 -and (ConvertFrom-Json $bKey.Text).data.items.Count -eq 0 -and (ConvertFrom-Json $bValue.Text).data.items.Count -eq 0 -and (ConvertFrom-Json $bTimeline.Text).data.items.Count -eq 0 -and $bExport.Status -eq 404 -and $bManifest.Status -eq 404 -and $bPolicy.Status -in @(400, 404) -and $bExclusion.Status -eq 404 -and $bRebuild.Status -eq 403 -and $bProgress.Status -eq 403 -and $cursorTampered.Status -eq 400
Add 'two-tenant-isolation' $isolationPassed @{ search = $bSearch.Status; detail = $bDetail.Status; keyHistory = $bKey.Status; valueHistory = $bValue.Status; timeline = $bTimeline.Status; export = $bExport.Status; minioManifest = $bManifest.Status; policy = $bPolicy.Status; exclusion = $bExclusion.Status; rebuild = $bRebuild.Status; rebuildProgress = $bProgress.Status; cursor = $cursorTampered.Status }

$previewEvent = $events | Where-Object { $_.value.preview -and -not $_.value.redacted } | Select-Object -First 1
if (-not $previewEvent -and (Test-Path artifacts/sprint4-registry-capture-matrix.json)) {
    $captureMatrix = Get-Content artifacts/sprint4-registry-capture-matrix.json -Raw | ConvertFrom-Json
    $previewEvent = $captureMatrix.rows | Where-Object { $_.profile -eq 'bounded-preview' -and $_.passed } | Select-Object -First 1
}
if ($previewEvent) {
    $limited = @{ Authorization = "Bearer $(Jwt $tenantA @('registry:details:read') 'sprint4-limited-analyst')" }
    $limitedDetail = Request GET "http://localhost:8080/api/v1/registry-events/$($previewEvent.eventId)" $limited
    $limitedValue = if ($limitedDetail.Status -eq 200) { (ConvertFrom-Json $limitedDetail.Text).data.value } else { $null }
    Add 'sensitive-preview-authorization' ($limitedDetail.Status -eq 200 -and $null -eq $limitedValue.preview -and $limitedValue.failureReason -eq 'sensitive-preview-permission-required') @{ status = $limitedDetail.Status; preview = $limitedValue.preview; failureReason = $limitedValue.failureReason }
} else { Add 'sensitive-preview-authorization' $false 'no captured preview fixture' }

$frontend = Request GET http://localhost:8080/app.js @{}
Add 'frontend-contract' ($frontend.Status -eq 200 -and $frontend.Text -match 'Registry activity' -and $frontend.Text -match 'registry-telemetry-health' -and $frontend.Text -match 'Audited exclusions' -and $frontend.Text -match 'registry-policy-assign') @{ status = $frontend.Status; bytes = $frontend.Text.Length }
$outbox = [int](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.outbox where published_at is null")
$nats = docker exec deployment-nats-1 wget -qO- 'http://localhost:8222/jsz?streams=true&consumers=true' | ConvertFrom-Json
$consumer = $nats.account_details.stream_detail.consumer_detail
Add 'outbox-and-nats-drained' ($outbox -eq 0 -and $consumer.num_ack_pending -eq 0 -and $consumer.num_pending -eq 0) @{ outbox = $outbox; ackPending = $consumer.num_ack_pending; pending = $consumer.num_pending }

$failed = @($tests | Where-Object { -not $_.passed })
$report = [ordered]@{ schema = 'platform.sprint4.registry-api-matrix.v1'; executedAt = [DateTimeOffset]::UtcNow; endpointId = $endpoint; exportId = $job.id; tenantB = $tenantB; tests = $tests; passed = $failed.Count -eq 0 }
$report | ConvertTo-Json -Depth 12 | Set-Content $Output
$report | ConvertTo-Json -Depth 6
if ($failed.Count -gt 0) { exit 1 }
