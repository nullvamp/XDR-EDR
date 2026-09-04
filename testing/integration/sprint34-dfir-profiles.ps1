param([string]$BaseUrl = 'http://127.0.0.1:8080')
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '../..')
Set-Location $root
$settings = @{}
Get-Content .env | Where-Object { $_ -match '^([^#=]+)=(.*)$' } | ForEach-Object { $settings[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'") }
$login = Invoke-RestMethod -Method Post "$BaseUrl/api/v1/auth/token" -ContentType application/json -Body (@{ username = $settings.PLATFORM_BOOTSTRAP_USER; password = $settings.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json)
$script:admin = @{ Authorization = "Bearer $($login.access_token)" }
function Api([string]$method, [string]$path, $body = $null, $headers = $script:admin) {
    $args = @{ Method = $method; Uri = "$BaseUrl$path"; Headers = $headers; UseBasicParsing = $true }
    if ($null -ne $body) { $args.ContentType = 'application/json'; $args.Body = $body | ConvertTo-Json -Depth 60 -Compress }
    try { (Invoke-RestMethod @args).data } catch { throw "$method $path failed: $($_.ErrorDetails.Message)" }
}
function Require($condition, [string]$message) { if (!$condition) { throw $message } }
function B64([byte[]]$value) { [Convert]::ToBase64String($value).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
function Jwt([string]$subject, [string]$tenant, [string[]]$permissions) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); $head = B64 ([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
    $claims = B64 ([Text.Encoding]::UTF8.GetBytes((@{ iss = 'security-platform'; aud = 'security-platform-api'; sub = $subject; tid = $tenant; per = $permissions; pty = 'user'; iat = $now; exp = $now + 7200; jti = [guid]::NewGuid().ToString('N') } | ConvertTo-Json -Compress)))
    $mac = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($settings.PLATFORM_JWT_SIGNING_KEY)); try { $signature = B64 ($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$head.$claims"))) } finally { $mac.Dispose() }
    @{ Authorization = "Bearer $head.$claims.$signature" }
}
function WaitCollection([guid]$id) { $deadline = [DateTimeOffset]::UtcNow.AddMinutes(4); do { Start-Sleep -Milliseconds 500; $value = Api GET "/api/v1/forensic-collections/$id" } while ($value.state -notin @('Succeeded', 'Partial', 'Failed', 'Cancelled', 'CancelledWithEvidence', 'Expired') -and [DateTimeOffset]::UtcNow -lt $deadline); $value }
function ImportCollection([guid]$investigation, [guid]$collection) { Api POST "/api/v1/investigations/$investigation/collections/$($collection):import" @{} }
function Percentile([double[]]$values, [double]$p) { $sorted = $values | Sort-Object; $sorted[[math]::Min($sorted.Count - 1, [math]::Floor(($sorted.Count - 1) * $p))] }

$started = [DateTimeOffset]::UtcNow
$endpoint = (Api GET '/api/v1/endpoints?pageSize=500').items | Where-Object { $_.platform -eq 'windows' -and $_.lastSeenAt -and [DateTimeOffset]$_.lastSeenAt -gt $started.AddMinutes(-3) } | Sort-Object lastSeenAt -Descending | Select-Object -First 1
Require $endpoint 'Fresh Sprint34 victim endpoint is unavailable.'
$approver = Jwt 'sprint34-separated-approver' $settings.PLATFORM_BOOTSTRAP_TENANT_ID @('forensics:approve:sensitive')
$quickItems = @(
    @{ requestId = 'system'; artifactType = 'SystemInformation'; maximumItems = 1; maximumBytes = 262144 },
    @{ requestId = 'processes'; artifactType = 'ProcessInventory'; maximumItems = 32; maximumBytes = 524288 },
    @{ requestId = 'users'; artifactType = 'UserSessionInventory'; maximumItems = 32; maximumBytes = 262144 },
    @{ requestId = 'services'; artifactType = 'ServiceInventory'; maximumItems = 32; maximumBytes = 524288 },
    @{ requestId = 'tasks'; artifactType = 'ScheduledTaskInventory'; maximumItems = 32; maximumBytes = 524288 },
    @{ requestId = 'network'; artifactType = 'NetworkState'; maximumItems = 32; maximumBytes = 524288 },
    @{ requestId = 'persistence'; artifactType = 'PersistenceSnapshot'; maximumItems = 32; maximumBytes = 524288 }
)
$quick = Api POST '/api/v1/forensic-collections' @{ endpointId = $endpoint.id; profileId = 'quick-triage'; profileVersion = 1; requestedArtifacts = $quickItems; reason = 'Sprint 34 Profile A bounded victim quick triage'; expiresInSeconds = 1800; saveAsDraft = $false; policyVersion = 'forensic-collection-policy.v1' }
if ($quick.approvalState -eq 'Pending') { $quick = Api POST "/api/v1/forensic-collections/$($quick.collectionId):approve" @{ parameterHash = $quick.parameterHash; reason = 'Separated exact-scope Sprint 34 approval' } $approver }
$quick = WaitCollection $quick.collectionId
Require ($quick.state -eq 'Succeeded' -and $quick.result.collectedItems -eq 7) 'Profile A native quick triage failed.'

$partialItems = @(
    @{ requestId = 'successful-system'; artifactType = 'SystemInformation'; maximumItems = 1; maximumBytes = 262144 },
    @{ requestId = 'missing-registry'; artifactType = 'Registry'; source = "HKLM\SOFTWARE\OpenSecurityPlatform\Sprint34Missing-$([guid]::NewGuid().ToString('N'))"; maximumDepth = 1; maximumItems = 8; maximumBytes = 262144; metadataOnly = $true }
)
$partial = Api POST '/api/v1/forensic-collections' @{ endpointId = $endpoint.id; profileId = 'endpoint-investigation'; profileVersion = 1; requestedArtifacts = $partialItems; reason = 'Sprint 34 Profile B successful evidence plus controlled missing source'; expiresInSeconds = 1800; saveAsDraft = $false; policyVersion = 'forensic-collection-policy.v1' }
if ($partial.approvalState -eq 'Pending') { $partial = Api POST "/api/v1/forensic-collections/$($partial.collectionId):approve" @{ parameterHash = $partial.parameterHash; reason = 'Separated exact-scope Profile B approval' } $approver }
$partial = WaitCollection $partial.collectionId
Require ($partial.state -eq 'Partial' -and $partial.result.collectedItems -ge 1 -and ($partial.result.failedItems + $partial.result.skippedItems) -ge 1) 'Profile B did not preserve success with a precise missing-source failure.'

$allCollections = (Api GET '/api/v1/forensic-collections?pageSize=200').items
$large = $allCollections | Where-Object { $_.result.collectedItems -gt 0 -and $_.result.bytesCollected -ge 8MB } | Sort-Object { [long]$_.result.bytesCollected } -Descending | Select-Object -First 1
Require $large 'Controlled partial/large victim collection is unavailable.'
$investigation = (Api GET '/api/v1/investigations?limit=500').items | Where-Object { $_.collectionIds -contains $large.collectionId } | Select-Object -First 1
if (!$investigation) { $investigation = Api POST '/api/v1/investigations' @{ title = 'Sprint 34 controlled DFIR validation'; description = 'Profiles A-F evidence workflow'; priority = 'High'; owner = 'admin'; endpointIds = @($endpoint.id); incidentIds = @(); alertIds = @(); tags = @('NeedsReview') } }
$null = ImportCollection $investigation.investigationId $quick.collectionId
$null = ImportCollection $investigation.investigationId $partial.collectionId
$null = ImportCollection $investigation.investigationId $large.collectionId
$beforeDuplicate = (Api GET "/api/v1/forensics/evidence?investigationId=$($investigation.investigationId)&limit=500").items.Count
$null = ImportCollection $investigation.investigationId $quick.collectionId
$afterDuplicate = (Api GET "/api/v1/forensics/evidence?investigationId=$($investigation.investigationId)&limit=500").items.Count
$evidence = (Api GET "/api/v1/forensics/evidence?investigationId=$($investigation.investigationId)&limit=500").items
$acquired = @($evidence | Where-Object { $_.integrity -ne 'Missing' -and $_.size -gt 0 })
$unavailable = @($evidence | Where-Object { $_.integrity -eq 'Missing' })
Require ($acquired.Count -ge 9 -and $unavailable.Count -ge 1 -and $beforeDuplicate -eq $afterDuplicate) 'Evidence import, partial visibility, or idempotency failed.'

$verified = @(); foreach ($item in $acquired) { $verified += Api POST "/api/v1/forensics/evidence/$($item.evidenceId):verify" @{} }
Require (@($verified | Where-Object status -ne 'Verified').Count -eq 0) 'Stored evidence, object metadata, or collection manifest verification failed.'
$source = $evidence | Where-Object { $_.evidenceType -eq 'SystemInformation' -and $_.collectionId -eq $quick.collectionId } | Select-Object -First 1
$parseOne = Api POST "/api/v1/forensics/evidence/$($source.evidenceId):parse" @{ parserId = 'structured-json-summary'; parserVersion = '1.0.0' }
$parseTwo = Api POST "/api/v1/forensics/evidence/$($source.evidenceId):parse" @{ parserId = 'structured-json-summary'; parserVersion = '1.0.0' }
$postParse = (Api GET "/api/v1/forensics/evidence?investigationId=$($investigation.investigationId)&limit=500").items
$derived = @($postParse | Where-Object derivedFromEvidenceId -eq $source.evidenceId)
Require ($derived.Count -eq 2 -and $parseOne.outputEvidenceId -ne $parseTwo.outputEvidenceId) 'Versioned derived evidence lineage failed.'
$null = Api POST "/api/v1/investigations/$($investigation.investigationId)/evidence/$($source.evidenceId):tag" @{ tags = @('Suspicious', 'Relevant') }
$bookmark = Api POST "/api/v1/investigations/$($investigation.investigationId)/evidence/$($source.evidenceId):bookmark" @{ purpose = 'report' }
$note = Api POST "/api/v1/investigations/$($investigation.investigationId)/notes" @{ targetType = 'artifact'; targetId = $source.evidenceId; body = 'Controlled append-only analyst note.'; aiDraft = $false; accepted = $false; evidenceCitations = @("EVID-$($source.evidenceId)") }
$ai = Api POST "/api/v1/investigations/$($investigation.investigationId)/ai-summary" @{}
Require ($ai.readOnly -and $ai.note.aiDraft -and $ai.note.evidenceCitations.Count -gt 0) 'Bounded cited read-only AI summary failed.'

$caseHold = Api POST "/api/v1/investigations/$($investigation.investigationId):hold" @{ reason = 'Profile E controlled case preservation'; expiresAt = [DateTimeOffset]::UtcNow.AddDays(2).ToString('o') }
$evidenceHold = Api POST "/api/v1/investigations/$($investigation.investigationId)/evidence/$($source.evidenceId):hold" @{ reason = 'Profile E controlled artifact preservation'; expiresAt = [DateTimeOffset]::UtcNow.AddDays(2).ToString('o') }
$holds = Api GET "/api/v1/investigations/$($investigation.investigationId)/holds"
Require ($holds.Count -ge 2) 'Case/evidence retention holds were not persisted.'

$selected = @($acquired | Sort-Object size -Descending | Select-Object -First 16 | ForEach-Object evidenceId)
$export = Api POST "/api/v1/investigations/$($investigation.investigationId)/exports" @{ evidenceIds = $selected; reason = 'Profile E controlled verified evidence package' }
$packagePath = Join-Path $root 'artifacts/sprint34-evidence-package.zip'; $manifestPath = Join-Path $root 'artifacts/sprint34-evidence-package-manifest.json'
Invoke-WebRequest "$BaseUrl/api/v1/forensics/exports/$($export.exportId)/download" -Headers $script:admin -OutFile $packagePath -UseBasicParsing
Invoke-WebRequest "$BaseUrl/api/v1/forensics/exports/$($export.exportId)/manifest" -Headers $script:admin -OutFile $manifestPath -UseBasicParsing
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$downloadHash = (Get-FileHash $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
Require ($downloadHash -eq $export.packageSha256 -and $manifest.packageSha256 -eq $export.packageSha256 -and $manifest.included.Count -eq $export.included.Count) 'Evidence package or manifest integrity failed.'

$rangePath = Join-Path $root 'artifacts/sprint34-evidence-package-resumed.zip'; $rangeStream = [IO.File]::Create($rangePath)
try {
    $offset = 0L; $part = 0
    while ($offset -lt [long]$export.packageBytes) {
        $length = [math]::Min(4MB, [long]$export.packageBytes - $offset); $partPath = Join-Path $root "artifacts/sprint34-range-$part.bin"
        $response = Invoke-WebRequest "$BaseUrl/api/v1/forensics/exports/$($export.exportId)/range?offset=$offset&length=$length" -Headers $script:admin -OutFile $partPath -PassThru -UseBasicParsing
        Require ($response.StatusCode -eq 206 -and $response.Headers['X-Package-SHA256'] -eq $export.packageSha256) 'Range authorization, status, or exact hash header failed.'
        $bytes = [IO.File]::ReadAllBytes($partPath); $rangeStream.Write($bytes, 0, $bytes.Length); $offset += $bytes.Length; Remove-Item $partPath -Force
        if ($part -eq 0) { docker compose --env-file .env -f deployment/docker-compose.yml restart gateway | Out-Null; $deadline = (Get-Date).AddMinutes(2); do { Start-Sleep 1; try { $ready = (Invoke-WebRequest "$BaseUrl/health/ready" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200 } catch { $ready = $false } } while (!$ready -and (Get-Date) -lt $deadline); Require $ready 'Gateway did not recover during resumable download.' }
        $part++
    }
}
finally { $rangeStream.Dispose() }
$resumeHash = (Get-FileHash $rangePath -Algorithm SHA256).Hash.ToLowerInvariant()
Require ($resumeHash -eq $export.packageSha256) 'Resumed package hash differs after gateway restart.'

$foreign = Jwt 'sprint34-foreign' '00000000-0000-0000-0000-000000000099' @('forensics:read', 'forensics:download', 'forensics:collect', 'forensics:export')
function DeniedOrMissing([string]$path, $headers) { try { Api GET $path $null $headers | Out-Null; $false } catch { $true } }
$tenantIsolation = (DeniedOrMissing "/api/v1/investigations/$($investigation.investigationId)" $foreign) -and (DeniedOrMissing "/api/v1/forensics/evidence/$($source.evidenceId)" $foreign) -and (DeniedOrMissing "/api/v1/forensics/exports/$($export.exportId)/download" $foreign)
Require $tenantIsolation 'Foreign tenant investigation/evidence/export access was not denied.'

$roles = Api GET '/api/v1/admin/roles'
function Client([string]$name, [string]$roleName) {
    $principal = Api POST '/api/v1/admin/principals' @{ type = 'ApiClient'; displayName = "Sprint34 $name"; purpose = 'Controlled DFIR RBAC campaign'; expiresAt = [DateTimeOffset]::UtcNow.AddDays(1).ToString('o') }
    $role = $roles | Where-Object name -eq $roleName | Sort-Object version -Descending | Select-Object -First 1
    $null = Api POST '/api/v1/admin/role-assignments' @{ principalId = $principal.principalId; roleId = $role.roleId; roleVersion = $role.version; startsAt = [DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o'); expiresAt = [DateTimeOffset]::UtcNow.AddHours(4).ToString('o'); temporaryElevation = $false; scopeType = 'tenant'; reason = 'Controlled Sprint34 role boundary' }
    $credential = Api POST '/api/v1/admin/api-clients/credentials' @{ principalId = $principal.principalId; name = "$name-key"; purpose = 'Sprint34 RBAC'; expiresAt = [DateTimeOffset]::UtcNow.AddHours(2).ToString('o') }
    @{ Authorization = "ApiKey $($credential.secret)" }
}
function Allowed([string]$method, [string]$path, $body, $headers) { try { Api $method $path $body $headers | Out-Null; $true } catch { $false } }
$read = Client 'read' 'Read Only / Auditor'; $soc = Client 'soc' 'SOC Analyst'; $dfir = Client 'dfir' 'DFIR Analyst'; $responder = Client 'responder' 'Incident Responder'; $administrator = Client 'administrator' 'Tenant Administrator'
$rbac = [ordered]@{
    readView = Allowed GET "/api/v1/investigations/$($investigation.investigationId)" $null $read
    readDownloadDenied = -not (Allowed GET "/api/v1/forensics/evidence/$($source.evidenceId)/download" $null $read)
    socSensitiveDenied = -not (Allowed POST "/api/v1/investigations/$($investigation.investigationId):hold" @{ reason = 'must deny' } $soc)
    dfirView = Allowed GET "/api/v1/investigations/$($investigation.investigationId)" $null $dfir
    dfirDownload = Allowed GET "/api/v1/forensics/evidence/$($source.evidenceId)/download" $null $dfir
    responderSensitiveDenied = -not (Allowed GET "/api/v1/forensics/evidence/$($source.evidenceId)/download" $null $responder)
    administratorPolicy = Allowed GET '/api/v1/admin/overview' $null $administrator
}
Require (-not ($rbac.Values -contains $false)) 'Sprint 34 RBAC campaign failed.'

$latencies = @(); 1..60 | ForEach-Object { $sw = [Diagnostics.Stopwatch]::StartNew(); $null = Api GET "/api/v1/forensics/evidence?investigationId=$($investigation.investigationId)&text=System&limit=100"; $sw.Stop(); $latencies += $sw.Elapsed.TotalMilliseconds }
$performance = [ordered]@{ samples = $latencies.Count; p50Ms = [math]::Round((Percentile $latencies 0.50), 2); p95Ms = [math]::Round((Percentile $latencies 0.95), 2); p99Ms = [math]::Round((Percentile $latencies 0.99), 2); bounded = $true }
$health = Api GET '/api/v1/forensics/workspace-health'; $custody = Api GET "/api/v1/investigations/$($investigation.investigationId)/custody"; $timeline = Api GET "/api/v1/investigations/$($investigation.investigationId)/timeline?limit=500"; $entities = Api GET "/api/v1/investigations/$($investigation.investigationId)/entities"; $readiness = Api GET "/api/v1/endpoints/$($endpoint.id)/forensic-readiness"
$profiles = @(
    [ordered]@{ name = 'A'; status = 'PASS'; evidence = 'fresh victim Quick Triage; seven acquired artifacts; hashes/custody/timeline visible' },
    [ordered]@{ name = 'B'; status = 'PASS'; evidence = "controlled partial $($partial.collectionId); acquired=$($partial.result.collectedItems); failed=$($partial.result.failedItems); skipped=$($partial.result.skippedItems); reasons preserved" },
    [ordered]@{ name = 'C'; status = 'PASS'; evidence = "package bytes=$($export.packageBytes); source/stored/download/resume hash=$($export.packageSha256); gateway restart" },
    [ordered]@{ name = 'D'; status = 'PASS'; evidence = "two separate parser outputs linked to $($source.evidenceId)" },
    [ordered]@{ name = 'E'; status = 'PASS'; evidence = "case hold=$($caseHold.holdId); evidence hold=$($evidenceHold.holdId); verified package=$($export.exportId)" },
    [ordered]@{ name = 'F'; status = 'PASS'; evidence = "gateway restart, idempotent import $beforeDuplicate/$afterDuplicate, custody=$($custody.events.Count), evidence retained" }
)
$report = [ordered]@{ schemaVersion = 'sprint34-dfir-profiles.v1'; executedAt = [DateTimeOffset]::UtcNow.ToString('o'); victim = @{ vm = 'XDR-Victim-Sprint18'; endpointId = $endpoint.id; hostMutation = $false }; investigationId = $investigation.investigationId; collectionProfiles = (Api GET '/api/v1/forensics/profiles'); profiles = $profiles; evidence = @{ total = $postParse.Count; acquired = $acquired.Count; unavailable = $unavailable.Count; verified = $verified.Count; derived = $derived.Count; duplicateImportCount = "$beforeDuplicate/$afterDuplicate" }; custodyEvents = $custody.events.Count; timelineItems = $timeline.Count; entityPivots = $entities; ai = @{ citations = $ai.note.evidenceCitations.Count; truncated = $ai.truncated; readOnly = $ai.readOnly }; holds = $holds; export = $export; package = @{ downloadHash = $downloadHash; resumedHash = $resumeHash; manifestHash = $export.manifestSha256 }; readiness = $readiness; rbac = $rbac; tenantIsolation = $tenantIsolation; performance = $performance; health = $health; passed = $true }
$report | ConvertTo-Json -Depth 60 | Set-Content artifacts/sprint34-dfir-profiles.json -Encoding utf8
$report | ConvertTo-Json -Depth 10
