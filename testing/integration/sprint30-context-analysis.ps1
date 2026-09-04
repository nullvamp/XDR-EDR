param([string]$BaseUrl = 'http://127.0.0.1:8080')
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $root
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^\s*([^#=\s]+)=(.*)$' } | ForEach-Object { $cfg[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'") }
$tenant = $cfg.PLATFORM_BOOTSTRAP_TENANT_ID
$token = (Invoke-RestMethod -Method Post "$BaseUrl/api/v1/auth/token" -ContentType application/json -Body (@{ username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json -Compress)).access_token
$headers = @{ Authorization = "Bearer $token" }
function Sql([string]$query) { (docker exec deployment-postgres-1 psql -U platform -d platform -Atc $query).Trim() }
function Qualify([string]$type, [string]$id, [string]$expectedType) {
    if ([string]::IsNullOrWhiteSpace($id)) { return [ordered]@{ contextType = $type; status = 'ENVIRONMENT BLOCKER'; reason = 'No populated authoritative record exists.' } }
    $conversation = (Invoke-RestMethod -Method Post "$BaseUrl/api/v1/ai/conversations" -Headers $headers -ContentType application/json -Body (@{ contextType = $type; contextId = $id; title = "Sprint 30 populated $type qualification" } | ConvertTo-Json -Compress)).data
    $requestId = "sprint30-$type-$([guid]::NewGuid().ToString('N'))"
    $answer = (Invoke-RestMethod -Method Post "$BaseUrl/api/v1/ai/conversations/$($conversation.conversationId)/analyze" -Headers $headers -ContentType application/json -Body (@{ question = 'Summarize only the supplied evidence, identify ambiguity, and suggest read-only pivots.'; clientRequestId = $requestId } | ConvertTo-Json -Compress)).data
    $items = @($answer.evidencePackage.items)
    $claims = @($answer.analysis.claims)
    $citations = @($claims | ForEach-Object { @($_.citations) })
    $resolved = $null
    if ($citations.Count -gt 0) { $resolved = (Invoke-RestMethod "$BaseUrl/api/v1/ai/evidence/$($answer.evidencePackage.packageId)/citations/$($citations[0])" -Headers $headers).data }
    $passed = $items.Count -gt 0 -and (@($items.evidenceType) -contains $expectedType) -and $answer.analysis.readOnly -and @($claims | Where-Object { $_.kind -ne 'Unknown' -and @($_.citations).Count -eq 0 }).Count -eq 0 -and $null -ne $resolved
    [ordered]@{ contextType = $type; contextId = $id; expectedEvidenceType = $expectedType; evidenceItems = $items.Count; evidenceTypes = @($items.evidenceType | Sort-Object -Unique); claims = $claims.Count; citations = $citations.Count; citationResolved = $null -ne $resolved; packageHash = $answer.evidencePackage.packageHash; readOnly = $answer.analysis.readOnly; status = if ($passed) { 'PASS' } else { 'FAIL' } }
}
$ids = [ordered]@{
    detection = Sql "select finding_id from platform.detection_findings where tenant_id='$tenant' order by last_seen desc limit 1;"
    correlation = Sql "select correlated_finding_id from platform.correlated_findings where tenant_id='$tenant' order by last_seen desc limit 1;"
    process = Sql "select entity_id from platform.investigation_entities where tenant_id='$tenant' and entity_type='Process' order by last_observed desc limit 1;"
    entity = Sql "select entity_id from platform.investigation_entities where tenant_id='$tenant' order by last_observed desc limit 1;"
    ioc = Sql "select indicator_id from platform.threat_indicators where tenant_id='$tenant' order by created_at desc limit 1;"
    tunnel = Sql "select finding_id from platform.tunnel_findings where tenant_id='$tenant' order by created_at desc limit 1;"
    forensic = Sql "select action_data#>>'{parameters,collectionId}' from platform.response_actions where tenant_id='$tenant' and action_type='forensic.collect' and action_data#>'{result,structuredResult,items}' is not null order by requested_at desc limit 1;"
}
$results = @(
    Qualify detection $ids.detection detection
    Qualify correlation $ids.correlation correlation
    Qualify process $ids.process entity
    Qualify entity $ids.entity entity
    Qualify ioc $ids.ioc ioc
    Qualify tunnel $ids.tunnel tunnel
    Qualify forensic $ids.forensic forensic
)
$report = [ordered]@{ schemaVersion = 'sprint30-context-analysis.v1'; executedAt = [DateTimeOffset]::UtcNow.ToString('o'); tenantId = $tenant; contexts = $results; passed = @($results | Where-Object { $_.status -eq 'FAIL' }).Count -eq 0 }
$report | ConvertTo-Json -Depth 12 | Set-Content artifacts/sprint30-context-analysis.json -Encoding utf8
$report | ConvertTo-Json -Depth 12
if (-not $report.passed) { throw 'Sprint 30 populated context analysis failed.' }
