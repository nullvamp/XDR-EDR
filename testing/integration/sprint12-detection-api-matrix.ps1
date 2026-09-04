param([string]$BaseUrl = 'http://localhost:8080')
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$cfg = @{}
Get-Content (Join-Path $root '.env') | ForEach-Object { if ($_ -match '^([^#=]+)=(.*)$') { $cfg[$matches[1]] = $matches[2] } }
$login = @{ username=$cfg.PLATFORM_BOOTSTRAP_USER; password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json
$token = (Invoke-RestMethod "$BaseUrl/api/v1/auth/token" -Method Post -ContentType application/json -Body $login).access_token
$headers = @{ Authorization="Bearer $token" }
function Call([string]$path,[string]$method='Get',$body=$null) {
    $p=@{Uri="$BaseUrl$path";Method=$method;Headers=$headers}
    if($null-ne$body){$p.ContentType='application/json';$p.Body=($body|ConvertTo-Json -Depth 16 -Compress)}
    try { (Invoke-RestMethod @p).data } catch { throw "$method $path failed: $($_.Exception.Message)" }
}
function Check([string]$name,[bool]$passed,$evidence) {
    $script:checks += [ordered]@{name=$name;status=if($passed){'PASS'}else{'FAIL'};evidence=$evidence}
}
function Event([guid]$id,[guid]$endpoint,[datetime]$at) {
    @{eventId=$id;tenantId=$cfg.PLATFORM_BOOTSTRAP_TENANT_ID;domain='Process';eventTime=$at.ToUniversalTime().ToString('o');endpointId=$endpoint;processEntityId='sprint12-api-process';entityId='sprint12-api-entity';fields=@{path='C:\Sprint12Fixtures\api-matrix.exe';processName='api-matrix.exe';endpointId=$endpoint.ToString()};evidenceReference="postgresql://platform/sprint12_api_fixture/$id";late=$false;incomplete=$false;missingTelemetry=@();quality=@('complete')}
}
$checks=@()
$rules=@(Call '/api/v1/detection-rules')
$rule=$rules|Where-Object{$_.domain-eq'Process'}|Select-Object -First 1
$detail=Call "/api/v1/detection-rules/$($rule.detectionId)"
$history=@(Call "/api/v1/detection-rules/$($rule.detectionId)/versions")
$tests=@(Call "/api/v1/detection-rule-versions/$($rule.detectionId)/1/tests")
Check 'rule list/details' ($rules.Count-eq9-and$detail.detectionId-eq$rule.detectionId) @{rules=$rules.Count;status=$detail.status}
Check 'immutable version history' ($history.Count-ge1-and$history[0].detectionVersion-eq1) @{versions=$history.Count}
Check 'stored controlled tests' ($tests.Count-eq6-and@($tests|Where-Object{-not$_.result.passed}).Count-eq0) @{tests=$tests.Count}

$before=@((Call '/api/v1/findings?pageSize=500').items).Count
$event=Event ([guid]::NewGuid()) ([guid]::NewGuid()) (Get-Date)
$dry=Call '/internal/v1/detection-events:evaluate' 'Post' @{event=$event;productionFindings=$true;mode='DryRun'}
$after=@((Call '/api/v1/findings?pageSize=500').items).Count
Check 'dry-run is non-production' ($dry.finding-and$dry.finding.executionMode-eq'DryRun'-and$after-eq$before) @{before=$before;after=$after;mode=$dry.finding.executionMode}

$simulation=Call '/api/v1/detection-simulations' 'Post' @{detectionId=$rule.detectionId;version=1;events=@($event)}
Check 'simulation is non-production' ($simulation.mode-eq'Simulation'-and-not$simulation.productionFindings-and$simulation.findings.Count-eq1-and@((Call '/api/v1/findings?pageSize=500').items).Count-eq$before) @{matches=$simulation.matches;findings=$simulation.findings.Count}

$from=(Get-Date).ToUniversalTime().AddMinutes(-1);$to=$from.AddMinutes(2)
$replay=Call '/api/v1/detection-replays' 'Post' @{detectionId=$rule.detectionId;version=1;from=$from.ToString('o');to=$to.ToString('o');productionFindings=$false;controlledFixtureEvents=@($event)}
$runId=$replay.run.id
$status=Call "/api/v1/detection-replays/$runId"
$results=Call "/api/v1/detection-replays/$runId/results"
Check 'bounded replay status/results' ($status.status-eq'completed'-and$status.eventsEvaluated-eq1-and$results.run.id-eq$runId) @{runId=$runId;events=$status.eventsEvaluated;findings=$status.findings}

$page=Call '/api/v1/findings?pageSize=10'
$finding=$page.items[0]
$findingDetail=Call "/api/v1/findings/$($finding.findingId)"
$evidence=Call "/api/v1/findings/$($finding.findingId)/evidence"
$conditions=@(Call "/api/v1/findings/$($finding.findingId)/matched-conditions")
$findingRule=Call "/api/v1/findings/$($finding.findingId)/rule-version"
$findingHistory=@(Call "/api/v1/findings/$($finding.findingId)/history")
Check 'finding search/details' ($page.items.Count-ge1-and$findingDetail.findingId-eq$finding.findingId) @{returned=$page.items.Count;findingId=$finding.findingId;nextCursor=$page.nextCursor}
Check 'exact evidence, explanation and history' ($evidence.matchingEventIds.Count-ge1-and$evidence.evidenceReferences.Count-ge1-and$conditions.Count-ge1-and$findingRule.detectionVersion-eq$finding.detectionVersion-and$findingHistory.Count-ge1-and$findingHistory[0].snapshot.findingId-eq$finding.findingId) @{events=$evidence.matchingEventIds.Count;conditions=$conditions.Count;version=$findingRule.detectionVersion;history=$findingHistory.Count}

$health=Call '/api/v1/detection-health'
$ruleHealth=Call "/api/v1/detection-rules/$($rule.detectionId)/health"
$replayHealth=Call '/api/v1/detection-replay-health'
$exclusions=@(Call '/api/v1/detection-exclusions')
Check 'engine, rule, replay health and exclusions APIs' ($null-ne$health.eventsEvaluated-and$health.evaluationFailures-eq0-and$health.replayQueueDepth-eq0-and$ruleHealth.lastValidationPassed-and$ruleHealth.lastValidatedAt-and$ruleHealth.testsFailed-eq0-and$ruleHealth.testsPassed-eq6-and$replayHealth.replayQueueDepth-eq0-and$exclusions.Count-ge9) @{eventsEvaluated=$health.eventsEvaluated;evaluationFailures=$health.evaluationFailures;lastValidatedAt=$ruleHealth.lastValidatedAt;ruleTests=$ruleHealth.testsPassed;replayQueueDepth=$replayHealth.replayQueueDepth;exclusions=$exclusions.Count}

$export=Call '/api/v1/finding-exports' 'Post' @{format='jsonl';query=@{};maximumRecords=100}
$manifest=Invoke-RestMethod "$BaseUrl/api/v1/finding-exports/$($export.id)/manifest" -Headers $headers
$url=Call "/api/v1/finding-exports/$($export.id)/download-url" 'Post'
$contentFile=[IO.Path]::GetTempFileName();$downloadFile=[IO.Path]::GetTempFileName()
try {
    Invoke-WebRequest "$BaseUrl/api/v1/finding-exports/$($export.id)/content" -Headers $headers -UseBasicParsing -OutFile $contentFile
    Invoke-WebRequest $url.url -UseBasicParsing -OutFile $downloadFile
    $contentHash=(Get-FileHash -LiteralPath $contentFile -Algorithm SHA256).Hash.ToLowerInvariant()
    $downloadHash=(Get-FileHash -LiteralPath $downloadFile -Algorithm SHA256).Hash.ToLowerInvariant()
    Check 'tenant-bound finding export' ($manifest.tenantBinding-eq$cfg.PLATFORM_BOOTSTRAP_TENANT_ID-and$manifest.recordCount-eq$export.recordCount-and$contentHash-eq$manifest.sha256-and$downloadHash-eq$contentHash) @{exportId=$export.id;records=$manifest.recordCount;sha256=$manifest.sha256;signedDownload=$true}
} finally { Remove-Item -LiteralPath $contentFile,$downloadFile -Force -ErrorAction SilentlyContinue }

$report=[ordered]@{schemaVersion='sprint12-detection-api-matrix.v1';executedAt=[DateTimeOffset]::UtcNow.ToString('o');checks=$checks;failed=@($checks|Where-Object{$_.status-eq'FAIL'}).Count;passed=@($checks|Where-Object{$_.status-eq'FAIL'}).Count-eq0}
$report|ConvertTo-Json -Depth 10|Set-Content (Join-Path $root 'artifacts/sprint12-detection-api-matrix.json') -Encoding utf8
$report|ConvertTo-Json -Depth 10
if(-not$report.passed){throw 'Sprint 12 detection API matrix failed.'}
