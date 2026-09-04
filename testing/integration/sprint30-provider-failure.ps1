param([string]$BaseUrl = 'http://127.0.0.1:8080')
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $root
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^\s*([^#=\s]+)=(.*)$' } | ForEach-Object { $cfg[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'") }
$token = (Invoke-RestMethod -Method Post "$BaseUrl/api/v1/auth/token" -ContentType application/json -Body (@{ username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json -Compress)).access_token
$headers = @{ Authorization = "Bearer $token" }
function PolicyBody($p, [string]$provider, [string[]]$models, [int]$maximumRequests) {
    @{ enabled = $p.enabled; dataMode = $p.dataMode; providerId = $provider; allowedModels = $models; allowedEvidenceTypes = $p.allowedEvidenceTypes; redactPersonalData = $p.redactPersonalData; redactSecrets = $p.redactSecrets; maximumEvidenceItems = $p.maximumEvidenceItems; maximumEvidenceBytes = $p.maximumEvidenceBytes; maximumOutputCharacters = $p.maximumOutputCharacters; maximumRequestsPerMinute = $maximumRequests; maximumConcurrentRequests = $p.maximumConcurrentRequests; maximumProviderRetries = $p.maximumProviderRetries; promptRetentionDays = $p.promptRetentionDays; responseRetentionDays = $p.responseRetentionDays; timeoutSeconds = $p.timeoutSeconds; contextTokenLimit = $p.contextTokenLimit; determinism = $p.determinism; allowedUseCases = $p.allowedUseCases }
}
function PutPolicy($body) { (Invoke-RestMethod -Method Put "$BaseUrl/api/v1/ai/policy" -Headers $headers -ContentType application/json -Body ($body | ConvertTo-Json -Depth 10 -Compress)).data }
function Status([string]$uri, [string]$method = 'Get', $body = $null) { try { $args = @{ Uri = $uri; Method = $method; Headers = $headers; UseBasicParsing = $true }; if ($null -ne $body) { $args.ContentType = 'application/json'; $args.Body = ($body | ConvertTo-Json -Compress) }; (Invoke-WebRequest @args).StatusCode } catch { [int]$_.Exception.Response.StatusCode } }
$original = (Invoke-RestMethod "$BaseUrl/api/v1/ai/health" -Headers $headers).data.policy
$self = (Invoke-RestMethod -Method Post "$BaseUrl/internal/v1/ai/self-test" -Headers $headers).data
$missing = PutPolicy (PolicyBody $original 'unavailable-provider' @('unavailable-v1') $original.maximumRequestsPerMinute)
$outageStatus = Status "$BaseUrl/api/v1/ai/conversations/$($self.conversationId)/analyze" Post @{ question = 'Summarize evidence.'; clientRequestId = "sprint30-outage-$([guid]::NewGuid().ToString('N'))" }
$degraded = (Invoke-RestMethod "$BaseUrl/api/v1/ai/health" -Headers $headers).data
$readyDuringOutage = Status "$BaseUrl/health/ready"
$findingsDuringOutage = Status "$BaseUrl/api/v1/findings?pageSize=1"
$ratePolicy = PutPolicy (PolicyBody $original 'local-evidence' @('local-evidence-v1') 1)
$first = Status "$BaseUrl/api/v1/ai/conversations/$($self.conversationId)/analyze" Post @{ question = 'Summarize evidence.'; clientRequestId = "sprint30-rate-a-$([guid]::NewGuid().ToString('N'))" }
$second = Status "$BaseUrl/api/v1/ai/conversations/$($self.conversationId)/analyze" Post @{ question = 'Summarize evidence.'; clientRequestId = "sprint30-rate-b-$([guid]::NewGuid().ToString('N'))" }
$restored = PutPolicy (PolicyBody $original 'local-evidence' @('local-evidence-v1') $original.maximumRequestsPerMinute)
$healthy = (Invoke-RestMethod "$BaseUrl/api/v1/ai/health" -Headers $headers).data
$passed = $outageStatus -eq 400 -and -not $degraded.selectedProviderAvailable -and $degraded.degraded -and $readyDuringOutage -eq 200 -and $findingsDuringOutage -eq 200 -and $first -eq 200 -and $second -eq 400 -and $healthy.selectedProviderAvailable -and -not $healthy.degraded
$report = [ordered]@{ schemaVersion = 'sprint30-provider-failure.v1'; executedAt = [DateTimeOffset]::UtcNow.ToString('o'); unavailableProvider = [ordered]@{ policyVersion = $missing.version; analysisStatus = $outageStatus; selectedProviderAvailable = $degraded.selectedProviderAvailable; degraded = $degraded.degraded; coreReadinessStatus = $readyDuringOutage; findingWorkflowStatus = $findingsDuringOutage }; rateLimit = [ordered]@{ policyVersion = $ratePolicy.version; firstRequestStatus = $first; secondRequestStatus = $second }; restoredPolicyVersion = $restored.version; restoredAvailable = $healthy.selectedProviderAvailable; passed = $passed }
$report | ConvertTo-Json -Depth 10 | Set-Content artifacts/sprint30-provider-failure.json -Encoding utf8
$report | ConvertTo-Json -Depth 10
if (-not $passed) { throw 'Sprint 30 provider failure isolation failed.' }
