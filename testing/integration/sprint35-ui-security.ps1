param([string]$BaseUrl = 'http://127.0.0.1:8080')
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '../..'); Set-Location $root
$cfg = @{}; Get-Content .env | Where-Object { $_ -match '^([^#=]+)=(.*)$' } | ForEach-Object { $cfg[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'") }
$login = Invoke-RestMethod -Method Post "$BaseUrl/api/v1/auth/token" -ContentType application/json -Body (@{ username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json)
$admin = @{ Authorization = "Bearer $($login.access_token)" }
function B64([byte[]]$x) { [Convert]::ToBase64String($x).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
function Jwt([string]$subject, [string]$tenant, [string[]]$permissions) { $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$head=B64([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'));$claims=B64([Text.Encoding]::UTF8.GetBytes((@{iss='security-platform';aud='security-platform-api';sub=$subject;tid=$tenant;per=$permissions;pty='user';iat=$now;exp=$now+900;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress)));$mac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($cfg.PLATFORM_JWT_SIGNING_KEY));try{$sig=B64($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$head.$claims")))}finally{$mac.Dispose()};@{Authorization="Bearer $head.$claims.$sig"} }
function Status([string]$path,$headers){try{[int](Invoke-WebRequest "$BaseUrl$path" -Headers $headers -UseBasicParsing).StatusCode}catch{[int]$_.Exception.Response.StatusCode}}
$alerts=(Invoke-RestMethod "$BaseUrl/api/v1/triage-queue" -Headers $admin).data.items
$alert=$alerts|Select-Object -First 1
if(-not $alert){throw 'Populated alert required for tenant-isolation review.'}
$foreign=Jwt 'sprint35-foreign' ([guid]::NewGuid().ToString()) @('alert:read','incident:read')
$none=Jwt 'sprint35-no-permissions' $cfg.PLATFORM_BOOTSTRAP_TENANT_ID @()
$source=Get-Content frontend/app.js -Raw
$checks=[ordered]@{
  crossTenantAlertDeepLink=(Status "/api/v1/alerts/$($alert.alertId)" $foreign)-eq 404
  unauthorizedAlertRoute=(Status "/api/v1/alerts/$($alert.alertId)" $none)-eq 403
  guessedEntityRejected=(Status "/api/v1/process-trees/$([guid]::NewGuid())?depth=1&pageSize=1" $admin)-eq 404
  outputEncodingHelper=$source.Contains('const esc = (v) =>') -and $source.Contains('/[&<>''"]/g')
  boundedGlobalSearch=$source.Contains('term.length > 128') -and $source.Contains('maxlength="128"')
  boundedSavedViews=$source.Contains('.slice(0, 20)') -and $source.Contains('String(v).length <= 256')
  noRawSearchDsl=$source.Contains('Search does not accept backend query syntax.')
  bearerNotCookieAuth=$source.Contains('Authorization: `Bearer ${token()}`')
  destructiveDoubleSubmitGuard=$source.Contains('form.dataset.submitting==="true"')
  uncertainMutationGuidance=$source.Contains('Execution may be uncertain; inspect the audit trail and target state before retrying.')
  commandPaletteNoDestructiveAction=$source.Contains('destructive actions require their normal workflow')
}
$report=[ordered]@{schemaVersion='sprint35-ui-security.v1';capturedAt=[DateTimeOffset]::UtcNow.ToString('o');populatedAlertId=$alert.alertId;checks=$checks;csrfAssumption='Bearer token in sessionStorage; APIs do not use ambient cookie authentication';serverAuthority='Existing route permissions, tenant RLS, stable-target validation, exact approval hashes, and audit remain authoritative';inheritedCampaigns=@('207 unit/control tests','Sprint 33 880-route explicit-permission campaign','Sprint 34 tenant/evidence security campaign','response stale-target and uncertain-state suites');passed=@($checks.Values|Where-Object{-not $_}).Count-eq 0}
$report|ConvertTo-Json -Depth 10|Set-Content artifacts/sprint35-ui-security.json -Encoding utf8
$report|ConvertTo-Json -Depth 10
if(-not $report.passed){throw 'Sprint 35 UI security review failed.'}
