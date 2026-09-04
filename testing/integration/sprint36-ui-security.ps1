param([string]$BaseUrl = 'http://127.0.0.1:8080')
$ErrorActionPreference='Stop';$root=Resolve-Path(Join-Path $PSScriptRoot '../..');Set-Location $root
$cfg=@{};Get-Content .env|Where-Object{$_ -match '^([^#=]+)=(.*)$'}|ForEach-Object{$cfg[$matches[1]]=$matches[2].Trim().Trim('"').Trim("'")}
$login=Invoke-RestMethod -Method Post "$BaseUrl/api/v1/auth/token" -ContentType application/json -Body(@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json);$admin=@{Authorization="Bearer $($login.access_token)"}
function B64([byte[]]$x){[Convert]::ToBase64String($x).TrimEnd('=').Replace('+','-').Replace('/','_')}
function Jwt([string]$subject,[string]$tenant,[string[]]$permissions){$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$h=B64([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'));$c=B64([Text.Encoding]::UTF8.GetBytes((@{iss='security-platform';aud='security-platform-api';sub=$subject;tid=$tenant;per=$permissions;pty='user';iat=$now;exp=$now+900;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress)));$mac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($cfg.PLATFORM_JWT_SIGNING_KEY));try{$s=B64($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$h.$c")))}finally{$mac.Dispose()};@{Authorization="Bearer $h.$c.$s"}}
function Status([string]$path,$headers){try{[int](Invoke-WebRequest "$BaseUrl$path" -Headers $headers -UseBasicParsing).StatusCode}catch{[int]$_.Exception.Response.StatusCode}}
$alert=(Invoke-RestMethod "$BaseUrl/api/v1/triage-queue" -Headers $admin).data.items|Select-Object -First 1;if(-not $alert){throw 'Populated alert required.'}
$foreign=Jwt 'sprint36-foreign' ([guid]::NewGuid().ToString()) @('alert:read','incident:read');$none=Jwt 'sprint36-none' $cfg.PLATFORM_BOOTSTRAP_TENANT_ID @();$source=Get-Content frontend/app.js -Raw
$checks=[ordered]@{
 crossTenantDeepLink=(Status "/api/v1/alerts/$($alert.alertId)" $foreign)-eq 404
 staleAuthorizationServerDenied=(Status "/api/v1/alerts/$($alert.alertId)" $none)-eq 403
 savedViewsTenantAndUserScoped=$source.Contains('soc.saved-views.${context.tenant}.${context.subject}')
 savedViewRouteAllowlist=$source.Contains('if (!pages[route]) throw Error("This workspace cannot be saved.")')
 savedViewFieldBounds=$source.Contains('String(v).length <= 256') -and $source.Contains('.slice(0, 20)')
 urlStateBounded=$source.Contains('term.length > 128') -and $source.Contains('maxlength="128"')
 contextualOutputEncoded=$source.Contains('const esc = (v) =>') -and $source.Contains('/[&<>''"]/g')
 obsoleteReadsCancelled=$source.Contains('activeReadController.abort()') -and $source.Contains('CANCELLED_NAVIGATION')
 mutationsNotAutoCancelled=$source.Contains('["GET", "HEAD"].includes(method)')
 staleEntityProtection=$source.Contains('Execution may be uncertain; inspect the audit trail and target state before retrying.')
 doubleSubmitGuard=$source.Contains('form.dataset.submitting==="true"')
 approvalSeparation=$source.Contains('approvals are not bypassed by this interface')
 noDestructivePalette=$source.Contains('destructive actions require their normal workflow')
 noUnboundedClientCache=-not $source.Contains('new Map(api')
 ephemeralQueueContext=$source.Contains('sessionStorage.setItem(`soc.queue.')
 bearerNotAmbientCookie=$source.Contains('Authorization: `Bearer ${token()}`')
}
$report=[ordered]@{schemaVersion='sprint36-ui-security.v1';capturedAt=[DateTimeOffset]::UtcNow.ToString('o');checks=$checks;inherited=@('207 unit/control tests','Sprint 33 explicit permission campaign','Sprint 34 evidence isolation','Sprint 35 UI security');passed=@($checks.Values|Where-Object{-not $_}).Count-eq 0};$report|ConvertTo-Json -Depth 10|Set-Content artifacts/sprint36-ui-security.json -Encoding utf8;$report|ConvertTo-Json -Depth 10;if(-not $report.passed){throw 'Sprint 36 UI security review failed.'}
