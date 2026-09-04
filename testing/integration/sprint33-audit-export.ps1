param([string]$GatewayA='http://127.0.0.1:8080',[string]$GatewayB='http://127.0.0.1:8081')
$ErrorActionPreference='Stop';$root=Resolve-Path(Join-Path $PSScriptRoot '..\..');Set-Location $root
Add-Type -AssemblyName System.Net.Http
$cfg=@{};Get-Content .env|Where-Object{$_-match'^\s*([^#=\s]+)=(.*)$'}|ForEach-Object{$cfg[$matches[1]]=$matches[2].Trim().Trim('"').Trim("'")}
$token=(Invoke-RestMethod -Method Post "$GatewayA/api/v1/auth/token" -ContentType application/json -Body(@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json -Compress)).access_token
$headers=@{Authorization="Bearer $token"};$campaign=(Invoke-RestMethod "$GatewayA/api/v1/admin/permissions/routes" -Headers $headers).data
$campaign|ConvertTo-Json -Depth 40|Set-Content artifacts/sprint33-permission-campaign.json
$request=@{format='jsonl';query=@{from=[DateTimeOffset]::UtcNow.AddDays(-1).ToString('o');to=[DateTimeOffset]::UtcNow.AddMinutes(1).ToString('o');limit=1000}}
$created=(Invoke-RestMethod -Method Post "$GatewayA/api/v1/admin/audit-exports" -Headers $headers -ContentType application/json -Body($request|ConvertTo-Json -Depth 10)).data
$client=[Net.Http.HttpClient]::new();$client.DefaultRequestHeaders.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$token)
try{$manifestBytes=$client.GetByteArrayAsync("$GatewayB/api/v1/admin/audit-exports/$($created.id)/manifest").GetAwaiter().GetResult();$contentBytes=$client.GetByteArrayAsync("$GatewayB/api/v1/admin/audit-exports/$($created.id)/content").GetAwaiter().GetResult()}finally{$client.Dispose()}
$manifest=[Text.Encoding]::UTF8.GetString($manifestBytes)|ConvertFrom-Json;$hasher=[Security.Cryptography.SHA256]::Create();try{$sha=([BitConverter]::ToString($hasher.ComputeHash($contentBytes))).Replace('-','').ToLowerInvariant()}finally{$hasher.Dispose()}
$result=[ordered]@{schemaVersion='sprint33-audit-export-validation.v1';executedAt=[DateTimeOffset]::UtcNow.ToString('o');exportId=$created.id;createdOn='gateway-a';downloadedFrom='gateway-b';rowCount=$created.rowCount;manifestRows=$manifest.rowCount;expectedSha256=$manifest.sha256;actualSha256=$sha;requestedByPresent=-not[string]::IsNullOrWhiteSpace($manifest.requestedBy);timestampPresent=$null-ne$manifest.requestedAt;tenantBound=$manifest.tenantId-eq$cfg.PLATFORM_BOOTSTRAP_TENANT_ID;crossGateway=$true;passed=$created.rowCount-eq$manifest.rowCount-and$manifest.sha256-eq$sha-and(-not[string]::IsNullOrWhiteSpace($manifest.requestedBy))-and$null-ne$manifest.requestedAt-and$manifest.tenantId-eq$cfg.PLATFORM_BOOTSTRAP_TENANT_ID}
$result|ConvertTo-Json -Depth 10|Set-Content artifacts/sprint33-audit-export.json;$result|ConvertTo-Json -Depth 10;if(-not$result.passed){throw 'Sprint 33 audit export validation failed.'}
