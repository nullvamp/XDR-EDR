$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root
function Assert($condition,[string]$message){if(-not $condition){throw "FAIL: $message"};Write-Host "PASS $message"}
function Settings{$values=@{};Get-Content .env|Where-Object{$_ -match '^[^#].*='}|ForEach-Object{$p=$_.Split('=',2);$values[$p[0]]=$p[1]};$values}
function B64Url([byte[]]$bytes){[Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')}
function Jwt([string]$tenant,[hashtable]$settings){$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$header=B64Url([Text.Encoding]::UTF8.GetBytes((@{alg='HS256';typ='JWT'}|ConvertTo-Json -Compress)));$payload=B64Url([Text.Encoding]::UTF8.GetBytes((@{iss='security-platform';aud='security-platform-api';sub='certificate-acceptance';tid=$tenant;per=@('platform:admin','agent:enroll','endpoint:read');pty='user';iat=$now;exp=$now+900;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress)));$hmac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($settings.PLATFORM_JWT_SIGNING_KEY));"$header.$payload.$(B64Url($hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$header.$payload"))))"}

$settings=Settings
$admin=Jwt $settings.PLATFORM_BOOTSTRAP_TENANT_ID $settings
$headers=@{Authorization="Bearer $admin"}
$token=Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/enrollment-tokens -Headers $headers -ContentType application/json -Body (@{expiresAt=[DateTimeOffset]::UtcNow.AddHours(1).ToString('o');maximumUses=1;allowedPlatforms=@('linux');endpointGroupId=$null;policyId=$null}|ConvertTo-Json)
$name="sprint1-cert-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$volume="$name-data"
$certificates=(Resolve-Path deployment/certificates).Path
try{
  docker volume create $volume|Out-Null
  docker run -d --name $name --network deployment_platform -v "${volume}:/data" -v "${certificates}:/certificates:ro" -e PLATFORM_CONTROL_PLANE_URL=https://gateway:8443 -e PLATFORM_CA_CERT_PATH=/certificates/ca.crt -e PLATFORM_AGENT_DATA=/data -e PLATFORM_PROCESS_COLLECTOR=procfs -e PLATFORM_FALCO_JSON_PATH=/data/falco-events.jsonl -e PLATFORM_FALCO_EVENT_PATH=/data/falco-events.jsonl -e PLATFORM_ENROLLMENT_TOKEN_ID=$($token.data.metadata.id) -e PLATFORM_ENROLLMENT_TOKEN_SECRET=$($token.data.secret) -e PLATFORM_FORCE_CERTIFICATE_ROTATION=true deployment-agent:latest|Out-Null
  $logs=''
  1..45|ForEach-Object{if($logs -match 'Agent certificate rotated' -and $logs -match 'Authenticated heartbeat'){return};Start-Sleep 1;$logs=docker logs $name 2>&1|Out-String}
  if($logs -notmatch 'Agent certificate rotated'){Write-Host 'Certificate agent diagnostics:';Write-Host $logs}
  Assert ($logs -match 'Agent certificate rotated') 'agent performs authenticated certificate rotation'
  Assert ($logs -match 'Authenticated heartbeat') 'agent recovers and heartbeats with the renewed certificate'
  $match=[regex]::Match($logs,'endpoint (?<id>[0-9a-f-]{36})',[Text.RegularExpressions.RegexOptions]::IgnoreCase)
  Assert $match.Success 'certificate test endpoint identity is recorded'
  $endpointId=$match.Groups['id'].Value
  $credentialCounts=docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -Atc "select count(*) filter(where revoked_at is not null),count(*) filter(where revoked_at is null) from platform.agent_credentials c join platform.agents a on a.id=c.agent_id where a.endpoint_id='$endpointId'"
  Assert ($credentialCounts -eq '1|1') 'rotation revokes the previous credential and activates exactly one replacement'
  $validUntil=docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -Atc "select certificate_not_after from platform.agent_credentials c join platform.agents a on a.id=c.agent_id where a.endpoint_id='$endpointId' and c.revoked_at is null";if($LASTEXITCODE-ne 0){throw 'Credential expiry fixture query failed'}
  $beforeExpiry=[long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select coalesce(max(sequence),0) from platform.agent_heartbeats where endpoint_id='$endpointId'")
  docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -c "update platform.agent_credentials c set certificate_not_after=now()-interval '1 minute' from platform.agents a where a.id=c.agent_id and a.endpoint_id='$endpointId' and c.revoked_at is null"|Out-Null;if($LASTEXITCODE-ne 0){throw 'Credential expiration fixture failed'}
  Start-Sleep 35
  $expiredLogs=docker logs $name 2>&1|Out-String
  $afterExpiry=[long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select coalesce(max(sequence),0) from platform.agent_heartbeats where endpoint_id='$endpointId'")
  Assert ($afterExpiry -eq $beforeExpiry) 'expired credential metadata is rejected during authentication'
  docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -c "update platform.agent_credentials c set certificate_not_after='$validUntil' from platform.agents a where a.id=c.agent_id and a.endpoint_id='$endpointId' and c.revoked_at is null"|Out-Null;if($LASTEXITCODE-ne 0){throw 'Credential validity restore failed'}
  $beforeRecovery=([regex]::Matches($expiredLogs,'Authenticated heartbeat')).Count
  $recoveredLogs=$expiredLogs
  1..45|ForEach-Object{if(([regex]::Matches($recoveredLogs,'Authenticated heartbeat')).Count -gt $beforeRecovery){return};Start-Sleep 1;$recoveredLogs=docker logs $name 2>&1|Out-String}
  Assert (([regex]::Matches($recoveredLogs,'Authenticated heartbeat')).Count -gt $beforeRecovery) 'agent recovers after credential validity is restored'
  $beforeRevocation=[long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select coalesce(max(sequence),0) from platform.agent_heartbeats where endpoint_id='$endpointId'")
  Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/endpoints/${endpointId}:revoke" -Headers $headers -ContentType application/json -Body (@{reason='automated certificate revocation acceptance'}|ConvertTo-Json)|Out-Null
  Start-Sleep 35
  $afterRevocation=[long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select coalesce(max(sequence),0) from platform.agent_heartbeats where endpoint_id='$endpointId'")
  Assert ($afterRevocation -eq $beforeRevocation) 'revoked certificate is rejected on the next authenticated heartbeat'
  $revoked=docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -Atc "select (e.status='revoked') and bool_and(c.revoked_at is not null) from platform.endpoints e join platform.agents a on a.endpoint_id=e.id join platform.agent_credentials c on c.agent_id=a.id where e.id='$endpointId' group by e.status"
  Assert ($revoked -eq 't') 'endpoint revocation persists and revokes all credentials'
}finally{
  docker rm -f $name 2>$null|Out-Null
  docker volume rm $volume 2>$null|Out-Null
}
Write-Host 'Certificate lifecycle acceptance suite passed.'
