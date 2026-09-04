param([string]$GatewayA='http://127.0.0.1:8080',[string]$GatewayB='http://127.0.0.1:8081')
$ErrorActionPreference='Stop';$root=Resolve-Path(Join-Path $PSScriptRoot '..\..');Set-Location $root
$cfg=@{};Get-Content .env|Where-Object{$_-match'^\s*([^#=\s]+)=(.*)$'}|ForEach-Object{$cfg[$matches[1]]=$matches[2].Trim().Trim('"').Trim("'")}
function Login($url){$x=Invoke-RestMethod -Method Post "$url/api/v1/auth/token" -ContentType application/json -Body(@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json -Compress);@{Authorization="Bearer $($x.access_token)"}}
function Sql($q){$v=docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -Atc $q;if($null-eq$v){''}else{($v|Out-String).Trim()}}
$admin=Login $GatewayA;$tenant=$cfg.PLATFORM_BOOTSTRAP_TENANT_ID
$ids=(Sql "select (select package_id from platform.agent_update_packages where tenant_id='$tenant' and revoked=false limit 1)||'|'||(select policy_id from platform.agent_update_policies where tenant_id='$tenant' limit 1)||'|'||(select endpoint_id from platform.fleet_endpoint_metadata where tenant_id='$tenant' limit 1);").Split('|')
$create=@{packageId=$ids[0];policyId=$ids[1];endpointIds=@($ids[2]);ringIds=@('ring-0');reason='Sprint 28 controlled update-worker failover'}|ConvertTo-Json -Compress
$rollout=(Invoke-RestMethod -Method Post "$GatewayA/api/v1/agent-update/rollouts" -Headers $admin -ContentType application/json -Body $create).data
$started=(Invoke-RestMethod -Method Post "$GatewayA/api/v1/agent-update/rollouts/$($rollout.rolloutId):start" -Headers $admin -ContentType application/json -Body '{"reason":"controlled failover start"}').data
$before=(Invoke-RestMethod "$GatewayA/api/v1/agent-update/rollouts/$($rollout.rolloutId)" -Headers $admin).data
$leaseBefore=(Sql "select worker_id||'|'||generation from platform.worker_leases where job_type='update-rollout' and job_id='coordinator';").Split('|')
if($leaseBefore[0]-eq'gateway-a'){$ownerContainer='deployment-gateway-1';$replacement='gateway-b';$survivor=$GatewayB}else{$ownerContainer='deployment-gateway-b-1';$replacement='gateway-a';$survivor=$GatewayA}
docker stop $ownerContainer|Out-Null
try {
  $deadline=(Get-Date).AddSeconds(50);do{Start-Sleep 2;$leaseAfter=(Sql "select worker_id||'|'||generation from platform.worker_leases where job_type='update-rollout' and job_id='coordinator' and state='Owned' and expires_at>now();").Split('|')}while((Get-Date)-lt$deadline-and$leaseAfter[0]-ne$replacement)
  if($leaseAfter[0]-ne$replacement){throw'Replacement gateway did not acquire update-rollout lease.'}
  $adminB=Login $survivor;$after=(Invoke-RestMethod "$survivor/api/v1/agent-update/rollouts/$($rollout.rolloutId)" -Headers $adminB).data
  $pressure=0;1..50|ForEach-Object{if((Invoke-WebRequest -UseBasicParsing "$survivor/health/ready" -TimeoutSec 5).StatusCode-eq200){$pressure++}}
  $cancelled=(Invoke-RestMethod -Method Post "$survivor/api/v1/agent-update/rollouts/$($rollout.rolloutId):cancel" -Headers $adminB -ContentType application/json -Body '{"reason":"controlled failover cleanup"}').data
  $assignmentIdsBefore=@($before.assignments|ForEach-Object{$_.assignmentId}|Sort-Object);$assignmentIdsAfter=@($after.assignments|ForEach-Object{$_.assignmentId}|Sort-Object)
  $checks=[ordered]@{survivingGatewayReady=$pressure-eq50;newOwner=$leaseAfter[0]-eq$replacement;generationAdvanced=[long]$leaseAfter[1]-gt[long]$leaseBefore[1];rolloutIdentityPreserved=$after.rollout.rolloutId-eq$before.rollout.rolloutId;countsPreserved=$after.assignments.Count-eq$before.assignments.Count;assignmentsPreserved=(Compare-Object $assignmentIdsBefore $assignmentIdsAfter).Count-eq0;completedNotReinstalled=@($after.assignments|Where-Object{$_.state-eq'Succeeded'}).Count-eq@($before.assignments|Where-Object{$_.state-eq'Succeeded'}).Count;terminalCleanup=$cancelled.state-eq'Cancelled'}
  $report=[ordered]@{schemaVersion='sprint28-gateway-worker-failover.v1';executedAt=[DateTimeOffset]::UtcNow.ToString('o');rolloutId=$rollout.rolloutId;leaseBefore=[ordered]@{owner=$leaseBefore[0];generation=[long]$leaseBefore[1]};leaseAfter=[ordered]@{owner=$leaseAfter[0];generation=[long]$leaseAfter[1]};gatewayBReadyRequests=$pressure;assignmentCount=$after.assignments.Count;checks=$checks;passed=@($checks.GetEnumerator()|Where-Object{-not$_.Value}).Count-eq0}
} finally { docker start $ownerContainer|Out-Null }
$report|ConvertTo-Json -Depth 10|Set-Content artifacts/sprint28-gateway-worker-failover.json -Encoding utf8;$report|ConvertTo-Json -Depth 10;if(-not$report.passed){exit 1}
