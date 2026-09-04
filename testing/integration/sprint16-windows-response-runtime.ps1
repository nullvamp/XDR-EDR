$ErrorActionPreference='Stop'
$root=Resolve-Path(Join-Path $PSScriptRoot '../..');Set-Location $root
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated Windows token required.'}
$settings=@{};Get-Content .env|Where-Object{$_-match'^[^#][^=]*='}|ForEach-Object{$i=$_.IndexOf('=');$settings[$_.Substring(0,$i)]=$_.Substring($i+1)}
$login=Invoke-RestMethod -Method Post http://localhost:8080/api/v1/auth/token -ContentType application/json -Body(@{username=$settings.PLATFORM_BOOTSTRAP_USER;password=$settings.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json)
$headers=@{Authorization="Bearer $($login.access_token)"}
$token=(Invoke-RestMethod -Method Post http://localhost:8080/api/v1/enrollment-tokens -Headers $headers -ContentType application/json -Body(@{expiresAt=[DateTimeOffset]::UtcNow.AddHours(1).ToString('o');maximumUses=1;allowedPlatforms=@('windows');endpointGroupId=$null;policyId=$null}|ConvertTo-Json)).data
$started=[DateTimeOffset]::UtcNow;$data=Join-Path $root "artifacts/sprint16-windows-agent-$([guid]::NewGuid().ToString('N'))";New-Item -ItemType Directory -Path $data|Out-Null
$fixture=Join-Path $data 'metadata-fixture.txt';Set-Content -Path $fixture -Value 'Sprint 16 bounded metadata fixture.' -Encoding UTF8
$log=Join-Path $data 'agent.log';$errorLog=Join-Path $data 'agent-error.log'
$keys=@('PLATFORM_CONTROL_PLANE_URL','PLATFORM_ENROLLMENT_TOKEN_ID','PLATFORM_ENROLLMENT_TOKEN_SECRET','PLATFORM_AGENT_DATA','PLATFORM_CA_CERT_PATH','PLATFORM_ENVIRONMENT','PLATFORM_RESPONSE_ONLY')
$old=@{};foreach($key in $keys){$old[$key]=[Environment]::GetEnvironmentVariable($key)}
$env:PLATFORM_CONTROL_PLANE_URL='https://localhost:8443';$env:PLATFORM_ENROLLMENT_TOKEN_ID=$token.metadata.id;$env:PLATFORM_ENROLLMENT_TOKEN_SECRET=$token.secret;$env:PLATFORM_AGENT_DATA=$data;$env:PLATFORM_CA_CERT_PATH=(Join-Path $root 'deployment/certificates/ca.crt');$env:PLATFORM_ENVIRONMENT='production'
$process=$null
function Api([string]$method,[string]$path,$body=$null){$a=@{Method=$method;Uri="http://localhost:8080$path";Headers=$headers};if($null-ne$body){$a.ContentType='application/json';$a.Body=$body|ConvertTo-Json -Depth 15 -Compress};(Invoke-RestMethod @a).data}
function Create([guid]$endpoint,[string]$type,$parameters=@{}){Api POST '/api/v1/response-actions' @{endpointId=$endpoint;actionType=$type;actionVersion=1;parameters=$parameters;timeoutSeconds=30;expiresInSeconds=300}}
function Wait([guid]$id){$deadline=(Get-Date).AddSeconds(75);do{Start-Sleep -Milliseconds 500;$x=Api GET "/api/v1/response-actions/$id"}while($x.state-notin@('Succeeded','Failed','TimedOut','Cancelled','Expired','Rejected')-and(Get-Date)-lt$deadline);$x}
try{
 $process=Start-Process dotnet -ArgumentList @('run','--project','agent/core/Platform.Agent','-c','Release','--no-build') -PassThru -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError $errorLog
 $deadline=(Get-Date).AddSeconds(90);do{Start-Sleep 2;$items=(Api GET '/api/v1/endpoints?pageSize=100').items;$endpoint=$items|Where-Object{$_.platform-eq'windows'-and$_.hostname-eq[Environment]::MachineName-and$_.lastSeenAt-and[DateTimeOffset]$_.lastSeenAt-ge$started}|Sort-Object{[DateTimeOffset]$_.lastSeenAt}-Descending|Select-Object -First 1}while(!$endpoint-and(Get-Date)-lt$deadline)
 if(!$endpoint){throw 'Native Windows agent did not enroll/check in.'}
 Stop-Process -Id $process.Id -Force;Wait-Process -Id $process.Id -ErrorAction SilentlyContinue
 $env:PLATFORM_RESPONSE_ONLY='true'
 $process=Start-Process dotnet -ArgumentList @('run','--project','agent/core/Platform.Agent','-c','Release','--no-build') -PassThru -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError $errorLog
 Start-Sleep 2
 $cases=@(
   @{type='endpoint.status';parameters=@{}},
   @{type='process.list';parameters=@{maximumRecords=30}},
   @{type='network.connections';parameters=@{maximumRecords=30;protocol='all'}},
   @{type='service.status';parameters=@{serviceName='EventLog'}},
   @{type='file.metadata';parameters=@{path=$fixture;includeHash=$true;maximumHashBytes=1048576}}
 )
 $results=@();foreach($case in $cases){$action=Create ([guid]$endpoint.id) $case.type $case.parameters;$results+=Wait $action.responseActionId}
 $diagnostic=Create ([guid]$endpoint.id) 'collect.diagnostic' @{includeQueueHealth=$true}
 # Runtime uses the repository-proven second-analyst approval profile; this native leg validates execution/artifact generation.
 $tenant=$settings.PLATFORM_BOOTSTRAP_TENANT_ID;$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
 function B64([byte[]]$b){[Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')}
 $jh=B64([Text.Encoding]::UTF8.GetBytes((@{alg='HS256';typ='JWT'}|ConvertTo-Json -Compress)));$jp=B64([Text.Encoding]::UTF8.GetBytes((@{iss='security-platform';aud='security-platform-api';sub='sprint16-windows-approver';tid=$tenant;per=@('platform:admin');pty='user';iat=$now;exp=$now+1800;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress)));$hm=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($settings.PLATFORM_JWT_SIGNING_KEY));try{$sig=B64($hm.ComputeHash([Text.Encoding]::ASCII.GetBytes("$jh.$jp")))}finally{$hm.Dispose()};$approvalHeaders=@{Authorization="Bearer $jh.$jp.$sig"}
 $a=@{Method='POST';Uri="http://localhost:8080/api/v1/response-actions/$($diagnostic.responseActionId):approve";Headers=$approvalHeaders;ContentType='application/json';Body=(@{parameterHash=$diagnostic.parameterHash;reason='native Windows diagnostic qualification'}|ConvertTo-Json)};Invoke-RestMethod @a|Out-Null;$results+=Wait $diagnostic.responseActionId
 $checks=@($results|ForEach-Object{[ordered]@{actionType=$_.actionType;actionId=$_.responseActionId;state=$_.state;records=$_.result.resultRecords;resultHash=$_.result.resultHash;artifactCount=@($_.result.artifacts).Count;exactLifecycle=(@($_.auditHistory|Where-Object{$_.action-eq'response.execution.started'}).Count-eq1);structuredResult=$_.result.structuredResult}})
 $status=$checks|Where-Object{$_.actionType-eq'endpoint.status'}
 $processList=$checks|Where-Object{$_.actionType-eq'process.list'}
 $fileMetadata=$checks|Where-Object{$_.actionType-eq'file.metadata'}
 $nativeEvidence=[ordered]@{
   endpointStatus=($status.structuredResult.uptimeSeconds-ge0-and$status.structuredResult.responseQueueCapacity-eq32-and$status.structuredResult.responseWorkers-eq2-and$status.structuredResult.activePolicyVersions.response-eq'response-policy.v1')
   processList=($processList.records-le30-and@($processList.structuredResult.processes).Count-eq$processList.records-and@($processList.structuredResult.processes|Where-Object{$null-eq$_.pid-or[String]::IsNullOrWhiteSpace($_.name)}).Count-eq0)
   fileMetadata=($fileMetadata.structuredResult.hashState-eq'succeeded-race-safe'-and![String]::IsNullOrWhiteSpace($fileMetadata.structuredResult.sha256)-and![String]::IsNullOrWhiteSpace($fileMetadata.structuredResult.nativeIdentity))
 }
 $report=[ordered]@{schemaVersion='sprint16-windows-response-runtime.v1';executedAt=[DateTimeOffset]::UtcNow;os=(Get-CimInstance Win32_OperatingSystem).Caption;build=(Get-CimInstance Win32_OperatingSystem).BuildNumber;architecture=$env:PROCESSOR_ARCHITECTURE;dotnet=(dotnet --version);administrator=$true;integrity='High';endpointId=$endpoint.id;agentProcessId=$process.Id;actions=$checks;nativeEvidence=$nativeEvidence;noShellExecutor=$true;passed=($checks.Count-eq6-and@($checks|Where-Object{$_.state-ne'Succeeded'-or!$_.exactLifecycle}).Count-eq0-and($checks|Where-Object{$_.actionType-eq'collect.diagnostic'}).artifactCount-eq1-and@($nativeEvidence.Values|Where-Object{!$_}).Count-eq0)}
 $report|ConvertTo-Json -Depth 15|Set-Content artifacts/sprint16-windows-response-runtime.json;$report|ConvertTo-Json -Depth 15;if(!$report.passed){exit 1}
}finally{
 if($process-and!$process.HasExited){Stop-Process -Id $process.Id -Force;Wait-Process -Id $process.Id -ErrorAction SilentlyContinue}
 foreach($key in $keys){[Environment]::SetEnvironmentVariable($key,$old[$key])}
}
