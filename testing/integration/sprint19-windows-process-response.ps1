[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $VictimVmName,
    [Parameter(Mandatory)] [string] $CredentialPath,
    [string] $QualificationRoot = 'C:\Sprint19Qualification',
    [int] $TimeoutSeconds = 180
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '../..')
Set-Location $root
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated host token required.' }
if ((docker ps --filter 'name=falco' --format '{{.Names}}')) { throw 'Falco must remain stopped.' }
if (@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object Group -Like 'OpenSecurityPlatform-Isolation-*').Count -ne 0) { throw 'Host platform firewall drift detected.' }
$settings = @{}
Get-Content .env | Where-Object { $_ -match '^\s*([^#=\s]+)=(.*)$' } | ForEach-Object { $settings[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'") }
$login = Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/auth/token -ContentType application/json -Body (@{ username=$settings.PLATFORM_BOOTSTRAP_USER; password=$settings.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json -Compress)
$admin = @{ Authorization = "Bearer $($login.access_token)" }
function B64([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }
function Jwt([string]$subject) { $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); $head=B64([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}')); $body=B64([Text.Encoding]::UTF8.GetBytes((@{iss='security-platform';aud='security-platform-api';sub=$subject;tid=$settings.PLATFORM_BOOTSTRAP_TENANT_ID;per=@('platform:admin','process-response:approve');pty='user';iat=$now;exp=$now+3600;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress))); $h=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($settings.PLATFORM_JWT_SIGNING_KEY)); try {$sig=B64($h.ComputeHash([Text.Encoding]::ASCII.GetBytes("$head.$body")))} finally {$h.Dispose()}; @{Authorization="Bearer $head.$body.$sig"} }
$approver = Jwt 'sprint19-approver'
function Api([string]$method,[string]$path,$headers=$admin,$body=$null) { $a=@{Method=$method;Uri="http://127.0.0.1:8080$path";Headers=$headers;DisableKeepAlive=$true}; if($null-ne$body){$a.ContentType='application/json';$a.Body=$body|ConvertTo-Json -Depth 30 -Compress}; (Invoke-RestMethod @a).data }
foreach($stale in (Api GET '/api/v1/response-actions?pageSize=200').items | Where-Object {$_.actionType -like 'process*' -and $_.state -notin @('Succeeded','Failed','TimedOut','Cancelled','Expired','Rejected')}) { Api POST "/api/v1/response-actions/$($stale.responseActionId):cancel" $admin @{reason='cleanup after interrupted controlled Sprint 19 qualification'} | Out-Null }
function Wait-Action([guid]$id) { $deadline=[DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds); do {Start-Sleep -Milliseconds 400; $a=Api GET "/api/v1/response-actions/$id"} while($a.state -notin @('Succeeded','Failed','TimedOut','Cancelled','Expired','Rejected') -and [DateTimeOffset]::UtcNow-lt$deadline); $a }
function Approve-Wait($action) { if($action.approvalState-eq'Pending'){$action=Api POST "/api/v1/process-response-actions/$($action.responseActionId):approve" $approver @{parameterHash=$action.parameterHash;reason='verified exact Sprint 19 preview'}}; Wait-Action $action.responseActionId }
function Session { $cred=Import-Clixml -LiteralPath $CredentialPath;$deadline=[DateTimeOffset]::UtcNow.AddMinutes(3);do{try{return New-PSSession -VMName $VictimVmName -Credential $cred -ErrorAction Stop}catch{Start-Sleep 3}}while([DateTimeOffset]::UtcNow-lt$deadline);throw 'PowerShell Direct unavailable after bounded retry.' }
$script:token = Api POST '/api/v1/enrollment-tokens' $admin @{expiresAt=[DateTimeOffset]::UtcNow.AddHours(1).ToString('o');maximumUses=1;allowedPlatforms=@('windows')}
$script:freshEnrollment = $true
function Start-Agent { $s=Session; try { Invoke-Command -Session $s -ScriptBlock { param($q,$id,$secret,$fresh) Get-Process Platform.Agent -ErrorAction SilentlyContinue|Stop-Process -Force;Start-Sleep 1;if($fresh){Remove-Item "$q\runtime-data" -Recurse -Force -ErrorAction SilentlyContinue};@('OpenSecurityPlatform-ProcessLifecycle-v1','OpenSecurityPlatform-RegistryLifecycle-v1','OpenSecurityPlatform-FileLifecycle-v1','OpenSecurityPlatform-NetworkLifecycle-v1','OpenSecurityPlatform-DnsClient-v1','OpenSecurityPlatform-ModuleImageLoad-v1')|ForEach-Object{& logman stop $_ -ets 2>$null|Out-Null};$env:PLATFORM_CONTROL_PLANE_URL='https://gateway:8443';$env:PLATFORM_ENROLLMENT_TOKEN_ID=$id;$env:PLATFORM_ENROLLMENT_TOKEN_SECRET=$secret;$env:PLATFORM_AGENT_DATA="$q\runtime-data";$env:PLATFORM_CA_CERT_PATH="$q\ca.crt";$env:PLATFORM_ENVIRONMENT='production';$env:PLATFORM_PROCESS_RESPONSE_SELF_TEST='false';(Start-Process "$q\agent\Platform.Agent.exe" -PassThru -WindowStyle Hidden -RedirectStandardOutput "$q\agent.log" -RedirectStandardError "$q\agent-error.log").Id } -ArgumentList $QualificationRoot,$script:token.metadata.id,$script:token.secret,$script:freshEnrollment } finally {Remove-PSSession $s};$script:freshEnrollment=$false }
function Stop-Agent { $s=Session; try {Invoke-Command -Session $s -ScriptBlock {Get-Process Platform.Agent -ErrorAction SilentlyContinue|Stop-Process -Force;Start-Sleep 1}|Out-Null} finally {Remove-PSSession $s} }
function Start-Fixture([int]$lifetime=600000) { $s=Session; try {Invoke-Command -Session $s -ScriptBlock {param($q,$ms) $p=Start-Process "$q\fixture\ProcessGenerator.exe" -ArgumentList "--child --lifetime-ms $ms" -PassThru -WindowStyle Hidden;[pscustomobject]@{pid=$p.Id;startTime=$p.StartTime.ToUniversalTime()}} -ArgumentList $QualificationRoot,$lifetime} finally {Remove-PSSession $s} }
function Alive([int]$pidValue) { $s=Session; try {[bool](Invoke-Command -Session $s -ScriptBlock {param($p)[bool](Get-Process -Id $p -ErrorAction SilentlyContinue)} -ArgumentList $pidValue)} finally {Remove-PSSession $s} }
function Process-Entity([guid]$endpoint,[int]$pidValue) { $deadline=[DateTimeOffset]::UtcNow.AddSeconds(90); do {Start-Sleep 1;$items=(Api GET "/api/v1/processes?endpointId=$endpoint&pid=$pidValue&state=running&pageSize=20").items;$p=$items|Where-Object {$_.processId-eq$pidValue -or $_.pid-eq$pidValue}|Sort-Object startTime -Descending|Select-Object -First 1} while(!$p-and[DateTimeOffset]::UtcNow-lt$deadline); if(!$p){throw "Process entity for PID $pidValue not observed"};$p }
function Request([guid]$endpoint,[string]$entity,[string]$operation,[string]$reason) { $value=Api POST "/api/v1/endpoints/$endpoint/processes/$entity`:$operation" $admin @{reason=$reason;sourceEntityId=$entity;expiresInSeconds=300}; if($value.action){$value.action}else{$value} }

$native = $null; $s=Session; try {$native=Invoke-Command -Session $s -ScriptBlock {param($q)Get-Content "$q\native-self-test.json" -Raw|ConvertFrom-Json} -ArgumentList $QualificationRoot} finally {Remove-PSSession $s}
$started=[DateTimeOffset]::UtcNow; $agentPid=Start-Agent; $deadline=[DateTimeOffset]::UtcNow.AddSeconds(120)
do {Start-Sleep 2;$endpoint=(Api GET '/api/v1/endpoints?pageSize=100').items|Where-Object {$_.platform-eq'windows'-and$_.lastSeenAt-and[DateTimeOffset]$_.lastSeenAt-ge$started}|Sort-Object lastSeenAt -Descending|Select-Object -First 1} while(!$endpoint-and[DateTimeOffset]::UtcNow-lt$deadline)
if(!$endpoint){throw 'Victim agent did not enroll.'}
$s=Session;try{Invoke-Command -Session $s -ScriptBlock {New-Item -ItemType Directory -Path C:\Sprint19Telemetry -Force|Out-Null}}finally{Remove-PSSession $s}
$effectiveFile=Api GET "/api/v1/endpoints/$($endpoint.id)/file-policy"; $bounded=$effectiveFile.policy.policy; $bounded.includedPaths=@('C:\Sprint19Telemetry\');$bounded.excludedPaths=@();$bounded.maximumBatchEvents=1000;$bounded.maximumBatchBytes=4194304;$bounded.flushSeconds=1
$createdFile=Api POST '/api/v1/file-telemetry/policies' $admin @{name="sprint19-bounded-$([guid]::NewGuid().ToString('N'))";policy=$bounded};Api POST "/api/v1/file-telemetry/policies/$($createdFile.id):assign" $admin @{endpointId=$endpoint.id}|Out-Null
Stop-Agent;$agentPid=Start-Agent;Start-Sleep 5

$fixture=Start-Fixture; $entity=Process-Entity $endpoint.id $fixture.pid
$preview=Api GET "/api/v1/endpoints/$($endpoint.id)/processes/$($entity.processEntityId)/response-preview"
$single=Approve-Wait (Request $endpoint.id $entity.processEntityId terminate 'Profile A control-plane exact termination')
$singlePass=$single.state-eq'Succeeded'-and$single.result.structuredResult.state-eq'Terminated'-and-not(Alive $fixture.pid)

$offline=Start-Fixture; $offlineEntity=Process-Entity $endpoint.id $offline.pid; Stop-Agent
$queued=Request $endpoint.id $offlineEntity.processEntityId terminate 'Profile F offline exact identity'; $queued=Api POST "/api/v1/process-response-actions/$($queued.responseActionId):approve" $approver @{parameterHash=$queued.parameterHash;reason='offline preview verified'}
docker compose --env-file .env -f deployment/docker-compose.yml restart gateway | Out-Null
$ready=[DateTimeOffset]::UtcNow.AddSeconds(90); do {try{$ok=(Invoke-WebRequest http://127.0.0.1:8080/health/ready -UseBasicParsing -TimeoutSec 2).StatusCode-eq200}catch{$ok=$false};if(!$ok){Start-Sleep 2}}while(!$ok-and[DateTimeOffset]::UtcNow-lt$ready)
$agentPid=Start-Agent; $offlineResult=Wait-Action $queued.responseActionId; $offlinePass=$offlineResult.state-eq'Succeeded'-and-not(Alive $offline.pid)
Stop-Agent; $agentPid=Start-Agent; Start-Sleep 4; $replayed=Api GET "/api/v1/response-actions/$($queued.responseActionId)"; $replayPass=$replayed.result.resultHash-eq$offlineResult.result.resultHash

$cancelFixture=Start-Fixture; $cancelEntity=Process-Entity $endpoint.id $cancelFixture.pid; Stop-Agent
$cancel=Request $endpoint.id $cancelEntity.processEntityId terminate 'Profile F cancellation before delivery'; $cancel=Api POST "/api/v1/process-response-actions/$($cancel.responseActionId):approve" $approver @{parameterHash=$cancel.parameterHash;reason='preview verified'}; $cancel=Api POST "/api/v1/process-response-actions/$($cancel.responseActionId):cancel" $admin @{reason='controlled pre-delivery cancellation'}
$agentPid=Start-Agent; Start-Sleep 4; $cancelPass=$cancel.state-eq'Cancelled'-and(Alive $cancelFixture.pid)
$cleanup=Approve-Wait (Request $endpoint.id $cancelEntity.processEntityId terminate 'controlled fixture cleanup')

$history=(Api GET "/api/v1/endpoints/$($endpoint.id)/process-response-history").items
$health=Api GET '/api/v1/process-response-health'
$responseQueue=[long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.response_actions where state not in ('Succeeded','Failed','TimedOut','Cancelled','Expired','Rejected');")
$outboxPending=[long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.outbox where published_at is null and failed_at is null;")
$outboxFailed=[long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.outbox where failed_at is not null;")
$drainDeadline=[DateTimeOffset]::UtcNow.AddSeconds(600);do{$guestQueues=$null;$s=Session;try{$guestQueues=Invoke-Command -Session $s -ScriptBlock {param($q)$names='process','file','registry','network','dns','module','persistence','identity','execution';$o=[ordered]@{};foreach($n in $names){$p="$q\runtime-data\$n-queue";$o[$n]=if(Test-Path $p){@(Get-ChildItem $p -File -Filter '*.json').Count}else{0}};[pscustomobject]$o} -ArgumentList $QualificationRoot}finally{Remove-PSSession $s};$guestRemaining=[long](($guestQueues.psobject.Properties|Where-Object {$_.Name-notin @('PSComputerName','RunspaceId','PSShowComputerName')}|ForEach-Object {[long]$_.Value}|Measure-Object -Sum).Sum);if($guestRemaining-gt0){Start-Sleep 3}}while($guestRemaining-gt0-and[DateTimeOffset]::UtcNow-lt$drainDeadline)
$profileF=$offlinePass-and$replayPass-and$cancelPass-and$responseQueue-eq0-and$guestRemaining-eq0
$report=[ordered]@{schemaVersion='sprint19-windows-process-response.v1';executedAt=[DateTimeOffset]::UtcNow;victim=@{vm=$VictimVmName;endpointId=$endpoint.id;agentPid=$agentPid};native=$native;controlPlaneSingle=@{status=if($singlePass){'PASS'}else{'FAIL'};preview=$preview;actionId=$single.responseActionId;state=$single.state;processState=$single.result.structuredResult.state};profileF=@{status=if($profileF){'PASS'}else{'FAIL'};offlineSameIdentity=$offlinePass;backendRestart=$ok;agentRestartReplaySafe=$replayPass;cancelledBeforeDelivery=$cancelPass;cancelledTargetSurvived=$cancelPass};historyCount=$history.Count;health=$health;queues=@{response=$responseQueue;guest=$guestQueues;outboxPending=$outboxPending;outboxFailed=$outboxFailed};result=if($native.result-eq'PASS'-and$singlePass-and$profileF-and$outboxPending-eq0-and$outboxFailed-eq0){'PASS'}else{'FAIL'}}
$report|ConvertTo-Json -Depth 40|Set-Content artifacts/sprint19-windows-process-response.json -Encoding utf8
$report|ConvertTo-Json -Depth 40
if($report.result-ne'PASS'){exit 1}
