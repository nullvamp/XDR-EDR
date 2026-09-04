[CmdletBinding()]
param(
    [string] $VictimVmName = 'XDR-Victim-Sprint18',
    [string] $CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
    [string] $QualificationRoot = 'C:\Sprint20Qualification',
    [string] $FixtureRoot = 'C:\Sprint20Telemetry',
    [int] $TimeoutSeconds = 240
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '../..')
Set-Location $root
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated host token required.' }
if ((docker ps --filter 'name=falco' --format '{{.Names}}')) { throw 'Falco must remain stopped.' }
if ((docker ps --filter 'name=deployment-agent' --format '{{.Names}}')) { throw 'Docker agent must remain stopped.' }
if (@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object Group -Like 'OpenSecurityPlatform-Isolation-*').Count -ne 0) { throw 'Host platform firewall drift detected.' }
$settings = @{}
Get-Content .env | Where-Object { $_ -match '^\s*([^#=\s]+)=(.*)$' } | ForEach-Object { $settings[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'") }
$login = Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/auth/token -ContentType application/json -Body (@{ username=$settings.PLATFORM_BOOTSTRAP_USER; password=$settings.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json -Compress)
$admin = @{ Authorization = "Bearer $($login.access_token)" }
function B64([byte[]]$value) { [Convert]::ToBase64String($value).TrimEnd('=').Replace('+','-').Replace('/','_') }
function Jwt([string]$subject) { $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$head=B64([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'));$body=B64([Text.Encoding]::UTF8.GetBytes((@{iss='security-platform';aud='security-platform-api';sub=$subject;tid=$settings.PLATFORM_BOOTSTRAP_TENANT_ID;per=@('platform:admin','file-response:approve');pty='user';iat=$now;exp=$now+7200;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress)));$h=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($settings.PLATFORM_JWT_SIGNING_KEY));try{$sig=B64($h.ComputeHash([Text.Encoding]::ASCII.GetBytes("$head.$body")))}finally{$h.Dispose()};@{Authorization="Bearer $head.$body.$sig"} }
$approver = Jwt 'sprint20-approver'
function Api([string]$method,[string]$path,$headers=$admin,$body=$null) { $args=@{Method=$method;Uri="http://127.0.0.1:8080$path";Headers=$headers;DisableKeepAlive=$true};if($null-ne$body){$args.ContentType='application/json';$args.Body=$body|ConvertTo-Json -Depth 40 -Compress};try{(Invoke-RestMethod @args).data}catch{$detail='';try{$reader=[IO.StreamReader]::new($_.Exception.Response.GetResponseStream());$detail=$reader.ReadToEnd();$reader.Dispose()}catch{};throw "$method $path failed: $detail"} }
function Session { $credential=Import-Clixml -LiteralPath $CredentialPath;$deadline=[DateTimeOffset]::UtcNow.AddMinutes(3);do{try{return New-PSSession -VMName $VictimVmName -Credential $credential -ErrorAction Stop}catch{Start-Sleep 3}}while([DateTimeOffset]::UtcNow-lt$deadline);throw 'PowerShell Direct unavailable.' }
function Stop-Agent { $session=Session;try{Invoke-Command -Session $session -ScriptBlock { Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 1 }|Out-Null}finally{Remove-PSSession $session} }
$script:token = Api POST '/api/v1/enrollment-tokens' $admin @{expiresAt=[DateTimeOffset]::UtcNow.AddHours(2).ToString('o');maximumUses=1;allowedPlatforms=@('windows')}
$script:freshEnrollment=$true
function Start-Agent { $session=Session;try{Invoke-Command -Session $session -ScriptBlock { param($q,$id,$secret,$fresh) Get-Process Platform.Agent -ErrorAction SilentlyContinue|Stop-Process -Force;Start-Sleep 1;if($fresh){Remove-Item "$q\runtime-data" -Recurse -Force -ErrorAction SilentlyContinue};@('OpenSecurityPlatform-ProcessLifecycle-v1','OpenSecurityPlatform-RegistryLifecycle-v1','OpenSecurityPlatform-FileLifecycle-v1','OpenSecurityPlatform-NetworkLifecycle-v1','OpenSecurityPlatform-DnsClient-v1','OpenSecurityPlatform-ModuleImageLoad-v1')|ForEach-Object{& logman stop $_ -ets 2>$null|Out-Null};$env:PLATFORM_CONTROL_PLANE_URL='https://gateway:8443';$env:PLATFORM_ENROLLMENT_TOKEN_ID=$id;$env:PLATFORM_ENROLLMENT_TOKEN_SECRET=$secret;$env:PLATFORM_AGENT_DATA="$q\runtime-data";$env:PLATFORM_CA_CERT_PATH='C:\Sprint19Qualification\ca.crt';$env:PLATFORM_ENVIRONMENT='production';$env:PLATFORM_FILE_RESPONSE_SELF_TEST='false';(Start-Process "$q\agent\Platform.Agent.exe" -PassThru -WindowStyle Hidden -RedirectStandardOutput "$q\agent.log" -RedirectStandardError "$q\agent-error.log").Id } -ArgumentList $QualificationRoot,$script:token.metadata.id,$script:token.secret,$script:freshEnrollment}finally{Remove-PSSession $session};$script:freshEnrollment=$false }
function Wait-Action([guid]$id) { $deadline=[DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds);do{Start-Sleep -Milliseconds 500;$action=Api GET "/api/v1/response-actions/$id"}while($action.state-notin@('Succeeded','Failed','TimedOut','Cancelled','Expired','Rejected')-and[DateTimeOffset]::UtcNow-lt$deadline);$action }
function Approve-Wait($action) { if($action.approvalState-eq'Pending'){$action=Api POST "/api/v1/file-response-actions/$($action.responseActionId):approve" $approver @{parameterHash=$action.parameterHash;reason='verified exact Sprint 20 target and parameter hash'}};Wait-Action $action.responseActionId }
function Present([string]$path) { $session=Session;try{[bool](Invoke-Command -Session $session -ScriptBlock { param($p) Test-Path -LiteralPath $p } -ArgumentList $path)}finally{Remove-PSSession $session} }
function Content([string]$path) { $session=Session;try{Invoke-Command -Session $session -ScriptBlock { param($p) Get-Content -LiteralPath $p -Raw } -ArgumentList $path}finally{Remove-PSSession $session} }
function Write-Fixture([string]$path,[string]$content) { $session=Session;try{Invoke-Command -Session $session -ScriptBlock { param($root,$p,$value) New-Item -ItemType Directory -Path $root -Force|Out-Null;Set-Content -LiteralPath $p -Value $value -NoNewline -Encoding utf8 } -ArgumentList $FixtureRoot,$path,$content|Out-Null}finally{Remove-PSSession $session} }
function Find-File([guid]$endpoint,[string]$path) { $deadline=[DateTimeOffset]::UtcNow.AddSeconds(120);do{Start-Sleep 1;$page=Api GET "/api/v1/files?endpointId=$endpoint&pageSize=200";$file=$page.items|Where-Object {$_.currentPath-eq$path-and($_.nativeIdentity.fileId-or$_.nativeIdentity.inode)-and$null-ne$_.metadata.size-and$_.hash.state-eq'Succeeded'}|Sort-Object lastObserved -Descending|Select-Object -First 1}while(!$file-and[DateTimeOffset]::UtcNow-lt$deadline);if(!$file){throw "Response-safe file entity not observed: $path"};$file }
function Request-File([guid]$endpoint,[string]$entity,[string]$operation,[string]$reason) { $value=Api POST "/api/v1/endpoints/$endpoint/files/$entity`:$operation" $admin @{reason=$reason;sourceEntityId=$entity;expiresInSeconds=300};if($value.action){$value.action}else{$value} }

foreach($stale in (Api GET '/api/v1/response-actions?pageSize=200').items|Where-Object{$_.actionType-like'file.*'-and$_.state-notin@('Succeeded','Failed','TimedOut','Cancelled','Expired','Rejected')}) { Api POST "/api/v1/file-response-actions/$($stale.responseActionId):cancel" $admin @{reason='bounded Sprint 20 qualification cleanup'}|Out-Null }
$started=[DateTimeOffset]::UtcNow; $agentPid=Start-Agent; $deadline=[DateTimeOffset]::UtcNow.AddSeconds(150)
do{Start-Sleep 2;$endpoint=(Api GET '/api/v1/endpoints?pageSize=100').items|Where-Object{$_.platform-eq'windows'-and$_.lastSeenAt-and[DateTimeOffset]$_.lastSeenAt-ge$started}|Sort-Object lastSeenAt -Descending|Select-Object -First 1}while(!$endpoint-and[DateTimeOffset]::UtcNow-lt$deadline)
if(!$endpoint){throw 'Victim agent did not enroll.'}
$effective=Api GET "/api/v1/endpoints/$($endpoint.id)/file-policy";$policy=$effective.policy.policy;$policy.includedPaths=@("$FixtureRoot\");$policy.excludedPaths=@();$policy.hashingEnabled=$true;$policy.maximumHashBytes=8388608;$policy.maximumBatchEvents=1000;$policy.maximumBatchBytes=4194304;$policy.flushSeconds=1
$created=Api POST '/api/v1/file-telemetry/policies' $admin @{name="sprint20-bounded-$([guid]::NewGuid().ToString('N'))";policy=$policy};Api POST "/api/v1/file-telemetry/policies/$($created.id):assign" $admin @{endpointId=$endpoint.id}|Out-Null
Stop-Agent;$agentPid=Start-Agent;Start-Sleep 15

$runTag=[guid]::NewGuid().ToString('N');$pathA="$FixtureRoot\control-plane-a-$runTag.bin";Write-Fixture $pathA 'sprint20-control-plane-quarantine';$fileA=Find-File $endpoint.id $pathA
$preview=Api GET "/api/v1/endpoints/$($endpoint.id)/files/$($fileA.fileEntityId)/response-preview"
$quarantine=Approve-Wait (Request-File $endpoint.id $fileA.fileEntityId quarantine 'Profile A signed control-plane quarantine')
$record=Api GET "/api/v1/quarantines/$($quarantine.responseActionId)";$artifact=$quarantine.result.artifacts|Select-Object -First 1
$evidencePath='artifacts/sprint20-quarantine-evidence.bin';Invoke-WebRequest -Uri "http://127.0.0.1:8080/api/v1/response-actions/$($quarantine.responseActionId)/artifacts/$($artifact.artifactId)/content" -Headers $admin -UseBasicParsing -OutFile $evidencePath
$artifactHash=(Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash.ToLowerInvariant()
$sourceRemovedAtQuarantine=-not(Present $pathA);$profileA=$quarantine.state-eq'Succeeded'-and$quarantine.result.structuredResult.state-eq'Quarantined'-and$sourceRemovedAtQuarantine-and$artifactHash-eq$quarantine.result.structuredResult.sha256-and$record.record.quarantineId-eq$quarantine.responseActionId

$restoreValue=Api POST "/api/v1/quarantines/$($quarantine.responseActionId):restore" $admin @{reason='Profile B explicit verified restore';sourceEntityId=$fileA.fileEntityId;expiresInSeconds=300};$restore=Approve-Wait $(if($restoreValue.action){$restoreValue.action}else{$restoreValue})
$restoredRecord=Api GET "/api/v1/quarantines/$($quarantine.responseActionId)"
$profileB=$restore.state-eq'Succeeded'-and$restore.result.structuredResult.state-eq'Restored'-and(Present $pathA)-and(Content $pathA)-eq'sprint20-control-plane-quarantine'-and$restoredRecord.record.state-eq'Restored'

$pathF="$FixtureRoot\offline-race-$runTag.bin";Write-Fixture $pathF 'offline-original-A';$fileF=Find-File $endpoint.id $pathF;Stop-Agent
$offline=Request-File $endpoint.id $fileF.fileEntityId quarantine 'Profile F offline stale identity rejection';$offline=Api POST "/api/v1/file-response-actions/$($offline.responseActionId):approve" $approver @{parameterHash=$offline.parameterHash;reason='offline exact target reviewed'}
Write-Fixture $pathF 'offline-replacement-B';docker compose --env-file .env -f deployment/docker-compose.yml restart gateway|Out-Null
$ready=[DateTimeOffset]::UtcNow.AddSeconds(120);do{try{$gatewayReady=(Invoke-WebRequest http://127.0.0.1:8080/health/ready -UseBasicParsing -TimeoutSec 3).StatusCode-eq200}catch{$gatewayReady=$false};if(!$gatewayReady){Start-Sleep 2}}while(!$gatewayReady-and[DateTimeOffset]::UtcNow-lt$ready)
$agentPid=Start-Agent;$offlineResult=Wait-Action $offline.responseActionId
$replacementSurvives=(Present $pathF)-and(Content $pathF)-eq'offline-replacement-B'
Stop-Agent;$agentPid=Start-Agent;Start-Sleep 4;$replayed=Api GET "/api/v1/response-actions/$($offline.responseActionId)"
$profileF=$gatewayReady-and$offlineResult.state-eq'Failed'-and$offlineResult.result.failureCategory-eq'Integrity'-and$replacementSurvives-and$replayed.result.resultHash-eq$offlineResult.result.resultHash

$history=(Api GET "/api/v1/endpoints/$($endpoint.id)/file-response-history").items;$health=Api GET '/api/v1/file-response-health';$quarantines=(Api GET "/api/v1/quarantines?endpointId=$($endpoint.id)").items
$responseQueue=[long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.response_actions where state not in ('Succeeded','Failed','TimedOut','Cancelled','Expired','Rejected');")
$outbox=((docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) filter(where published_at is null and failed_at is null)||'|'||count(*) filter(where failed_at is not null) from platform.outbox;").Trim()).Split('|')|ForEach-Object{[long]$_}
$report=[ordered]@{schemaVersion='sprint20-windows-file-response.v1';executedAt=[DateTimeOffset]::UtcNow;victim=@{vm=$VictimVmName;endpointId=$endpoint.id;agentPid=$agentPid};profileA=@{status=if($profileA){'PASS'}else{'FAIL'};preview=$preview;actionId=$quarantine.responseActionId;state=$quarantine.state;quarantineState=$quarantine.result.structuredResult.state;sourceRemovedAtQuarantine=$sourceRemovedAtQuarantine;artifactHashVerified=$artifactHash-eq$quarantine.result.structuredResult.sha256};profileB=@{status=if($profileB){'PASS'}else{'FAIL'};actionId=$restore.responseActionId;state=$restore.state;recordState=$restoredRecord.record.state;pathRestored=Present $pathA};profileF=@{status=if($profileF){'PASS'}else{'FAIL'};offlineQueued=$true;backendRestart=$gatewayReady;identityMismatch=$offlineResult.result.failureCategory-eq'Integrity';replacementSurvived=$replacementSurvives;agentRestartReplaySafe=$replayed.result.resultHash-eq$offlineResult.result.resultHash};api=@{historyCount=$history.Count;quarantineCount=$quarantines.Count;health=$health};queues=@{response=$responseQueue;outboxPending=$outbox[0];outboxFailed=$outbox[1]};result=if($profileA-and$profileB-and$profileF-and$responseQueue-eq0-and$outbox[0]-eq0-and$outbox[1]-eq0){'PASS'}else{'FAIL'}}
$report|ConvertTo-Json -Depth 50|Set-Content artifacts/sprint20-windows-file-response.json -Encoding utf8
$report|ConvertTo-Json -Depth 50
if($report.result-ne'PASS'){exit 1}
