$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '../..')
Set-Location $root
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated Windows token required.' }
$settings = @{}
Get-Content .env | Where-Object { $_ -match '^[^#][^=]*=' } | ForEach-Object { $i=$_.IndexOf('='); $settings[$_.Substring(0,$i)]=$_.Substring($i+1) }
$login = Invoke-RestMethod -Method Post http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{username=$settings.PLATFORM_BOOTSTRAP_USER;password=$settings.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json)
$admin = @{Authorization="Bearer $($login.access_token)"}
function B64([byte[]]$bytes) { [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }
function Jwt([string]$subject,[string]$tenant) { $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$h=B64([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'));$payload=@{iss='security-platform';aud='security-platform-api';sub=$subject;tid=$tenant;per=@('platform:admin');pty='user';iat=$now;exp=$now+3600;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress;$p=B64([Text.Encoding]::UTF8.GetBytes($payload));$mac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($settings.PLATFORM_JWT_SIGNING_KEY));try{$s=B64($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$h.$p")))}finally{$mac.Dispose()};@{Authorization="Bearer $h.$p.$s"} }
$approver = Jwt 'sprint17-approver' $settings.PLATFORM_BOOTSTRAP_TENANT_ID
$foreign = Jwt 'sprint17-foreign' ([guid]::NewGuid().ToString('D'))
function Api([string]$method,[string]$path,$headers=$admin,$body=$null) { $a=@{Method=$method;Uri="http://localhost:8080$path";Headers=$headers};if($null-ne$body){$a.ContentType='application/json';$a.Body=$body|ConvertTo-Json -Depth 20 -Compress};(Invoke-RestMethod @a).data }
function Status([string]$method,[string]$path,$headers=$admin,$body=$null) { try { Api $method $path $headers $body|Out-Null;200 } catch { [int]$_.Exception.Response.StatusCode } }
function WaitSession([guid]$id,[string[]]$states=@('Active'),[int]$seconds=60) { $deadline=(Get-Date).AddSeconds($seconds);do{Start-Sleep -Milliseconds 300;$x=Api GET "/api/v1/live-response/sessions/$id"}while($x.state-notin$states-and(Get-Date)-lt$deadline);$x }
function Run([guid]$session,[string]$type,[string]$exactCommand,[int]$timeout=30) { $c=Api POST "/api/v1/live-response/sessions/$session/commands" $admin @{commandType=$type;input=$exactCommand;timeoutSeconds=$timeout};$deadline=(Get-Date).AddSeconds([Math]::Max(30,$timeout+15));do{Start-Sleep -Milliseconds 250;$c=Api GET "/api/v1/live-response/sessions/$session/commands/$($c.commandId)"}while($c.state-notin@('Succeeded','Failed','TimedOut','Cancelled','Expired','Uncertain')-and(Get-Date)-lt$deadline);$c }
$token=(Api POST '/api/v1/enrollment-tokens' $admin @{expiresAt=[DateTimeOffset]::UtcNow.AddHours(1).ToString('o');maximumUses=1;allowedPlatforms=@('windows');endpointGroupId=$null;policyId=$null})
$started=[DateTimeOffset]::UtcNow
$data=Join-Path $root "artifacts/sprint17-windows-agent-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $data | Out-Null
$fixture=Join-Path $data 'unicode-Ω-fixture.txt'
[IO.File]::WriteAllText($fixture,'Sprint 17 bounded acquisition fixture.',[Text.UTF8Encoding]::new($false))
$fixtureHash=(Get-FileHash $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
$log=Join-Path $data 'agent.log';$errorLog=Join-Path $data 'agent-error.log'
$keys=@('PLATFORM_CONTROL_PLANE_URL','PLATFORM_ENROLLMENT_TOKEN_ID','PLATFORM_ENROLLMENT_TOKEN_SECRET','PLATFORM_AGENT_DATA','PLATFORM_CA_CERT_PATH','PLATFORM_ENVIRONMENT','PLATFORM_RESPONSE_ONLY','PLATFORM_LIVE_RESPONSE_ROOTS','PLATFORM_LIVE_RESPONSE_UPLOAD_ENABLED')
$old=@{};foreach($key in $keys){$old[$key]=[Environment]::GetEnvironmentVariable($key)}
$env:PLATFORM_CONTROL_PLANE_URL='https://localhost:8443';$env:PLATFORM_ENROLLMENT_TOKEN_ID=$token.metadata.id;$env:PLATFORM_ENROLLMENT_TOKEN_SECRET=$token.secret;$env:PLATFORM_AGENT_DATA=$data;$env:PLATFORM_CA_CERT_PATH=(Join-Path $root 'deployment/certificates/ca.crt');$env:PLATFORM_ENVIRONMENT='production';Remove-Item Env:PLATFORM_RESPONSE_ONLY -ErrorAction SilentlyContinue;$env:PLATFORM_LIVE_RESPONSE_ROOTS=$data;Remove-Item Env:PLATFORM_LIVE_RESPONSE_UPLOAD_ENABLED -ErrorAction SilentlyContinue
$process=$null
function StartAgent { Start-Process dotnet -ArgumentList @('run','--project','agent/core/Platform.Agent','-c','Release','--no-build') -PassThru -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError $errorLog }
try {
  $process=StartAgent
  $deadline=(Get-Date).AddSeconds(90);do{Start-Sleep 2;$items=(Api GET '/api/v1/endpoints?pageSize=100').items;$endpoint=$items|Where-Object{$_.platform-eq'windows'-and$_.hostname-eq[Environment]::MachineName-and$_.lastSeenAt-and[DateTimeOffset]$_.lastSeenAt-ge$started}|Sort-Object{[DateTimeOffset]$_.lastSeenAt}-Descending|Select-Object -First 1}while(!$endpoint-and(Get-Date)-lt$deadline)
  if(!$endpoint){throw 'Native Windows agent did not enroll/check in.'}
  Stop-Process -Id $process.Id -Force;Wait-Process -Id $process.Id -ErrorAction SilentlyContinue
  $env:PLATFORM_RESPONSE_ONLY='true'
  $process=StartAgent
  Start-Sleep 2
  $request=Api POST '/api/v1/live-response/sessions' $admin @{endpointId=$endpoint.id;capabilities=@('builtin','file-download','cmd','powershell','file-upload');idleTimeoutSeconds=900;absoluteLifetimeSeconds=3600;policyVersion='live-response-policy.v1'}
  $forgedApproval=Status POST "/api/v1/live-response/sessions/$($request.sessionId):approve" $approver @{capabilityHash=('0'*64);reason='forged capability hash fixture'}
  $approved=Api POST "/api/v1/live-response/sessions/$($request.sessionId):approve" $approver @{capabilityHash=$request.capabilityHash;reason='controlled elevated Windows qualification'}
  $session=WaitSession $request.sessionId
  if($session.state-ne'Active'){throw "Live Response session did not activate: $($session.state)"}

  $builtins=@('help','pwd',"cd `"$data`"",'ls','ps','services','connections',"hash `"$fixture`"", "stat `"$fixture`"", "get `"$fixture`"",'session-info')
  $aCommands=@($builtins|ForEach-Object{Run $session.sessionId BuiltIn $_})
  $profileA=[ordered]@{name='A';status=if(@($aCommands|Where-Object{$_.state-ne'Succeeded'}).Count-eq0){'PASS'}else{'FAIL'};commands=@($aCommands|ForEach-Object{@{input=$_.exactInput;state=$_.state;outputHash=$_.result.outputHash}});workingDirectory=(Api GET "/api/v1/live-response/sessions/$($session.sessionId)").workingDirectory}

  $cmds=@('echo sprint17-cmd','whoami','hostname','dir')|ForEach-Object{Run $session.sessionId Cmd $_}
  $profileB=[ordered]@{name='B';status=if(@($cmds|Where-Object{$_.state-ne'Succeeded'}).Count-eq0){'PASS'}else{'FAIL'};commands=@($cmds|ForEach-Object{@{input=$_.exactInput;state=$_.state;identity=$_.result.executionIdentity}})}

  $powershell=@('[DateTime]::UtcNow','Get-Process | Select-Object -First 3 Id,ProcessName','Write-Output "sprint17-powershell"')|ForEach-Object{Run $session.sessionId PowerShell $_}
  $profileC=[ordered]@{name='C';status=if(@($powershell|Where-Object{$_.state-ne'Succeeded'}).Count-eq0){'PASS'}else{'FAIL'};commands=@($powershell|ForEach-Object{@{input=$_.exactInput;state=$_.state;identity=$_.result.executionIdentity}})}

  $get=$aCommands|Where-Object{$_.exactInput-like'get *'}|Select-Object -First 1;$artifact=$get.result.artifacts[0];$meta=Api GET "/api/v1/live-response/artifacts/$($artifact.artifactId)";$signed=Api POST "/api/v1/live-response/artifacts/$($artifact.artifactId):url" $admin @{expiresInSeconds=60};$download=Invoke-WebRequest $signed.url -UseBasicParsing;$downloadHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($download.Content)).ToLowerInvariant()
  $profileD=[ordered]@{name='D';status=if($artifact.sha256-eq$fixtureHash-and$downloadHash-eq$fixtureHash-and$meta.nativeIdentity-and$meta.consistent){'PASS'}else{'FAIL'};artifactId=$artifact.artifactId;expectedHash=$fixtureHash;metadataHash=$meta.sha256;downloadHash=$downloadHash;nativeIdentity=$meta.nativeIdentity;consistent=$meta.consistent}

  # Profiles A-D intentionally consume most of the hard 20-command/minute budget.
  # Preserve that production bound and enter the next fixed rate window for E-F.
  Start-Sleep -Seconds 61
  $injection=Status POST "/api/v1/live-response/sessions/$($session.sessionId)/commands" $admin @{commandType='BuiltIn';input='pwd;whoami';timeoutSeconds=5}
  $guess=Status GET "/api/v1/live-response/sessions/$([guid]::NewGuid())"
  $foreignRead=Status GET "/api/v1/live-response/sessions/$($session.sessionId)" $foreign
  $uploadDisabled=Status POST "/api/v1/live-response/sessions/$($session.sessionId)/commands" $admin @{commandType='Upload';input=(Join-Path $data 'uploaded.txt');timeoutSeconds=5;uploadContentBase64=[Convert]::ToBase64String([byte[]](1,2,3));uploadSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]](1,2,3))).ToLowerInvariant();overwrite=$false}
  $traversal=Run $session.sessionId BuiltIn 'stat ..\outside.txt'
  $ansi=Run $session.sessionId PowerShell 'Write-Output ([char]27 + "[31mRED")'
  $ansiText=($ansi.output|ForEach-Object{$_.text})-join''
  $flood=Run $session.sessionId PowerShell '1..20000 | ForEach-Object { "X" * 40 }' 60
  $cancel=Api POST "/api/v1/live-response/sessions/$($session.sessionId)/commands" $admin @{commandType='PowerShell';input='Start-Sleep -Seconds 20';timeoutSeconds=30}
  $deadline=(Get-Date).AddSeconds(15);do{Start-Sleep -Milliseconds 150;$cancel=Api GET "/api/v1/live-response/sessions/$($session.sessionId)/commands/$($cancel.commandId)"}while($cancel.state-ne'Running'-and(Get-Date)-lt$deadline)
  Api POST "/api/v1/live-response/sessions/$($session.sessionId)/commands/$($cancel.commandId):cancel" $admin @{reason='controlled process-scoped cancellation'}|Out-Null
  $deadline=(Get-Date).AddSeconds(20);do{Start-Sleep -Milliseconds 250;$cancel=Api GET "/api/v1/live-response/sessions/$($session.sessionId)/commands/$($cancel.commandId)"}while($cancel.state-notin@('Cancelled','Failed','TimedOut')-and(Get-Date)-lt$deadline)
  $timeout=Run $session.sessionId PowerShell 'Start-Sleep -Seconds 10' 2
  $profileE=[ordered]@{name='E';status=if($forgedApproval-eq400-and$injection-eq400-and$guess-eq404-and$foreignRead-eq404-and$uploadDisabled-eq400-and$traversal.state-eq'Failed'-and$ansiText-notmatch"`e"-and$flood.result.truncated-and$cancel.state-eq'Cancelled'-and$timeout.state-eq'TimedOut'){'PASS'}else{'FAIL'};forgedApproval=$forgedApproval;injection=$injection;guess=$guess;foreignRead=$foreignRead;uploadDisabled=$uploadDisabled;traversal=$traversal.state;ansiSanitized=($ansiText-notmatch"`e");floodState=$flood.state;floodBytes=$flood.result.stdoutBytes;floodTruncated=$flood.result.truncated;cancellation=$cancel.state;timeout=$timeout.state}

  $uncertain=Api POST "/api/v1/live-response/sessions/$($session.sessionId)/commands" $admin @{commandType='PowerShell';input='Start-Sleep -Seconds 20';timeoutSeconds=30}
  $deadline=(Get-Date).AddSeconds(15);do{Start-Sleep -Milliseconds 150;$uncertain=Api GET "/api/v1/live-response/sessions/$($session.sessionId)/commands/$($uncertain.commandId)"}while($uncertain.state-ne'Running'-and(Get-Date)-lt$deadline)
  Stop-Process -Id $process.Id -Force;Wait-Process -Id $process.Id -ErrorAction SilentlyContinue;Start-Sleep 1;$process=StartAgent
  $deadline=(Get-Date).AddSeconds(30);do{Start-Sleep -Milliseconds 400;$uncertain=Api GET "/api/v1/live-response/sessions/$($session.sessionId)/commands/$($uncertain.commandId)"}while($uncertain.state-ne'Uncertain'-and(Get-Date)-lt$deadline)
  $afterRestart=Run $session.sessionId BuiltIn 'pwd'
  $profileF=[ordered]@{name='F';status=if($uncertain.state-eq'Uncertain'-and$afterRestart.state-eq'Succeeded'){'PASS'}else{'FAIL'};interruptedCommand=$uncertain.commandId;interruptedState=$uncertain.state;postRestartCommand=$afterRestart.commandId;postRestartState=$afterRestart.state;replayed=$false}

  $transcript=Api GET "/api/v1/live-response/sessions/$($session.sessionId)/transcript";$export=Api POST "/api/v1/live-response/sessions/$($session.sessionId)/transcript:export"
  $final=Api GET "/api/v1/live-response/sessions/$($session.sessionId)";$profiles=@($profileA,$profileB,$profileC,$profileD,$profileE,$profileF)
  $report=[ordered]@{schemaVersion='sprint17-windows-live-response.v1';executedAt=[DateTimeOffset]::UtcNow;os=(Get-CimInstance Win32_OperatingSystem).Caption;build=(Get-CimInstance Win32_OperatingSystem).BuildNumber;architecture=$env:PROCESSOR_ARCHITECTURE;dotnet=(dotnet --version);administrator=$true;integrity='High';endpointId=$endpoint.id;agentId=$final.agentId;agentInstallationId=$final.agentInstallationId;agentProcessId=$process.Id;sessionId=$session.sessionId;requester=$request.analystId;approver=$approved.approverId;capabilityHash=$request.capabilityHash;profiles=$profiles;transcript=[ordered]@{records=@($transcript.transcript).Count;hash=$transcript.transcriptHash;verified=$transcript.verified;exportRecords=$export.records;exportHash=$export.sha256};hashAndArtifact=$profileD;passed=(@($profiles|Where-Object{$_.status-ne'PASS'}).Count-eq0-and$transcript.verified-and$export.records-gt0)}
  $report|ConvertTo-Json -Depth 30|Set-Content artifacts/sprint17-windows-live-response.json
  $report|ConvertTo-Json -Depth 30
  if(!$report.passed){exit 1}
} finally {
  if($process-and!$process.HasExited){Stop-Process -Id $process.Id -Force;Wait-Process -Id $process.Id -ErrorAction SilentlyContinue}
  foreach($key in $keys){[Environment]::SetEnvironmentVariable($key,$old[$key])}
}
