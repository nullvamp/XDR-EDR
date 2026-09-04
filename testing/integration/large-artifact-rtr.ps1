[CmdletBinding()]
param(
    [string] $VictimVmName = 'XDR-Victim-Sprint18',
    [string] $CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
    [string] $QualificationRoot = 'C:\Sprint24Qualification',
    [int] $TimeoutSeconds = 300
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '../..'); Set-Location $root
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated host token required.' }
if ((Get-VM -Name $VictimVmName).State -ne 'Running') { throw 'Existing victim VM must be running.' }
if (-not (Test-Path -LiteralPath $CredentialPath)) { throw 'Existing victim credential is unavailable.' }
if ((docker ps --filter 'name=falco' --format '{{.Names}}') -or (docker ps --filter 'name=deployment-agent' --format '{{.Names}}')) { throw 'Falco and the Docker demo agent must remain stopped.' }

$settings=@{}; Get-Content .env|Where-Object{$_-match '^\s*([^#=\s]+)=(.*)$'}|ForEach-Object{$settings[$matches[1]]=$matches[2].Trim().Trim('"').Trim("'")}
$login=Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/auth/token -ContentType application/json -Body (@{username=$settings.PLATFORM_BOOTSTRAP_USER;password=$settings.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json -Compress)
$admin=@{Authorization="Bearer $($login.access_token)"}
function B64([byte[]]$v){[Convert]::ToBase64String($v).TrimEnd('=').Replace('+','-').Replace('/','_')}
function Jwt([string]$subject,[string]$tenant=$settings.PLATFORM_BOOTSTRAP_TENANT_ID){$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$h=B64([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'));$b=B64([Text.Encoding]::UTF8.GetBytes((@{iss='security-platform';aud='security-platform-api';sub=$subject;tid=$tenant;per=@('platform:admin','live:approve:elevated');pty='user';iat=$now;exp=$now+7200;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress)));$mac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($settings.PLATFORM_JWT_SIGNING_KEY));try{$s=B64($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$h.$b")))}finally{$mac.Dispose()};@{Authorization="Bearer $h.$b.$s"}}
$approver=Jwt 'large-artifact-separated-approver'; $foreign=Jwt 'large-artifact-foreign' ([guid]::NewGuid().ToString('D'))
function Api([string]$method,[string]$path,$headers=$admin,$body=$null){$a=@{Method=$method;Uri="http://127.0.0.1:8080$path";Headers=$headers;DisableKeepAlive=$true};if($null-ne$body){$a.ContentType='application/json';$a.Body=[Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Depth 40 -Compress))};(Invoke-RestMethod @a).data}
function Status([string]$method,[string]$path,$headers=$admin){try{Api $method $path $headers|Out-Null;200}catch{[int]$_.Exception.Response.StatusCode}}
function Session{$credential=Import-Clixml -LiteralPath $CredentialPath;$deadline=[DateTimeOffset]::UtcNow.AddMinutes(3);do{try{return New-PSSession -VMName $VictimVmName -Credential $credential -ErrorAction Stop}catch{Start-Sleep 2}}while([DateTimeOffset]::UtcNow-lt$deadline);throw 'PowerShell Direct unavailable.'}
function Victim([scriptblock]$script,[object[]]$arguments=@()){$s=Session;try{Invoke-Command -Session $s -ScriptBlock $script -ArgumentList $arguments}finally{Remove-PSSession $s}}
function Wait-Session([guid]$id){$deadline=[DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds);do{Start-Sleep -Milliseconds 400;$x=Api GET "/api/v1/live-response/sessions/$id"}while($x.state-notin@('Active','Rejected','Expired','Closed')-and[DateTimeOffset]::UtcNow-lt$deadline);$x}
function Run-Command([guid]$session,[string]$exactCommand,[int]$timeout=300){$x=Api POST "/api/v1/live-response/sessions/$session/commands" $admin @{commandType='BuiltIn';input=$exactCommand;timeoutSeconds=$timeout};$deadline=[DateTimeOffset]::UtcNow.AddSeconds([Math]::Max($TimeoutSeconds,$timeout+30));do{Start-Sleep -Milliseconds 400;$x=Api GET "/api/v1/live-response/sessions/$session/commands/$($x.commandId)"}while($x.state-notin@('Succeeded','Failed','TimedOut','Cancelled','Expired','Uncertain')-and[DateTimeOffset]::UtcNow-lt$deadline);$x}

$publish=Join-Path $root '.tooling/large-artifact-agent'; $agentProcess=$null
try {
    dotnet publish agent/core/Platform.Agent/Platform.Agent.csproj -c Release -r win-x64 --self-contained true --no-restore -o $publish | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Victim agent publish failed.' }
    $s=Session
    try {
        Invoke-Command -Session $s -ScriptBlock { param($q) Get-Process Platform.Agent -ErrorAction SilentlyContinue|Stop-Process -Force; New-Item -ItemType Directory -Path "$q\agent" -Force|Out-Null; Get-ChildItem "$q\agent" -Force -ErrorAction SilentlyContinue|Remove-Item -Recurse -Force } -ArgumentList $QualificationRoot
        Copy-Item -Path (Join-Path $publish '*') -Destination "$QualificationRoot\agent" -ToSession $s -Recurse -Force
    } finally { Remove-PSSession $s }
    $fixture=Victim { param($q) New-Item -ItemType Directory -Path $q -Force|Out-Null;$path="$q\large-artifact.bin";$stream=[IO.File]::Open($path,'Create','Write','None');try{$buffer=New-Object byte[] (1MB);for($i=0;$i-lt12;$i++){for($j=0;$j-lt$buffer.Length;$j++){$buffer[$j]=[byte](($i+$j)%251)};$stream.Write($buffer,0,$buffer.Length)};$stream.Flush($true)}finally{$stream.Dispose()};[pscustomobject]@{Path=$path;Size=(Get-Item $path).Length;Sha256=(Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()} } @($QualificationRoot)
    $identityState=Victim { param($q) Add-Type -AssemblyName System.Security;New-Item -ItemType Directory -Path "$q\runtime-data" -Force|Out-Null;Copy-Item C:\Sprint21Qualification\runtime-data\state.dat "$q\runtime-data\state.dat" -Force;$hasher=[Security.Cryptography.SHA256]::Create();try{$entropy=$hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes('open-security-platform-agent-state-v1'))}finally{$hasher.Dispose()};$bytes=[IO.File]::ReadAllBytes("$q\runtime-data\state.dat");$clear=[Security.Cryptography.ProtectedData]::Unprotect($bytes,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine);$state=[Text.Encoding]::UTF8.GetString($clear)|ConvertFrom-Json;[pscustomobject]@{EndpointId=$state.endpointId;AgentId=$state.agentId;InstallationId=$state.installationId} } @($QualificationRoot)
    $endpoint=(Api GET '/api/v1/endpoints?pageSize=100').items|Where-Object{$_.id-eq$identityState.EndpointId}|Select-Object -First 1;if(!$endpoint){throw 'Existing victim endpoint identity was not found.'}
    $agentProcess=Victim { param($q) Get-Process Platform.Agent -ErrorAction SilentlyContinue|Stop-Process -Force;Start-Sleep 1;$env:PLATFORM_CONTROL_PLANE_URL='https://gateway:8443';Remove-Item Env:PLATFORM_ENROLLMENT_TOKEN_ID -ErrorAction SilentlyContinue;Remove-Item Env:PLATFORM_ENROLLMENT_TOKEN_SECRET -ErrorAction SilentlyContinue;$env:PLATFORM_AGENT_DATA="$q\runtime-data";$env:PLATFORM_CA_CERT_PATH='C:\Sprint19Qualification\ca.crt';$env:PLATFORM_ENVIRONMENT='production';$env:PLATFORM_RESPONSE_ONLY='true';$env:PLATFORM_LIVE_RESPONSE_ROOTS=$q;$env:PLATFORM_ARTIFACT_TRANSFER_MIBPS='32';(Start-Process "$q\agent\Platform.Agent.exe" -PassThru -WindowStyle Hidden -RedirectStandardOutput "$q\agent-response.log" -RedirectStandardError "$q\agent-response-error.log").Id } @($QualificationRoot)
    $requested=Api POST '/api/v1/live-response/sessions' $admin @{endpointId=$endpoint.id;capabilities=@('builtin','file-download','file-upload');idleTimeoutSeconds=900;absoluteLifetimeSeconds=3600;policyVersion='live-response-policy.v1'}
    if($requested.state-eq'PendingApproval'){$null=Api POST "/api/v1/live-response/sessions/$($requested.sessionId):approve" $approver @{capabilityHash=$requested.capabilityHash;reason='Separated approval for bounded large-artifact victim qualification'}}
    $session=Wait-Session $requested.sessionId;if($session.state-ne'Active'){throw "Live Response session did not activate: $($session.state)"}

    $get=Run-Command $session.sessionId "get `"$($fixture.Path)`"" 900;if($get.state-ne'Succeeded'){throw "Large artifact get failed: $($get.state)"}
    $artifact=$get.result.artifacts|Select-Object -First 1;$transfer=(Api GET "/api/v1/artifact-transfers?ownerId=$($get.commandId)")|Select-Object -First 1
    $download=Join-Path $root 'artifacts/large-artifact-download.bin';Invoke-WebRequest -Uri "http://127.0.0.1:8080/api/v1/artifact-transfers/$($transfer.transferId)/content" -Headers $admin -OutFile $download -UseBasicParsing
    $downloadHash=(Get-FileHash $download -Algorithm SHA256).Hash.ToLowerInvariant()
    $foreignStatus=Status GET "/api/v1/artifact-transfers/$($transfer.transferId)" $foreign

    $tool=Join-Path $root 'artifacts/controlled-forensic-tool.exe';[IO.File]::WriteAllBytes($tool,[Text.Encoding]::UTF8.GetBytes(('CONTROLLED-NONEXECUTABLE-LARGE-ARTIFACT-RTR-'*4096)));$toolHash=(Get-FileHash $tool -Algorithm SHA256).Hash.ToLowerInvariant();$toolSize=(Get-Item $tool).Length
    $toolHeaders=$admin.Clone();$toolHeaders['X-Tool-Name']='controlled-non-executable';$toolHeaders['X-Tool-Version']='1.0.0';$toolHeaders['X-Tool-FileName']='controlled-tool.exe';$toolHeaders['X-Tool-SHA256']=$toolHash;$toolHeaders['X-Tool-Allow-Unsigned']='true'
    $package=(Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8080/api/v1/live-response/tool-packages' -Headers $toolHeaders -ContentType 'application/octet-stream' -InFile $tool).data
    $stage=Run-Command $session.sessionId "stage-tool $($package.packageId)" 300;$stageText=($stage.output|ForEach-Object{$_.text})-join'';$stageData=$stageText|ConvertFrom-Json
    $staged=Victim { param($q,$id,$file) $path="$q\runtime-data\approved-tools\$id\$file";[pscustomobject]@{Exists=Test-Path -LiteralPath $path;Sha256=if(Test-Path -LiteralPath $path){(Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null};ProcessCount=@(Get-Process controlled-tool -ErrorAction SilentlyContinue).Count} } @($QualificationRoot,$package.packageId,$package.fileName)
    $remove=Run-Command $session.sessionId "remove-tool $($package.packageId)";$removeText=($remove.output|ForEach-Object{$_.text})-join'';$removeData=$removeText|ConvertFrom-Json
    $removed=Victim { param($q,$id) -not(Test-Path -LiteralPath "$q\runtime-data\approved-tools\$id") } @($QualificationRoot,$package.packageId)
    $closed=Api POST "/api/v1/live-response/sessions/$($session.sessionId):close" $admin @{reason='Large-artifact RTR qualification complete'}
    $profileA=$transfer.state-eq'Completed'-and$transfer.size-eq12582912-and$transfer.totalChunks-eq3-and$transfer.receivedChunks-eq3-and$transfer.receivedBytes-eq$transfer.size
    $profileB=$artifact.sha256-eq$fixture.Sha256-and$downloadHash-eq$fixture.Sha256-and$foreignStatus-in@(403,404)
    $profileC=$stage.state-eq'Succeeded'-and$stageData.executed-eq$false-and$stageData.signerState-eq'unsigned'-and$staged.Exists-and$staged.Sha256-eq$toolHash-and$staged.ProcessCount-eq0
    $profileD=$remove.state-eq'Succeeded'-and$removeData.ownedPathOnly-and$removeData.removed-and$removed
    $report=[ordered]@{schemaVersion='large-artifact-rtr.v1';executedAt=[DateTimeOffset]::UtcNow;victim=@{vm=$VictimVmName;endpointId=$endpoint.id;agentPid=$agentProcess;hostMutation='none';newVmOrImage=$false};largeArtifact=@{source=$fixture;artifactId=$artifact.artifactId;transfer=$transfer;downloadSha256=$downloadHash;foreignTenantStatus=$foreignStatus};toolPackage=@{packageId=$package.packageId;size=$toolSize;sha256=$toolHash;allowUnsigned=$true;stageState=$stage.state;stageResult=$stageData;victim=$staged;removeState=$remove.state;removeResult=$removeData;removed=$removed;autoExecuted=$false};profiles=@{A=if($profileA){'PASS'}else{'FAIL'};B=if($profileB){'PASS'}else{'FAIL'};C=if($profileC){'PASS'}else{'FAIL'};D=if($profileD){'PASS'}else{'FAIL'}};sessionClose=$closed.state;result=if($profileA-and$profileB-and$profileC-and$profileD-and$closed.state-eq'Closed'){'PASS'}else{'FAIL'}}
    $report|ConvertTo-Json -Depth 40|Set-Content artifacts/large-artifact-rtr.json -Encoding utf8;$report|ConvertTo-Json -Depth 12
    if($report.result-ne'PASS'){exit 1}
} finally {
    try { Victim { Get-Process Platform.Agent -ErrorAction SilentlyContinue|Stop-Process -Force } | Out-Null } catch {}
}

