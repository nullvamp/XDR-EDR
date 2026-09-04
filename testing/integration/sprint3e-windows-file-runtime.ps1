param([string]$Output = "artifacts/sprint3e-windows-file-runtime.json")

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator token is required for the Windows ETW file runtime matrix.'
}
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object { $p=$_.Split('=',2);$cfg[$p[0]]=$p[1] }
$session = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json)
$headers = @{Authorization="Bearer $($session.access_token)"}
$before = @((Invoke-RestMethod -Uri http://localhost:8080/api/v1/endpoints?pageSize=100 -Headers $headers).data.items.id)
$token = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/enrollment-tokens -Headers $headers -ContentType application/json -Body (@{expiresAt=[DateTimeOffset]::UtcNow.AddHours(2).ToString('o');maximumUses=1;allowedPlatforms=@('windows');endpointGroupId=$null;policyId=$null}|ConvertTo-Json)
$run = Join-Path $root "artifacts/sprint3e-windows-$([DateTimeOffset]::UtcNow.ToString('yyyyMMddHHmmss'))"
$work = Join-Path $run 'workload with spaces-Δ'
$work = Join-Path $run ("workload with spaces-" + [char]0x0394)
New-Item -ItemType Directory -Force $work | Out-Null
$env:PLATFORM_AGENT_DATA=$run
$env:PLATFORM_ENVIRONMENT='production'
$env:PLATFORM_CONTROL_PLANE_URL='https://localhost:8443'
$env:PLATFORM_CA_CERT_PATH=(Resolve-Path deployment/certificates/ca.crt).Path
$env:PLATFORM_ENROLLMENT_TOKEN_ID=$token.data.metadata.id
$env:PLATFORM_ENROLLMENT_TOKEN_SECRET=$token.data.secret
$agent = Start-Process -FilePath (Join-Path $root 'agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.exe') -RedirectStandardOutput (Join-Path $run 'agent.log') -RedirectStandardError (Join-Path $run 'agent.stderr.log') -PassThru -WindowStyle Hidden
$endpoint=$null;$deadline=[DateTimeOffset]::UtcNow.AddSeconds(60)
do { Start-Sleep 1;$items=@((Invoke-RestMethod -Uri http://localhost:8080/api/v1/endpoints?pageSize=100 -Headers $headers).data.items);$endpoint=$items|Where-Object{$_.id -notin $before}|Select-Object -First 1 } while(-not $endpoint -and [DateTimeOffset]::UtcNow -lt $deadline)
if(-not $endpoint){Stop-Process -Id $agent.Id -Force;throw 'Elevated Windows agent did not enroll.'}
$source=@((Invoke-RestMethod -Uri http://localhost:8080/api/v1/file-telemetry/policies -Headers $headers).data)|Sort-Object version -Descending|Select-Object -First 1
$source.policy.collectorSource='windows.etw-file';$source.policy.includedPaths=@($work);$source.policy.excludedPaths=@();$source.policy.enabled=$true;$source.policy.hashingEnabled=$true;$source.policy.hashesPerMinute=10000
$policyJson = @{name="sprint3e-windows-$([guid]::NewGuid().ToString('N'))";policy=$source.policy}|ConvertTo-Json -Depth 12
$created=Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/file-telemetry/policies -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($policyJson))
Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/file-telemetry/policies/$($created.data.id):assign" -Headers $headers -ContentType application/json -Body (@{endpointId=$endpoint.id}|ConvertTo-Json)|Out-Null
$env:PLATFORM_ENROLLMENT_TOKEN_ID='';$env:PLATFORM_ENROLLMENT_TOKEN_SECRET=''
Stop-Process -Id $agent.Id -Force;$agent.WaitForExit()
$agent = Start-Process -FilePath (Join-Path $root 'agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.exe') -RedirectStandardOutput (Join-Path $run 'assigned.log') -RedirectStandardError (Join-Path $run 'assigned.stderr.log') -PassThru -WindowStyle Hidden
$policyDeadline=[DateTimeOffset]::UtcNow.AddSeconds(45);$effective=$null
do { Start-Sleep 1;$effective=(Invoke-RestMethod -Uri "http://localhost:8080/api/v1/endpoints/$($endpoint.id)/file-policy" -Headers $headers).data } while(($effective.policy.id -ne $created.data.id -or $effective.appliedVersion -ne $created.data.version) -and [DateTimeOffset]::UtcNow -lt $policyDeadline)
if($effective.policy.id -ne $created.data.id -or $effective.appliedVersion -ne $created.data.version){Stop-Process -Id $agent.Id -Force;throw 'Windows file policy was not applied and acknowledged before workload execution.'}

$manifest=@()
function NativeId([string]$path){if($path.Length -gt 2 -and $path.Substring(2).Contains(':')){return $null};if(-not(Test-Path -LiteralPath $path)){return $null};$text=(& fsutil file queryfileid $path 2>$null|Out-String);$match=[regex]::Match($text,'0x[0-9a-fA-F]+');if($match.Success){return $match.Value.ToLowerInvariant()};return $null}
function Record([string]$operation,[string]$path,[string]$sourcePath=$null){$script:manifest += @{operation=$operation;sourcePath=if($sourcePath){$sourcePath}else{$path};destinationPath=if($sourcePath){$path}else{$null};expectedNativeIdentity=(NativeId $path);at=[DateTimeOffset]::UtcNow.ToString('O')};Start-Sleep -Milliseconds 1500}
$file=Join-Path $work 'sample.txt';$createdStream=[IO.File]::Open($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);$createdStream.Dispose();Record 'file-creation' $file;[IO.File]::WriteAllText($file,'initial');Record 'initial-write' $file
[IO.File]::AppendAllText($file,' append');Record 'append' $file
[IO.File]::WriteAllText($file,'overwrite');Record 'overwrite' $file
$stream=[IO.File]::OpenWrite($file);$stream.SetLength(3);$stream.Dispose();Record 'truncate' $file
$renamed=Join-Path $work 'renamed.txt';Move-Item -LiteralPath $file -Destination $renamed;Record 'rename' $renamed $file
$movedDir=Join-Path $work 'moved';New-Item -ItemType Directory $movedDir|Out-Null;$moved=Join-Path $movedDir 'renamed.txt';Move-Item -LiteralPath $renamed -Destination $moved;Record 'move' $moved $renamed
$replacement=Join-Path $work 'replacement.tmp';$replacementBackup=Join-Path $work 'replacement.backup';[IO.File]::WriteAllText($replacement,'replacement');[IO.File]::Replace($replacement,$moved,$replacementBackup);Remove-Item -LiteralPath $replacementBackup -Force;Record 'atomic-replace' $moved
$temporary=Join-Path $work 'temporary.tmp';[IO.File]::WriteAllText($temporary,'temp');Record 'temporary-file' $temporary
$rapid=Join-Path $work 'rapid.txt';[IO.File]::WriteAllText($rapid,'rapid');Remove-Item -LiteralPath $rapid;Record 'rapid-create-delete' $rapid
$unicode=Join-Path $work 'ملف-Δ.txt';[IO.File]::WriteAllText($unicode,'unicode');Record 'unicode-path' $unicode
$unicodeStable=Join-Path $work ([string]::Concat([char]0x0645,[char]0x0644,[char]0x0641,'-',[char]0x0394,'.txt'));[IO.File]::WriteAllText($unicodeStable,'unicode-stable');Record 'unicode-normalization' $unicodeStable
$longDir=$work;1..8|ForEach-Object{$longDir=Join-Path $longDir ('segment-'+('x'*20));New-Item -ItemType Directory -Force $longDir|Out-Null};$long=Join-Path $longDir 'long.txt';[IO.File]::WriteAllText($long,'long');Record 'long-path' $long
$same=Join-Path $work 'recreated.txt';[IO.File]::WriteAllText($same,'old');Record 'same-path-old-create' $same;Remove-Item -LiteralPath $same;Record 'same-path-delete' $same;[IO.File]::WriteAllText($same,'new');Record 'same-path-recreation' $same
[IO.File]::SetAttributes($same,[IO.FileAttributes]::ReadOnly);[IO.File]::SetAttributes($same,[IO.FileAttributes]::Normal);Record 'attribute-change' $same
$acl=Get-Acl -LiteralPath $same;Set-Acl -LiteralPath $same -AclObject $acl;Record 'permission-change' $same
Set-Content -LiteralPath $same -Stream 'sprint3e' -Value 'ads';Record 'alternate-data-stream' ($same + ':sprint3e')
Remove-Item -LiteralPath $moved -Force;Record 'delete' $moved
$identitySource=Join-Path $work 'identity-source.txt';[IO.File]::WriteAllText($identitySource,'identity-chain');Record 'identity-create' $identitySource;Start-Sleep 4
$identityRenamed=Join-Path $work 'identity-renamed.txt';Move-Item -LiteralPath $identitySource -Destination $identityRenamed;Record 'identity-rename' $identityRenamed $identitySource;Start-Sleep 4
$identityDir=Join-Path $work 'identity-destination';New-Item -ItemType Directory -Force $identityDir|Out-Null;$identityMoved=Join-Path $identityDir 'identity-renamed.txt';Move-Item -LiteralPath $identityRenamed -Destination $identityMoved;Record 'identity-same-volume-move' $identityMoved $identityRenamed;Start-Sleep 4
$agentBeforeRecreate=$agent.Id;Stop-Process -Id $agent.Id -Force;$agent.WaitForExit();$agent=Start-Process -FilePath (Join-Path $root 'agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.exe') -RedirectStandardOutput (Join-Path $run 'identity-restart.log') -RedirectStandardError (Join-Path $run 'identity-restart.stderr.log') -PassThru -WindowStyle Hidden;Start-Sleep 5
$recreateProbe=Join-Path $work 'identity-recreate.txt';[IO.File]::WriteAllText($recreateProbe,'old-identity');Record 'identity-recreate-old' $recreateProbe;Start-Sleep 4
Remove-Item -LiteralPath $recreateProbe -Force;Record 'identity-recreate-delete' $recreateProbe;Start-Sleep 4
[IO.File]::WriteAllText($recreateProbe,'new-identity');Record 'identity-recreate-new' $recreateProbe;Start-Sleep 4
Start-Sleep 15
Stop-Process -Id $agent.Id -Force;$agent.WaitForExit()
$env:PLATFORM_ENROLLMENT_TOKEN_ID='';$env:PLATFORM_ENROLLMENT_TOKEN_SECRET=''
$restart=Start-Process -FilePath (Join-Path $root 'agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.exe') -RedirectStandardOutput (Join-Path $run 'restart.log') -RedirectStandardError (Join-Path $run 'restart.stderr.log') -PassThru -WindowStyle Hidden
Start-Sleep 10
if(-not $restart.HasExited){Stop-Process -Id $restart.Id -Force;$restart.WaitForExit()}
$db=docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*),count(distinct event_id),count(distinct sequence),count(*) filter(where event_type='created'),count(*) filter(where event_type='modified'),count(*) filter(where event_type in('renamed','moved')),count(*) filter(where event_type='deleted') from platform.file_events where endpoint_id='$($endpoint.id)'"
$counts=$db.Trim().Split('|')
$report=@{schema='platform.sprint3e.windows-file-runtime.v1';executedAt=[DateTimeOffset]::UtcNow.ToString('O');elevated=$true;identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;endpointId=$endpoint.id;manifest=$manifest;authority=@{rows=[int]$counts[0];distinctEventIds=[int]$counts[1];distinctSequences=[int]$counts[2];created=[int]$counts[3];modified=[int]$counts[4];renameMove=[int]$counts[5];deleted=[int]$counts[6]};restartExit=$restart.ExitCode;passed=[int]$counts[0] -gt 0 -and $counts[0] -eq $counts[1] -and $counts[0] -eq $counts[2]}
$report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $Output
$report|ConvertTo-Json -Depth 6
if(-not $report.passed){exit 1}
