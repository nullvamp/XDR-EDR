param([string]$RuntimeArtifact='artifacts/sprint3h-windows-runtime-delete-recreate.json',[string]$Output='artifacts/sprint3h-windows-policy-lifecycle.json')
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path;Set-Location $root
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent();if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator token required.'}
$endpointId=(Get-Content $RuntimeArtifact -Raw|ConvertFrom-Json).endpointId
$run=(Get-ChildItem artifacts -Directory -Filter 'sprint3e-windows-*'|Sort-Object LastWriteTime -Descending|Select-Object -First 1).FullName
$work=Get-ChildItem $run -Directory|Where-Object Name -Like 'workload with spaces-*'|Select-Object -First 1 -ExpandProperty FullName
$cfg=@{};Get-Content .env|Where-Object{$_ -match '^[^#].*='}|ForEach-Object{$p=$_.Split('=',2);$cfg[$p[0]]=$p[1]}
$session=Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json)
$headers=@{Authorization="Bearer $($session.access_token)"}
$effective=(Invoke-RestMethod -Uri "http://localhost:8080/api/v1/endpoints/$endpointId/file-policy" -Headers $headers).data
$originalBody=$effective.policy.policy|ConvertTo-Json -Depth 12|ConvertFrom-Json
$env:PLATFORM_AGENT_DATA=$run;$env:PLATFORM_ENVIRONMENT='production';$env:PLATFORM_CONTROL_PLANE_URL='https://localhost:8443';$env:PLATFORM_CA_CERT_PATH=(Resolve-Path deployment/certificates/ca.crt).Path;$env:PLATFORM_ENROLLMENT_TOKEN_ID='';$env:PLATFORM_ENROLLMENT_TOKEN_SECRET=''
$exe=Join-Path $root 'agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.exe'
function CreatePolicy($body,[string]$name){$json=@{name=$name;policy=$body}|ConvertTo-Json -Depth 12;(Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/file-telemetry/policies -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json))).data}
function Assign($policy){Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/file-telemetry/policies/$($policy.id):assign" -Headers $headers -ContentType application/json -Body (@{endpointId=$endpointId}|ConvertTo-Json)|Out-Null}
function Restart([string]$name){Get-Process Platform.Agent -ErrorAction SilentlyContinue|Stop-Process -Force;Start-Process -FilePath $exe -RedirectStandardOutput (Join-Path $run "$name.log") -RedirectStandardError (Join-Path $run "$name.stderr.log") -PassThru -WindowStyle Hidden}
function WaitPolicy($policy,[bool]$rejected){$deadline=[DateTimeOffset]::UtcNow.AddSeconds(45);do{Start-Sleep 1;$state=(Invoke-RestMethod -Uri "http://localhost:8080/api/v1/endpoints/$endpointId/file-policy" -Headers $headers).data;$ok=if($rejected){$state.policy.id -eq $policy.id -and $state.rejectedVersion -eq $policy.version -and $state.drift}else{$state.policy.id -eq $policy.id -and $state.appliedVersion -eq $policy.version -and -not $state.drift}}while(-not $ok -and [DateTimeOffset]::UtcNow -lt $deadline);if(-not $ok){throw "Policy $($policy.id) acknowledgement did not reach expected state."};$state}
function PathCount([string]$path){[long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.file_events where endpoint_id='$endpointId' and event_data->>'currentPath'='$($path.Replace("'","''"))'")}
$agent=$null;$rows=@();$restoreBody=$originalBody|ConvertTo-Json -Depth 12|ConvertFrom-Json
try{
  $disabledBody=$originalBody|ConvertTo-Json -Depth 12|ConvertFrom-Json;$disabledBody.enabled=$false
  $disabled=CreatePolicy $disabledBody "sprint3h-disabled-$([guid]::NewGuid().ToString('N'))";Assign $disabled;$agent=Restart 'policy-disabled';$disabledState=WaitPolicy $disabled $false
  $disabledPath=Join-Path $work "policy-disabled-$([guid]::NewGuid().ToString('N')).txt";$before=PathCount $disabledPath;[IO.File]::WriteAllText($disabledPath,'must-not-collect');Start-Sleep 5;$after=PathCount $disabledPath
  $rows+=@{name='policy-disable';before=$before;after=$after;acknowledgedAt=$disabledState.acknowledgedAt;drift=$disabledState.drift;passed=$after -eq $before}
  $enabledBody=$restoreBody|ConvertTo-Json -Depth 12|ConvertFrom-Json;$enabledBody.enabled=$true
  $enabled=CreatePolicy $enabledBody "sprint3h-enabled-$([guid]::NewGuid().ToString('N'))";Assign $enabled;$agent=Restart 'policy-enabled';$enabledState=WaitPolicy $enabled $false
  $enabledPath=Join-Path $work "policy-enabled-$([guid]::NewGuid().ToString('N')).txt";$enabledBefore=PathCount $enabledPath;$stream=[IO.File]::Open($enabledPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);$stream.Dispose();[IO.File]::WriteAllText($enabledPath,'collect');Start-Sleep 8;$enabledAfter=PathCount $enabledPath
  $rows+=@{name='policy-re-enable';before=$enabledBefore;after=$enabledAfter;acknowledgedAt=$enabledState.acknowledgedAt;drift=$enabledState.drift;passed=$enabledAfter -gt $enabledBefore}
  $mismatchBody=$enabledBody|ConvertTo-Json -Depth 12|ConvertFrom-Json;$mismatchBody.collectorSource='linux.falco-json'
  $mismatch=CreatePolicy $mismatchBody "sprint3h-mismatch-$([guid]::NewGuid().ToString('N'))";Assign $mismatch;$agent=Restart 'policy-mismatch';$mismatchState=WaitPolicy $mismatch $true
  $rows+=@{name='policy-source-mismatch';rejectedVersion=$mismatchState.rejectedVersion;validationError=$mismatchState.validationError;drift=$mismatchState.drift;passed=$mismatchState.drift -and $mismatchState.validationError -match 'collector'}
  $restored=CreatePolicy $enabledBody "sprint3h-file-restore-$([guid]::NewGuid().ToString('N'))";Assign $restored;$agent=Restart 'policy-restored';$restoredState=WaitPolicy $restored $false
  $rows+=@{name='policy-restoration';policyId=$restored.id;version=$restored.version;drift=$restoredState.drift;passed=-not $restoredState.drift}
  $report=@{schema='platform.sprint3h.windows-policy-lifecycle.v1';executedAt=[DateTimeOffset]::UtcNow;endpointId=$endpointId;rows=$rows;passed=@($rows|Where-Object{-not $_.passed}).Count -eq 0};$report|ConvertTo-Json -Depth 8|Set-Content $Output;if(-not $report.passed){throw 'Windows policy lifecycle acceptance failed.'}
}finally{if($agent -and -not $agent.HasExited){Stop-Process -Id $agent.Id -Force;$agent.WaitForExit()}}
