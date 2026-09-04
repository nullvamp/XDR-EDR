param([string]$Output = "artifacts/sprint2c/policy-validation.json")
$ErrorActionPreference='Stop'; Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))
$config=@{};Get-Content .env|Where-Object{$_ -match '^[^#].*='}|ForEach-Object{$p=$_.Split('=',2);$config[$p[0]]=$p[1]}
$login=Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{username=$config.PLATFORM_BOOTSTRAP_USER;password=$config.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json);$headers=@{Authorization="Bearer $($login.access_token)"}
$endpoint=docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select endpoint_id from platform.process_events where tenant_id='$($config.PLATFORM_BOOTSTRAP_TENANT_ID)' order by received_at desc limit 1";$name="sprint2c-$([guid]::NewGuid().ToString('N'))"
function Create($policy){(Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/process-telemetry/policies -Headers $headers -ContentType application/json -Body (@{name=$name;policy=$policy}|ConvertTo-Json -Depth 20)).data}
function Assign($id){Invoke-WebRequest -Method Post -Uri "http://localhost:8080/api/v1/process-telemetry/policies/$id`:assign" -Headers $headers -ContentType application/json -Body (@{endpointId=$endpoint}|ConvertTo-Json) -UseBasicParsing|Out-Null}
function Effective(){(Invoke-RestMethod -Uri "http://localhost:8080/api/v1/endpoints/$endpoint/process-policy" -Headers $headers).data}
function WaitApplied($id,$version){$deadline=[DateTimeOffset]::UtcNow.AddSeconds(50);do{$x=Effective;if($x.policy.id -eq $id -and $x.appliedVersion -eq $version -and -not $x.drift){return $x};Start-Sleep -Seconds 2}while([DateTimeOffset]::UtcNow -lt $deadline);return $x}
$v1=Create @{collectorSource='procfs';startEnabled=$true;exitEnabled=$true};Assign $v1.id;$a1=WaitApplied $v1.id $v1.version
$v2=Create @{collectorSource='procfs';startEnabled=$false;exitEnabled=$true};Assign $v2.id;$a2=WaitApplied $v2.id $v2.version
$rollback=(Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/process-telemetry/policies/$($v1.id)`:rollback" -Headers $headers -ContentType application/json -Body (@{version=1}|ConvertTo-Json)).data;Assign $rollback.id;$ar=WaitApplied $rollback.id $rollback.version
$invalid=@(
 @{name='match_all';policy=@{exclusionRules=@(@{id=[guid]::NewGuid();category='name';pattern='*'})}}
 @{name='excessive_wildcards';policy=@{exclusionRules=@(@{id=[guid]::NewGuid();category='name';pattern='a*b*c*d*e*f*g*h*i*'})}}
 @{name='overlong';policy=@{exclusionRules=@(@{id=[guid]::NewGuid();category='name';pattern=('a'*257)})}}
 @{name='collector';policy=@{collectorSource='unsupported-source'}}
 @{name='queue';policy=@{maximumQueueBytes=1}}
 @{name='batch';policy=@{maximumBatchEvents=0}}
)
$invalidResults=@();foreach($case in $invalid){try{Invoke-WebRequest -Method Post -Uri http://localhost:8080/api/v1/process-telemetry/policies -Headers $headers -ContentType application/json -Body (@{name="$name-$($case.name)";policy=$case.policy}|ConvertTo-Json -Depth 20)-UseBasicParsing|Out-Null;$status=201}catch{$status=[int]$_.Exception.Response.StatusCode};$invalidResults+=[pscustomobject]@{case=$case.name;status=$status;rejected=($status -eq 400)}}
$audit=docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.process_policy_audit where policy_id in ('$($v1.id)','$($v2.id)','$($rollback.id)')"
$passed=$a1.appliedVersion -eq 1 -and $a2.appliedVersion -eq 2 -and $ar.appliedVersion -eq $rollback.version -and -not $ar.drift -and ($invalidResults.rejected -notcontains $false) -and [int]$audit -gt 0
$report=[ordered]@{passed=$passed;endpoint=$endpoint;v1=$v1;v1Acknowledgement=$a1;v2=$v2;v2Acknowledgement=$a2;rollback=$rollback;rollbackAcknowledgement=$ar;invalid=$invalidResults;auditRecords=[int]$audit};New-Item -ItemType Directory -Force (Split-Path $Output)|Out-Null;$report|ConvertTo-Json -Depth 10|Set-Content $Output;$report|ConvertTo-Json -Depth 5;if(-not $passed){exit 1}
