param([string]$Output = "artifacts/sprint2c/tenant-isolation.json")
$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))
$config = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object { $p=$_.Split('=',2); $config[$p[0]]=$p[1] }
$tenantB = [guid]::NewGuid()
$seed = (docker exec deployment-postgres-1 psql -U platform -d platform -AtF ',' -c "select organization_id,region,status from platform.tenants where id='00000000-0000-0000-0000-000000000002'").Split(',')
docker exec deployment-postgres-1 psql -U platform -d platform -v ON_ERROR_STOP=1 -c "insert into platform.tenants(id,organization_id,name,region,status) values('$tenantB','$($seed[0])','Sprint2C Tenant B','$($seed[1])','$($seed[2])')" | Out-Null
if ($LASTEXITCODE) { throw 'Tenant B creation failed.' }
$a = (docker exec deployment-postgres-1 psql -U platform -d platform -AtF ',' -c "select tenant_id,endpoint_id,process_entity_id,event_id from platform.process_events order by received_at desc limit 1").Split(',')
$policyA = docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select id from platform.process_policy_versions where tenant_id='$($a[0])' limit 1"
function Base64Url([byte[]]$value) { [Convert]::ToBase64String($value).TrimEnd('=').Replace('+','-').Replace('/','_') }
$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); $header=Base64Url([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
$claims=@{iss='security-platform';aud='security-platform-api';sub='tenant-b-admin';tid=$tenantB.ToString();per=@('platform:admin','process:read','process:tree:read','process:timeline:read','process:health:read','process:export','process:projection:rebuild');pty='user';iat=$now;exp=$now+3600;jti=[guid]::NewGuid().ToString('N')}
$payload=Base64Url([Text.Encoding]::UTF8.GetBytes(($claims|ConvertTo-Json -Compress))); $mac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($config.PLATFORM_JWT_SIGNING_KEY)); $signature=Base64Url($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$header.$payload"))); $headers=@{Authorization="Bearer $header.$payload.$signature"}
function Attempt($name,$method,$path,$body=$null) { try { $parameters=@{Method=$method;Uri="http://localhost:8080$path";Headers=$headers;UseBasicParsing=$true}; if($body){$parameters.ContentType='application/json';$parameters.Body=$body|ConvertTo-Json};$response=Invoke-WebRequest @parameters; $content=if($response.Content -is [byte[]]){[Text.Encoding]::UTF8.GetString($response.Content)}else{[string]$response.Content}; [pscustomobject]@{name=$name;status=[int]$response.StatusCode;body=$content.Substring(0,[Math]::Min(200,$content.Length))} } catch { $status=if($_.Exception.Response){[int]$_.Exception.Response.StatusCode}else{-1}; [pscustomobject]@{name=$name;status=$status;body=$_.Exception.Message} } }
$results=@(
    Attempt search GET '/api/v1/processes?pageSize=100'
    Attempt detail GET "/api/v1/endpoints/$($a[1])/processes/$($a[2])"
    Attempt tree GET "/api/v1/endpoints/$($a[1])/processes/$($a[2])/tree"
    Attempt timeline GET "/api/v1/endpoints/$($a[1])/process-timeline"
    Attempt health GET "/api/v1/endpoints/$($a[1])/process-telemetry-health"
    Attempt export GET '/api/v1/processes:export'
    Attempt exclusions GET "/api/v1/endpoints/$($a[1])/process-exclusion-metrics"
    Attempt cross_policy POST "/api/v1/process-telemetry/policies/$policyA`:assign" @{endpointId=$a[1]}
    Attempt projection_rebuild POST '/api/v1/processes/projections:rebuild'
)
$passed = ($results|Where-Object{$_.name -eq 'search'}).body -match '"items":\[\]' -and ($results|Where-Object{$_.name -in 'detail','tree','health'}).status -notcontains 200 -and ($results|Where-Object{$_.name -eq 'timeline'}).body -match '"items":\[\]' -and ($results|Where-Object{$_.name -eq 'export'}).status -eq 200 -and ($results|Where-Object{$_.name -eq 'export'}).body -notmatch $a[0] -and ($results|Where-Object{$_.name -eq 'cross_policy'}).status -eq 404 -and ($results|Where-Object{$_.name -eq 'projection_rebuild'}).status -eq 403
$report=[ordered]@{tenantA=$a[0];tenantB=$tenantB;endpointA=$a[1];entityA=$a[2];eventA=$a[3];passed=$passed;results=$results}; New-Item -ItemType Directory -Force (Split-Path $Output)|Out-Null; $report|ConvertTo-Json -Depth 6|Set-Content $Output; $report|ConvertTo-Json -Depth 6; if(-not $passed){exit 1}
