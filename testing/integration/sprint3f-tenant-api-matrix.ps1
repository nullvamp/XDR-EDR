param([string]$Output='artifacts/sprint3f-tenant-api-matrix.json')
$ErrorActionPreference='Stop';Set-Location (Resolve-Path (Join-Path $PSScriptRoot '../..'))
$cfg=@{};Get-Content .env|Where-Object{$_ -match '^[^#].*='}|ForEach-Object{$p=$_.Split('=',2);$cfg[$p[0]]=$p[1]}
function B64([byte[]]$b){[Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')}
function Jwt([string]$tenant,[string[]]$permissions){$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$h=B64([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'));$p=B64([Text.Encoding]::UTF8.GetBytes((@{iss='security-platform';aud='security-platform-api';sub='sprint3f-tenant-b';tid=$tenant;per=$permissions;pty='user';iat=$now;exp=$now+1800;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress)));$mac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($cfg.PLATFORM_JWT_SIGNING_KEY));"$h.$p.$(B64($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$h.$p"))))"}
$login=Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json);$a=@{Authorization="Bearer $($login.access_token)"}
$tenantB=[guid]::NewGuid().ToString();docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -c "insert into platform.tenants(id,organization_id,name,region,status) select '$tenantB',organization_id,'Sprint3F Tenant B','local','active' from platform.tenants limit 1"|Out-Null
$b=@{Authorization="Bearer $(Jwt $tenantB @('platform:admin'))"};$tests=@()
function Request([string]$name,[string]$method,[string]$uri,[hashtable]$headers,[object]$body=$null,[int[]]$allowed=@(200,201,202,204,400,403,404)){$status=0;$text='';try{$args=@{Method=$method;Uri=$uri;Headers=$headers;UseBasicParsing=$true};if($null-ne $body){$args.ContentType='application/json';$args.Body=($body|ConvertTo-Json -Depth 12)};$r=Invoke-WebRequest @args;$status=[int]$r.StatusCode;$text=$r.Content}catch{$status=[int]$_.Exception.Response.StatusCode;try{$reader=[IO.StreamReader]::new($_.Exception.Response.GetResponseStream());$text=$reader.ReadToEnd();$reader.Dispose()}catch{}};$leak=$text -match $cfg.PLATFORM_BOOTSTRAP_PASSWORD -or $text -match $cfg.POSTGRES_PASSWORD;$script:tests += [ordered]@{operation=$name;method=$method;uri=$uri;status=$status;serverError=$status -eq 500;secretLeak=$leak;allowed=$status -in $allowed;responseBytes=$text.Length};return [pscustomobject]@{status=$status;text=$text}}
$aPage=Request 'tenant-a-file-search' GET 'http://localhost:8080/api/v1/files?pageSize=1' $a
$aJson=$aPage.text|ConvertFrom-Json;$entity=$aJson.data.items[0];$endpoint=$entity.endpointId;$entityId=$entity.fileEntityId
$aCursor=$aJson.data.nextCursor;$policy=(Invoke-RestMethod -Uri http://localhost:8080/api/v1/file-telemetry/policies -Headers $a).data|Select-Object -First 1
$queries=@('','path=..%2F..%2F','path=%252e%252e%252f','path=%CE%94','path=C%3A%5CTEMP','filename=sample.txt',('sha256=' + ('a'*64)),'user=root','container=guess','path=destination-probe')
$names=@('file-search','path-search','encoded-path-search','unicode-search','case-search','filename-search','hash-search','user-search','container-search','destination-path-search')
for($i=0;$i-lt$queries.Count;$i++){Request $names[$i] GET ("http://localhost:8080/api/v1/files?pageSize=5&"+$queries[$i]) $b|Out-Null}
Request 'entity-details' GET "http://localhost:8080/api/v1/endpoints/$endpoint/files/$entityId" $b @() @(404)|Out-Null
Request 'event-details-direct-guess' GET "http://localhost:8080/api/v1/endpoints/$endpoint/files/$entityId" $b @() @(404)|Out-Null
Request 'file-history' GET "http://localhost:8080/api/v1/endpoints/$endpoint/files/$entityId/history" $b @() @(200)|Out-Null
Request 'endpoint-timeline' GET "http://localhost:8080/api/v1/endpoints/$endpoint/file-timeline" $b @() @(200)|Out-Null
Request 'process-to-file' GET "http://localhost:8080/api/v1/endpoints/$endpoint/processes/$('a'*64)/files" $b @() @(200)|Out-Null
Request 'telemetry-health' GET "http://localhost:8080/api/v1/endpoints/$endpoint/file-telemetry-health" $b @() @(404)|Out-Null
if($aCursor){Request 'cursor-reuse' GET ("http://localhost:8080/api/v1/files?pageSize=1&cursor="+[uri]::EscapeDataString($aCursor)) $b @() @(400)|Out-Null;$suffix='A';if($aCursor.EndsWith('A')){$suffix='B'};$bad=$aCursor.Substring(0,$aCursor.Length-1)+$suffix;Request 'cursor-modification' GET ("http://localhost:8080/api/v1/files?pageSize=1&cursor="+[uri]::EscapeDataString($bad)) $b @() @(400)|Out-Null}
Request 'export-retrieval-sync' GET "http://localhost:8080/api/v1/files:export?endpointId=$endpoint" $b @() @(200)|Out-Null
Request 'policy-read' GET 'http://localhost:8080/api/v1/file-telemetry/policies' $b @() @(200)|Out-Null
Request 'policy-assignment' POST "http://localhost:8080/api/v1/file-telemetry/policies/$($policy.id):assign" $b @{endpointId=$endpoint} @(400,404)|Out-Null
Request 'policy-rollback' POST "http://localhost:8080/api/v1/file-telemetry/policies/$($policy.id):rollback" $b @{version=$policy.version} @(400,404)|Out-Null
Request 'projection-rebuild-platform-admin' POST 'http://localhost:8080/api/v1/files/projections:rebuild' $b $null @(403)|Out-Null
Request 'cached-query-first' GET 'http://localhost:8080/api/v1/files?pageSize=5&path=cache-probe' $b|Out-Null;Request 'cached-query-reuse' GET 'http://localhost:8080/api/v1/files?pageSize=5&path=cache-probe' $b|Out-Null
$missing=@('event-details-route','previous-path-search','native-file-id-search','export-creation','export-status','export-manifest','policy-version-read','exclusion-list','exclusion-create','exclusion-update','exclusion-delete','projection-progress')|ForEach-Object{[ordered]@{operation=$_;status='not-implemented';passed=$false}}
$report=[ordered]@{schema='platform.sprint3f.tenant-api-matrix.v1';executedAt=[DateTimeOffset]::UtcNow.ToString('O');tenantA=$cfg.PLATFORM_BOOTSTRAP_TENANT_ID;tenantB=$tenantB;tests=$tests;missingOperations=$missing;implementedBoundariesPassed=@($tests|Where-Object{$_.serverError-or$_.secretLeak-or-not$_.allowed}).Count-eq 0;complete=$false}
$report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $Output;$report|ConvertTo-Json -Depth 5
if(-not $report.implementedBoundariesPassed){exit 1}
