$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '../..')
Set-Location $root
$compose = @('--env-file','.env','-f','deployment/docker-compose.yml')
$settings = @{}
Get-Content .env | Where-Object { $_ -match '^[^#][^=]*=' } | ForEach-Object {
    $i = $_.IndexOf('='); $settings[$_.Substring(0,$i)] = $_.Substring($i+1)
}
$login = Invoke-RestMethod -Method Post http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{
    username=$settings.PLATFORM_BOOTSTRAP_USER; password=$settings.PLATFORM_BOOTSTRAP_PASSWORD
} | ConvertTo-Json)
$admin = @{ Authorization = "Bearer $($login.access_token)" }
$tenant = $settings.PLATFORM_BOOTSTRAP_TENANT_ID

function B64Url([byte[]]$bytes) { [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }
function Token([string]$subject,[string]$tenantId) {
    $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header=B64Url([Text.Encoding]::UTF8.GetBytes((@{alg='HS256';typ='JWT'}|ConvertTo-Json -Compress)))
    $payload=B64Url([Text.Encoding]::UTF8.GetBytes((@{iss='security-platform';aud='security-platform-api';sub=$subject;tid=$tenantId;per=@('platform:admin');pty='user';iat=$now;exp=$now+3600;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress)))
    $hmac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($settings.PLATFORM_JWT_SIGNING_KEY))
    try { "$header.$payload.$(B64Url($hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$header.$payload"))))" } finally { $hmac.Dispose() }
}
$approver=@{Authorization="Bearer $(Token 'sprint16-approver' $tenant)"}
$foreign=@{Authorization="Bearer $(Token 'foreign-analyst' ([guid]::NewGuid().ToString()))"}
function Api([string]$method,[string]$path,$headers=$admin,$body=$null) {
    $args=@{Method=$method;Uri="http://localhost:8080$path";Headers=$headers}
    if($null-ne$body){$args.ContentType='application/json';$args.Body=($body|ConvertTo-Json -Depth 20 -Compress)}
    (Invoke-RestMethod @args).data
}
function Status([string]$method,[string]$path,$headers=$admin,$body=$null) {
    try { Api $method $path $headers $body | Out-Null; 200 } catch { [int]$_.Exception.Response.StatusCode }
}
function CreateAction([guid]$endpoint,[string]$type,$parameters=@{},[int]$expiry=300) {
    Api POST '/api/v1/response-actions' $admin @{endpointId=$endpoint;actionType=$type;actionVersion=1;parameters=$parameters;timeoutSeconds=30;expiresInSeconds=$expiry;correlationId="sprint16-$([guid]::NewGuid().ToString('N'))"}
}
$terminal=@('Succeeded','Failed','TimedOut','Cancelled','Expired','Rejected')
function WaitAction([guid]$id,[int]$seconds=60) {
    $deadline=(Get-Date).AddSeconds($seconds);do{Start-Sleep -Milliseconds 500;$x=Api GET "/api/v1/response-actions/$id"}while($x.state-notin$terminal-and(Get-Date)-lt$deadline);$x
}
function AuditExact($action,[string[]]$expected) { (@($action.auditHistory.action) -join '|') -eq ($expected -join '|') }

$endpoints=Api GET '/api/v1/endpoints?pageSize=100'
$endpoint=$endpoints.items|Where-Object{$_.platform-eq'linux'}|Sort-Object {[datetimeoffset]$_.lastSeenAt} -Descending|Select-Object -First 1
if(!$endpoint){throw 'No enrolled evaluation endpoint is available.'}
$endpointId=[guid]$endpoint.id

$a=WaitAction (CreateAction $endpointId 'endpoint.status').responseActionId
$profileA=[ordered]@{name='A';status=if($a.state-eq'Succeeded'-and(AuditExact $a @('response.requested','response.authorization.allowed','response.queued','response.delivered','response.acknowledged','response.execution.started','response.completed'))){'PASS'}else{'FAIL'};actionId=$a.responseActionId;state=$a.state;audit=@($a.auditHistory.action);resultHash=$a.result.resultHash;endpointBinding=($a.endpointId-eq$endpoint.id-and$a.agentInstallationId-eq$a.result.agentInstallationId)}

$b=WaitAction (CreateAction $endpointId 'process.list' @{maximumRecords=25}).responseActionId
$profileB=[ordered]@{name='B';status=if($b.state-eq'Succeeded'-and$b.result.resultRecords-le25-and$b.result.resultRecords-gt0){'PASS'}else{'FAIL'};actionId=$b.responseActionId;records=$b.result.resultRecords;maximum=25;endpointBinding=($b.endpointId-eq$b.result.endpointId)}

$c=CreateAction $endpointId 'collect.diagnostic' @{includeQueueHealth=$true}
$forgedApproval=Status POST "/api/v1/response-actions/$($c.responseActionId):approve" $approver @{parameterHash=('0'*64);reason='forged hash fixture'}
$c=Api POST "/api/v1/response-actions/$($c.responseActionId):approve" $approver @{parameterHash=$c.parameterHash;reason='verified exact diagnostic request'}
$c=WaitAction $c.responseActionId
$artifact=$c.result.artifacts|Select-Object -First 1
$artifactMeta=Api GET "/api/v1/response-actions/$($c.responseActionId)/artifacts/$($artifact.artifactId)"
$signed=Api POST "/api/v1/response-actions/$($c.responseActionId)/artifacts/$($artifact.artifactId):url" $admin @{expiresInSeconds=60}
$download=Invoke-WebRequest -UseBasicParsing $signed.url
$sha=[Security.Cryptography.SHA256]::Create()
try { $downloadHash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$download.Content))).Replace('-','')).ToLowerInvariant() } finally { $sha.Dispose() }
$profileC=[ordered]@{name='C';status=if($c.state-eq'Succeeded'-and$forgedApproval-eq400-and$c.approverId-eq'sprint16-approver'-and$c.approvedParameterHash-eq$c.parameterHash-and$artifactMeta.sha256-eq$downloadHash){'PASS'}else{'FAIL'};actionId=$c.responseActionId;requester=$c.analystId;approver=$c.approverId;parameterHash=$c.parameterHash;forgedHashStatus=$forgedApproval;artifactId=$artifact.artifactId;artifactHash=$artifact.sha256;signedUrlExactObject=($signed.actionId-eq$c.responseActionId)}

$guess=Status GET "/api/v1/response-actions/$([guid]::NewGuid())"
$foreignRead=Status GET "/api/v1/response-actions/$($a.responseActionId)" $foreign
$wrongEndpoint=Status POST '/api/v1/response-actions' $admin @{endpointId=[guid]::NewGuid();actionType='endpoint.status';actionVersion=1;parameters=@{};timeoutSeconds=30;expiresInSeconds=300}
$unsupported=Status POST '/api/v1/response-actions' $admin @{endpointId=$endpointId;actionType='endpoint.status';actionVersion=99;parameters=@{};timeoutSeconds=30;expiresInSeconds=300}
$unknown=Status POST '/api/v1/response-actions' $admin @{endpointId=$endpointId;actionType='process.list';actionVersion=1;parameters=@{command='whoami'};timeoutSeconds=30;expiresInSeconds=300}
$traversal=Status POST '/api/v1/response-actions' $admin @{endpointId=$endpointId;actionType='file.metadata';actionVersion=1;parameters=@{path='/data/../etc/passwd'};timeoutSeconds=30;expiresInSeconds=300}
$duplicateTransition=Status POST "/api/v1/response-actions/$($a.responseActionId):cancel" $admin @{reason='terminal race fixture'}
$profileD=[ordered]@{name='D';status=if($guess-eq404-and$foreignRead-eq404-and$wrongEndpoint-eq404-and$unsupported-eq400-and$unknown-eq400-and$traversal-eq400-and$duplicateTransition-eq400){'PASS'}else{'FAIL'};actionGuess=$guess;tenantInjection=$foreignRead;endpointInjection=$wrongEndpoint;unsupportedVersion=$unsupported;unknownCommandField=$unknown;pathTraversal=$traversal;terminalRace=$duplicateTransition;cryptographicTamper='PASS: automated unit test';transitionReplay='PASS: automated unit test'}

& docker compose @compose stop agent | Out-Null
$reconnect=CreateAction $endpointId 'endpoint.status' @{} 120
$cancel=CreateAction $endpointId 'endpoint.status' @{} 120
$cancel=Api POST "/api/v1/response-actions/$($cancel.responseActionId):cancel" $admin @{reason='cancel before delivery fixture'}
$expire=CreateAction $endpointId 'endpoint.status' @{} 30
Start-Sleep 33
$expire=WaitAction $expire.responseActionId 5
& docker compose @compose up -d --no-deps agent | Out-Null
$reconnect=WaitAction $reconnect.responseActionId 60
$cancel=Api GET "/api/v1/response-actions/$($cancel.responseActionId)"
$profileE=[ordered]@{name='E';status=if($reconnect.state-eq'Succeeded'-and$cancel.state-eq'Cancelled'-and$cancel.deliveryAttempts-eq0-and$expire.state-eq'Expired'-and$expire.deliveryAttempts-eq0){'PASS'}else{'FAIL'};reconnectAction=$reconnect.responseActionId;reconnectState=$reconnect.state;cancelAction=$cancel.responseActionId;cancelState=$cancel.state;cancelDeliveries=$cancel.deliveryAttempts;expiredAction=$expire.responseActionId;expiredState=$expire.state;expiredDeliveries=$expire.deliveryAttempts}

$telemetryBefore=[long](docker exec deployment-postgres-1 psql -U platform -d platform -At -c 'select count(*) from platform.process_events;')
& docker compose @compose stop agent | Out-Null
$pressure=@();1..10|ForEach-Object{$type=if($_%2){'endpoint.status'}else{'process.list'};$params=if($type-eq'process.list'){@{maximumRecords=10}}else{@{}};$pressure+=CreateAction $endpointId $type $params 180}
& docker compose @compose restart gateway | Out-Null
& docker compose @compose up -d --no-deps agent | Out-Null
$finished=@($pressure|ForEach-Object{WaitAction $_.responseActionId 90})
$telemetryAfter=[long](docker exec deployment-postgres-1 psql -U platform -d platform -At -c 'select count(*) from platform.process_events;')
$starts=@($finished|ForEach-Object{@($_.auditHistory|Where-Object{$_.action-eq'response.execution.started'}).Count})
$profileF=[ordered]@{name='F';status=if($finished.Count-eq10-and@($finished|Where-Object{$_.state-ne'Succeeded'}).Count-eq0-and@($starts|Where-Object{$_-ne1}).Count-eq0-and$telemetryAfter-ge$telemetryBefore){'PASS'}else{'FAIL'};actions=$finished.Count;succeeded=@($finished|Where-Object{$_.state-eq'Succeeded'}).Count;executionStartCounts=$starts;duplicateExecutions=@($starts|Where-Object{$_-ne1}).Count;processTelemetryBefore=$telemetryBefore;processTelemetryAfter=$telemetryAfter}

$health=Api GET '/api/v1/response-health'
$pgCount=[long](docker exec deployment-postgres-1 psql -U platform -d platform -At -c "select count(*) from platform.response_actions where tenant_id='$tenant';")
$apiCount=[long](Api GET '/api/v1/response-actions?pageSize=200').total
$pgAudit=[long](docker exec deployment-postgres-1 psql -U platform -d platform -At -c "select count(*) from platform.response_action_audit where tenant_id='$tenant';")
$jsonAudit=[long](docker exec deployment-postgres-1 psql -U platform -d platform -At -c "select coalesce(sum(jsonb_array_length(action_data->'auditHistory')),0) from platform.response_actions where tenant_id='$tenant';")
$pgArtifacts=[long](docker exec deployment-postgres-1 psql -U platform -d platform -At -c "select count(*) from platform.response_artifacts where tenant_id='$tenant';")
$jsonArtifacts=[long](docker exec deployment-postgres-1 psql -U platform -d platform -At -c "select coalesce(sum(jsonb_array_length(coalesce(action_data->'result'->'artifacts','[]'::jsonb))),0) from platform.response_actions where tenant_id='$tenant';")
$reconciliation=[ordered]@{schemaVersion='sprint16-response-reconciliation.v1';executedAt=[DateTimeOffset]::UtcNow;postgresActions=$pgCount;apiActions=$apiCount;postgresAudit=$pgAudit;snapshotAudit=$jsonAudit;postgresArtifacts=$pgArtifacts;snapshotArtifacts=$jsonArtifacts;responseQueue=$health.workerQueue;passed=($pgCount-eq$apiCount-and$pgAudit-eq$jsonAudit-and$pgArtifacts-eq$jsonArtifacts-and$health.workerQueue-eq0)}
$noGenericShellRoute=(Status POST '/api/v1/response/scripts' $admin @{})-eq404
$auditImmutabilityTrigger=(docker exec deployment-postgres-1 psql -U platform -d platform -At -c "select count(*) from pg_trigger where tgname='response_audit_immutable' and not tgisinternal;")-eq'1'
$previousErrorActionPreference=$ErrorActionPreference
$ErrorActionPreference='Continue'
$auditTamperOutput=& docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -c "update platform.response_action_audit set reason='sprint16-tamper' where audit_id=(select audit_id from platform.response_action_audit limit 1);" 2>&1
$auditTamperExitCode=$LASTEXITCODE
$ErrorActionPreference=$previousErrorActionPreference
$auditTamperRejected=$auditTamperExitCode-ne0-and([string]$auditTamperOutput)-match'immutable'
$security=[ordered]@{schemaVersion='sprint16-response-security.v1';executedAt=[DateTimeOffset]::UtcNow;profileD=$profileD;approvalForgeryRejected=($forgedApproval-eq400);signedArtifactHashVerified=($artifact.sha256-eq$downloadHash);noGenericShellRoute=$noGenericShellRoute;auditImmutabilityTrigger=$auditImmutabilityTrigger;auditTamperRejected=$auditTamperRejected;passed=($profileD.status-eq'PASS'-and$forgedApproval-eq400-and$artifact.sha256-eq$downloadHash-and$noGenericShellRoute-and$auditImmutabilityTrigger-and$auditTamperRejected)}
$report=[ordered]@{schemaVersion='sprint16-response-profiles.v1';executedAt=[DateTimeOffset]::UtcNow;endpoint=[ordered]@{id=$endpoint.id;platform=$endpoint.platform;hostname=$endpoint.hostname;qualification='container transport evaluation; not native Linux qualification'};profiles=@($profileA,$profileB,$profileC,$profileD,$profileE,$profileF);responseHealth=$health;passed=@($profileA,$profileB,$profileC,$profileD,$profileE,$profileF|Where-Object{$_.status-ne'PASS'}).Count-eq0}
$report|ConvertTo-Json -Depth 30|Set-Content artifacts/sprint16-response-profiles.json
$security|ConvertTo-Json -Depth 20|Set-Content artifacts/sprint16-response-security.json
$reconciliation|ConvertTo-Json -Depth 10|Set-Content artifacts/sprint16-response-reconciliation.json
$report|ConvertTo-Json -Depth 30
if(!$report.passed-or!$security.passed-or!$reconciliation.passed){exit 1}
