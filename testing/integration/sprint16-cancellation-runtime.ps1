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
$headers = @{ Authorization = "Bearer $($login.access_token)" }
function Api([string]$method,[string]$path,$body=$null) {
    $args=@{Method=$method;Uri="http://localhost:8080$path";Headers=$headers}
    if($null-ne$body){$args.ContentType='application/json';$args.Body=($body|ConvertTo-Json -Depth 10 -Compress)}
    (Invoke-RestMethod @args).data
}

$endpoint = (Api GET '/api/v1/endpoints?pageSize=100').items |
    Where-Object { $_.platform -eq 'linux' } | Sort-Object {[datetimeoffset]$_.lastSeenAt} -Descending | Select-Object -First 1
if(!$endpoint){throw 'No enrolled Linux endpoint is available for the controlled cancellation fixture.'}

try {
    & docker compose @compose stop agent | Out-Null
    $action = Api POST '/api/v1/response-actions' @{
        endpointId=$endpoint.id; actionType='endpoint.status'; actionVersion=1; parameters=@{};
        timeoutSeconds=30; expiresInSeconds=300; correlationId="sprint16-cancellation-$([guid]::NewGuid().ToString('N'))"
    }
    $id = [guid]$action.responseActionId
    $sql = "UPDATE platform.response_actions SET state='Delivered', action_data=jsonb_set(jsonb_set(jsonb_set(action_data,'{state}',to_jsonb('Delivered'::text)),'{deliveredAt}',to_jsonb(now())),'{deliveryAttempts}',to_jsonb(1)), updated_at=now() WHERE tenant_id='$($settings.PLATFORM_BOOTSTRAP_TENANT_ID)'::uuid AND response_action_id='$($id.ToString('D'))'::uuid AND state='Queued';"
    $updated = [string](& docker exec deployment-postgres-1 psql -U platform -d platform -Atc $sql)
    $updated = $updated.Trim()
    if($updated -ne 'UPDATE 1'){throw "Controlled delivered-state setup failed: $updated"}
    $requested = Api POST "/api/v1/response-actions/$($id.ToString('D')):cancel" @{reason='controlled reconnect cancellation qualification'}
    if($requested.state -ne 'CancelRequested'){throw "Expected CancelRequested, got $($requested.state)."}
    & docker compose @compose start agent | Out-Null
    $deadline=(Get-Date).AddSeconds(45)
    do { Start-Sleep -Milliseconds 250; $final=Api GET "/api/v1/response-actions/$($id.ToString('D'))" } while($final.state -ne 'Cancelled' -and (Get-Date) -lt $deadline)
    $last=@($final.auditHistory)[-1]
    $passed=$final.state -eq 'Cancelled' -and $final.completedAt -and $last.action -eq 'response.cancelled' -and $last.actor -eq 'agent'
    $report=[ordered]@{
        schemaVersion='sprint16-cancellation-runtime.v1';result=if($passed){'PASS'}else{'FAIL'}
        actionId=$id;endpointId=$endpoint.id;installationId=$final.agentInstallationId
        initialState='Queued';controlledSetupState='Delivered';cancelRequestState=$requested.state
        finalState=$final.state;completedAt=$final.completedAt;finalAuditAction=$last.action;finalAuditActor=$last.actor
        authenticatedEndpointCancellationChannel=$passed;timestamp=[DateTimeOffset]::UtcNow
    }
    $report|ConvertTo-Json -Depth 10|Set-Content artifacts/sprint16-cancellation-runtime.json
    $report|ConvertTo-Json -Depth 10
    if(!$passed){exit 1}
}
finally {
    & docker compose @compose start agent | Out-Null
}
