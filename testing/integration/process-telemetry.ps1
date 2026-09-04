$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$gateway = if ($env:PLATFORM_TEST_URL) { $env:PLATFORM_TEST_URL } else { 'http://localhost:8080' }
$username = if ($env:PLATFORM_BOOTSTRAP_USER) { $env:PLATFORM_BOOTSTRAP_USER } else { 'admin' }
if (-not $env:PLATFORM_BOOTSTRAP_PASSWORD) { throw 'PLATFORM_BOOTSTRAP_PASSWORD is required.' }
$agentContainer = if (docker ps --format '{{.Names}}' | Select-String '^sprint1b-mtls-agent$') { 'sprint1b-mtls-agent' } else { (docker ps --format '{{.Names}}' | Select-String 'agent' | Select-Object -First 1).Line }
if (-not $agentContainer) { throw 'No running agent container was found.' }

docker exec -d $agentContainer sh -c 'sleep 30' | Out-Null
Start-Sleep -Seconds 12

$eventCount = [int](docker exec deployment-postgres-1 psql -U platform -d platform -Atc 'select count(*) from process_events')
$entityCount = [int](docker exec deployment-postgres-1 psql -U platform -d platform -Atc 'select count(*) from process_entities')
$outboxCount = [int](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.outbox where topic like 'process.%'")
Assert-True ($eventCount -gt 0) 'No authoritative process events were persisted.'
Assert-True ($entityCount -gt 0) 'No process entities were reconstructed.'
Assert-True ($outboxCount -ge $eventCount) 'Transactional process outbox records are incomplete.'

$loginBody = @{ username = $username; password = $env:PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json
$session = Invoke-RestMethod -Method Post -Uri "$gateway/api/v1/auth/token" -ContentType 'application/json' -Body $loginBody
$headers = @{ Authorization = "Bearer $($session.access_token)" }
$search = $null
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    try {
        $candidate = Invoke-RestMethod -Uri "$gateway/api/v1/processes?pageSize=20" -Headers $headers
        if ($candidate.data.items.Count -gt 0) { $search = $candidate; break }
    } catch {
        Write-Host "Process projection is not ready on attempt $($attempt + 1); retrying."
    }
    Start-Sleep -Seconds 1
}
Assert-True ($search.data.items.Count -gt 0) 'Tenant-scoped process search returned no documents.'
$process = $search.data.items[0]
$detail = Invoke-RestMethod -Uri "$gateway/api/v1/endpoints/$($process.endpointId)/processes/$($process.processEntityId)" -Headers $headers
$tree = Invoke-RestMethod -Uri "$gateway/api/v1/endpoints/$($process.endpointId)/processes/$($process.processEntityId)/tree?depth=4" -Headers $headers
$health = Invoke-RestMethod -Uri "$gateway/api/v1/endpoints/$($process.endpointId)/process-telemetry-health" -Headers $headers
Assert-True ($detail.data.processEntityId -eq $process.processEntityId) 'Process details identity mismatch.'
Assert-True ($tree.data.process.processEntityId -eq $process.processEntityId) 'Process tree root mismatch.'
Assert-True ($health.data.enabled) 'Process telemetry health reports disabled.'

$before = $eventCount
docker restart $agentContainer | Out-Null
Start-Sleep -Seconds 4
$after = [int](docker exec deployment-postgres-1 psql -U platform -d platform -Atc 'select count(*) from process_events')
Assert-True ($after -eq $before) 'Agent restart created duplicate authoritative events.'

Write-Host "PASS process telemetry: events=$eventCount entities=$entityCount outbox=$outboxCount search=$($search.data.items.Count)"
