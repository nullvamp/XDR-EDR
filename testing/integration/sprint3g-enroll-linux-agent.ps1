param(
    [string]$Name = 'sprint3g-linux-agent'
)

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '../..'))

$settings = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object {
    $pair = $_.Split('=', 2)
    $settings[$pair[0]] = $pair[1]
}

$login = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{
    username = $settings.PLATFORM_BOOTSTRAP_USER
    password = $settings.PLATFORM_BOOTSTRAP_PASSWORD
} | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.access_token)" }
$token = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/enrollment-tokens -Headers $headers -ContentType application/json -Body (@{
    expiresAt = [DateTimeOffset]::UtcNow.AddHours(2).ToString('O')
    maximumUses = 1
    allowedPlatforms = @('linux')
    endpointGroupId = $null
    policyId = $null
} | ConvertTo-Json)

$certificates = (Resolve-Path deployment/certificates).Path
$volume = "$Name-data"
docker volume create $volume | Out-Null
if ((docker container ls -a --filter "name=^/$Name$" --format '{{.Names}}') -eq $Name) {
    throw "Container $Name already exists; choose a new name to preserve its state."
}

docker run -d --name $Name --restart unless-stopped --network deployment_platform `
    -v "${volume}:/data" `
    -v "${certificates}:/certificates:ro" `
    -v 'deployment_falco-output:/var/run/platform-falco:ro' `
    -e PLATFORM_CONTROL_PLANE_URL=https://gateway:8443 `
    -e PLATFORM_CA_CERT_PATH=/certificates/ca.crt `
    -e PLATFORM_AGENT_DATA=/data `
    -e PLATFORM_ENVIRONMENT=production `
    -e PLATFORM_PROCESS_COLLECTOR=falco `
    -e PLATFORM_FALCO_JSON_PATH=/var/run/platform-falco/process-events.jsonl `
    -e "PLATFORM_ENROLLMENT_TOKEN_ID=$($token.data.metadata.id)" `
    -e "PLATFORM_ENROLLMENT_TOKEN_SECRET=$($token.data.secret)" `
    deployment-agent:latest | Out-Null

$logs = ''
foreach ($attempt in 1..45) {
    Start-Sleep -Seconds 1
    $logs = docker logs $Name 2>&1 | Out-String
    if ($logs -match 'Authenticated heartbeat') { break }
}
if ($logs -notmatch 'Authenticated heartbeat') {
    throw "Fresh agent did not authenticate within 45 seconds.`n$logs"
}

[ordered]@{
    container = $Name
    volume = $volume
    enrolled = $true
    authenticatedHeartbeat = $true
    recordedAt = [DateTimeOffset]::UtcNow.ToString('O')
} | ConvertTo-Json
