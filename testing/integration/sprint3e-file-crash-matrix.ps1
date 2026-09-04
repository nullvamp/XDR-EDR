param(
    [string]$Output = "artifacts/sprint3e-file-crash-matrix.json"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $root
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
$beforeEndpoints = @((Invoke-RestMethod -Uri http://localhost:8080/api/v1/endpoints?pageSize=100 -Headers $headers).data.items.id)
$token = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/enrollment-tokens -Headers $headers -ContentType application/json -Body (@{
    expiresAt = [DateTimeOffset]::UtcNow.AddHours(2).ToString('o')
    maximumUses = 1
    allowedPlatforms = @('linux')
    endpointGroupId = $null
    policyId = $null
} | ConvertTo-Json)

$volume = "sprint3e-file-crash-$([guid]::NewGuid().ToString('N'))"
docker volume create $volume | Out-Null
$certificates = (Resolve-Path deployment/certificates).Path

function Remove-TestContainer([string]$name) {
    $exists = docker ps -a --filter "name=^/${name}$" --format '{{.Names}}'
    if ($exists -eq $name) { docker rm -f $name | Out-Null }
}

function Start-TestAgent([string]$name, [string]$eventPath, [string]$failpoint = "") {
    Remove-TestContainer $name
    $arguments = @(
        'run', '-d', '--name', $name,
        '--network', 'deployment_platform',
        '-v', "${volume}:/data",
        '-v', "${certificates}:/certificates:ro",
        '-e', 'PLATFORM_AGENT_DATA=/data',
        '-e', 'PLATFORM_ENVIRONMENT=evaluation',
        '-e', 'PLATFORM_CONTROL_PLANE_URL=https://gateway:8443',
        '-e', 'PLATFORM_CA_CERT_PATH=/certificates/ca.crt',
        '-e', 'PLATFORM_PROCESS_COLLECTOR=procfs',
        '-e', "PLATFORM_LOCAL_TEST_FILE_EVENT_PATH=$eventPath",
        '-e', 'PLATFORM_LOCAL_TEST_FAILPOINT_MARKER=/data/failpoint.marker'
    )
    if ($failpoint) { $arguments += @('-e', "PLATFORM_LOCAL_TEST_FAILPOINT=$failpoint") }
    $arguments += 'deployment-agent:sprint3e'
    & docker @arguments | Out-Null
}

function Volume-Sh([string]$command) {
    $arguments = @('run', '--rm', '--user', '100:101', '-v', "${volume}:/data", 'alpine:3.20', 'sh', '-c', $command)
    & docker @arguments
}

function Wait-VolumeFile([string]$path, [int]$seconds = 45) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($seconds)
    do {
        & docker run --rm -v "${volume}:/data" alpine:3.20 test -f "/data/$path" 2>$null
        if ($LASTEXITCODE -eq 0) { return $true }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $false
}

function Queue-State {
    Volume-Sh 'mkdir -p /data/file-queue/quarantine' | Out-Null
    $temporary = Volume-Sh 'find /data/file-queue -maxdepth 1 -type f -name *.tmp | wc -l'
    $committing = Volume-Sh 'find /data/file-queue -maxdepth 1 -type f -name *.committing | wc -l'
    $final = Volume-Sh 'find /data/file-queue -maxdepth 1 -type f -name *.json | wc -l'
    $quarantine = Volume-Sh 'find /data/file-queue/quarantine -type f -name *.bad | wc -l'
    return [ordered]@{ temporary = [int]$temporary; committing = [int]$committing; final = [int]$final; quarantine = [int]$quarantine }
}

function Wait-Drain([int]$seconds = 60) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($seconds)
    do {
        if ((Queue-State).final -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $false
}

# Enroll one dedicated agent identity, then preserve its volume and advance it across every case.
$enrollName = 'sprint3e-file-crash-enroll'
Remove-TestContainer $enrollName
docker run -d --name $enrollName --network deployment_platform -v "${volume}:/data" -v "${certificates}:/certificates:ro" `
    -e PLATFORM_AGENT_DATA=/data -e PLATFORM_ENVIRONMENT=evaluation -e PLATFORM_CONTROL_PLANE_URL=https://gateway:8443 `
    -e PLATFORM_CA_CERT_PATH=/certificates/ca.crt -e PLATFORM_PROCESS_COLLECTOR=procfs `
    -e PLATFORM_LOCAL_TEST_FILE_EVENT_PATH=/data/enrollment-probe.txt `
    -e "PLATFORM_ENROLLMENT_TOKEN_ID=$($token.data.metadata.id)" -e "PLATFORM_ENROLLMENT_TOKEN_SECRET=$($token.data.secret)" `
    deployment-agent:sprint3e | Out-Null

$endpoint = $null
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
do {
    Start-Sleep -Seconds 1
    $items = @((Invoke-RestMethod -Uri http://localhost:8080/api/v1/endpoints?pageSize=100 -Headers $headers).data.items)
    $endpoint = $items | Where-Object { $_.id -notin $beforeEndpoints } | Select-Object -First 1
} while (-not $endpoint -and [DateTimeOffset]::UtcNow -lt $deadline)
if (-not $endpoint) { throw 'Dedicated crash-matrix agent did not enroll.' }
docker stop $enrollName | Out-Null
Remove-TestContainer $enrollName

$policies = @((Invoke-RestMethod -Uri http://localhost:8080/api/v1/file-telemetry/policies -Headers $headers).data)
$policy = $policies | Where-Object { $_.policy.enabled -and $_.policy.collectorSource -eq 'linux.falco-json' } | Sort-Object version -Descending | Select-Object -First 1
if (-not $policy) { throw 'No enabled linux.falco-json file policy exists.' }
$policy.policy.includedPaths = @('/data')
$policy.policy.excludedPaths = @()
$createdPolicy = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/file-telemetry/policies -Headers $headers -ContentType application/json -Body (@{
    name = "sprint3e-crash-$([guid]::NewGuid().ToString('N'))"
    policy = $policy.policy
} | ConvertTo-Json -Depth 12)
$policy = $createdPolicy.data
Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/file-telemetry/policies/$($policy.id):assign" -Headers $headers -ContentType application/json -Body (@{ endpointId = $endpoint.id } | ConvertTo-Json) | Out-Null
Volume-Sh 'rm -f /data/local-test-file-emitted /data/failpoint.marker; mkdir -p /data/file-queue/quarantine; printf seed > /data/enrollment-probe.txt' | Out-Null

$points = @(
    'file-queue-before-temp-write',
    'file-queue-during-temp-write',
    'file-queue-after-write-before-flush',
    'file-queue-after-flush-before-rename',
    'file-queue-rename-boundary',
    'file-queue-after-rename-before-state',
    'file-queue-before-index-update',
    'file-queue-after-index-update',
    'file-queue-before-quarantine-move',
    'file-queue-during-quarantine-move',
    'file-batch-after-selection',
    'file-batch-after-canonical',
    'file-batch-during-compression',
    'file-batch-after-compression',
    'file-batch-after-integrity',
    'file-batch-before-transport',
    'file-batch-after-commit-before-ack',
    'file-batch-during-ack-cleanup'
)
$results = @()
foreach ($point in $points) {
    $safe = $point -replace '[^a-z0-9-]', '-'
    $eventPath = "/data/$safe.txt"
    Volume-Sh "rm -f /data/local-test-file-emitted /data/failpoint.marker; printf '$safe' > '$eventPath'" | Out-Null
    if ($point -like '*quarantine*') {
        Volume-Sh "printf '{broken' > /data/file-queue/$safe.json.tmp" | Out-Null
    }
    $before = Queue-State
    $caseName = "s3e-$safe"
    Start-TestAgent $caseName $eventPath $point
    $hit = Wait-VolumeFile 'failpoint.marker' 45
    $exitCode = $null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
    do {
        $running = docker inspect $caseName --format '{{.State.Running}}' 2>$null
        if ($running -eq 'false') { $exitCode = [int](docker inspect $caseName --format '{{.State.ExitCode}}'); break }
        Start-Sleep -Milliseconds 200
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($running -ne 'false') { docker stop -t 1 $caseName | Out-Null }
    $afterCrash = Queue-State
    Remove-TestContainer $caseName
    Volume-Sh 'rm -f /data/failpoint.marker' | Out-Null
    $recoveryName = "$caseName-recovery"
    Start-TestAgent $recoveryName $eventPath
    $drained = Wait-Drain 75
    $emitted = Wait-VolumeFile 'local-test-file-emitted' 20
    docker stop -t 2 $recoveryName | Out-Null
    Remove-TestContainer $recoveryName
    $afterRecovery = Queue-State
    $results += [ordered]@{
        category = if ($point -like 'file-batch*') { 'batch' } else { 'queue' }
        failpoint = $point
        hit = $hit
        crashExitCode = $exitCode
        before = $before
        afterCrash = $afterCrash
        afterRecovery = $afterRecovery
        replayed = $emitted
        drained = $drained
        passed = $hit -and $drained -and $emitted -and $afterRecovery.temporary -eq 0 -and $afterRecovery.committing -eq 0 -and $afterRecovery.final -eq 0
    }
}

$db = docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*),count(distinct event_id),count(distinct sequence) from platform.file_events where endpoint_id='$($endpoint.id)'"
$projection = docker exec deployment-opensearch-1 curl -fs "http://localhost:9200/platform-files/_count?q=endpoint_id%3A%22$($endpoint.id)%22" | ConvertFrom-Json
$counts = $db.Trim().Split('|')
$report = [ordered]@{
    schema = 'platform.sprint3e.file-crash-matrix.v1'
    executedAt = [DateTimeOffset]::UtcNow.ToString('O')
    productionFailpointsDisabled = $true
    endpointId = $endpoint.id
    volume = $volume
    results = $results
    authority = @{ rows = [int]$counts[0]; distinctEventIds = [int]$counts[1]; distinctSequences = [int]$counts[2] }
    projectionDocuments = [int]$projection.count
    passed = @($results | Where-Object { -not $_.passed }).Count -eq 0 -and $counts[0] -eq $counts[1] -and $counts[0] -eq $counts[2] -and [int]$projection.count -eq [int]$counts[0]
}
$target = if ([IO.Path]::IsPathRooted($Output)) { $Output } else { Join-Path $root $Output }
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $target
$report | ConvertTo-Json -Depth 6
if (-not $report.passed) { exit 1 }
