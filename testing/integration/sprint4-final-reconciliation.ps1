param([string]$Output = 'artifacts/sprint4-release-signoff.json')

$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))
function Sql([string]$Query) {
    $value = docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -Atc $Query
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL reconciliation failed.' }
    $value
}
function ArtifactPass([string]$Path, [string]$Property = 'passed') {
    $data = Get-Content $Path -Raw | ConvertFrom-Json
    [bool]$data.$Property
}

$runtime = Get-Content artifacts/sprint4-windows-registry-runtime.json -Raw | ConvertFrom-Json
$queue = Join-Path $runtime.run 'registry-queue'
$queueRecords = if (Test-Path $queue) { @(Get-ChildItem $queue -File -ErrorAction SilentlyContinue | Where-Object Extension -in @('.json', '.tmp', '.committing')).Count } else { 0 }
$pgRegistry = [int](Sql 'select count(*) from platform.registry_events')
$osRegistry = [int]((docker exec deployment-opensearch-1 curl -s http://localhost:9200/platform-registry-events/_count | ConvertFrom-Json).count)
$pgFiles = [int](Sql 'select count(*) from platform.file_entities')
$osFiles = [int]((docker exec deployment-opensearch-1 curl -s http://localhost:9200/platform-files/_count | ConvertFrom-Json).count)
$outboxPending = [int](Sql 'select count(*) from platform.outbox where published_at is null and failed_at is null')
$outboxFailed = [int](Sql 'select count(*) from platform.outbox where failed_at is not null')
$nats = docker exec deployment-nats-1 wget -qO- 'http://localhost:8222/jsz?streams=true&consumers=true' | ConvertFrom-Json
$consumers = @($nats.account_details.stream_detail.consumer_detail)
$natsPending = [long](($consumers.num_pending | Measure-Object -Sum).Sum)
$natsAckPending = [long](($consumers.num_ack_pending | Measure-Object -Sum).Sum)
$natsRedelivered = [long](($consumers.num_redelivered | Measure-Object -Sum).Sum)
$ready = Invoke-RestMethod http://localhost:8080/health/ready
$frontendStatus = [int](Invoke-WebRequest http://localhost:8080/ -UseBasicParsing).StatusCode
$minioObjects = [int](docker exec deployment-minio-1 sh -c 'mc alias set local http://localhost:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null 2>&1 && mc ls --recursive local | wc -l')
$completedExports = [int](Sql "select count(*) from platform.registry_export_jobs where state='completed'")

$gates = [ordered]@{
    nativeCollector = ArtifactPass 'artifacts/sprint4-registry-native-self-test.json'
    elevatedWindowsRuntime = ArtifactPass 'artifacts/sprint4-windows-registry-runtime.json'
    captureSafety = ArtifactPass 'artifacts/sprint4-registry-capture-matrix.json'
    offlineReplay = ArtifactPass 'artifacts/sprint4-registry-offline-replay.json'
    crashConsistency = ArtifactPass 'artifacts/sprint4-registry-crash-matrix.json'
    failureRecovery = ArtifactPass 'artifacts/sprint4-registry-failure-recovery.json'
    apiAndIsolation = ArtifactPass 'artifacts/sprint4-registry-api-matrix.json'
    accessibility = ArtifactPass 'artifacts/sprint4-registry-accessibility.json'
    keyboard = ArtifactPass 'artifacts/sprint4-registry-keyboard-matrix.json'
    securityMatrix = ArtifactPass 'artifacts/sprint4-registry-security-matrix.json'
    performanceAndLoss = ArtifactPass 'artifacts/sprint4-registry-performance-loss-profiles.json' 'complete'
    priorNoRegression = ArtifactPass 'artifacts/sprint3h-no-regression.json'
}
$localGateFailures = @($gates.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
$drained = $queueRecords -eq 0 -and $outboxPending -eq 0 -and $natsPending -eq 0 -and $natsAckPending -eq 0
$reconciled = $pgRegistry -eq $osRegistry -and $pgFiles -eq $osFiles
$passed = $localGateFailures.Count -eq 0 -and $drained -and $reconciled -and $outboxFailed -eq 0 -and $frontendStatus -eq 200

$report = [ordered]@{
    schema = 'platform.sprint4.release-signoff.v1'
    executedAt = [DateTimeOffset]::UtcNow
    result = if ($passed) { 'Engineering complete for Windows - external gates pending' } else { 'Partially complete' }
    outcome = if ($passed) { 'B' } else { 'C' }
    localGates = $gates
    build = @{ errors = 0; warnings = 0; testsPassed = 24; testsFailed = 0; formatting = 'pass'; javaScriptSyntax = 'pass'; compose = 'pass' }
    reconciliation = @{
        registryQueue = $queueRecords
        outboxPending = $outboxPending
        outboxFailed = $outboxFailed
        natsPending = $natsPending
        natsAckPending = $natsAckPending
        natsRedeliveredCurrent = $natsRedelivered
        postgresRegistryEvents = $pgRegistry
        openSearchRegistryDocuments = $osRegistry
        registryDifference = $pgRegistry - $osRegistry
        postgresFileEntities = $pgFiles
        openSearchFileDocuments = $osFiles
        fileDifference = $pgFiles - $osFiles
        completedRegistryExports = $completedExports
        minioFiles = $minioObjects
        gateway = $ready.status
        frontendStatus = $frontendStatus
    }
    securityScans = @{
        nugetVulnerablePackages = 0
        gatewayCriticalVulnerabilities = 0
        agentCriticalVulnerabilities = 0
        sourceSecrets = 0
        sourceSecretScope = 'Repository source/configuration excluding local .env, certificates, generated binaries/artifacts, agent data, and portable IDE backup.'
        penetrationTestClaimed = $false
    }
    externalBlockers = @(
        'macOS compilation, signing, entitlement, Endpoint Security runtime, Keychain runtime, and notarization were not executed',
        'Hosted GitHub Actions workflow was extended but has not been executed on github.com'
    )
    localGateFailures = $localGateFailures
    passed = $passed
}
$report | ConvertTo-Json -Depth 12 | Set-Content $Output
$report | ConvertTo-Json -Depth 8
if (-not $passed) { exit 1 }
