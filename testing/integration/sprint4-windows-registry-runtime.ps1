param([string]$Output = 'artifacts/sprint4-windows-registry-runtime.json')

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator token is required for the Windows ETW registry runtime matrix.'
}

function Stop-StalePlatformEtwSessions {
    if (@(Get-Process Platform.Agent -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Refusing ETW cleanup while a Platform.Agent process is running.'
    }
    $active = (& logman query -ets 2>$null | Out-String)
    @(
        'OpenSecurityPlatform-RegistryLifecycle-v1',
        'OpenSecurityPlatform-ProcessLifecycle-v1',
        'OpenSecurityPlatform-FileLifecycle-v1'
    ) | Where-Object { $active.IndexOf($_, [StringComparison]::Ordinal) -ge 0 } | ForEach-Object {
        & logman stop $_ -ets | Out-Null
    }
}

Stop-StalePlatformEtwSessions

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root
$ready = $false
$readyDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
do {
    try { $ready = (Invoke-WebRequest http://localhost:8080/health/ready -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200 } catch { Start-Sleep 1 }
} while (-not $ready -and [DateTimeOffset]::UtcNow -lt $readyDeadline)
if (-not $ready) { throw 'Gateway readiness timed out.' }
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object {
    $part = $_.Split('=', 2)
    $cfg[$part[0]] = $part[1]
}
$session = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{
        username = $cfg.PLATFORM_BOOTSTRAP_USER
        password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD
    } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($session.access_token)" }
$before = @((Invoke-RestMethod 'http://localhost:8080/api/v1/endpoints?pageSize=500' -Headers $headers).data.items.id)
$token = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/enrollment-tokens -Headers $headers -ContentType application/json -Body (@{
        expiresAt = [DateTimeOffset]::UtcNow.AddHours(2).ToString('O')
        maximumUses = 1
        allowedPlatforms = @('windows')
        endpointGroupId = $null
        policyId = $null
    } | ConvertTo-Json)

$run = Join-Path $root "artifacts/sprint4-windows-$([DateTimeOffset]::UtcNow.ToString('yyyyMMddHHmmss'))"
New-Item -ItemType Directory -Force $run | Out-Null
$env:PLATFORM_AGENT_DATA = $run
$env:PLATFORM_ENVIRONMENT = 'production'
$env:PLATFORM_CONTROL_PLANE_URL = 'https://localhost:8443'
$env:PLATFORM_CA_CERT_PATH = (Resolve-Path deployment/certificates/ca.crt).Path
$env:PLATFORM_ENROLLMENT_TOKEN_ID = $token.data.metadata.id
$env:PLATFORM_ENROLLMENT_TOKEN_SECRET = $token.data.secret
$agentPath = Join-Path $root 'agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.exe'
$agent = Start-Process -FilePath $agentPath -RedirectStandardOutput (Join-Path $run 'agent.log') -RedirectStandardError (Join-Path $run 'agent.stderr.log') -PassThru -WindowStyle Hidden
$env:PLATFORM_ENROLLMENT_TOKEN_ID = ''
$env:PLATFORM_ENROLLMENT_TOKEN_SECRET = ''

try {
    $endpoint = $null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(75)
    do {
        Start-Sleep 1
        $items = @((Invoke-RestMethod 'http://localhost:8080/api/v1/endpoints?pageSize=500' -Headers $headers).data.items)
        $endpoint = $items | Where-Object { $_.id -notin $before } | Select-Object -First 1
    } while (-not $endpoint -and [DateTimeOffset]::UtcNow -lt $deadline)
    if (-not $endpoint) { throw 'Sprint 4 Windows endpoint enrollment timed out.' }

    $policyBody = @{
        name = "sprint4-registry-$([guid]::NewGuid().ToString('N'))"
        policy = @{
            enabled = $true
            keyCreateEnabled = $true
            keyDeleteEnabled = $true
            keyRenameEnabled = $true
            valueSetEnabled = $true
            valueDeleteEnabled = $true
            securityChangeEnabled = $false
            captureMode = 'metadataOnly'
            maximumCapturedBytes = 0
            contentHashingEnabled = $false
            includedHives = @()
            includedPaths = @('\Software\OpenSecurityPlatform\Sprint4')
            excludedPaths = @()
            excludedValueNames = @()
            allowedCapturePaths = @()
            redactionPatterns = @('secret', 'password', 'token')
            maximumQueueBytes = 134217728
            maximumQueueAgeHours = 24
            maximumBatchEvents = 200
            maximumBatchBytes = 1048576
            flushSeconds = 2
            collectorSource = 'windows.etw-registry'
            diagnosticMode = $false
            exclusionRules = @()
        }
    }
    $created = (Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/registry-telemetry/policies -Headers $headers -ContentType application/json -Body ($policyBody | ConvertTo-Json -Depth 12)).data
    Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/registry-telemetry/policies/$($created.id):assign" -Headers $headers -ContentType application/json -Body (@{ endpointId = $endpoint.id } | ConvertTo-Json) | Out-Null

    $processSource = @((Invoke-RestMethod http://localhost:8080/api/v1/process-telemetry/policies -Headers $headers).data) | Sort-Object version -Descending | Select-Object -First 1
    $processSource.policy.telemetryEnabled = $false
    $processSource.policy.collectorSource = 'windows.etw'
    $processDisabled = (Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/process-telemetry/policies -Headers $headers -ContentType application/json -Body (@{ name = "sprint4-registry-process-disabled-$([guid]::NewGuid().ToString('N'))"; policy = $processSource.policy } | ConvertTo-Json -Depth 12)).data
    Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/process-telemetry/policies/$($processDisabled.id):assign" -Headers $headers -ContentType application/json -Body (@{ endpointId = $endpoint.id } | ConvertTo-Json) | Out-Null
    $fileSource = @((Invoke-RestMethod http://localhost:8080/api/v1/file-telemetry/policies -Headers $headers).data) | Sort-Object version -Descending | Select-Object -First 1
    $fileSource.policy.enabled = $false
    $fileSource.policy.collectorSource = 'windows.etw-file'
    $fileSource.policy.includedPaths = @()
    $fileSource.policy.excludedPaths = @()
    $fileDisabled = (Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/file-telemetry/policies -Headers $headers -ContentType application/json -Body (@{ name = "sprint4-registry-file-disabled-$([guid]::NewGuid().ToString('N'))"; policy = $fileSource.policy } | ConvertTo-Json -Depth 12)).data
    Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/v1/file-telemetry/policies/$($fileDisabled.id):assign" -Headers $headers -ContentType application/json -Body (@{ endpointId = $endpoint.id } | ConvertTo-Json) | Out-Null

    Stop-Process -Id $agent.Id -Force
    $agent.WaitForExit()
    Stop-StalePlatformEtwSessions
    $agent = Start-Process -FilePath $agentPath -RedirectStandardOutput (Join-Path $run 'assigned.log') -RedirectStandardError (Join-Path $run 'assigned.stderr.log') -PassThru -WindowStyle Hidden
    $effective = $null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        Start-Sleep 1
        $effective = (Invoke-RestMethod -Uri "http://localhost:8080/api/v1/endpoints/$($endpoint.id)/registry-policy" -Headers $headers).data
    } while (($effective.policy.id -ne $created.id -or $effective.appliedVersion -ne $created.version) -and [DateTimeOffset]::UtcNow -lt $deadline)
    if ($effective.policy.id -ne $created.id -or $effective.appliedVersion -ne $created.version) {
        throw 'Registry policy was not applied and acknowledged.'
    }

    $base = 'HKCU:\Software\OpenSecurityPlatform\Sprint4'
    $testName = "runtime-$([guid]::NewGuid().ToString('N'))"
    $key = Join-Path $base $testName
    $nativeKey = "HKCU\Software\OpenSecurityPlatform\Sprint4\$testName"
    $manifest = @()
    function Record([string]$operation, [string]$path, [string]$valueName = '') {
        $script:manifest += [ordered]@{ operation = $operation; path = $path; valueName = $valueName; at = [DateTimeOffset]::UtcNow.ToString('O') }
        Start-Sleep -Milliseconds 1200
    }
    function Invoke-ControlledReg([string[]]$arguments) {
        & reg.exe @arguments 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Controlled reg.exe workload failed with exit code $LASTEXITCODE." }
    }
    Invoke-ControlledReg @('add', $nativeKey, '/f')
    Record 'key-create' $key
    Invoke-ControlledReg @('add', $nativeKey, '/v', 'TextValue', '/t', 'REG_SZ', '/d', 'first', '/f')
    Record 'value-set-string' $key 'TextValue'
    Invoke-ControlledReg @('add', $nativeKey, '/v', 'TextValue', '/t', 'REG_SZ', '/d', 'second', '/f')
    Record 'value-modify-string' $key 'TextValue'
    Invoke-ControlledReg @('add', $nativeKey, '/v', 'DwordValue', '/t', 'REG_DWORD', '/d', '42', '/f')
    Record 'value-set-dword' $key 'DwordValue'
    Invoke-ControlledReg @('add', $nativeKey, '/v', 'Password', '/t', 'REG_SZ', '/d', 'must-never-leave-endpoint', '/f')
    Record 'secret-like-value-set' $key 'Password'
    $relationship = Start-Process -FilePath (Join-Path $root 'tools/ProcessGenerator/bin/Release/net8.0/ProcessGenerator.exe') -ArgumentList @('--child', '--registry-path', "Software\OpenSecurityPlatform\Sprint4\$testName", '--registry-value', 'ProcessValue', '--lifetime-ms', '30000') -PassThru -WindowStyle Hidden
    Record 'process-related-value-set' $key 'ProcessValue'
    Invoke-ControlledReg @('delete', $nativeKey, '/v', 'DwordValue', '/f')
    Record 'value-delete' $key 'DwordValue'
    Invoke-ControlledReg @('delete', $nativeKey, '/f')
    Record 'key-delete' $key
    Invoke-ControlledReg @('add', $nativeKey, '/f')
    Record 'key-recreate' $key
    Invoke-ControlledReg @('add', $nativeKey, '/v', 'TextValue', '/t', 'REG_SZ', '/d', 'recreated', '/f')
    Record 'value-recreate' $key 'TextValue'
    Invoke-ControlledReg @('delete', $nativeKey, '/f')
    Record 'key-recreate-delete' $key

    Start-Sleep 15
    $from = [uri]::EscapeDataString(([DateTimeOffset]::UtcNow.AddMinutes(-10)).ToString('O'))
    $to = [uri]::EscapeDataString(([DateTimeOffset]::UtcNow.AddMinutes(1)).ToString('O'))
    $page = (Invoke-RestMethod -Uri "http://localhost:8080/api/v1/registry-events?endpointId=$($endpoint.id)&from=$from&to=$to&pageSize=500" -Headers $headers).data
    $events = @($page.items | Where-Object { $_.keyPath -like "*$testName*" })
    $pg = (docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*),count(distinct event_id),count(distinct sequence) from platform.registry_events where endpoint_id='$($endpoint.id)'").Trim().Split('|')
    $health = (Invoke-RestMethod -Uri "http://localhost:8080/api/v1/endpoints/$($endpoint.id)/registry-telemetry-health" -Headers $headers).data
    $secret = @($events | Where-Object { $_.valueName -eq 'Password' })
    $related = @($events | Where-Object { $_.valueName -eq 'ProcessValue' -and $_.process.processEntityId })
    $resolvedTextValues = @($events | Where-Object { $_.valueName -eq 'TextValue' -and $_.registryValueEntityId } | Select-Object -ExpandProperty registryValueEntityId -Unique)
    $resolvedTextKeys = @($events | Where-Object { $_.valueName -eq 'TextValue' -and $_.registryKeyEntityId } | Select-Object -ExpandProperty registryKeyEntityId -Unique)
    $kinds = @($events.kind | Sort-Object -Unique)
    $passed = $events.Count -ge 12 -and $related.Count -ge 1 -and $resolvedTextValues.Count -ge 2 -and $resolvedTextKeys.Count -ge 2 -and $kinds -contains 'KeyCreated' -and $kinds -contains 'KeyDeleted' -and $kinds -contains 'ValueSet' -and $kinds -contains 'ValueDeleted' -and [int]$pg[0] -eq [int]$pg[1] -and [int]$pg[0] -eq [int]$pg[2] -and $health.queueDepth -eq 0 -and $health.sourceLosses -eq 0 -and $health.droppedEvents -eq 0 -and @($secret | Where-Object { -not $_.value.redacted -or $_.value.preview }).Count -eq 0
    $report = [ordered]@{
        schema = 'platform.sprint4.windows-registry-runtime.v1'
        executedAt = [DateTimeOffset]::UtcNow.ToString('O')
        elevated = $true
        identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        run = $run
        endpointId = $endpoint.id
        policyId = $created.id
        manifest = $manifest
        nativeSource = 'Microsoft-Windows-Kernel-Registry ETW via KernelTraceEventParser'
        sourceLimitations = @('value create versus modify is indistinguishable', 'rename destination is not emitted by subscribed callbacks', 'security change is not emitted by subscribed callbacks', 'value bytes/type/length are enrichment rather than native payload')
        observedKinds = $kinds
        apiEvents = $events.Count
        postgresEvents = [int]$pg[0]
        distinctEventIds = [int]$pg[1]
        distinctSequences = [int]$pg[2]
        health = $health
        secretLikeEvents = $secret.Count
        processRelationshipEvents = $related.Count
        processEntityId = if ($related.Count -gt 0) { $related[0].process.processEntityId } else { $null }
        distinctTextValueEntities = $resolvedTextValues.Count
        distinctTextKeyEntities = $resolvedTextKeys.Count
        secretLikeRedactionPassed = @($secret | Where-Object { -not $_.value.redacted -or $_.value.preview }).Count -eq 0
        passed = $passed
    }
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Output
    $report | ConvertTo-Json -Depth 5
    if (-not $passed) { exit 1 }
}
finally {
    $env:PLATFORM_ENROLLMENT_TOKEN_ID = ''
    $env:PLATFORM_ENROLLMENT_TOKEN_SECRET = ''
    if ($agent -and -not $agent.HasExited) {
        Stop-Process -Id $agent.Id -Force
        $agent.WaitForExit()
    }
    if ($relationship -and -not $relationship.HasExited) {
        Stop-Process -Id $relationship.Id -Force
        $relationship.WaitForExit()
    }
    Stop-StalePlatformEtwSessions
}
