param([string]$Output = 'artifacts/sprint4-registry-capture-matrix.json')

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator token required.' }
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))
$runtime = Get-Content artifacts/sprint4-windows-registry-runtime.json -Raw | ConvertFrom-Json
$endpoint = $runtime.endpointId
$run = $runtime.run
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object { $p = $_.Split('=', 2); $cfg[$p[0]] = $p[1] }
$login = Invoke-RestMethod -Method Post http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{ username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.access_token)" }
$active = (& logman query -ets 2>$null | Out-String)
@('OpenSecurityPlatform-RegistryLifecycle-v1', 'OpenSecurityPlatform-ProcessLifecycle-v1', 'OpenSecurityPlatform-FileLifecycle-v1') | Where-Object { $active.IndexOf($_, [StringComparison]::Ordinal) -ge 0 } | ForEach-Object { & logman stop $_ -ets | Out-Null }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$testName = "capture-$([guid]::NewGuid().ToString('N'))"
$relative = "Software\OpenSecurityPlatform\Sprint4\$testName"
$native = "HKCU\$relative"
$allowed = "HKU\$sid\$relative"
$generator = (Resolve-Path tools/ProcessGenerator/bin/Release/net8.0/ProcessGenerator.exe).Path
$agentPath = (Resolve-Path agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.exe).Path
$env:PLATFORM_AGENT_DATA = $run
$env:PLATFORM_ENVIRONMENT = 'production'
$env:PLATFORM_CONTROL_PLANE_URL = 'https://localhost:8443'
$env:PLATFORM_CA_CERT_PATH = (Resolve-Path deployment/certificates/ca.crt).Path
$rows = [Collections.Generic.List[object]]::new()
$agent = $null
$child = $null

function Create-Policy([string]$mode, [int]$max, [string[]]$redactions = @(), [string[]]$types = @('String', 'Binary')) {
    $capture = $mode -notin @('None', 'MetadataOnly')
    [string[]]$capturePaths = if ($capture) { @($allowed) } else { @() }
    $body = @{
        name = "sprint4-capture-$($mode.ToLowerInvariant())-$([guid]::NewGuid().ToString('N'))"
        policy = @{
            enabled = $true; keyCreateEnabled = $true; keyDeleteEnabled = $true; valueSetEnabled = $true; valueDeleteEnabled = $true
            captureMode = $mode; maximumCapturedBytes = $max; contentHashingEnabled = $false
            includedHives = @('HKU'); includedPaths = @('\Software\OpenSecurityPlatform\Sprint4'); excludedPaths = @()
            includedValueTypes = $types; excludedValueTypes = @(); excludedValueNames = @()
            allowedCapturePaths = $capturePaths
            redactionPatterns = $redactions; maximumQueueBytes = 134217728; maximumQueueAgeHours = 24
            maximumBatchEvents = 200; maximumBatchBytes = 1048576; flushSeconds = 1
            collectorSource = 'windows.etw-registry'; diagnosticMode = $false; exclusionRules = @()
        }
    }
    (Invoke-RestMethod -Method Post http://localhost:8080/api/v1/registry-telemetry/policies -Headers $headers -ContentType application/json -Body ($body | ConvertTo-Json -Depth 12)).data
}
function Assign-Policy($policy) {
    Invoke-RestMethod -Method Post "http://localhost:8080/api/v1/registry-telemetry/policies/$($policy.id):assign" -Headers $headers -ContentType application/json -Body (@{ endpointId = $endpoint } | ConvertTo-Json) | Out-Null
}
function Wait-PolicyAcknowledgement($policy) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
    do { Start-Sleep -Milliseconds 500; $effective = (Invoke-RestMethod "http://localhost:8080/api/v1/endpoints/$endpoint/registry-policy" -Headers $headers).data } while (($effective.policy.id -ne $policy.id -or $effective.appliedVersion -ne $policy.version) -and [DateTimeOffset]::UtcNow -lt $deadline)
    if ($effective.policy.id -ne $policy.id -or $effective.appliedVersion -ne $policy.version) { throw "Policy $($policy.id) was not acknowledged." }
}
function Assign-And-Wait($policy) {
    Assign-Policy $policy
    Wait-PolicyAcknowledgement $policy
}
function Exercise([string]$name, [string]$mode, [int]$max, [string]$value, [string]$kind = 'string', [string[]]$redactions = @(), [scriptblock]$validate) {
    $policy = Create-Policy $mode $max $redactions
    Assign-And-Wait $policy
    $valueName = "$name-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    $started = [DateTimeOffset]::UtcNow
    $args = @('--child', '--registry-path', $relative, '--registry-value', $valueName, '--registry-kind', $kind)
    if (-not [string]::IsNullOrEmpty($value)) { $args += @('--registry-data', $value) }
    $args += @('--lifetime-ms', '12000')
    $script:child = Start-Process -FilePath $generator -ArgumentList $args -PassThru -WindowStyle Hidden
    Start-Sleep 5
    $from = [uri]::EscapeDataString($started.AddSeconds(-1).ToString('O'))
    $to = [uri]::EscapeDataString(([DateTimeOffset]::UtcNow.AddSeconds(2)).ToString('O'))
    $events = @((Invoke-RestMethod "http://localhost:8080/api/v1/registry-events?endpointId=$endpoint&from=$from&to=$to&valueName=$valueName&pageSize=100" -Headers $headers).data.items)
    $event = $events | Where-Object { $_.valueName -eq $valueName } | Select-Object -First 1
    $passed = $null -ne $event -and [bool](& $validate $event)
    $rows.Add([ordered]@{ profile = $name; mode = $mode; policyId = $policy.id; eventId = $event.eventId; value = $event.value; passed = $passed })
    if ($child -and -not $child.HasExited) { Stop-Process $child.Id -Force; $child.WaitForExit() }
    $script:child = $null
}

try {
    $metadata = Create-Policy 'MetadataOnly' 0
    Assign-Policy $metadata
    $effective = (Invoke-RestMethod "http://localhost:8080/api/v1/endpoints/$endpoint/registry-policy" -Headers $headers).data
    if ($effective.policy.id -ne $metadata.id) { throw "Policy $($metadata.id) was not effective before agent startup." }
    $agent = Start-Process -FilePath $agentPath -RedirectStandardOutput (Join-Path $run 'capture-matrix.log') -RedirectStandardError (Join-Path $run 'capture-matrix.stderr.log') -PassThru -WindowStyle Hidden
    Wait-PolicyAcknowledgement $metadata
    Exercise 'metadata-only' 'MetadataOnly' 0 'metadata-value' 'string' @() { param($e) $e.value.captureMode -eq 'MetadataOnly' -and -not $e.value.preview -and -not $e.value.sha256 }
    Exercise 'hash-only' 'ContentHash' 0 'hash-value' 'string' @() { param($e) $e.value.captureMode -eq 'ContentHash' -and $e.value.sha256 -match '^[0-9a-f]{64}$' -and $e.value.hashAlgorithm -eq 'SHA-256' -and -not $e.value.preview }
    Exercise 'bounded-preview' 'BoundedPreview' 8 'abcdefghijklmnopqrstuvwxyz' 'string' @() { param($e) $e.value.capturedLength -eq 8 -and $e.value.truncated -and $e.value.preview.Length -le 8 }
    Exercise 'redaction' 'BoundedPreview' 64 'prefix-mask-me-suffix' 'string' @('mask-me') { param($e) $e.value.redacted -and $e.value.preview -eq '[REDACTED]' }
    Exercise 'oversized' 'BoundedPreview' 16 ('x' * 4096) 'string' @() { param($e) $e.value.capturedLength -eq 16 -and $e.value.truncated -and $e.value.dataLength -gt 16 }
    Exercise 'binary' 'ContentHash' 0 '' 'binary' @() { param($e) $e.value.valueType -eq 'Binary' -and $e.value.dataLength -eq 512 -and $e.value.sha256 -match '^[0-9a-f]{64}$' }
    Exercise 'capture-disabled' 'None' 0 'disabled-value' 'string' @() { param($e) $e.value.captureMode -eq 'None' -and -not $e.value.preview -and -not $e.value.sha256 }
    $protected = Invoke-WebRequest -Method Post http://localhost:8080/api/v1/registry-telemetry/policies -Headers $headers -ContentType application/json -Body (@{ name = 'protected-rejected'; policy = @{ captureMode = 'BoundedPreview'; allowedCapturePaths = @('HKLM\SAM'); collectorSource = 'windows.etw-registry' } } | ConvertTo-Json -Depth 8) -UseBasicParsing -ErrorAction SilentlyContinue
} catch {
    if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 400 -and $rows.Count -eq 7) {
        $rows.Add([ordered]@{ profile = 'protected-path-rejected'; mode = 'BoundedPreview'; status = 400; passed = $true })
    } else { throw }
} finally {
    if ($child -and -not $child.HasExited) { Stop-Process $child.Id -Force; $child.WaitForExit() }
    if ($agent -and -not $agent.HasExited) { Stop-Process $agent.Id -Force; $agent.WaitForExit() }
    $active = (& logman query -ets 2>$null | Out-String)
    @('OpenSecurityPlatform-RegistryLifecycle-v1', 'OpenSecurityPlatform-ProcessLifecycle-v1', 'OpenSecurityPlatform-FileLifecycle-v1') | Where-Object { $active.IndexOf($_, [StringComparison]::Ordinal) -ge 0 } | ForEach-Object { & logman stop $_ -ets | Out-Null }
    Remove-Item -LiteralPath "HKCU:\$relative" -Recurse -Force -ErrorAction SilentlyContinue
}
$failed = @($rows | Where-Object { -not $_.passed })
$report = [ordered]@{ schema = 'platform.sprint4.registry-capture-matrix.v1'; executedAt = [DateTimeOffset]::UtcNow; endpointId = $endpoint; allowedPath = $allowed; rows = $rows; passed = $rows.Count -eq 8 -and $failed.Count -eq 0 }
$report | ConvertTo-Json -Depth 12 | Set-Content $Output
$report | ConvertTo-Json -Depth 7
if (-not $report.passed) { exit 1 }
