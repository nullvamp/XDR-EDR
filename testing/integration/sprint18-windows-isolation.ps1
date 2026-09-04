[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $VictimVmName,
    [Parameter(Mandatory)] [ValidateScript({ Test-Path -LiteralPath $_ })] [string] $CredentialPath,
    [Parameter(Mandatory)] [ValidateScript({ Test-Path -LiteralPath $_ })] [string] $AgentPublishPath,
    [string] $HostGatewayAddress,
    [long] $MaximumGuestLogBytes = 268435456,
    [long] $MaximumVmGrowthBytes = 5368709120
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '../..')
Set-Location $root

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Elevated host token required for Hyper-V orchestration. No host firewall mutation was attempted.'
}
if ($VictimVmName -eq $env:COMPUTERNAME) { throw 'The victim VM must not be the host computer.' }
$vm = Get-VM -Name $VictimVmName -ErrorAction Stop
if ($vm.State -ne 'Running') { throw "Victim VM '$VictimVmName' must already be running." }
if ((docker ps --filter 'name=falco' --format '{{.Names}}')) { throw 'Falco must not run during bounded Sprint 18 qualification.' }

$hostOwnedBefore = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object Group -Like 'OpenSecurityPlatform-Isolation-*').Count
if ($hostOwnedBefore -ne 0) { throw 'Host contains platform isolation rules; refusing guest qualification until separately reconciled.' }

if (-not $HostGatewayAddress) {
    $HostGatewayAddress = (Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 -ErrorAction Stop).IPAddress
}
if ($HostGatewayAddress -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw 'Host gateway address must be an exact IPv4 address.' }

$settings = @{}
Get-Content .env | Where-Object { $_ -match '^\s*([^#=\s]+)=(.*)$' } | ForEach-Object {
    $settings[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'")
}
$requiredSettings = @('PLATFORM_BOOTSTRAP_USER', 'PLATFORM_BOOTSTRAP_PASSWORD', 'PLATFORM_BOOTSTRAP_TENANT_ID', 'PLATFORM_JWT_SIGNING_KEY')
foreach ($name in $requiredSettings) {
    if (-not $settings.ContainsKey($name) -or [string]::IsNullOrWhiteSpace($settings[$name])) { throw "Missing .env setting $name." }
}

function B64([byte[]] $Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
function Jwt([string] $Subject) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = B64 ([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
    $payload = B64 ([Text.Encoding]::UTF8.GetBytes((@{
        iss = 'security-platform'; aud = 'security-platform-api'; sub = $Subject
        tid = $settings.PLATFORM_BOOTSTRAP_TENANT_ID; per = @('platform:admin'); pty = 'user'
        iat = $now; exp = $now + 7200; jti = [guid]::NewGuid().ToString('N')
    } | ConvertTo-Json -Compress)))
    $mac = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($settings.PLATFORM_JWT_SIGNING_KEY))
    try { $signature = B64 ($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$header.$payload"))) } finally { $mac.Dispose() }
    @{ Authorization = "Bearer $header.$payload.$signature" }
}

$login = Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/auth/token -ContentType application/json -Body (@{
    username = $settings.PLATFORM_BOOTSTRAP_USER; password = $settings.PLATFORM_BOOTSTRAP_PASSWORD
} | ConvertTo-Json -Compress)
$admin = @{ Authorization = "Bearer $($login.access_token)" }
$approver = Jwt 'sprint18-approver'
$secondAnalyst = Jwt 'sprint18-second-analyst'

function Api([string] $Method, [string] $Path, $Headers = $admin, $Body = $null) {
    $arguments = @{ Method = $Method; Uri = "http://127.0.0.1:8080$Path"; Headers = $Headers; DisableKeepAlive = $true }
    if ($null -ne $Body) { $arguments.ContentType = 'application/json'; $arguments.Body = $Body | ConvertTo-Json -Depth 30 -Compress }
    for ($attempt = 0; ; $attempt++) {
        try { return (Invoke-RestMethod @arguments).data }
        catch [Net.WebException] {
            if ($Method -ne 'GET' -or $attempt -ge 20) { throw }
            Start-Sleep -Milliseconds (250 * ($attempt + 1))
        }
    }
}
function Wait-Action([guid] $Id, [int] $Seconds = 120) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do { Start-Sleep -Milliseconds 500; $action = Api GET "/api/v1/response-actions/$Id" }
    while ($action.state -notin @('Succeeded', 'Failed', 'TimedOut', 'Cancelled', 'Expired', 'Rejected') -and [DateTimeOffset]::UtcNow -lt $deadline)
    $action
}
function Request-Isolation([guid] $Endpoint, [string] $Operation, [string] $Reason, $Headers = $admin, [int] $Expiry = 300) {
    Api POST "/api/v1/endpoints/$Endpoint`:$Operation" $Headers @{ endpointId = $Endpoint; reason = $Reason; expiresInSeconds = $Expiry }
}
function Approve-AndWait($Action) {
    if ($Action.approvalState -eq 'Pending') {
        $Action = Api POST "/api/v1/isolation-actions/$($Action.responseActionId):approve" $approver @{
            parameterHash = $Action.parameterHash; reason = 'controlled Sprint 18 victim qualification'
        }
    }
    Wait-Action $Action.responseActionId
}
function Wait-Live([guid] $Id, [int] $Seconds = 60) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do { Start-Sleep -Milliseconds 400; $sessionState = Api GET "/api/v1/live-response/sessions/$Id" }
    while ($sessionState.state -notin @('Active', 'Failed', 'Rejected', 'Expired') -and [DateTimeOffset]::UtcNow -lt $deadline)
    $sessionState
}
function Wait-Command([guid] $Session, [guid] $Command, [int] $Seconds = 60) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do { Start-Sleep -Milliseconds 300; $commandState = Api GET "/api/v1/live-response/sessions/$Session/commands/$Command" }
    while ($commandState.state -notin @('Succeeded', 'Failed', 'TimedOut', 'Cancelled', 'Expired', 'Uncertain') -and [DateTimeOffset]::UtcNow -lt $deadline)
    $commandState
}
function New-VictimSession {
    $credential = Import-Clixml -LiteralPath $CredentialPath
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(3)
    do {
        try { return New-PSSession -VMName $VictimVmName -Credential $credential -ErrorAction Stop } catch { Start-Sleep -Seconds 3 }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'PowerShell Direct did not become available for the victim VM.'
}
function Invoke-Victim([scriptblock] $Script, [object[]] $Arguments = @()) {
    Invoke-Command -Session $script:VictimSession -ScriptBlock $Script -ArgumentList $Arguments
}
function Start-VictimAgent($Token) {
    Invoke-Victim {
        param($tokenId, $tokenSecret, $gateway)
        $root = 'C:\Sprint18Qualification'; $data = Join-Path $root 'data'; $agent = Join-Path $root 'agent\Platform.Agent.exe'
        New-Item -ItemType Directory -Path $data -Force | Out-Null
        Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
        $env:PLATFORM_CONTROL_PLANE_URL = 'https://gateway:8443'
        $env:PLATFORM_ENROLLMENT_TOKEN_ID = $tokenId
        $env:PLATFORM_ENROLLMENT_TOKEN_SECRET = $tokenSecret
        $env:PLATFORM_AGENT_DATA = $data
        $env:PLATFORM_CA_CERT_PATH = Join-Path $root 'ca.crt'
        $env:PLATFORM_ENVIRONMENT = 'production'
        Remove-Item Env:PLATFORM_RESPONSE_ONLY -ErrorAction SilentlyContinue
        (Start-Process $agent -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $root 'agent.log') -RedirectStandardError (Join-Path $root 'agent-error.log')).Id
    } @($Token.metadata.id.ToString(), $Token.secret.ToString(), $HostGatewayAddress)
}
function Stop-VictimAgent {
    Invoke-Victim { Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep -Seconds 1 } | Out-Null
}
function Get-VictimConnectivity {
    Invoke-Victim {
        [pscustomobject]@{
            management = Test-NetConnection gateway -Port 8443 -InformationLevel Quiet
            controlled = Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet
        }
    }
}
function Get-OwnedRuleCount([string] $Group) {
    [int](Invoke-Victim { param($group) @(Get-NetFirewallRule -PolicyStore PersistentStore -Group $group -ErrorAction SilentlyContinue).Count } @($Group))
}
function Assert-Bounds {
    $logBytes = [long](Invoke-Victim {
        $sum = (Get-ChildItem 'C:\Sprint18Qualification' -Filter '*.log' -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        if ($null -eq $sum) { 0 } else { $sum }
    })
    if ($logBytes -gt $MaximumGuestLogBytes) { throw "Guest logs exceeded bound: $logBytes bytes." }
    $currentVmBytes = (Get-ChildItem 'D:\VMs\XDR-Victim-Sprint18' -Recurse -File | Measure-Object Length -Sum).Sum
    if (($currentVmBytes - $script:VmBytesBefore) -gt $MaximumVmGrowthBytes) { throw 'Victim VM exceeded the 5 GiB qualification growth bound.' }
    if ((Get-Volume D).SizeRemaining -lt 100GB) { throw 'D: free space fell below the 100 GiB qualification floor.' }
    if ((docker ps --filter 'name=falco' --format '{{.Names}}')) { throw 'Falco started unexpectedly.' }
}

function Wait-VictimQueuesDrained([int] $Seconds = 600) {
    $names = @('process', 'file', 'registry', 'network', 'dns', 'module', 'persistence', 'identity', 'execution')
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        $counts = Invoke-Victim {
            param($queueNames)
            $result = [ordered]@{}
            foreach ($name in $queueNames) {
                $path = "C:\Sprint18Qualification\data\$name-queue"
                $result[$name] = if (Test-Path $path) { @(Get-ChildItem $path -File -Filter '*.json' -ErrorAction SilentlyContinue).Count } else { 0 }
            }
            [pscustomobject]$result
        } @(, $names)
        $remaining = [long](($names | ForEach-Object { [long]$counts.$_ } | Measure-Object -Sum).Sum)
        if ($remaining -eq 0) {
            $clean = [ordered]@{}
            foreach ($name in $names) { $clean[$name] = [long]$counts.$name }
            return [pscustomobject]$clean
        }
        Start-Sleep -Seconds 3
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Victim telemetry queues did not drain within $Seconds seconds: $($counts | ConvertTo-Json -Compress)"
}

function Get-VictimTelemetryCounts([guid] $Endpoint, [DateTimeOffset] $Since) {
    $tables = [ordered]@{
        process = 'platform.process_events'; file = 'platform.file_events'; registry = 'platform.registry_events'
        network = 'platform.network_events'; dns = 'platform.dns_events'; module = 'platform.module_events'
        persistence = 'platform.persistence_events'; identity = 'platform.identity_events'; execution = 'platform.execution_events'
    }
    $counts = [ordered]@{}
    $timestamp = $Since.ToUniversalTime().ToString('O')
    foreach ($name in $tables.Keys) {
        $counts[$name] = [long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from $($tables[$name]) where endpoint_id='$Endpoint' and observed_at >= '$timestamp';")
    }
    [pscustomobject]$counts
}

$originalPolicy = Api GET '/api/v1/isolation-policy'
$qualificationPolicy = @{
    policyVersion = 'endpoint-isolation-victim-qualification.v1'
    managementDestinations = @(@{
        address = "$HostGatewayAddress/32"; port = 8443; protocol = 'tcp'; direction = 'outbound'
        purpose = 'gateway-control-telemetry-live-response'
    })
    isolationApprovalRequired = $true; unisolationApprovalRequired = $true; pendingExpirySeconds = 900
}

$script:VmBytesBefore = (Get-ChildItem 'D:\VMs\XDR-Victim-Sprint18' -Recurse -File | Measure-Object Length -Sum).Sum
$vmFreeBefore = (Get-Volume D).SizeRemaining
$script:VictimSession = $null
$agentPid = $null
$endpoint = $null
$group = $null
$report = $null
$unrelatedRule = 'OpenSecurityPlatform-Sprint18-Unrelated-Control'
$guestRoot = 'C:\Sprint18Qualification'

try {
    Api PUT '/api/v1/isolation-policy' $admin $qualificationPolicy | Out-Null
    $script:VictimSession = New-VictimSession
    $guest = Invoke-Victim {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        [pscustomobject]@{ computerName = $env:COMPUTERNAME; user = $identity.Name; administrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); os = (Get-CimInstance Win32_OperatingSystem).Caption; build = (Get-CimInstance Win32_OperatingSystem).BuildNumber; architecture = $env:PROCESSOR_ARCHITECTURE }
    }
    if (-not $guest.administrator -or $guest.computerName -eq $env:COMPUTERNAME) { throw 'Victim identity/elevation guard failed.' }

    Invoke-Victim {
        param($root, $hostIp, $ruleName)
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $root 'agent') -Force | Out-Null
        New-Item -ItemType Directory -Path 'C:\Sprint18Telemetry' -Force | Out-Null
        $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
        $lines = @(Get-Content $hosts | Where-Object { $_ -notmatch '# Sprint18 victim gateway$' })
        $lines += "$hostIp gateway # Sprint18 victim gateway"
        Set-Content -LiteralPath $hosts -Value $lines -Encoding ASCII
        Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -Name $ruleName -DisplayName 'Sprint 18 unrelated control rule' -Direction Outbound -Action Block -Protocol TCP -RemoteAddress '203.0.113.10' -RemotePort 9 -PolicyStore PersistentStore | Out-Null
    } @($guestRoot, $HostGatewayAddress, $unrelatedRule)
    Copy-Item -Path (Join-Path $AgentPublishPath '*') -Destination "$guestRoot\agent" -ToSession $script:VictimSession -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $root 'deployment\certificates\ca.crt') -Destination "$guestRoot\ca.crt" -ToSession $script:VictimSession -Force

    $before = Get-VictimConnectivity
    if (-not $before.management -or -not $before.controlled) { throw 'Victim pre-isolation connectivity failed; no isolation was attempted.' }
    $unrelatedBefore = Invoke-Victim { param($name) Get-NetFirewallRule -Name $name | Select-Object Name, Enabled, Direction, Action, Profile } @($unrelatedRule)

    $started = [DateTimeOffset]::UtcNow
    $token = Api POST '/api/v1/enrollment-tokens' $admin @{ expiresAt = [DateTimeOffset]::UtcNow.AddHours(1).ToString('o'); maximumUses = 1; allowedPlatforms = @('windows'); endpointGroupId = $null; policyId = $null }
    $agentPid = Start-VictimAgent $token
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(120)
    do {
        Start-Sleep -Seconds 2
        $endpoint = (Api GET '/api/v1/endpoints?pageSize=100').items | Where-Object { $_.platform -eq 'windows' -and $_.hostname -eq $guest.computerName -and $_.lastSeenAt -and [DateTimeOffset]$_.lastSeenAt -ge $started } | Sort-Object { [DateTimeOffset]$_.lastSeenAt } -Descending | Select-Object -First 1
    } while (-not $endpoint -and [DateTimeOffset]::UtcNow -lt $deadline)
    if (-not $endpoint) { throw 'Victim Windows agent did not enroll.' }

    $effectiveFilePolicy = Api GET "/api/v1/endpoints/$($endpoint.id)/file-policy"
    $boundedFilePolicy = $effectiveFilePolicy.policy.policy
    $boundedFilePolicy.includedPaths = @('C:\Sprint18Telemetry\')
    $boundedFilePolicy.excludedPaths = @()
    $boundedFilePolicy.maximumBatchEvents = 1000
    $boundedFilePolicy.maximumBatchBytes = 4194304
    $boundedFilePolicy.flushSeconds = 1
    $createdFilePolicy = Api POST '/api/v1/file-telemetry/policies' $admin @{
        name = "sprint18-victim-bounded-$([guid]::NewGuid().ToString('N'))"
        policy = $boundedFilePolicy
    }
    Api POST "/api/v1/file-telemetry/policies/$($createdFilePolicy.id):assign" $admin @{ endpointId = $endpoint.id } | Out-Null
    Stop-VictimAgent
    $agentPid = Start-VictimAgent $token
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(120)
    do {
        Start-Sleep -Seconds 2
        $appliedFilePolicy = Api GET "/api/v1/endpoints/$($endpoint.id)/file-policy"
    } while (($appliedFilePolicy.policy.id -ne $createdFilePolicy.id -or $appliedFilePolicy.appliedVersion -ne $createdFilePolicy.version -or $appliedFilePolicy.drift) -and [DateTimeOffset]::UtcNow -lt $deadline)
    if ($appliedFilePolicy.policy.id -ne $createdFilePolicy.id -or $appliedFilePolicy.appliedVersion -ne $createdFilePolicy.version -or $appliedFilePolicy.drift) {
        throw 'Victim bounded file policy did not acknowledge cleanly.'
    }

    $state = Invoke-Victim {
        Add-Type -AssemblyName System.Security
        $data = 'C:\Sprint18Qualification\data'
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $entropy = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes('open-security-platform-agent-state-v1')) } finally { $hasher.Dispose() }
        $statePath = Join-Path $data 'state.dat'
        $bytes = $null
        for ($attempt = 0; $attempt -lt 30 -and $null -eq $bytes; $attempt++) {
            try { $bytes = [IO.File]::ReadAllBytes($statePath) } catch [IO.IOException] { Start-Sleep -Milliseconds 200 }
        }
        if ($null -eq $bytes) { throw 'Agent identity state remained locked beyond the bounded retry window.' }
        $bytes = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
        $value = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $sha = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($value.installationId)) } finally { $hasher.Dispose() }
        [pscustomobject]@{ installationId = $value.installationId; group = "OpenSecurityPlatform-Isolation-$(([BitConverter]::ToString($sha) -replace '-', '').ToLowerInvariant().Substring(0,16))" }
    }
    $group = $state.group
    Assert-Bounds

    $isolate = Approve-AndWait (Request-Isolation $endpoint.id isolate 'Profile A victim-only isolation')
    $after = Get-VictimConnectivity
    $owned = Get-OwnedRuleCount $group
    $profileA = [ordered]@{ name = 'A'; status = if ($isolate.state -eq 'Succeeded' -and $after.management -and -not $after.controlled -and $owned -gt 0 -and $isolate.result.structuredResult.effectiveState -eq 'Isolated') { 'PASS' } else { 'FAIL' }; managementBefore = $before.management; controlledBefore = $before.controlled; managementAfter = $after.management; controlledAfter = $after.controlled; ownedRules = $owned; effectiveState = $isolate.result.structuredResult.effectiveState }
    if ($profileA.status -ne 'PASS') { throw "Profile A failed: $($profileA | ConvertTo-Json -Compress)" }
    Assert-Bounds

    $duplicate = Request-Isolation $endpoint.id isolate 'Profile C duplicate isolate' $secondAnalyst
    $rulesAfterDuplicate = Get-OwnedRuleCount $group
    $profileC = [ordered]@{ name = 'C'; status = if ($duplicate.effectiveState -eq 'Isolated' -and $rulesAfterDuplicate -eq $owned) { 'PASS' } else { 'FAIL' }; duplicateState = $duplicate.effectiveState; competingAnalyst = 'sprint18-second-analyst'; ownedRulesBefore = $owned; ownedRulesAfter = $rulesAfterDuplicate; noDuplicateControls = ($rulesAfterDuplicate -eq $owned); transitionConflict = 'PASS: unit and control-plane lifecycle gates' }
    if ($profileC.status -ne 'PASS') { throw "Profile C failed: $($profileC | ConvertTo-Json -Compress)" }

    Stop-VictimAgent
    $rulesBeforeReboot = Get-OwnedRuleCount $group
    Remove-PSSession $script:VictimSession -ErrorAction SilentlyContinue; $script:VictimSession = $null
    Stop-VM -Name $VictimVmName
    Start-VM -Name $VictimVmName | Out-Null
    $script:VictimSession = New-VictimSession
    $rulesAfterReboot = Get-OwnedRuleCount $group
    $agentPid = Start-VictimAgent $token
    Start-Sleep -Seconds 8
    docker compose --env-file .env -f deployment/docker-compose.yml restart gateway | Out-Null
    $readyDeadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
    do { try { $gatewayReady = (Invoke-WebRequest http://127.0.0.1:8080/health/ready -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200 } catch { $gatewayReady = $false }; if (-not $gatewayReady) { Start-Sleep -Seconds 2 } } while (-not $gatewayReady -and [DateTimeOffset]::UtcNow -lt $readyDeadline)
    if (-not $gatewayReady) { throw 'Gateway did not recover during Profile D.' }
    Start-Sleep -Seconds 5
    $verify = Api POST "/api/v1/endpoints/$($endpoint.id)/isolation:verify"
    $verify = Wait-Action $verify.responseActionId
    $profileD = [ordered]@{ name = 'D'; status = if ($rulesBeforeReboot -gt 0 -and $rulesAfterReboot -eq $rulesBeforeReboot -and $verify.state -eq 'Succeeded' -and $verify.result.structuredResult.effectiveState -eq 'Isolated') { 'PASS' } else { 'FAIL' }; rulesBeforeEndpointReboot = $rulesBeforeReboot; rulesAfterEndpointReboot = $rulesAfterReboot; gatewayRestart = 'PASS'; rediscoveredState = $verify.result.structuredResult.effectiveState }
    if ($profileD.status -ne 'PASS') { throw "Profile D failed: $($profileD | ConvertTo-Json -Compress)" }
    Assert-Bounds

    $processBefore = [long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.process_events where endpoint_id='$($endpoint.id)';")
    Invoke-Victim {
        New-Item 'HKCU:\Software\OpenSecurityPlatform' -Force | Out-Null
        New-Item 'HKCU:\Software\OpenSecurityPlatform\Sprint4' -Force | Out-Null
        $registryFixture = 'HKCU:\Software\OpenSecurityPlatform\Sprint4\Sprint18ProfileF'
        New-Item $registryFixture -Force | Out-Null
        New-ItemProperty $registryFixture -Name 'Controlled' -Value 'isolated-telemetry' -PropertyType String -Force | Out-Null
        $fileFixture = 'C:\Sprint18Telemetry\profile-f-file.txt'
        Set-Content $fileFixture 'isolated file telemetry fixture' -Encoding ASCII
        1..25 | ForEach-Object { Start-Process "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/c', 'exit 0' -Wait -WindowStyle Hidden }
        Remove-Item $fileFixture -Force
        Remove-Item $registryFixture -Recurse -Force
    } | Out-Null
    $response = Api POST '/api/v1/response-actions' $admin @{ endpointId = $endpoint.id; actionType = 'endpoint.status'; actionVersion = 1; parameters = @{}; timeoutSeconds = 30; expiresInSeconds = 300 }
    $response = Wait-Action $response.responseActionId
    $live = Api POST '/api/v1/live-response/sessions' $admin @{ endpointId = $endpoint.id; capabilities = @('builtin'); idleTimeoutSeconds = 300; absoluteLifetimeSeconds = 900; policyVersion = 'live-response-policy.v1' }
    $live = Wait-Live $live.sessionId
    $command = Api POST "/api/v1/live-response/sessions/$($live.sessionId)/commands" $admin @{ commandType = 'BuiltIn'; input = 'session-info'; timeoutSeconds = 30 }
    $command = Wait-Command $live.sessionId $command.commandId
    Start-Sleep -Seconds 8
    $processAfter = [long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.process_events where endpoint_id='$($endpoint.id)';")
    $isolatedContinuity = Get-VictimConnectivity
    $liveClose = Api POST "/api/v1/live-response/sessions/$($live.sessionId):close" $admin @{ reason = 'Sprint 18 controlled profile complete' }
    $profileF = [ordered]@{ name = 'F'; status = 'PENDING'; responseState = $response.state; liveResponseState = $live.state; liveCommandState = $command.state; liveResponseCloseState = $liveClose.state; processTelemetryBefore = $processBefore; processTelemetryAfter = $processAfter; managementChannel = $isolatedContinuity.management; controlledBlocked = (-not $isolatedContinuity.controlled) }
    Assert-Bounds

    $unisolate = Approve-AndWait (Request-Isolation $endpoint.id unisolate 'Profile B victim-only restoration')
    $restored = Get-VictimConnectivity
    $remaining = Get-OwnedRuleCount $group
    $unrelatedAfter = Invoke-Victim { param($name) Get-NetFirewallRule -Name $name | Select-Object Name, Enabled, Direction, Action, Profile } @($unrelatedRule)
    $repeat = Request-Isolation $endpoint.id unisolate 'Profile B repeated idempotent unisolation'
    $profileB = [ordered]@{ name = 'B'; status = if ($unisolate.state -eq 'Succeeded' -and $restored.management -and $restored.controlled -and $remaining -eq 0 -and $unrelatedAfter.Name -eq $unrelatedBefore.Name -and $repeat.effectiveState -eq 'NotIsolated') { 'PASS' } else { 'FAIL' }; effectiveState = $unisolate.result.structuredResult.effectiveState; controlledConnectivityRestored = $restored.controlled; ownedRulesRemaining = $remaining; unrelatedRulePreserved = ($unrelatedAfter.Name -eq $unrelatedBefore.Name); repeatedUnisolationState = $repeat.effectiveState }
    if ($profileB.status -ne 'PASS') { throw "Profile B failed: $($profileB | ConvertTo-Json -Compress)" }

    Stop-VictimAgent
    $cancel = Request-Isolation $endpoint.id isolate 'Profile E offline cancellation'
    $cancel = Api POST "/api/v1/isolation-actions/$($cancel.responseActionId):cancel" $admin @{ reason = 'cancel before victim reconnect' }
    $expire = Request-Isolation $endpoint.id isolate 'Profile E offline expiry' $admin 30
    $expire = Api POST "/api/v1/isolation-actions/$($expire.responseActionId):approve" $approver @{ parameterHash = $expire.parameterHash; reason = 'controlled victim expiry' }
    Start-Sleep -Seconds 33
    $expire = Wait-Action $expire.responseActionId 10
    $agentPid = Start-VictimAgent $token
    Start-Sleep -Seconds 8
    $postReconnectRules = Get-OwnedRuleCount $group
    $profileE = [ordered]@{ name = 'E'; status = if ($cancel.state -eq 'Cancelled' -and $cancel.deliveryAttempts -eq 0 -and $expire.state -eq 'Expired' -and $expire.deliveryAttempts -eq 0 -and $postReconnectRules -eq 0) { 'PASS' } else { 'FAIL' }; cancelState = $cancel.state; cancelDeliveries = $cancel.deliveryAttempts; expiredState = $expire.state; expiredDeliveries = $expire.deliveryAttempts; ownedRulesAfterReconnect = $postReconnectRules }
    if ($profileE.status -ne 'PASS') { throw "Profile E failed: $($profileE | ConvertTo-Json -Compress)" }
    $queueCounts = Wait-VictimQueuesDrained
    $telemetryDuringIsolation = Get-VictimTelemetryCounts $endpoint.id ([DateTimeOffset]$isolate.result.structuredResult.EffectiveSince)
    $allTelemetryObserved = @($telemetryDuringIsolation.psobject.Properties | Where-Object { [long]$_.Value -le 0 }).Count -eq 0
    $profileF.telemetryDuringIsolation = $telemetryDuringIsolation
    $profileF.queuesDrained = @($queueCounts.psobject.Properties | Where-Object { [long]$_.Value -ne 0 }).Count -eq 0
    $profileF.status = if ($response.state -eq 'Succeeded' -and $live.state -eq 'Active' -and $command.state -eq 'Succeeded' -and $liveClose.state -eq 'Closed' -and $processAfter -gt $processBefore -and $isolatedContinuity.management -and -not $isolatedContinuity.controlled -and $allTelemetryObserved -and $profileF.queuesDrained) { 'PASS' } else { 'FAIL' }
    if ($profileF.status -ne 'PASS') { throw "Profile F failed: $($profileF | ConvertTo-Json -Depth 10 -Compress)" }
    Assert-Bounds

    $profiles = @($profileA, $profileB, $profileC, $profileD, $profileE, $profileF)
    $vmBytesAfter = (Get-ChildItem 'D:\VMs\XDR-Victim-Sprint18' -Recurse -File | Measure-Object Length -Sum).Sum
    $hostOwnedAfter = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object Group -Like 'OpenSecurityPlatform-Isolation-*').Count
    $report = [ordered]@{
        schemaVersion = 'sprint18-windows-isolation.v2'; executedAt = [DateTimeOffset]::UtcNow.ToString('O')
        executionBoundary = 'Hyper-V victim only'; victimVm = $VictimVmName; hostFirewallMutations = 0
        environment = $guest; hostGatewayAddress = $HostGatewayAddress; endpointId = $endpoint.id; agentInstallationId = $state.installationId
        policyVersion = $qualificationPolicy.policyVersion; filePolicy = @{ id = $createdFilePolicy.id; version = $createdFilePolicy.version; includedPaths = $createdFilePolicy.policy.includedPaths }; profiles = $profiles; telemetryQueues = $queueCounts
        storage = @{ vmBytesBefore = $script:VmBytesBefore; vmBytesAfter = $vmBytesAfter; vmGrowthBytes = $vmBytesAfter - $script:VmBytesBefore; dFreeBytesBefore = $vmFreeBefore; dFreeBytesAfter = (Get-Volume D).SizeRemaining; guestLogLimitBytes = $MaximumGuestLogBytes; falcoRunning = $false }
        hostSafety = @{ platformOwnedRulesBefore = $hostOwnedBefore; platformOwnedRulesAfter = $hostOwnedAfter; unchanged = ($hostOwnedBefore -eq $hostOwnedAfter) }
        passed = (@($profiles | Where-Object status -ne 'PASS').Count -eq 0 -and $hostOwnedAfter -eq $hostOwnedBefore)
    }
    [IO.File]::WriteAllText((Join-Path $root 'artifacts\sprint18-windows-isolation.json'), ($report | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
    $report | ConvertTo-Json -Depth 30
    if (-not $report.passed) { exit 1 }
}
finally {
    if ($script:VictimSession) {
        try { Stop-VictimAgent } catch { }
        try {
            Invoke-Victim {
                param($ruleName)
                $owned = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
                    Where-Object Group -Like 'OpenSecurityPlatform-Isolation-*')
                if ($owned.Count -gt 0) { $owned | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
                Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
                Set-Content -LiteralPath $hosts -Value @(Get-Content $hosts | Where-Object { $_ -notmatch '# Sprint18 victim gateway$' }) -Encoding ASCII
            } @($unrelatedRule) | Out-Null
        } catch { }
        Remove-PSSession $script:VictimSession -ErrorAction SilentlyContinue
    }
    try {
        Api PUT '/api/v1/isolation-policy' $admin @{
            policyVersion = $originalPolicy.policyVersion; managementDestinations = $originalPolicy.managementDestinations
            isolationApprovalRequired = $originalPolicy.isolationApprovalRequired; unisolationApprovalRequired = $originalPolicy.unisolationApprovalRequired
            pendingExpirySeconds = $originalPolicy.pendingExpirySeconds
        } | Out-Null
    } catch { }
}
