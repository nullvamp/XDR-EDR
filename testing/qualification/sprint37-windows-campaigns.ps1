param(
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
    [string]$BaseUrl = 'http://127.0.0.1:8080'
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $root
$artifactPath = Join-Path $root 'artifacts\sprint37-windows-campaigns.json'
$scenarioPath = Join-Path $root 'testing\qualification\sprint37-scenarios.json'
$scenarioCatalog = Get-Content $scenarioPath -Raw | ConvertFrom-Json
$credential = Import-Clixml -LiteralPath $CredentialPath
$configuration = @{}
Get-Content .env | Where-Object { $_ -match '^\s*([^#=\s]+)=(.*)$' } | ForEach-Object {
    $configuration[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'")
}

function Invoke-Victim([scriptblock]$Script, [object[]]$Arguments = @()) {
    $session = New-PSSession -VMName $VictimVmName -Credential $credential
    try { Invoke-Command -Session $session -ScriptBlock $Script -ArgumentList $Arguments -ErrorAction SilentlyContinue }
    finally { Remove-PSSession $session }
}

function Get-DomainCounts([string]$EndpointId) {
    $tables = @('process_events','file_events','registry_events','network_events','dns_events','module_events','persistence_events','identity_events','execution_events')
    $parts = $tables | ForEach-Object { "select '$_',count(*) from platform.$_ where endpoint_id='$EndpointId'" }
    $rows = docker exec deployment-postgres-1 psql -U platform -d platform -Atc ($parts -join ' union all ')
    $counts = [ordered]@{}
    foreach ($row in $rows) { $value = $row.Trim().Split('|'); if ($value.Count -eq 2) { $counts[$value[0]] = [long]$value[1] } }
    $counts
}

function Get-TransportState {
    $outbox = (docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) filter(where published_at is null and failed_at is null)||'|'||count(*) filter(where failed_at is not null) from platform.outbox;").Trim().Split('|')
    $nats = docker exec deployment-nats-1 wget -qO- 'http://localhost:8222/jsz?streams=true&consumers=true' | ConvertFrom-Json
    $consumers = @($nats.account_details.stream_detail.consumer_detail)
    [ordered]@{
        outboxPending = [long]$outbox[0]
        outboxFailed = [long]$outbox[1]
        natsPending = [long](($consumers | Measure-Object num_pending -Sum).Sum)
        natsAckPending = [long](($consumers | Measure-Object num_ack_pending -Sum).Sum)
    }
}

$tenant = $configuration.PLATFORM_BOOTSTRAP_TENANT_ID
$endpoint = (docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select e.id from platform.endpoints e join platform.agents a on a.tenant_id=e.tenant_id and a.endpoint_id=e.id where e.tenant_id='$tenant' and e.os_type='windows' and lower(a.status)='active' order by a.last_checkin desc nulls last limit 1;").Trim()
if (-not $endpoint) { throw 'No active controlled Windows endpoint is available.' }

$startedAt = [DateTimeOffset]::UtcNow
$before = Get-DomainCounts $endpoint

$native = Invoke-Victim {
    # Windows PowerShell remoting converts expected native stderr from negative
    # controls into ErrorRecord objects. Keep those bounded commands observable
    # without aborting cleanup; cmdlet operations that must succeed are explicit.
    $ErrorActionPreference = 'Continue'
    $fixture = 'C:\Users\Public\Sprint37Qualification'
    $payload = Join-Path $fixture 's37-stage.exe'
    $dll = Join-Path $fixture 's37-unsigned-fixture.dll'
    $runPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $taskName = 'Sprint37ControlledTask'
    $serviceName = 'Sprint37ControlledService'
    $userName = 's37_fixture_user'
    $campaigns = [ordered]@{}
    New-Item -ItemType Directory -Path $fixture -Force | Out-Null
    try {
        Copy-Item "$env:WINDIR\System32\whoami.exe" $payload -Force
        Set-Content (Join-Path $fixture 'benign.txt') 'Sprint 37 benign control' -Encoding ASCII
        Get-Content (Join-Path $fixture 'benign.txt') | Out-Null
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('cmd.exe /c "tasklist >nul & nslookup gateway >nul"'))
        $child = Start-Process powershell.exe -ArgumentList @('-NoProfile','-EncodedCommand',$encoded) -PassThru -WindowStyle Hidden
        $null = $child.WaitForExit(30000)
        & $payload | Out-Null
        try { Resolve-DnsName gateway -Type A -ErrorAction Stop | Out-Null } catch {}
        try { Invoke-WebRequest 'http://gateway:8080/health/live' -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {}
        $campaigns.A = [ordered]@{ stagedFile = Test-Path $payload; childExited = $child.HasExited; benignControl = $true }

        New-ItemProperty -Path $runPath -Name Sprint37ControlledRun -Value $payload -PropertyType String -Force | Out-Null
        & schtasks.exe /Create /TN $taskName /TR $payload /SC ONCE /ST 23:59 /F | Out-Null
        New-Service -Name $serviceName -BinaryPathName $payload -StartupType Manual -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 12
        & $payload | Out-Null
        $campaigns.B = [ordered]@{
            registryCreated = $null -ne (Get-ItemProperty -Path $runPath -Name Sprint37ControlledRun -ErrorAction SilentlyContinue)
            taskCreated = $null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
            serviceCreated = $null -ne (Get-Service $serviceName -ErrorAction SilentlyContinue)
        }

        $fixturePassword = ConvertTo-SecureString 'S37-Fixture-Only!42' -AsPlainText -Force
        New-LocalUser -Name $userName -Password $fixturePassword -AccountNeverExpires -PasswordNeverExpires -ErrorAction Stop | Out-Null
        if (-not ('Sprint37.NativeMethods' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Sprint37 {
  public static class NativeMethods {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string password, int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
  }
}
'@
        }
        1..3 | ForEach-Object {
            $token = [IntPtr]::Zero
            $null = [Sprint37.NativeMethods]::LogonUser($userName, $env:COMPUTERNAME, 'wrong-S37-password', 3, 0, [ref]$token)
            if ($token -ne [IntPtr]::Zero) { [Sprint37.NativeMethods]::CloseHandle($token) | Out-Null }
        }
        & net.exe user $userName | Out-Null
        $campaigns.C = [ordered]@{ controlledAccountCreated = $null -ne (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue); remoteAttributionClaimed = $false }

        & whoami.exe /all | Out-Null
        & systeminfo.exe | Out-Null
        & tasklist.exe | Out-Null
        & net.exe user | Out-Null
        & cmd.exe /c 'ipconfig /all >nul' | Out-Null
        $campaigns.D = [ordered]@{ commands = @('whoami','systeminfo','tasklist','net user','cmd /c ipconfig'); completed = $true }

        Copy-Item "$env:WINDIR\System32\version.dll" $dll -Force
        $campaigns.E = [ordered]@{ userWritableDllCreated = Test-Path $dll; realSecurityControlChanged = $false }

        try { Resolve-DnsName gateway -Type TXT -ErrorAction Stop | Out-Null } catch {}
        try { Test-NetConnection gateway -Port 8080 -InformationLevel Quiet | Out-Null } catch {}
        $campaigns.F = [ordered]@{ dnsTxtAttempted = $true; tcpConnectionAttempted = $true; nativeTunnelStarted = $false }

        & $payload | Out-Null
        & whoami.exe | Out-Null
        & cmd.exe /c 'ipconfig >nul' | Out-Null
        try { Resolve-DnsName gateway | Out-Null } catch {}
        $campaigns.G = [ordered]@{ stages = @('file','process','discovery','persistence','dns','network','identity-context'); completed = $true }
        Start-Sleep -Seconds 15
    }
    finally {
        Remove-ItemProperty -Path $runPath -Name Sprint37ControlledRun -ErrorAction SilentlyContinue
        & cmd.exe /c "schtasks /Delete /TN $taskName /F >nul 2>&1" | Out-Null
        & cmd.exe /c "sc stop $serviceName >nul 2>&1" | Out-Null
        & cmd.exe /c "sc delete $serviceName >nul 2>&1" | Out-Null
        & cmd.exe /c "net user $userName /delete >nul 2>&1" | Out-Null
        Remove-Item $fixture -Recurse -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
    $cleanup = [ordered]@{
        fixtureRootAbsent = -not (Test-Path $fixture)
        registryAbsent = $null -eq (Get-ItemProperty -Path $runPath -Name Sprint37ControlledRun -ErrorAction SilentlyContinue)
        taskAbsent = $null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
        serviceAbsent = $null -eq (Get-Service $serviceName -ErrorAction SilentlyContinue)
        userAbsent = $null -eq (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)
        agentRunning = $null -ne (Get-Process Platform.Agent -ErrorAction SilentlyContinue)
    }
    # Freeze the controlled corpus after the agent has durably emptied its local
    # queues. Otherwise ordinary Windows background activity keeps creating new
    # telemetry while the backend drain is being measured.
    $runtimeRoot = 'C:\Sprint34Qualification\runtime-data'
    $queueNames = @('process-queue','file-queue','registry-queue','network-queue','dns-queue','module-queue','persistence-queue','identity-queue','execution-queue','file-hash-work','forensic-collection-work')
    $queueDeadline = (Get-Date).AddMinutes(10)
    do {
        $localQueueDepth = @($queueNames | ForEach-Object { Get-ChildItem (Join-Path $runtimeRoot $_) -Filter '*.json' -File -ErrorAction SilentlyContinue }).Count
        if ($localQueueDepth -gt 0) { Start-Sleep -Seconds 2 }
    } while ($localQueueDepth -gt 0 -and (Get-Date) -lt $queueDeadline)
    Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
    $cleanup.localQueueDepthBeforeCaptureStop = $localQueueDepth
    $cleanup.captureStopped = $null -eq (Get-Process Platform.Agent -ErrorAction SilentlyContinue)
    $os = Get-CimInstance Win32_OperatingSystem
    [ordered]@{
        os = $os.Caption
        build = $os.BuildNumber
        architecture = $env:PROCESSOR_ARCHITECTURE
        administrator = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        campaigns = $campaigns
        cleanup = $cleanup
    }
}

$deadline = (Get-Date).AddMinutes(15)
do {
    Start-Sleep -Seconds 3
    $transport = Get-TransportState
} while (($transport.outboxPending -gt 0 -or $transport.natsPending -gt 0 -or $transport.natsAckPending -gt 0) -and (Get-Date) -lt $deadline)

$after = Get-DomainCounts $endpoint
$delta = [ordered]@{}
foreach ($name in $after.Keys) { $delta[$name] = [long]$after[$name] - [long]$before[$name] }
$findingRows = docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select dd.name||'|'||count(*)||'|'||min(df.first_seen)||'|'||max(df.first_seen) from platform.detection_findings df join platform.detection_definitions dd on dd.tenant_id=df.tenant_id and dd.detection_id=df.detection_id where df.tenant_id='$tenant' and df.endpoint_id='$endpoint' and df.first_seen >= '$($startedAt.ToString('o'))' group by dd.name order by dd.name;"
$findings = @($findingRows | ForEach-Object { $part = $_.Trim().Split('|'); if ($part.Count -ge 4) { [ordered]@{ rule=$part[0]; count=[long]$part[1]; firstSeen=$part[2]; lastSeen=$part[3] } } })
$cleanupPassed = [bool]$native.cleanup.fixtureRootAbsent -and [bool]$native.cleanup.registryAbsent -and [bool]$native.cleanup.taskAbsent -and [bool]$native.cleanup.serviceAbsent -and [bool]$native.cleanup.userAbsent -and [bool]$native.cleanup.agentRunning -and [bool]$native.cleanup.captureStopped -and [long]$native.cleanup.localQueueDepthBeforeCaptureStop -eq 0
$telemetryPassed = @('process_events','file_events','registry_events','network_events','dns_events','module_events','persistence_events','identity_events','execution_events' | Where-Object { $delta[$_] -le 0 }).Count -eq 0
$result = [ordered]@{
    schemaVersion = 'sprint37-windows-campaigns.v1'
    scenarioCatalogVersion = $scenarioCatalog.version
    startedAt = $startedAt.ToString('o')
    completedAt = [DateTimeOffset]::UtcNow.ToString('o')
    target = $VictimVmName
    endpointId = $endpoint
    native = $native
    telemetryBefore = $before
    telemetryAfter = $after
    telemetryDelta = $delta
    observedProductionFindings = $findings
    transport = $transport
    cleanupPassed = $cleanupPassed
    allTelemetryDomainsObserved = $telemetryPassed
    passed = $cleanupPassed -and $telemetryPassed -and $transport.outboxPending -eq 0 -and $transport.outboxFailed -eq 0 -and $transport.natsPending -eq 0 -and $transport.natsAckPending -eq 0
}
$result | ConvertTo-Json -Depth 20 | Set-Content $artifactPath -Encoding utf8
$result | ConvertTo-Json -Depth 20
if (-not $result.passed) { throw 'Sprint 37 native Windows campaign qualification failed.' }
