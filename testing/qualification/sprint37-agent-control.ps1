param(
    [ValidateSet('Start','StartDrain','Stop','Status','SyncSprint19','SyncSprint20','SyncSprint21','CleanupSprint21')][string]$Action = 'Status',
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml'
)
$ErrorActionPreference = 'Stop'
$credential = Import-Clixml -LiteralPath $CredentialPath
$result = Invoke-Command -VMName $VictimVmName -Credential $credential -ScriptBlock {
    param($RequestedAction)
    $sessions = @(
        'OpenSecurityPlatform-ProcessLifecycle-v1',
        'OpenSecurityPlatform-RegistryLifecycle-v1',
        'OpenSecurityPlatform-FileLifecycle-v1',
        'OpenSecurityPlatform-NetworkLifecycle-v1',
        'OpenSecurityPlatform-DnsClient-v1',
        'OpenSecurityPlatform-ModuleImageLoad-v1'
    )
    if ($RequestedAction -in @('Start','StartDrain') -and -not (Get-Process Platform.Agent -ErrorAction SilentlyContinue)) {
        foreach ($name in $sessions) { & logman stop $name -ets 2>$null | Out-Null }
        $env:PLATFORM_CONTROL_PLANE_URL = 'https://gateway:8443'
        $env:PLATFORM_AGENT_DATA = 'C:\Sprint34Qualification\runtime-data'
        $env:PLATFORM_CA_CERT_PATH = 'C:\Sprint19Qualification\ca.crt'
        $env:PLATFORM_ENVIRONMENT = 'production'
        $env:PLATFORM_TELEMETRY_DRAIN_ONLY = if ($RequestedAction -eq 'StartDrain') { 'true' } else { 'false' }
        Start-Process 'C:\Sprint37Qualification\agent\Platform.Agent.exe' -WindowStyle Hidden `
            -RedirectStandardOutput C:\Sprint34Qualification\agent.log `
            -RedirectStandardError C:\Sprint34Qualification\agent-error.log | Out-Null
        Start-Sleep -Seconds 5
    }
    if ($RequestedAction -eq 'Stop') {
        Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
        foreach ($name in $sessions) { & logman stop $name -ets 2>$null | Out-Null }
    }
    if ($RequestedAction -eq 'SyncSprint19') {
        Get-Process Platform.Agent,ProcessGenerator -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
        Remove-Item C:\Sprint19Qualification\agent -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item C:\Sprint37Qualification\agent C:\Sprint19Qualification\agent -Recurse -Force
    }
    if ($RequestedAction -in @('SyncSprint20','SyncSprint21')) {
        Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
        $destination = if ($RequestedAction -eq 'SyncSprint20') { 'C:\Sprint20Qualification\agent' } else { 'C:\Sprint21Qualification\agent' }
        Remove-Item $destination -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item C:\Sprint37Qualification\agent $destination -Recurse -Force
    }
    if ($RequestedAction -eq 'CleanupSprint21') {
        Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
        Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.PSObject.Properties | Where-Object Name -Like 'Sprint21-*' | ForEach-Object { Remove-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $_.Name -ErrorAction SilentlyContinue } }
        Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -Like 'Sprint21*' -or $_.Name -Like 'OpenSecurityPlatformSprint21*' } |
            ForEach-Object { & sc.exe stop $_.Name | Out-Null; & sc.exe delete $_.Name | Out-Null }
        Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -Like '\Sprint21*' -or $_.TaskName -Like '*Sprint21*' } |
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter -Like '*Sprint21-*' -or $_.Consumer -Like '*Sprint21-*' }
        $bindings | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | Where-Object Name -Like 'Sprint21-*' | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Where-Object Name -Like 'Sprint21-*' | Remove-WmiObject -ErrorAction SilentlyContinue
        Remove-Item C:\Sprint20Telemetry,C:\Sprint19Telemetry -Recurse -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    $queues = @('process-queue','file-queue','registry-queue','network-queue','dns-queue','module-queue','persistence-queue','identity-queue','execution-queue','file-hash-work','forensic-collection-work')
    [ordered]@{
        action = $RequestedAction
        running = [bool](Get-Process Platform.Agent -ErrorAction SilentlyContinue)
        queueDepth = @($queues | ForEach-Object { Get-ChildItem (Join-Path 'C:\Sprint34Qualification\runtime-data' $_) -Filter '*.json' -File -ErrorAction SilentlyContinue }).Count
        errorTail = @(Get-Content C:\Sprint34Qualification\agent-error.log -Tail 5 -ErrorAction SilentlyContinue)
    }
} -ArgumentList $Action
$result | ConvertTo-Json -Depth 5
