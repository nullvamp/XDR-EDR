param(
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
    [int]$TimeoutSeconds = 300
)
$ErrorActionPreference = 'Stop'
$credential = Import-Clixml $CredentialPath
$session = New-PSSession -VMName $VictimVmName -Credential $credential
try {
    Invoke-Command -Session $session -ScriptBlock {
        Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
        $qualification = 'C:\Sprint22Qualification'
        $env:PLATFORM_CONTROL_PLANE_URL = 'https://gateway:8443'
        $env:PLATFORM_AGENT_DATA = "$qualification\runtime-data"
        $env:PLATFORM_CA_CERT_PATH = 'C:\Sprint19Qualification\ca.crt'
        $env:PLATFORM_ENVIRONMENT = 'production'
        # Sprint 29 bounded drain mode prevents native file/network/DNS intake from
        # creating more durable work while an existing backlog is being replayed.
        $env:PLATFORM_TELEMETRY_DRAIN_ONLY = 'true'
        $env:PLATFORM_FORENSIC_COLLECTION_SELF_TEST = 'false'
        Start-Process "$qualification\agent\Platform.Agent.exe" -WindowStyle Hidden -RedirectStandardOutput "$qualification\drain-agent.log" -RedirectStandardError "$qualification\drain-agent-error.log" | Out-Null
    }

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep 2
        $queues = Invoke-Command -Session $session -ScriptBlock {
            $root = 'C:\Sprint22Qualification\runtime-data'
            $result = [ordered]@{}
            foreach ($name in 'process','file','registry','network','dns','module','persistence','identity','execution') {
                $path = "$root\$name-queue"
                $result[$name] = if (Test-Path $path) { @(Get-ChildItem $path -File -Filter '*.json').Count } else { 0 }
            }
            $result['fileHashWork'] = @(Get-ChildItem "$root\file-hash-work" -File -Filter '*.json' -ErrorAction SilentlyContinue).Count
            $result['forensicProgress'] = @(Get-ChildItem "$root\forensic-collection-work" -File -Filter '*.dat' -ErrorAction SilentlyContinue).Count
            [pscustomobject]$result
        }
        $remaining = [long](($queues.psobject.Properties | Where-Object { $_.Name -notlike 'PS*' -and $_.Name -ne 'RunspaceId' } | ForEach-Object { [long]$_.Value } | Measure-Object -Sum).Sum)
    } while ($remaining -ne 0 -and [DateTimeOffset]::UtcNow -lt $deadline)

    Invoke-Command -Session $session -ScriptBlock { Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force }
    [pscustomobject]@{ remaining = $remaining; queues = $queues; agentRunning = [bool](Invoke-Command -Session $session -ScriptBlock { Get-Process Platform.Agent -ErrorAction SilentlyContinue }) }
    if ($remaining -ne 0) { exit 1 }
}
finally {
    Remove-PSSession $session
}
