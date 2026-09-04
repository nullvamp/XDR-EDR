param(
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml'
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '../..')
Set-Location $root
$settings = @{}
Get-Content .env | Where-Object { $_ -match '^([^#=]+)=(.*)$' } | ForEach-Object { $settings[$matches[1]] = $matches[2] }
$login = Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/auth/token -ContentType application/json -Body (@{ username = $settings.PLATFORM_BOOTSTRAP_USER; password = $settings.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.access_token)" }
$token = (Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/enrollment-tokens -Headers $headers -ContentType application/json -Body (@{ expiresAt = [DateTimeOffset]::UtcNow.AddHours(3).ToString('o'); maximumUses = 1; allowedPlatforms = @('windows') } | ConvertTo-Json)).data
$credential = Import-Clixml $CredentialPath
$session = New-PSSession -VMName $VictimVmName -Credential $credential
try {
    $agentProcessId = Invoke-Command $session {
        param($tokenId, $tokenSecret)
        Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
        New-Item C:\Sprint34Qualification -ItemType Directory -Force | Out-Null
        Remove-Item C:\Sprint34Qualification\runtime-data -Recurse -Force -ErrorAction SilentlyContinue
        @('OpenSecurityPlatform-ProcessLifecycle-v1','OpenSecurityPlatform-RegistryLifecycle-v1','OpenSecurityPlatform-FileLifecycle-v1','OpenSecurityPlatform-NetworkLifecycle-v1','OpenSecurityPlatform-DnsClient-v1','OpenSecurityPlatform-ModuleImageLoad-v1') | ForEach-Object { & logman stop $_ -ets 2>$null | Out-Null }
        $env:PLATFORM_CONTROL_PLANE_URL = 'https://gateway:8443'
        $env:PLATFORM_ENROLLMENT_TOKEN_ID = $tokenId
        $env:PLATFORM_ENROLLMENT_TOKEN_SECRET = $tokenSecret
        $env:PLATFORM_AGENT_DATA = 'C:\Sprint34Qualification\runtime-data'
        $env:PLATFORM_CA_CERT_PATH = 'C:\Sprint19Qualification\ca.crt'
        $env:PLATFORM_ENVIRONMENT = 'production'
        (Start-Process 'C:\Sprint37Qualification\agent\Platform.Agent.exe' -PassThru -WindowStyle Hidden -RedirectStandardOutput C:\Sprint34Qualification\agent.log -RedirectStandardError C:\Sprint34Qualification\agent-error.log).Id
    } -ArgumentList $token.metadata.id, $token.secret
}
finally { Remove-PSSession $session }
$deadline = (Get-Date).AddMinutes(2)
do {
    Start-Sleep 3
    $endpoints = @((Invoke-RestMethod 'http://127.0.0.1:8080/api/v1/endpoints?pageSize=500' -Headers $headers).data.items)
    $endpoint = $endpoints | Where-Object { $_.lastSeenAt -and [DateTimeOffset]$_.lastSeenAt -gt [DateTimeOffset]::UtcNow.AddMinutes(-2) } | Sort-Object lastSeenAt -Descending | Select-Object -First 1
} while (!$endpoint -and (Get-Date) -lt $deadline)
if (!$endpoint) { throw 'Fresh Sprint34 victim enrollment failed.' }
[pscustomobject]@{ AgentProcessId = $agentProcessId; EndpointId = $endpoint.id; Status = $endpoint.status; LastSeenAt = $endpoint.lastSeenAt } | ConvertTo-Json
