param(
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml'
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$publish = Join-Path $root 'artifacts\sprint37-agent-publish'
dotnet publish (Join-Path $root 'agent\core\Platform.Agent\Platform.Agent.csproj') -c Release -r win-x64 --self-contained true -o $publish
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$credential = Import-Clixml -LiteralPath $CredentialPath
$session = New-PSSession -VMName $VictimVmName -Credential $credential
try {
    Invoke-Command -Session $session -ScriptBlock {
        Get-Process Platform.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
        Remove-Item C:\Sprint37Qualification\agent -Recurse -Force -ErrorAction SilentlyContinue
        New-Item C:\Sprint37Qualification\agent -ItemType Directory -Force | Out-Null
    }
    Copy-Item (Join-Path $publish '*') -Destination C:\Sprint37Qualification\agent -ToSession $session -Recurse -Force
    Invoke-Command -Session $session -ScriptBlock {
        [ordered]@{
            synchronized = Test-Path C:\Sprint37Qualification\agent\Platform.Agent.exe
            sha256 = (Get-FileHash C:\Sprint37Qualification\agent\Platform.Agent.exe -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
}
finally { Remove-PSSession $session }
