param([string]$VictimVmName='XDR-Victim-Sprint18',[string]$CredentialPath='D:\VMs\XDR-Victim-Sprint18\victim-credential.xml')
$ErrorActionPreference='Stop'
$publish=Join-Path (Get-Location) 'artifacts\sprint26-agent-publish'
dotnet publish agent/core/Platform.Agent/Platform.Agent.csproj -c Release -r win-x64 --self-contained true -o $publish
if($LASTEXITCODE-ne0){exit $LASTEXITCODE}
$credential=Import-Clixml -LiteralPath $CredentialPath
$session=New-PSSession -VMName $VictimVmName -Credential $credential
try {
    Invoke-Command -Session $session -ScriptBlock {
        $qualification='C:\Sprint26Qualification'
        $agent=Join-Path $qualification 'agent'
        New-Item -ItemType Directory -Force -Path $qualification,$agent|Out-Null
        Get-ChildItem -LiteralPath $agent -Force -ErrorAction SilentlyContinue|Remove-Item -Recurse -Force
    }
    Copy-Item (Join-Path $publish '*') -Destination 'C:\Sprint26Qualification\agent' -ToSession $session -Recurse -Force
    $native=Invoke-Command -Session $session -ScriptBlock {
        $qualification='C:\Sprint26Qualification'
        $env:PLATFORM_SELF_PROTECTION_SELF_TEST='true'
        $env:PLATFORM_SELF_PROTECTION_SELF_TEST_ROOT=Join-Path $qualification 'fixtures'
        $env:PLATFORM_SELF_PROTECTION_SELF_TEST_OUTPUT=Join-Path $qualification 'native.json'
        & (Join-Path $qualification 'agent\Platform.Agent.exe')|Out-Null
        $code=$LASTEXITCODE
        $result=Get-Content (Join-Path $qualification 'native.json') -Raw|ConvertFrom-Json
        $os=Get-CimInstance Win32_OperatingSystem
        [pscustomobject]@{
            exitCode=$code;os=$os.Caption;build=$os.BuildNumber;architecture=$env:PROCESSOR_ARCHITECTURE
            dotnet='8.0 self-contained runtime'
            administrator=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            integrity=((& whoami /groups|Select-String 'S-1-16-(\d+)'|ForEach-Object{$_.Matches.Groups[1].Value}))
            result=$result
            serviceRemaining=[bool](Get-Service PlatformSprint26Fixture -ErrorAction SilentlyContinue)
            firewallRemaining=@(Get-NetFirewallRule -Group PlatformSprint26FixtureRules -ErrorAction SilentlyContinue).Count
        }
    }
    $native|ConvertTo-Json -Depth 20|Set-Content artifacts/sprint26-native-windows.json -Encoding utf8
    $native|ConvertTo-Json -Depth 20
    if($native.exitCode-ne0-or-not$native.result.passed-or$native.serviceRemaining-or$native.firewallRemaining){exit 1}
}
finally { Remove-PSSession $session }
