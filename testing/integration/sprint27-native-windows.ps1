param([string]$VictimVmName='XDR-Victim-Sprint18',[string]$CredentialPath='D:\VMs\XDR-Victim-Sprint18\victim-credential.xml')
$ErrorActionPreference='Stop';$root=Resolve-Path(Join-Path $PSScriptRoot '..\..');Set-Location $root
$publish=Join-Path $root 'artifacts\sprint27-agent-publish';dotnet publish agent/core/Platform.Agent/Platform.Agent.csproj -c Release -r win-x64 --self-contained true -o $publish
if($LASTEXITCODE-ne0){exit $LASTEXITCODE}
$credential=Import-Clixml -LiteralPath $CredentialPath;$session=New-PSSession -VMName $VictimVmName -Credential $credential
try {
  Invoke-Command -Session $session -ScriptBlock {$q='C:\Sprint27Qualification';$a=Join-Path $q 'agent';New-Item -ItemType Directory -Force -Path $q,$a|Out-Null;Get-ChildItem $a -Force -ErrorAction SilentlyContinue|Remove-Item -Recurse -Force}
  Copy-Item (Join-Path $publish '*') -Destination 'C:\Sprint27Qualification\agent' -ToSession $session -Recurse -Force
  $native=Invoke-Command -Session $session -ScriptBlock {
    $q='C:\Sprint27Qualification';$env:PLATFORM_AGENT_UPDATE_SELF_TEST='true';$env:PLATFORM_AGENT_UPDATE_SELF_TEST_ROOT=Join-Path $q 'fixtures';$env:PLATFORM_AGENT_UPDATE_SELF_TEST_OUTPUT=Join-Path $q 'native.json'
    & (Join-Path $q 'agent\Platform.Agent.exe')|Out-Null;$code=$LASTEXITCODE;$result=Get-Content (Join-Path $q 'native.json') -Raw|ConvertFrom-Json;$os=Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{exitCode=$code;os=$os.Caption;build=$os.BuildNumber;architecture=$env:PROCESSOR_ARCHITECTURE;dotnet='8.0 self-contained runtime';administrator=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);integrity=((& whoami /groups|Select-String 'S-1-16-(\d+)'|ForEach-Object{$_.Matches.Groups[1].Value}));result=$result;hostNetworkChanged=$false;hostServicesChanged=$false}
  }
  $native|ConvertTo-Json -Depth 20|Set-Content artifacts/sprint27-native-windows.json -Encoding utf8;$native|ConvertTo-Json -Depth 20
  if($native.exitCode-ne0-or-not$native.result.passed-or-not$native.administrator){exit 1}
} finally {Remove-PSSession $session}
