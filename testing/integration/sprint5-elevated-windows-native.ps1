param([string]$RepositoryRoot)
$ErrorActionPreference='Stop';Set-Location $RepositoryRoot
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=[Security.Principal.WindowsPrincipal]::new($identity);$groups=whoami /groups /fo csv|ConvertFrom-Csv;$integrity=($groups|Where-Object{$_.SID-match'S-1-16-'}|Select-Object -First 1).'Group Name';$os=Get-CimInstance Win32_OperatingSystem
$environment=[ordered]@{schema='platform.sprint5.windows-environment.v1';executedAt=[DateTimeOffset]::UtcNow;account=$identity.Name;administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);integrityLevel=$integrity;osCaption=$os.Caption;osVersion=$os.Version;osBuild=$os.BuildNumber;architecture=$os.OSArchitecture;dotnet=(dotnet --version);processId=$PID};$environment|ConvertTo-Json -Depth 5|Set-Content artifacts/sprint5-windows-environment.json
if(-not$environment.administrator){exit 3}
$env:PLATFORM_NETWORK_COLLECTOR_SELF_TEST='true';$env:PLATFORM_NETWORK_COLLECTOR_SELF_TEST_OUTPUT=(Join-Path $RepositoryRoot 'artifacts\sprint5-windows-network-native.json');$env:PLATFORM_AGENT_DATA=(Join-Path $RepositoryRoot 'artifacts\sprint5-windows-agent-data')
dotnet run --project agent/core/Platform.Agent/Platform.Agent.csproj -c Release --no-build
exit $LASTEXITCODE
