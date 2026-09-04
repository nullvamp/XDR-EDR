param([ValidateSet("Debug","Release")][string]$Configuration="Release")
$ErrorActionPreference="Stop"
$root=Split-Path -Parent $PSScriptRoot
$dotnet=Join-Path $root ".tooling\dotnet\dotnet.exe"
if(-not(Test-Path $dotnet)){$dotnet="dotnet"}
$env:DOTNET_CLI_HOME=Join-Path $root ".tooling\home"
$env:APPDATA=Join-Path $root ".tooling\appdata"
$env:LOCALAPPDATA=Join-Path $root ".tooling\localappdata"
$env:DOTNET_CLI_TELEMETRY_OPTOUT="1"
& $dotnet restore (Join-Path $root "SecurityPlatform.sln") --configfile (Join-Path $root "NuGet.Config")
if($LASTEXITCODE){exit $LASTEXITCODE}
& $dotnet build (Join-Path $root "SecurityPlatform.sln") -c $Configuration --no-restore
if($LASTEXITCODE){exit $LASTEXITCODE}
& $dotnet run --no-build -c $Configuration --project (Join-Path $root "testing\Platform.Tests\Platform.Tests.csproj")
$result=$LASTEXITCODE
& $dotnet build-server shutdown | Out-Null
exit $result
