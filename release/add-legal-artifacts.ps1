param([Parameter(Mandatory)][string]$Output)
$ErrorActionPreference='Stop'
$output=[IO.Path]::GetFullPath($Output);if(-not(Test-Path $output)){throw "Release output missing: $output"}
$dotnet=(Split-Path (Get-Command dotnet).Source)
$license=Join-Path $dotnet 'LICENSE.txt';$notices=Join-Path $dotnet 'ThirdPartyNotices.txt'
if(-not(Test-Path $license)-or-not(Test-Path $notices)){throw 'Installed .NET license/notices are unavailable'}
Copy-Item $license (Join-Path $output 'DOTNET-LICENSE.txt')
Copy-Item $notices (Join-Path $output 'DOTNET-THIRD-PARTY-NOTICES.txt')
Copy-Item (Join-Path $PSScriptRoot '..\docs\release\v1.0.0\THIRD-PARTY-NOTICES.md') $output
Copy-Item (Join-Path $PSScriptRoot '..\docs\release\v1.0.0\third-party-components.json') $output
Copy-Item (Join-Path $PSScriptRoot 'licenses\*.txt') $output
