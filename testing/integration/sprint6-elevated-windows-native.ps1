param([string]$RepositoryRoot)
$ErrorActionPreference = 'Stop'
$root = if ($RepositoryRoot) { (Resolve-Path $RepositoryRoot).Path } else { (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path }
Set-Location $root
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Elevated Administrator token required.' }
$data = Join-Path $root 'artifacts\sprint6-native-agent-data'
New-Item -ItemType Directory -Force -Path $data | Out-Null
$env:PLATFORM_AGENT_DATA = $data
$env:PLATFORM_DNS_COLLECTOR_SELF_TEST = 'true'
$env:PLATFORM_DNS_COLLECTOR_SELF_TEST_OUTPUT = Join-Path $root 'artifacts\sprint6-windows-dns-native.json'
& (Join-Path $root 'agent\core\Platform.Agent\bin\Release\net8.0\Platform.Agent.exe')
exit $LASTEXITCODE
