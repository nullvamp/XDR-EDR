$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$env:PLATFORM_WINDOWS_FILE_COLLECTOR_PRIVILEGE_SELF_TEST='true'
$env:PLATFORM_WINDOWS_FILE_COLLECTOR_PRIVILEGE_SELF_TEST_OUTPUT=(Join-Path $root 'artifacts\sprint3h-windows-insufficient-privilege.json')
& (Join-Path $root 'agent\core\Platform.Agent\bin\Release\net8.0\Platform.Agent.exe')
exit $LASTEXITCODE
