param([switch]$Docker)
$ErrorActionPreference="Stop"
$root=Split-Path -Parent $PSScriptRoot
if($Docker){
  & (Join-Path $PSScriptRoot "bootstrap-docker.ps1")
  exit $LASTEXITCODE
}
& (Join-Path $PSScriptRoot "build.ps1") Release
if($LASTEXITCODE){exit $LASTEXITCODE}
$dotnet=Join-Path $root ".tooling\dotnet\dotnet.exe";if(-not(Test-Path $dotnet)){$dotnet="dotnet"}
$services=@("gateway","authentication","endpoints","policy","detection","response","threat-intelligence","timeline","evidence","cases","notifications","plugins","ai-gateway")
$run=Join-Path $root "artifacts\run";New-Item -ItemType Directory -Force $run|Out-Null
$env:PLATFORM_JWT_SIGNING_KEY="local-development-key-change-before-use-123456"
$env:PLATFORM_ENROLLMENT_PEPPER="local-development-pepper-change-before-use-123"
$env:PLATFORM_BOOTSTRAP_USER="admin";$env:PLATFORM_BOOTSTRAP_PASSWORD="local-development-password-change-before-use"
$gatewayPort=5080
for($i=0;$i-lt $services.Count;$i++){
  $service=$services[$i];$port=$gatewayPort+$i
  $startInfo=New-Object System.Diagnostics.ProcessStartInfo
  $startInfo.FileName=$dotnet;$startInfo.WorkingDirectory=$root;$startInfo.UseShellExecute=$false;$startInfo.CreateNoWindow=$true
  $startInfo.Arguments='"backend\Platform.ServiceHost\bin\Release\net8.0\Platform.ServiceHost.dll"'
  $startInfo.EnvironmentVariables["PLATFORM_SERVICE_NAME"]=$service;$startInfo.EnvironmentVariables["ASPNETCORE_URLS"]="http://127.0.0.1:$port";$startInfo.EnvironmentVariables["PLATFORM_DATA_DIRECTORY"]=(Join-Path $run $service);$startInfo.EnvironmentVariables["PLATFORM_JWT_SIGNING_KEY"]=$env:PLATFORM_JWT_SIGNING_KEY;$startInfo.EnvironmentVariables["PLATFORM_BOOTSTRAP_USER"]=$env:PLATFORM_BOOTSTRAP_USER;$startInfo.EnvironmentVariables["PLATFORM_BOOTSTRAP_PASSWORD"]=$env:PLATFORM_BOOTSTRAP_PASSWORD
  if($service-ne"gateway"){$startInfo.EnvironmentVariables["PLATFORM_REGISTRY_URL"]="http://127.0.0.1:$gatewayPort"}
  $p=[System.Diagnostics.Process]::Start($startInfo);Set-Content (Join-Path $run "$service.pid") $p.Id
}
$agentInfo=New-Object System.Diagnostics.ProcessStartInfo;$agentInfo.FileName=$dotnet;$agentInfo.WorkingDirectory=$root;$agentInfo.UseShellExecute=$false;$agentInfo.CreateNoWindow=$true;$agentInfo.Arguments='"agent\core\Platform.Agent\bin\Release\net8.0\Platform.Agent.dll"';$agentInfo.EnvironmentVariables["PLATFORM_CONTROL_PLANE_URL"]="http://127.0.0.1:$gatewayPort";$agentInfo.EnvironmentVariables["PLATFORM_AGENT_DATA"]=(Join-Path $run "agent");$agentInfo.EnvironmentVariables["PLATFORM_ENROLLMENT_TOKEN"]="sprint-zero";$agent=[System.Diagnostics.Process]::Start($agentInfo);Set-Content (Join-Path $run "agent.pid") $agent.Id
Write-Output "Started 13 services and one agent. UI/API: http://127.0.0.1:5080. Run scripts/stop.ps1 to stop."
