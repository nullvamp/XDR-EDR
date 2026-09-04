param([string]$Dotnet = ".\.tooling\dotnet\dotnet.exe", [int]$Port = 5080)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:PLATFORM_JWT_SIGNING_KEY = "local-smoke-signing-key-with-at-least-32-characters"
$env:PLATFORM_BOOTSTRAP_USER = "smoke-admin"
$env:PLATFORM_BOOTSTRAP_PASSWORD = "smoke-password-long-and-random"
$env:PLATFORM_DATA_DIRECTORY = Join-Path $root "artifacts\smoke-data"
$env:ASPNETCORE_URLS = "http://127.0.0.1:$Port"
$process = Start-Process -FilePath $Dotnet -ArgumentList 'backend\Platform.ServiceHost\bin\Release\net8.0\Platform.ServiceHost.dll' -WorkingDirectory $root -PassThru -WindowStyle Hidden
try {
  $ready = $false
  foreach ($attempt in 1..40) { try { $health = Invoke-RestMethod "http://127.0.0.1:$Port/health/ready"; if ($health.status -eq "ready") { $ready=$true; break } } catch { Start-Sleep -Milliseconds 250 } }
  if (-not $ready) { throw "Service did not become ready" }
  $token = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/api/v1/auth/token" -ContentType "application/json" -Body '{"username":"smoke-admin","password":"smoke-password-long-and-random","tenantId":"root"}'
  $headers = @{Authorization="Bearer $($token.access_token)"}
  $session = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/v1/session" -Headers $headers
  if ($session.data.tenant -ne "root") { throw "Authenticated tenant mismatch" }
  $registration = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/agent/v1/register" -ContentType "application/json" -Body '{"enrollmentToken":"sprint-zero","instanceId":"smoke-agent","tenantId":"root","platform":"test","capabilities":["heartbeat.v1"]}'
  if (-not $registration.data.agent_id) { throw "Agent registration failed" }
  Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/agent/v1/checkins" -ContentType "application/json" -Body ("{`"agentId`":`""+$registration.data.agent_id+"`",`"tenantId`":`"root`",`"status`":`"healthy`",`"version`":`"0.1.0`",`"capabilities`":[`"heartbeat.v1`"]}") | Out-Null
  Invoke-WebRequest "http://127.0.0.1:$Port/" -UseBasicParsing | Out-Null
  Write-Output "SMOKE PASS: health, authentication, API, agent registration, heartbeat, frontend"
} finally { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
