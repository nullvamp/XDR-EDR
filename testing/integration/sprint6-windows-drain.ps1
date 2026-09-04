param([string]$RepositoryRoot)
$ErrorActionPreference='Stop';$root=(Resolve-Path $RepositoryRoot).Path;Set-Location $root
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);if(-not$admin){throw 'Elevated Administrator token required.'}
$data=Join-Path $root 'artifacts\sprint5-windows-20260807063635';$exe=Join-Path $root 'agent\core\Platform.Agent\bin\Release\net8.0\Platform.Agent.exe'
$env:PLATFORM_CONTROL_PLANE_URL='https://localhost:8443';$env:PLATFORM_CA_CERT_PATH=Join-Path $root 'deployment\certificates\ca.crt';$env:PLATFORM_AGENT_DATA=$data;$env:PLATFORM_ENVIRONMENT='production';$env:PLATFORM_PROCESS_COLLECTOR='etw';$env:PLATFORM_AGENT_CREDENTIAL_STORE='platform'
$before=@(Get-ChildItem(Join-Path $data 'dns-queue') -Filter '*.json' -ErrorAction SilentlyContinue).Count;$agent=Start-Process $exe -WindowStyle Hidden -RedirectStandardOutput artifacts/sprint6-drain-agent.log -RedirectStandardError artifacts/sprint6-drain-agent.err.log -PassThru
$deadline=(Get-Date).AddSeconds(180);do{$depth=@(Get-ChildItem(Join-Path $data 'dns-queue') -Filter '*.json' -ErrorAction SilentlyContinue).Count;if($depth-eq 0){Start-Sleep -Seconds 3;$depth=@(Get-ChildItem(Join-Path $data 'dns-queue') -Filter '*.json' -ErrorAction SilentlyContinue).Count;if($depth-eq 0){break}};Start-Sleep -Seconds 1}while((Get-Date)-lt$deadline)
Stop-Process -Id $agent.Id -Force -ErrorAction SilentlyContinue;Wait-Process -Id $agent.Id -ErrorAction SilentlyContinue
[ordered]@{schema='platform.sprint6.drain.v1';executedAt=[DateTimeOffset]::UtcNow;elevated=$admin;queueBefore=$before;queueAfter=$depth;passed=$before-gt 0 -and $depth-eq 0}|ConvertTo-Json|Set-Content artifacts/sprint6-drain.json
if($depth-ne 0){exit 4};exit 0
