param([string]$RepositoryRoot)
$ErrorActionPreference='Stop';$root=(Resolve-Path $RepositoryRoot).Path;Set-Location $root
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);if(-not$admin){throw 'Elevated Administrator token required.'}
$data=Join-Path $root 'artifacts\sprint5-windows-20260807063635';$marker=Join-Path $root 'artifacts\sprint6-offline-workload-ready';$exe=Join-Path $root 'agent\core\Platform.Agent\bin\Release\net8.0\Platform.Agent.exe';Remove-Item $marker -Force -ErrorAction SilentlyContinue
$env:PLATFORM_CONTROL_PLANE_URL='https://localhost:8443';$env:PLATFORM_CA_CERT_PATH=Join-Path $root 'deployment\certificates\ca.crt';$env:PLATFORM_AGENT_DATA=$data;$env:PLATFORM_ENVIRONMENT='production';$env:PLATFORM_PROCESS_COLLECTOR='etw';$env:PLATFORM_AGENT_CREDENTIAL_STORE='platform'
docker stop deployment-gateway-1 | Out-Null
$queryJob=Start-Job -ScriptBlock{1..40|ForEach-Object{Resolve-DnsName "offline-$([Guid]::NewGuid().ToString('N')).invalid" -Type A -DnsOnly -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 100}}
$agent=Start-Process $exe -WindowStyle Hidden -RedirectStandardOutput artifacts/sprint6-offline-agent.log -RedirectStandardError artifacts/sprint6-offline-agent.err.log -PassThru;Wait-Job $queryJob -Timeout 12|Out-Null;Remove-Job $queryJob -Force;Start-Sleep -Seconds 15
$peak=@(Get-ChildItem(Join-Path $data 'dns-queue') -Filter '*.json' -ErrorAction SilentlyContinue).Count;Set-Content $marker $peak
docker start deployment-gateway-1 | Out-Null
$deadline=(Get-Date).AddSeconds(45);do{$depth=@(Get-ChildItem(Join-Path $data 'dns-queue') -Filter '*.json' -ErrorAction SilentlyContinue).Count;if($depth-eq 0){break};Start-Sleep -Seconds 1}while((Get-Date)-lt$deadline)
Stop-Process -Id $agent.Id -Force -ErrorAction SilentlyContinue;Wait-Process -Id $agent.Id -ErrorAction SilentlyContinue
[ordered]@{schema='platform.sprint6.offline-replay.v1';executedAt=[DateTimeOffset]::UtcNow;elevated=$admin;queries=40;queuePeak=$peak;queueAfter=$depth;passed=$peak-gt 0 -and $depth-eq 0}|ConvertTo-Json -Depth 5|Set-Content artifacts/sprint6-offline-replay.json
if($peak-le 0-or$depth-ne 0){exit 4};exit 0
