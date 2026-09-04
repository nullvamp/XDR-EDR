param([string]$RepositoryRoot)
$ErrorActionPreference='Stop'
$root=if($RepositoryRoot){(Resolve-Path $RepositoryRoot).Path}else{(Resolve-Path(Join-Path $PSScriptRoot '..\..')).Path};Set-Location $root
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);if(-not$admin){throw 'Elevated Administrator token required.'}
$data=Join-Path $root 'artifacts\sprint5-windows-20260807063635';$log=Join-Path $root 'artifacts\sprint6-windows-pipeline.log';$err=Join-Path $root 'artifacts\sprint6-windows-pipeline.err.log';$exe=Join-Path $root 'agent\core\Platform.Agent\bin\Release\net8.0\Platform.Agent.exe'
$env:PLATFORM_CONTROL_PLANE_URL='https://localhost:8443';$env:PLATFORM_CA_CERT_PATH=Join-Path $root 'deployment\certificates\ca.crt';$env:PLATFORM_AGENT_DATA=$data;$env:PLATFORM_ENVIRONMENT='production';$env:PLATFORM_PROCESS_COLLECTOR='etw';$env:PLATFORM_AGENT_CREDENTIAL_STORE='platform'
function Start-Agent{return Start-Process -FilePath $exe -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError $err -PassThru}
$before=@(Get-ChildItem(Join-Path $data 'dns-queue') -Filter '*.json' -ErrorAction SilentlyContinue).Count
$agent=Start-Agent;Start-Sleep -Seconds 5
$records=[System.Collections.Generic.List[object]]::new()
foreach($type in 'A','AAAA'){try{$answer=Resolve-DnsName example.com -Type $type -DnsOnly -ErrorAction Stop;$records.Add([ordered]@{profile='A';name='example.com';type=$type;answers=@($answer|Where-Object IPAddress|Select-Object -ExpandProperty IPAddress)})}catch{$records.Add([ordered]@{profile='A';name='example.com';type=$type;error=$_.Exception.GetType().Name})}}
try{$answer=Resolve-DnsName www.example.com -Type CNAME -DnsOnly -ErrorAction Stop;$records.Add([ordered]@{profile='B';name='www.example.com';type='CNAME';answers=@($answer|Where-Object NameHost|Select-Object -ExpandProperty NameHost)})}catch{$records.Add([ordered]@{profile='B';name='www.example.com';type='CNAME';error=$_.Exception.GetType().Name})}
$missing="sprint6-$([Guid]::NewGuid().ToString('N')).invalid";try{Resolve-DnsName $missing -Type A -DnsOnly -ErrorAction Stop|Out-Null}catch{$records.Add([ordered]@{profile='B';name=$missing;type='A';negative=$true})}
1..3|ForEach-Object{Resolve-DnsName example.com -Type A -DnsOnly -ErrorAction SilentlyContinue|Out-Null};$records.Add([ordered]@{profile='C';name='example.com';type='A';retries=3})
try{$ips=[System.Net.Dns]::GetHostAddresses('example.com')|Where-Object AddressFamily -eq InterNetwork;$tcp=[System.Net.Sockets.TcpClient]::new();$tcp.Connect($ips[0],80);$tcp.Dispose();$records.Add([ordered]@{profile='E';answer=$ips[0].ToString();connection='tcp/80'})}catch{$records.Add([ordered]@{profile='E';error=$_.Exception.GetType().Name})}
1..100|ForEach-Object{[System.Net.Dns]::GetHostAddresses('example.com')|Out-Null};$records.Add([ordered]@{profile='F';queries=100})
Start-Sleep -Seconds 20;Stop-Process -Id $agent.Id -Force;Wait-Process -Id $agent.Id -ErrorAction SilentlyContinue;Start-Sleep -Seconds 2
$restart=Start-Agent;Start-Sleep -Seconds 12;Stop-Process -Id $restart.Id -Force;Wait-Process -Id $restart.Id -ErrorAction SilentlyContinue;Start-Sleep -Seconds 2
$after=@(Get-ChildItem(Join-Path $data 'dns-queue') -Filter '*.json' -ErrorAction SilentlyContinue).Count
[ordered]@{schema='platform.sprint6.windows-pipeline.v1';executedAt=[DateTimeOffset]::UtcNow;elevated=$admin;dataDirectory=$data;queueBefore=$before;queueAfter=$after;profiles=$records;restartExecuted=$true;passed=$after -eq 0}|ConvertTo-Json -Depth 8|Set-Content artifacts/sprint6-windows-pipeline.json
if($after-ne 0){exit 4};exit 0
