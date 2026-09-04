param(
  [string]$Output = 'artifacts/sprint7-windows-native/profiles-c-e-remediation.json',
  [string]$EndpointId = '78137cff-c605-4331-a150-4fa6c8020109'
)
$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))

function Assert([bool]$condition, [string]$message) { if (-not $condition) { throw $message } }
function Sql([string]$query) { (& docker exec deployment-postgres-1 psql -U platform -d platform -Atc $query) -join "`n" }
function Rows([string]$basename, [DateTimeOffset]$from) {
  $text = Sql "select event_data::text from platform.module_events where endpoint_id='$EndpointId' and basename='$basename' and event_type='ImageLoaded' and observed_at >= '$($from.ToString('o'))' order by observed_at"
  if ([string]::IsNullOrWhiteSpace($text)) { return @() }
  @($text -split "`n" | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
}
function Wait-Rows([string]$basename, [DateTimeOffset]$from, [int]$expected = 1) {
  $deadline = [DateTimeOffset]::UtcNow.AddSeconds(120)
  do { Start-Sleep 2; $rows = @(Rows $basename $from) } while ($rows.Count -lt $expected -and [DateTimeOffset]::UtcNow -lt $deadline)
  Assert ($rows.Count -eq $expected) "Expected exactly $expected reconciled load for $basename; observed $($rows.Count)."
  $rows
}
function Os-Count([string]$basename) {
  & docker exec deployment-opensearch-1 curl -fsS -X POST http://localhost:9200/platform-module-events/_refresh | Out-Null
  [int]((& docker exec deployment-opensearch-1 curl -fsS "http://localhost:9200/platform-module-events/_count?q=basename:%22$basename%22") | ConvertFrom-Json).count
}
function Pg-Count([string]$basename) { [int](Sql "select count(*) from platform.module_events where endpoint_id='$EndpointId' and basename='$basename'").Trim() }
function Native-Id([string]$path) { ((& fsutil file queryfileid $path) | Out-String).Trim() }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
Assert $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 'Elevated Administrator token is required.'
Assert ((Sql "select count(*) from platform.module_policy_acknowledgements a join platform.module_policy_assignments s on s.endpoint_id=a.endpoint_id and s.policy_id=a.policy_id where a.endpoint_id='$EndpointId' and a.applied=true and a.policy_id=(select policy_id from platform.module_policy_assignments where endpoint_id='$EndpointId')").Trim() -eq '1') 'The active module policy is not acknowledged.'

$buildId = [Guid]::NewGuid().ToString('N').Substring(0, 10)
$out = Join-Path (Resolve-Path 'artifacts/sprint7-windows-native') "remediation-bin-$buildId"
$fixture = 'testing\fixtures\sprint7-native-module'
$vc = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat'
Assert (Test-Path $vc) 'Visual C++ Build Tools are required for the controlled native fixtures.'
New-Item -ItemType Directory -Force $out | Out-Null
& cmd.exe /d /c "call `"$vc`" x64 >nul && cl /nologo /W4 /WX /O2 /MT /LD /DMODULE_VERSION=1 $fixture\module.c /link /OUT:$out\module-a-x64.dll && cl /nologo /W4 /WX /O2 /MT /LD /DMODULE_VERSION=2 $fixture\module.c /link /OUT:$out\module-b-x64.dll && cl /nologo /W4 /WX /O2 /MT $fixture\loader.c /link /SUBSYSTEM:CONSOLE /OUT:$out\loader-x64.exe"
Assert ($LASTEXITCODE -eq 0) 'x64 fixture build failed.'
& cmd.exe /d /c "call `"$vc`" x86 >nul && cl /nologo /W4 /WX /O2 /MT /LD /DMODULE_VERSION=3 $fixture\module.c /link /OUT:$out\module-wow64-x86.dll && cl /nologo /W4 /WX /O2 /MT $fixture\loader.c /link /SUBSYSTEM:CONSOLE /OUT:$out\loader-x86.exe"
Assert ($LASTEXITCODE -eq 0) 'x86 fixture build failed.'
$unsigned = @("$out\module-a-x64.dll", "$out\module-b-x64.dll", "$out\module-wow64-x86.dll") | ForEach-Object { Get-AuthenticodeSignature $_ }
Assert (@($unsigned | Where-Object Status -ne 'NotSigned').Count -eq 0) 'A controlled fixture is not genuinely unsigned.'

$run = [Guid]::NewGuid().ToString('N').Substring(0, 10)
$controlled = Join-Path (Resolve-Path 'artifacts/sprint7-windows-native/controlled') "remediation-$run"
$unicodeName = 'unicode-' + [char]0x0645 + [char]0x0644 + [char]0x0641 + '-' + [char]0x6a21 + [char]0x5757 + '-' + [char]0x03a9
$unicode = Join-Path $controlled $unicodeName
New-Item -ItemType Directory -Force $unicode | Out-Null
$c64Name = "c-$run-unicode.dll"; $c86Name = "c-$run-wow64.dll"
$c64 = Join-Path $unicode $c64Name; $c86 = Join-Path $unicode $c86Name
Copy-Item "$out\module-a-x64.dll" $c64; Copy-Item "$out\module-wow64-x86.dll" $c86
$cStarted = [DateTimeOffset]::UtcNow
$p64 = Start-Process "$out\loader-x64.exe" -ArgumentList "`"$c64`"",'120000' -PassThru -WindowStyle Hidden
$p86 = Start-Process "$out\loader-x86.exe" -ArgumentList "`"$c86`"",'120000' -PassThru -WindowStyle Hidden
try { $c64Rows = @(Wait-Rows $c64Name $cStarted); $c86Rows = @(Wait-Rows $c86Name $cStarted) }
finally { $p64,$p86 | Where-Object { -not $_.HasExited } | Stop-Process -Force }
$cRows = @($c64Rows + $c86Rows)
Assert ($cRows[0].architecture -eq 'x64' -and $cRows[1].architecture -eq 'x86') 'x64/WOW64 architecture reconciliation failed.'
Assert (@($cRows | Where-Object { $_.process.attributionConfidence -ne 'high' -or -not $_.process.processEntityId }).Count -eq 0) 'Full process attribution was not retained.'
Assert (@($cRows | Where-Object { -not $_.backingFileIdentity.fileId }).Count -eq 0) 'Backing identity was not recorded.'
$arabic = [string]([char]0x0645) + [char]0x0644 + [char]0x0641; $cjk = [string]([char]0x6a21) + [char]0x5757
Assert (@($cRows | Where-Object { -not $_.originalPath.Contains($arabic) -or -not $_.normalizedPath.Contains($cjk) }).Count -eq 0) 'Unicode/native path provenance was not retained.'

$eName = "e-$run-replacement.dll"; $ePath = Join-Path $controlled $eName
Copy-Item "$out\module-a-x64.dll" $ePath
$hashA = (Get-FileHash $ePath -Algorithm SHA256).Hash.ToLowerInvariant(); $nativeA = Native-Id $ePath; $aStarted = [DateTimeOffset]::UtcNow
$pa = Start-Process "$out\loader-x64.exe" -ArgumentList "`"$ePath`"",'30000' -PassThru -WindowStyle Hidden
$aRows = @(Wait-Rows $eName $aStarted); $pa.WaitForExit(); Assert ($pa.ExitCode -eq 0) 'Version A loader failed.'
$temp = "$ePath.new"; Copy-Item "$out\module-b-x64.dll" $temp; Move-Item $temp $ePath -Force
$hashB = (Get-FileHash $ePath -Algorithm SHA256).Hash.ToLowerInvariant(); $nativeB = Native-Id $ePath; $bStarted = [DateTimeOffset]::UtcNow
Assert ($hashA -ne $hashB -and $nativeA -ne $nativeB) 'Replacement did not create distinct content and native identity.'
$pb = Start-Process "$out\loader-x64.exe" -ArgumentList "`"$ePath`"",'30000' -PassThru -WindowStyle Hidden
$bRows = @(Wait-Rows $eName $bStarted); $pb.WaitForExit(); Assert ($pb.ExitCode -eq 0) 'Version B loader failed.'
$eRows = @($aRows + $bRows)
Assert ($eRows[0].hash.value -eq $hashA -and $eRows[1].hash.value -eq $hashB) 'Replacement hashes did not remain bound to their mappings.'
Assert ($eRows[0].backingFileIdentity.fileId -ne $eRows[1].backingFileIdentity.fileId) 'Replacement backing identities collapsed.'
Assert (@($eRows | Where-Object { $_.signer.signedState -ne 'unsigned' -or $_.signer.verificationStatus -ne 'no-embedded-signature' -or $_.signer.verificationSource -ne 'pe-authenticode-security-directory' }).Count -eq 0) 'Exact unsigned signer result/provenance failed.'

$allNames = @($c64Name, $c86Name, $eName); $pgCounts = @{}; $osCounts = @{}
foreach ($name in $allNames) { $pgCounts[$name] = Pg-Count $name; $osCounts[$name] = Os-Count $name }
Assert (@($allNames | Where-Object { $pgCounts[$_] -ne $osCounts[$_] }).Count -eq 0) 'OpenSearch controlled-workload reconciliation failed.'
$report = [ordered]@{
  schema='platform.sprint7.profiles-c-e-remediation.v1'; executedAt=[DateTimeOffset]::UtcNow; endpointId=$EndpointId; runId=$run
  profileC=@{status='PASS'; expectedLoads=2; postgresLoads=2; postgresDocuments=$pgCounts[$c64Name]+$pgCounts[$c86Name]; openSearchDocuments=$osCounts[$c64Name]+$osCounts[$c86Name]; events=$cRows}
  profileE=@{status='PASS'; expectedLoads=2; postgresLoads=2; postgresDocuments=$pgCounts[$eName]; openSearchDocuments=$osCounts[$eName]; hashA=$hashA; hashB=$hashB; nativeIdA=$nativeA; nativeIdB=$nativeB; events=$eRows}
  unsignedFixtures=@($unsigned | ForEach-Object { @{path=$_.Path; authenticodeStatus=$_.Status.ToString()} })
}
$report | ConvertTo-Json -Depth 20 | Set-Content $Output
$report | ConvertTo-Json -Depth 8
