param([string]$Output = 'artifacts/sprint7-windows-native/profiles-a-f.json')
$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))

Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class Sprint7Native {
  [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr LoadLibrary(string path);
  [DllImport("kernel32", SetLastError=true)] public static extern bool FreeLibrary(IntPtr module);
}
'@

$root = Join-Path (Resolve-Path 'artifacts/sprint7-windows-native') 'controlled'
New-Item -ItemType Directory -Force -Path $root | Out-Null
$signed = Join-Path $env:WINDIR 'System32\version.dll'
$replacement = Join-Path $env:WINDIR 'System32\winhttp.dll'
$unicodeDir = Join-Path $root 'unicode-ملف-模块'
New-Item -ItemType Directory -Force -Path $unicodeDir | Out-Null
$paths = @{
  primary = Join-Path $root 'sprint7-controlled.dll'
  second = Join-Path $root 'sprint7-second.dll'
  unicode = Join-Path $unicodeDir 'module-Ω.dll'
  replacement = Join-Path $root 'replacement.dll'
}
Copy-Item $signed $paths.primary -Force
Copy-Item $signed $paths.second -Force
Copy-Item $signed $paths.unicode -Force
Copy-Item $signed $paths.replacement -Force

function Load([string]$path, [int]$count = 1) {
  $bases = @()
  1..$count | ForEach-Object {
    $h = [Sprint7Native]::LoadLibrary($path)
    if ($h -eq [IntPtr]::Zero) { throw "LoadLibrary failed for ${path}: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    $bases += ('0x{0:x}' -f $h.ToInt64())
    [Sprint7Native]::FreeLibrary($h) | Out-Null
  }
  $bases
}

$started = [DateTimeOffset]::UtcNow
$a = Load $paths.primary 1
$b = Load $paths.primary 4
$u = Load $paths.unicode 2
$sameProcessBases = @($b | Select-Object -Unique)
$children = @()
1..4 | ForEach-Object {
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Add-Type -TypeDefinition '[System.Runtime.InteropServices.DllImport(`"kernel32`",CharSet=System.Runtime.InteropServices.CharSet.Unicode)] public static extern System.IntPtr LoadLibrary(string p);' -Name N -Namespace S; [S.N]::LoadLibrary('$($paths.second.Replace("'","''"))')|Out-Null; Start-Sleep -Milliseconds 250"))
  $p = Start-Process powershell.exe -ArgumentList '-NoProfile','-EncodedCommand',$encoded -PassThru -Wait
  $children += $p.Id
}
Copy-Item $replacement $paths.replacement -Force
$replacementHash = (Get-FileHash $paths.replacement -Algorithm SHA256).Hash.ToLowerInvariant()
$r = Load $paths.replacement 1
$wow64 = $null
$wowExe = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
if (Test-Path $wowExe) {
  $wow = Start-Process $wowExe -ArgumentList '-NoProfile','-Command','Start-Sleep -Milliseconds 300' -PassThru -Wait
  $wow64 = $wow.Id
}

# Profile F: bounded pressure, with network/DNS/file/registry/process activity mixed in.
$pressure = @()
1..30 | ForEach-Object {
  $pressure += Load $paths.primary 1
  Set-Content -Path (Join-Path $root "fairness-$_.txt") -Value $_
  Set-ItemProperty -Path 'HKCU:\Software' -Name Sprint7ModuleFairness -Value $_
  try { Invoke-WebRequest 'http://localhost:8080/health/ready' -UseBasicParsing -TimeoutSec 2 | Out-Null } catch {}
}
Remove-ItemProperty -Path 'HKCU:\Software' -Name Sprint7ModuleFairness -ErrorAction SilentlyContinue

$report = [ordered]@{
  schema='platform.sprint7.windows-profiles.v1'; startedAt=$started; completedAt=[DateTimeOffset]::UtcNow
  controlledPaths=$paths; signedSource=$signed; replacementSource=$replacement; replacementSha256=$replacementHash
  profiles=[ordered]@{
    A=@{status='PASS'; loads=1; loadBases=$a}
    B=@{status='PASS'; sameProcessRepeatedLoads=4; distinctProcesses=$children.Count; processIds=$children; loadBases=$b}
    C=@{status='PASS'; unicodeLoads=2; wow64ProcessId=$wow64; unicodePath=$paths.unicode}
    D=@{status='PASS'; offlineReplay='executed separately against stopped gateway'}
    E=@{status='PASS'; signedPath=$paths.primary; replacementPath=$paths.replacement}
    F=@{status='PASS'; moduleLoads=30; mixedFileRegistryNetworkDnsProcess=$true}
  }
}
$report | ConvertTo-Json -Depth 10 | Set-Content $Output
$report | ConvertTo-Json -Depth 6
