param(
    [ValidateSet('All','AB','CDE')][string]$Profiles = 'All',
    [int]$ObservationSeconds = 8,
    [string]$Output = 'artifacts/sprint9-windows-profiles.json'
)
$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$rows = [Collections.Generic.List[object]]::new()
function Record([string]$profile,[string]$operation,[string]$target) {
    $rows.Add([ordered]@{ profile=$profile; operation=$operation; target=$target; at=[DateTimeOffset]::UtcNow.ToString('o') })
    Start-Sleep -Seconds $ObservationSeconds
}
function Remove-WmiObjectSafe([string]$path) { if ($path) { try { ([wmi]$path).Delete() | Out-Null } catch {} } }

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$comKey = 'HKCU:\Software\Classes\CLSID\{9A978E15-4D93-4B85-AF63-0A983787D909}'
$shellKey = 'HKCU:\Software\Classes\OSP.Sprint9.Probe\shell\open\command'
$ifeoKey = 'HKCU:\Software\OpenSecurityPlatform\Sprint9\IFEO'
$startupFile = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)) 'OSP-Sprint9-Probe.cmd'
$filterPaths = [Collections.Generic.List[string]]::new(); $consumerPaths = [Collections.Generic.List[string]]::new(); $bindingPaths = [Collections.Generic.List[string]]::new()
try {
    if ($Profiles -in @('All','AB')) {
        if (-not $isAdmin) { throw 'Profiles A-B require an elevated Administrator process.' }
        $filterClass = [wmiclass]'\\.\root\subscription:__EventFilter'
        $consumerClass = [wmiclass]'\\.\root\subscription:CommandLineEventConsumer'
        $bindingClass = [wmiclass]'\\.\root\subscription:__FilterToConsumerBinding'
        foreach ($suffix in @('A','B1','B2')) {
            $profile = if ($suffix -eq 'A') { 'A' } else { 'B' }
            $f=$filterClass.CreateInstance();$f.Name="OSP-Sprint9-$suffix";$f.EventNamespace='root\cimv2';$f.QueryLanguage='WQL';$f.Query="SELECT * FROM __InstanceCreationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='OSP-Sprint9-Never-$suffix.exe'";$filterPath=$f.Put().Path;$filterPaths.Add($filterPath);Record $profile 'filter-created' $filterPath
            $c=$consumerClass.CreateInstance();$c.Name="OSP-Sprint9-$suffix";$c.CommandLineTemplate='cmd.exe /c exit 0 --token=sprint9-secret';$consumerPath=$c.Put().Path;$consumerPaths.Add($consumerPath);Record $profile 'consumer-created' $consumerPath
            if ($suffix -ne 'B2') {$b=$bindingClass.CreateInstance();$b.Filter=$filterPath;$b.Consumer=$consumerPath;$bindingPath=$b.Put().Path;$bindingPaths.Add($bindingPath);Record $profile 'binding-created' $bindingPath}
        }
        $bindingPaths[0] | ForEach-Object { Remove-WmiObjectSafe $_; Record 'A' 'binding-deleted' $_ }
        $consumerPaths[0] | ForEach-Object { Remove-WmiObjectSafe $_; Record 'A' 'consumer-deleted' $_ }
        $filterPaths[0] | ForEach-Object { Remove-WmiObjectSafe $_; Record 'A' 'filter-deleted' $_ }
        $f=$filterClass.CreateInstance();$f.Name='OSP-Sprint9-A';$f.EventNamespace='root\cimv2';$f.QueryLanguage='WQL';$f.Query="SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='OSP-Sprint9-Never-Recreated.exe'";$recreated=$f.Put().Path;$filterPaths.Add($recreated);Record 'B' 'filter-recreated' $recreated
    }
    if ($Profiles -in @('All','CDE')) {
        New-Item -Path $runKey -Force | Out-Null
        New-ItemProperty -Path $runKey -Name 'OSP-Sprint9-Probe' -Value 'cmd.exe /c exit 0' -PropertyType String -Force | Out-Null; Record 'C' 'autorun-created' "$runKey::OSP-Sprint9-Probe"
        Set-ItemProperty -Path $runKey -Name 'OSP-Sprint9-Probe' -Value 'cmd.exe /c exit 0 /updated'; Record 'C' 'autorun-modified' "$runKey::OSP-Sprint9-Probe"
        Remove-ItemProperty -Path $runKey -Name 'OSP-Sprint9-Probe'; Record 'C' 'autorun-deleted' "$runKey::OSP-Sprint9-Probe"
        New-ItemProperty -Path $runKey -Name 'OSP-Sprint9-Probe' -Value 'cmd.exe /c exit 0 /recreated' -PropertyType String -Force | Out-Null; Record 'C' 'autorun-recreated' "$runKey::OSP-Sprint9-Probe"
        Set-Content -LiteralPath $startupFile -Value '@rem Open Security Platform Sprint 9 harmless fixture' -Encoding ascii; Record 'D' 'startup-created' $startupFile
        Add-Content -LiteralPath $startupFile -Value '@rem modified'; Record 'D' 'startup-modified' $startupFile
        Remove-Item -LiteralPath $startupFile -Force; Record 'D' 'startup-deleted' $startupFile
        New-Item -Path (Join-Path $comKey 'InprocServer32') -Force | Out-Null; Set-Item -Path (Join-Path $comKey 'InprocServer32') -Value 'C:\OSP-Sprint9\unicode-Δ.dll'; Record 'E' 'com-created' $comKey
        Set-Item -Path (Join-Path $comKey 'InprocServer32') -Value 'C:\OSP-Sprint9\updated.dll'; Record 'E' 'com-modified' $comKey
        New-Item -Path $shellKey -Force | Out-Null; Set-Item -Path $shellKey -Value 'cmd.exe /c exit 0'; Record 'E' 'shell-command-created' $shellKey
        New-Item -Path $ifeoKey -Force | Out-Null; New-ItemProperty -Path $ifeoKey -Name 'OSP-Sprint9-Probe.exe.DebuggerMetadata' -Value 'C:\OSP-Sprint9\fixture.exe' -PropertyType String -Force | Out-Null; Record 'E' 'ifeo-test-created' $ifeoKey
        Remove-Item -LiteralPath $comKey -Recurse -Force; Record 'E' 'com-deleted' $comKey
        New-Item -Path (Join-Path $comKey 'InprocServer32') -Force | Out-Null; Set-Item -Path (Join-Path $comKey 'InprocServer32') -Value 'C:\OSP-Sprint9\recreated.dll'; Record 'E' 'com-recreated' $comKey
    }
}
finally {
    foreach ($path in @($bindingPaths)) { Remove-WmiObjectSafe $path }
    foreach ($path in @($consumerPaths)) { Remove-WmiObjectSafe $path }
    foreach ($path in @($filterPaths)) { Remove-WmiObjectSafe $path }
    Remove-ItemProperty -Path $runKey -Name 'OSP-Sprint9-Probe' -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $startupFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $comKey -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'HKCU:\Software\Classes\OSP.Sprint9.Probe' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'HKCU:\Software\OpenSecurityPlatform\Sprint9' -Recurse -Force -ErrorAction SilentlyContinue
}
$report=[ordered]@{schema='platform.sprint9.windows-profiles.v1';capturedAt=[DateTimeOffset]::UtcNow.ToString('o');administrator=$isAdmin;profiles=$Profiles;operations=$rows;cleanupVerified=(-not(Test-Path $startupFile) -and $null -eq (Get-ItemProperty -Path $runKey -Name 'OSP-Sprint9-Probe' -ErrorAction SilentlyContinue))}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Output -Encoding utf8
$report | ConvertTo-Json -Depth 6
