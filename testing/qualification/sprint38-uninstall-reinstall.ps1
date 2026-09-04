param(
  [string]$VictimVmName = 'XDR-Victim-Sprint18',
  [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
  [string]$Msi = 'artifacts\sprint38-build-probe8\OpenSecurityPlatform-Agent-1.0.0-x64.msi'
)
$ErrorActionPreference='Stop'
$root=Resolve-Path(Join-Path $PSScriptRoot '..\..');Set-Location $root
$cfg=@{};Get-Content .env|Where-Object{$_-match '^([^#=]+)=(.*)$'}|ForEach-Object{$cfg[$matches[1]]=$matches[2]}
$login=Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/auth/token -ContentType application/json -Body(@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json -Compress)
$headers=@{Authorization="Bearer $($login.access_token)"}
function CurrentInstall { docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select e.id||'|'||e.device_identity||'|'||a.id||'|'||a.instance_id||'|'||e.status||'|'||e.last_seen_at from platform.endpoints e join platform.agents a on a.tenant_id=e.tenant_id and a.endpoint_id=e.id where e.hostname='XDR-VICTIM18' order by e.last_seen_at desc limit 1;" }
$before=(CurrentInstall)
$credential=Import-Clixml $CredentialPath;$session=New-PSSession -VMName $VictimVmName -Credential $credential
try {
  Copy-Item (Resolve-Path $Msi) C:\Sprint38Qualification\agent-final.msi -ToSession $session -Force
  $uninstall=Invoke-Command $session {
    $data='C:\ProgramData\OpenSecurityPlatform\Agent\data'
    $quarantineExisted = Test-Path (Join-Path $data 'protected-quarantine-v1')
    New-Item 'C:\ProgramData\OpenSecurityPlatform\Agent\logs' -ItemType Directory -Force|Out-Null
    Set-Content 'C:\ProgramData\OpenSecurityPlatform\Agent\logs\retention-proof.log' 'preserve-on-uninstall'
    New-NetFirewallRule -DisplayName 'Sprint38 owned cleanup proof' -Group 'OpenSecurityPlatform-Isolation-Sprint38' -Direction Outbound -Action Block -RemoteAddress '192.0.2.1'|Out-Null
    $p=Start-Process msiexec.exe -ArgumentList '/x C:\Sprint38Qualification\agent-final.msi MAINTENANCEAUTHORIZED=1 /qn /norestart /l*v C:\Sprint38Qualification\authorized-uninstall.log' -Wait -PassThru
    [ordered]@{
      exit=$p.ExitCode
      serviceAbsent=-not[bool](Get-Service OpenSecurityPlatformAgent -ErrorAction SilentlyContinue)
      executableAbsent=-not(Test-Path 'C:\Program Files\Open Security Platform\Agent\Platform.Agent.exe')
      stateAbsent=-not(Test-Path (Join-Path $data 'state.dat'))
      activeQueues=@(Get-ChildItem $data -Directory -ErrorAction SilentlyContinue|Where-Object Name -Match 'queue|work|stage|backup').Count
      ownedFirewallRules=@(Get-NetFirewallRule -Group 'OpenSecurityPlatform-Isolation-*' -ErrorAction SilentlyContinue).Count
      quarantinePreserved=$quarantineExisted -and (Test-Path (Join-Path $data 'protected-quarantine-v1'))
      logsPreserved=Test-Path 'C:\ProgramData\OpenSecurityPlatform\Agent\logs\retention-proof.log'
    }
  }
  Start-Sleep 5
  $token=(Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/enrollment-tokens -Headers $headers -ContentType application/json -Body(@{expiresAt=[DateTimeOffset]::UtcNow.AddHours(2).ToString('o');maximumUses=1;allowedPlatforms=@('windows')}|ConvertTo-Json)).data
  $reinstall=Invoke-Command $session -ArgumentList $token.metadata.id,$token.secret {param($id,$secret)
    [ordered]@{controlPlaneUrl='https://gateway:8443';enrollmentTokenId=$id.ToString();enrollmentTokenSecret=$secret;dataDirectory='C:\ProgramData\OpenSecurityPlatform\Agent\data';caCertificatePath='C:\ProgramData\OpenSecurityPlatform\Agent\ca.crt';environment='production';credentialStore='platform';forceCertificateRotation=$false}|ConvertTo-Json|Set-Content C:\ProgramData\OpenSecurityPlatform\Agent\agent-config.json -Encoding utf8
    & icacls.exe C:\ProgramData\OpenSecurityPlatform\Agent /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F'|Out-Null
    $p=Start-Process msiexec.exe -ArgumentList '/i C:\Sprint38Qualification\agent-final.msi /qn /norestart /l*v C:\Sprint38Qualification\reinstall.log' -Wait -PassThru
    $deadline=(Get-Date).AddMinutes(2);do{Start-Sleep 2;$service=Get-Service OpenSecurityPlatformAgent -ErrorAction SilentlyContinue}while((!$service-or$service.Status-ne'Running')-and(Get-Date)-lt$deadline)
    [ordered]@{exit=$p.ExitCode;service=$service.Status.ToString();state=Test-Path C:\ProgramData\OpenSecurityPlatform\Agent\data\state.dat;secretRemoved=-not((Get-Content C:\ProgramData\OpenSecurityPlatform\Agent\agent-config.json -Raw|ConvertFrom-Json).PSObject.Properties.Name-contains'enrollmentTokenSecret');quarantinePreserved=Test-Path C:\ProgramData\OpenSecurityPlatform\Agent\data\protected-quarantine-v1;logsPreserved=Test-Path C:\ProgramData\OpenSecurityPlatform\Agent\logs\retention-proof.log}
  }
  $deadline=(Get-Date).AddMinutes(3);do{Start-Sleep 3;$after=(CurrentInstall)}while(((!$after)-or($after-eq$before))-and(Get-Date)-lt$deadline)
  $bp=$before.Split('|');$ap=$after.Split('|')
  $passed=$uninstall.exit-eq0-and$uninstall.serviceAbsent-and$uninstall.executableAbsent-and$uninstall.stateAbsent-and$uninstall.activeQueues-eq0-and$uninstall.ownedFirewallRules-eq0-and$uninstall.quarantinePreserved-and$uninstall.logsPreserved-and$reinstall.exit-eq0-and$reinstall.service-eq'Running'-and$reinstall.state-and$reinstall.secretRemoved-and$ap[3]-ne$bp[3]
  $report=[ordered]@{schemaVersion='sprint38-uninstall-reinstall.v1';capturedAt=[DateTimeOffset]::UtcNow.ToString('o');victim=$VictimVmName;installationBefore=$before;authorizedUninstall=$uninstall;reinstall=$reinstall;installationAfter=$after;newInstallationIdentity=($ap[3]-ne$bp[3]);serverHistoryPreserved=[bool](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select exists(select 1 from platform.agents where instance_id='$($bp[3])');");passed=$passed}
  $report|ConvertTo-Json -Depth 10|Set-Content artifacts/sprint38-uninstall-reinstall.json -Encoding utf8;$report|ConvertTo-Json -Depth 10
  if(-not$passed){exit 1}
} finally {Remove-PSSession $session}
