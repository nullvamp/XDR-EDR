param(
  [string]$VictimVmName = 'XDR-Victim-Sprint18',
  [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',
  [string]$Msi = 'artifacts\sprint38-build-probe8\OpenSecurityPlatform-Agent-1.0.0-x64.msi'
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $root
$credential = Import-Clixml $CredentialPath
$msi = (Resolve-Path $Msi).Path
function Get-CurrentInstallation {
  $row = docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select e.id||'|'||e.device_identity||'|'||a.id||'|'||a.instance_id||'|'||e.last_seen_at from platform.endpoints e join platform.agents a on a.tenant_id=e.tenant_id and a.endpoint_id=e.id where e.hostname='XDR-VICTIM18' and e.status='online' order by e.last_seen_at desc limit 1;"
  if (-not $row) { return $null }
  $parts = $row.Split('|')
  [ordered]@{ endpointId=$parts[0]; deviceIdentity=$parts[1]; agentId=$parts[2]; installationId=$parts[3]; lastSeenAt=$parts[4] }
}
$installationBefore = Get-CurrentInstallation
$session = New-PSSession -VMName $VictimVmName -Credential $credential
try {
  Copy-Item $msi C:\Sprint38Qualification\agent-final.msi -ToSession $session -Force
  $result = Invoke-Command $session {
    $agent = 'C:\Program Files\Open Security Platform\Agent\Platform.Agent.exe'
    $data = 'C:\ProgramData\OpenSecurityPlatform\Agent\data'
    $state = Join-Path $data 'state.dat'
    function Snapshot([string]$name) {
      [ordered]@{
        name = $name
        service = (Get-Service OpenSecurityPlatformAgent -ErrorAction SilentlyContinue).Status.ToString()
        executable = Test-Path $agent
        state = Test-Path $state
        stateMetadata = if (Test-Path $state) { $item=Get-Item $state; "$($item.Length):$($item.LastWriteTimeUtc.Ticks)" } else { $null }
        version = if (Test-Path $agent) { (Get-Item $agent).VersionInfo.ProductVersion } else { $null }
      }
    }
    $before = Snapshot 'before'
    $repeat = Start-Process msiexec.exe -ArgumentList '/i C:\Sprint38Qualification\agent-final.msi /qn /norestart /l*v C:\Sprint38Qualification\repeat.log' -Wait -PassThru
    $afterRepeat = Snapshot 'afterRepeat'
    $repair = Start-Process msiexec.exe -ArgumentList '/fa C:\Sprint38Qualification\agent-final.msi /qn /norestart /l*v C:\Sprint38Qualification\repair.log' -Wait -PassThru
    $afterRepair = Snapshot 'afterRepair'
    $unauthorized = Start-Process msiexec.exe -ArgumentList '/x C:\Sprint38Qualification\agent-final.msi /qn /norestart /l*v C:\Sprint38Qualification\unauthorized-uninstall.log' -Wait -PassThru
    $afterUnauthorized = Snapshot 'afterUnauthorized'
    [ordered]@{
      before = $before
      repeatedInstallExit = $repeat.ExitCode
      afterRepeatedInstall = $afterRepeat
      repairExit = $repair.ExitCode
      afterRepair = $afterRepair
      unauthorizedUninstallExit = $unauthorized.ExitCode
      afterUnauthorizedUninstall = $afterUnauthorized
      passed = $repeat.ExitCode -eq 0 -and $repair.ExitCode -eq 0 -and $unauthorized.ExitCode -eq 1603 -and
        $afterRepeat.state -and $afterRepair.state -and $afterUnauthorized.state -and
        $afterUnauthorized.service -eq 'Running' -and $afterUnauthorized.executable
    }
  }
  $report = [ordered]@{
    schemaVersion = 'sprint38-installer-lifecycle.v1'
    capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
    victim = $VictimVmName
    installationBefore = $installationBefore
    installationAfter = (Get-CurrentInstallation)
    result = $result
  }
  $report.result.passed = $report.result.passed -and $report.installationBefore -and
    $report.installationBefore.endpointId -eq $report.installationAfter.endpointId -and
    $report.installationBefore.installationId -eq $report.installationAfter.installationId
  $report | ConvertTo-Json -Depth 10 | Set-Content artifacts/sprint38-installer-lifecycle.json -Encoding utf8
  $report | ConvertTo-Json -Depth 10
  if (-not $result.passed) { exit 1 }
}
finally {
  Remove-PSSession $session
}
