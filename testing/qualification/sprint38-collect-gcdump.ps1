param([string]$VictimVmName='XDR-Victim-Sprint18',[string]$CredentialPath='D:\VMs\XDR-Victim-Sprint18\victim-credential.xml')
$ErrorActionPreference='Stop';$root=Resolve-Path(Join-Path $PSScriptRoot '..\..');$credential=Import-Clixml $CredentialPath;$session=New-PSSession -VMName $VictimVmName -Credential $credential
try{
  Invoke-Command $session {Remove-Item C:\Sprint38Qualification\gcdump -Recurse -Force -ErrorAction SilentlyContinue;New-Item C:\Sprint38Qualification\gcdump -ItemType Directory|Out-Null}
  Copy-Item (Join-Path $root '.tooling\diagnostics\.store\dotnet-gcdump\9.0.661903\dotnet-gcdump\9.0.661903\tools\net8.0\any\*') C:\Sprint38Qualification\gcdump -ToSession $session -Recurse -Force
  Copy-Item 'C:\Program Files\dotnet\*' C:\Sprint38Qualification\dotnet -ToSession $session -Recurse -Force
  $result=Invoke-Command $session {$process=Get-Process Platform.Agent;& C:\Sprint38Qualification\dotnet\dotnet.exe C:\Sprint38Qualification\gcdump\dotnet-gcdump.dll collect -p $process.Id -o C:\Sprint38Qualification\agent-final.gcdump;[pscustomobject]@{exit=$LASTEXITCODE;bytes=(Get-Item C:\Sprint38Qualification\agent-final.gcdump -ErrorAction SilentlyContinue).Length;pid=$process.Id;private=$process.PrivateMemorySize64}}
  Copy-Item C:\Sprint38Qualification\agent-final.gcdump (Join-Path $root 'artifacts\sprint38-agent-final.gcdump') -FromSession $session -Force
  $result|ConvertTo-Json
}finally{Remove-PSSession $session}
