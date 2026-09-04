param([string]$RepositoryRoot)
$ErrorActionPreference='Stop';Set-Location $RepositoryRoot;$log=Join-Path $RepositoryRoot 'artifacts\sprint5-profile-run.log'
try{& (Join-Path $RepositoryRoot 'testing\performance\sprint5-windows-network-profiles.ps1') -Output (Join-Path $RepositoryRoot 'artifacts\sprint5-windows-network-profiles.json') *>&1|Out-File $log;exit $LASTEXITCODE}catch{$_|Format-List * -Force|Out-File $log -Append;exit 99}
