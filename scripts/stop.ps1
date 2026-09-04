$root=Split-Path -Parent $PSScriptRoot
$run=Join-Path $root "artifacts\run"
Get-ChildItem $run -Filter *.pid -ErrorAction SilentlyContinue|ForEach-Object{$id=[int](Get-Content $_.FullName);Stop-Process -Id $id -ErrorAction SilentlyContinue}
Write-Output "Stopped local Sprint Zero services."
