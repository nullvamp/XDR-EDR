param([string]$VictimVmName='XDR-Victim-Sprint18',[string]$CredentialPath='D:\VMs\XDR-Victim-Sprint18\victim-credential.xml')
$ErrorActionPreference='Stop'
$credential=Import-Clixml $CredentialPath
$result=Invoke-Command -VMName $VictimVmName -Credential $credential -ScriptBlock {
    $output='C:\Sprint22Qualification\file-etw-regression.json'
    Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue
    $env:PLATFORM_AGENT_DATA='C:\Sprint22Qualification\etw-regression-data'
    $env:PLATFORM_WINDOWS_FILE_COLLECTOR_SELF_TEST='true'
    $env:PLATFORM_WINDOWS_FILE_COLLECTOR_SELF_TEST_OUTPUT=$output
    $process=Start-Process 'C:\Sprint22Qualification\agent\Platform.Agent.exe' -Wait -PassThru -WindowStyle Hidden
    [pscustomobject]@{exitCode=$process.ExitCode;evidence=if(Test-Path $output){Get-Content $output -Raw|ConvertFrom-Json}else{$null}}
}
$result|ConvertTo-Json -Depth 30|Set-Content artifacts/sprint22-file-etw-regression.json -Encoding utf8
$result|ConvertTo-Json -Depth 30
if($result.exitCode-ne0){exit 1}
