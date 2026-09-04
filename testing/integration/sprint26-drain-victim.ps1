param([string]$VictimVmName='XDR-Victim-Sprint18',[string]$CredentialPath='D:\VMs\XDR-Victim-Sprint18\victim-credential.xml',[int]$TimeoutSeconds=240)
$ErrorActionPreference='Stop';$root=Resolve-Path(Join-Path $PSScriptRoot '..\..');Set-Location $root;$publish=Join-Path $root 'artifacts\sprint26-agent-publish';dotnet publish agent/core/Platform.Agent/Platform.Agent.csproj -c Release -r win-x64 --self-contained true -o $publish;if($LASTEXITCODE-ne0){exit $LASTEXITCODE};$credential=Import-Clixml -LiteralPath $CredentialPath;$session=New-PSSession -VMName $VictimVmName -Credential $credential
try {
    Invoke-Command -Session $session -ScriptBlock { Get-Process Platform.Agent -ErrorAction SilentlyContinue|Stop-Process -Force;Start-Sleep 1;New-Item -ItemType Directory -Force 'C:\Sprint26Qualification\drain-agent'|Out-Null;Get-ChildItem 'C:\Sprint26Qualification\drain-agent' -Force -ErrorAction SilentlyContinue|Remove-Item -Recurse -Force }
    Copy-Item (Join-Path $publish '*') -Destination 'C:\Sprint26Qualification\drain-agent' -ToSession $session -Recurse -Force
    $agentPid=Invoke-Command -Session $session -ScriptBlock {
        $qualification='C:\Sprint24Qualification';Get-Process Platform.Agent -ErrorAction SilentlyContinue|Stop-Process -Force
        $env:PLATFORM_CONTROL_PLANE_URL='https://gateway:8443';$env:PLATFORM_AGENT_DATA=Join-Path $qualification 'runtime-data';$env:PLATFORM_CA_CERT_PATH='C:\Sprint19Qualification\ca.crt';$env:PLATFORM_ENVIRONMENT='production';$env:PLATFORM_TELEMETRY_DRAIN_ONLY='true'
        (Start-Process 'C:\Sprint26Qualification\drain-agent\Platform.Agent.exe' -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $qualification 'sprint26-drain.log') -RedirectStandardError (Join-Path $qualification 'sprint26-drain-error.log')).Id
    }
    $deadline=[DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep 3
        $remaining=Invoke-Command -Session $session -ScriptBlock {
            $root='C:\Sprint24Qualification\runtime-data';$counts=@();foreach($name in 'process','file','registry','network','dns','module','persistence','identity','execution'){$path=Join-Path $root "$name-queue";$counts+=if(Test-Path $path){@(Get-ChildItem $path -File -Filter '*.json').Count}else{0}};[long](($counts|Measure-Object -Sum).Sum)
        }
    } while($remaining-ne0-and[DateTimeOffset]::UtcNow-lt$deadline)
    Invoke-Command -Session $session -ScriptBlock { Get-Process Platform.Agent -ErrorAction SilentlyContinue|Stop-Process -Force }|Out-Null
    [pscustomobject]@{agentPid=$agentPid;remaining=$remaining;agentStopped=$true}|ConvertTo-Json
    if($remaining-ne0){exit 1}
}
finally { Remove-PSSession $session }
