param([string]$Version='1.0.0',[string]$Output='release-output',[string]$WixPath='.tooling/release-tools/wix.exe',[string]$SourceCommit='')
$ErrorActionPreference='Stop'
$root=Resolve-Path(Join-Path $PSScriptRoot '..');Set-Location $root
$outputPath=if([IO.Path]::IsPathRooted($Output)){[IO.Path]::GetFullPath($Output)}else{[IO.Path]::GetFullPath((Join-Path $root $Output))};$payload=Join-Path $outputPath 'agent-win-x64'
if(Test-Path $outputPath){throw "Release output already exists: $outputPath"}
New-Item $payload -ItemType Directory -Force|Out-Null
dotnet restore agent/core/Platform.Agent/Platform.Agent.csproj -r win-x64 --locked-mode
if($LASTEXITCODE-ne0){throw 'Locked restore failed'}
dotnet publish agent/core/Platform.Agent/Platform.Agent.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:DebugType=None -p:DebugSymbols=false -o $payload --no-restore
if($LASTEXITCODE-ne0){throw 'Agent publish failed'}
Copy-Item release/windows/agent-config.example.json $payload
$wix=if([IO.Path]::IsPathRooted($WixPath)){[IO.Path]::GetFullPath($WixPath)}else{[IO.Path]::GetFullPath((Join-Path $root $WixPath))};if(-not(Test-Path $wix)){throw 'Pinned WiX 6.0.2 tool is required'}
&$wix build release/windows/AgentInstaller.wxs -arch x64 -d "Payload=$payload" -d "Version=$Version" -o (Join-Path $outputPath "OpenSecurityPlatform-Agent-$Version-x64.msi")
if($LASTEXITCODE-ne0){throw 'MSI build failed'}
Compress-Archive -Path "$payload\*" -DestinationPath (Join-Path $outputPath "OpenSecurityPlatform-Agent-$Version-x64.zip") -CompressionLevel Optimal
if(-not$SourceCommit){$SourceCommit=try{(git rev-parse HEAD 2>$null).Trim()}catch{'unknown'}}
[pscustomobject]@{schemaVersion='release-build.v1';version=$Version;builtAt=[DateTimeOffset]::UtcNow.ToString('o');commit=$SourceCommit;dotnet=(dotnet --version).Trim();wix=(&$wix --version).Trim();dependencyLockMode='locked';artifacts=@(Get-ChildItem $outputPath -File|ForEach-Object{@{name=$_.Name;bytes=$_.Length;sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $outputPath 'build-report.json') -Encoding utf8
