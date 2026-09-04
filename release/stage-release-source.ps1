param([Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference='Stop'
$root=(Resolve-Path(Join-Path $PSScriptRoot '..')).Path
$destination=[IO.Path]::GetFullPath($Destination)
if(Test-Path $destination){throw "Isolated source destination already exists: $destination"}
New-Item $destination -ItemType Directory|Out-Null
$topFiles=@('Directory.Build.props','Directory.Packages.props','NuGet.Config','global.json','SecurityPlatform.sln')
$topDirectories=@('agent','backend','shared','infrastructure','frontend','release','storage','deployment')
$excludedSegments=@('\bin\','\obj\','\.tooling\','\artifacts\','\release-output\','\certificates\','\backup\','\backups\','\logs\')
$sources=@($topFiles|ForEach-Object{Join-Path $root $_})+@($topDirectories|ForEach-Object{Join-Path $root $_})
$files=@(foreach($source in $sources){
  if(-not(Test-Path $source)){continue}
  if(Test-Path $source -PathType Leaf){Get-Item $source;continue}
  Get-ChildItem $source -File -Recurse|Where-Object{
    $path=$_.FullName.ToLowerInvariant();-not($excludedSegments|Where-Object{$path.Contains($_)})
  }
})
foreach($file in $files){
  $relative=$file.FullName.Substring($root.Length).TrimStart('\')
  $target=Join-Path $destination $relative
  New-Item (Split-Path $target) -ItemType Directory -Force|Out-Null
  Copy-Item $file.FullName $target
}
$manifest=[ordered]@{
  schemaVersion='isolated-release-source.v1'
  createdAt=[DateTimeOffset]::UtcNow.ToString('o')
  sourceRoot=$root
  commit=(git -C $root rev-parse HEAD).Trim()
  dirtyEntries=@(git -C $root status --porcelain).Count
  includeRoots=$topDirectories
  excludedSegments=$excludedSegments
  fileCount=$files.Count
  files=@($files|ForEach-Object{$relative=$_.FullName.Substring($root.Length).TrimStart('\');[ordered]@{path=$relative.Replace('\','/');sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant();bytes=$_.Length}}|Sort-Object path)
}
$manifest|ConvertTo-Json -Depth 7|Set-Content (Join-Path $destination 'isolated-source-manifest.json') -Encoding utf8
[pscustomobject]$manifest|Select-Object schemaVersion,createdAt,commit,dirtyEntries,fileCount|ConvertTo-Json
