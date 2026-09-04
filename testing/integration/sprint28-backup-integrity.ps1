$ErrorActionPreference='Stop';$root=Resolve-Path(Join-Path $PSScriptRoot '..\..');Set-Location $root
$source=(Resolve-Path 'artifacts/sprint28-dr/platform-sprint28.dump').Path;$temp=(Join-Path (Split-Path $source) 'tampered-test.dump')
Copy-Item -LiteralPath $source -Destination $temp -Force
try {
  $stream=[IO.File]::Open($temp,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try {$stream.Seek(-1,[IO.SeekOrigin]::End)|Out-Null;$value=$stream.ReadByte();$stream.Seek(-1,[IO.SeekOrigin]::End)|Out-Null;$stream.WriteByte($value -bxor 0xff)} finally {$stream.Dispose()}
  $expected='46de266feeaf686ffb65d084b979f39cda2f72b4a6ceaf7885449bfe17fbb350';$actual=(Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash.ToLowerInvariant()
  $report=[ordered]@{schemaVersion='sprint28-backup-integrity.v1';executedAt=[DateTimeOffset]::UtcNow.ToString('o');expectedSha256=$expected;modifiedSha256=$actual;modifiedArchiveRejected=$actual-ne$expected;restoreAttempted=$false;passed=$actual-ne$expected}
  $report|ConvertTo-Json|Set-Content artifacts/sprint28-backup-integrity.json -Encoding utf8;$report|ConvertTo-Json;if(-not$report.passed){exit 1}
} finally {Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue}
