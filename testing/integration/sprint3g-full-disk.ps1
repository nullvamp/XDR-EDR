param(
    [string]$Image = "deployment-agent:latest",
    [string]$Output = "artifacts/sprint3g-full-disk-matrix.json",
    [switch]$Build
)

$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$outputPath = [IO.Path]::GetFullPath((Join-Path $repositoryRoot $Output))
$artifactDirectory = Split-Path $outputPath -Parent
$artifactName = Split-Path $outputPath -Leaf
New-Item -ItemType Directory -Force -Path $artifactDirectory | Out-Null

if ($Build) {
    docker compose --env-file (Join-Path $repositoryRoot ".env") `
        -f (Join-Path $repositoryRoot "deployment\docker-compose.yml") build agent
    if ($LASTEXITCODE -ne 0) { throw "Agent image build failed." }
}

# /bounded is an isolated 16 MiB in-memory filesystem. The product self-test also
# refuses to execute against any filesystem larger than 64 MiB, so this command
# cannot consume the host system disk. --rm is the complete cleanup operation.
docker run --rm --user 0:0 `
    --tmpfs "/bounded:rw,size=16m,mode=0700" `
    --mount "type=bind,source=$artifactDirectory,target=/artifacts" `
    --env PLATFORM_FILE_DISK_SELF_TEST=true `
    --env PLATFORM_FILE_DISK_SELF_TEST_ROOT=/bounded `
    --env "PLATFORM_FILE_DISK_SELF_TEST_OUTPUT=/artifacts/$artifactName" `
    $Image
if ($LASTEXITCODE -ne 0) { throw "Bounded full-disk matrix failed." }

$report = Get-Content -Raw $outputPath | ConvertFrom-Json
if (-not $report.passed -or $report.volumeSizeBytes -gt 64MB) {
    throw "Full-disk artifact did not satisfy the bounded-volume acceptance gate."
}

Write-Host "PASS: $($report.cases.Count) disk-pressure surfaces; volume=$($report.volumeSizeBytes) bytes; artifact=$outputPath"
