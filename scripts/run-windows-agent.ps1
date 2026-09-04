param(
    [Parameter(Mandatory = $true)][string]$DataDirectory,
    [Parameter(Mandatory = $true)][string]$LogPath,
    [string]$ControlPlaneUrl = "https://localhost:8443",
    [string]$CaCertificatePath,
    [ValidateSet("etw")][string]$Collector = "etw",
    [string]$EtwFailureMarker,
    [ValidateSet("production", "evaluation")][string]$Environment = "production",
    [string]$LocalTestFailpoint,
    [string]$LocalTestFailpointMarker,
    [int]$LocalTestCompressionBytes = 1024
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dotnet = Join-Path $root ".tooling\dotnet\dotnet.exe"
$agent = Join-Path $root "agent\core\Platform.Agent\bin\Release\net8.0\Platform.Agent.dll"
$ca = if ($CaCertificatePath) {
    $CaCertificatePath
} else {
    Join-Path $root "deployment\certificates\ca.crt"
}

if (-not (Test-Path -LiteralPath $dotnet)) {
    throw "Workspace .NET runtime is missing: $dotnet"
}
if (-not (Test-Path -LiteralPath $agent)) {
    throw "Build the Release agent before starting it: $agent"
}

New-Item -ItemType Directory -Force -Path $DataDirectory | Out-Null
$env:PLATFORM_CONTROL_PLANE_URL = $ControlPlaneUrl
$env:PLATFORM_CA_CERT_PATH = $ca
$env:PLATFORM_AGENT_DATA = $DataDirectory
$env:PLATFORM_ENVIRONMENT = $Environment
$env:PLATFORM_PROCESS_COLLECTOR = $Collector
if ($EtwFailureMarker) {
    $env:PLATFORM_ETW_FAILURE_MARKER = $EtwFailureMarker
}
if ($LocalTestFailpoint) {
    $env:PLATFORM_LOCAL_TEST_FAILPOINT = $LocalTestFailpoint
    $env:PLATFORM_LOCAL_TEST_FAILPOINT_MARKER = $LocalTestFailpointMarker
    $env:PLATFORM_LOCAL_TEST_COMPRESSION_BYTES = $LocalTestCompressionBytes
}
& $dotnet $agent *>> $LogPath
exit $LASTEXITCODE
