param([string]$BaseUrl = 'http://127.0.0.1:8080', [int]$Samples = 30)
$ErrorActionPreference = 'Stop'; $root = Resolve-Path (Join-Path $PSScriptRoot '../..'); Set-Location $root
$cfg = @{}; Get-Content .env | Where-Object { $_ -match '^([^#=]+)=(.*)$' } | ForEach-Object { $cfg[$matches[1]] = $matches[2] }
$token = (Invoke-RestMethod -Method Post "$BaseUrl/api/v1/auth/token" -ContentType application/json -Body (@{ username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json)).access_token
$headers = @{ Authorization = "Bearer $token" }
$investigation = ((Invoke-RestMethod "$BaseUrl/api/v1/investigations?limit=500" -Headers $headers).data.items | Where-Object title -like 'Sprint 34*' | Select-Object -First 1)
$evidence = (Invoke-RestMethod "$BaseUrl/api/v1/forensics/evidence?investigationId=$($investigation.investigationId)&limit=500" -Headers $headers).data.items | Select-Object -First 1
function Percentile([double[]]$values, [double]$p) { $sorted = $values | Sort-Object; [math]::Round($sorted[[math]::Floor(($sorted.Count - 1) * $p)], 3) }
function Measure-Surface([string]$name, [string]$path) { $values = @(); 1..$Samples | ForEach-Object { $watch = [Diagnostics.Stopwatch]::StartNew(); $null = Invoke-RestMethod "$BaseUrl$path" -Headers $headers; $watch.Stop(); $values += $watch.Elapsed.TotalMilliseconds }; [ordered]@{ surface = $name; samples = $Samples; p50Ms = Percentile $values .50; p95Ms = Percentile $values .95; p99Ms = Percentile $values .99; maximumMs = [math]::Round(($values | Measure-Object -Maximum).Maximum, 3) } }
$id = $investigation.investigationId
$results = @(
    Measure-Surface 'investigation-list' '/api/v1/investigations?limit=100'
    Measure-Surface 'collection-list' "/api/v1/investigations/$id/collections"
    Measure-Surface 'hash-search' "/api/v1/forensics/evidence?investigationId=$id&hash=$($evidence.sha256)&limit=100"
    Measure-Surface 'timeline' "/api/v1/investigations/$id/timeline?limit=200"
    Measure-Surface 'entity-pivots' "/api/v1/investigations/$id/entities"
    Measure-Surface 'custody' "/api/v1/investigations/$id/custody"
)
$report = [ordered]@{ schemaVersion = 'sprint34-performance.v1'; capturedAt = [DateTimeOffset]::UtcNow.ToString('o'); samplesPerSurface = $Samples; results = $results; passed = @($results | Where-Object { $_.p95Ms -gt 1000 }).Count -eq 0 }
$report | ConvertTo-Json -Depth 8 | Set-Content artifacts/sprint34-performance.json -Encoding utf8
$report | ConvertTo-Json -Depth 8
if (-not $report.passed) { throw 'Sprint 34 bounded performance campaign failed.' }
