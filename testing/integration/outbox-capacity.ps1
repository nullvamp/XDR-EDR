param([int]$Messages = 1000, [int]$TimeoutSeconds = 60, [string]$Output = "artifacts/sprint2c/outbox-capacity.json")
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root
$tenant = docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select id from platform.tenants order by created_at limit 1"
if (-not $tenant) { throw 'No production tenant exists.' }
$run = [guid]::NewGuid().ToString('N')
$before = docker exec deployment-postgres-1 psql -U platform -d platform -AtF ',' -c "select count(*),coalesce(extract(epoch from(now()-min(created_at))),0) from platform.outbox where published_at is null and failed_at is null"
$sql = "insert into platform.outbox(id,tenant_id,topic,subject,message,trace_id) select gen_random_uuid(),'$tenant','sprint2c.capacity','sprint2c.capacity.v1',jsonb_build_object('run','$run','sequence',n),'$run' from generate_series(1,$Messages) n;"
$sw = [Diagnostics.Stopwatch]::StartNew()
docker exec deployment-postgres-1 psql -U platform -d platform -v ON_ERROR_STOP=1 -c $sql | Out-Null
$samples = @()
$deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    $row = docker exec deployment-postgres-1 psql -U platform -d platform -AtF ',' -c "select count(*) filter(where published_at is null and failed_at is null and trace_id='$run'),count(*) filter(where published_at is not null and trace_id='$run'),count(*) filter(where failed_at is not null and trace_id='$run'),coalesce(extract(epoch from(now()-min(created_at) filter(where published_at is null and failed_at is null and trace_id='$run'))),0),count(*) filter(where lease_until>now() and trace_id='$run') from platform.outbox"
    $parts = $row.Split(',')
    $samples += [ordered]@{ elapsed_ms=$sw.ElapsedMilliseconds; pending=[int]$parts[0]; published=[int]$parts[1]; failed=[int]$parts[2]; oldest_seconds=[double]$parts[3]; leased=[int]$parts[4] }
    if ([int]$parts[0] -eq 0) { break }
    Start-Sleep -Milliseconds 250
} while ([DateTimeOffset]::UtcNow -lt $deadline)
$sw.Stop()
$last = $samples[-1]
$report = [ordered]@{
    run=$run; messages=$Messages; baseline=$before; duration_ms=$sw.ElapsedMilliseconds
    peak_pending=($samples.pending | Measure-Object -Maximum).Maximum
    peak_oldest_seconds=($samples.oldest_seconds | Measure-Object -Maximum).Maximum
    remaining_pending=$last.pending; published=$last.published; failed=$last.failed
    publish_per_second=[math]::Round($last.published / [math]::Max(0.001,$sw.Elapsed.TotalSeconds),2)
    passed=($last.pending -eq 0 -and $last.published -eq $Messages -and $last.failed -eq 0)
    samples=$samples
}
$directory = Split-Path $Output
New-Item -ItemType Directory -Force $directory | Out-Null
$report | ConvertTo-Json -Depth 6 | Set-Content $Output
$report | ConvertTo-Json -Depth 3
if (-not $report.passed) { exit 1 }
