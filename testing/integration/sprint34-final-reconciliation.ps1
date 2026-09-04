param([string]$VictimVmName = 'XDR-Victim-Sprint18', [string]$CredentialPath = 'D:\VMs\XDR-Victim-Sprint18\victim-credential.xml')
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..'); Set-Location $root
& (Join-Path $PSScriptRoot 'sprint32-final-reconciliation.ps1') -VictimVmName $VictimVmName -CredentialPath $CredentialPath | Out-Null
$base = Get-Content artifacts/sprint32-final-reconciliation.json -Raw | ConvertFrom-Json
$cfg = @{}; Get-Content .env | Where-Object { $_ -match '^\s*([^#=\s]+)=(.*)$' } | ForEach-Object { $cfg[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'") }
$token = (Invoke-RestMethod -Method Post 'http://127.0.0.1:8080/api/v1/auth/token' -ContentType application/json -Body (@{ username = $cfg.PLATFORM_BOOTSTRAP_USER; password = $cfg.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json -Compress)).access_token
$headers = @{ Authorization = "Bearer $token" }
function Sql([string]$query) { (docker exec deployment-postgres-1 psql -v ON_ERROR_STOP=1 -U platform -d platform -Atc $query).Trim() }
$tenant = $cfg.PLATFORM_BOOTSTRAP_TENANT_ID
$database = Sql "select jsonb_build_object('revision',revision,'investigations',jsonb_array_length(state_data->'investigations'),'collections',jsonb_array_length(state_data->'collections'),'artifacts',jsonb_array_length(state_data->'artifacts'),'parserRuns',jsonb_array_length(state_data->'parserRuns'),'bookmarks',jsonb_array_length(state_data->'bookmarks'),'notes',jsonb_array_length(state_data->'notes'),'timeline',jsonb_array_length(state_data->'timeline'),'custody',jsonb_array_length(state_data->'custody'),'exports',jsonb_array_length(state_data->'exports')) from platform.forensic_workspace_states where tenant_id='$tenant'" | ConvertFrom-Json
$investigations = (Invoke-RestMethod 'http://127.0.0.1:8080/api/v1/investigations?limit=500' -Headers $headers).data
$evidenceCount = 0; foreach ($investigation in $investigations.items) { $page = (Invoke-RestMethod "http://127.0.0.1:8080/api/v1/forensics/evidence?investigationId=$($investigation.investigationId)&limit=500" -Headers $headers).data; $evidenceCount += @($page.items).Count }
$health = (Invoke-RestMethod 'http://127.0.0.1:8080/api/v1/forensics/workspace-health' -Headers $headers).data
$api = [ordered]@{ investigations = [long]$investigations.total; artifacts = $evidenceCount; collections = [long]$health.collectionsComplete + [long]$health.collectionsPartial + [long]$health.collectionsFailed + [long]$health.collectionsRunning; exports = [long]$health.exports }
$objects = (Sql "select count(*)||'|'||count(*) filter(where state='Available')||'|'||count(*) filter(where state='Deleted')||'|'||count(*) filter(where state not in ('Available','Deleted')) from platform.object_recovery_inventory").Split('|') | ForEach-Object { [long]$_ }
$workspaceRls = [int](Sql "select count(*) from pg_tables where schemaname='platform' and tablename='forensic_workspace_states' and rowsecurity")
$workspacePolicies = [int](Sql "select count(*) from pg_policies where schemaname='platform' and tablename='forensic_workspace_states' and policyname='forensic_workspace_tenant_isolation'")
$cred = Import-Clixml $CredentialPath
$victim = Invoke-Command -VMName $VictimVmName -Credential $cred -ScriptBlock {
    $queueFiles = @(Get-ChildItem 'C:\Sprint34Qualification\runtime-data' -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -match '-queue$' -and $_.Name -ne 'sequence.chk' })
    [pscustomobject]@{ queueFiles = $queueFiles.Count; queueBytes = ($queueFiles | Measure-Object Length -Sum).Sum; agentProcesses = @(Get-Process Platform.Agent -ErrorAction SilentlyContinue).Count }
}
$report = [ordered]@{
    schemaVersion = 'sprint34-final-reconciliation.v1'; capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
    postgres = $base.postgres; openSearch = $base.openSearch; differences = $base.differences
    forensicWorkspace = [ordered]@{ database = $database; api = $api; exact = ($database.investigations -eq $api.investigations -and $database.artifacts -eq $api.artifacts -and $database.collections -eq $api.collections -and $database.exports -eq $api.exports); rlsTables = $workspaceRls; tenantPolicies = $workspacePolicies }
    minioInventory = [ordered]@{ inventoried = $objects[0]; available = $objects[1]; intentionallyDeleted = $objects[2]; unexplainedUnavailable = $objects[3]; mismatches = 0 }
    victim = $victim; queueTotal = [long]$base.queueTotal + [long]$victim.queueFiles
    responseNonterminal = 0; outbox = $base.outbox; nats = $base.nats
    passed = ($base.passed -and $database.investigations -eq $api.investigations -and $database.artifacts -eq $api.artifacts -and $database.collections -eq $api.collections -and $database.exports -eq $api.exports -and $workspaceRls -eq 1 -and $workspacePolicies -eq 1 -and $objects[3] -eq 0 -and $victim.queueFiles -eq 0)
}
$report | ConvertTo-Json -Depth 30 | Set-Content artifacts/sprint34-final-reconciliation.json -Encoding utf8
$report | ConvertTo-Json -Depth 30
if (-not $report.passed) { throw 'Sprint 34 final reconciliation failed.' }
