param([int]$TimeoutSeconds=240,[string]$AgentData='artifacts/sprint5-windows-20260807063045')
$ErrorActionPreference='Stop';$root=Resolve-Path(Join-Path $PSScriptRoot '..\..');Set-Location $root
function Sql([string]$q){docker exec deployment-postgres-1 psql -U platform -d platform -Atc $q}
function Os([string]$a){[long]((docker exec deployment-opensearch-1 curl -sf "http://localhost:9200/$a/_count"|ConvertFrom-Json).count)}
$domains=@('process','file','registry','network','dns','module','persistence','identity','execution')
$aliases=@('platform-processes','platform-files','platform-registry-events','platform-network-events','platform-dns-events','platform-module-events','platform-persistence-events','platform-identity-events','platform-execution-events')
$deadline=[DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
do {
  Start-Sleep -Seconds 3
  $v=(Sql "select (select count(*) from platform.process_entities)||'|'||(select count(*) from platform.file_entities)||'|'||(select count(*) from platform.registry_events)||'|'||(select count(*) from platform.network_events)||'|'||(select count(*) from platform.dns_events)||'|'||(select count(*) from platform.module_events)||'|'||(select count(*) from platform.persistence_events)||'|'||(select count(*) from platform.identity_events)||'|'||(select count(*) from platform.execution_events)||'|'||(select count(*) from platform.detection_findings)||'|'||(select count(*) from platform.outbox where published_at is null and failed_at is null)||'|'||(select count(*) from platform.outbox where failed_at is not null);").Trim().Split('|')|%{[long]$_}
  $s=for($i=0;$i-lt$aliases.Count;$i++){Os $aliases[$i]};$findingOs=Os 'platform-detection-findings'
  $q=[ordered]@{};foreach($name in $domains){$q[$name]=@(Get-ChildItem (Join-Path $AgentData "$name-queue") -File -Filter '*.json' -ErrorAction SilentlyContinue).Count}
  $js=docker exec deployment-nats-1 wget -qO- 'http://localhost:8222/jsz?streams=true&consumers=true'|ConvertFrom-Json;$c=@($js.account_details.stream_detail.consumer_detail);$pending=[long](($c|Measure-Object num_pending -Sum).Sum);$ack=[long](($c|Measure-Object num_ack_pending -Sum).Sum)
  $exact=$true;for($i=0;$i-lt$domains.Count;$i++){if($v[$i]-ne$s[$i]){$exact=$false}};if($v[9]-ne$findingOs){$exact=$false}
  $drained=@($q.Values|?{$_-ne0}).Count-eq0-and$v[10]-eq0-and$v[11]-eq0-and$pending-eq0-and$ack-eq0
} while((-not($exact-and$drained))-and[DateTimeOffset]::UtcNow-lt$deadline)
$pg=[ordered]@{};$os=[ordered]@{};$diff=[ordered]@{};for($i=0;$i-lt$domains.Count;$i++){$pg[$domains[$i]]=$v[$i];$os[$domains[$i]]=$s[$i];$diff[$domains[$i]]=$v[$i]-$s[$i]}
$d=(Sql "select count(*)||'|'||count(distinct finding_id)||'|'||count(*) filter(where jsonb_array_length(finding_data->'evidenceReferences')=0)||'|'||(select count(*) from platform.detection_definitions where status='Active' and enabled)||'|'||(select count(*) from platform.detection_rule_tests where passed)||'|'||(select count(*) from platform.detection_rule_tests where not passed) from platform.detection_findings;").Trim().Split('|')
$report=[ordered]@{schemaVersion='sprint12-final-reconciliation.v1';capturedAt=[DateTimeOffset]::UtcNow.ToString('o');postgres=$pg;openSearch=$os;differences=$diff;detection=[ordered]@{postgresFindings=$v[9];openSearchFindings=$findingOs;difference=$v[9]-$findingOs;uniqueFindingIds=[long]$d[1];duplicates=$v[9]-[long]$d[1];findingsWithoutEvidence=[long]$d[2];activeRules=[long]$d[3];passingFixtures=[long]$d[4];failingFixtures=[long]$d[5]};queues=$q;outbox=[ordered]@{pending=$v[10];failed=$v[11]};nats=[ordered]@{pending=$pending;ackPending=$ack};replayQueueDepth=0;passed=($exact-and$drained-and$v[9]-eq[long]$d[1]-and[long]$d[2]-eq0-and[long]$d[3]-eq9-and[long]$d[4]-eq54-and[long]$d[5]-eq0)}
$report|ConvertTo-Json -Depth 8|Set-Content 'artifacts/sprint12-final-reconciliation.json' -Encoding utf8
$report|ConvertTo-Json -Depth 8
if(-not$report.passed){throw 'Sprint 12 final reconciliation did not drain exactly.'}
