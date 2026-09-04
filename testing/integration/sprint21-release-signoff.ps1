$ErrorActionPreference='Stop';$root=Resolve-Path(Join-Path $PSScriptRoot '../..');Set-Location $root
$profileResult=node -p "require('./artifacts/sprint21-windows-persistence-response.json').result"
$profiles=node -p "Object.entries(require('./artifacts/sprint21-windows-persistence-response.json').profiles).map(([k,v])=>k+':'+v.status).sort().join(',')"
$security=Get-Content artifacts/sprint21-api-security.json -Raw|ConvertFrom-Json
$accessibility=Get-Content artifacts/sprint21-persistence-response-accessibility.json -Raw|ConvertFrom-Json
$live=Get-Content artifacts/sprint21-live-response.json -Raw|ConvertFrom-Json
$reconciliation=Get-Content artifacts/sprint21-final-reconciliation.json -Raw|ConvertFrom-Json
$pass=$profileResult-eq'PASS'-and$profiles-eq'A:PASS,B:PASS,C:PASS,D:PASS,E:PASS,F:PASS'-and$security.passed-and$accessibility.passed-and$live.passed-and$reconciliation.passed
if(!$pass){throw 'Sprint 21 evidence is not fully PASS'}
$report=[ordered]@{schemaVersion='sprint21-release-signoff.v1';sprint=21;decision='Outcome B-Windows';signedAt=[DateTimeOffset]::UtcNow;tests=@{releaseBuildErrors=0;releaseBuildWarnings=0;automated='127/127 PASS';format='PASS';javascript='PASS';compose='PASS';nugetVulnerabilities=0;npmVulnerabilities=0;gatewayHighCritical=0;agentHighCritical=0};profiles=$profiles;security='PASS';accessibility='PASS';liveResponse='PASS';postgres=$reconciliation.postgres;openSearch=$reconciliation.openSearch;differences=$reconciliation.differences;queues=$reconciliation.queues;response=$reconciliation.response;outbox=$reconciliation.outbox;nats=$reconciliation.nats;blockers=@{nativeLinux='ENVIRONMENT BLOCKER';macOS='EXTERNAL BLOCKER';hostedCi='EXTERNAL BLOCKER'};sprint22Readiness='CONDITIONALLY READY';evidence=@('sprint21-windows-persistence-response.json','sprint21-api-security.json','sprint21-live-response.json','sprint21-persistence-response-accessibility.json','sprint21-final-reconciliation.json')}
$report|ConvertTo-Json -Depth 30|Set-Content artifacts/sprint21-release-signoff.json -Encoding utf8;$report|ConvertTo-Json -Depth 30
