$ErrorActionPreference='Stop'
$root=Resolve-Path(Join-Path $PSScriptRoot '..\..');Set-Location $root
$cfg=@{};Get-Content .env|ForEach-Object{if($_ -match '^([^#=]+)=(.*)$'){$cfg[$matches[1]]=$matches[2]}}
$login=Invoke-RestMethod -Method Post http://localhost:8080/api/v1/auth/token -ContentType application/json -Body(@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json)
$h=@{Authorization="Bearer $($login.access_token)"};$tenant=$cfg.PLATFORM_BOOTSTRAP_TENANT_ID
function Api($method,$path,$body=$null,$headers=$h){$p=@{Method=$method;Uri="http://localhost:8080$path";Headers=$headers};if($null-ne$body){$p.ContentType='application/json';$p.Body=$body|ConvertTo-Json -Depth 30 -Compress};try{(Invoke-RestMethod @p).data}catch{throw "API $method $path failed: $($_.ErrorDetails.Message) body=$($p.Body)"}}
function Check($name,$ok,$evidence){[ordered]@{name=$name;status=if($ok){'PASS'}else{'FAIL'};evidence=$evidence}}
function B64([byte[]]$b){[Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')}
function Token($tid){$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$head=B64([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'));$payload=B64([Text.Encoding]::UTF8.GetBytes((@{iss='security-platform';aud='security-platform-api';sub='sprint14-other';tid=$tid;per=@('platform:admin');pty='user';iat=$now;exp=$now+900;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress)));$mac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($cfg.PLATFORM_JWT_SIGNING_KEY));"$head.$payload.$(B64($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$head.$payload"))))"}
function Status($method,$path,$body,$headers=$h){try{$p=@{Method=$method;Uri="http://localhost:8080$path";Headers=$headers;UseBasicParsing=$true};if($null-ne$body){$p.ContentType='application/json';$p.Body=$body|ConvertTo-Json -Depth 30 -Compress};(Invoke-WebRequest @p).StatusCode}catch{[int]$_.Exception.Response.StatusCode}}
$seed=Api Post '/internal/v1/investigation:seed-controlled'
$profiles=[Collections.Generic.List[object]]::new();$checks=[Collections.Generic.List[object]]::new()

$tree=Api Get "/api/v1/process-trees/$($seed.root)?depth=6&pageSize=200"
$parentPairs=@($tree.relationships|ForEach-Object{"$($_.sourceEntityId)>$($_.destinationEntityId)"})
$profiles.Add((Check 'Profile A - exact four-generation process tree' ($tree.processes.Count-eq 4-and$tree.relationships.Count-eq 3-and($parentPairs-join',')-eq' sprint14-process-0>sprint14-process-1,sprint14-process-1>sprint14-process-2,sprint14-process-2>sprint14-process-3'.Trim()) @{processes=$tree.processes.Count;relationships=$tree.relationships.Count;pairs=$parentPairs;missing=$tree.missingParents}))

$graphBody=@{rootEntityId=$seed.leaf;rootType='Process';maximumDepth=2;maximumNodes=100;maximumEdges=200;maximumExpansionPerNode=100;timeoutMilliseconds=5000;pageSize=100}
$graph=Api Post '/api/v1/entity-graph:query' $graphBody;$edgeTypes=@($graph.edges.relationshipType|Sort-Object -Unique)
$required=@('modified','queried','connected-to','loaded','configured','executed-as','executed','evidence-for')
$missingEdgeTypes=@($required|Where-Object{$_-notin$edgeTypes});$edgesWithoutEvidence=@($graph.edges|Where-Object{$_.sourceEvidenceIds.Count-eq 0-or$_.evidenceReferences.Count-eq 0})
$profiles.Add((Check 'Profile B - cross-domain evidence graph' ($missingEdgeTypes.Count-eq 0-and$edgesWithoutEvidence.Count-eq 0) @{nodes=$graph.nodes.Count;edges=$graph.edges.Count;types=$edgeTypes;missingTypes=$missingEdgeTypes;edgesWithoutEvidence=$edgesWithoutEvidence.Count}))

$story=Api Post "/api/v1/attack-stories/$($seed.root)" (@{rootEntityId=$seed.root;maximumDepth=6;maximumNodes=200;maximumEdges=400;maximumExpansionPerNode=100;timeoutMilliseconds=5000;pageSize=200})
$profiles.Add((Check 'Profile C - reproducible attack story' ($story.timeline.Count-gt 10-and$story.detectionFindingIds.Count-eq 1-and$story.correlatedFindingIds.Count-eq 1-and$story.relationships.Count-gt 10-and$story.timeline.evidenceReferences.Count-gt 0) @{storyId=$story.storyId;timeline=$story.timeline.Count;detections=$story.detectionFindingIds.Count;correlations=$story.correlatedFindingIds.Count;mitre=$story.mitreMappings}))

$now=[DateTimeOffset]::UtcNow;$hunt=@{schemaVersion='threat-hunt.v1';huntId=[guid]::NewGuid().ToString('D');version=1;tenantId=$tenant;name='Sprint 14 controlled multi-domain hunt';description='Exact controlled evidence';entityTypes=@('Process','File','Registry','Network','Dns','Module','Persistence','Identity','Execution','DetectionFinding','CorrelatedFinding');from=$now.AddHours(-2).ToString('o');to=$now.AddHours(1).ToString('o');where=@{boolean='And';predicate=@{field='processEntityId';operator='Equal';values=@('sprint14-process-3')};children=@()};maximumResults=200;timeoutMilliseconds=5000;maximumJoinDepth=1;joinRelationships=@('modified','connected-to','queried','loaded','configured','executed-as','executed','evidence-for');enabled=$true;owner=$cfg.PLATFORM_BOOTSTRAP_USER;sharedWith=@();createdAt=$now.ToString('o')}
$valid=Api Post '/api/v1/threat-hunts:validate' $hunt;$run=Api Post '/api/v1/threat-hunts:execute' @{hunt=$hunt}
$profiles.Add((Check 'Profile D - deterministic multi-domain hunt' ($valid.valid-and$run.status-eq'completed'-and$run.returned-eq 11-and@($run.results.entityType|Sort-Object -Unique).Count-ge 9-and@($run.results|Where-Object{$_.evidenceIds.Count-eq 0}).Count-eq 0) @{estimatedCost=$valid.estimatedCost;examined=$run.examined;returned=$run.returned;types=@($run.results.entityType|Sort-Object -Unique);runId=$run.runId}))

$large=@{rootEntityId=$seed.largeRoot;rootType='Process';maximumDepth=1;maximumNodes=50;maximumEdges=50;maximumExpansionPerNode=50;timeoutMilliseconds=1000;pageSize=25}
$large1=Api Post '/api/v1/entity-graph:query' $large;$large.cursor=$large1.nextCursor;$large2=Api Post '/api/v1/entity-graph:query' $large
$overlap=@($large1.nodes.entityId|Where-Object{$_-in$large2.nodes.entityId})
$abuseDepth=Status Post '/api/v1/entity-graph:query' (@{rootEntityId=$seed.largeRoot;maximumDepth=999;maximumNodes=50;maximumEdges=50;maximumExpansionPerNode=50;timeoutMilliseconds=1000;pageSize=25})
$cancelled=Api Post "/api/v1/threat-hunt-runs/$($run.runId):cancel"
$profiles.Add((Check 'Profile E - large graph bounds, pagination and cancellation' ($large1.truncated-and$large1.nodes.Count-eq 25-and$large1.edges.Count-le 50-and$large2.nodes.Count-gt 0-and$overlap.Count-eq 0-and$abuseDepth-eq 400-and$cancelled.status-eq'cancelled') @{page1=$large1.nodes.Count;page2=$large2.nodes.Count;edges=$large1.edges.Count;overlap=$overlap.Count;depthAbuseStatus=$abuseDepth;cancel=$cancelled.status}))

$saved=Api Post '/api/v1/saved-hunts' @{hunt=$hunt;newVersion=$false}
docker compose --env-file .env -f deployment/docker-compose.yml restart gateway|Out-Null
$deadline=[DateTimeOffset]::UtcNow.AddMinutes(2);do{try{$ready=(Invoke-WebRequest http://localhost:8080/health/ready -UseBasicParsing).StatusCode-eq 200}catch{$ready=$false};if(!$ready){Start-Sleep 1}}while(!$ready-and[DateTimeOffset]::UtcNow-lt$deadline)
$savedAfter=Api Get '/api/v1/saved-hunts';$runAfter=Api Get "/api/v1/threat-hunt-runs/$($run.runId)";$graphAfter=Api Post '/api/v1/entity-graph:query' $graphBody;$null=Api Get "/api/v1/process-trees/$($seed.root)?depth=6&pageSize=200";$null=Api Post "/api/v1/attack-stories/$($seed.root)" (@{rootEntityId=$seed.root;maximumDepth=6;maximumNodes=200;maximumEdges=400;maximumExpansionPerNode=100;timeoutMilliseconds=5000;pageSize=200});$null=Api Post '/api/v1/threat-hunts:execute' @{hunt=$hunt}
$profiles.Add((Check 'Profile F - restart and pressure durability' ($ready-and@($savedAfter|Where-Object{$_.huntId-eq$saved.huntId}).Count-eq 1-and$runAfter.runId-eq$run.runId-and$graphAfter.edges.Count-eq$graph.edges.Count) @{ready=$ready;savedHunt=$saved.huntId;run=$runAfter.runId;edgesBefore=$graph.edges.Count;edgesAfter=$graphAfter.edges.Count}))

$other=(docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select id from platform.tenants where id<>'$tenant' limit 1;").Trim();$h2=@{Authorization="Bearer $(Token $other)"}
$checks.Add((Check 'two-tenant graph isolation' ((Status Post '/api/v1/entity-graph:query' $graphBody $h2)-eq 404) @{otherTenant=$other}))
$checks.Add((Check 'entity ID guessing' ((Status Get '/api/v1/entities/Process/not-a-real-entity/neighbors' $null)-eq 404) @{}))
$checks.Add((Check 'cursor tampering' ((Status Post '/api/v1/entity-graph:query' ($graphBody+@{cursor='forged'}))-eq 409-or(Status Post '/api/v1/entity-graph:query' ($graphBody+@{cursor='forged'}))-eq 400) @{}))
$badHunt=$hunt.Clone();$badHunt.where=@{boolean='And';predicate=@{field='path';operator='Contains';values=@('SELECT * FROM platform.process_events')};children=@()}
$checks.Add((Check 'SQL and backend query injection rejection' (!(Api Post '/api/v1/threat-hunts:validate' $badHunt).valid) @{}))
$badField=$hunt.Clone();$badField.where=@{boolean='And';predicate=@{field='credentialMaterial';operator='Exists';values=@('true')};children=@()}
$checks.Add((Check 'unauthorized field rejection' (!(Api Post '/api/v1/threat-hunts:validate' $badField).valid) @{}))
$ownershipStatus=Status Delete "/api/v1/saved-hunts/$($saved.huntId)" $null $h2
$checks.Add((Check 'saved-hunt ownership isolation' ($ownershipStatus-in@(400,403,404,409)) @{status=$ownershipStatus}))
$checks.Add((Check 'graph relationship evidence integrity' (@($graph.edges|Where-Object{$_.sourceEvidenceIds.Count-eq 0-or$_.evidenceReferences.Count-eq 0}).Count-eq 0) @{edges=$graph.edges.Count}))

$export=Api Post '/api/v1/investigation-exports' @{kind='graph';format='graph-json';rootEntityId=$seed.root;query=@{rootEntityId=$seed.root;maximumDepth=6;maximumNodes=300;maximumEdges=600;maximumExpansionPerNode=100;timeoutMilliseconds=5000;pageSize=200}}
$content=Invoke-WebRequest "http://localhost:8080/api/v1/investigation-exports/$($export.id)/content" -Headers $h -UseBasicParsing;$manifest=Invoke-RestMethod "http://localhost:8080/api/v1/investigation-exports/$($export.id)/manifest" -Headers $h
$sha=[Security.Cryptography.SHA256]::Create();$hash=([BitConverter]::ToString($sha.ComputeHash($content.RawContentStream.ToArray()))).Replace('-','').ToLowerInvariant();$sha.Dispose()
$checks.Add((Check 'tenant-bound SHA-256 investigation export' ($manifest.tenantBinding-eq$tenant-and$manifest.sha256-eq$hash-and$export.sha256-eq$hash) @{id=$export.id;sha256=$hash;tenant=$manifest.tenantBinding}))
$health=Api Get '/api/v1/investigation-health'
$checks.Add((Check 'bounded investigation health' ($health.treeQueries-gt 0-and$health.graphQueries-gt 0-and$health.huntQueries-gt 0-and$health.nodesTraversed-gt 0-and$health.edgesTraversed-gt 0-and$health.savedHunts-ge 1) $health))

$failed=@($profiles+$checks|Where-Object{$_.status-ne'PASS'}).Count
$report=[ordered]@{schemaVersion='sprint14-investigation-validation.v1';executedAt=[DateTimeOffset]::UtcNow.ToString('o');seed=$seed;profiles=$profiles;checks=$checks;health=$health;failed=$failed;passed=$failed-eq 0}
$report|ConvertTo-Json -Depth 20|Set-Content artifacts/sprint14-investigation-validation.json -Encoding utf8
$report|ConvertTo-Json -Depth 20
if($failed){throw "Sprint 14 validation failed: $failed"}
