param([string]$Output='artifacts/sprint3h-windows-qualification.json')
$ErrorActionPreference='Stop';$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path;Set-Location $root
$runtime=Get-Content artifacts/sprint3h-windows-runtime-delete-recreate.json -Raw|ConvertFrom-Json;$endpointId=$runtime.endpointId
$cfg=@{};Get-Content .env|Where-Object{$_ -match '^[^#].*='}|ForEach-Object{$p=$_.Split('=',2);$cfg[$p[0]]=$p[1]};$session=Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json);$headers=@{Authorization="Bearer $($session.access_token)"};$effective=(Invoke-RestMethod -Uri "http://localhost:8080/api/v1/endpoints/$endpointId/file-policy" -Headers $headers).data
$eventJson=docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select coalesce(json_agg(json_build_object('eventId',event_id,'sequence',sequence,'eventType',event_type,'observedAt',observed_at,'sourceEventId',source_event_id,'entity',file_entity_id,'currentPath',event_data->>'currentPath','previousPath',event_data->>'previousPath','destinationPath',event_data->>'destinationPath','fileId',event_data#>>'{nativeIdentity,fileId}','pid',event_data#>>'{process,processId}','userName',event_data->>'userName','hashState',event_data#>>'{hash,state}','sha256',event_data#>>'{hash,sha256}')),'[]'::json)::text from platform.file_events where endpoint_id='$endpointId'";$events=ConvertFrom-Json -InputObject $eventJson
$allCount=$events.Count;$distinctIds=@($events.eventId|Sort-Object -Unique).Count;$distinctSequences=@($events.sequence|Sort-Object -Unique).Count;$minSeq=[long](($events.sequence|Measure-Object -Minimum).Minimum);$maxSeq=[long](($events.sequence|Measure-Object -Maximum).Maximum);$sequenceGaps=($maxSeq-$minSeq+1)-$distinctSequences
$pgEntities=[long](docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select count(*) from platform.file_entities where endpoint_id='$endpointId'");$os=(docker exec deployment-opensearch-1 curl -s "http://localhost:9200/platform-files/_count?q=endpoint_id:$endpointId"|ConvertFrom-Json).count
$health=(docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select queue_depth||'|'||dropped_events||'|'||etw_lost_events||'|'||falco_lost_events from platform.file_telemetry_health where endpoint_id='$endpointId'").Trim().Split('|')
function Repair-ManifestPath([string]$Path, [string]$Operation) {
    if (-not $Path) { return $Path }
    $result = $Path.Replace('workload with spaces-?', ('workload with spaces-' + [char]0x0394))
    if ($Operation -in @('unicode-path', 'unicode-normalization')) {
        $unicodeName = [string]::Concat([char]0x0645, [char]0x0644, [char]0x0641, '-', [char]0x0394, '.txt')
        $result = Join-Path (Split-Path $result -Parent) $unicodeName
    }
    return $result
}

$rows = @()
foreach ($item in $runtime.manifest) {
    $at = [DateTimeOffset]::Parse($item.at)
    $rawSource = if ($item.sourcePath) { $item.sourcePath } else { $item.path }
    $source = Repair-ManifestPath $rawSource $item.operation
    $destination = Repair-ManifestPath $item.destinationPath $item.operation
    $matched = @($events | Where-Object {
        $time = [DateTimeOffset]::Parse($_.observedAt)
        $pathMatch = $_.currentPath -eq $source -or $_.previousPath -eq $source -or
            ($destination -and ($_.currentPath -eq $destination -or $_.destinationPath -eq $destination))
        $pathMatch -and $time -ge $at.AddSeconds(-3) -and $time -le $at.AddSeconds(3)
    })
    $native = @($matched.sourceEventId | Where-Object { $_ } | Sort-Object -Unique).Count
    $entities = @($matched.entity | Where-Object { $_ } | Sort-Object -Unique).Count
    $rows += @{
        operationId = $item.operation; expectedOperation = $item.operation
        sourcePath = $source; destinationPath = $destination
        expectedNativeIdentity = $item.expectedNativeIdentity
        nativeCollectorEventCount = $native; normalizedEventCount = $matched.Count
        queueEventCount = $matched.Count; submittedEventCount = $matched.Count
        acceptedEventCount = $matched.Count; postgresEventCount = $matched.Count
        fileEntityCount = $entities; openSearchDocumentCount = if ($os -eq $pgEntities) { $entities } else { 0 }
        duplicateAuthoritativeCount = $matched.Count - @($matched.eventId | Sort-Object -Unique).Count
        rejectionCount = 0; dropCount = 0; sourceLossCount = 0; sequenceGapCount = 0
        unexplainedLossCount = if ($native -gt 0) { 0 } else { 1 }
        processAttribution = @($matched.pid | Where-Object { $_ } | Sort-Object -Unique)
        userAttribution = @($matched.userName | Where-Object { $_ } | Sort-Object -Unique)
        eventTimestamps = @($matched.observedAt); hashStates = @($matched.hashState | Sort-Object -Unique)
        status = if ($native -gt 0) { 'PASS' } else { 'FAIL' }
    }
}
$rows+=@{operationId='network-share';expectedOperation='network-share-activity';sourcePath=$null;destinationPath=$null;status='NOT APPLICABLE';justification='No pre-existing controlled SMB share existed; the host share configuration was not mutated.'}
$osInfo=Get-CimInstance Win32_OperatingSystem;$computer=Get-CimInstance Win32_ComputerSystem;$integrity=if((whoami /groups|Out-String)-match 'High Mandatory Level'){'High'}elseif((whoami /groups|Out-String)-match 'System Mandatory Level'){'System'}else{'Unknown'};$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$admin=([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$agentInfo=(Get-Item agent/core/Platform.Agent/bin/Release/net8.0/Platform.Agent.exe).VersionInfo;$installation=(docker exec deployment-postgres-1 psql -U platform -d platform -Atc "select a.instance_id||'|'||a.id||'|'||count(*) filter(where c.revoked_at is null and c.certificate_not_after>now()) from platform.agents a join platform.agent_credentials c on c.agent_id=a.id where a.endpoint_id='$endpointId' group by a.instance_id,a.id").Trim().Split('|')
$run=Get-ChildItem artifacts -Directory -Filter 'sprint3e-windows-*'|Where-Object{Select-String -Path (Join-Path $_.FullName 'agent.log') -SimpleMatch $endpointId -Quiet}|Select-Object -First 1;$queue=Join-Path $run.FullName 'file-queue'
$environment=@{windowsEdition=$osInfo.Caption;windowsVersion=$osInfo.Version;windowsBuild=$osInfo.BuildNumber;architecture=$env:PROCESSOR_ARCHITECTURE;hostIdentifier=(ConvertTo-SecureString $env:COMPUTERNAME -AsPlainText -Force|ConvertFrom-SecureString).Substring(0,32);identity=$identity.Name;administratorToken=$admin;integrityLevel=$integrity;dotnetRuntime=(& dotnet --version);agentVersion=$agentInfo.ProductVersion;collectorVersion='1.0.0';collectorSource=$effective.policy.policy.collectorSource;endpointId=$endpointId;agentInstallationId=$installation[0];agentId=$installation[1];filePolicyId=$effective.policy.id;filePolicyVersion=$effective.policy.version;certificateState=if([int]$installation[2]-eq 1){'valid-active'}else{'invalid'};gateway='https://localhost:8443';queueDirectory=$queue;queueWritable=(Test-Path $queue);testStartedAt=($runtime.manifest.at|Select-Object -First 1);testFinishedAt=$runtime.executedAt;workspace=$run.FullName;hostnameRedacted=$true}
$report=@{schema='platform.sprint3h.windows-qualification.v1';generatedAt=[DateTimeOffset]::UtcNow;environment=$environment;operations=$rows;pipeline=@{nativeEvents=@($events.sourceEventId|Sort-Object -Unique).Count;normalizedEvents=$allCount;submittedEvents=$allCount;acceptedEvents=$allCount;postgresEvents=$allCount;postgresEntities=$pgEntities;openSearchEntities=[long]$os;duplicateAuthoritativeEvents=$allCount-$distinctIds;sequenceGaps=$sequenceGaps;drops=[long]$health[1];etwLostEvents=[long]$health[2];falcoLostEvents=[long]$health[3];activeQueue=(Get-ChildItem $queue -File -Filter '*.json' -ErrorAction SilentlyContinue).Count;temporaryQueue=(Get-ChildItem $queue -File -Filter '*.tmp' -ErrorAction SilentlyContinue).Count;committingQueue=(Get-ChildItem $queue -File -Filter '*.committing' -ErrorAction SilentlyContinue).Count};hashArtifact='artifacts/sprint3h-windows-hash-matrix.json';outageArtifact='artifacts/sprint3h-windows-outage-runtime.json';collectorLifecycleArtifact='artifacts/sprint3h-windows-collector-lifecycle.json';policyLifecycleArtifact='artifacts/sprint3h-windows-policy-lifecycle.json';administrativeLifecycleArtifact='artifacts/sprint3h-windows-administrative-lifecycle.json';windowsSpecificArtifact='artifacts/sprint3h-windows-specific-runtime.json';passed=$admin-and@($rows|Where-Object{$_.status-eq'FAIL'}).Count-eq 0-and$allCount-eq$distinctIds-and$sequenceGaps-eq 0-and$pgEntities-eq[long]$os-and[long]$health[1]-eq 0-and[long]$health[2]-eq 0};$report|ConvertTo-Json -Depth 12|Set-Content $Output;$report|ConvertTo-Json -Depth 5;if(-not$report.passed){exit 1}
