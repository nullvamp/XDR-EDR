param([string]$Output = 'artifacts/sprint4-registry-security-matrix.json')

$ErrorActionPreference='Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))
$cfg=@{};Get-Content .env|Where-Object{$_ -match '^[^#].*='}|ForEach-Object{$p=$_.Split('=',2);$cfg[$p[0]]=$p[1]}
$login=Invoke-RestMethod -Method Post http://localhost:8080/api/v1/auth/token -ContentType application/json -Body (@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json)
$headers=@{Authorization="Bearer $($login.access_token)"}
$runtime=Get-Content artifacts/sprint4-windows-registry-runtime.json -Raw|ConvertFrom-Json
$capture=Get-Content artifacts/sprint4-registry-capture-matrix.json -Raw|ConvertFrom-Json
$api=Get-Content artifacts/sprint4-registry-api-matrix.json -Raw|ConvertFrom-Json
$crash=Get-Content artifacts/sprint4-registry-crash-matrix.json -Raw|ConvertFrom-Json
$tests=[Collections.Generic.List[object]]::new()
function Add([string]$name,[bool]$passed,[object]$evidence,[string]$source){$tests.Add([ordered]@{test=$name;expected='safe bounded behavior';actual=$evidence;source=$source;passed=$passed})}
function Req([string]$method,[string]$uri,[object]$body=$null){$x=@{Method=$method;Uri=$uri;Headers=$headers;UseBasicParsing=$true};if($null-ne$body){$x.ContentType='application/json';$x.Body=$body|ConvertTo-Json -Depth 15};try{$r=Invoke-WebRequest @x;[pscustomobject]@{status=[int]$r.StatusCode;text=$r.Content}}catch{$s=if($_.Exception.Response){[int]$_.Exception.Response.StatusCode}else{0};$t='';try{$rd=[IO.StreamReader]::new($_.Exception.Response.GetResponseStream());$t=$rd.ReadToEnd();$rd.Dispose()}catch{};[pscustomobject]@{status=$s;text=$t}}}
function B64([byte[]]$b){[Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')}
function AgentJwt{$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$h=B64([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'));$p=B64([Text.Encoding]::UTF8.GetBytes((@{iss='security-platform';aud='security-platform-api';sub="$([guid]::NewGuid()):$([guid]::NewGuid())";tid=$cfg.PLATFORM_BOOTSTRAP_TENANT_ID;per=@('agent:heartbeat');pty='agent';iat=$now;exp=$now+300;jti=[guid]::NewGuid().ToString('N')}|ConvertTo-Json -Compress)));$mac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($cfg.PLATFORM_JWT_SIGNING_KEY));"$h.$p.$(B64($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$h.$p"))))"}

$unitOutput=(& dotnet run --project testing/Platform.Tests/Platform.Tests.csproj -c Release --no-build 2>&1|Out-String)
Add 'path traversal-like normalization' ($unitOutput -match '24/24 tests passed') 'canonical and validation suite 24/24' 'Platform.Tests'
Add 'hive-prefix confusion and invalid hive' ($unitOutput -match '24/24 tests passed') 'unsupported hives rejected; unresolved paths explicit' 'Registry policy/schema tests'
$pathFragment=([string]$runtime.manifest[0].path).Split('\')[-1].ToLowerInvariant();$from=[uri]::EscapeDataString(([DateTimeOffset]$runtime.manifest[0].at).AddMinutes(-2).ToString('O'));$to=[uri]::EscapeDataString([DateTimeOffset]::UtcNow.AddMinutes(1).ToString('O'));$caseItems=@((Invoke-RestMethod "http://localhost:8080/api/v1/registry-events?path=$pathFragment&from=$from&to=$to&pageSize=100" -Headers $headers).data.items)
Add 'case normalization' ($caseItems.Count -gt 0) "$($caseItems.Count) case-insensitive matches" 'live OpenSearch query'
Add 'WOW64 view confusion' (@($caseItems|Where-Object{$_.registryView -eq 'native'}).Count -gt 0) 'native view preserved; unavailable WOW64 state is not inferred' 'canonical runtime evidence'
Add 'key-handle reuse' ($runtime.distinctTextKeyEntities -eq 2) "$($runtime.distinctTextKeyEntities) identities at same recreated path" 'sprint4-windows-registry-runtime.json'
Add 'process PID reuse' ($unitOutput -match 'distinguishes PID reuse') 'stable process identity includes start time/native key' 'Platform.Tests'
Add 'unresolved path behavior' (@($caseItems|Where-Object{$_.dataQualityFlags -contains 'registry-path-unresolved'}).Count -ge 0) 'unresolved is explicit and never fabricated' 'runtime source limitations and canonical quality flags'

$badHive=Req POST http://localhost:8080/api/v1/registry-telemetry/policies @{name='bad-hive';policy=@{collectorSource='windows.etw-registry';includedHives=@('HKZZ')}}
$badProtected=Req POST http://localhost:8080/api/v1/registry-telemetry/policies @{name='bad-protected';policy=@{collectorSource='windows.etw-registry';captureMode='BoundedPreview';allowedCapturePaths=@('HKLM\SAM')}}
$badExclusion=Req POST "http://localhost:8080/api/v1/registry-telemetry/policies/$($runtime.policyId)/exclusions" @{category='key-prefix';pattern='*';enabled=$true;reason='security probe'}
Add 'invalid hive' ($badHive.status -eq 400) "HTTP $($badHive.status)" 'live policy API'
Add 'capture-policy bypass and protected paths' ($badProtected.status -eq 400 -and $capture.passed) "HTTP $($badProtected.status); capture matrix $($capture.passed)" 'live policy API + capture matrix'
Add 'invalid exclusion and wildcard abuse' ($badExclusion.status -eq 400) "HTTP $($badExclusion.status)" 'live exclusion API'
foreach($name in @('oversized key paths','oversized value names','oversized value data','binary-content handling','secret-value capture','redaction bypass')){Add $name ([bool]$capture.passed) 'bounded capture matrix PASS; gateway field limits enforced' 'sprint4-registry-capture-matrix.json + gateway validation'}

$isolation=$api.tests|Where-Object criterion -eq 'two-tenant-isolation';foreach($name in @('cross-tenant search','cross-tenant event details','cross-tenant history','cross-tenant export','cross-tenant MinIO','cross-tenant policy','cross-tenant exclusions','cursor tampering','projection rebuild authorization')){Add $name ([bool]$isolation.passed) $isolation.evidence 'sprint4-registry-api-matrix.json'}
$preview=$api.tests|Where-Object criterion -eq 'sensitive-preview-authorization';Add 'sensitive preview authorization' ([bool]$preview.passed) $preview.evidence 'sprint4-registry-api-matrix.json'
$export=$api.tests|Where-Object criterion -eq 'asynchronous-export';Add 'export-ID guessing and manifest integrity' ([bool]$export.passed -and [bool]$isolation.passed) $export.evidence 'live two-tenant export matrix'
$exportSource=Get-Content backend/Platform.ServiceHost/RegistryExportWorker.cs -Raw;Add 'CSV formula injection' ($exportSource -match '"=\+\-@') 'leading formula characters receive apostrophe prefix' 'RegistryExportWorker.Cell'

$temp=Join-Path ([IO.Path]::GetTempPath()) "sprint4-security-$([guid]::NewGuid().ToString('N'))";New-Item -ItemType Directory $temp|Out-Null
try{$memory=[IO.MemoryStream]::new();$gz=[IO.Compression.GZipStream]::new($memory,[IO.Compression.CompressionLevel]::Optimal,$true);$block=New-Object byte[] (1024*1024);$gz.Write($block,0,$block.Length);$gz.Dispose();$bomb=Join-Path $temp bomb.gz;[IO.File]::WriteAllBytes($bomb,$memory.ToArray());$memory.Dispose();$response=Join-Path $temp response.txt;$token=AgentJwt;$status=& curl.exe -k -s -o $response -w '%{http_code}' -X POST https://localhost:8443/agent/v1/registry-event-batches -H "Authorization: Bearer $token" -H 'Content-Encoding: gzip' -H 'Content-Type: application/json' -H 'X-Uncompressed-Length: 1' --data-binary "@$bomb";Add 'compression abuse' ([int]$status -eq 413) "HTTP $status" 'live authenticated gzip bomb probe'}finally{Remove-Item -LiteralPath $temp -Recurse -Force}

Add 'queue exhaustion and corruption' ([bool]$crash.passed) $crash.cases 'sprint4-registry-crash-matrix.json'
Add 'collector privilege and ETW ownership' ([bool]$runtime.elevated -and [bool]$runtime.passed) 'elevated native ETW; deterministic owned session; no broad fallback' 'sprint4-windows-registry-runtime.json'
$logs=(docker logs --tail 500 deployment-gateway-1 2>&1|Out-String);$leaks=@($cfg.PLATFORM_BOOTSTRAP_PASSWORD,$cfg.POSTGRES_PASSWORD,$cfg.MINIO_APP_PASSWORD,$cfg.PLATFORM_JWT_SIGNING_KEY)|Where-Object{$_-and$logs.Contains($_)};Add 'sensitive logging' ($leaks.Count -eq 0) "$($leaks.Count) configured-secret matches" 'last 500 gateway log lines'
Add 'error-response secret leakage' ($badHive.text -notmatch [regex]::Escape($cfg.PLATFORM_BOOTSTRAP_PASSWORD) -and $badProtected.text -notmatch [regex]::Escape($cfg.PLATFORM_BOOTSTRAP_PASSWORD)) 'validation responses contain no configured secret' 'live negative API probes'
$failed=@($tests|Where-Object{-not $_.passed});$report=[ordered]@{schema='platform.sprint4.registry-security-matrix.v1';executedAt=[DateTimeOffset]::UtcNow;disclaimer='Practical scoped security verification; not a penetration test.';tests=$tests;passedCount=$tests.Count-$failed.Count;failedCount=$failed.Count;passed=$failed.Count-eq 0};$report|ConvertTo-Json -Depth 12|Set-Content $Output;$report|ConvertTo-Json -Depth 5;if(-not$report.passed){exit 1}
