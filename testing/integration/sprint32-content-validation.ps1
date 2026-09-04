param([string]$BaseUrl='http://127.0.0.1:8080')
$ErrorActionPreference='Stop';$root=Resolve-Path(Join-Path $PSScriptRoot '..\..');Set-Location $root
$cfg=@{};Get-Content .env|Where-Object{$_-match'^\s*([^#=\s]+)=(.*)$'}|ForEach-Object{$cfg[$matches[1]]=$matches[2].Trim().Trim('"').Trim("'")}
$token=(Invoke-RestMethod -Method Post "$BaseUrl/api/v1/auth/token" -ContentType application/json -Body(@{username=$cfg.PLATFORM_BOOTSTRAP_USER;password=$cfg.PLATFORM_BOOTSTRAP_PASSWORD}|ConvertTo-Json -Compress)).access_token;$h=@{Authorization="Bearer $token"}
function Call([string]$method,[string]$path){$watch=[Diagnostics.Stopwatch]::StartNew();$value=(Invoke-RestMethod -Method $method "$BaseUrl$path" -Headers $h -ContentType application/json).data;$watch.Stop();[pscustomobject]@{Data=$value;Milliseconds=$watch.ElapsedMilliseconds}}
$unauthorized=0;try{Invoke-WebRequest "$BaseUrl/api/v1/detection-content/catalog" -UseBasicParsing|Out-Null}catch{$unauthorized=[int]$_.Exception.Response.StatusCode}
$profileA=Call Post '/internal/v1/detection-production-pack:seed';$profileB=Call Get '/api/v1/detection-content/catalog';$profileC=Call Get '/api/v1/detection-content/coverage';$profileD=Call Get '/api/v1/detection-content/gaps';$profileE=Call Get '/api/v1/detection-rules';$profileF=Call Post '/internal/v1/correlation-production-pack:seed';$correlations=Call Get '/api/v1/correlation-rules'
$rules=@($profileA.Data.rules);$catalog=@($profileB.Data);$coverage=@($profileC.Data);$corr=@($correlations.Data)
$profiles=[ordered]@{
 A=[ordered]@{status=if($rules.Count-eq30-and@($rules|Where-Object activated).Count-eq30){'PASS'}else{'FAIL'};rules=$rules.Count;active=@($rules|Where-Object activated).Count;milliseconds=$profileA.Milliseconds}
 B=[ordered]@{status=if(@($catalog|Where-Object{$_.fixtureCount-eq9-and$_.validationPassed}).Count-eq30){'PASS'}else{'FAIL'};fixtureCampaigns=@($catalog|Where-Object{$_.fixtureCount-eq9-and$_.validationPassed}).Count;milliseconds=$profileB.Milliseconds}
 C=[ordered]@{status=if(@($rules|Where-Object{$_.boundedVolume-and$_.historicalMatches-le1000}).Count-eq30){'PASS'}else{'FAIL'};historicalEvents=(@($rules|Measure-Object historicalEvents -Sum).Sum);historicalMatches=(@($rules|Measure-Object historicalMatches -Sum).Sum)}
 D=[ordered]@{status=if($coverage.Count-ge15-and@($coverage|Where-Object{$_.support-eq'Covered'}).Count-eq$coverage.Count){'PASS'}else{'FAIL'};techniques=$coverage.Count;covered=@($coverage|Where-Object{$_.support-eq'Covered'}).Count;milliseconds=$profileC.Milliseconds}
 E=[ordered]@{status=if($unauthorized-eq401-and@($profileD.Data).Count-ge5){'PASS'}else{'FAIL'};unauthorizedStatus=$unauthorized;gaps=@($profileD.Data).Count;catalogLatencyMs=$profileB.Milliseconds;coverageLatencyMs=$profileC.Milliseconds}
 F=[ordered]@{status=if(@($profileF.Data.rules).Count-eq18-and@($profileF.Data.rules|Where-Object{$_.status-eq'Active'}).Count-eq18){'PASS'}else{'FAIL'};packVersion=$profileF.Data.packVersion;rules=@($profileF.Data.rules).Count;active=@($profileF.Data.rules|Where-Object{$_.status-eq'Active'}).Count;milliseconds=$profileF.Milliseconds}
}
$allPassed=@($profiles.Values|Where-Object{$_.status-ne'PASS'}).Count-eq0
$report=[ordered]@{schemaVersion='sprint32-content-validation.v1';executedAt=[DateTimeOffset]::UtcNow.ToString('o');profiles=$profiles;productionDetections=@($profileE.Data|Where-Object{$_.enabled-and$_.status-eq'Active'}).Count;productionCorrelations=@($corr|Where-Object{$_.enabled-and$_.status-eq'Active'}).Count;allPassed=$allPassed}
$report|ConvertTo-Json -Depth 20|Set-Content artifacts/sprint32-content-validation.json -Encoding utf8;$report|ConvertTo-Json -Depth 20;if(-not$report.allPassed){throw 'Sprint 32 Profiles A-F failed.'}
