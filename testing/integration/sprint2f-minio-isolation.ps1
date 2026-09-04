param([string]$Output = "artifacts/sprint2f-minio-isolation.json")

$ErrorActionPreference = "Stop"
Set-Location (Resolve-Path (Join-Path $PSScriptRoot "../.."))
$cfg = @{}
Get-Content .env | Where-Object { $_ -match "^[^#].*=" } | ForEach-Object { $p=$_.Split("=",2); $cfg[$p[0]]=$p[1] }
$network = "deployment_platform"
$image = "minio/mc:latest"
$bucket = "platform-objects"
$tenantA = "00000000-0000-0000-0000-000000000002"
$tenantB = [guid]::NewGuid().ToString()
$aPrefix = "tenants/$($tenantA.Replace('-',''))/objects"
$bPrefix = "tenants/$($tenantB.Replace('-',''))/objects"
$objectId = [guid]::NewGuid().ToString("N")
$manifestId = [guid]::NewGuid().ToString("N")
$aObject = "$aPrefix/$objectId"
$aManifest = "$aPrefix/$manifestId"
$work = Join-Path (Resolve-Path artifacts) "sprint2f-minio"
New-Item -ItemType Directory -Force $work | Out-Null
Set-Content (Join-Path $work "object.jsonl") '{"type":"process","safe":true}'
Set-Content (Join-Path $work "manifest.json") '{"type":"manifest","count":1}'

function Secret() {
    $rng=[Security.Cryptography.RandomNumberGenerator]::Create();$bytes=New-Object byte[] 24;$rng.GetBytes($bytes);$rng.Dispose()
    return [Convert]::ToBase64String($bytes).Replace('+','A').Replace('/','B')
}
$aUser = "s2f-a-$($tenantA.Substring(0,8))"
$bUser = "s2f-b-$($tenantB.Substring(0,8))"
$aSecret = Secret
$bSecret = Secret

function Mc([string]$alias, [string]$user, [string]$password, [string[]]$arguments) {
    $hostValue = "http://${user}:${password}@minio:9000"
    $oldPreference=$ErrorActionPreference;$ErrorActionPreference="Continue"
    $output = & docker run --rm --network $network -e "MC_HOST_$alias=$hostValue" -v "${work}:/work" $image @arguments 2>&1
    $code=$LASTEXITCODE;$ErrorActionPreference=$oldPreference
    return [pscustomobject]@{ code=$code; output=(($output -join "`n").Replace($password,"[redacted]").Substring(0,[Math]::Min(4096,(($output -join "`n").Replace($password,"[redacted]")).Length))) }
}
function Root([string[]]$arguments) { Mc "root" $cfg.MINIO_ROOT_USER $cfg.MINIO_ROOT_PASSWORD $arguments }
function A([string[]]$arguments) { Mc "a" $aUser $aSecret $arguments }
function B([string[]]$arguments) { Mc "b" $bUser $bSecret $arguments }

function Policy([string]$name, [string]$prefix, [bool]$application=$false) {
    $resource = if($application){"arn:aws:s3:::$bucket/tenants/*"}else{"arn:aws:s3:::$bucket/$prefix/*"}
    $condition = if($application){@{StringLike=@{"s3:prefix"=@("tenants/*")}}}else{@{StringLike=@{"s3:prefix"=@("$prefix/*","$prefix")}}}
    $listStatement=if($application){@{Effect="Allow";Action=@("s3:ListBucket");Resource=@("arn:aws:s3:::$bucket")}}else{@{Effect="Allow";Action=@("s3:ListBucket");Resource=@("arn:aws:s3:::$bucket");Condition=$condition}}
    $statements=@(
        @{Effect="Allow";Action=@("s3:GetBucketLocation");Resource=@("arn:aws:s3:::$bucket")},
        $listStatement,
        @{Effect="Allow";Action=@("s3:GetObject","s3:GetObjectVersion","s3:GetObjectAttributes","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts");Resource=@($resource)}
    )
    if($application){$statements+=@{Effect="Allow";Action=@("s3:ListAllMyBuckets");Resource=@("arn:aws:s3:::*")}}
    $policy = @{Version="2012-10-17";Statement=$statements}
    $file = Join-Path $work "$name.json"
    $policy | ConvertTo-Json -Depth 10 | Set-Content $file
    Root @("admin","policy","create","root",$name,"/work/$name.json") | Out-Null
}

# Provision a non-root application identity and isolated tenant identities.
foreach($user in @($cfg.MINIO_APP_USER,$aUser,$bUser)){ Root @("admin","user","remove","root",$user) | Out-Null }
Policy "platform-app-bounded" "tenants" $true
Policy "tenant-a-$($tenantA.Substring(0,8))" $aPrefix
Policy "tenant-b-$($tenantB.Substring(0,8))" $bPrefix
Root @("admin","user","add","root",$cfg.MINIO_APP_USER,$cfg.MINIO_APP_PASSWORD) | Out-Null
Root @("admin","policy","attach","root","platform-app-bounded","--user",$cfg.MINIO_APP_USER) | Out-Null
Root @("admin","user","add","root",$aUser,$aSecret) | Out-Null
Root @("admin","policy","attach","root","tenant-a-$($tenantA.Substring(0,8))","--user",$aUser) | Out-Null
Root @("admin","user","add","root",$bUser,$bSecret) | Out-Null
Root @("admin","policy","attach","root","tenant-b-$($tenantB.Substring(0,8))","--user",$bUser) | Out-Null

$oldPreference=$ErrorActionPreference;$ErrorActionPreference="Continue"
docker rm -f sprint2f-minio-trace *> $null
$ErrorActionPreference=$oldPreference
$rootHost = "http://$($cfg.MINIO_ROOT_USER):$($cfg.MINIO_ROOT_PASSWORD)@minio:9000"
docker run -d --name sprint2f-minio-trace --network $network -e "MC_HOST_root=$rootHost" --entrypoint /bin/sh $image -c "mc admin trace --json --all root" *> $null
Start-Sleep -Seconds 1

$aUpload = A @("cp","/work/object.jsonl","a/$bucket/$aObject")
$aManifestUpload = A @("cp","/work/manifest.json","a/$bucket/$aManifest")
if($aUpload.code -ne 0 -or $aManifestUpload.code -ne 0){throw "Tenant A fixture upload failed: $($aUpload.output) $($aManifestUpload.output)"}
$tests = @()
function Test-Operation([string]$operation,[string[]]$arguments,[bool]$deny=$true,[string]$object=$aObject) {
    $r=B $arguments
    $passed=if($deny){$r.code -ne 0}else{$r.code -eq 0}
    $script:tests += [ordered]@{operation=$operation;tenant=$tenantB;object=$object;expected=if($deny){"AccessDenied"}else{"Allowed"};actualExit=$r.code;actual=$r.output;auditRecord=$operation;passed=$passed}
}
Test-Operation "download" @("cp","b/$bucket/$aObject","/work/b-download")
Test-Operation "metadata-head" @("stat","b/$bucket/$aObject")
Test-Operation "range-read" @("cat","--offset","1","b/$bucket/$aObject")
Test-Operation "export-retrieval" @("cp","b/$bucket/$aObject","/work/b-export")
Test-Operation "manifest-retrieval" @("cp","b/$bucket/$aManifest","/work/b-manifest") $true $aManifest
Test-Operation "prefix-guess" @("find","b/$bucket/$aPrefix")
Test-Operation "modified-object-key" @("stat","b/$bucket/$aPrefix/$([guid]::NewGuid().ToString('N'))")
Test-Operation "upload-a-key" @("cp","/work/object.jsonl","b/$bucket/$aPrefix/$([guid]::NewGuid().ToString('N'))")
Test-Operation "overwrite" @("cp","/work/manifest.json","b/$bucket/$aObject")
Test-Operation "create-under-a-prefix" @("cp","/work/object.jsonl","b/$bucket/$aPrefix/new")
Test-Operation "copy-from-a" @("cp","b/$bucket/$aObject","b/$bucket/$bPrefix/copied")
Test-Operation "copy-into-a" @("cp","/work/object.jsonl","b/$bucket/$aPrefix/copied")
Test-Operation "change-metadata" @("cp","--attr","x-amz-meta-test=changed","/work/object.jsonl","b/$bucket/$aObject")
Test-Operation "multipart-upload" @("cp","/work/object.jsonl","b/$bucket/$aPrefix/multipart")
Test-Operation "delete" @("rm","--force","b/$bucket/$aObject")
Test-Operation "list-a-prefix" @("ls","b/$bucket/$aPrefix")
Test-Operation "enumerate-bucket" @("ls","--recursive","b/$bucket")
Test-Operation "abort-a-multipart" @("rm","--incomplete","--recursive","--force","b/$bucket/$aPrefix")

function Docker-HttpStatus([string]$url) {
    $oldPreference=$ErrorActionPreference;$ErrorActionPreference="Continue"
    $status=& docker run --rm --network $network curlimages/curl:8.15.0 -s -o /dev/null -w "%{http_code}" $url 2>$null
    $code=$LASTEXITCODE;$ErrorActionPreference=$oldPreference
    if($code -eq 0){return [int]$status}
    return 0
}
$anonymousStatus = Docker-HttpStatus "http://minio:9000/$bucket/$aObject"
$tests += [ordered]@{operation="anonymous-read";tenant="anonymous";object=$aObject;expected="403";actualExit=$anonymousStatus;actual="HTTP $anonymousStatus";auditRecord="anonymous-read";passed=$anonymousStatus -eq 403}

# A presigned URL is an intentionally scoped bearer: verify exact-object access and expiration.
$share=A @("share","download","--expire","10s","a/$bucket/$aObject")
$cleanShare=$share.output -replace '\x1B\[[0-9;]*[A-Za-z]',''
$url=@([regex]::Matches($cleanShare,'https?://[^\r\n\s]+')|ForEach-Object{$_.Value.Trim('`','"',"'").Trim()}|Where-Object{$_ -match 'X-Amz-'})|Select-Object -Last 1
$immediate=if($url){Docker-HttpStatus $url}else{0}
Start-Sleep -Seconds 11
$expired=if($url){Docker-HttpStatus $url}else{0}
$shareDiagnostic=($share.output -replace '(https?://[^?\s]+)\?\S+','$1?[redacted]')
$tests += [ordered]@{operation="presigned-exact-object-and-expiry";tenant="bearer";object=$aObject;expected="200 then denied";actualExit=$expired;actual="immediate=$immediate expired=$expired shareExit=$($share.code) diagnostic=$shareDiagnostic";auditRecord="presigned";passed=$immediate -eq 200 -and $expired -in @(400,403)}

docker stop sprint2f-minio-trace *> $null
$trace = docker logs sprint2f-minio-trace 2>&1
docker rm sprint2f-minio-trace *> $null
$traceFile=Join-Path $work "audit-trace.jsonl";$trace|Set-Content $traceFile
$traceRecords=@($trace|Where-Object{$_ -match 's3|API|api'}).Count

$report=[ordered]@{schema="platform.sprint2f.minio-isolation.v1";executedAt=[DateTimeOffset]::UtcNow.ToString("O");tenantA=$tenantA;tenantB=$tenantB;bucket=$bucket;applicationIdentity=$cfg.MINIO_APP_USER;applicationPolicy="platform-app-bounded";publicBucket=$false;tests=$tests;auditTraceRecords=$traceRecords;auditArtifact="artifacts/sprint2f-minio/audit-trace.jsonl";passed=@($tests|Where-Object{-not $_.passed}).Count -eq 0 -and $traceRecords -gt 0}
$report|ConvertTo-Json -Depth 8|Set-Content $Output
$report|ConvertTo-Json -Depth 6
if(-not $report.passed){exit 1}
