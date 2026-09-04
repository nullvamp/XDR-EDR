$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '../..')
Set-Location $root
$settings = @{}
Get-Content .env | Where-Object { $_ -match '^\s*([^#=\s]+)=(.*)$' } | ForEach-Object { $settings[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'") }
$login = Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/auth/token -ContentType application/json -Body (@{ username = $settings.PLATFORM_BOOTSTRAP_USER; password = $settings.PLATFORM_BOOTSTRAP_PASSWORD } | ConvertTo-Json -Compress)
$admin = @{ Authorization = "Bearer $($login.access_token)" }
function B64([byte[]]$value) { [Convert]::ToBase64String($value).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
function ForeignJwt {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $head = B64([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
    $body = B64([Text.Encoding]::UTF8.GetBytes((@{ iss='security-platform'; aud='security-platform-api'; sub='foreign-tenant'; tid=[guid]::NewGuid().ToString('D'); per=@('platform:admin'); pty='user'; iat=$now; exp=$now+600; jti=[guid]::NewGuid().ToString('N') } | ConvertTo-Json -Compress)))
    $hmac = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($settings.PLATFORM_JWT_SIGNING_KEY))
    try { $signature = B64($hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes("$head.$body"))) } finally { $hmac.Dispose() }
    "$head.$body.$signature"
}
function Status([string]$method, [string]$uri, $headers, $body = $null) {
    try {
        $args = @{ Method=$method; Uri=$uri; Headers=$headers; UseBasicParsing=$true }
        if ($null -ne $body) { $args.ContentType='application/json'; $args.Body=$body | ConvertTo-Json -Depth 20 -Compress }
        [int](Invoke-WebRequest @args).StatusCode
    } catch { [int]$_.Exception.Response.StatusCode }
}
$control = Get-Content artifacts/sprint20-windows-file-response.json -Raw | ConvertFrom-Json
$id = [guid]$control.profileA.actionId
$endpoint = [guid]$control.victim.endpointId
$entity = [string]$control.profileA.preview.target.fileEntityId
$foreign = @{ Authorization = "Bearer $(ForeignJwt)" }
$normalRecord = Status GET "http://127.0.0.1:8080/api/v1/quarantines/$id" $admin
$foreignRecord = Status GET "http://127.0.0.1:8080/api/v1/quarantines/$id" $foreign
$forgedEntity = Status GET "http://127.0.0.1:8080/api/v1/endpoints/$endpoint/files/$('0' * 64)/response-preview" $admin
$wrongEndpoint = Status GET "http://127.0.0.1:8080/api/v1/endpoints/$([guid]::NewGuid())/files/$entity/response-preview" $admin
$artifactGuess = Status GET "http://127.0.0.1:8080/api/v1/response-actions/$id/artifacts/$([guid]::NewGuid())/content" $admin
$genericFileAction = Status POST 'http://127.0.0.1:8080/api/v1/response-actions' $admin @{ endpointId=$endpoint; actionType='file.delete'; actionVersion=1; parameters=@{ path='C:\path-only.bin' }; reason='path-only forgery'; executionTimeoutSeconds=180; expiresInSeconds=300 }
$report = [ordered]@{ schemaVersion='sprint20-api-security.v1'; capturedAt=[DateTimeOffset]::UtcNow; checks=[ordered]@{ authorizedQuarantineRecord=$normalRecord; foreignTenantRecord=$foreignRecord; forgedFileEntity=$forgedEntity; wrongEndpoint=$wrongEndpoint; artifactGuess=$artifactGuess; genericPathOnlyFileAction=$genericFileAction }; passed=$normalRecord-eq200-and$foreignRecord-eq404-and$forgedEntity-eq404-and$wrongEndpoint-eq404-and$artifactGuess-eq404-and$genericFileAction-eq400 }
$report | ConvertTo-Json -Depth 20 | Set-Content artifacts/sprint20-api-security.json -Encoding utf8
$report | ConvertTo-Json -Depth 20
if (-not $report.passed) { exit 1 }
