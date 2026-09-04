param([ValidateSet("start","stop","status","logs","reset","migrate","rollback","test")][string]$Command="status")
$ErrorActionPreference="Stop";$root=Split-Path -Parent $PSScriptRoot;$compose=Join-Path $root "deployment\docker-compose.yml";$envFile=Join-Path $root ".env";if(-not(Test-Path $envFile)){throw "Copy .env.example to .env and replace every placeholder."};$base=@("compose","--env-file",$envFile,"-f",$compose)
switch($Command){
 "start"{& (Join-Path $PSScriptRoot "bootstrap-docker.ps1")}
 "stop"{docker @base down}
 "status"{docker @base ps}
 "logs"{docker @base logs --tail 200}
 "reset"{docker @base down --volumes --remove-orphans}
 "migrate"{docker @base exec -T postgres psql -U platform -d platform -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/0002_endpoint_enrollment.up.sql}
 "rollback"{Get-Content (Join-Path $root "storage\migrations\0002_endpoint_enrollment.down.sql")|docker @base exec -T postgres psql -U platform -d platform -v ON_ERROR_STOP=1}
 "test"{docker @base ps;Invoke-WebRequest http://localhost:8080/health/ready -UseBasicParsing}
}
