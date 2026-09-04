@echo off
cd /d "%~dp0\..\.."
set "PLATFORM_CONTROL_PLANE_URL=https://localhost:8443"
set "PLATFORM_CA_CERT_PATH=%CD%\deployment\certificates\ca.crt"
set "PLATFORM_AGENT_DATA=%CD%\artifacts\sprint5-windows-20260807063045"
set "PLATFORM_ENVIRONMENT=production"
set "PLATFORM_PROCESS_COLLECTOR=etw"
"%CD%\.tooling\dotnet\dotnet.exe" "%CD%\agent\core\Platform.Agent\bin\Release\net8.0\Platform.Agent.dll" >> "%CD%\artifacts\sprint7-windows-native\agent-remediation-detached.log" 2>&1
