# Windows Agent Packaging

Sprint Zero uses the shared `Platform.Agent` runtime. Windows packaging must install it as a restricted service, protect its data directory, register recovery actions, and use the signed update framework. No telemetry collector is enabled.
