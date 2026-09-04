using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OpenSecurityPlatform.Foundation;

static class RejectedEventIdExtensions
{
    public static HashSet<Guid> ToHashSet(this IReadOnlyDictionary<Guid, string> values) => values.Keys.ToHashSet();
}

sealed class AgentSelfProtectionClient(AgentOptions options, ILogger log)
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly string cachePath = Path.Combine(options.DataDirectory, "self-protection-policy.json");
    AgentProtectionPolicy? current;
    DateTimeOffset next = DateTimeOffset.MinValue;
    public async Task RunOnceAsync(AgentState state, Func<AgentState, HttpClient> clientFactory, CancellationToken ct)
    {
        if (DateTimeOffset.UtcNow < next) return;
        try
        {
            using var client = clientFactory(state); var suffix = $"?endpointId={state.EndpointId:D}&installationId={Uri.EscapeDataString(state.InstallationId)}";
            var envelope = await Envelope<SignedProtectionPolicyEnvelope>(client, "/agent/v1/self-protection/policy" + suffix, ct); if (envelope is null) { next = DateTimeOffset.UtcNow.AddMinutes(1); return; }
            if (!AgentProtectionSafety.VerifyPolicy(envelope, state.CaCertificatePem, state.TenantId, state.EndpointId, state.InstallationId, current?.Version ?? LoadVersion())) { await ReportPolicyFailure(state, client, envelope.Policy, "signature/binding/version validation failed", ct); next = DateTimeOffset.UtcNow.AddSeconds(30); return; }
            current = envelope.Policy; await AtomicWrite(cachePath, JsonSerializer.Serialize(current, Json), ct);
            var maintenance = await Envelope<MaintenanceAuthorization[]>(client, "/agent/v1/self-protection/maintenance" + suffix, ct) ?? [];
            var authorized = maintenance.Where(x => AgentProtectionSafety.VerifyMaintenance(x, state.CaCertificatePem, state.TenantId, state.EndpointId, state.InstallationId)).ToArray();
            var verifier = new WindowsAgentProtectionVerifier(options.DataDirectory); var report = await verifier.VerifyAsync(state.TenantId, state.EndpointId, state.InstallationId, ProductRelease.Version, current, authorized, true, ct);
            using var response = await client.PostAsJsonAsync("/agent/v1/self-protection/reports" + suffix, report, Json, ct); response.EnsureSuccessStatusCode(); next = DateTimeOffset.UtcNow.AddSeconds(current.VerificationIntervalSeconds);
        }
        catch (Exception e) when (e is HttpRequestException or IOException or JsonException or UnauthorizedAccessException)
        {
            log.LogWarning("Self-protection verification failed safely without stopping telemetry: {ErrorType}", e.GetType().Name); next = DateTimeOffset.UtcNow.AddSeconds(30);
        }
    }
    int LoadVersion() { try { return JsonSerializer.Deserialize<AgentProtectionPolicy>(File.ReadAllText(cachePath), Json)?.Version ?? 0; } catch { return 0; } }
    async Task ReportPolicyFailure(AgentState state, HttpClient client, AgentProtectionPolicy policy, string observed, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow; var result = new ResourceIntegrityResult("policy-envelope", ProtectedResourceType.PolicyCache, IntegrityState.InvalidIdentity, cachePath, "valid signed endpoint-bound monotonic policy", observed, "rsa-sha256+binding+version", AgentProtectionSafety.Hash(new { policy.Version, observed }), now, TamperPreventionResult.Prevented, RepairState.NotRequested, null, ["policy-rejected"], "agent-policy-verifier.v1"); var id = AgentProtectionSafety.StableId(state.TenantId, state.EndpointId.ToString("D"), "agent.policy.tampered", result.EvidenceHash); var evt = new TamperEvent("agent-tamper-event.v1", id, state.TenantId, state.EndpointId, state.InstallationId, "agent.policy.tampered", result.ResourceId, result.Type, result.ExpectedState, result.ObservedState, result.EvidenceHash, result.Prevention, result.Repair, null, now, Math.Max(1, policy.Version), ["agent://policy-envelope"], result.Provenance, ""); evt = evt with { EventHash = AgentProtectionSafety.EventHash(evt) }; var snapshot = new ProtectionSnapshot("agent-protection-snapshot.v1", state.TenantId, state.EndpointId, state.InstallationId, Math.Max(1, policy.Version), ProtectionState.TamperDetected, now, [result], 1, 1, RepairState.NotRequested, false, null, "0.3.0", ""); snapshot = snapshot with { SnapshotHash = AgentProtectionSafety.SnapshotHash(snapshot) }; using var response = await client.PostAsJsonAsync($"/agent/v1/self-protection/reports?endpointId={state.EndpointId:D}&installationId={Uri.EscapeDataString(state.InstallationId)}", new ProtectionReport(snapshot, [evt]), Json, ct); if (!response.IsSuccessStatusCode) log.LogWarning("Rejected policy tamper report was not accepted: {StatusCode}", response.StatusCode);
    }
    static async Task<T?> Envelope<T>(HttpClient client, string path, CancellationToken ct)
    {
        using var response = await client.GetAsync(path, ct); if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return default; response.EnsureSuccessStatusCode(); var envelope = await response.Content.ReadFromJsonAsync<ApiEnvelope<T>>(Json, ct); return envelope is null ? default : envelope.Data;
    }
    static async Task AtomicWrite(string path, string content, CancellationToken ct) { Directory.CreateDirectory(Path.GetDirectoryName(path)!); var tmp = path + ".tmp"; await File.WriteAllTextAsync(tmp, content, ct); File.Move(tmp, path, true); }
}

sealed class WindowsAgentProtectionVerifier(string dataDirectory)
{
    public async Task<ProtectionReport> VerifyAsync(string tenant, Guid endpoint, string installation, string agentVersion,
        AgentProtectionPolicy policy, MaintenanceAuthorization[] maintenance, bool identityHealthy, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow; var active = maintenance.Where(x => x.StartsAt <= now && x.ExpiresAt > now).ToArray(); var results = new List<ResourceIntegrityResult>(); long hashed = 0;
        foreach (var resource in policy.Resources.Take(AgentProtectionSafety.MaximumResources))
        {
            ct.ThrowIfCancellationRequested(); ResourceIntegrityResult result;
            try { result = resource.Type switch { ProtectedResourceType.AgentBinary or ProtectedResourceType.RequiredLibrary => await FileResult(resource, policy.MaximumHashBytesPerCycle - hashed, now, ct), ProtectedResourceType.AgentService => await ServiceResult(resource, policy, now, ct), ProtectedResourceType.Certificate or ProtectedResourceType.PrivateKey or ProtectedResourceType.InstallationIdentity => IdentityResult(resource, identityHealthy, now), ProtectedResourceType.IsolationControl => await IsolationResult(resource, now, ct), _ => await StateResult(resource, now, ct) }; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or System.ComponentModel.Win32Exception) { result = Result(resource, IntegrityState.Unknown, "verification-error:" + e.GetType().Name, now, ["verification-error"]); }
            if (active.Any(x => Allows(x.Capabilities, resource.Type)) && result.State != IntegrityState.Healthy) result = result with { State = IntegrityState.MaintenanceSuppressed, Prevention = TamperPreventionResult.AuthorizedMaintenance, Quality = result.Quality.Append("authorized-maintenance-scope").ToArray() };
            results.Add(result); if (resource.ExpectedSha256 is not null && File.Exists(resource.ObjectName)) hashed += new FileInfo(resource.ObjectName).Length;
        }
        var events = results.Where(x => x.State is not (IntegrityState.Healthy or IntegrityState.MaintenanceSuppressed)).Take(policy.MaximumEventsPerReport).Select(x => Event(tenant, endpoint, installation, policy.Version, x)).ToArray(); var state = AgentProtectionSafety.State(results.ToArray(), active.Length > 0, policy.Enabled); var repair = results.Any(x => x.Repair == RepairState.Failed) ? RepairState.Failed : results.Any(x => x.Repair == RepairState.Succeeded) ? RepairState.Succeeded : RepairState.NotRequested; var snapshot = new ProtectionSnapshot("agent-protection-snapshot.v1", tenant, endpoint, installation, policy.Version, state, now, results.ToArray(), events.Length, results.Count(x => x.State is not (IntegrityState.Healthy or IntegrityState.MaintenanceSuppressed)), repair, active.Length > 0, active.OrderBy(x => x.ExpiresAt).FirstOrDefault()?.ExpiresAt, agentVersion, ""); snapshot = snapshot with { SnapshotHash = AgentProtectionSafety.SnapshotHash(snapshot) }; return new(snapshot, events);
    }
    static async Task<ResourceIntegrityResult> FileResult(ProtectedResourceDefinition resource, long remaining, DateTimeOffset now, CancellationToken ct)
    {
        if (!File.Exists(resource.ObjectName)) return Result(resource, IntegrityState.Missing, "missing", now);
        var before = NativeFileSnapshotReader.TryRead(resource.ObjectName); if (before is null) return Result(resource, IntegrityState.Unknown, "native-identity-unavailable", now);
        if (before.Identity.SymbolicLink == true || before.Identity.HardLink == true) return Result(resource, IntegrityState.Replaced, $"unsafe-link:{Identity(before)}", now, ["reparse-or-hardlink"]);
        var identity = Identity(before); if (resource.ExpectedNativeIdentity is not null && resource.ExpectedNativeIdentity != identity) return Result(resource, IntegrityState.Replaced, $"native={identity}", now);
        if (resource.ExpectedSha256 is not null)
        {
            if (before.Size > remaining) return Result(resource, IntegrityState.Unknown, "cycle-hash-budget-exhausted", now, ["bounded-hash-deferred"]);
            await using var stream = new FileStream(resource.ObjectName, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan); var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).ToLowerInvariant(); var after = NativeFileSnapshotReader.TryRead(resource.ObjectName); if (after is null || !before.SameState(after)) return Result(resource, IntegrityState.Replaced, "identity-or-state-changed-during-hash", now, ["race-detected"]); if (!CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(hash), System.Text.Encoding.ASCII.GetBytes(resource.ExpectedSha256))) return Result(resource, IntegrityState.Modified, $"sha256={hash};native={identity}", now);
        }
        var permission = Permission(resource.ObjectName, resource.ExpectedOwner, resource.ExpectedSecurityDescriptor); if (permission is not null) return Result(resource, IntegrityState.PermissionDrift, permission, now);
        return Result(resource, IntegrityState.Healthy, $"sha256={resource.ExpectedSha256 ?? "not-required"};native={identity}", now);
    }
    static async Task<ResourceIntegrityResult> ServiceResult(ProtectedResourceDefinition resource, AgentProtectionPolicy policy, DateTimeOffset now, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Result(resource, IntegrityState.Unknown, "windows-service-source-unavailable", now, ["platform-unsupported"]); var qc = await Sc(resource.ObjectName, "qc", ct); var query = await Sc(resource.ObjectName, "query", ct); if (qc.ExitCode != 0) return Result(resource, IntegrityState.Missing, "service-not-found", now); var observed = qc.Output + "\n" + query.Output; var state = query.Output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase) || resource.ExpectedSigner == "state:any" ? IntegrityState.Healthy : IntegrityState.Stopped; if (resource.ExpectedVersion is { } startup && !qc.Output.Contains(startup, StringComparison.OrdinalIgnoreCase)) state = IntegrityState.Disabled; if (resource.ExpectedNativeIdentity is { } path && !qc.Output.Contains(path, StringComparison.OrdinalIgnoreCase)) state = IntegrityState.Replaced; if (resource.ExpectedOwner.Length > 0 && !qc.Output.Contains(resource.ExpectedOwner, StringComparison.OrdinalIgnoreCase)) state = IntegrityState.PermissionDrift; var repair = RepairState.NotRequested; if (state == IntegrityState.Disabled && resource.RepairMethod == "service-startup" && policy.RepairServiceConfiguration) { var repaired = await Sc(resource.ObjectName, "config", ct, "start=", "auto"); repair = repaired.ExitCode == 0 ? RepairState.Succeeded : RepairState.Failed; }
        return Result(resource, state, AgentProtectionSafety.Hash(observed), now, repair: repair);
    }
    static ResourceIntegrityResult IdentityResult(ProtectedResourceDefinition resource, bool healthy, DateTimeOffset now) => Result(resource, healthy ? IntegrityState.Healthy : IntegrityState.InvalidIdentity, healthy ? "present;bound;private-key-not-exported" : "missing-or-binding-invalid", now);
    async Task<ResourceIntegrityResult> StateResult(ProtectedResourceDefinition resource, DateTimeOffset now, CancellationToken ct)
    {
        var path = Resolve(resource.ObjectName); if (!File.Exists(path) && !Directory.Exists(path)) return Result(resource, IntegrityState.Missing, "missing", now); var permission = Permission(path, resource.ExpectedOwner, resource.ExpectedSecurityDescriptor); if (permission is not null) return Result(resource, IntegrityState.PermissionDrift, permission, now); if (File.Exists(path)) { try { var bytes = await File.ReadAllBytesAsync(path, ct); if (bytes.Length == 0) return Result(resource, IntegrityState.Corrupt, "empty-state-file", now); if (Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase)) using (JsonDocument.Parse(bytes)) { } if (resource.ExpectedSha256 is { } expected) { var actual = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); if (actual != expected) return Result(resource, IntegrityState.Modified, $"sha256={actual}", now); } } catch (JsonException) { return Result(resource, IntegrityState.Corrupt, "malformed-json", now); } }
        else { var files = Directory.EnumerateFiles(path, "*", SearchOption.TopDirectoryOnly).Take(1001).ToArray(); if (files.Length > 1000) return Result(resource, IntegrityState.Unknown, "directory-bound-exceeded", now, ["bounded-scan"]); foreach (var file in files.Where(x => Path.GetExtension(x).Equals(".json", StringComparison.OrdinalIgnoreCase))) try { using var document = JsonDocument.Parse(await File.ReadAllBytesAsync(file, ct)); } catch (JsonException) { return Result(resource, IntegrityState.Corrupt, $"malformed:{Path.GetFileName(file)}", now); } }
        return Result(resource, IntegrityState.Healthy, "present;bounded-content-valid", now);
    }
    static async Task<ResourceIntegrityResult> IsolationResult(ProtectedResourceDefinition resource, DateTimeOffset now, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Result(resource, IntegrityState.Unknown, "windows-firewall-source-unavailable", now, ["platform-unsupported"]); var result = await PowerShell($"@(Get-NetFirewallRule -PolicyStore PersistentStore -Group '{resource.ObjectName.Replace("'", "''", StringComparison.Ordinal)}' -ErrorAction SilentlyContinue).Count", ct); return result.ExitCode == 0 && int.TryParse(result.Output.Trim(), out var count) && count > 0 ? Result(resource, IntegrityState.Healthy, $"owned-rules={count}", now) : Result(resource, IntegrityState.Modified, "owned-rules=0", now);
    }
    string Resolve(string value) => value.StartsWith("agent-data:", StringComparison.Ordinal) ? Path.Combine(dataDirectory, value[11..]) : value;
    static string? Permission(string path, string owner, string? expectedDescriptor)
    {
        if (!OperatingSystem.IsWindows() || owner.Length == 0 && expectedDescriptor is null) return null; try { FileSystemSecurity security = Directory.Exists(path) ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl(); var actualOwner = security.GetOwner(typeof(SecurityIdentifier))?.Value ?? "unknown"; if (owner.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) && actualOwner != new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value) return $"owner={actualOwner}"; if (expectedDescriptor is { Length: > 0 } && expectedDescriptor.StartsWith("O:", StringComparison.Ordinal) && security.GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner) != expectedDescriptor) return "security-descriptor-mismatch"; return null; } catch (Exception e) when (e is UnauthorizedAccessException or SystemException) { return "acl-unavailable:" + e.GetType().Name; }
    }
    static ResourceIntegrityResult Result(ProtectedResourceDefinition r, IntegrityState state, string observed, DateTimeOffset now, string[]? quality = null, RepairState repair = RepairState.NotRequested) => new(r.ResourceId, r.Type, state, r.Sensitive ? "[protected-resource]" : r.ObjectName, Expected(r), observed, r.VerificationMethod, AgentProtectionSafety.Hash(new { r.ResourceId, state, observed }), now, state == IntegrityState.Healthy ? TamperPreventionResult.Prevented : TamperPreventionResult.DetectedOnly, repair, null, quality ?? [], "windows-agent-supported-apis.v1");
    static string Expected(ProtectedResourceDefinition r) => AgentProtectionSafety.Hash(new { r.ExpectedOwner, r.ExpectedSecurityDescriptor, r.ExpectedSha256, r.ExpectedNativeIdentity, r.ExpectedSigner, r.ExpectedVersion });
    static TamperEvent Event(string tenant, Guid endpoint, string installation, int version, ResourceIntegrityResult r) { var type = AgentProtectionSafety.EventType(r); var id = AgentProtectionSafety.StableId(tenant, endpoint.ToString("D"), installation, type, r.ResourceId, r.EvidenceHash); var value = new TamperEvent("agent-tamper-event.v1", id, tenant, endpoint, installation, type, r.ResourceId, r.Type, r.ExpectedState, r.ObservedState, r.EvidenceHash, r.Prevention, r.Repair, r.ActorProcess, r.VerifiedAt, version, [$"agent://protected-resource/{r.ResourceId}"], r.Provenance, ""); return value with { EventHash = AgentProtectionSafety.EventHash(value) }; }
    static bool Allows(string[] capabilities, ProtectedResourceType type) => capabilities.Any(x => x switch { "uninstall" => true, "upgrade" => type is ProtectedResourceType.AgentBinary or ProtectedResourceType.RequiredLibrary or ProtectedResourceType.UpdateManifest, "certificate-rotation" => type is ProtectedResourceType.Certificate or ProtectedResourceType.PrivateKey or ProtectedResourceType.InstallationIdentity, "repair" => true, "controlled-troubleshooting" => type is ProtectedResourceType.AgentService or ProtectedResourceType.Configuration or ProtectedResourceType.CollectorConfiguration, _ => false });
    static string Identity(NativeFileSnapshot s) => string.Join(':', s.Identity.VolumeId ?? "", s.Identity.FileId ?? "", s.Size);
    static Task<CommandResult> Sc(string service, string command, CancellationToken ct, params string[] extra) => Command("sc.exe", [command, service, .. extra], ct);
    static Task<CommandResult> PowerShell(string script, CancellationToken ct) => Command("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], ct);
    static async Task<CommandResult> Command(string file, string[] args, CancellationToken ct) { using var p = new Process { StartInfo = new(file) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } }; foreach (var a in args) p.StartInfo.ArgumentList.Add(a); p.Start(); var output = await p.StandardOutput.ReadToEndAsync(ct); var error = await p.StandardError.ReadToEndAsync(ct); await p.WaitForExitAsync(ct); return new(p.ExitCode, (output + "\n" + error).Trim()); }
    sealed record CommandResult(int ExitCode, string Output);
}

static class AgentSelfProtectionSelfTest
{
    static readonly JsonSerializerOptions OutputJson = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    public static async Task<int> RunAsync(string? root, string? output)
    {
        root ??= Path.Combine(Path.GetTempPath(), "sprint26-self-protection-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root); var elevated = Elevated(); var endpoint = Guid.NewGuid(); var tenant = Guid.NewGuid().ToString(); const string install = "fixture-installation"; const string serviceName = "PlatformSprint26Fixture"; const string firewallGroup = "PlatformSprint26FixtureRules";
        var file = Path.Combine(root, "agent.fixture.exe"); var policyCache = Path.Combine(root, "policy.json"); var queue = Path.Combine(root, "queue"); Directory.CreateDirectory(queue); await File.WriteAllTextAsync(file, "version-a"); await File.WriteAllTextAsync(policyCache, "{\"version\":1}"); await File.WriteAllTextAsync(Path.Combine(queue, "0001.json"), "{}");
        var snapshot = NativeFileSnapshotReader.TryRead(file)!; var hash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(file))).ToLowerInvariant(); var policyHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(policyCache))).ToLowerInvariant(); var native = string.Join(':', snapshot.Identity.VolumeId ?? "", snapshot.Identity.FileId ?? "", snapshot.Size);
        var serviceCreated = false; var firewallCreated = false;
        try
        {
            if (OperatingSystem.IsWindows() && elevated)
            {
                serviceCreated = (await Run("sc.exe", ["create", serviceName, "binPath=", Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\cmd.exe /c exit 0"), "start=", "auto", "obj=", "LocalSystem"])).ExitCode == 0;
                firewallCreated = (await Run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", $"New-NetFirewallRule -Name '{serviceName}' -DisplayName '{serviceName}' -Group '{firewallGroup}' -Direction Outbound -Action Block -RemoteAddress 203.0.113.254 -PolicyStore PersistentStore | Out-Null"])).ExitCode == 0;
            }
            var resources = new List<ProtectedResourceDefinition> { new("agent-copy", ProtectedResourceType.AgentBinary, file, Environment.UserName, null, hash, native, null, "1", "sha256+native-file-id+acl", null), new("policy", ProtectedResourceType.PolicyCache, policyCache, Environment.UserName, null, policyHash, null, null, "1", "sha256+monotonic-version", null), new("queue", ProtectedResourceType.TelemetryQueue, queue, Environment.UserName, null, null, null, null, null, "record-integrity+acl", null) };
            if (serviceCreated) resources.Add(new("service", ProtectedResourceType.AgentService, serviceName, "LocalSystem", null, null, null, "state:any", "AUTO_START", "SCM-query", "service-startup"));
            if (firewallCreated) resources.Add(new("isolation", ProtectedResourceType.IsolationControl, firewallGroup, "SYSTEM", null, null, null, null, null, "owned-rule-manifest", "isolation-rules"));
            var p = new AgentProtectionPolicy("agent-protection-policy.v1", 1, tenant, endpoint, install, true, 30, 16 * 1024 * 1024, 128, true, false, true, resources.ToArray(), DateTimeOffset.UtcNow, "self-test", "", ""); p = p with { PolicyHash = AgentProtectionSafety.PolicyHash(p) }; var verifier = new WindowsAgentProtectionVerifier(root); var healthy = await verifier.VerifyAsync(tenant, endpoint, install, "0.3.0", p, [], true, default);
            if (serviceCreated) await Run("sc.exe", ["config", serviceName, "start=", "disabled"]); var serviceDrift = await verifier.VerifyAsync(tenant, endpoint, install, "0.3.0", p, [], true, default); var serviceRepair = !serviceCreated || serviceDrift.Snapshot.Resources.Any(x => x.ResourceId == "service" && x.State == IntegrityState.Disabled && x.Repair == RepairState.Succeeded);
            await File.WriteAllTextAsync(file, "version-b"); var fileTamper = await verifier.VerifyAsync(tenant, endpoint, install, "0.3.0", p, [], true, default); await File.WriteAllTextAsync(policyCache, "{\"version\":0}"); var policyRollback = await verifier.VerifyAsync(tenant, endpoint, install, "0.3.0", p, [], true, default);
            if (firewallCreated) await Run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", $"Get-NetFirewallRule -PolicyStore PersistentStore -Group '{firewallGroup}' | Remove-NetFirewallRule"]); await File.WriteAllTextAsync(Path.Combine(queue, "0001.json"), "{"); var stateTamper = await verifier.VerifyAsync(tenant, endpoint, install, "0.3.0", p, [], true, default); var isolationDetected = !firewallCreated || stateTamper.Events.Any(x => x.EventType == "agent.isolation.drift");
            var now = DateTimeOffset.UtcNow; var maintenance = new MaintenanceAuthorization("maintenance-authorization.v1", Guid.NewGuid(), tenant, endpoint, install, "requester", "approver", "controlled", ["upgrade"], now.AddSeconds(-1), now.AddMinutes(1), MaintenanceState.Approved, "controlled-hash", "nonce", now, now, "controlled", "controlled", "controlled"); var maintenanceReport = await verifier.VerifyAsync(tenant, endpoint, install, "0.3.0", p, [maintenance], true, default); var eventAgain = await verifier.VerifyAsync(tenant, endpoint, install, "0.3.0", p, [], true, default); var firstFile = fileTamper.Events.FirstOrDefault(x => x.ResourceId == "agent-copy"); var repeatedFile = eventAgain.Events.FirstOrDefault(x => x.ResourceId == "agent-copy");
            var profileA = healthy.Snapshot.State == ProtectionState.Protected && serviceRepair; var profileB = fileTamper.Events.Any(x => x.EventType == "agent.file.modified"); var profileC = policyRollback.Events.Any(x => x.EventType == "agent.policy.tampered"); var profileD = stateTamper.Events.Any(x => x.EventType == "agent.queue.tampered") && isolationDetected; var profileE = maintenanceReport.Snapshot.State == ProtectionState.MaintenanceMode && maintenanceReport.Snapshot.Resources.First(x => x.ResourceId == "agent-copy").State == IntegrityState.MaintenanceSuppressed; var profileF = firstFile is not null && repeatedFile is not null && firstFile.EventId == repeatedFile.EventId;
            var result = new { schemaVersion = "sprint26-native-self-test.v1", platform = OperatingSystem.IsWindows() ? "windows" : "other", elevated, controlledRoot = root, nativeSources = new { fileIdentity = snapshot.Identity, serviceControlManager = serviceCreated, firewallPowerShell = firewallCreated }, profiles = new { A = profileA, B = profileB, C = profileC, D = profileD, E = profileE, F = profileF }, prevention = new { samePrivilege = "ACL/service configuration raises the bar and all drift is verified", administrator = "DETECTED; NOT GUARANTEED PREVENTED", kernel = "NOT OBSERVABLE BY SOURCE / NOT PREVENTABLE without an authorized driver" }, passed = profileA && profileB && profileC && profileD && profileE && profileF }; var json = JsonSerializer.Serialize(result, OutputJson); if (output is not null) { Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!); await File.WriteAllTextAsync(output, json); }
            Console.WriteLine(json); return result.passed ? 0 : 1;
        }
        finally
        {
            if (OperatingSystem.IsWindows() && elevated) { await Run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", $"Get-NetFirewallRule -PolicyStore PersistentStore -Group '{firewallGroup}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"]); await Run("sc.exe", ["delete", serviceName]); }
        }
    }
    static async Task<(int ExitCode, string Output)> Run(string file, string[] args) { using var process = new Process { StartInfo = new(file) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } }; foreach (var value in args) process.StartInfo.ArgumentList.Add(value); process.Start(); var output = await process.StandardOutput.ReadToEndAsync(); var error = await process.StandardError.ReadToEndAsync(); await process.WaitForExitAsync(); return (process.ExitCode, output + error); }
    static bool Elevated() { if (!OperatingSystem.IsWindows()) return Environment.UserName == "root"; using var i = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(i).IsInRole(WindowsBuiltInRole.Administrator); }
}
