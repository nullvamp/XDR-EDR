using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using OpenSecurityPlatform.Foundation;

#pragma warning disable CA1822 // Helpers are intentionally instance-scoped with the executor workflow.
#pragma warning disable CA1416 // Every public entry point rejects non-Windows before these native helpers run.
sealed class WindowsPersistenceRemediation : IDisposable
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    readonly string _agentRoot;
    readonly string _store;
    readonly string _generationPath;
    readonly SemaphoreSlim _gate = new(1, 1);

    public WindowsPersistenceRemediation(string agentRoot)
    {
        _agentRoot = Path.GetFullPath(agentRoot);
        _store = Path.Combine(_agentRoot, "protected-persistence-backups-v1");
        _generationPath = Path.Combine(_agentRoot, "persistence-generations.json");
        Directory.CreateDirectory(_store);
        ProtectDirectory(_store);
        CleanupExpired();
    }

    public sealed record Execution(ResponseActionState State, JsonElement Structured,
        ResponseArtifactUpload[] Artifacts, int Records, ResponseFailureCategory Failure, string? FailureReason);

    public async Task<Execution> ExecuteAsync(AgentState state, SignedResponseActionEnvelope action, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        await _gate.WaitAsync(ct);
        try
        {
            if (PersistenceResponseSafety.IsStatus(action.ActionType)) return Status(state, action);
            if (PersistenceResponseSafety.IsRestore(action.ActionType)) return await Restore(state, action, ct);
            var target = action.Parameters.GetProperty("target").Deserialize<PersistenceRemediationTarget>(Json)
                ?? throw new InvalidDataException("PersistenceTargetMissing");
            PersistenceResponseSafety.ValidateTarget(action.ActionType, target);
            return await Mutate(state, action, target, ct);
        }
        finally { _gate.Release(); }
    }

    async Task<Execution> Mutate(AgentState state, SignedResponseActionEnvelope action,
        PersistenceRemediationTarget target, CancellationToken ct)
    {
        await Task.Yield();
        var started = DateTimeOffset.UtcNow;
        var steps = new List<PersistenceRemediationStep> { Step(PersistenceRemediationStage.Validating, "started", "signed action and stable target contract accepted") };
        try
        {
            ValidateBinding(state, target);
            ValidateProtection(target);
            var current = Capture(target);
            if (current is null) return Failure(state, action, target, started, steps, PersistenceRemediationState.TargetIdentityMismatch, "TargetIdentityMismatch", ResponseFailureCategory.Integrity);
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(current.StateHash), Encoding.ASCII.GetBytes(target.ExpectedStateHash)))
                return Failure(state, action, target, started, steps, PersistenceRemediationState.TargetIdentityMismatch, "TargetIdentityMismatch", ResponseFailureCategory.Integrity);
            steps.Add(Step(PersistenceRemediationStage.Validating, "passed", "live native identity, generation and expected state match"));
            ct.ThrowIfCancellationRequested();
            steps.Add(Step(PersistenceRemediationStage.BackingUp, "started", "bounded pre-mutation backup acquisition"));
            var backup = PersistBackup(state, action, target, current.Payload);
            steps.Add(Step(PersistenceRemediationStage.BackingUp, "passed", $"backup:{backup.Record.BackupId:D};sha256:{backup.Record.ContentSha256}"));
            ct.ThrowIfCancellationRequested();
            steps.Add(Step(PersistenceRemediationStage.MutationStarted, "started", action.ActionType));
            var mutation = MutateNative(action.ActionType, target);
            steps.Add(Step(PersistenceRemediationStage.MutationStarted, mutation.Success ? "passed" : "partial", mutation.Detail));
            steps.Add(Step(PersistenceRemediationStage.Verifying, "started", "native post-state verification"));
            var verified = VerifyMutation(action.ActionType, target, mutation);
            steps.Add(Step(PersistenceRemediationStage.Verifying, verified ? "passed" : "failed", verified ? "expected post-state observed" : "post-state did not match"));
            var stateValue = !mutation.Success ? mutation.Partial ? PersistenceRemediationState.Partial : PersistenceRemediationState.Failed :
                !verified ? PersistenceRemediationState.VerificationFailed : action.ActionType switch
                {
                    "service.stop" => PersistenceRemediationState.Stopped,
                    "service.disable" or "scheduled_task.disable" => PersistenceRemediationState.Disabled,
                    _ => PersistenceRemediationState.Removed
                };
            var terminal = mutation.Success && verified ? ResponseActionState.Succeeded : ResponseActionState.Failed;
            steps.Add(Step(terminal == ResponseActionState.Succeeded ? PersistenceRemediationStage.Succeeded : mutation.Partial ? PersistenceRemediationStage.Partial : PersistenceRemediationStage.Failed, terminal.ToString(), mutation.Detail));
            var record = Record(state, action, target, backup.Record.BackupId, stateValue, terminal == ResponseActionState.Succeeded ? null : mutation.Detail, steps, backup.Record, started, verified ? "verified" : "failed");
            return new(terminal, JsonSerializer.SerializeToElement(record, Json), [backup.Artifact], steps.Count,
                terminal == ResponseActionState.Succeeded ? ResponseFailureCategory.None : mutation.Category,
                terminal == ResponseActionState.Succeeded ? null : mutation.Detail);
        }
        catch (PersistenceFailure ex)
        {
            return Failure(state, action, target, started, steps, ex.State, ex.Code, ex.Category);
        }
    }

    async Task<Execution> Restore(AgentState state, SignedResponseActionEnvelope action, CancellationToken ct)
    {
        await Task.Yield();
        var started = DateTimeOffset.UtcNow;
        var id = action.Parameters.GetProperty("backupId").GetGuid();
        var steps = new List<PersistenceRemediationStep> { Step(PersistenceRemediationStage.Validating, "started", $"backup:{id:D}") };
        PersistenceBackupRecord backup;
        byte[] payload;
        try
        {
            (backup, payload) = LoadBackup(id);
            if (backup.TenantId != state.TenantId || backup.EndpointId != state.EndpointId || backup.AgentInstallationId != state.InstallationId)
                throw new PersistenceFailure("BackupBindingMismatch", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Authorization);
            if (!backup.RestoreEligible || backup.State is PersistenceRemediationState.Restored)
                throw new PersistenceFailure("RestoreNotEligible", PersistenceRemediationState.Failed, ResponseFailureCategory.Validation);
            ValidateRestoreAction(action.ActionType, backup.Target.RemediationKind);
            steps.Add(Step(PersistenceRemediationStage.Validating, "passed", "DPAPI, SHA-256, tenant, endpoint, installation and action binding verified"));
            ct.ThrowIfCancellationRequested();
            steps.Add(Step(PersistenceRemediationStage.MutationStarted, "started", "explicit restore"));
            var result = RestoreNative(state, backup.Target, payload);
            steps.Add(Step(PersistenceRemediationStage.MutationStarted, result.Success ? "passed" : "failed", result.Detail));
            steps.Add(Step(PersistenceRemediationStage.Verifying, "started", "restored native configuration verification"));
            var verified = result.Success && VerifyRestore(state, backup.Target, payload);
            steps.Add(Step(PersistenceRemediationStage.Verifying, verified ? "passed" : "failed", verified ? "restored configuration matches backup" : "restored configuration mismatch"));
            if (verified)
            {
                backup = backup with { State = PersistenceRemediationState.Restored, RestoreEligible = false, IntegrityState = "dpapi-local-machine+sha256-verified+restored" };
                SaveRecord(backup);
            }
            var terminal = verified ? ResponseActionState.Succeeded : ResponseActionState.Failed;
            steps.Add(Step(verified ? PersistenceRemediationStage.Succeeded : PersistenceRemediationStage.Failed, terminal.ToString(), result.Detail));
            var record = Record(state, action, backup.Target, id, verified ? PersistenceRemediationState.Restored : result.State,
                verified ? null : result.Detail, steps, backup, started, verified ? "verified" : "failed");
            return new(terminal, JsonSerializer.SerializeToElement(record, Json), [], steps.Count,
                verified ? ResponseFailureCategory.None : result.Category, verified ? null : result.Detail);
        }
        catch (PersistenceFailure ex)
        {
            return Failure(state, action, null, started, steps, ex.State, ex.Code, ex.Category, id);
        }
    }

    Execution Status(AgentState state, SignedResponseActionEnvelope action)
    {
        var id = action.Parameters.GetProperty("backupId").GetGuid();
        try
        {
            var (backup, _) = LoadBackup(id);
            if (backup.TenantId != state.TenantId || backup.EndpointId != state.EndpointId || backup.AgentInstallationId != state.InstallationId)
                throw new PersistenceFailure("BackupBindingMismatch", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Authorization);
            var now = DateTimeOffset.UtcNow;
            var record = new PersistenceRemediationRecord(PersistenceResponseSafety.SchemaVersion, action.ActionId, state.TenantId,
                state.EndpointId, state.InstallationId, action.ActionType, backup.Target, id, backup.State, null,
                [Step(PersistenceRemediationStage.Verifying, "passed", "backup metadata and integrity verified")], backup, now, now, "verified");
            return new(ResponseActionState.Succeeded, JsonSerializer.SerializeToElement(record, Json), [], 1, ResponseFailureCategory.None, null);
        }
        catch (PersistenceFailure ex) { return Failure(state, action, null, DateTimeOffset.UtcNow, [], ex.State, ex.Code, ex.Category, id); }
    }

    void ValidateBinding(AgentState state, PersistenceRemediationTarget target)
    {
        var generation = Generation(target);
        if (generation != target.LifecycleGeneration) throw new PersistenceFailure("TargetIdentityMismatch", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Integrity);
        var canonical = target.RemediationKind switch
        {
            PersistenceRemediationKind.Service => target.ServiceName!,
            PersistenceRemediationKind.ScheduledTask => target.TaskPath!,
            _ => target.CanonicalIdentity
        };
        var expected = PersistenceSafety.EntityId(state.EndpointId, state.InstallationId, target.ObjectKind, canonical, generation);
        if (!string.Equals(expected, target.PersistenceEntityId, StringComparison.OrdinalIgnoreCase))
            throw new PersistenceFailure("TargetIdentityMismatch", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Integrity);
    }

    void ValidateProtection(PersistenceRemediationTarget target)
    {
        if (target.RemediationKind == PersistenceRemediationKind.Service)
        {
            var protectedNames = new[] { "WinDefend", "WdNisSvc", "SecurityHealthService", "EventLog", "RpcSs", "DcomLaunch", "SamSs", "LSM", "Schedule", "Wmi", "Winmgmt", "BFE", "mpssvc" };
            if (target.DriverService == true || protectedNames.Contains(target.ServiceName, StringComparer.OrdinalIgnoreCase) ||
                target.ServiceName!.Contains("OpenSecurityPlatform", StringComparison.OrdinalIgnoreCase) ||
                target.ServiceBinaryPath?.StartsWith(_agentRoot, StringComparison.OrdinalIgnoreCase) == true)
                throw new PersistenceFailure("ProtectedObject", PersistenceRemediationState.Protected, ResponseFailureCategory.Authorization);
        }
        if (target.RemediationKind == PersistenceRemediationKind.ScheduledTask &&
            (target.TaskPath!.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase) || target.TaskPath.Contains("OpenSecurityPlatform", StringComparison.OrdinalIgnoreCase) && !target.TaskPath.StartsWith(@"\OpenSecurityPlatform\Sprint21\", StringComparison.OrdinalIgnoreCase)))
            throw new PersistenceFailure("ProtectedObject", PersistenceRemediationState.Protected, ResponseFailureCategory.Authorization);
        if (target.RemediationKind is PersistenceRemediationKind.RegistryValue or PersistenceRemediationKind.RegistryKey or PersistenceRemediationKind.GenericRegistryConfiguration)
        {
            var full = $"{target.RegistryHive}\\{target.RegistryKeyPath}";
            var allowed = full.StartsWith(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase) ||
                full.StartsWith(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase) ||
                full.StartsWith(@"HKCU\Software\OpenSecurityPlatform\Sprint21", StringComparison.OrdinalIgnoreCase);
            if (!allowed || full.Contains(@"\Winlogon", StringComparison.OrdinalIgnoreCase) || full.Contains(@"\Control\Lsa", StringComparison.OrdinalIgnoreCase) ||
                full.Contains(@"\AppCertDlls", StringComparison.OrdinalIgnoreCase) || full.Contains(@"\Image File Execution Options", StringComparison.OrdinalIgnoreCase))
                throw new PersistenceFailure("ProtectedObject", PersistenceRemediationState.Protected, ResponseFailureCategory.Authorization);
        }
        if ((target.RemediationKind is PersistenceRemediationKind.WmiFilter or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiBinding) &&
            !string.Equals(target.WmiNamespace, @"root\subscription", StringComparison.OrdinalIgnoreCase))
            throw new PersistenceFailure("ProtectedObject", PersistenceRemediationState.Protected, ResponseFailureCategory.Authorization);
        if (target.FilePath?.StartsWith(_agentRoot, StringComparison.OrdinalIgnoreCase) == true || target.FilePath?.StartsWith(_store, StringComparison.OrdinalIgnoreCase) == true)
            throw new PersistenceFailure("ProtectedObject", PersistenceRemediationState.Protected, ResponseFailureCategory.Authorization);
    }

    Captured? Capture(PersistenceRemediationTarget target) => target.RemediationKind switch
    {
        PersistenceRemediationKind.RegistryValue or PersistenceRemediationKind.RegistryKey or PersistenceRemediationKind.GenericRegistryConfiguration => CaptureRegistry(target),
        PersistenceRemediationKind.Service => CaptureService(target),
        PersistenceRemediationKind.ScheduledTask => CaptureTask(target),
        PersistenceRemediationKind.WmiFilter or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiBinding => CaptureWmi(target),
        _ => throw new PersistenceFailure("RemediationNotSupported", PersistenceRemediationState.Failed, ResponseFailureCategory.Unsupported)
    };

    Captured? CaptureRegistry(PersistenceRemediationTarget target)
    {
        using var root = RegistryRoot(target.RegistryHive!, target.RegistryView!, true);
        using var key = root.OpenSubKey(target.RegistryKeyPath!, true);
        if (key is null) return null;
        if (target.RemediationKind == PersistenceRemediationKind.RegistryKey)
        {
            if (key.SubKeyCount != 0 || key.ValueCount != 0) throw new PersistenceFailure("RegistryKeyNotEmpty", PersistenceRemediationState.Protected, ResponseFailureCategory.Authorization);
            var payload = JsonSerializer.SerializeToUtf8Bytes(new RegistryPayload(target.RegistryHive!, target.RegistryView!, target.RegistryKeyPath!, null, "Key", ""), Json);
            return new(target.ExpectedStateHash, payload);
        }
        if (!key.GetValueNames().Contains(target.RegistryValueName!, StringComparer.OrdinalIgnoreCase)) return null;
        var kind = key.GetValueKind(target.RegistryValueName!); var raw = key.GetValue(target.RegistryValueName!, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        var text = ValueText(raw); var hash = PersistenceResponseSafety.StateHash(target.CanonicalIdentity, text);
        var payloadValue = EncodeRegistry(raw, kind);
        return new(hash, JsonSerializer.SerializeToUtf8Bytes(new RegistryPayload(target.RegistryHive!, target.RegistryView!, target.RegistryKeyPath!, target.RegistryValueName!, kind.ToString(), payloadValue), Json));
    }

    Captured? CaptureService(PersistenceRemediationTarget target)
    {
        var payload = CaptureServicePayload(target.ServiceName!); if (payload is null) return null;
        var hash = PersistenceResponseSafety.StateHash(payload.Name, payload.BinaryPath, NormalizeStart(payload.StartMode), payload.Account, payload.Driver.ToString(CultureInfo.InvariantCulture));
        return new(hash, JsonSerializer.SerializeToUtf8Bytes(payload, Json));
    }

    Captured? CaptureTask(PersistenceRemediationTarget target)
    {
        var value = GetTask(target.TaskPath!); if (value is null) return null;
        try
        {
            dynamic task = value.Task!; string xml = task.Xml; bool enabled = task.Enabled;
            if (Encoding.UTF8.GetByteCount(xml) > PersistenceResponseSafety.MaximumBackupBytes) throw new PersistenceFailure("BackupSizeExceeded", PersistenceRemediationState.Failed, ResponseFailureCategory.OutputLimit);
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(xml))).ToLowerInvariant();
            return new(PersistenceResponseSafety.StateHash(target.TaskPath, hash), JsonSerializer.SerializeToUtf8Bytes(new TaskPayload(target.TaskPath!, xml, enabled), Json));
        }
        finally { value.Dispose(); }
    }

    Captured? CaptureWmi(PersistenceRemediationTarget target)
    {
        using var value = WmiObject(target); if (value is null) return null; value.Get();
        var properties = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        foreach (PropertyData property in value.Properties)
        {
            if (property.Name.StartsWith("__", StringComparison.Ordinal) || property.Value is null) continue;
            if (properties.Count >= 64) break;
            if (property.Value is string text && text.Length <= 32767) properties[property.Name] = JsonSerializer.SerializeToElement(text);
            else if (property.Value is string[] strings && strings.Length <= 64 && strings.All(x => x.Length <= 4096)) properties[property.Name] = JsonSerializer.SerializeToElement(strings);
            else if (property.Value is byte[] bytes && bytes.Length <= 4096) properties[property.Name] = JsonSerializer.SerializeToElement(Convert.ToBase64String(bytes));
            else if (property.Value is int or uint or long or ulong or short or ushort or bool) properties[property.Name] = JsonSerializer.SerializeToElement(property.Value);
        }
        var filter = Text(value, "Filter"); var consumer = Text(value, "Consumer"); var expected = target.RemediationKind == PersistenceRemediationKind.WmiFilter ? Text(value, "Query") ?? Text(value, "EventNamespace") : target.RemediationKind == PersistenceRemediationKind.WmiConsumer ? Text(value, "ExecutablePath") ?? Text(value, "CommandLineTemplate") ?? Text(value, "ScriptText") : null;
        var hash = PersistenceResponseSafety.StateHash(target.CanonicalIdentity, filter, consumer, expected);
        return new(hash, JsonSerializer.SerializeToUtf8Bytes(new WmiPayload(target.WmiNamespace!, target.WmiClass!, target.WmiRelativePath!, properties), Json));
    }

    MutationResult MutateNative(string action, PersistenceRemediationTarget target) => action switch
    {
        "registry.value.remove" or "persistence.remove" when target.RemediationKind is PersistenceRemediationKind.RegistryValue or PersistenceRemediationKind.GenericRegistryConfiguration => RemoveRegistryValue(target),
        "registry.key.remove" => RemoveRegistryKey(target),
        "service.stop" => StopService(target),
        "service.disable" => ChangeServiceStart(target, "Disabled"),
        "service.delete" => DeleteService(target),
        "scheduled_task.disable" => DisableTask(target),
        "scheduled_task.delete" => DeleteTask(target),
        "wmi.binding.remove" or "wmi.consumer.remove" or "wmi.filter.remove" or "persistence.remove" when target.RemediationKind is PersistenceRemediationKind.WmiBinding or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiFilter => RemoveWmi(target),
        _ => throw new PersistenceFailure("RemediationNotSupported", PersistenceRemediationState.Failed, ResponseFailureCategory.Unsupported)
    };

    MutationResult RemoveRegistryValue(PersistenceRemediationTarget target)
    {
        using var root = RegistryRoot(target.RegistryHive!, target.RegistryView!, true); using var key = root.OpenSubKey(target.RegistryKeyPath!, true);
        if (key is null) return new(false, false, "TargetIdentityMismatch", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Integrity);
        key.DeleteValue(target.RegistryValueName!, true); key.Flush(); return new(true, false, "exact registry value removed", PersistenceRemediationState.Removed, ResponseFailureCategory.None);
    }
    MutationResult RemoveRegistryKey(PersistenceRemediationTarget target)
    {
        var slash = target.RegistryKeyPath!.LastIndexOf('\\'); if (slash <= 0) throw new PersistenceFailure("RegistryKeyScopeInvalid", PersistenceRemediationState.Protected, ResponseFailureCategory.Authorization);
        using var root = RegistryRoot(target.RegistryHive!, target.RegistryView!, true); using var parent = root.OpenSubKey(target.RegistryKeyPath[..slash], true);
        if (parent is null) return new(false, false, "TargetIdentityMismatch", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Integrity);
        parent.DeleteSubKey(target.RegistryKeyPath[(slash + 1)..], true); parent.Flush(); return new(true, false, "exact empty controlled registry key removed", PersistenceRemediationState.Removed, ResponseFailureCategory.None);
    }
    MutationResult StopService(PersistenceRemediationTarget target)
    {
        if (CaptureServicePayload(target.ServiceName!) is null) return new(false, false, "TargetIdentityMismatch", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Integrity);
        if (!string.Equals(ServiceState(target.ServiceName!), "Stopped", StringComparison.OrdinalIgnoreCase)) { var result = RunSc("stop", target.ServiceName!); if (result.ExitCode != 0 && !result.Output.Contains("1062", StringComparison.Ordinal)) return new(false, false, $"StopService:{result.ExitCode}", PersistenceRemediationState.Failed, ResponseFailureCategory.Execution); }
        return WaitService(target.ServiceName!, "Stopped") ? new(true, false, "exact service stopped", PersistenceRemediationState.Stopped, ResponseFailureCategory.None) : new(false, true, "ServiceStopVerificationFailed", PersistenceRemediationState.Partial, ResponseFailureCategory.Execution);
    }
    MutationResult ChangeServiceStart(PersistenceRemediationTarget target, string mode)
    {
        if (CaptureServicePayload(target.ServiceName!) is null) return new(false, false, "TargetIdentityMismatch", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Integrity);
        var result = RunSc("config", target.ServiceName!, "start=", ScStart(mode));
        return result.ExitCode == 0 ? new(true, false, $"service start mode set to {mode}", PersistenceRemediationState.Disabled, ResponseFailureCategory.None) : new(false, false, $"ChangeStartMode:{result.ExitCode}", PersistenceRemediationState.Failed, ResponseFailureCategory.Execution);
    }
    MutationResult DeleteService(PersistenceRemediationTarget target)
    {
        var stop = StopService(target); if (!stop.Success && !string.Equals(stop.Detail, "TargetIdentityMismatch", StringComparison.Ordinal)) return stop with { Partial = true };
        if (CaptureServicePayload(target.ServiceName!) is null) return new(true, false, "service already absent after stop", PersistenceRemediationState.Removed, ResponseFailureCategory.None);
        var result = RunSc("delete", target.ServiceName!);
        return result.ExitCode == 0 ? new(true, false, "exact service deleted", PersistenceRemediationState.Removed, ResponseFailureCategory.None) : new(false, true, $"DeleteService:{result.ExitCode}", PersistenceRemediationState.Partial, ResponseFailureCategory.Execution);
    }
    MutationResult DisableTask(PersistenceRemediationTarget target)
    {
        var value = GetTask(target.TaskPath!); if (value is null) return new(false, false, "TargetIdentityMismatch", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Integrity);
        try { ((dynamic)value.Task!).Enabled = false; return new(true, false, "exact task disabled", PersistenceRemediationState.Disabled, ResponseFailureCategory.None); }
        finally { value.Dispose(); }
    }
    MutationResult DeleteTask(PersistenceRemediationTarget target)
    {
        var value = GetTask(target.TaskPath!); if (value is null) return new(false, false, "TargetIdentityMismatch", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Integrity);
        try { ((dynamic)value.Folder).DeleteTask(value.Name, 0); return new(true, false, "exact task deleted", PersistenceRemediationState.Removed, ResponseFailureCategory.None); }
        finally { value.Dispose(); }
    }
    MutationResult RemoveWmi(PersistenceRemediationTarget target)
    {
        if (target.RemediationKind is PersistenceRemediationKind.WmiFilter or PersistenceRemediationKind.WmiConsumer)
        {
            var references = WmiBindingReferences(target);
            if (references > 0) return new(false, false, "SharedDependency", PersistenceRemediationState.SharedDependency, ResponseFailureCategory.Authorization);
        }
        using var value = WmiObject(target); if (value is null) return new(false, false, "TargetIdentityMismatch", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Integrity);
        value.Delete(); return new(true, false, "exact WMI object removed", PersistenceRemediationState.Removed, ResponseFailureCategory.None);
    }

    bool VerifyMutation(string action, PersistenceRemediationTarget target, MutationResult result)
    {
        if (!result.Success) return false;
        return action switch
        {
            "service.stop" => ServiceState(target.ServiceName!) == "Stopped",
            "service.disable" => ServiceStartMode(target.ServiceName!) == "disabled",
            "scheduled_task.disable" => TaskEnabled(target.TaskPath!) == false,
            _ => Capture(target) is null
        };
    }

    MutationResult RestoreNative(AgentState state, PersistenceRemediationTarget target, byte[] payload) => target.RemediationKind switch
    {
        PersistenceRemediationKind.RegistryValue or PersistenceRemediationKind.RegistryKey or PersistenceRemediationKind.GenericRegistryConfiguration => RestoreRegistry(target, payload),
        PersistenceRemediationKind.Service => RestoreService(state, target, payload),
        PersistenceRemediationKind.ScheduledTask => RestoreTask(state, target, payload),
        PersistenceRemediationKind.WmiFilter or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiBinding => RestoreWmi(target, payload),
        _ => new(false, false, "RestoreNotSupported", PersistenceRemediationState.Failed, ResponseFailureCategory.Unsupported)
    };

    MutationResult RestoreRegistry(PersistenceRemediationTarget target, byte[] bytes)
    {
        var payload = JsonSerializer.Deserialize<RegistryPayload>(bytes, Json) ?? throw new PersistenceFailure("BackupInvalid", PersistenceRemediationState.Failed, ResponseFailureCategory.Integrity);
        using var root = RegistryRoot(payload.Hive, payload.View, true);
        if (payload.Kind == "Key")
        {
            if (root.OpenSubKey(payload.Path, false) is not null) return new(false, false, "DestinationOccupied", PersistenceRemediationState.DestinationOccupied, ResponseFailureCategory.Integrity);
            using var key = root.CreateSubKey(payload.Path, true); return new(true, false, "controlled registry key restored", PersistenceRemediationState.Restored, ResponseFailureCategory.None);
        }
        using var existing = root.OpenSubKey(payload.Path, false); if (existing?.GetValueNames().Contains(payload.Name!, StringComparer.OrdinalIgnoreCase) == true) return new(false, false, "DestinationOccupied", PersistenceRemediationState.DestinationOccupied, ResponseFailureCategory.Integrity);
        using var keyValue = root.CreateSubKey(payload.Path, true); var kind = Enum.Parse<RegistryValueKind>(payload.Kind, true); keyValue.SetValue(payload.Name!, DecodeRegistry(payload.Data, kind), kind); keyValue.Flush(); return new(true, false, "exact registry value restored", PersistenceRemediationState.Restored, ResponseFailureCategory.None);
    }
    MutationResult RestoreService(AgentState state, PersistenceRemediationTarget target, byte[] bytes)
    {
        var payload = JsonSerializer.Deserialize<ServicePayload>(bytes, Json) ?? throw new PersistenceFailure("BackupInvalid", PersistenceRemediationState.Failed, ResponseFailureCategory.Integrity);
        var existing = CaptureServicePayload(payload.Name);
        if (existing is not null)
        {
            ValidateBinding(state, target);
            if (!string.Equals(existing.BinaryPath, payload.BinaryPath, StringComparison.OrdinalIgnoreCase) || !string.Equals(existing.Account, payload.Account, StringComparison.OrdinalIgnoreCase))
                return new(false, false, "IdentityConflict", PersistenceRemediationState.DestinationOccupied, ResponseFailureCategory.Integrity);
            var changed = RunSc("config", payload.Name, "start=", ScStart(payload.StartMode));
            return changed.ExitCode == 0 ? new(true, false, "exact existing service configuration restored", PersistenceRemediationState.Restored, ResponseFailureCategory.None) : new(false, false, $"ChangeStartMode:{changed.ExitCode}", PersistenceRemediationState.Failed, ResponseFailureCategory.Execution);
        }
        if (!string.IsNullOrWhiteSpace(payload.Account) && payload.Account is not ("LocalSystem" or "NT AUTHORITY\\LocalSystem")) return new(false, false, "ServiceAccountRestoreUnsupported", PersistenceRemediationState.Failed, ResponseFailureCategory.Unsupported);
        var create = RunSc("create", payload.Name, "binPath=", payload.BinaryPath, "start=", ScStart(payload.StartMode), "obj=", "LocalSystem", "DisplayName=", payload.DisplayName ?? payload.Name);
        if (create.ExitCode != 0) return new(false, false, $"CreateService:{create.ExitCode}", PersistenceRemediationState.Failed, ResponseFailureCategory.Execution);
        if (payload.Dependencies.Length > 0) _ = RunSc("config", payload.Name, "depend=", string.Join('/', payload.Dependencies));
        if (!string.IsNullOrWhiteSpace(payload.Description)) _ = RunSc("description", payload.Name, payload.Description);
        if (string.Equals(payload.State, "Running", StringComparison.OrdinalIgnoreCase)) _ = RunSc("start", payload.Name);
        return new(true, false, "supported service configuration restored", PersistenceRemediationState.Restored, ResponseFailureCategory.None);
    }
    MutationResult RestoreTask(AgentState state, PersistenceRemediationTarget target, byte[] bytes)
    {
        var payload = JsonSerializer.Deserialize<TaskPayload>(bytes, Json) ?? throw new PersistenceFailure("BackupInvalid", PersistenceRemediationState.Failed, ResponseFailureCategory.Integrity);
        var existing = GetTask(payload.Path);
        if (existing is not null)
        {
            try { ValidateBinding(state, target); dynamic task = existing.Task!; task.Enabled = payload.Enabled; return new(true, false, "exact existing task enabled state restored", PersistenceRemediationState.Restored, ResponseFailureCategory.None); }
            finally { existing.Dispose(); }
        }
        var location = OpenTaskFolder(payload.Path, create: true);
        try { dynamic folder = location.Folder!; _ = folder.RegisterTask(location.Name, payload.Xml, 2, null, null, 0, null); var registered = GetTask(payload.Path); try { if (registered is not null) ((dynamic)registered.Task!).Enabled = payload.Enabled; } finally { registered?.Dispose(); } return new(true, false, "task restored from verified XML backup", PersistenceRemediationState.Restored, ResponseFailureCategory.None); }
        catch (COMException ex) { return new(false, false, $"TaskRestore:{ex.ErrorCode}", PersistenceRemediationState.Failed, ResponseFailureCategory.Execution); }
        finally { location.Dispose(); }
    }
    MutationResult RestoreWmi(PersistenceRemediationTarget target, byte[] bytes)
    {
        var payload = JsonSerializer.Deserialize<WmiPayload>(bytes, Json) ?? throw new PersistenceFailure("BackupInvalid", PersistenceRemediationState.Failed, ResponseFailureCategory.Integrity);
        using var existing = WmiObject(target); if (existing is not null) return new(false, false, "DestinationOccupied", PersistenceRemediationState.DestinationOccupied, ResponseFailureCategory.Integrity);
        var scope = new ManagementScope($@"\\.\{payload.Namespace}"); scope.Connect(); using var cls = new ManagementClass(scope, new ManagementPath(payload.Class), null); using var instance = cls.CreateInstance(); if (instance is null) return new(false, false, "WmiCreateFailed", PersistenceRemediationState.Failed, ResponseFailureCategory.Execution);
        foreach (var item in payload.Properties) if (instance.Properties[item.Key] is not null) instance[item.Key] = WmiValue(item.Value, instance.Properties[item.Key].Type, instance.Properties[item.Key].IsArray);
        _ = instance.Put(); return new(true, false, "WMI object restored without executing consumer payload", PersistenceRemediationState.Restored, ResponseFailureCategory.None);
    }

    bool VerifyRestore(AgentState state, PersistenceRemediationTarget target, byte[] payload)
    {
        try
        {
            return target.RemediationKind switch
            {
                PersistenceRemediationKind.RegistryValue or PersistenceRemediationKind.GenericRegistryConfiguration => VerifyRegistryPayload(JsonSerializer.Deserialize<RegistryPayload>(payload, Json)!),
                PersistenceRemediationKind.RegistryKey => RegistryKeyExists(JsonSerializer.Deserialize<RegistryPayload>(payload, Json)!),
                PersistenceRemediationKind.Service => VerifyServicePayload(JsonSerializer.Deserialize<ServicePayload>(payload, Json)!),
                PersistenceRemediationKind.ScheduledTask => VerifyTaskPayload(JsonSerializer.Deserialize<TaskPayload>(payload, Json)!),
                PersistenceRemediationKind.WmiFilter or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiBinding => WmiObject(target) is not null,
                _ => false
            };
        }
        catch { return false; }
    }

    BackupBundle PersistBackup(AgentState state, SignedResponseActionEnvelope action, PersistenceRemediationTarget target, byte[] payload)
    {
        if (payload.Length > PersistenceResponseSafety.MaximumBackupBytes) throw new PersistenceFailure("BackupSizeExceeded", PersistenceRemediationState.Failed, ResponseFailureCategory.OutputLimit);
        var records = Directory.EnumerateFiles(_store, "metadata.json", SearchOption.AllDirectories).Select(ReadRecord).Where(x => x is not null).Cast<PersistenceBackupRecord>().ToArray();
        if (records.Length >= PersistenceResponseSafety.MaximumStoreRecords || records.Sum(x => x.ContentBytes) + payload.LongLength > PersistenceResponseSafety.MaximumStoreBytes)
            throw new PersistenceFailure("BackupQuotaExceeded", PersistenceRemediationState.Failed, ResponseFailureCategory.OutputLimit);
        var id = action.ActionId; var directory = RecordDirectory(id); Directory.CreateDirectory(directory); ProtectDirectory(directory);
        var hash = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        var record = new PersistenceBackupRecord(id, state.TenantId, state.EndpointId, state.InstallationId, action.ActionId, target, hash, payload.LongLength,
            "dpapi-local-machine", $"agent-protected://persistence-backups/{id:N}", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(PersistenceResponseSafety.RetentionDays), true,
            PersistenceRemediationState.BackupCreated, "dpapi-local-machine+sha256-verified");
        var encrypted = ProtectedData.Protect(payload, Entropy(record), DataProtectionScope.LocalMachine); File.WriteAllBytes(Path.Combine(directory, "content.bin"), encrypted); SaveRecord(record);
        var artifact = new ResponseArtifactUpload(Guid.NewGuid(), $"persistence-backup-{id:N}.json", "application/vnd.open-security-platform.persistence-backup+json", hash, Convert.ToBase64String(payload));
        return new(record, artifact);
    }
    (PersistenceBackupRecord Record, byte[] Payload) LoadBackup(Guid id)
    {
        var record = ReadRecord(Path.Combine(RecordDirectory(id), "metadata.json")) ?? throw new PersistenceFailure("BackupNotFound", PersistenceRemediationState.Failed, ResponseFailureCategory.Validation);
        if (record.RetainUntil <= DateTimeOffset.UtcNow) throw new PersistenceFailure("BackupExpired", PersistenceRemediationState.Failed, ResponseFailureCategory.Validation);
        byte[] payload;
        try { payload = ProtectedData.Unprotect(File.ReadAllBytes(Path.Combine(RecordDirectory(id), "content.bin")), Entropy(record), DataProtectionScope.LocalMachine); }
        catch (CryptographicException) { throw new PersistenceFailure("BackupIntegrityMismatch", PersistenceRemediationState.Failed, ResponseFailureCategory.Integrity); }
        var hash = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(hash), Encoding.ASCII.GetBytes(record.ContentSha256))) throw new PersistenceFailure("BackupIntegrityMismatch", PersistenceRemediationState.Failed, ResponseFailureCategory.Integrity);
        return (record, payload);
    }
    void SaveRecord(PersistenceBackupRecord record) { var path = Path.Combine(RecordDirectory(record.BackupId), "metadata.json"); var temp = path + ".tmp"; File.WriteAllText(temp, JsonSerializer.Serialize(record, Json)); File.Move(temp, path, true); }
    PersistenceBackupRecord? ReadRecord(string path) { try { return JsonSerializer.Deserialize<PersistenceBackupRecord>(File.ReadAllText(path), Json); } catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { return null; } }
    string RecordDirectory(Guid id) => Path.Combine(_store, id.ToString("N"));
    static byte[] Entropy(PersistenceBackupRecord record) => SHA256.HashData(Encoding.UTF8.GetBytes($"{record.TenantId}|{record.EndpointId:D}|{record.AgentInstallationId}|{record.BackupId:D}|persistence-backup-v1"));
    void CleanupExpired() { foreach (var path in Directory.EnumerateFiles(_store, "metadata.json", SearchOption.AllDirectories).ToArray()) { var record = ReadRecord(path); if (record is not null && record.RetainUntil > DateTimeOffset.UtcNow) continue; try { var directory = Path.GetDirectoryName(path)!; foreach (var file in Directory.EnumerateFiles(directory)) { File.SetAttributes(file, FileAttributes.Normal); File.Delete(file); } Directory.Delete(directory); } catch { } } }

    long Generation(PersistenceRemediationTarget target)
    {
        try
        {
            var state = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, long>>>(File.ReadAllText(_generationPath), Json);
            var group = target.RemediationKind == PersistenceRemediationKind.Service ? "services" : target.RemediationKind == PersistenceRemediationKind.ScheduledTask ? "tasks" : "configurations";
            var key = target.RemediationKind == PersistenceRemediationKind.Service ? target.ServiceName! : target.RemediationKind == PersistenceRemediationKind.ScheduledTask ? target.TaskPath! : target.CanonicalIdentity;
            return state?.GetValueOrDefault(group)?.GetValueOrDefault(key) ?? 0;
        }
        catch (Exception ex) when (ex is IOException or JsonException) { throw new PersistenceFailure("GenerationStateUnavailable", PersistenceRemediationState.TargetIdentityMismatch, ResponseFailureCategory.Integrity); }
    }

    static RegistryKey RegistryRoot(string hive, string view, bool writable)
    {
        var h = hive.ToUpperInvariant() switch { "HKCU" => RegistryHive.CurrentUser, "HKLM" => RegistryHive.LocalMachine, _ => throw new PersistenceFailure("RegistryHiveUnsupported", PersistenceRemediationState.Protected, ResponseFailureCategory.Authorization) };
        var v = Enum.TryParse<RegistryView>(view, true, out var parsed) ? parsed : RegistryView.Default;
        return RegistryKey.OpenBaseKey(h, v);
    }
    static ServicePayload? CaptureServicePayload(string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}", false); if (key is null) return null;
            var serviceType = Convert.ToUInt32(key.GetValue("Type", 16), CultureInfo.InvariantCulture); var start = Convert.ToInt32(key.GetValue("Start", 3), CultureInfo.InvariantCulture);
            var error = Convert.ToUInt32(key.GetValue("ErrorControl", 1), CultureInfo.InvariantCulture); var dependencies = key.GetValue("DependOnService") as string[] ?? [];
            return new(name, key.GetValue("DisplayName")?.ToString(), key.GetValue("ImagePath", "", RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "",
                start switch { 0 => "Boot", 1 => "System", 2 => "Automatic", 3 => "Manual", 4 => "Disabled", _ => $"Native:{start}" },
                key.GetValue("ObjectName")?.ToString() ?? "LocalSystem", ServiceState(name), serviceType, error, dependencies,
                key.GetValue("Description")?.ToString(), serviceType is 1 or 2);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException) { return null; }
    }
    static string NormalizeStart(string? value) => value?.ToLowerInvariant() switch { "auto" or "automatic" => "automatic", "manual" => "manual", "disabled" => "disabled", "boot" => "boot", "system" => "system", _ => value?.ToLowerInvariant() ?? "unknown" };
    static string ScStart(string? value) => NormalizeStart(value) switch { "automatic" => "auto", "manual" => "demand", "disabled" => "disabled", "boot" => "boot", "system" => "system", _ => "demand" };
    static ScResult RunSc(params string[] arguments)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe")) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        if (!process.Start()) return new(-1, "start-failed");
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(10_000)) { try { process.Kill(true); } catch { } return new(-2, "timeout"); }
        Task.WaitAll([output, error], 1_000); return new(process.ExitCode, output.Result + "\n" + error.Result);
    }
    static bool WaitService(string name, string state) { var deadline = DateTimeOffset.UtcNow.AddSeconds(20); do { if (string.Equals(ServiceState(name), state, StringComparison.OrdinalIgnoreCase)) return true; Thread.Sleep(250); } while (DateTimeOffset.UtcNow < deadline); return false; }
    static string? ServiceState(string name) { var value = RunSc("query", name); if (value.ExitCode != 0) return null; var line = value.Output.Split('\n').FirstOrDefault(x => x.Contains("STATE", StringComparison.OrdinalIgnoreCase)); return line?.Contains("STOPPED", StringComparison.OrdinalIgnoreCase) == true ? "Stopped" : line?.Contains("RUNNING", StringComparison.OrdinalIgnoreCase) == true ? "Running" : "Pending"; }
    static string? ServiceStartMode(string name) => NormalizeStart(CaptureServicePayload(name)?.StartMode);

    static TaskLocation? GetTask(string path) { try { var value = OpenTaskFolder(path, false); value.Task = ((dynamic)value.Folder).GetTask(value.Name); return value; } catch (Exception ex) when (ex is COMException or FileNotFoundException) { return null; } }
    static TaskLocation OpenTaskFolder(string path, bool create)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new PlatformNotSupportedException(); var service = Activator.CreateInstance(type)!; dynamic scheduler = service; scheduler.Connect(); var slash = path.LastIndexOf('\\'); var folderPath = slash <= 0 ? "\\" : path[..slash]; var name = path[(slash + 1)..]; object folder;
        try { folder = scheduler.GetFolder(folderPath); }
        catch (COMException) when (create) { dynamic current = scheduler.GetFolder("\\"); foreach (var part in folderPath.Split('\\', StringSplitOptions.RemoveEmptyEntries)) { try { current = current.GetFolder(part); } catch (COMException) { current = current.CreateFolder(part); } } folder = current; }
        return new(service, folder, name);
    }
    static bool? TaskEnabled(string path) { var value = GetTask(path); if (value is null) return null; try { return (bool)((dynamic)value.Task!).Enabled; } finally { value.Dispose(); } }
    static ManagementObject? WmiObject(PersistenceRemediationTarget target) { try { var scope = new ManagementScope($@"\\.\{target.WmiNamespace}"); scope.Connect(); var value = new ManagementObject(scope, new ManagementPath(target.WmiRelativePath), null); value.Get(); return value; } catch (ManagementException) { return null; } }
    static int WmiBindingReferences(PersistenceRemediationTarget target)
    {
        var scope = new ManagementScope($@"\\.\{target.WmiNamespace}"); scope.Connect(); using var search = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Filter,Consumer FROM __FilterToConsumerBinding")); using var values = search.Get(); var count = 0;
        foreach (ManagementBaseObject value in values) using (value) { var reference = target.RemediationKind == PersistenceRemediationKind.WmiFilter ? value["Filter"]?.ToString() : value["Consumer"]?.ToString(); if (string.Equals(reference, target.WmiRelativePath, StringComparison.OrdinalIgnoreCase) || reference?.Contains(target.WmiRelativePath!, StringComparison.OrdinalIgnoreCase) == true) count++; }
        return count;
    }
    static string? Text(ManagementBaseObject value, string property) { try { return value[property]?.ToString(); } catch (ManagementException) { return null; } }
    static object? WmiValue(JsonElement value, CimType type, bool array)
    {
        if (array && type == CimType.String) return value.EnumerateArray().Select(x => x.GetString() ?? "").ToArray();
        if (array && type == CimType.UInt8) return Convert.FromBase64String(value.GetString() ?? "");
        return type switch { CimType.String or CimType.Reference or CimType.DateTime => value.GetString(), CimType.Boolean => value.GetBoolean(), CimType.SInt32 => value.GetInt32(), CimType.UInt32 => value.GetUInt32(), CimType.SInt64 => value.GetInt64(), CimType.UInt64 => value.GetUInt64(), CimType.UInt16 => value.GetUInt16(), CimType.SInt16 => value.GetInt16(), CimType.UInt8 => value.GetByte(), _ => value.ToString() };
    }

    static string ValueText(object? value) => value switch { null => "", string text => text, string[] values => string.Join(';', values), byte[] bytes => $"binary:{bytes.Length}", _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "" };
    static string EncodeRegistry(object? value, RegistryValueKind kind) => kind switch { RegistryValueKind.Binary or RegistryValueKind.None => Convert.ToBase64String(value as byte[] ?? []), RegistryValueKind.MultiString => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(value as string[] ?? [])), RegistryValueKind.DWord => Convert.ToBase64String(BitConverter.GetBytes(Convert.ToInt32(value, CultureInfo.InvariantCulture))), RegistryValueKind.QWord => Convert.ToBase64String(BitConverter.GetBytes(Convert.ToInt64(value, CultureInfo.InvariantCulture))), _ => Convert.ToBase64String(Encoding.UTF8.GetBytes(value?.ToString() ?? "")) };
    static object DecodeRegistry(string value, RegistryValueKind kind) { var bytes = Convert.FromBase64String(value); return kind switch { RegistryValueKind.Binary or RegistryValueKind.None => bytes, RegistryValueKind.MultiString => JsonSerializer.Deserialize<string[]>(bytes) ?? [], RegistryValueKind.DWord => BitConverter.ToInt32(bytes), RegistryValueKind.QWord => BitConverter.ToInt64(bytes), _ => Encoding.UTF8.GetString(bytes) }; }
    static bool VerifyRegistryPayload(RegistryPayload payload) { using var root = RegistryRoot(payload.Hive, payload.View, false); using var key = root.OpenSubKey(payload.Path, false); if (key is null || !key.GetValueNames().Contains(payload.Name!, StringComparer.OrdinalIgnoreCase)) return false; var kind = Enum.Parse<RegistryValueKind>(payload.Kind, true); return key.GetValueKind(payload.Name!) == kind && EncodeRegistry(key.GetValue(payload.Name!, null, RegistryValueOptions.DoNotExpandEnvironmentNames), kind) == payload.Data; }
    static bool RegistryKeyExists(RegistryPayload payload) { using var root = RegistryRoot(payload.Hive, payload.View, false); using var key = root.OpenSubKey(payload.Path, false); return key is not null; }
    static bool VerifyServicePayload(ServicePayload expected) { var current = CaptureServicePayload(expected.Name); return current is not null && string.Equals(current.BinaryPath, expected.BinaryPath, StringComparison.OrdinalIgnoreCase) && NormalizeStart(current.StartMode) == NormalizeStart(expected.StartMode) && string.Equals(current.Account, expected.Account, StringComparison.OrdinalIgnoreCase); }
    static bool VerifyTaskPayload(TaskPayload expected) { var value = GetTask(expected.Path); if (value is null) return false; try { dynamic task = value.Task!; var xml = (string)task.Xml; return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(xml))).Equals(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(expected.Xml))), StringComparison.OrdinalIgnoreCase) && (bool)task.Enabled == expected.Enabled; } finally { value.Dispose(); } }

    static void ValidateRestoreAction(string action, PersistenceRemediationKind kind)
    {
        var valid = action switch { "registry.value.restore" => kind is PersistenceRemediationKind.RegistryValue or PersistenceRemediationKind.RegistryKey or PersistenceRemediationKind.GenericRegistryConfiguration, "service.restore" => kind == PersistenceRemediationKind.Service, "scheduled_task.restore" => kind == PersistenceRemediationKind.ScheduledTask, "wmi.persistence.restore" => kind is PersistenceRemediationKind.WmiFilter or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiBinding, "persistence.restore" => true, _ => false };
        if (!valid) throw new PersistenceFailure("RestoreKindMismatch", PersistenceRemediationState.Failed, ResponseFailureCategory.Validation);
    }
    static PersistenceRemediationStep Step(PersistenceRemediationStage stage, string result, string? detail) => new(stage, result, DateTimeOffset.UtcNow, detail);
    static PersistenceRemediationRecord Record(AgentState state, SignedResponseActionEnvelope action, PersistenceRemediationTarget? target, Guid? backup, PersistenceRemediationState remediationState, string? failure, List<PersistenceRemediationStep> steps, PersistenceBackupRecord? record, DateTimeOffset started, string verification) => new(PersistenceResponseSafety.SchemaVersion, action.ActionId, state.TenantId, state.EndpointId, state.InstallationId, action.ActionType, target, backup, remediationState, failure, steps.ToArray(), record, started, DateTimeOffset.UtcNow, verification);
    static Execution Failure(AgentState state, SignedResponseActionEnvelope action, PersistenceRemediationTarget? target, DateTimeOffset started, List<PersistenceRemediationStep> steps, PersistenceRemediationState remediationState, string reason, ResponseFailureCategory category, Guid? backup = null)
    {
        steps.Add(Step(PersistenceRemediationStage.Failed, "failed", reason)); var record = Record(state, action, target, backup, remediationState, reason, steps, null, started, "failed"); return new(ResponseActionState.Failed, JsonSerializer.SerializeToElement(record, Json), [], steps.Count, category, reason);
    }
    static void ProtectDirectory(string path)
    {
        var info = new DirectoryInfo(path); info.Attributes |= FileAttributes.Hidden | FileAttributes.NotContentIndexed;
        if (!OperatingSystem.IsWindows()) return;
        var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false); security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow)); security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow)); info.SetAccessControl(security);
    }
    public void Dispose() => _gate.Dispose();

    sealed record Captured(string StateHash, byte[] Payload);
    sealed record BackupBundle(PersistenceBackupRecord Record, ResponseArtifactUpload Artifact);
    sealed record MutationResult(bool Success, bool Partial, string Detail, PersistenceRemediationState State, ResponseFailureCategory Category);
    sealed record ScResult(int ExitCode, string Output);
    sealed record RegistryPayload(string Hive, string View, string Path, string? Name, string Kind, string Data);
    sealed record ServicePayload(string Name, string? DisplayName, string BinaryPath, string StartMode, string? Account, string? State, uint ServiceType, uint ErrorControl, string[] Dependencies, string? Description, bool Driver);
    sealed record TaskPayload(string Path, string Xml, bool Enabled);
    sealed record WmiPayload(string Namespace, string Class, string RelativePath, Dictionary<string, JsonElement> Properties);
    sealed class PersistenceFailure(string code, PersistenceRemediationState state, ResponseFailureCategory category) : Exception(code) { public string Code { get; } = code; public PersistenceRemediationState State { get; } = state; public ResponseFailureCategory Category { get; } = category; }
    sealed class TaskLocation(object service, object folder, string name) : IDisposable { public object Service { get; } = service; public object Folder { get; } = folder; public string Name { get; } = name; public object? Task { get; set; } public void Dispose() { Release(Task); Release(Folder); Release(Service); } static void Release(object? value) { if (value is not null && Marshal.IsComObject(value)) Marshal.FinalReleaseComObject(value); } }
}
