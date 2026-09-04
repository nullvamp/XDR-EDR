using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using OpenSecurityPlatform.Foundation;

sealed class WindowsFileQuarantine : IDisposable
{
    const uint GenericRead = 0x80000000;
    const uint DeleteAccess = 0x00010000;
    const uint ReadAttributes = 0x00000080;
    const uint OpenExisting = 3;
    const uint OpenReparsePoint = 0x00200000;
    const int FileDispositionInfo = 4;
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    readonly string _agentRoot;
    readonly string _store;
    readonly SemaphoreSlim _gate = new(1, 1);

    public WindowsFileQuarantine(string agentRoot)
    {
        _agentRoot = Path.GetFullPath(agentRoot);
        _store = Path.Combine(_agentRoot, "protected-quarantine-v1");
        Directory.CreateDirectory(_store);
        ProtectStore();
    }

    public static async Task<int> RunSelfTestAsync(string dataDirectory, string? fixtureRoot, string? output)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(fixtureRoot)) return 2;
        var root = Path.GetFullPath(fixtureRoot); var agentRoot = Path.GetFullPath(dataDirectory);
        if (root.StartsWith(agentRoot, StringComparison.OrdinalIgnoreCase) || agentRoot.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return 2;
        Directory.CreateDirectory(root); Directory.CreateDirectory(agentRoot);
        var tenant = Guid.NewGuid().ToString(); var endpoint = Guid.NewGuid(); var agent = Guid.NewGuid(); const string installation = "sprint20-native-self-test";
        var state = new AgentState(endpoint, agent, installation, "unused", "unused", DateTimeOffset.UtcNow.AddHours(1), 0, TenantId: tenant);
        static string Entity(string value) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
        static FileResponseTarget Target(string path, string entity)
        {
            var snapshot = NativeFileSnapshotReader.TryRead(path) ?? throw new IOException("Native fixture identity unavailable.");
            var bytes = File.ReadAllBytes(path);
            return new(entity, snapshot.Identity, path, bytes.LongLength, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), DateTimeOffset.UtcNow,
                File.GetCreationTimeUtc(path), File.GetLastWriteTimeUtc(path));
        }
        static SignedResponseActionEnvelope Action(AgentState state, string type, JsonElement parameters, Guid? id = null) =>
            new("response-envelope.v1", state.TenantId, state.EndpointId, state.AgentId, state.InstallationId, id ?? Guid.NewGuid(), type, 1,
                parameters, ResponseSafety.ParameterHash(parameters), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5),
                Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(), FileResponseSafety.PolicyVersion, 180, "self-test", "self-test", "self-test");
        var results = new Dictionary<string, object>();
        try
        {
            using (var executor = new WindowsFileQuarantine(agentRoot))
            {
                var pathA = Path.Combine(root, "profile-a.bin"); var original = RandomNumberGenerator.GetBytes(4096); await File.WriteAllBytesAsync(pathA, original);
                var targetA = Target(pathA, Entity("profile-a")); var quarantineAction = Action(state, "file.quarantine", FileResponseSafety.TargetParameters("profile A", targetA));
                var quarantine = await executor.ExecuteAsync(state, quarantineAction, default);
                var recordA = quarantine.Structured.Deserialize<FileQuarantineRecord>(Json)!;
                var protectedContent = Path.Combine(agentRoot, "protected-quarantine-v1", quarantineAction.ActionId.ToString("N"), "content.bin");
                var profileA = quarantine.State == ResponseActionState.Succeeded && recordA.State == FileQuarantineState.Quarantined && !File.Exists(pathA) && File.Exists(protectedContent) &&
                    quarantine.Artifacts.Length == 1 && Convert.FromBase64String(quarantine.Artifacts[0].ContentBase64 ?? throw new InvalidDataException("Quarantine self-test artifact content is missing.")).SequenceEqual(original) && !File.ReadAllBytes(protectedContent).SequenceEqual(original);
                results["profileA"] = new { result = profileA ? "PASS" : "FAIL", originalRemoved = !File.Exists(pathA), encryptedProtectedCopy = File.Exists(protectedContent) && !File.ReadAllBytes(protectedContent).SequenceEqual(original), recordA.Sha256, recordA.IntegrityState };

                await File.WriteAllTextAsync(pathA, "occupied-destination");
                var collision = await executor.ExecuteAsync(state, Action(state, "file.restore", FileResponseSafety.QuarantineParameters("profile B collision", quarantineAction.ActionId, targetA)), default);
                var collisionRejected = collision.State == ResponseActionState.Failed && collision.FailureReason == "DestinationOccupied" && await File.ReadAllTextAsync(pathA) == "occupied-destination";
                File.Delete(pathA);
                var restoreAction = Action(state, "file.restore", FileResponseSafety.QuarantineParameters("profile B", quarantineAction.ActionId, targetA));
                var restore = await executor.ExecuteAsync(state, restoreAction, default); var restored = NativeFileSnapshotReader.TryRead(pathA);
                var profileB = collisionRejected && restore.State == ResponseActionState.Succeeded && File.ReadAllBytes(pathA).SequenceEqual(original) && restored is not null && restored.Size == targetA.Size && restore.Structured.GetProperty("state").GetString() == "Restored";
                results["profileB"] = new { result = profileB ? "PASS" : "FAIL", collisionRejectedWithoutOverwrite = collisionRejected, pathRestored = File.Exists(pathA), hashRestored = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(pathA))).Equals(targetA.Sha256, StringComparison.OrdinalIgnoreCase), nativeIdentity = restored?.Identity, state = restore.Structured.GetProperty("state").GetString() };

                var racePath = Path.Combine(root, "profile-c.bin"); await File.WriteAllTextAsync(racePath, "file-A"); var stale = Target(racePath, Entity("profile-c")); File.Delete(racePath); await File.WriteAllTextAsync(racePath, "file-B");
                var race = await executor.ExecuteAsync(state, Action(state, "file.quarantine", FileResponseSafety.TargetParameters("profile C", stale)), default);
                var profileC = race.State == ResponseActionState.Failed && race.Failure == ResponseFailureCategory.Integrity && await File.ReadAllTextAsync(racePath) == "file-B";
                results["profileC"] = new { result = profileC ? "PASS" : "FAIL", race.Failure, race.FailureReason, replacementSurvived = File.Exists(racePath) };

                var lockedPath = Path.Combine(root, "profile-d.bin"); await File.WriteAllTextAsync(lockedPath, "locked-fixture"); var lockedTarget = Target(lockedPath, Entity("profile-d"));
                Execution locked; await using (var lockStream = new FileStream(lockedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) locked = await executor.ExecuteAsync(state, Action(state, "file.quarantine", FileResponseSafety.TargetParameters("profile D", lockedTarget)), default);
                var profileD = locked.State == ResponseActionState.Failed && File.Exists(lockedPath) && await File.ReadAllTextAsync(lockedPath) == "locked-fixture";
                results["profileD"] = new { result = profileD ? "PASS" : "FAIL", locked.FailureReason, noCorruption = await File.ReadAllTextAsync(lockedPath) == "locked-fixture" };

                var deletePath = Path.Combine(root, "profile-e.bin"); await File.WriteAllTextAsync(deletePath, "delete-fixture"); var deleteTarget = Target(deletePath, Entity("profile-e"));
                var deleted = await executor.ExecuteAsync(state, Action(state, "file.delete", FileResponseSafety.TargetParameters("profile E", deleteTarget)), default);
                var protectedRejected = false; try { var agentTarget = Target(Environment.ProcessPath!, Entity("agent")); _ = await executor.ExecuteAsync(state, Action(state, "file.delete", FileResponseSafety.TargetParameters("protected", agentTarget)), default); } catch (UnauthorizedAccessException) { protectedRejected = true; }
                var profileE = deleted.State == ResponseActionState.Succeeded && !File.Exists(deletePath) && protectedRejected;
                results["profileE"] = new { result = profileE ? "PASS" : "FAIL", controlledFileRemoved = !File.Exists(deletePath), agentBinaryRejected = protectedRejected, terminology = deleted.Structured.GetProperty("terminology").GetString() };
            }

            using (var restarted = new WindowsFileQuarantine(agentRoot))
            {
                var persistedId = Directory.EnumerateFiles(Path.Combine(agentRoot, "protected-quarantine-v1"), "metadata.json", SearchOption.AllDirectories)
                    .Select(x => Guid.ParseExact(Path.GetFileName(Path.GetDirectoryName(x)!), "N")).First();
                var persistent = await restarted.ExecuteAsync(state, Action(state, "file.quarantine_status", FileResponseSafety.RecordParameters("profile F restart", persistedId)), default);
                var pressureRejected = false;
                for (var i = 0; i < FileResponseSafety.MaximumStoreFiles + 1; i++)
                {
                    var path = Path.Combine(root, $"pressure-{i:D3}.bin"); await File.WriteAllBytesAsync(path, []); var target = Target(path, Entity("pressure-" + i));
                    var value = await restarted.ExecuteAsync(state, Action(state, "file.quarantine", FileResponseSafety.TargetParameters("profile F pressure", target)), default);
                    if (value.FailureReason == "QuarantineQuotaExceeded") { pressureRejected = true; break; }
                }
                var profileF = persistent.State == ResponseActionState.Succeeded && pressureRejected;
                results["profileF"] = new { result = profileF ? "PASS" : "FAIL", restartRecordReadable = persistent.State == ResponseActionState.Succeeded, boundedPressureRejected = pressureRejected, maximumFiles = FileResponseSafety.MaximumStoreFiles };
            }
            var passed = results.Values.All(x => string.Equals(x.GetType().GetProperty("result")?.GetValue(x)?.ToString(), "PASS", StringComparison.Ordinal));
            var report = JsonSerializer.Serialize(new { schemaVersion = "file-response-native-self-test.v1", platform = Environment.OSVersion.ToString(), architecture = RuntimeInformation.OSArchitecture.ToString(), elevated = IsElevated(), documentedApis = new[] { "CreateFileW", "GetFileInformationByHandle", "RandomAccess.Read", "SetFileInformationByHandle(FileDispositionInfo)", "CryptProtectData/DPAPI" }, noShellDelete = true, profiles = results, result = passed ? "PASS" : "FAIL", timestamp = DateTimeOffset.UtcNow }, Json);
            if (!string.IsNullOrWhiteSpace(output)) await File.WriteAllTextAsync(output, report); Console.WriteLine(report); return passed ? 0 : 1;
        }
        finally { CleanupSelfTest(root); CleanupSelfTest(agentRoot); }
    }

    public sealed record Execution(ResponseActionState State, JsonElement Structured,
        ResponseArtifactUpload[] Artifacts, int Records, ResponseFailureCategory Failure, string? FailureReason);

    public async Task<Execution> ExecuteAsync(AgentState state, SignedResponseActionEnvelope action, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        await _gate.WaitAsync(ct);
        try
        {
            return action.ActionType switch
            {
                "file.quarantine" => await Quarantine(state, action, ct),
                "file.restore" => await Restore(state, action, ct),
                "file.delete" => await Delete(state, action, ct),
                "file.quarantine_status" or "file.quarantine_metadata" => await Status(action, ct),
                _ => throw new InvalidOperationException("Unsupported file response action."),
            };
        }
        finally { _gate.Release(); }
    }

    [SupportedOSPlatform("windows")]
    async Task<Execution> Quarantine(AgentState state, SignedResponseActionEnvelope action, CancellationToken ct)
    {
        var target = Target(action.Parameters);
        ValidateTarget(target);
        var quarantineId = action.ActionId;
        var directory = RecordDirectory(quarantineId);
        if (File.Exists(MetadataPath(quarantineId)) && await Load(quarantineId, ct) is { } existing)
            return Success(existing, []);
        await CleanupExpired(ct);
        try { EnforceQuota(target.Size); }
        catch (InvalidOperationException) { return Failure("QuarantineQuotaExceeded", "The bounded local quarantine store is full.", FileQuarantineState.Failed); }
        Directory.CreateDirectory(directory);
        ProtectDirectory(directory);
        var temporary = Path.Combine(directory, $"acquiring-{quarantineId:N}.tmp");
        var content = Path.Combine(directory, "content.bin");
        HandleSnapshot before;
        string hash;
        byte[] bytes;
        try
        {
            using var handle = OpenExact(target.CanonicalPath);
            before = Snapshot(handle);
            Match(target, before);
            bytes = await ReadExactAsync(handle, before.Size, ct);
            var protectedBytes = ProtectedData.Protect(bytes, Entropy(quarantineId, state.InstallationId), DataProtectionScope.LocalMachine);
            await File.WriteAllBytesAsync(temporary, protectedBytes, ct);
            hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var after = Snapshot(handle);
            if (!before.SameState(after)) return await FailedRecord(state, action, target, quarantineId, "FileChangedDuringAcquisition", FileQuarantineState.IdentityMismatch, ct);
            if (bytes.LongLength != target.Size || target.Sha256 is { Length: 64 } expected && !Fixed(expected, hash))
                return await FailedRecord(state, action, target, quarantineId, "HashOrSizeMismatch", FileQuarantineState.IdentityMismatch, ct);
            ct.ThrowIfCancellationRequested();
            File.Move(temporary, content, false);
            File.SetAttributes(content, FileAttributes.Hidden | FileAttributes.ReadOnly | FileAttributes.NotContentIndexed);
            var disposition = new FileDispositionInformation { DeleteFile = true };
            if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref disposition, Marshal.SizeOf<FileDispositionInformation>()))
                return await PartialRecord(state, action, target, quarantineId, before, hash, bytes, "VerifiedCopyButSourceRemovalFailed", ct);
        }
        catch (FileIdentityException ex)
        {
            TryDelete(temporary);
            TryDeleteEmpty(directory);
            return Failure("FileIdentityMismatch", ex.Message, FileQuarantineState.IdentityMismatch);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(temporary);
            TryDeleteEmpty(directory);
            return Failure("LockedOrAccessDenied", ex.GetType().Name, FileQuarantineState.Failed);
        }
        catch (CryptographicException ex)
        {
            TryDelete(temporary);
            TryDeleteEmpty(directory);
            return Failure("QuarantineEncryptionFailed", ex.GetType().Name, FileQuarantineState.Failed);
        }
        finally { TryDelete(temporary); }

        var pathState = NativeFileSnapshotReader.TryRead(target.CanonicalPath);
        if (pathState is not null && Same(target.NativeIdentity, pathState.Identity))
            return await PartialRecord(state, action, target, quarantineId, before, hash, bytes, "TargetStillPresentAfterDeleteDisposition", ct);
        var record = NewRecord(state, action, target, quarantineId, hash, FileQuarantineState.Quarantined,
            true, pathState is null ? "stable-acquisition" : "replacement-appeared-after-target-removal", "basic-metadata-preserved", attributes: before.Attributes);
        await Save(record, ct);
        var artifact = new ResponseArtifactUpload(Guid.NewGuid(), target.FileEntityId + ".quarantine.bin",
            "application/octet-stream", hash, Convert.ToBase64String(bytes));
        return Success(record, [artifact]);
    }

    [SupportedOSPlatform("windows")]
    async Task<Execution> Restore(AgentState state, SignedResponseActionEnvelope action, CancellationToken ct)
    {
        var id = action.Parameters.GetProperty("quarantineId").GetGuid();
        var target = Target(action.Parameters);
        ValidateTarget(target);
        var record = await Load(id, ct);
        if (record is null || record.TenantId != state.TenantId || record.EndpointId != state.EndpointId ||
            record.AgentInstallationId != state.InstallationId || record.FileEntityId != target.FileEntityId)
            return Failure("QuarantineBindingMismatch", "The quarantine record is unavailable for this endpoint installation.", FileQuarantineState.IdentityMismatch);
        if (record.State is not (FileQuarantineState.Quarantined or FileQuarantineState.Partial) || !record.RestoreEligible)
            return Failure("RestoreNotEligible", "The quarantine record is not restorable.", record.State);
        if (File.Exists(target.CanonicalPath) || Directory.Exists(target.CanonicalPath))
            return Failure("DestinationOccupied", "Restore never overwrites an occupied destination.", FileQuarantineState.RestorePending);
        var content = Path.Combine(RecordDirectory(id), "content.bin");
        byte[] bytes;
        try
        {
            var protectedBytes = await File.ReadAllBytesAsync(content, ct);
            bytes = ProtectedData.Unprotect(protectedBytes, Entropy(id, record.AgentInstallationId), DataProtectionScope.LocalMachine);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException) { return Failure("QuarantineContentUnavailable", ex.GetType().Name, FileQuarantineState.Failed); }
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (!Fixed(hash, record.Sha256)) return Failure("QuarantineHashMismatch", "Stored quarantine integrity verification failed.", FileQuarantineState.IdentityMismatch);
        Directory.CreateDirectory(Path.GetDirectoryName(target.CanonicalPath)!);
        var temporary = target.CanonicalPath + $".platform-restore-{id:N}.tmp";
        try
        {
            await File.WriteAllBytesAsync(temporary, bytes, ct);
            await using (var verify = File.OpenRead(temporary))
                if (!Fixed(Convert.ToHexString(await SHA256.HashDataAsync(verify, ct)).ToLowerInvariant(), record.Sha256))
                    return Failure("RestoreHashMismatch", "Temporary restore verification failed.", FileQuarantineState.Failed);
            File.Move(temporary, target.CanonicalPath, false);
            if (record.OriginalCreationTime is { } created) File.SetCreationTimeUtc(target.CanonicalPath, created.UtcDateTime);
            if (record.OriginalLastWriteTime is { } modified) File.SetLastWriteTimeUtc(target.CanonicalPath, modified.UtcDateTime);
            var safeAttributes = (FileAttributes)record.OriginalAttributes & ~(FileAttributes.ReparsePoint | FileAttributes.Device | FileAttributes.Directory);
            File.SetAttributes(target.CanonicalPath, safeAttributes);
            var restored = NativeFileSnapshotReader.TryRead(target.CanonicalPath);
            await using var finalStream = File.OpenRead(target.CanonicalPath);
            var finalHash = Convert.ToHexString(await SHA256.HashDataAsync(finalStream, ct)).ToLowerInvariant();
            if (restored is null || restored.Size != record.OriginalSize || !Fixed(finalHash, record.Sha256)) return Failure("RestoreVerificationFailed", "Final restored file identity, size, or hash could not be verified.", FileQuarantineState.Partial);
            var completed = record with { State = FileQuarantineState.Restored, RestoreEligible = false, RestoredAt = DateTimeOffset.UtcNow, RestoredNativeIdentity = restored.Identity, MetadataState = "basic-metadata-restored;acl-and-ads-inventory-not-restored" };
            await Save(completed, ct);
            return Success(completed, []);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Failure("RestoreFailed", ex.GetType().Name, FileQuarantineState.Failed);
        }
        finally { TryDelete(temporary); }
    }

    async Task<Execution> Delete(AgentState state, SignedResponseActionEnvelope action, CancellationToken ct)
    {
        var target = Target(action.Parameters);
        ValidateTarget(target);
        try
        {
            using var handle = OpenExact(target.CanonicalPath);
            var before = Snapshot(handle);
            Match(target, before);
            var bytes = await ReadExactAsync(handle, before.Size, ct);
            var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var after = Snapshot(handle);
            if (!before.SameState(after) || target.Sha256 is { Length: 64 } expected && !Fixed(expected, hash))
                return Failure("FileIdentityMismatch", "The file changed during delete verification.", FileQuarantineState.IdentityMismatch);
            ct.ThrowIfCancellationRequested();
            var disposition = new FileDispositionInformation { DeleteFile = true };
            if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref disposition, Marshal.SizeOf<FileDispositionInformation>()))
                return Failure("DeleteFailed", $"Win32:{Marshal.GetLastWin32Error()}", FileQuarantineState.Failed);
            handle.Dispose();
            var pathState = NativeFileSnapshotReader.TryRead(target.CanonicalPath);
            if (pathState is not null && Same(target.NativeIdentity, pathState.Identity))
                return Failure("DeleteVerificationFailed", "The targeted native file identity remains present.", FileQuarantineState.Partial);
            var value = JsonSerializer.SerializeToElement(new { schemaVersion = FileResponseSafety.SchemaVersion, state = FileQuarantineState.Deleted, target, sha256 = hash, deletedAt = DateTimeOffset.UtcNow, terminology = "normal-filesystem-deletion-not-secure-erase" });
            return new(ResponseActionState.Succeeded, value, [], 1, ResponseFailureCategory.None, null);
        }
        catch (FileIdentityException ex)
        {
            return Failure("FileIdentityMismatch", ex.Message, FileQuarantineState.IdentityMismatch);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Failure("LockedOrAccessDenied", ex.GetType().Name, FileQuarantineState.Failed);
        }
    }

    async Task<Execution> Status(SignedResponseActionEnvelope action, CancellationToken ct)
    {
        var id = action.Parameters.GetProperty("quarantineId").GetGuid();
        var record = await Load(id, ct);
        return record is null ? Failure("QuarantineNotFound", "The quarantine identity is unavailable.", FileQuarantineState.Unknown) : Success(record, []);
    }

    void ValidateTarget(FileResponseTarget target)
    {
        var path = Path.GetFullPath(target.CanonicalPath);
        if (FileResponseSafety.IsHardProtectedPath(path, _agentRoot) || path.StartsWith(_store + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("ProtectedPath");
        if (target.NativeIdentity.SymbolicLink == true || target.NativeIdentity.HardLink == true)
            throw new UnauthorizedAccessException("ReparseOrHardLinkTargetForbidden");
    }

    static SafeFileHandle OpenExact(string path)
    {
        var handle = CreateFile(path, GenericRead | DeleteAccess | ReadAttributes, (uint)FileShare.Read,
            IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid) throw new IOException($"CreateFile failed:{Marshal.GetLastWin32Error()}");
        return handle;
    }

    static HandleSnapshot Snapshot(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var value)) throw new IOException($"GetFileInformationByHandle failed:{Marshal.GetLastWin32Error()}");
        var index = ((ulong)value.FileIndexHigh << 32) | value.FileIndexLow;
        var size = ((long)value.FileSizeHigh << 32) | value.FileSizeLow;
        var modified = DateTimeOffset.FromFileTime(((long)value.LastWriteTime.dwHighDateTime << 32) | (uint)value.LastWriteTime.dwLowDateTime);
        var identity = new FileNativeIdentity(value.VolumeSerialNumber.ToString("x8", CultureInfo.InvariantCulture), $"windows:{value.VolumeSerialNumber:x8}:{index:x16}", null, null, null, (value.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0, value.NumberOfLinks > 1);
        return new(identity, size, modified, (int)value.FileAttributes);
    }

    static void Match(FileResponseTarget target, HandleSnapshot snapshot)
    {
        if (!Same(target.NativeIdentity, snapshot.Identity) || target.Size != snapshot.Size)
            throw new FileIdentityException("FileIdentityMismatch");
        if (snapshot.Identity.SymbolicLink == true || snapshot.Identity.HardLink == true)
            throw new FileIdentityException("ReparseOrHardLinkTargetForbidden");
    }

    static bool Same(FileNativeIdentity expected, FileNativeIdentity actual) =>
        string.Equals(expected.VolumeId, actual.VolumeId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(expected.FileId, actual.FileId, StringComparison.OrdinalIgnoreCase);
    static bool Fixed(string a, string b) => CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(a.ToLowerInvariant()), System.Text.Encoding.ASCII.GetBytes(b.ToLowerInvariant()));
    static FileResponseTarget Target(JsonElement parameters) => parameters.GetProperty("target").Deserialize<FileResponseTarget>(Json)!;
    static byte[] Entropy(Guid id, string installation) => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"platform-file-quarantine-v1\n{id:D}\n{installation}"));

    static async Task<byte[]> ReadExactAsync(SafeFileHandle handle, long length, CancellationToken ct)
    {
        if (length is < 0 or > FileResponseSafety.MaximumFileBytes) throw new IOException("FileSizeOutsidePolicy");
        var bytes = new byte[(int)length];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = await RandomAccess.ReadAsync(handle, bytes.AsMemory(offset), offset, ct);
            if (read == 0) throw new IOException("UnexpectedEndOfFile");
            offset += read;
        }
        return bytes;
    }

    static FileQuarantineRecord NewRecord(AgentState state, SignedResponseActionEnvelope action, FileResponseTarget target,
        Guid id, string hash, FileQuarantineState status, bool eligible, string race, string metadata, string? failure = null, int? attributes = null) =>
        new(FileResponseSafety.SchemaVersion, id, action.ActionId, state.TenantId, state.EndpointId, state.InstallationId,
            target.FileEntityId, target.NativeIdentity, target.CanonicalPath, Path.GetFileName(target.CanonicalPath), target.Size,
            hash, target.CreatedAt, target.ModifiedAt, attributes ?? (File.Exists(target.CanonicalPath) ? (int)File.GetAttributes(target.CanonicalPath) : 0),
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(FileResponseSafety.RetentionDays), status, eligible,
            "agent-protected-quarantine-v1", "dpapi-local-machine+sha256-verified", race, metadata, failure);

    async Task<Execution> PartialRecord(AgentState state, SignedResponseActionEnvelope action, FileResponseTarget target,
        Guid id, HandleSnapshot before, string hash, byte[] bytes, string reason, CancellationToken ct)
    {
        var record = NewRecord(state, action, target, id, hash, FileQuarantineState.Partial, true, reason, "basic-metadata-preserved", reason, before.Attributes);
        await Save(record, ct);
        var artifact = new ResponseArtifactUpload(Guid.NewGuid(), target.FileEntityId + ".quarantine.bin", "application/octet-stream", hash, Convert.ToBase64String(bytes));
        return new(ResponseActionState.Failed, JsonSerializer.SerializeToElement(record, Json), [artifact], 1, ResponseFailureCategory.Execution, reason);
    }

    async Task<Execution> FailedRecord(AgentState state, SignedResponseActionEnvelope action, FileResponseTarget target,
        Guid id, string reason, FileQuarantineState status, CancellationToken ct)
    {
        var record = NewRecord(state, action, target, id, target.Sha256 ?? new string('0', 64), status, false, reason, "not-acquired", reason);
        await Save(record, ct); return Failure(reason, reason, status, record);
    }

    static Execution Success(FileQuarantineRecord record, ResponseArtifactUpload[] artifacts) =>
        new(ResponseActionState.Succeeded, JsonSerializer.SerializeToElement(record, Json), artifacts, 1, ResponseFailureCategory.None, null);
    static Execution Failure(string code, string detail, FileQuarantineState state, FileQuarantineRecord? record = null) =>
        new(ResponseActionState.Failed, record is null ? JsonSerializer.SerializeToElement(new { schemaVersion = FileResponseSafety.SchemaVersion, state, code, detail }) : JsonSerializer.SerializeToElement(record, Json), [], 1,
            code.Contains("Identity", StringComparison.OrdinalIgnoreCase) || code.Contains("Hash", StringComparison.OrdinalIgnoreCase) ? ResponseFailureCategory.Integrity : code.Contains("Protected", StringComparison.OrdinalIgnoreCase) ? ResponseFailureCategory.Authorization : ResponseFailureCategory.Execution, code);

    void EnforceQuota(long incoming)
    {
        var files = Directory.EnumerateFiles(_store, "content.bin", SearchOption.AllDirectories).Select(x => new FileInfo(x)).ToArray();
        if (files.Length >= FileResponseSafety.MaximumStoreFiles || files.Sum(x => x.Length) + incoming > FileResponseSafety.MaximumStoreBytes)
            throw new InvalidOperationException("QuarantineQuotaExceeded");
    }

    async Task CleanupExpired(CancellationToken ct)
    {
        foreach (var directory in Directory.EnumerateDirectories(_store))
        {
            ct.ThrowIfCancellationRequested();
            if (!Guid.TryParseExact(Path.GetFileName(directory), "N", out var id)) continue;
            var record = await Load(id, ct);
            if (record is null || record.RetainUntil > DateTimeOffset.UtcNow) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)) File.SetAttributes(file, FileAttributes.Normal);
                Directory.Delete(directory, true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    string RecordDirectory(Guid id) => Path.Combine(_store, id.ToString("N"));
    string MetadataPath(Guid id) => Path.Combine(RecordDirectory(id), "metadata.json");
    async Task<FileQuarantineRecord?> Load(Guid id, CancellationToken ct)
    {
        var path = MetadataPath(id); if (!File.Exists(path)) return null;
        try { return JsonSerializer.Deserialize<FileQuarantineRecord>(await File.ReadAllTextAsync(path, ct), Json); }
        catch (JsonException) { return null; }
    }
    async Task Save(FileQuarantineRecord record, CancellationToken ct)
    {
        var directory = RecordDirectory(record.QuarantineId); Directory.CreateDirectory(directory); ProtectDirectory(directory);
        var path = MetadataPath(record.QuarantineId);
        var temporary = path + ".tmp";
        if (File.Exists(path)) File.SetAttributes(path, FileAttributes.Normal);
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(record, Json), ct);
        File.Move(temporary, path, true); File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.ReadOnly | FileAttributes.NotContentIndexed);
    }
    void ProtectStore() { ProtectDirectory(_store); }
    static void ProtectDirectory(string path)
    {
        var info = new DirectoryInfo(path); info.Attributes |= FileAttributes.Hidden | FileAttributes.NotContentIndexed;
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            info.SetAccessControl(security);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or PlatformNotSupportedException) { throw new UnauthorizedAccessException("QuarantineStoreAclFailed", ex); }
    }
    static void TryDelete(string path) { try { if (File.Exists(path)) { File.SetAttributes(path, FileAttributes.Normal); File.Delete(path); } } catch { } }
    static void TryDeleteEmpty(string path) { try { if (Directory.Exists(path) && !Directory.EnumerateFileSystemEntries(path).Any()) Directory.Delete(path); } catch { } }

    static void CleanupSelfTest(string path)
    {
        try { if (!Directory.Exists(path)) return; foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)) File.SetAttributes(file, FileAttributes.Normal); Directory.Delete(path, true); } catch { }
    }
    [SupportedOSPlatform("windows")]
    static bool IsElevated() { using var identity = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); }

    public void Dispose() => _gate.Dispose();

    sealed record HandleSnapshot(FileNativeIdentity Identity, long Size, DateTimeOffset ModifiedAt, int Attributes)
    {
        public bool SameState(HandleSnapshot other) => Same(Identity, other.Identity) && Size == other.Size && ModifiedAt == other.ModifiedAt;
    }
    sealed class FileIdentityException(string message) : IOException(message);
    [StructLayout(LayoutKind.Sequential)] struct FileDispositionInformation { [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile; }
    [StructLayout(LayoutKind.Sequential)] struct ByHandleFileInformation { public uint FileAttributes; public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime; public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation information);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetFileInformationByHandle(SafeFileHandle handle, int informationClass, ref FileDispositionInformation information, int size);
}
