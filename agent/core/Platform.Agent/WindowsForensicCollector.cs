using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using OpenSecurityPlatform.Foundation;

#pragma warning disable CA1416 // Every entry is guarded by ExecuteAsync's Windows-only fail-closed check.
#pragma warning disable CA1859 // Heterogeneous inventory helpers intentionally return object for one bounded serializer.
sealed class WindowsForensicCollector : IDisposable
{
    const uint GenericRead = 0x80000000;
    const uint ShareReadWriteDelete = 0x00000001 | 0x00000002 | 0x00000004;
    const uint OpenExisting = 3;
    const uint SequentialScan = 0x08000000;
    const uint OpenReparsePoint = 0x00200000;
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly string _workingRoot;
    readonly ForensicProgressStore _progress;

    public WindowsForensicCollector(string dataDirectory)
    {
        _workingRoot = Path.GetFullPath(Path.Combine(dataDirectory, "forensic-collection-work"));
        Directory.CreateDirectory(_workingRoot);
        _progress = new ForensicProgressStore(_workingRoot);
    }

    public async Task<Execution> ExecuteAsync(AgentState state, SignedResponseActionEnvelope action, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Sprint 22 collection requires Windows.");
        ForensicCollectionSafety.ValidateActionParameters(action.Parameters);
        var collectionId = action.Parameters.GetProperty("collectionId").GetGuid();
        var analyst = action.Parameters.GetProperty("analystId").GetString()!;
        var profileId = action.Parameters.GetProperty("profileId").GetString()!;
        var profileVersion = action.Parameters.GetProperty("profileVersion").GetInt32();
        var profileHash = action.Parameters.GetProperty("profileHash").GetString()!;
        var policyVersion = action.Parameters.GetProperty("policyVersion").GetString()!;
        var requests = action.Parameters.GetProperty("requestedArtifacts").Deserialize<ForensicArtifactRequest[]>(Json)!;
        var started = DateTimeOffset.UtcNow;
        var prior = await _progress.LoadAsync(action.ActionId, action.ParameterHash, collectionId, ct);
        var items = new List<ForensicEvidenceItem>(prior?.Items.Select(x => x.State == ForensicItemState.Running ? x with { State = ForensicItemState.Failed, FailureReason = "UncertainAfterRestart", CollectionQuality = "not-reacquired-after-uncertain-interruption", AcquisitionCompletedAt = DateTimeOffset.UtcNow } : x) ?? []);
        var uploads = new List<ResponseArtifactUpload>(prior?.Uploads ?? []);
        long bytes = prior?.Bytes ?? 0;
        var cancelled = false;
        var interruptedArtifacts = uploads.Where(x => x.ContentBase64 is null && x.TransferId is null && x.LocalPath is null)
            .Select(x => x.ArtifactId).ToHashSet();
        if (interruptedArtifacts.Count > 0)
        {
            items.RemoveAll(x => x.ArtifactId is { } id && interruptedArtifacts.Contains(id));
            uploads.RemoveAll(x => interruptedArtifacts.Contains(x.ArtifactId));
            bytes = items.Sum(x => x.AcquiredSize);
        }

        foreach (var request in requests)
        {
            if (ct.IsCancellationRequested) { cancelled = true; break; }
            if (items.Any(x => x.RequestId == request.RequestId)) continue;
            items.Add(Failure(state.EndpointId, collectionId, request, "AcquisitionInProgress", ForensicItemState.Running));
            await _progress.SaveAsync(action.ActionId, action.ParameterHash, collectionId, items, uploads, bytes, ct);
            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250), ct);
                var acquired = await Acquire(state.EndpointId, collectionId, request, ct);
                items.RemoveAll(x => x.RequestId == request.RequestId && x.State == ForensicItemState.Running);
                foreach (var entry in acquired)
                {
                    if (items.Count >= ForensicCollectionSafety.MaximumEvidenceItems || bytes + entry.Item.AcquiredSize > ForensicCollectionSafety.MaximumCollectionBytes)
                    {
                        items.Add(Failure(state.EndpointId, collectionId, request, "CollectionQuotaReached", ForensicItemState.Skipped));
                        break;
                    }
                    items.Add(entry.Item);
                    if (entry.Upload is not null) uploads.Add(entry.Upload);
                    bytes += entry.Item.AcquiredSize;
                }
                await _progress.SaveAsync(action.ActionId, action.ParameterHash, collectionId, items, uploads, bytes, ct);
            }
            catch (OperationCanceledException) { cancelled = true; break; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or EventLogException)
            {
                items.RemoveAll(x => x.RequestId == request.RequestId && x.State == ForensicItemState.Running);
                items.Add(Failure(state.EndpointId, collectionId, request, ex.GetType().Name, ForensicItemState.Failed));
                await _progress.SaveAsync(action.ActionId, action.ParameterHash, collectionId, items, uploads, bytes, ct);
            }
        }

        var completed = DateTimeOffset.UtcNow;
        var acquiredCount = items.Count(x => x.State is ForensicItemState.Acquired or ForensicItemState.UnstableDuringAcquisition or ForensicItemState.Truncated);
        var failed = items.Count(x => x.State == ForensicItemState.Failed);
        var skipped = items.Count(x => x.State is ForensicItemState.Skipped or ForensicItemState.Cancelled);
        var unstable = items.Count(x => x.RaceState == ForensicRaceState.UnstableDuringAcquisition);
        var truncated = items.Count(x => x.Truncated);
        var collectionState = cancelled ? acquiredCount > 0 ? ForensicCollectionState.CancelledWithEvidence : ForensicCollectionState.Cancelled
            : failed > 0 || skipped > 0 || unstable > 0 || truncated > 0 ? ForensicCollectionState.Partial
            : ForensicCollectionState.Succeeded;
        var packageSeed = JsonSerializer.SerializeToElement(new
        {
            collectionId,
            state.TenantId,
            state.EndpointId,
            state.InstallationId,
            analyst,
            profileId,
            profileVersion,
            profileHash,
            policyVersion,
            requestedScope = requests,
            actualScope = items.Select(x => x.RequestId).ToArray(),
            started,
            completed,
            items,
            acquiredCount,
            failed,
            skipped,
            unstable,
            truncated,
            bytes,
            platformVersion = Environment.OSVersion.VersionString
        }, Json);
        var packageHash = ForensicCollectionSafety.Hash(packageSeed);
        var manifest = new ForensicCollectionManifest(ForensicCollectionSafety.ManifestSchemaVersion, collectionId,
            state.TenantId, state.EndpointId, state.InstallationId, analyst, profileId, profileVersion, profileHash,
            policyVersion, requests, items.Select(x => x.RequestId).ToArray(), started, completed, items.ToArray(),
            acquiredCount, failed, skipped, unstable, truncated, bytes, Environment.OSVersion.VersionString, packageHash);
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, Json);
        var manifestHash = Hash(manifestBytes);
        var manifestId = Guid.NewGuid();
        uploads.Add(new(manifestId, "forensic-collection-manifest.json", "application/json", manifestHash, Convert.ToBase64String(manifestBytes)));
        var result = new ForensicCollectionResult(ForensicCollectionSafety.SchemaVersion, collectionId, collectionState,
            items.ToArray(), manifestId, manifestHash, packageHash, bytes, acquiredCount, failed, skipped,
            unstable, truncated, cancelled, collectionState == ForensicCollectionState.Succeeded ? null : collectionState.ToString(), "1.0.0");
        var responseState = collectionState switch
        {
            ForensicCollectionState.Succeeded => ResponseActionState.Succeeded,
            ForensicCollectionState.Cancelled or ForensicCollectionState.CancelledWithEvidence => ResponseActionState.Cancelled,
            _ => ResponseActionState.Failed
        };
        return new(responseState, JsonSerializer.SerializeToElement(result, Json), uploads.ToArray(), items.Count,
            responseState == ResponseActionState.Succeeded ? ResponseFailureCategory.None : cancelled ? ResponseFailureCategory.Cancelled : ResponseFailureCategory.Execution,
            result.FailureReason);
    }

    public Task CompleteAsync(Guid actionId) => _progress.DeleteAsync(actionId);
    public void Dispose() { _progress.Dispose(); }

    async Task<IReadOnlyList<Acquired>> Acquire(Guid endpoint, Guid collection, ForensicArtifactRequest request, CancellationToken ct) => request.ArtifactType switch
    {
        ForensicArtifactType.File => [await AcquireExactFile(endpoint, collection, request, request.FileTarget!.CanonicalPath, request.FileTarget.NativeIdentity, request.FileTarget.ExpectedSize, ct)],
        ForensicArtifactType.Directory => await AcquireDirectory(endpoint, collection, request, ct),
        ForensicArtifactType.WindowsEventLog => [await AcquireEventLog(endpoint, collection, request, ct)],
        ForensicArtifactType.Registry => [AcquireRegistry(endpoint, collection, request)],
        _ => [AcquireStructured(endpoint, collection, request)]
    };

    static Acquired AcquireStructured(Guid endpoint, Guid collection, ForensicArtifactRequest request)
    {
        var started = DateTimeOffset.UtcNow;
        object value = request.ArtifactType switch
        {
            ForensicArtifactType.SystemInformation => new { schemaVersion = "system-triage.v1", hostname = Environment.MachineName, os = Environment.OSVersion.VersionString, architecture = RuntimeInformation.OSArchitecture.ToString(), bootTime = DateTimeOffset.Now.AddMilliseconds(-Environment.TickCount64), uptimeSeconds = Environment.TickCount64 / 1000, timezone = TimeZoneInfo.Local.Id, agentVersion = ProductRelease.Version, collectedAt = DateTimeOffset.UtcNow },
            ForensicArtifactType.ProcessInventory => Processes(request.MaximumItems),
            ForensicArtifactType.UserSessionInventory => Sessions(),
            ForensicArtifactType.ServiceInventory => Services(request.MaximumItems),
            ForensicArtifactType.ScheduledTaskInventory => Tasks(request.MaximumItems),
            ForensicArtifactType.NetworkState => Network(request.MaximumItems),
            ForensicArtifactType.DnsState => Dns(),
            ForensicArtifactType.InstalledSoftwareInventory => Software(request.MaximumItems),
            ForensicArtifactType.PersistenceSnapshot => Persistence(request.MaximumItems),
            _ => throw new InvalidOperationException("Unsupported structured artifact.")
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, Json);
        return Create(endpoint, collection, request, request.ArtifactType.ToString(), null, "windows-native-structured", started, bytes, ForensicRaceState.NotApplicable, false, "complete", ForensicItemState.Acquired, null, ForensicSensitivity.Internal);
    }

    async Task<Acquired> AcquireExactFile(Guid endpoint, Guid collection, ForensicArtifactRequest request,
        string path, FileNativeIdentity? expectedIdentity, long? expectedSize, CancellationToken ct)
    {
        var started = DateTimeOffset.UtcNow;
        using var handle = OpenExact(path);
        var before = Snapshot(handle);
        if (before.Identity.SymbolicLink == true || before.Identity.HardLink == true) throw new UnauthorizedAccessException("ReparseOrHardLinkTargetForbidden");
        if (expectedIdentity is not null && !Same(expectedIdentity, before.Identity)) throw new IOException("NativeIdentityMismatch");
        if (expectedSize is not null && before.Size != expectedSize) throw new IOException("ExpectedSizeMismatch");
        if (before.Size > Math.Min(request.MaximumBytes, ForensicCollectionSafety.MaximumSingleArtifactBytes)) throw new IOException("SingleArtifactQuotaExceeded");
        var acquiredPath = Path.Combine(_workingRoot, $"{collection:D}-{Guid.NewGuid():N}.evidence");
        string hash;
        HandleSnapshot afterHandle;
        try
        {
            await using (var stream = new FileStream(handle, FileAccess.Read, 256 * 1024, false))
            await using (var output = new FileStream(acquiredPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                256 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough))
            {
                using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[256 * 1024]; long copied = 0; int read;
                while ((read = await stream.ReadAsync(buffer, ct)) > 0)
                {
                    copied += read; if (copied > before.Size) throw new IOException("SourceGrewDuringAcquisition");
                    hasher.AppendData(buffer, 0, read); await output.WriteAsync(buffer.AsMemory(0, read), ct);
                    await ArtifactTransferClient.ThrottleAsync(read, ct);
                }
                if (copied != before.Size) throw new IOException("ShortRead");
                await output.FlushAsync(ct); output.Flush(true);
                hash = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
            }
            afterHandle = Snapshot(handle);
            HandleSnapshot? afterPath = null;
            try { using var reopened = OpenExact(path); afterPath = Snapshot(reopened); } catch (IOException) { }
            var observedHashMatches = expectedIdentity is null || expectedSize is null || string.IsNullOrWhiteSpace(request.FileTarget?.ExpectedSha256) ||
                string.Equals(hash, request.FileTarget.ExpectedSha256, StringComparison.OrdinalIgnoreCase);
            var stable = before.SameState(afterHandle) && afterPath is not null && before.SameState(afterPath) && observedHashMatches;
            var state = stable ? ForensicItemState.Acquired : ForensicItemState.UnstableDuringAcquisition;
            var race = stable ? ForensicRaceState.Stable : ForensicRaceState.UnstableDuringAcquisition;
            var id = Guid.NewGuid(); var artifactId = Guid.NewGuid();
            var item = new ForensicEvidenceItem(ForensicCollectionSafety.ItemSchemaVersion, id, collection, request.RequestId,
                request.ArtifactType, endpoint, path, Native(before.Identity), "CreateFileW+handle-spool+GetFileInformationByHandle",
                "2.0.0", started, started, DateTimeOffset.UtcNow, before.Size, before.Size, hash,
                JsonSerializer.SerializeToElement(before, Json), JsonSerializer.SerializeToElement(new { snapshot = afterPath ?? afterHandle, observedHashMatches }, Json),
                race, false, stable ? "complete-stable-copy" : "preserved-unstable-copy", state,
                stable ? null : "SourceChangedDuringAcquisition", artifactId, true, ForensicSensitivity.Restricted);
            var upload = new ResponseArtifactUpload(artifactId, $"{request.RequestId}-{id:N}{Path.GetExtension(path)}",
                "application/octet-stream", hash, null, null, before.Size, acquiredPath);
            return new(item, [], upload);
        }
        catch { try { File.Delete(acquiredPath); } catch (IOException) { } throw; }
    }

    async Task<IReadOnlyList<Acquired>> AcquireDirectory(Guid endpoint, Guid collection, ForensicArtifactRequest request, CancellationToken ct)
    {
        var result = new List<Acquired>(); var root = Path.GetFullPath(request.Source!); var queue = new Queue<(string Path, int Depth)>(); queue.Enqueue((root, 0)); long bytes = 0;
        while (queue.Count > 0 && result.Count < request.MaximumItems)
        {
            ct.ThrowIfCancellationRequested(); var current = queue.Dequeue();
            foreach (var directory in Directory.EnumerateDirectories(current.Path).Order(StringComparer.OrdinalIgnoreCase))
            {
                if (current.Depth >= request.MaximumDepth) break;
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) continue;
                queue.Enqueue((directory, current.Depth + 1));
            }
            foreach (var file in Directory.EnumerateFiles(current.Path).Order(StringComparer.OrdinalIgnoreCase))
            {
                if (result.Count >= request.MaximumItems) break;
                var attributes = File.GetAttributes(file);
                if ((attributes & FileAttributes.ReparsePoint) != 0 || (!request.IncludeHidden && (attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0) || !request.AllowedExtensions!.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase)) continue;
                var remaining = request.MaximumBytes - bytes; if (remaining <= 0) break;
                try { var acquired = await AcquireExactFile(endpoint, collection, request with { MaximumBytes = Math.Min(remaining, ForensicCollectionSafety.MaximumSingleArtifactBytes) }, file, null, null, ct); result.Add(acquired); bytes += acquired.Bytes.LongLength; }
                catch (IOException ex) { result.Add(new(Failure(endpoint, collection, request, ex.GetType().Name, ForensicItemState.Failed, file), [], null)); }
            }
        }
        return result;
    }

    async Task<Acquired> AcquireEventLog(Guid endpoint, Guid collection, ForensicArtifactRequest request, CancellationToken ct)
    {
        var started = DateTimeOffset.UtcNow; var channel = request.Source!; long? firstId = null, lastId = null; DateTime? earliest = null;
        var query = new EventLogQuery(channel, PathType.LogName) { ReverseDirection = true, TolerateQueryErrors = false };
        using (var reader = new EventLogReader(query))
        {
            for (var i = 0; i < request.MaximumRecords; i++)
            {
                using var record = reader.ReadEvent(); if (record is null) break;
                firstId = record.RecordId; lastId ??= record.RecordId; earliest = record.TimeCreated;
            }
        }
        if (firstId is null || lastId is null) throw new InvalidOperationException("EventLogContainsNoRecords");
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-request.LookbackMinutes);
        var lower = earliest is null || earliest.Value < cutoff.UtcDateTime ? cutoff.UtcDateTime : earliest.Value;
        var xpath = $"*[System[(EventRecordID >= {firstId.Value.ToString(CultureInfo.InvariantCulture)} and EventRecordID <= {lastId.Value.ToString(CultureInfo.InvariantCulture)}) and TimeCreated[@SystemTime >= '{lower:O}']]]";
        var temp = Path.Combine(_workingRoot, $"{collection:D}-{Guid.NewGuid():N}.evtx");
        try
        {
            var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "wevtutil.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true };
            foreach (var argument in new[] { "epl", channel, temp, $"/q:{xpath}", "/ow:true" }) psi.ArgumentList.Add(argument);
            using var process = Process.Start(psi) ?? throw new InvalidOperationException("EventLogExporterUnavailable");
            await process.WaitForExitAsync(ct); var error = await process.StandardError.ReadToEndAsync(ct);
            if (process.ExitCode != 0) throw new InvalidOperationException($"EventLogExportFailed:{process.ExitCode}:{Bound(error)}");
            var info = new FileInfo(temp); if (!info.Exists || info.Length > request.MaximumBytes || info.Length > ForensicCollectionSafety.MaximumSingleArtifactBytes) throw new IOException("EventLogSizeQuotaExceeded");
            var bytes = await File.ReadAllBytesAsync(temp, ct);
            var pre = JsonSerializer.SerializeToElement(new { channel, firstRecordId = firstId, lastRecordId = lastId, cutoff, exporter = "wevtutil-epl", exactNativeEvtx = true }, Json);
            return Create(endpoint, collection, request, channel, null, "Windows Event Log API+wevtutil epl", started, bytes, ForensicRaceState.NotApplicable, false, "bounded-native-evtx", ForensicItemState.Acquired, null, ForensicSensitivity.Restricted, pre, null, ".evtx", "application/x-ms-evtx");
        }
        finally { try { File.Delete(temp); } catch (IOException) { } }
    }

    static Acquired AcquireRegistry(Guid endpoint, Guid collection, ForensicArtifactRequest request)
    {
        var started = DateTimeOffset.UtcNow; var source = request.Source!; var separator = source.IndexOf('\\'); var hiveName = source[..separator]; var path = source[(separator + 1)..];
        using var hive = hiveName.Equals("HKLM", StringComparison.OrdinalIgnoreCase) ? RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64) : RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
        using var key = hive.OpenSubKey(path, false) ?? throw new InvalidOperationException("RegistryTargetUnavailable");
        var rows = new List<object>(); var queue = new Queue<(RegistryKey Key, string Path, int Depth)>(); queue.Enqueue((key, source, 0));
        while (queue.Count > 0 && rows.Count < request.MaximumItems)
        {
            var current = queue.Dequeue();
            try
            {
                foreach (var name in current.Key.GetValueNames().Order(StringComparer.OrdinalIgnoreCase))
                {
                    if (rows.Count >= request.MaximumItems) break;
                    object? raw = null; try { raw = current.Key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames); } catch (UnauthorizedAccessException) { }
                    rows.Add(new { key = current.Path, valueName = name, valueKind = Try(() => current.Key.GetValueKind(name).ToString()), dataLength = raw switch { byte[] b => b.Length, string s => s.Length, string[] a => a.Sum(x => x.Length), _ => raw is null ? 0 : raw.ToString()?.Length ?? 0 }, content = "[REDACTED]", metadataOnly = true });
                }
                if (current.Depth < request.MaximumDepth) foreach (var child in current.Key.GetSubKeyNames().Order(StringComparer.OrdinalIgnoreCase)) { var opened = current.Key.OpenSubKey(child, false); if (opened is not null) queue.Enqueue((opened, current.Path + "\\" + child, current.Depth + 1)); }
            }
            finally { if (!ReferenceEquals(current.Key, key)) current.Key.Dispose(); }
        }
        while (queue.Count > 0) queue.Dequeue().Key.Dispose();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = "registry-forensic-snapshot.v1", source, view = hiveName == "HKLM" ? "registry64" : "default", metadataOnly = true, secretMaterialExposed = false, entries = rows, truncated = rows.Count >= request.MaximumItems, observedAt = DateTimeOffset.UtcNow }, Json);
        if (bytes.LongLength > request.MaximumBytes) throw new IOException("RegistrySizeQuotaExceeded");
        return Create(endpoint, collection, request, source, null, "Microsoft.Win32.RegistryKey-readonly", started, bytes, ForensicRaceState.NotApplicable, rows.Count >= request.MaximumItems, rows.Count >= request.MaximumItems ? "bounded-truncated" : "complete", rows.Count >= request.MaximumItems ? ForensicItemState.Truncated : ForensicItemState.Acquired, null, ForensicSensitivity.High);
    }

    static object Processes(int maximum) => Process.GetProcesses().OrderBy(x => x.Id).Take(maximum).Select(x => { try { return new { pid = x.Id, parentEntity = (string?)null, name = Try(() => x.ProcessName), image = Try(() => x.MainModule?.FileName), startTime = Try(() => x.StartTime.ToUniversalTime().ToString("O")), sessionId = Try(() => x.SessionId.ToString(CultureInfo.InvariantCulture)), commandLine = "not-collected", integrity = "not-observable-without-token-query" }; } finally { x.Dispose(); } }).ToArray();
    static object Sessions() => Process.GetProcesses().Select(x => { try { return new { sessionId = Try(() => x.SessionId), user = x.SessionId == Process.GetCurrentProcess().SessionId ? Environment.UserName : null }; } finally { x.Dispose(); } }).Distinct().Take(64).ToArray();
    static object Services(int maximum) { using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64); using var services = root.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false); return (services?.GetSubKeyNames() ?? []).Order(StringComparer.OrdinalIgnoreCase).Take(maximum).Select(name => { using var key = services!.OpenSubKey(name, false); return new { name, imagePath = key?.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString(), start = key?.GetValue("Start")?.ToString(), type = key?.GetValue("Type")?.ToString(), account = key?.GetValue("ObjectName")?.ToString() }; }).ToArray(); }
    static object Tasks(int maximum) { var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks"); return Directory.Exists(root) ? Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Take(maximum).Select(x => { var info = new FileInfo(x); return new { taskPath = Path.GetRelativePath(root, x), size = info.Length, modified = info.LastWriteTimeUtc, content = "not-collected" }; }).ToArray() : []; }
    static object Network(int maximum) { var ip = IPGlobalProperties.GetIPGlobalProperties(); return new { tcp = ip.GetActiveTcpConnections().Take(maximum).Select(x => new { local = x.LocalEndPoint.ToString(), remote = x.RemoteEndPoint.ToString(), state = x.State.ToString() }).ToArray(), listeners = ip.GetActiveTcpListeners().Take(maximum).Select(x => x.ToString()).ToArray(), udp = ip.GetActiveUdpListeners().Take(maximum).Select(x => x.ToString()).ToArray(), interfaces = NetworkInterface.GetAllNetworkInterfaces().Take(64).Select(x => new { x.Id, x.Name, type = x.NetworkInterfaceType.ToString(), status = x.OperationalStatus.ToString(), addresses = x.GetIPProperties().UnicastAddresses.Take(32).Select(a => a.Address.ToString()).ToArray(), dns = x.GetIPProperties().DnsAddresses.Select(a => a.ToString()).ToArray() }).ToArray() }; }
    static object Dns() => new { cache = "not-observable-by-approved-native-source", interfaces = NetworkInterface.GetAllNetworkInterfaces().Take(64).Select(x => new { x.Name, servers = x.GetIPProperties().DnsAddresses.Select(a => a.ToString()).ToArray(), suffix = x.GetIPProperties().DnsSuffix }).ToArray() };
    static object Software(int maximum) { using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64); using var uninstall = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", false); return (uninstall?.GetSubKeyNames() ?? []).Take(maximum).Select(name => { using var key = uninstall!.OpenSubKey(name, false); return new { productId = name, name = key?.GetValue("DisplayName")?.ToString(), version = key?.GetValue("DisplayVersion")?.ToString(), publisher = key?.GetValue("Publisher")?.ToString(), installDate = key?.GetValue("InstallDate")?.ToString() }; }).Where(x => x.name is not null).ToArray(); }
    static object Persistence(int maximum) { var rows = new List<object>(); using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64); foreach (var path in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" }) { using var key = root.OpenSubKey(path, false); foreach (var name in key?.GetValueNames() ?? []) { if (rows.Count >= maximum) break; rows.Add(new { category = "registry-autorun", key = "HKLM\\" + path, valueName = name, content = "[REDACTED]" }); } } return new { authoritativeTelemetryPreferred = true, observedAt = DateTimeOffset.UtcNow, items = rows }; }

    static Acquired Create(Guid endpoint, Guid collection, ForensicArtifactRequest request, string source,
        string? nativeIdentity, string method, DateTimeOffset started, byte[] bytes, ForensicRaceState race,
        bool truncated, string quality, ForensicItemState state, string? failure, ForensicSensitivity sensitivity,
        JsonElement? pre = null, JsonElement? post = null, string extension = ".json", string mediaType = "application/json")
    {
        var id = Guid.NewGuid(); var hash = Hash(bytes); var artifactId = Guid.NewGuid();
        var item = new ForensicEvidenceItem(ForensicCollectionSafety.ItemSchemaVersion, id, collection,
            request.RequestId, request.ArtifactType, endpoint, source, nativeIdentity, method, "1.0.0", started,
            started, DateTimeOffset.UtcNow, bytes.LongLength, bytes.LongLength, hash, pre, post, race, truncated,
            quality, state, failure, artifactId, true, sensitivity);
        var upload = new ResponseArtifactUpload(artifactId, $"{request.RequestId}-{id:N}{extension}", mediaType, hash, Convert.ToBase64String(bytes));
        return new(item, bytes, upload);
    }

    static ForensicEvidenceItem Failure(Guid endpoint, Guid collection, ForensicArtifactRequest request, string reason, ForensicItemState state, string? source = null)
    {
        var now = DateTimeOffset.UtcNow; return new(ForensicCollectionSafety.ItemSchemaVersion, Guid.NewGuid(), collection,
            request.RequestId, request.ArtifactType, endpoint, source ?? request.Source ?? request.FileTarget?.CanonicalPath ?? request.ArtifactType.ToString(),
            null, "bounded-collector", "1.0.0", now, now, now, 0, 0, null, null, null,
            ForensicRaceState.NotApplicable, false, "not-acquired", state, reason, null, true,
            request.ArtifactType == ForensicArtifactType.Registry ? ForensicSensitivity.High : ForensicSensitivity.Restricted);
    }

    static SafeFileHandle OpenExact(string path) { var handle = CreateFile(path, GenericRead, ShareReadWriteDelete, IntPtr.Zero, OpenExisting, SequentialScan | OpenReparsePoint, IntPtr.Zero); if (handle.IsInvalid) { var error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new IOException($"CreateFileFailed:{error}"); } return handle; }
    static HandleSnapshot Snapshot(SafeFileHandle handle) { if (!GetFileInformationByHandle(handle, out var value)) throw new IOException($"GetFileInformationByHandleFailed:{Marshal.GetLastWin32Error()}"); var index = ((ulong)value.FileIndexHigh << 32) | value.FileIndexLow; var size = ((long)value.FileSizeHigh << 32) | value.FileSizeLow; var modified = DateTimeOffset.FromFileTime(((long)value.LastWriteTime.dwHighDateTime << 32) | (uint)value.LastWriteTime.dwLowDateTime); return new(new(value.VolumeSerialNumber.ToString("x8", CultureInfo.InvariantCulture), $"windows:{value.VolumeSerialNumber:x8}:{index:x16}", null, null, null, (value.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0, value.NumberOfLinks > 1), size, modified, (int)value.FileAttributes); }
    static bool Same(FileNativeIdentity a, FileNativeIdentity b) => string.Equals(a.VolumeId, b.VolumeId, StringComparison.OrdinalIgnoreCase) && string.Equals(a.FileId, b.FileId, StringComparison.OrdinalIgnoreCase);
    static string Native(FileNativeIdentity value) => $"volume:{value.VolumeId};file:{value.FileId}";
    static string Hash(byte[] value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
    static string Bound(string value) => value.Length <= 256 ? value.Replace('\r', ' ').Replace('\n', ' ') : value[..256].Replace('\r', ' ').Replace('\n', ' ');
    static T? Try<T>(Func<T> value) { try { return value(); } catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException or UnauthorizedAccessException) { return default; } }
    internal sealed record Execution(ResponseActionState State, JsonElement Structured, ResponseArtifactUpload[] Artifacts, int Records, ResponseFailureCategory Failure, string? FailureReason);
    sealed record Acquired(ForensicEvidenceItem Item, byte[] Bytes, ResponseArtifactUpload? Upload);
    sealed record HandleSnapshot(FileNativeIdentity Identity, long Size, DateTimeOffset ModifiedAt, int Attributes) { public bool SameState(HandleSnapshot other) => Same(Identity, other.Identity) && Size == other.Size && ModifiedAt == other.ModifiedAt; }
    [StructLayout(LayoutKind.Sequential)] struct ByHandleFileInformation { public uint FileAttributes; public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime; public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation information);
}

sealed class ForensicProgressStore : IDisposable
{
    const int MaximumProtectedBytes = 28 * 1024 * 1024;
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly string _root;
    readonly SemaphoreSlim _gate = new(1, 1);
    public ForensicProgressStore(string root) => _root = root;

    public async Task<Progress?> LoadAsync(Guid actionId, string parameterHash, Guid collectionId, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try
        {
            var path = PathFor(actionId); if (!File.Exists(path)) return null; var protectedBytes = await File.ReadAllBytesAsync(path, ct);
            if (protectedBytes.Length is <= 0 or > MaximumProtectedBytes) throw new InvalidDataException("Forensic progress checkpoint is outside its bound.");
            var plain = ProtectedData.Unprotect(protectedBytes, Entropy(actionId, parameterHash), DataProtectionScope.LocalMachine);
            var value = JsonSerializer.Deserialize<Progress>(plain, Json) ?? throw new InvalidDataException("Forensic progress checkpoint is empty.");
            if (value.ActionId != actionId || value.CollectionId != collectionId || !CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(value.ParameterHash), System.Text.Encoding.ASCII.GetBytes(parameterHash))) throw new InvalidDataException("Forensic progress binding is invalid.");
            return value;
        }
        finally { _gate.Release(); }
    }

    public async Task SaveAsync(Guid actionId, string parameterHash, Guid collectionId, IReadOnlyList<ForensicEvidenceItem> items, IReadOnlyList<ResponseArtifactUpload> uploads, long bytes, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try
        {
            var value = new Progress(actionId, parameterHash, collectionId, items.ToArray(), uploads.ToArray(), bytes, DateTimeOffset.UtcNow);
            var plain = JsonSerializer.SerializeToUtf8Bytes(value, Json); var protectedBytes = ProtectedData.Protect(plain, Entropy(actionId, parameterHash), DataProtectionScope.LocalMachine);
            if (protectedBytes.Length > MaximumProtectedBytes) throw new IOException("Forensic progress checkpoint exceeded its storage bound.");
            var path = PathFor(actionId); var temporary = path + ".tmp"; await using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough)) { await stream.WriteAsync(protectedBytes, ct); await stream.FlushAsync(ct); stream.Flush(true); }
            if (File.Exists(path)) File.Replace(temporary, path, path + ".bak", true); else File.Move(temporary, path);
        }
        finally { _gate.Release(); }
    }

    public async Task DeleteAsync(Guid actionId)
    {
        await _gate.WaitAsync(); try { foreach (var path in new[] { PathFor(actionId), PathFor(actionId) + ".bak", PathFor(actionId) + ".tmp" }) try { File.Delete(path); } catch (IOException) { } } finally { _gate.Release(); }
    }
    string PathFor(Guid actionId) => Path.Combine(_root, actionId.ToString("D") + ".progress.dpapi");
    static byte[] Entropy(Guid actionId, string parameterHash) => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"platform-forensic-progress-v1\n{actionId:D}\n{parameterHash}"));
    public void Dispose() => _gate.Dispose();
    internal sealed record Progress(Guid ActionId, string ParameterHash, Guid CollectionId, ForensicEvidenceItem[] Items, ResponseArtifactUpload[] Uploads, long Bytes, DateTimeOffset UpdatedAt);
}
