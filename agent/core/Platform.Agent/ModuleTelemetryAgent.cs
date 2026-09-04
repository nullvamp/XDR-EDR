using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using OpenSecurityPlatform.Foundation;

sealed record NativeModuleEvent(
    ModuleEventKind Kind,
    string Path,
    int ProcessId,
    DateTimeOffset ObservedAt,
    string NativeEventId,
    ulong? ImageBase,
    long? ImageSize,
    ulong? PreferredBase,
    uint? Checksum,
    uint? TimeDateStamp,
    bool Driver
);

interface IModuleCollector : IAsyncDisposable
{
    string Type { get; }
    string Version { get; }
    string State { get; }
    string? Error { get; }
    long LostEvents { get; }
    bool Elevated { get; }
    string[] KnownLimitations { get; }
    void ApplyPolicy(ModuleTelemetryPolicy policy);
    Task StartAsync(CancellationToken ct);
    Task<IReadOnlyList<NativeModuleEvent>> PollAsync(CancellationToken ct);
}

sealed class WindowsKernelImageCollector(string dataDirectory, bool standalone = false) : IModuleCollector
{
    internal const string SessionName = "OpenSecurityPlatform-ModuleImageLoad-v1";
    const int MaximumBufferedEvents = 100_000;
    readonly ConcurrentQueue<NativeModuleEvent> _events = [];
    readonly object _policyGate = new();
    readonly string _owner = Path.Combine(dataDirectory, "etw-module-session-owner.json");
    TraceEventSession? _session;
    Task? _reader;
    long _queued, _overflow, _native;
    bool _shared;
    ModuleTelemetryPolicy _capturePolicy = new();

    public string Type => "windows.kernel-image-etw";
    public string Version => "1.0.0";
    public string State { get; private set; } = "stopped";
    public string? Error { get; private set; }
    public bool Elevated => OperatingSystem.IsWindows() && new System.Security.Principal.WindowsPrincipal(
        System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    public long LostEvents { get { try { return (_session?.EventsLost ?? 0) + Interlocked.Read(ref _overflow); } catch { return Interlocked.Read(ref _overflow); } } }
    public string[] KnownLimitations =>
    [
        "Kernel image ETW may omit unload events and signer metadata is a bounded post-capture enrichment.",
        "Kernel device paths may not be resolvable to a backing file without a volume mapping.",
        "Events that predate collector startup are not reconstructed."
    ];

    public Task StartAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) { State = "unsupported"; Error = "Windows kernel image ETW requires Windows."; return Task.CompletedTask; }
        try
        {
            if (!standalone)
            {
                if (!WindowsKernelImageHub.Active)
                {
                    State = "waiting-for-shared-kernel-session";
                    Error = null;
                    return Task.CompletedTask;
                }
                WindowsKernelImageHub.Subscribe(Emit);
                _shared = true;
                WriteOwner();
                State = "healthy";
                Error = null;
                return Task.CompletedTask;
            }
            if (TraceEventSession.GetActiveSessionNames().Contains(SessionName, StringComparer.Ordinal))
            {
                if (!OwnedStale()) throw new InvalidOperationException("ETW module session-name conflict is not demonstrably platform-owned.");
                using var stale = new TraceEventSession(SessionName); stale.Stop();
            }
            _session = new TraceEventSession(SessionName) { StopOnDispose = true, BufferSizeMB = 8 };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.ImageLoad);
            var parser = new KernelTraceEventParser(
                _session.Source,
                KernelTraceEventParser.ParserTrackingOptions.None
            );
            parser.ImageLoad += d => Emit(d, false);
            parser.ImageUnload += d => Emit(d, true);
            _reader = Task.Run(() => _session.Source.Process(), CancellationToken.None);
            WriteOwner(); State = "healthy";
        }
        catch (Exception e) { State = "failed"; Error = $"{e.GetType().Name}: {e.Message}"; }
        return Task.CompletedTask;
    }

    void Emit(TraceEvent d, bool unload)
    {
        try
        {
            var path = Text(d, "FileName") ?? Text(d, "ImageName");
            if (string.IsNullOrWhiteSpace(path)) return;
            var driver = d.ProcessID is 0 or 4 || path.EndsWith(".sys", StringComparison.OrdinalIgnoreCase);
            lock (_policyGate) if (!CaptureAllowed(path, driver, unload)) return;
            var n = Interlocked.Increment(ref _native);
            if (Interlocked.Increment(ref _queued) > MaximumBufferedEvents) { Interlocked.Decrement(ref _queued); Interlocked.Increment(ref _overflow); return; }
            _events.Enqueue(new(
                unload ? (driver ? ModuleEventKind.DriverUnloaded : ModuleEventKind.ImageUnloaded) : (driver ? ModuleEventKind.DriverLoaded : ModuleEventKind.ImageLoaded),
                path, d.ProcessID, new DateTimeOffset(d.TimeStamp.ToUniversalTime()),
                $"{SessionName}:{(int)d.ID}:{d.ProcessID}:{d.TimeStampRelativeMSec:F6}:{n}",
                U64(d, "ImageBase"), I64(d, "ImageSize"), U64(d, "DefaultBase"), U32(d, "ImageChecksum"), U32(d, "TimeDateStamp"), driver));
        }
        catch (Exception e) when (e is ArgumentException or FormatException or OverflowException) { Error = $"event-normalization:{e.GetType().Name}"; }
    }
    public void ApplyPolicy(ModuleTelemetryPolicy policy)
    {
        lock (_policyGate)
        {
            _capturePolicy = policy;
            var retained = new List<NativeModuleEvent>();
            while (_events.TryDequeue(out var item))
            {
                Interlocked.Decrement(ref _queued);
                if (CaptureAllowed(item.Path, item.Driver, item.Kind is ModuleEventKind.ImageUnloaded or ModuleEventKind.DriverUnloaded)) retained.Add(item);
            }
            foreach (var item in retained) { _events.Enqueue(item); Interlocked.Increment(ref _queued); }
        }
    }
    bool CaptureAllowed(string path, bool driver, bool unload)
    {
        var policy = _capturePolicy;
        if (!policy.Enabled || driver && !policy.DriverLoads || !driver && !policy.UserModeModules || unload && !policy.UnloadEvents) return false;
        var type = ImageType(path, driver);
        if (!policy.ExecutableImages && type == "executable" || !policy.SharedLibraries && type is "dll" or "shared-library") return false;
        if (policy.IncludedImageTypes is { Length: > 0 } && !policy.IncludedImageTypes.Contains(type, StringComparer.OrdinalIgnoreCase) || policy.ExcludedImageTypes?.Contains(type, StringComparer.OrdinalIgnoreCase) == true) return false;
        if (policy.IncludedPaths is { Length: > 0 } && !policy.IncludedPaths.Any(x => Match(path, x)) || policy.ExcludedPaths?.Any(x => Match(path, x)) == true) return false;
        return true;
    }
    static string ImageType(string path, bool driver) => driver ? "driver" : Path.GetExtension(path).ToLowerInvariant() switch { ".exe" => "executable", ".dll" => "dll", ".so" => "shared-library", _ => "image" };
    static bool Match(string value, string pattern) { var p = pattern.Trim(); if (!p.Contains('*') && !p.Contains('?')) return value.Contains(p, StringComparison.OrdinalIgnoreCase); var parts = p.Split('*', StringSplitOptions.RemoveEmptyEntries); var cursor = 0; foreach (var part in parts) { var i = value.IndexOf(part.Trim('?'), cursor, StringComparison.OrdinalIgnoreCase); if (i < 0) return false; cursor = i + part.Length; } return true; }
    static object? Payload(TraceEvent d, string name) { try { return d.PayloadByName(name); } catch (ArgumentException) { return null; } }
    static string? Text(TraceEvent d, string name) => Payload(d, name)?.ToString() is { Length: > 0 } x ? x : null;
    static ulong? U64(TraceEvent d, string name) => Payload(d, name) switch { ulong x => x, long x => unchecked((ulong)x), uint x => x, int x => unchecked((ulong)x), var x when ulong.TryParse(x?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) => v, _ => null };
    static long? I64(TraceEvent d, string name) => Payload(d, name) switch { long x => x, ulong x when x <= long.MaxValue => (long)x, uint x => x, int x => x, var x when long.TryParse(x?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) => v, _ => null };
    static uint? U32(TraceEvent d, string name) => Payload(d, name) switch { uint x => x, int x => unchecked((uint)x), var x when uint.TryParse(x?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) => v, _ => null };
    public Task<IReadOnlyList<NativeModuleEvent>> PollAsync(CancellationToken ct) { var result = new List<NativeModuleEvent>(); while (result.Count < 100 && _events.TryDequeue(out var x)) { Interlocked.Decrement(ref _queued); result.Add(x); } return Task.FromResult<IReadOnlyList<NativeModuleEvent>>(result); }
    bool OwnedStale() { try { if (!File.Exists(_owner)) return false; using var d = JsonDocument.Parse(File.ReadAllText(_owner)); if (d.RootElement.GetProperty("sessionName").GetString() != SessionName) return false; var pid = d.RootElement.GetProperty("ownerPid").GetInt32(); if (pid == Environment.ProcessId) return true; try { using var p = Process.GetProcessById(pid); return p.HasExited; } catch (ArgumentException) { return true; } } catch { return false; } }
    void WriteOwner() { Directory.CreateDirectory(Path.GetDirectoryName(_owner)!); using var s = new FileStream(_owner, FileMode.Create, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough); JsonSerializer.Serialize(s, new { sessionName = SessionName, ownerPid = Environment.ProcessId, createdAt = DateTimeOffset.UtcNow }); s.Flush(true); }
    void RemoveOwner() { try { if (File.Exists(_owner)) { using var d = JsonDocument.Parse(File.ReadAllText(_owner)); if (d.RootElement.GetProperty("ownerPid").GetInt32() == Environment.ProcessId) File.Delete(_owner); } } catch { } }
    public async ValueTask DisposeAsync() { if (_shared) { WindowsKernelImageHub.Unsubscribe(Emit); _shared = false; } _session?.Stop(); if (_reader is not null) try { await _reader.WaitAsync(TimeSpan.FromSeconds(5)); } catch (Exception e) when (e is COMException or TimeoutException) { } _session?.Dispose(); RemoveOwner(); State = "stopped"; }
}

sealed class UnsupportedModuleCollector : IModuleCollector
{
    public string Type => OperatingSystem.IsLinux() ? "linux.unsupported" : "unsupported";
    public string Version => "1.0.0";
    public string State => "unsupported";
    public string? Error => "No qualified native module source is available on this platform.";
    public long LostEvents => 0;
    public bool Elevated => false;
    public string[] KnownLimitations => ["ENVIRONMENT BLOCKER: native Linux module collection requires a qualified Linux host and source."];
    public void ApplyPolicy(ModuleTelemetryPolicy policy) { }
    public Task StartAsync(CancellationToken ct) => Task.CompletedTask;
    public Task<IReadOnlyList<NativeModuleEvent>> PollAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<NativeModuleEvent>>([]);
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

sealed class ModuleTelemetryPipeline : IAsyncDisposable
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly AgentOptions _options;
    readonly IModuleCollector _collector;
    readonly string _queue, _quarantine;
    ModuleTelemetryPolicy _policy = new();
    long _sequence, _queueBytes, _native, _normalized, _excluded, _queueDrops, _attributionFailures, _identityFailures,
        _hashRequested, _hashCompleted, _hashFailed, _signerRequested, _signerCompleted, _signerFailed, _uploads, _duplicates, _rejections;
    DateTimeOffset? _lastUpload;
    readonly Queue<DateTimeOffset> _hashRate = new(), _signerRate = new();
    bool _started;

    public string CurrentPolicyKey { get; private set; } = "module-policy.v1:0";
    public string CollectorType => _collector.Type;
    public string CollectorState => _collector.State;
    public long Depth => Directory.EnumerateFiles(_queue, "*.json").LongCount();
    public long Oldest => Directory.EnumerateFiles(_queue, "*.json").Select(x => new FileInfo(x)).DefaultIfEmpty().Max(x => x is null ? 0 : (long)Math.Max(0, (DateTimeOffset.UtcNow - x.CreationTimeUtc).TotalSeconds));

    public ModuleTelemetryPipeline(AgentOptions options, long sequence)
    {
        _options = options; _collector = string.Equals(Environment.GetEnvironmentVariable("PLATFORM_TELEMETRY_DRAIN_ONLY"), "true", StringComparison.OrdinalIgnoreCase) ? new UnsupportedModuleCollector() : OperatingSystem.IsWindows() ? new WindowsKernelImageCollector(options.DataDirectory) : new UnsupportedModuleCollector();
        _queue = Path.Combine(options.DataDirectory, "module-queue"); _quarantine = Path.Combine(_queue, "quarantine"); Directory.CreateDirectory(_queue); Protect(_queue); Recover();
        _queueBytes = Directory.EnumerateFiles(_queue, "*.json").Sum(x => new FileInfo(x).Length);
        _sequence = Math.Max(sequence, Directory.EnumerateFiles(_queue, "*.json").Select(x => long.TryParse(Path.GetFileName(x).Split('-')[0], out var n) ? n : 0).DefaultIfEmpty().Max());
    }
    public Task<IReadOnlyDictionary<string, string[]>> ApplyPolicyAsync(ModuleTelemetryPolicy p, Guid id, int version) { var e = ModulePolicyValidation.Validate(p); if (e.Count == 0) { _policy = p; _collector.ApplyPolicy(p); CurrentPolicyKey = $"{id:D}:{version}"; } return Task.FromResult(e); }
    public string[] Capabilities() => [$"module.image-load.v1:{CollectorType}", $"module.driver-load.v1:{CollectorType}", "module.queue.v1", $"module.hashing:{_policy.Hashing.ToString().ToLowerInvariant()}", $"module.signer:{_policy.SignerMetadata.ToString().ToLowerInvariant()}"];

    public async Task<long> RunOnceAsync(AgentState state, Func<AgentState, HttpClient> clientFactory, Func<long, CancellationToken, Task> checkpoint, CancellationToken ct)
    {
        if (!_started)
        {
            await _collector.StartAsync(ct);
            _started = _collector.State == "healthy";
        }
        var checkpointRequired = false;
        foreach (var n in await _collector.PollAsync(ct))
        {
            Interlocked.Increment(ref _native);
            if (!_policy.Enabled || !Allowed(n)) { Interlocked.Increment(ref _excluded); continue; }
            var sequence = Interlocked.Increment(ref _sequence);
            var observation = await NormalizeAsync(state, n, sequence, ct);
            if (observation is null) { Interlocked.Increment(ref _queueDrops); checkpointRequired = true; continue; }
            Interlocked.Increment(ref _normalized);
            try { await Persist(observation, ct); } catch (IOException) { Interlocked.Increment(ref _queueDrops); }
            checkpointRequired = true;
        }
        // The durable queue already carries the authoritative sequence. Persist one
        // state checkpoint per bounded poll quantum so image-load pressure cannot
        // delay the other telemetry partitions with per-event DPAPI state rewrites.
        if (checkpointRequired) await checkpoint(_sequence, ct);
        if (Depth > 0 && (Depth >= _policy.MaximumBatchEvents || _lastUpload is null || DateTimeOffset.UtcNow - _lastUpload >= TimeSpan.FromSeconds(_policy.FlushSeconds))) await Upload(state, clientFactory, ct);
        return _sequence;
    }

    bool Allowed(NativeModuleEvent n)
    {
        if (n.Driver && !_policy.DriverLoads || !n.Driver && !_policy.UserModeModules || n.Kind is ModuleEventKind.ImageUnloaded or ModuleEventKind.DriverUnloaded && !_policy.UnloadEvents) return false;
        var type = ImageType(n.Path, n.Driver);
        if (!_policy.ExecutableImages && type == "executable" || !_policy.SharedLibraries && type is "dll" or "shared-library") return false;
        if (_policy.IncludedImageTypes is { Length: > 0 } && !_policy.IncludedImageTypes.Contains(type, StringComparer.OrdinalIgnoreCase) || _policy.ExcludedImageTypes?.Contains(type, StringComparer.OrdinalIgnoreCase) == true) return false;
        if (_policy.IncludedPaths is { Length: > 0 } && !_policy.IncludedPaths.Any(x => Match(n.Path, x)) || _policy.ExcludedPaths?.Any(x => Match(n.Path, x)) == true) return false;
        var process = ProcessName(n.ProcessId);
        if (_policy.IncludedProcesses is { Length: > 0 } && !_policy.IncludedProcesses.Any(x => Match(process, x)) || _policy.ExcludedProcesses?.Any(x => Match(process, x)) == true) return false;
        foreach (var r in _policy.ExclusionRules?.Where(x => x.Enabled) ?? []) if (r.Category == "path" && Match(n.Path, r.Pattern) || r.Category == "process" && Match(process, r.Pattern) || r.Category == "image-type" && Match(type, r.Pattern)) return false;
        return true;
    }

    async Task<ModuleObservation?> NormalizeAsync(AgentState s, NativeModuleEvent n, long sequence, CancellationToken ct)
    {
        if (!ModuleObservation.TryNormalizePath(n.Path, OperatingSystem.IsWindows(), out var path, out _)) return null;
        var quality = new List<string>();
        var process = n.Driver ? null : Relationship(s.EndpointId, n.ProcessId, _collector.Type);
        if (!n.Driver && process?.ProcessEntityId is null) { quality.Add("process-attribution-unavailable"); Interlocked.Increment(ref _attributionFailures); }
        var identity = FileIdentity(path);
        if (identity is null) { quality.Add("backing-file-identity-unavailable"); Interlocked.Increment(ref _identityFailures); }
        var hash = new ModuleHashMetadata(); var signer = new ModuleSignerMetadata();
        if (_policy.Hashing && Permit(_hashRate, _policy.MaximumHashesPerMinute)) { Interlocked.Increment(ref _hashRequested); hash = await HashAsync(path, identity, ct); if (hash.State == ModuleHashState.Succeeded) Interlocked.Increment(ref _hashCompleted); else Interlocked.Increment(ref _hashFailed); }
        if (_policy.SignerMetadata && Permit(_signerRate, _policy.MaximumSignersPerMinute)) { Interlocked.Increment(ref _signerRequested); signer = Signer(path); if (signer.FailureState is null) Interlocked.Increment(ref _signerCompleted); else Interlocked.Increment(ref _signerFailed); }
        var type = ImageType(path, n.Driver);
        var imageMachine = PeMachine(path);
        var nativeIdentity = n.ImageBase is null ? null : $"{n.ProcessId}:{n.ImageBase:x}";
        return new ModuleObservation(
            EventId: Guid.NewGuid(), SchemaVersion: "module-event.v1", Kind: n.Kind, EndpointId: s.EndpointId, AgentId: s.AgentId, InstallationId: s.InstallationId,
            CollectorId: $"{_collector.Type}:{Environment.MachineName}", CollectorSource: _collector.Type, CollectorVersion: _collector.Version, SourcePlatform: OperatingSystem.IsWindows() ? "windows" : "linux",
            NativeProvider: "Windows-Kernel-Image", NativeProviderId: null, NativeEventId: n.NativeEventId, NativeOpcode: null, Sequence: sequence, ObservedAt: n.ObservedAt,
            NormalizationVersion: "module-normalization.v1", RawSha256: Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(n.NativeEventId))).ToLowerInvariant(),
            DataQualityFlags: quality.ToArray(), SourceConfidence: quality.Count == 0 ? "high" : "medium",
            ModuleEntityId: ModuleObservation.StableEntityId(s.EndpointId, s.InstallationId, process?.ProcessEntityId, process?.ProcessStartTime, nativeIdentity, n.ImageBase, path, n.ObservedAt, sequence),
            NativeImageIdentity: nativeIdentity, OriginalPath: n.Path, NormalizedPath: path, Basename: Path.GetFileName(path), BackingFileEntityId: identity is null ? null : $"windows:{identity.VolumeId}:{identity.FileId}", BackingFileIdentity: identity,
            ImageSize: n.ImageSize, PreferredImageBase: n.PreferredBase, ActualLoadBase: n.ImageBase, LoadAddress: n.ImageBase, MappingSize: n.ImageSize,
            Architecture: imageMachine.Architecture, MachineType: imageMachine.MachineType, ImageType: type, Mode: n.Driver ? ModuleMode.Kernel : ModuleMode.User, Driver: n.Driver,
            ExecutableImage: type == "executable", SharedLibrary: type is "dll" or "shared-library", LoadResult: "observed", Lifecycle: n.Kind is ModuleEventKind.ImageUnloaded or ModuleEventKind.DriverUnloaded ? ModuleLifecycleState.Unloaded : _policy.UnloadEvents ? ModuleLifecycleState.Loaded : ModuleLifecycleState.IncompleteLifecycle,
            Hash: hash, Signer: signer, Process: process, User: process?.User);
    }

    async Task<ModuleHashMetadata> HashAsync(string path, FileNativeIdentity? identity, CancellationToken ct)
    {
        try
        {
            var before = new FileInfo(path); if (!before.Exists) return new(ModuleHashState.Unavailable, FailureReason: "backing-file-unavailable", PolicyVersion: CurrentPolicyKey);
            if (before.Length > _policy.MaximumHashFileBytes) return new(ModuleHashState.TooLarge, FileSize: before.Length, PolicyVersion: CurrentPolicyKey);
            var length = before.Length; var modified = before.LastWriteTimeUtc; var id = identity is null ? null : $"{identity.VolumeId}:{identity.FileId}";
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var value = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).ToLowerInvariant();
            var after = new FileInfo(path); var afterIdentity = FileIdentity(path); var afterId = afterIdentity is null ? null : $"{afterIdentity.VolumeId}:{afterIdentity.FileId}";
            if (id is not null && afterId is not null && id != afterId) return new(ModuleHashState.ReplacedDuringHash, FileIdentity: id, FileSize: length, FailureReason: "identity-changed", PolicyVersion: CurrentPolicyKey);
            if (!after.Exists || after.Length != length || after.LastWriteTimeUtc != modified) return new(ModuleHashState.ChangedDuringHash, FileIdentity: id, FileSize: length, FailureReason: "metadata-changed", PolicyVersion: CurrentPolicyKey);
            return new(ModuleHashState.Succeeded, Value: value, FileIdentity: id, FileSize: length, CapturedAt: DateTimeOffset.UtcNow, PolicyVersion: CurrentPolicyKey);
        }
        catch (UnauthorizedAccessException) { return new(ModuleHashState.PermissionDenied, FailureReason: "permission-denied", PolicyVersion: CurrentPolicyKey); }
        catch (Exception e) when (e is IOException or CryptographicException or NotSupportedException) { return new(ModuleHashState.Failed, FailureReason: e.GetType().Name, PolicyVersion: CurrentPolicyKey); }
    }
    static ModuleSignerMetadata Signer(string path)
    {
        try { using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)); return new("signed", "embedded-certificate-present", cert.Subject, cert.Issuer, cert.Thumbprint, null, DateTimeOffset.UtcNow, null, "win32-authenticode-certificate"); }
        catch (CryptographicException)
        {
            var signature = EmbeddedSignature(path);
            return signature switch
            {
                false => new("unsigned", "no-embedded-signature", VerifiedAt: DateTimeOffset.UtcNow, VerificationSource: "pe-authenticode-security-directory"),
                true => new("unknown", "not-verified", FailureState: "embedded-certificate-unreadable", VerificationSource: "pe-authenticode-security-directory"),
                _ => new("unknown", "not-verified", FailureState: "pe-signature-state-unavailable", VerificationSource: "pe-authenticode-security-directory")
            };
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return new("unknown", "not-verified", FailureState: e.GetType().Name, VerificationSource: "win32-authenticode-certificate"); }
    }
    static bool? EmbeddedSignature(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new BinaryReader(stream);
            if (stream.Length < 64 || reader.ReadUInt16() != 0x5a4d) return null;
            stream.Position = 0x3c; var peOffset = reader.ReadInt32();
            if (peOffset < 0 || peOffset > stream.Length - 24) return null;
            stream.Position = peOffset;
            if (reader.ReadUInt32() != 0x00004550) return null;
            stream.Position = peOffset + 20; var optionalSize = reader.ReadUInt16();
            var optionalStart = peOffset + 24L;
            if (optionalSize < 2 || optionalStart + optionalSize > stream.Length) return null;
            stream.Position = optionalStart; var magic = reader.ReadUInt16();
            var directoryStart = magic switch { 0x10b => optionalStart + 96, 0x20b => optionalStart + 112, _ => -1 };
            const int certificateDirectoryOffset = 4 * 8;
            if (directoryStart < 0 || directoryStart + certificateDirectoryOffset + 8 > optionalStart + optionalSize) return null;
            stream.Position = directoryStart + certificateDirectoryOffset;
            var certificateOffset = reader.ReadUInt32(); var certificateSize = reader.ReadUInt32();
            if (certificateOffset == 0 && certificateSize == 0) return false;
            return certificateOffset > 0 && certificateSize > 0 && certificateOffset + (ulong)certificateSize <= (ulong)stream.Length;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or EndOfStreamException or NotSupportedException) { return null; }
    }
    static bool Permit(Queue<DateTimeOffset> q, int maximum) { var now = DateTimeOffset.UtcNow; lock (q) { while (q.Count > 0 && now - q.Peek() >= TimeSpan.FromMinutes(1)) q.Dequeue(); if (maximum <= 0 || q.Count >= maximum) return false; q.Enqueue(now); return true; } }
    static string ImageType(string path, bool driver) => driver ? "driver" : Path.GetExtension(path).ToLowerInvariant() switch { ".exe" => "executable", ".dll" => "dll", ".so" => "shared-library", _ => "image" };
    static (string? Architecture, string? MachineType) PeMachine(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new BinaryReader(stream);
            if (reader.ReadUInt16() != 0x5a4d) return (null, null);
            stream.Position = 0x3c; var header = reader.ReadInt32();
            if (header < 0 || header > stream.Length - 6) return (null, null);
            stream.Position = header;
            if (reader.ReadUInt32() != 0x00004550) return (null, null);
            var machine = reader.ReadUInt16();
            return machine switch { 0x014c => ("x86", "IMAGE_FILE_MACHINE_I386"), 0x8664 => ("x64", "IMAGE_FILE_MACHINE_AMD64"), 0xaa64 => ("arm64", "IMAGE_FILE_MACHINE_ARM64"), _ => ("unknown", $"0x{machine:x4}") };
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or EndOfStreamException or NotSupportedException) { return (null, null); }
    }
    static string ProcessName(int pid) { try { using var p = Process.GetProcessById(pid); return p.ProcessName; } catch { return ""; } }
    static ModuleProcessRelationship? Relationship(Guid endpoint, int pid, string source) { if (pid <= 0) return null; try { using var p = Process.GetProcessById(pid); var started = new DateTimeOffset(p.StartTime.ToUniversalTime()); return new(ProcessIdentity.Create(endpoint, pid, started, $"{source}:{started.UtcTicks}"), pid, started, p.ProcessName, Try(() => p.MainModule?.FileName), Try(() => p.StartInfo.UserName), Try(() => p.SessionId), source, "high"); } catch { return new(null, pid, null, null, null, null, null, source, "pid-only"); } }
    static T? Try<T>(Func<T> f) { try { return f(); } catch { return default; } }
    static bool Match(string value, string pattern) { var p = pattern.Trim(); if (!p.Contains('*') && !p.Contains('?')) return value.Contains(p, StringComparison.OrdinalIgnoreCase); var parts = p.Split('*', StringSplitOptions.RemoveEmptyEntries); var cursor = 0; foreach (var part in parts) { var i = value.IndexOf(part.Trim('?'), cursor, StringComparison.OrdinalIgnoreCase); if (i < 0) return false; cursor = i + part.Length; } return true; }

    async Task Upload(AgentState s, Func<AgentState, HttpClient> clientFactory, CancellationToken ct)
    {
        var items = new List<(string Path, ModuleObservation Event)>(); foreach (var path in Directory.EnumerateFiles(_queue, "*.json").OrderBy(x => x)) { var value = await Read(path, ct); if (value is not null) items.Add((path, value)); if (items.Count >= _policy.MaximumBatchEvents) break; }
        if (items.Count == 0) return;
        ModuleEventBatch batch; byte[] canonical; byte[] compressed;
        // A queue must always make forward progress. Module observations can be
        // metadata-heavy, so reduce an oversized candidate deterministically
        // instead of retrying the same impossible batch forever.
        while (true)
        {
            var events = items.Select(x => x.Event).ToArray(); var eventBytes = JsonSerializer.SerializeToUtf8Bytes(events, Json);
            batch = new ModuleEventBatch(Guid.NewGuid(), s.EndpointId, s.AgentId, s.InstallationId, events.Min(x => x.Sequence), events.Max(x => x.Sequence), events, Convert.ToHexString(SHA256.HashData(eventBytes)).ToLowerInvariant());
            canonical = JsonSerializer.SerializeToUtf8Bytes(batch, Json); await using var output = new MemoryStream(); await using (var gzip = new GZipStream(output, CompressionLevel.Fastest, true)) await gzip.WriteAsync(canonical, ct); compressed = output.ToArray();
            if (compressed.Length <= 1048576 && canonical.Length <= _policy.MaximumBatchBytes) break;
            if (items.Count == 1) { Quarantine(items[0].Path, "module-event-exceeds-batch-policy"); return; }
            items.RemoveRange((items.Count + 1) / 2, items.Count / 2);
        }
        using var content = new ByteArrayContent(compressed); content.Headers.ContentType = new("application/json"); content.Headers.ContentEncoding.Add("gzip"); void H(string k, long v) => content.Headers.Add(k, v.ToString(CultureInfo.InvariantCulture));
        H("X-Uncompressed-Length", canonical.Length); H("X-Native-Events", _native); H("X-Normalized-Events", _normalized); H("X-Attribution-Failures", _attributionFailures); H("X-File-Identity-Failures", _identityFailures); H("X-Hash-Requested", _hashRequested); H("X-Hash-Completed", _hashCompleted); H("X-Hash-Failed", _hashFailed); H("X-Signer-Requested", _signerRequested); H("X-Signer-Completed", _signerCompleted); H("X-Signer-Failed", _signerFailed); H("X-Source-Drops", _collector.LostEvents); H("X-Queue-Depth", Depth); H("X-Queue-Age", Oldest); H("X-Queue-Drops", _queueDrops); H("X-Excluded", _excluded); H("X-Uploads", _uploads); H("X-Duplicates", _duplicates); H("X-Rejections", _rejections);
        content.Headers.Add("X-Policy-Version", CurrentPolicyKey); content.Headers.Add("X-Elevated", _collector.Elevated.ToString()); content.Headers.Add("X-Known-Limitations", string.Join(';', _collector.KnownLimitations)); if (int.TryParse(CurrentPolicyKey.Split(':').Last(), out var pv)) content.Headers.Add("X-Applied-Policy-Version", pv.ToString(CultureInfo.InvariantCulture));
        using var client = clientFactory(s); using var response = await client.PostAsync("/agent/v1/module-event-batches", content, ct); response.EnsureSuccessStatusCode(); LocalTestFailpoint.Hit("module-batch-after-transport-before-ack", _options.Environment);
        var ack = await response.Content.ReadFromJsonAsync<ModuleBatchAcknowledgement>(Json, ct) ?? throw new InvalidDataException("Module acknowledgement invalid."); Interlocked.Increment(ref _uploads); Interlocked.Add(ref _duplicates, ack.DuplicateEventIds.Count); Interlocked.Add(ref _rejections, ack.RejectedEventIds.Count);
        var done = ack.AcceptedEventIds.Concat(ack.DuplicateEventIds).ToHashSet(); foreach (var item in items) if (done.Contains(item.Event.EventId)) { var length = new FileInfo(item.Path).Length; File.Delete(item.Path); Interlocked.Add(ref _queueBytes, -length); } else if (ack.RejectedEventIds.TryGetValue(item.Event.EventId, out var rejection)) { var length = new FileInfo(item.Path).Length; Quarantine(item.Path, $"server-rejected-{rejection}"); Interlocked.Add(ref _queueBytes, -length); }
        _lastUpload = DateTimeOffset.UtcNow;
    }
    async Task Persist(ModuleObservation x, CancellationToken ct) { var bytes = JsonSerializer.SerializeToUtf8Bytes(x, Json); if (Interlocked.Read(ref _queueBytes) + bytes.Length > _policy.MaximumQueueBytes) throw new IOException("module-queue-capacity-exceeded"); var final = Path.Combine(_queue, $"{x.Sequence:D20}-{x.EventId:N}.json"); var temp = final + ".tmp"; await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { await stream.WriteAsync(bytes, ct); await stream.FlushAsync(ct); stream.Flush(true); } File.Move(temp, final + ".committing"); File.Move(final + ".committing", final); Interlocked.Add(ref _queueBytes, bytes.Length); }
    async Task<ModuleObservation?> Read(string path, CancellationToken ct) { try { return JsonSerializer.Deserialize<ModuleObservation>(await File.ReadAllBytesAsync(path, ct), Json) ?? throw new JsonException(); } catch (Exception e) when (e is JsonException or IOException) { Quarantine(path, e.GetType().Name); return null; } }
    void Recover() { foreach (var p in Directory.EnumerateFiles(_queue, "*.tmp").Concat(Directory.EnumerateFiles(_queue, "*.committing")).ToArray()) try { _ = JsonSerializer.Deserialize<ModuleObservation>(File.ReadAllText(p), Json) ?? throw new JsonException(); var final = p.EndsWith(".committing", StringComparison.Ordinal) ? p[..^11] : p[..^4]; if (!File.Exists(final)) File.Move(p, final); else Quarantine(p, "duplicate-commit"); } catch (Exception e) when (e is JsonException or IOException) { Quarantine(p, e.GetType().Name); } }
    void Quarantine(string path, string reason) { try { Directory.CreateDirectory(_quarantine); var target = Path.Combine(_quarantine, $"{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.bad"); File.Move(path, target, true); File.WriteAllText(target + ".reason", reason); } finally { Interlocked.Increment(ref _queueDrops); } }
    static void Protect(string path) { if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
    static FileNativeIdentity? FileIdentity(string path) { if (!OperatingSystem.IsWindows()) return null; try { using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete); if (!GetFileInformationByHandle(handle, out var i)) return null; var id = ((ulong)i.FileIndexHigh << 32) | i.FileIndexLow; return new(i.VolumeSerialNumber.ToString("x8", CultureInfo.InvariantCulture), id.ToString("x16", CultureInfo.InvariantCulture), null, null, null, null, i.NumberOfLinks > 1); } catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException) { return null; } }
    [StructLayout(LayoutKind.Sequential)] struct ByHandleFileInformation { public uint FileAttributes; public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime; public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle, out ByHandleFileInformation information);
    public async ValueTask DisposeAsync() => await _collector.DisposeAsync();
}
