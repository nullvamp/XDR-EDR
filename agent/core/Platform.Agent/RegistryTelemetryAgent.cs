using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http.Json;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;
using OpenSecurityPlatform.Foundation;

sealed record NativeRegistryEvent(
    RegistryEventKind Kind,
    ulong KeyHandle,
    string KeyName,
    string? ValueName,
    int ProcessId,
    int ThreadId,
    int Status,
    int Index,
    DateTimeOffset ObservedAt,
    string SourceEventId,
    string NativeOperation,
    long NativeSequence
);

interface IRegistryCollector : IAsyncDisposable
{
    string Type { get; }
    string Version { get; }
    string State { get; }
    string? Error { get; }
    long LostEvents { get; }
    Task StartAsync(CancellationToken ct);
    Task<IReadOnlyList<NativeRegistryEvent>> PollAsync(CancellationToken ct);
}

sealed class WindowsEtwRegistryCollector(string dataDirectory) : IRegistryCollector
{
    private const string SessionName = "OpenSecurityPlatform-RegistryLifecycle-v1";
    private const int MaximumBufferedNativeEvents = 100_000;
    private const int MaximumTrackedKeyHandles = 25_000;
    private readonly ConcurrentQueue<NativeRegistryEvent> _events = [];
    private readonly ConcurrentDictionary<ulong, string> _keyNames = [];
    private readonly ConcurrentQueue<ulong> _keyNameOrder = [];
    private readonly string _owner = Path.Combine(dataDirectory, "etw-registry-session-owner.json");
    private TraceEventSession? _session; private Task? _reader; private long _native, _queued, _overflow;
    public string Type => "windows.etw-registry"; public string Version => "1.0.0"; public string State { get; private set; } = "stopped"; public string? Error { get; private set; }
    public long LostEvents { get { try { return (_session?.EventsLost ?? 0) + Interlocked.Read(ref _overflow); } catch { return Interlocked.Read(ref _overflow); } } }
    public Task StartAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) { State = "unsupported"; Error = "Windows registry ETW requires Windows."; return Task.CompletedTask; }
        try
        {
            if (TraceEventSession.GetActiveSessionNames().Contains(SessionName, StringComparer.Ordinal)) { if (!OwnedStale()) throw new InvalidOperationException("ETW registry session-name conflict is not demonstrably platform-owned."); using var stale = new TraceEventSession(SessionName); stale.Stop(); }
            _session = new TraceEventSession(SessionName) { StopOnDispose = true, BufferSizeMB = 64 };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Registry | KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Thread);
            // TraceEvent's RegistryNameToObject tracker is a HistoryDictionary and
            // is explicitly unbounded. Maintain the small amount of live handle
            // state needed by this real-time collector ourselves instead.
            var parser = new KernelTraceEventParser(_session.Source, KernelTraceEventParser.ParserTrackingOptions.ThreadToProcess);
            parser.RegistryOpen += Track;
            parser.RegistryKCBCreate += Track;
            parser.RegistryKCBRundownBegin += Track;
            parser.RegistryKCBRundownEnd += Track;
            parser.RegistryCreate += d => { Track(d); Emit(d, RegistryEventKind.KeyCreated, "create-key"); };
            parser.RegistryDelete += d => Emit(d, RegistryEventKind.KeyDeleted, "delete-key");
            parser.RegistrySetValue += d => Emit(d, RegistryEventKind.ValueSet, "set-value");
            parser.RegistryDeleteValue += d => Emit(d, RegistryEventKind.ValueDeleted, "delete-value");
            _reader = Task.Run(() => _session.Source.Process(), CancellationToken.None); WriteOwner(); State = "healthy";
        }
        catch (Exception e) { State = "failed"; Error = $"{e.GetType().Name}: {e.Message}"; }
        return Task.CompletedTask;
    }
    private void Emit(RegistryTraceData d, RegistryEventKind kind, string operation)
    {
        if (d.ProcessID == Environment.ProcessId) return; var seq = Interlocked.Increment(ref _native); var key = d.KeyName ?? ""; if (string.IsNullOrWhiteSpace(key)) _keyNames.TryGetValue(d.KeyHandle, out key); key ??= ""; if (Interlocked.Increment(ref _queued) > MaximumBufferedNativeEvents) { Interlocked.Decrement(ref _queued); Interlocked.Increment(ref _overflow); return; }
        _events.Enqueue(new(kind, d.KeyHandle, key, string.IsNullOrEmpty(d.ValueName) ? null : d.ValueName, d.ProcessID, d.ThreadID, d.Status, d.Index, new DateTimeOffset(d.TimeStamp.ToUniversalTime()), $"{SessionName}:{operation}:{d.ProcessID}:{d.ThreadID}:{d.TimeStampRelativeMSec:F6}:{seq}", operation, seq));
    }
    private void Track(RegistryTraceData d) { var key = d.KeyName; if (d.KeyHandle == 0 || string.IsNullOrWhiteSpace(key)) return; if (_keyNames.TryAdd(d.KeyHandle, key)) { _keyNameOrder.Enqueue(d.KeyHandle); while (_keyNames.Count > MaximumTrackedKeyHandles && _keyNameOrder.TryDequeue(out var oldest)) { if (_keyNames.TryRemove(oldest, out _)) Interlocked.Increment(ref _overflow); } } else _keyNames[d.KeyHandle] = key; }
    public Task<IReadOnlyList<NativeRegistryEvent>> PollAsync(CancellationToken ct) { var list = new List<NativeRegistryEvent>(); while (list.Count < 50_000 && _events.TryDequeue(out var x)) { Interlocked.Decrement(ref _queued); list.Add(x); } return Task.FromResult<IReadOnlyList<NativeRegistryEvent>>(list); }
    private bool OwnedStale() { try { if (!File.Exists(_owner)) return false; using var d = JsonDocument.Parse(File.ReadAllText(_owner)); if (d.RootElement.GetProperty("sessionName").GetString() != SessionName) return false; var pid = d.RootElement.GetProperty("ownerPid").GetInt32(); if (pid == Environment.ProcessId) return true; try { using var p = Process.GetProcessById(pid); return p.HasExited; } catch (ArgumentException) { return true; } } catch { return false; } }
    private void WriteOwner() { Directory.CreateDirectory(Path.GetDirectoryName(_owner)!); using var s = new FileStream(_owner, FileMode.Create, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough); JsonSerializer.Serialize(s, new { sessionName = SessionName, ownerPid = Environment.ProcessId, createdAt = DateTimeOffset.UtcNow }); s.Flush(true); }
    private void RemoveOwner() { try { if (File.Exists(_owner)) { using var d = JsonDocument.Parse(File.ReadAllText(_owner)); if (d.RootElement.GetProperty("ownerPid").GetInt32() == Environment.ProcessId) File.Delete(_owner); } } catch { } }
    public async ValueTask DisposeAsync() { _session?.Stop(); if (_reader is not null) try { await _reader.WaitAsync(TimeSpan.FromSeconds(5)); } catch (Exception e) when (e is System.Runtime.InteropServices.COMException or TimeoutException) { } _session?.Dispose(); _session = null; RemoveOwner(); State = "stopped"; }
}

sealed class UnsupportedRegistryCollector : IRegistryCollector
{
    public string Type => "unsupported"; public string Version => "1.0.0"; public string State => "unsupported"; public string? Error => "Registry telemetry is Windows-only."; public long LostEvents => 0; public Task StartAsync(CancellationToken ct) => Task.CompletedTask; public Task<IReadOnlyList<NativeRegistryEvent>> PollAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<NativeRegistryEvent>>([]); public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

static class RegistryCollectorSelfTest
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static async Task<int> RunAsync(string dataDirectory, string? output)
    {
        if (!OperatingSystem.IsWindows() || !IsAdministrator())
            return 2;
        var marker = $"native-{Guid.NewGuid():N}";
        var relative = $@"Software\OpenSecurityPlatform\Sprint4\{marker}";
        await using var collector = new WindowsEtwRegistryCollector(dataDirectory);
        await collector.StartAsync(default);
        if (collector.State != "healthy")
        {
            if (!string.IsNullOrWhiteSpace(output))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
                await File.WriteAllTextAsync(
                    output,
                    JsonSerializer.Serialize(
                        new
                        {
                            schema = "platform.registry-native-self-test.v1",
                            executedAt = DateTimeOffset.UtcNow,
                            elevated = true,
                            collector = collector.Type,
                            collectorState = collector.State,
                            collectorError = collector.Error,
                            passed = false,
                        },
                        Json
                    )
                );
            }
            return 3;
        }
        var nativePath = $@"HKCU\{relative}";
        var controlledPids = new HashSet<int>
        {
            RunReg($@"add ""{nativePath}"" /f"),
            RunReg($@"add ""{nativePath}"" /v TextValue /t REG_SZ /d first /f"),
            RunReg($@"add ""{nativePath}"" /v TextValue /t REG_SZ /d second /f"),
            RunReg($@"add ""{nativePath}"" /v DwordValue /t REG_DWORD /d 42 /f"),
            RunReg($@"delete ""{nativePath}"" /v DwordValue /f"),
            RunReg($@"delete ""{nativePath}"" /f"),
        };
        await Task.Delay(1500);
        var collected = new List<NativeRegistryEvent>();
        var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
        do
        {
            collected.AddRange(await collector.PollAsync(default));
            if (
                collected
                    .Where(x => x.KeyName.Contains(marker, StringComparison.OrdinalIgnoreCase))
                    .Select(x => x.Kind)
                    .Distinct()
                    .Count() >= 4
            )
                break;
            await Task.Delay(100);
        } while (DateTimeOffset.UtcNow < deadline);
        var events = collected
            .Where(x => x.KeyName.Contains(marker, StringComparison.OrdinalIgnoreCase))
            .Select(x => new
            {
                kind = x.Kind.ToString(),
                x.KeyName,
                x.ValueName,
                x.ProcessId,
                x.ThreadId,
                x.Status,
                x.NativeOperation,
            })
            .ToArray();
        var controlledEvents = collected
            .Where(x => controlledPids.Contains(x.ProcessId))
            .Select(x => new
            {
                kind = x.Kind.ToString(),
                x.KeyHandle,
                x.KeyName,
                x.ValueName,
                x.ProcessId,
                x.NativeOperation,
            })
            .Take(100)
            .ToArray();
        var report = new
        {
            schema = "platform.registry-native-self-test.v1",
            executedAt = DateTimeOffset.UtcNow,
            elevated = true,
            collector = collector.Type,
            collectorState = collector.State,
            lostEvents = collector.LostEvents,
            marker,
            events,
            controlledEvents,
            passed = new[]
            {
                RegistryEventKind.KeyCreated,
                RegistryEventKind.ValueSet,
                RegistryEventKind.ValueDeleted,
                RegistryEventKind.KeyDeleted,
            }.All(kind => events.Any(x => x.kind == kind.ToString())),
        };
        if (!string.IsNullOrWhiteSpace(output))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(report, Json));
        }
        return report.passed ? 0 : 1;
    }

    [SupportedOSPlatform("windows")]
    private static bool IsAdministrator()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(
            System.Security.Principal.WindowsBuiltInRole.Administrator
        );
    }

    private static int RunReg(string arguments)
    {
        using var process = Process.Start(
            new ProcessStartInfo("reg.exe", arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            }
        ) ?? throw new InvalidOperationException("Unable to launch controlled registry workload.");
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException("Controlled registry workload failed.");
        return process.Id;
    }
}

sealed class RegistryTelemetryPipeline : IAsyncDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly AgentOptions _options; private readonly IRegistryCollector _collector; private readonly string _queue; private readonly string _quarantine;
    private readonly Dictionary<string, (string Entity, DateTimeOffset Started, bool Deleted)> _keys = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (string Entity, DateTimeOffset Started, bool Deleted)> _values = new(StringComparer.OrdinalIgnoreCase);
    private RegistryTelemetryPolicy _policy = new(Enabled: false); private long _sequence, _queueBytes, _dropped, _excluded, _handleFailures, _pathFailures, _captureAttempts, _captureSkips, _captureFailures, _redacted; private DateTimeOffset? _lastSource, _lastUpload; private string _uploadResult = "not-attempted";
    public string CurrentPolicyKey { get; private set; } = "implicit"; public string CollectorState => !_policy.Enabled ? "policy-disabled" : _collector.State; public string CollectorRuntimeState => _collector.State; public string? CollectorError => _collector.Error; public string CollectorType => _collector.Type; public long QueueDepth => Directory.Exists(_queue) ? Directory.EnumerateFiles(_queue, "*.json").LongCount() : 0;
    public RegistryTelemetryPipeline(AgentOptions options, long sequence) { _options = options; _collector = string.Equals(Environment.GetEnvironmentVariable("PLATFORM_TELEMETRY_DRAIN_ONLY"), "true", StringComparison.OrdinalIgnoreCase) ? new UnsupportedRegistryCollector() : OperatingSystem.IsWindows() ? new WindowsEtwRegistryCollector(options.DataDirectory) : new UnsupportedRegistryCollector(); _queue = Path.Combine(options.DataDirectory, "registry-queue"); _quarantine = Path.Combine(_queue, "quarantine"); Directory.CreateDirectory(_queue); Protect(_queue); Recover(); _queueBytes = Directory.EnumerateFiles(_queue, "*.json").Sum(x => new FileInfo(x).Length); _sequence = Math.Max(sequence, Directory.EnumerateFiles(_queue, "*.json").Select(x => long.TryParse(Path.GetFileName(x).Split('-')[0], out var n) ? n : 0).DefaultIfEmpty().Max()); _collector.StartAsync(default).GetAwaiter().GetResult(); }
    public Task<IReadOnlyDictionary<string, string[]>> ApplyPolicyAsync(RegistryTelemetryPolicy policy, Guid id, int version) { var e = RegistryPolicyValidation.Validate(policy).ToDictionary(x => x.Key, x => x.Value); if (policy.CollectorSource != _collector.Type) e["collectorSource"] = ["Policy collector does not match the active production collector."]; if (e.Count == 0) { _policy = policy; CurrentPolicyKey = $"{id:D}:{version}"; } return Task.FromResult<IReadOnlyDictionary<string, string[]>>(e); }
    public async Task<long> RunOnceAsync(AgentState state, Func<AgentState, HttpClient> clientFactory, Func<long, CancellationToken, Task> checkpoint, CancellationToken ct)
    {
        foreach (var n in await _collector.PollAsync(ct))
        {
            _lastSource = n.ObservedAt; if (!_policy.Enabled || !Allowed(n)) { Interlocked.Increment(ref _excluded); continue; }
            var normalized = Normalize(state, n, Interlocked.Increment(ref _sequence)); try { await Persist(normalized, ct); } catch (IOException) { Interlocked.Increment(ref _dropped); }
            await checkpoint(_sequence, ct);
        }
        if (QueueDepth > 0 && (_lastUpload is null || DateTimeOffset.UtcNow - _lastUpload >= TimeSpan.FromSeconds(_policy.FlushSeconds))) await Upload(state, clientFactory, ct); return _sequence;
    }
    private bool Allowed(NativeRegistryEvent n)
    {
        if (n.Kind == RegistryEventKind.KeyCreated && !_policy.KeyCreateEnabled || n.Kind == RegistryEventKind.KeyDeleted && !_policy.KeyDeleteEnabled || n.Kind == RegistryEventKind.ValueSet && !_policy.ValueSetEnabled || n.Kind == RegistryEventKind.ValueDeleted && !_policy.ValueDeleteEnabled) return false;
        var (hive, path, _) = NormalizePath(n.KeyName); var full = $"{hive}\\{path}"; if (_policy.IncludedHives is { Length: > 0 } && !_policy.IncludedHives.Contains(hive, StringComparer.OrdinalIgnoreCase)) return false; if (_policy.IncludedPaths is { Length: > 0 } && !_policy.IncludedPaths.Any(x => full.Contains(x, StringComparison.OrdinalIgnoreCase))) return false; if (_policy.ExcludedPaths?.Any(x => full.StartsWith(x, StringComparison.OrdinalIgnoreCase)) == true) return false; if (_policy.ExcludedValueNames?.Any(x => string.Equals(x, n.ValueName, StringComparison.OrdinalIgnoreCase)) == true) return false;
        foreach (var r in _policy.ExclusionRules?.Where(x => x.Enabled) ?? []) { var match = r.Category switch { "key-exact" => full.Equals(r.Pattern, StringComparison.OrdinalIgnoreCase), "key-prefix" => full.StartsWith(r.Pattern, StringComparison.OrdinalIgnoreCase), "value" => Wildcard(n.ValueName ?? "", r.Pattern), "hive" => hive.Equals(r.Pattern, StringComparison.OrdinalIgnoreCase), _ => false }; if (match) return false; }
        return true;
    }
    private RegistryObservation Normalize(AgentState s, NativeRegistryEvent n, long sequence)
    {
        var (hive, path, resolved) = NormalizePath(n.KeyName); if (n.KeyHandle == 0) Interlocked.Increment(ref _handleFailures); if (!resolved) Interlocked.Increment(ref _pathFailures); var full = $"{hive}\\{path}"; var key = _keys.GetValueOrDefault(full); if (key.Entity is null || key.Deleted && n.Kind != RegistryEventKind.KeyDeleted) { var started = n.ObservedAt; key = (RegistryObservation.StableKeyEntityId(s.EndpointId, hive, path, started), started, false); }
        if (n.Kind == RegistryEventKind.KeyDeleted) { key.Deleted = true; foreach (var valueKey in _values.Keys.Where(x => x.StartsWith(full + "\0", StringComparison.OrdinalIgnoreCase)).ToArray()) { var value = _values[valueKey]; value.Deleted = true; _values[valueKey] = value; } }
        _keys[full] = key;
        string? valueEntity = null; if (n.ValueName is not null) { var valueKey = $"{full}\0{n.ValueName}"; var value = _values.GetValueOrDefault(valueKey); if (value.Entity is null || value.Deleted && n.Kind == RegistryEventKind.ValueSet) { var started = n.ObservedAt; value = (RegistryObservation.StableValueEntityId(s.EndpointId, key.Entity, n.ValueName, started), started, false); } if (n.Kind == RegistryEventKind.ValueDeleted) value.Deleted = true; _values[valueKey] = value; valueEntity = value.Entity; }
        var quality = new List<string>(); if (!resolved) quality.Add("registry-path-unresolved"); if (n.Kind == RegistryEventKind.KeyCreated) quality.Add("key-create-open-indistinguishable"); if (n.Kind == RegistryEventKind.ValueSet) quality.Add("value-create-modify-indistinguishable"); var process = Process(n.ProcessId, n.ThreadId, s.EndpointId); if (process is null) quality.Add("process-unavailable"); var metadata = n.ValueName is null ? RegistryValueMetadata.MetadataOnly("not-a-value-operation") : Capture(hive, path, n.ValueName, n.Kind);
        return new(Guid.NewGuid(), "registry-event.v1", n.Kind, s.EndpointId, s.AgentId, s.InstallationId, $"{_collector.Type}:{Environment.MachineName}", _collector.Type, _collector.Version, "windows", n.SourceEventId, sequence, n.ObservedAt, "registry-normalization.v1", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(n.SourceEventId))).ToLowerInvariant(), null, Activity.Current?.TraceId.ToString(), quality.ToArray(), resolved ? "high" : "low", key.Entity, valueEntity, hive, n.KeyHandle, path, Parent(path), null, null, n.ValueName, "native", "unknown", "unavailable", n.NativeOperation, n.Status, n.Status == 0 ? "success" : $"native-status:{n.Status}", null, null, n.Index == 0 ? null : n.Index.ToString(System.Globalization.CultureInfo.InvariantCulture), n.Kind is RegistryEventKind.KeyDeleted or RegistryEventKind.ValueDeleted, metadata, process, null);
    }
    private RegistryValueMetadata Capture(string hive, string path, string name, RegistryEventKind kind)
    {
        if (!OperatingSystem.IsWindows()) return RegistryValueMetadata.MetadataOnly("capture-unsupported-platform");
        var full = $"{hive}\\{path}"; if (kind == RegistryEventKind.ValueDeleted) return RegistryValueMetadata.MetadataOnly("value-deleted"); if (_policy.CaptureMode == RegistryCaptureMode.None) return RegistryValueMetadata.MetadataOnly("capture-disabled") with { CaptureMode = RegistryCaptureMode.None }; if (RegistryPolicyValidation.IsProtectedPath(full) || RegistryPolicyValidation.IsSecretLikeName(name)) { Interlocked.Increment(ref _captureSkips); Interlocked.Increment(ref _redacted); return RegistryValueMetadata.MetadataOnly("protected-or-secret-like") with { Redacted = true }; }
        try { using var key = Open(hive, path); if (key is null) { Interlocked.Increment(ref _captureFailures); return RegistryValueMetadata.MetadataOnly("key-unavailable"); } var kindName = key.GetValueKind(name).ToString(); if (_policy.CaptureMode == RegistryCaptureMode.MetadataOnly) { Interlocked.Increment(ref _captureSkips); return RegistryValueMetadata.MetadataOnly() with { ValueType = kindName, DataPresent = true, PolicyVersion = CurrentPolicyKey }; } if (_policy.AllowedCapturePaths is not { Length: > 0 } || !_policy.AllowedCapturePaths.Any(x => full.StartsWith(x, StringComparison.OrdinalIgnoreCase))) { Interlocked.Increment(ref _captureSkips); return RegistryValueMetadata.MetadataOnly("path-not-approved") with { ValueType = kindName, DataPresent = true, PolicyVersion = CurrentPolicyKey }; } if (_policy.IncludedValueTypes is { Length: > 0 } && !_policy.IncludedValueTypes.Contains(kindName, StringComparer.OrdinalIgnoreCase) || _policy.ExcludedValueTypes?.Contains(kindName, StringComparer.OrdinalIgnoreCase) == true) { Interlocked.Increment(ref _captureSkips); return RegistryValueMetadata.MetadataOnly("value-type-not-approved") with { ValueType = kindName, DataPresent = true, PolicyVersion = CurrentPolicyKey }; } Interlocked.Increment(ref _captureAttempts); var raw = Bytes(key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames)); var length = raw.Length; var hash = Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant(); if (_policy.CaptureMode == RegistryCaptureMode.ContentHash || _policy.ContentHashingEnabled) return new(kindName, length, true, RegistryCaptureMode.ContentHash, 0, false, false, hash, null, EncodingName(kindName), null, Classification(kindName), DateTimeOffset.UtcNow, CurrentPolicyKey, null, "SHA-256"); var take = Math.Min(length, _policy.MaximumCapturedBytes); var preview = kindName == "Binary" ? Convert.ToHexString(raw.AsSpan(0, take)).ToLowerInvariant() : Encoding.UTF8.GetString(raw, 0, take); var redacted = _policy.RedactionPatterns?.Any(x => preview.Contains(x, StringComparison.OrdinalIgnoreCase)) == true; if (redacted) { preview = "[REDACTED]"; Interlocked.Increment(ref _redacted); } return new(kindName, length, true, _policy.CaptureMode, take, take < length, redacted, hash, null, EncodingName(kindName), preview, Classification(kindName), DateTimeOffset.UtcNow, CurrentPolicyKey, null, "SHA-256"); } catch (Exception e) when (e is UnauthorizedAccessException or System.Security.SecurityException or IOException or ArgumentException) { Interlocked.Increment(ref _captureFailures); return RegistryValueMetadata.MetadataOnly(e.GetType().Name) with { PolicyVersion = CurrentPolicyKey }; }
    }
    private async Task Upload(AgentState s, Func<AgentState, HttpClient> clientFactory, CancellationToken ct)
    {
        var items = new List<(string Path, RegistryObservation Event)>(); foreach (var path in Directory.EnumerateFiles(_queue, "*.json").OrderBy(x => x)) { var x = await Read(path, ct); if (x is null) continue; items.Add((path, x)); if (items.Count >= _policy.MaximumBatchEvents) break; }
        if (items.Count == 0) return; var events = items.Select(x => x.Event).ToArray(); var eventBytes = JsonSerializer.SerializeToUtf8Bytes(events, Json); var draft = new RegistryEventBatch(Guid.NewGuid(), s.EndpointId, s.AgentId, s.InstallationId, events.Min(x => x.Sequence), events.Max(x => x.Sequence), events, Convert.ToHexString(SHA256.HashData(eventBytes)).ToLowerInvariant()); var canonical = JsonSerializer.SerializeToUtf8Bytes(draft, Json); await using var compressed = new MemoryStream(); await using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, true)) await gzip.WriteAsync(canonical, ct); if (compressed.Length > 1024 * 1024) { _uploadResult = "compressed-batch-too-large"; return; }
        var batch = draft with { UncompressedBytes = canonical.Length, CompressedBytes = (int)compressed.Length }; canonical = JsonSerializer.SerializeToUtf8Bytes(batch, Json); compressed.SetLength(0); await using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, true)) await gzip.WriteAsync(canonical, ct); using var content = new ByteArrayContent(compressed.ToArray()); content.Headers.ContentType = new("application/json"); content.Headers.ContentEncoding.Add("gzip"); content.Headers.Add("X-Uncompressed-Length", canonical.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-Queue-Depth", QueueDepth.ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-Queue-Oldest-Age", Oldest().ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-Dropped-Events", _dropped.ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-Excluded-Events", _excluded.ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-ETW-Lost-Events", _collector.LostEvents.ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-Handle-Resolution-Failures", _handleFailures.ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-Path-Resolution-Failures", _pathFailures.ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-Capture-Attempts", _captureAttempts.ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-Capture-Skips", _captureSkips.ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-Capture-Failures", _captureFailures.ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-Redacted-Values", _redacted.ToString(System.Globalization.CultureInfo.InvariantCulture)); content.Headers.Add("X-Policy-Version", CurrentPolicyKey); if (ParseVersion() is { } applied) content.Headers.Add("X-Applied-Policy-Version", applied.ToString(System.Globalization.CultureInfo.InvariantCulture)); using var client = clientFactory(s); using var response = await client.PostAsync("/agent/v1/registry-event-batches", content, ct); if (!response.IsSuccessStatusCode) { _uploadResult = $"http-{(int)response.StatusCode}"; response.EnsureSuccessStatusCode(); }
        LocalTestFailpoint.Hit("registry-batch-after-transport-before-ack", _options.Environment);
        var ack = await response.Content.ReadFromJsonAsync<RegistryBatchAcknowledgement>(Json, ct) ?? throw new InvalidDataException("Registry batch acknowledgement invalid."); var done = ack.AcceptedEventIds.Concat(ack.DuplicateEventIds).ToHashSet(); foreach (var item in items) if (done.Contains(item.Event.EventId)) { var length = new FileInfo(item.Path).Length; File.Delete(item.Path); Interlocked.Add(ref _queueBytes, -length); }
        _lastUpload = DateTimeOffset.UtcNow; _uploadResult = "accepted";
    }
    public RegistryTelemetryHealth Health(Guid endpoint) => new(endpoint, _policy.Enabled, _collector.Type, _collector.Version, _lastSource, null, QueueDepth, Oldest(), _dropped, _excluded, _collector.LostEvents, 0, _handleFailures, _pathFailures, _captureAttempts, _captureSkips, _captureFailures, _redacted, _uploadResult, CurrentPolicyKey, ParseVersion(), false, _lastUpload, _sequence);
    private int? ParseVersion() => int.TryParse(CurrentPolicyKey.Split(':').LastOrDefault(), out var x) ? x : null;
    private async Task Persist(RegistryObservation x, CancellationToken ct) { var bytes = JsonSerializer.SerializeToUtf8Bytes(x, Json); if (Interlocked.Read(ref _queueBytes) + bytes.Length > _policy.MaximumQueueBytes) throw new IOException("registry-queue-capacity-exceeded"); var final = Path.Combine(_queue, $"{x.Sequence:D20}-{x.EventId:N}.json"); var tmp = final + ".tmp"; LocalTestFailpoint.Hit("registry-queue-before-temp-write", _options.Environment); await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { await stream.WriteAsync(bytes, ct); await stream.FlushAsync(ct); stream.Flush(true); } LocalTestFailpoint.Hit("registry-queue-after-flush-before-rename", _options.Environment); File.Move(tmp, final + ".committing"); LocalTestFailpoint.Hit("registry-queue-rename-boundary", _options.Environment); File.Move(final + ".committing", final); Interlocked.Add(ref _queueBytes, bytes.Length); }
    private async Task<RegistryObservation?> Read(string path, CancellationToken ct) { try { var value = JsonSerializer.Deserialize<RegistryObservation>(await File.ReadAllBytesAsync(path, ct), Json) ?? throw new JsonException(); if (value.EventId == Guid.Empty || value.Sequence < 1) throw new InvalidDataException(); return value; } catch (Exception e) when (e is JsonException or IOException or InvalidDataException) { Quarantine(path, e.GetType().Name); return null; } }
    private void Recover() { foreach (var p in Directory.EnumerateFiles(_queue, "*.tmp").Concat(Directory.EnumerateFiles(_queue, "*.committing")).ToArray()) { try { var x = JsonSerializer.Deserialize<RegistryObservation>(File.ReadAllText(p), Json) ?? throw new JsonException(); var final = p.EndsWith(".committing", StringComparison.Ordinal) ? p[..^11] : p[..^4]; if (!File.Exists(final)) File.Move(p, final); else Quarantine(p, "duplicate-commit"); } catch (Exception e) when (e is JsonException or IOException) { Quarantine(p, e.GetType().Name); } } var cutoff = DateTimeOffset.UtcNow.AddHours(-_policy.MaximumQueueAgeHours); foreach (var p in Directory.EnumerateFiles(_queue, "*.json").Select(x => new FileInfo(x)).Where(x => x.CreationTimeUtc < cutoff)) Quarantine(p.FullName, "maximum-age"); }
    private void Quarantine(string path, string reason) { try { var length = File.Exists(path) ? new FileInfo(path).Length : 0; Directory.CreateDirectory(_quarantine); Protect(_quarantine); var target = Path.Combine(_quarantine, $"{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.bad"); File.Move(path, target, true); File.WriteAllText(target + ".reason", reason); if (string.Equals(Path.GetDirectoryName(path), _queue, StringComparison.OrdinalIgnoreCase) && path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) Interlocked.Add(ref _queueBytes, -length); Interlocked.Increment(ref _dropped); } catch { Interlocked.Increment(ref _dropped); } }
    private long Oldest() { var files = Directory.Exists(_queue) ? Directory.EnumerateFiles(_queue, "*.json").Select(x => new FileInfo(x)).ToArray() : []; return files.Length == 0 ? 0 : (long)Math.Max(0, (DateTimeOffset.UtcNow - files.Min(x => x.CreationTimeUtc)).TotalSeconds); }
    private static (string Hive, string Path, bool Resolved) NormalizePath(string native)
    {
        var n = (native ?? "").Replace('/', '\\').Trim();
        var prefixes = new[] { ("\\REGISTRY\\MACHINE\\", "HKLM"), ("REGISTRY\\MACHINE\\", "HKLM"), ("\\REGISTRY\\USER\\", "HKU"), ("REGISTRY\\USER\\", "HKU") };
        foreach (var (prefix, hive) in prefixes)
        {
            if (!n.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            var path = n[prefix.Length..].TrimStart('\\');
            if (hive == "HKU")
            {
                var separator = path.IndexOf('\\');
                var root = separator < 0 ? path : path[..separator];
                if (root.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                {
                    var sid = root[..^8];
                    var suffix = separator < 0 ? "" : path[(separator + 1)..];
                    path = $"{sid}\\Software\\Classes" + (suffix.Length == 0 ? "" : $"\\{suffix}");
                }
            }
            return (hive, path, true);
        }
        if (n.StartsWith("HK", StringComparison.OrdinalIgnoreCase)) { var split = n.IndexOf('\\'); return split > 0 ? (n[..split].ToUpperInvariant(), n[(split + 1)..], true) : (n.ToUpperInvariant(), "", true); }
        return ("UNRESOLVED", n.Length == 0 ? "<unavailable>" : n, false);
    }
    private static string? Parent(string path) { var i = path.LastIndexOf('\\'); return i <= 0 ? null : path[..i]; }
    private static RegistryProcessRelationship? Process(int pid, int thread, Guid endpoint) { if (pid <= 0) return null; try { using var p = System.Diagnostics.Process.GetProcessById(pid); var started = new DateTimeOffset(p.StartTime.ToUniversalTime()); return new(ProcessIdentity.Create(endpoint, pid, started, $"windows:{started.UtcTicks}"), pid, started, p.ProcessName, Try(() => p.MainModule?.FileName), null, null, Try(() => p.SessionId), thread, "native-etw", "high"); } catch { return new(null, pid, null, null, null, null, null, null, thread, "native-etw", "pid-only"); } }
    private static T? Try<T>(Func<T> value) { try { return value(); } catch { return default; } }
    [SupportedOSPlatform("windows")]
    private static RegistryKey? Open(string hive, string path) { var baseKey = hive switch { "HKLM" => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default), "HKU" => RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default), "HKCR" => RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Default), "HKCC" => RegistryKey.OpenBaseKey(RegistryHive.CurrentConfig, RegistryView.Default), "HKCU" => RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default), _ => null }; if (baseKey is null) return null; using (baseKey) return baseKey.OpenSubKey(path, false); }
    private static byte[] Bytes(object? value) => value switch { null => [], byte[] x => x, string x => Encoding.UTF8.GetBytes(x), string[] x => Encoding.UTF8.GetBytes(string.Join('\0', x)), int x => BitConverter.GetBytes(x), long x => BitConverter.GetBytes(x), _ => Encoding.UTF8.GetBytes(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "") };
    private static string Classification(string kind) => kind switch { "Binary" => "binary", "DWord" or "QWord" => "numeric", _ => "string" }; private static string EncodingName(string kind) => kind == "Binary" ? "binary" : kind is "DWord" or "QWord" ? "little-endian" : "utf-8";
    private static bool Wildcard(string value, string pattern) { if (pattern == "*") return true; var parts = pattern.Split('*'); var at = 0; foreach (var part in parts) { if (part.Length == 0) continue; at = value.IndexOf(part, at, StringComparison.OrdinalIgnoreCase); if (at < 0) return false; at += part.Length; } return true; }
    private static void Protect(string path) { if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
    public async ValueTask DisposeAsync() => await _collector.DisposeAsync();
}
