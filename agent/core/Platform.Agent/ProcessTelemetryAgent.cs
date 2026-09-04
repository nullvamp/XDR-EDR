using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

sealed record ProcessCollectorHealth(
    string State,
    DateTimeOffset? LastSourceEvent,
    long SourceEvents,
    long StartEvents,
    long ExitEvents,
    long ParseErrors,
    long CollectionErrors,
    long LostEvents,
    long SequenceGaps,
    long RestartCount,
    string? Error
);

static class LocalTestFailpoint
{
    public static void Hit(string name, string environment)
    {
        if (environment == "production")
            return;
        if (
            !string.Equals(
                Environment.GetEnvironmentVariable("PLATFORM_LOCAL_TEST_FAILPOINT"),
                name,
                StringComparison.Ordinal
            )
        )
            return;
        var marker = Environment.GetEnvironmentVariable("PLATFORM_LOCAL_TEST_FAILPOINT_MARKER");
        if (!string.IsNullOrWhiteSpace(marker))
        {
            using var file = new FileStream(
                marker,
                FileMode.Create,
                FileAccess.Write,
                FileShare.Read
            );
            using var writer = new StreamWriter(file, leaveOpen: true);
            writer.Write($"{name}|{DateTimeOffset.UtcNow:O}");
            writer.Flush();
            file.Flush(true);
        }
        Environment.FailFast($"Local deterministic test failpoint reached: {name}");
    }
}

interface IProcessCollector : IAsyncDisposable
{
    string Type { get; }
    string Version { get; }
    string Platform { get; }
    string SourceType { get; }
    string[] Capabilities { get; }
    ProcessCollectorHealth Health { get; }
    Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    Task UpdatePolicyAsync(ProcessTelemetryPolicy policy, CancellationToken cancellationToken) =>
        Task.CompletedTask;
    Task<IReadOnlyList<NativeProcessEvent>> PollAsync(CancellationToken cancellationToken);
    object DiagnosticSummary() => Health;
    ValueTask IAsyncDisposable.DisposeAsync() => ValueTask.CompletedTask;
}

sealed record NativeProcessEvent(
    ProcessEventKind Kind,
    int Pid,
    int? ParentPid,
    DateTimeOffset StartTime,
    DateTimeOffset ObservedAt,
    string StartKey,
    string? Name,
    string? Path,
    string? CommandLine,
    string? UserId,
    string? SessionId,
    string? ContainerId,
    DateTimeOffset? ExitTime,
    int? ExitCode,
    string? Error,
    string? NativeSourceEventId = null,
    long? NativeSequence = null,
    long LostEvents = 0
);

sealed class LinuxProcfsProcessCollector : IProcessCollector
{
    sealed record Snapshot(
        int Pid,
        int? ParentPid,
        long StartTicks,
        DateTimeOffset StartTime,
        string? Name,
        string? Path,
        string? CommandLine,
        string? UserId,
        string? SessionId,
        string? ContainerId
    );

    private Dictionary<int, Snapshot>? _previous;
    private readonly long _clockTicks = 100;
    private readonly DateTimeOffset _boot =
        DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
    public string Type => "linux.procfs";
    public string Version => "1.0.0";
    public string Platform => "linux";
    public string SourceType => "evaluation-polling";
    public string[] Capabilities => ["process.start", "process.exit", "evaluation-only"];
    public ProcessCollectorHealth Health { get; private set; } =
        new("starting", null, 0, 0, 0, 0, 0, 0, 0, 0, null);

    public Task<IReadOnlyList<NativeProcessEvent>> PollAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var current = new Dictionary<int, Snapshot>();
        foreach (var directory in Directory.EnumerateDirectories("/proc"))
        {
            ct.ThrowIfCancellationRequested();
            if (!int.TryParse(Path.GetFileName(directory), out var pid))
                continue;
            try
            {
                var stat = File.ReadAllText(Path.Combine(directory, "stat"));
                var close = stat.LastIndexOf(')');
                if (close < 0)
                    continue;
                var name = stat[(stat.IndexOf('(') + 1)..close];
                var fields = stat[(close + 2)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var ppid = int.Parse(fields[1], System.Globalization.CultureInfo.InvariantCulture);
                var session = fields[3];
                var startTicks = long.Parse(
                    fields[19],
                    System.Globalization.CultureInfo.InvariantCulture
                );
                var start = _boot.AddSeconds((double)startTicks / _clockTicks);
                var path = Link(Path.Combine(directory, "exe"));
                var command = ReadNullSeparated(Path.Combine(directory, "cmdline"));
                var status = File.ReadAllLines(Path.Combine(directory, "status"));
                var uid = status
                    .FirstOrDefault(x => x.StartsWith("Uid:", StringComparison.Ordinal))
                    ?.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
                    .ElementAtOrDefault(1);
                var cgroupPath = Path.Combine(directory, "cgroup");
                var cgroup = File.Exists(cgroupPath) ? File.ReadAllText(cgroupPath) : null;
                var container = cgroup is null
                    ? null
                    : cgroup
                        .Split('/', StringSplitOptions.RemoveEmptyEntries)
                        .LastOrDefault(x => x.Length >= 12);
                current[pid] = new(
                    pid,
                    ppid > 0 ? ppid : null,
                    startTicks,
                    start,
                    name,
                    path,
                    command,
                    uid,
                    session,
                    container
                );
            }
            catch (Exception e)
                when (e
                        is IOException
                            or UnauthorizedAccessException
                            or FormatException
                            or ArgumentException
                )
            {
                // A process may exit while procfs metadata is being read.
            }
        }
        var events = new List<NativeProcessEvent>();
        if (_previous is not null)
        {
            foreach (
                var item in current.Values.Where(x =>
                    !_previous.TryGetValue(x.Pid, out var old) || old.StartTicks != x.StartTicks
                )
            )
                events.Add(
                    new(
                        ProcessEventKind.Started,
                        item.Pid,
                        item.ParentPid,
                        item.StartTime,
                        now,
                        item.StartTicks.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        item.Name,
                        item.Path,
                        item.CommandLine,
                        item.UserId,
                        item.SessionId,
                        item.ContainerId,
                        null,
                        null,
                        null
                    )
                );
            foreach (
                var item in _previous.Values.Where(x =>
                    !current.TryGetValue(x.Pid, out var next) || next.StartTicks != x.StartTicks
                )
            )
                events.Add(
                    new(
                        ProcessEventKind.Exited,
                        item.Pid,
                        item.ParentPid,
                        item.StartTime,
                        now,
                        item.StartTicks.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        item.Name,
                        item.Path,
                        item.CommandLine,
                        item.UserId,
                        item.SessionId,
                        item.ContainerId,
                        now,
                        null,
                        null
                    )
                );
        }
        _previous = current;
        Health = Health with
        {
            State = "healthy-evaluation",
            LastSourceEvent = events.Count == 0 ? Health.LastSourceEvent : now,
            SourceEvents = Health.SourceEvents + events.Count,
            StartEvents =
                Health.StartEvents + events.Count(x => x.Kind == ProcessEventKind.Started),
            ExitEvents = Health.ExitEvents + events.Count(x => x.Kind == ProcessEventKind.Exited),
        };
        return Task.FromResult<IReadOnlyList<NativeProcessEvent>>(events);
    }

    private static string? Link(string path)
    {
        try
        {
            return File.ResolveLinkTarget(path, false)?.FullName;
        }
        catch
        {
            return null;
        }
    }

    private static string? ReadNullSeparated(string path)
    {
        try
        {
            var value = File.ReadAllText(path).Replace('\0', ' ').Trim();
            return value.Length == 0 ? null : value[..Math.Min(value.Length, 32768)];
        }
        catch
        {
            return null;
        }
    }
}

sealed class UnsupportedProcessCollector(string type) : IProcessCollector
{
    public string Type => type;
    public string Version => "build-only-1.0.0";
    public string Platform => type.Split('.')[0];
    public string SourceType => "unavailable";
    public string[] Capabilities => ["build-only"];
    public ProcessCollectorHealth Health =>
        new("unsupported", null, 0, 0, 0, 0, 0, 0, 0, 0, "Native collector unavailable.");

    public Task<IReadOnlyList<NativeProcessEvent>> PollAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<NativeProcessEvent>>([]);
}

sealed class DurableProcessQueue
{
    private readonly string _directory;
    private ProcessTelemetryPolicy _policy;
    private long _dropped;
    private string? _dropReason;
    private readonly string _environment;

    public DurableProcessQueue(
        string dataDirectory,
        ProcessTelemetryPolicy policy,
        string environment
    )
    {
        _directory = Path.Combine(dataDirectory, "process-queue");
        _policy = policy;
        _environment = environment;
        Directory.CreateDirectory(_directory);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                _directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            );
        }
        Recover();
    }

    public long Dropped => Interlocked.Read(ref _dropped);
    public string? DropReason => _dropReason;
    public long HighestSequence =>
        Directory
            .EnumerateFiles(_directory, "*.json")
            .Select(Path.GetFileNameWithoutExtension)
            .Select(x => long.TryParse(x?.Split('-', 2)[0], out var sequence) ? sequence : 0)
            .DefaultIfEmpty()
            .Max();

    public void UpdatePolicy(ProcessTelemetryPolicy policy) => _policy = policy;

    public async Task EnqueueAsync(ProcessObservation item, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(item);
        if (bytes.Length > 256 * 1024)
        {
            Drop("event-too-large");
            return;
        }
        Prune();
        if (Size() + bytes.Length > _policy.MaximumQueueBytes)
        {
            Drop("queue-capacity");
            return;
        }
        var path = Path.Combine(_directory, $"{item.Sequence:D20}-{item.EventId:N}.json");
        var temp = path + ".tmp";
        try
        {
            await using (
                var stream = new FileStream(
                    temp,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    81920,
                    FileOptions.Asynchronous | FileOptions.WriteThrough
                )
            )
            {
                await stream.WriteAsync(bytes, ct);
                await stream.FlushAsync(ct);
                stream.Flush(true);
            }
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            LocalTestFailpoint.Hit("queue-before-rename", _environment);
            if (
                _environment != "production"
                && Environment.GetEnvironmentVariable("PLATFORM_LOCAL_TEST_FAILPOINT")
                    == "queue-rename-boundary"
            )
            {
                File.Move(temp, path + ".committing");
                LocalTestFailpoint.Hit("queue-rename-boundary", _environment);
            }
            File.Move(temp, path);
            LocalTestFailpoint.Hit("queue-after-rename", _environment);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            TryDelete(temp);
            Drop(e is UnauthorizedAccessException ? "queue-read-only" : "queue-write-failed");
        }
    }

    public async Task<
        IReadOnlyList<(string Path, ProcessObservation Event, int Bytes)>
    > ReadBatchAsync(CancellationToken ct)
    {
        var values = new List<(string, ProcessObservation, int)>();
        var bytes = 0;
        foreach (
            var path in Directory
                .EnumerateFiles(_directory, "*.json")
                .OrderBy(x => x, StringComparer.Ordinal)
        )
        {
            try
            {
                var data = await File.ReadAllBytesAsync(path, ct);
                if (
                    data.Length + bytes > _policy.MaximumBatchBytes
                    || values.Count >= _policy.MaximumBatchEvents
                )
                    break;
                var item =
                    JsonSerializer.Deserialize<ProcessObservation>(data)
                    ?? throw new JsonException();
                values.Add((path, item, data.Length));
                bytes += data.Length;
            }
            catch (Exception e) when (e is IOException or JsonException)
            {
                File.Move(path, path + ".corrupt", true);
                Drop("queue-corrupt");
            }
        }
        return values;
    }

    public static void Acknowledge(IEnumerable<string> paths)
    {
        foreach (var path in paths)
            TryDelete(path);
    }

    public (long Depth, long Bytes, long OldestAge) Status()
    {
        var files = Directory
            .EnumerateFiles(_directory, "*.json")
            .Select(x => new FileInfo(x))
            .ToArray();
        return (
            files.LongLength,
            files.Sum(x => x.Length),
            files.Length == 0
                ? 0
                : (long)
                    Math.Max(
                        0,
                        (DateTimeOffset.UtcNow - files.Min(x => x.CreationTimeUtc)).TotalSeconds
                    )
        );
    }

    private void Recover()
    {
        foreach (
            var temp in Directory
                .EnumerateFiles(_directory)
                .Where(x =>
                    x.EndsWith(".tmp", StringComparison.Ordinal)
                    || x.EndsWith(".committing", StringComparison.Ordinal)
                )
        )
            RecoverTemporary(temp);
        Prune();
    }

    private void RecoverTemporary(string temporary)
    {
        try
        {
            var bytes = File.ReadAllBytes(temporary);
            _ = JsonSerializer.Deserialize<ProcessObservation>(bytes) ?? throw new JsonException();
            var final = temporary.EndsWith(".committing", StringComparison.Ordinal)
                ? temporary[..^".committing".Length]
                : temporary[..^".tmp".Length];
            if (File.Exists(final))
                TryDelete(temporary);
            else
                File.Move(temporary, final);
        }
        catch (Exception e) when (e is IOException or JsonException)
        {
            File.Move(temporary, temporary + ".corrupt", true);
            Drop("queue-recovery-corrupt");
        }
    }

    private void Prune()
    {
        var cutoff = DateTimeOffset.UtcNow.AddHours(-_policy.MaximumEventAgeHours);
        foreach (
            var file in Directory
                .EnumerateFiles(_directory, "*.json")
                .Select(x => new FileInfo(x))
                .Where(x => x.CreationTimeUtc < cutoff)
        )
        {
            TryDelete(file.FullName);
            Drop("maximum-age");
        }
    }

    private long Size() =>
        Directory.EnumerateFiles(_directory, "*.json").Sum(x => new FileInfo(x).Length);

    private void Drop(string reason)
    {
        Interlocked.Increment(ref _dropped);
        _dropReason = reason;
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch { }
    }
}

sealed class ProcessTelemetryPipeline
{
    private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web);
    private ProcessTelemetryPolicy _policy = new();
    private readonly IProcessCollector _collector;
    private readonly DurableProcessQueue _queue;
    private readonly Dictionary<int, (string EntityId, DateTimeOffset Start)> _active = [];
    private long _sequence;
    private DateTimeOffset _lastUpload = DateTimeOffset.MinValue;
    private string _uploadResult = "not-attempted";
    private bool _started;
    private int _collectorStartFailures;
    private DateTimeOffset _nextCollectorStart = DateTimeOffset.MinValue;
    private long _excluded;
    private ProcessExclusionRule? _lastExclusion;
    private DateTimeOffset? _lastExclusionAt;
    private string _appliedPolicyKey = "";
    private readonly string _environment;

    public ProcessTelemetryPipeline(AgentOptions options, long sequence)
    {
        _collector = string.Equals(Environment.GetEnvironmentVariable("PLATFORM_TELEMETRY_DRAIN_ONLY"), "true", StringComparison.OrdinalIgnoreCase)
            ? new UnsupportedProcessCollector("drain-only")
            : ProcessCollectorFactory.Create(options);
        _queue = new(options.DataDirectory, _policy, options.Environment);
        _environment = options.Environment;
        _sequence = Math.Max(sequence, _queue.HighestSequence);
        _collector.StartAsync(default).GetAwaiter().GetResult();
        _started = _collector.Health.State == "healthy";
    }

    public string[] Capabilities() =>
        [
            $"process.start.v1:{_collector.Type}",
            $"process.exit.v1:{_collector.Type}",
            $"process.metadata.hash:{_policy.HashingEnabled.ToString().ToLowerInvariant()}",
            $"process.metadata.signature:{_policy.SignatureEnabled.ToString().ToLowerInvariant()}",
        ];

    public string CurrentPolicyKey => _appliedPolicyKey;
    public ProcessCollectorHealth CollectorHealth =>
        !_policy.TelemetryEnabled
            ? _collector.Health with
            {
                State = "policy-disabled",
                Error = null,
            }
            : _collector.Health;
    public (long Depth, long Bytes, long OldestAge) QueueStatus => _queue.Status();

    public async Task<IReadOnlyDictionary<string, string[]>> ApplyPolicyAsync(
        ProcessTelemetryPolicy policy,
        Guid policyId,
        int version,
        CancellationToken ct
    )
    {
        var errors = ProcessPolicyValidation
            .Validate(policy)
            .ToDictionary(item => item.Key, item => item.Value);
        var requestedSource = policy.CollectorSource.Trim().ToLowerInvariant();
        var compatibleSource = requestedSource switch
        {
            "auto" => true,
            "etw" or "windows.etw" => _collector.Type.StartsWith(
                "windows.etw",
                StringComparison.Ordinal
            ),
            "falco" or "linux.falco-json" => _collector.Type == "linux.falco-json",
            "procfs" or "linux.procfs" => _collector.Type == "linux.procfs",
            "endpoint-security" or "macos.endpoint-security" => _collector.Type
                == "macos.endpoint-security",
            _ => false,
        };
        if (!compatibleSource)
            errors["collectorSource"] =
            [
                $"Collector source '{policy.CollectorSource}' is incompatible with active collector '{_collector.Type}'.",
            ];
        if (errors.Count != 0)
            return errors;
        if (_policy.TelemetryEnabled && !policy.TelemetryEnabled && _started)
        {
            await _collector.StopAsync(ct);
            _started = false;
        }
        _policy = policy;
        _queue.UpdatePolicy(policy);
        _appliedPolicyKey = $"{policyId:D}:{version}";
        return errors;
    }

    public async Task<long> RunOnceAsync(
        AgentState state,
        Func<AgentState, HttpClient> authenticatedClient,
        Func<long, CancellationToken, Task> checkpointSequence,
        CancellationToken ct
    )
    {
        if (_policy.TelemetryEnabled && !_started && DateTimeOffset.UtcNow >= _nextCollectorStart)
        {
            await _collector.StartAsync(ct);
            if (_collector.Health.State == "healthy")
            {
                await _collector.UpdatePolicyAsync(_policy, ct);
                _started = true;
                _collectorStartFailures = 0;
            }
            else
            {
                _collectorStartFailures = Math.Min(_collectorStartFailures + 1, 6);
                _nextCollectorStart = DateTimeOffset.UtcNow.AddSeconds(
                    Math.Min(60, Math.Pow(2, _collectorStartFailures))
                );
            }
        }
        var native = _policy.TelemetryEnabled
            ? await _collector.PollAsync(ct)
            : Array.Empty<NativeProcessEvent>();
        foreach (var item in native)
        {
            if (
                !_policy.TelemetryEnabled
                || item.Kind == ProcessEventKind.Started && !_policy.StartEnabled
                || item.Kind == ProcessEventKind.Exited && !_policy.ExitEnabled
            )
                continue;
            if (Excluded(item, out var exclusion))
            {
                Interlocked.Increment(ref _excluded);
                _lastExclusion = exclusion;
                _lastExclusionAt = DateTimeOffset.UtcNow;
                continue;
            }
            var entity = ProcessIdentity.Create(
                state.EndpointId,
                item.Pid,
                item.StartTime,
                item.StartKey
            );
            string? parentEntity = null;
            var lineage = LineageState.ParentNotObserved;
            if (
                item.ParentPid is { } parent
                && _active.TryGetValue(parent, out var known)
                && known.Start <= item.StartTime
            )
            {
                parentEntity = known.EntityId;
                lineage = LineageState.Resolved;
            }
            if (item.Kind == ProcessEventKind.Started)
                _active[item.Pid] = (entity, item.StartTime);
            else
                _active.Remove(item.Pid);
            var quality = new List<string>();
            if (!string.IsNullOrWhiteSpace(item.Error))
                quality.Add(item.Error);
            if (item.Path is null)
                quality.Add("executable-path-unavailable");
            if (parentEntity is null)
                quality.Add("parent-not-observed");
            var metadata = await Metadata(item.Path, ct);
            var observation = new ProcessObservation(
                Guid.NewGuid(),
                item.Kind,
                "process.event.v1",
                state.EndpointId,
                state.AgentId,
                state.InstallationId,
                $"{_collector.Type}:{Environment.MachineName}",
                _collector.Type,
                _collector.Version,
                OperatingSystem.IsLinux() ? "linux"
                    : OperatingSystem.IsWindows() ? "windows"
                    : "macos",
                item.NativeSourceEventId ?? item.StartKey,
                item.ObservedAt,
                Interlocked.Increment(ref _sequence),
                Guid.NewGuid().ToString("N"),
                Activity.Current?.TraceId.ToString(),
                null,
                "process.normalize.v1",
                quality.ToArray(),
                item.Pid,
                item.StartTime,
                entity,
                item.ParentPid,
                parentEntity,
                lineage,
                null,
                null,
                null,
                null,
                item.Name,
                item.Path,
                _policy.CommandLineEnabled ? Redact(item.CommandLine) : null,
                null,
                _policy.UserEnabled ? item.UserId : null,
                null,
                _policy.UserEnabled ? item.UserId : null,
                item.SessionId,
                null,
                null,
                null,
                System
                    .Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString()
                    .ToLowerInvariant(),
                _policy.ContainerMetadataEnabled ? item.ContainerId : null,
                null,
                metadata,
                item.ExitTime,
                item.ExitCode,
                item.ExitTime is null
                    ? null
                    : (long?)(item.ExitTime.Value - item.StartTime).TotalMilliseconds,
                null,
                item.Kind == ProcessEventKind.Exited ? "observed-exit" : null
            );
            await _queue.EnqueueAsync(observation, ct);
        }
        if (_sequence != state.ProcessSequence)
            await checkpointSequence(_sequence, ct);
        if (DateTimeOffset.UtcNow - _lastUpload >= TimeSpan.FromSeconds(_policy.FlushSeconds))
            await Upload(state, authenticatedClient, ct);
        return _sequence;
    }

    private async Task Upload(
        AgentState state,
        Func<AgentState, HttpClient> authenticatedClient,
        CancellationToken ct
    )
    {
        var items = await _queue.ReadBatchAsync(ct);
        if (items.Count == 0)
            return;
        LocalTestFailpoint.Hit("batch-after-read", _environment);
        var events = items.Select(x => x.Event).ToArray();
        var eventBytes = JsonSerializer.SerializeToUtf8Bytes(events, WireJson);
        var batch = new ProcessEventBatch(
            Guid.NewGuid(),
            "1.2",
            state.EndpointId,
            state.AgentId,
            state.InstallationId,
            events.Min(x => x.Sequence),
            events.Max(x => x.Sequence),
            "gzip",
            "pending",
            DateTimeOffset.UtcNow,
            events
        );
        var canonicalBatch = batch with
        {
            ContentSha256 = Convert.ToHexString(SHA256.HashData(eventBytes)).ToLowerInvariant(),
        };
        var json = JsonSerializer.SerializeToUtf8Bytes(canonicalBatch, WireJson);
        LocalTestFailpoint.Hit("batch-after-canonical", _environment);
        await using var compressed = new MemoryStream();
        await using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, true))
        {
            var threshold = int.TryParse(
                Environment.GetEnvironmentVariable("PLATFORM_LOCAL_TEST_COMPRESSION_BYTES"),
                out var configuredThreshold
            )
                ? Math.Max(1, configuredThreshold)
                : 1024;
            for (var offset = 0; offset < json.Length; offset += 1024)
            {
                var length = Math.Min(1024, json.Length - offset);
                await gzip.WriteAsync(json.AsMemory(offset, length), ct);
                if (offset + length >= threshold)
                    LocalTestFailpoint.Hit("batch-during-compression", _environment);
            }
        }
        LocalTestFailpoint.Hit("batch-after-compression", _environment);
        LocalTestFailpoint.Hit("batch-after-integrity", _environment);
        if (compressed.Length > 1024 * 1024)
        {
            _uploadResult = "compressed-batch-too-large";
            return;
        }
        using var client = authenticatedClient(state);
        using var content = new ByteArrayContent(compressed.ToArray());
        content.Headers.ContentType = new("application/json");
        content.Headers.ContentEncoding.Add("gzip");
        content.Headers.Add(
            "X-Uncompressed-Length",
            json.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)
        );
        var status = _queue.Status();
        content.Headers.Add(
            "X-Queue-Depth",
            status.Depth.ToString(System.Globalization.CultureInfo.InvariantCulture)
        );
        content.Headers.Add(
            "X-Queue-Oldest-Age",
            status.OldestAge.ToString(System.Globalization.CultureInfo.InvariantCulture)
        );
        content.Headers.Add(
            "X-Dropped-Events",
            _queue.Dropped.ToString(System.Globalization.CultureInfo.InvariantCulture)
        );
        content.Headers.Add(
            "X-Excluded-Events",
            _excluded.ToString(System.Globalization.CultureInfo.InvariantCulture)
        );
        content.Headers.Add("X-Policy-Version", _policy.Version);
        if (_lastExclusion is not null)
        {
            content.Headers.Add("X-Exclusion-Rule", _lastExclusion.Id.ToString("D"));
            content.Headers.Add("X-Exclusion-Category", _lastExclusion.Category);
            content.Headers.Add("X-Exclusion-At", _lastExclusionAt?.ToString("O"));
        }
        if (_queue.DropReason is not null)
            content.Headers.Add("X-Drop-Reason", _queue.DropReason);
        using var response = await client.PostAsync("/agent/v1/process-event-batches", content, ct);
        if (!response.IsSuccessStatusCode)
        {
            _uploadResult = $"http-{(int)response.StatusCode}";
            var responseBody = await response.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException(
                $"Process telemetry upload returned {(int)response.StatusCode}: {responseBody[..Math.Min(responseBody.Length, 512)]}",
                null,
                response.StatusCode
            );
        }
        LocalTestFailpoint.Hit("batch-after-transport-before-ack", _environment);
        var ack =
            await response.Content.ReadFromJsonAsync<ProcessBatchAcknowledgement>(
                cancellationToken: ct
            ) ?? throw new InvalidDataException("Process batch acknowledgement is invalid.");
        var cleared = ack.Accepted.Concat(ack.Duplicates).ToHashSet();
        DurableProcessQueue.Acknowledge(
            items.Where(x => cleared.Contains(x.Event.EventId)).Select(x => x.Path)
        );
        _lastUpload = DateTimeOffset.UtcNow;
        _uploadResult = "accepted";
    }

    private async Task<ProcessExecutableMetadata?> Metadata(string? path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;
        var started = Stopwatch.GetTimestamp();
        try
        {
            var file = new FileInfo(path);
            string? hash = null;
            var hashOutcome = "disabled";
            if (_policy.HashingEnabled && file.Exists && file.Length <= 128 * 1024 * 1024)
            {
                await using var stream = file.OpenRead();
                hash = Convert
                    .ToHexString(await SHA256.HashDataAsync(stream, ct))
                    .ToLowerInvariant();
                hashOutcome = "success";
            }
            return new(
                file.Name,
                file.FullName,
                file.Exists ? file.Length : null,
                file.Exists ? file.LastWriteTimeUtc : null,
                hash,
                ProcessSignatureState.NotChecked,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                hashOutcome,
                "disabled",
                Stopwatch.GetElapsedTime(started).TotalMilliseconds,
                file.Exists ? null : "not-found"
            );
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new(
                Path.GetFileName(path),
                path,
                null,
                null,
                null,
                ProcessSignatureState.Error,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                "error",
                "error",
                Stopwatch.GetElapsedTime(started).TotalMilliseconds,
                e is UnauthorizedAccessException ? "permission-denied" : "io-error"
            );
        }
    }

    private static string? Redact(string? command)
    {
        if (command is null)
            return null;
        var value = command[..Math.Min(command.Length, 32768)];
        foreach (var marker in new[] { "--password=", "--token=", "--secret=" })
        {
            var index = value.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                var end = value.IndexOf(' ', index);
                if (end < 0)
                    end = value.Length;
                value = value[..(index + marker.Length)] + "[REDACTED]" + value[end..];
            }
        }
        return value;
    }

    private bool Excluded(NativeProcessEvent item, out ProcessExclusionRule? matched)
    {
        foreach (var rule in _policy.ExclusionRules?.Where(x => x.Enabled) ?? [])
        {
            var value = rule.Category switch
            {
                "name" => item.Name,
                "path" => item.Path,
                "user" => item.UserId,
                "container" => item.ContainerId,
                _ => null,
            };
            if (
                value is not null
                && System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(
                    rule.Pattern,
                    value,
                    OperatingSystem.IsWindows()
                )
            )
            {
                matched = rule;
                return true;
            }
        }
        matched = null;
        return false;
    }
}
