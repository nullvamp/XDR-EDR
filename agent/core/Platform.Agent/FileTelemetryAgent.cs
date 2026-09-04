using System.Collections.Concurrent;
using System.Globalization;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using OpenSecurityPlatform.Foundation;

sealed record NativeFileEvent(
    FileEventKind Kind,
    string Path,
    string? PreviousPath,
    string? DestinationPath,
    string? FileId,
    long? DeviceId,
    long? Inode,
    int? ProcessId,
    string? ProcessName,
    string? ProcessPath,
    string? UserId,
    string? ContainerId,
    DateTimeOffset ObservedAt,
    string SourceEventId,
    string NativeOperation,
    string? Outcome,
    long NativeSequence
);

interface IFileCollector : IAsyncDisposable
{
    string Type { get; }
    string Version { get; }
    string Platform { get; }
    long LostEvents { get; }
    string State { get; }
    string? Error { get; }
    Task StartAsync(CancellationToken ct);
    Task<IReadOnlyList<NativeFileEvent>> PollAsync(CancellationToken ct);
    void AcknowledgePersisted(string sourceEventId) { }
    Task StopAsync(CancellationToken ct);
}

static class FileCollectorFactory
{
    public static IFileCollector Create(AgentOptions options)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("PLATFORM_TELEMETRY_DRAIN_ONLY"), "true", StringComparison.OrdinalIgnoreCase)) return new UnsupportedFileCollector();
        var localTestPath = Environment.GetEnvironmentVariable(
            "PLATFORM_LOCAL_TEST_FILE_EVENT_PATH"
        );
        if (options.Environment != "production" && !string.IsNullOrWhiteSpace(localTestPath))
            return new LocalTestFileCollector(localTestPath, options.DataDirectory);
        return OperatingSystem.IsWindows() ? new WindowsEtwFileCollector(options.DataDirectory)
        : OperatingSystem.IsLinux()
            ? new LinuxFalcoFileCollector(
                Environment.GetEnvironmentVariable("PLATFORM_FALCO_JSON_PATH")
                    ?? "/var/run/platform-falco/process-events.jsonl"
            )
        : new UnsupportedFileCollector();
    }
}

sealed class LocalTestFileCollector(string path, string dataDirectory) : IFileCollector
{
    readonly string _sourceId = $"local-test:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path))).ToLowerInvariant()}";
    readonly string _marker = Path.Combine(dataDirectory, "local-test-file-emitted");
    public string Type => "linux.falco-json";
    public string Version => "local-test-only";
    public string Platform => "local-test";
    public long LostEvents => 0;
    public string State { get; private set; } = "stopped";
    public string? Error => null;

    public Task StartAsync(CancellationToken ct)
    {
        State = "healthy";
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<NativeFileEvent>> PollAsync(CancellationToken ct)
    {
        if (File.Exists(_marker))
            return Task.FromResult<IReadOnlyList<NativeFileEvent>>([]);
        var queue = Path.Combine(dataDirectory, "file-queue");
        if (
            Directory.Exists(queue)
            && Directory.EnumerateFiles(queue, "*.json").Any(file =>
            {
                try
                {
                    return File.ReadAllText(file).Contains(_sourceId, StringComparison.Ordinal);
                }
                catch (IOException)
                {
                    return false;
                }
            })
        )
        {
            File.WriteAllText(_marker, _sourceId);
            return Task.FromResult<IReadOnlyList<NativeFileEvent>>([]);
        }
        var info = new FileInfo(path);
        return Task.FromResult<IReadOnlyList<NativeFileEvent>>(
            [
                new(
                    FileEventKind.Created,
                    path,
                    null,
                    null,
                    null,
                    null,
                    null,
                    Environment.ProcessId,
                    "Platform.Agent",
                    Environment.ProcessPath,
                    Environment.UserName,
                    null,
                    DateTimeOffset.UtcNow,
                    _sourceId,
                    "local-test-create",
                    info.Exists ? "success" : "not-found",
                    1
                ),
            ]
        );
    }

    public Task StopAsync(CancellationToken ct)
    {
        State = "stopped";
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    public void AcknowledgePersisted(string sourceEventId)
    {
        if (sourceEventId == _sourceId)
            File.WriteAllText(_marker, _sourceId);
    }
}

sealed class UnsupportedFileCollector : IFileCollector
{
    public string Type => "unsupported";
    public string Version => "0";
    public string Platform => "unknown";
    public long LostEvents => 0;
    public string State => "unsupported";
    public string? Error => "File collection is unsupported.";

    public Task StartAsync(CancellationToken ct) => Task.CompletedTask;

    public Task<IReadOnlyList<NativeFileEvent>> PollAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<NativeFileEvent>>([]);

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

sealed class WindowsEtwFileCollector(string dataDirectory) : IFileCollector
{
    const string SessionName = "OpenSecurityPlatform-FileLifecycle-v1";
    // File ETW is extremely bursty during inventories and response work. These
    // caps intentionally prefer explicit source-gap accounting over exhausting
    // memory on small endpoints.
    const int MaximumBufferedNativeEvents = 10_000;
    const int MaximumTrackedFileObjects = 25_000;
    readonly ConcurrentQueue<NativeFileEvent> _events = new();
    readonly ConcurrentDictionary<ulong, string> _paths = new();
    readonly ConcurrentDictionary<ulong, string> _previousPaths = new();
    readonly ConcurrentDictionary<ulong, string> _identities = new();
    readonly string _owner = Path.Combine(dataDirectory, "etw-file-session-owner.json");
    TraceEventSession? _session;
    Task? _reader;
    long _native;
    long _queued;
    long _overflow;
    public string Type => "windows.etw-file";
    public string Version => "1.0.0";
    public string Platform => "windows";
    public long LostEvents
    {
        get
        {
            try
            {
                return (_session?.EventsLost ?? 0) + Interlocked.Read(ref _overflow);
            }
            catch
            {
                return Interlocked.Read(ref _overflow);
            }
        }
    }
    public string State { get; private set; } = "stopped";
    public string? Error { get; private set; }

    public Task StartAsync(CancellationToken ct)
    {
        try
        {
            if (
                TraceEventSession
                    .GetActiveSessionNames()
                    .Contains(SessionName, StringComparer.Ordinal)
            )
            {
                if (!OwnedStale())
                    throw new InvalidOperationException(
                        "ETW file session-name conflict is not demonstrably platform-owned."
                    );
                using var stale = new TraceEventSession(SessionName);
                stale.Stop();
            }
            _session = new TraceEventSession(SessionName)
            {
                StopOnDispose = true,
                BufferSizeMB = 64,
            };
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.FileIO
                    | KernelTraceEventParser.Keywords.FileIOInit
            );
            var parser = new KernelTraceEventParser(
                _session.Source,
                KernelTraceEventParser.ParserTrackingOptions.None
            );
            parser.FileIOFileCreate += d => SafeCallback(() => Name(d.FileKey, d.FileName));
            parser.FileIODelete += d => SafeCallback(() =>
            {
                Emit(
                    FileEventKind.Deleted,
                    d.FileName,
                    d.FileKey,
                    d.ProcessID,
                    "delete",
                    d.FileObject
                );
                Forget(d.FileKey);
                Forget(d.FileObject);
            });
            parser.FileIOCreate += d => SafeCallback(() => Create(d));
            parser.FileIOWrite += d => SafeCallback(() =>
                Emit(
                    FileEventKind.Modified,
                    d.FileName,
                    d.FileKey,
                    d.ProcessID,
                    "write",
                    d.FileObject
                ));
            parser.FileIORename += d => SafeCallback(() =>
                Rename(d.FileName, d.FileKey, d.FileObject, d.ProcessID));
            parser.FileIOSetInfo += d => SafeCallback(() =>
                Emit(
                    (int)d.InfoClass is 13 or 64
                        ? FileEventKind.Deleted
                        : FileEventKind.MetadataChanged,
                    d.FileName,
                    d.FileKey,
                    d.ProcessID,
                    (int)d.InfoClass is 13 or 64
                        ? "delete-disposition"
                        : $"set-info:{(int)d.InfoClass}",
                    d.FileObject
                ));
            parser.FileIOCleanup += d => SafeCallback(() => Forget(d.FileObject));
            parser.FileIOClose += d => SafeCallback(() => Forget(d.FileObject));
            _reader = Task.Run(() => _session.Source.Process(), CancellationToken.None);
            WriteOwner();
            State = "healthy";
        }
        catch (Exception e)
        {
            State = "failed";
            Error = $"{e.GetType().Name}: {e.Message}";
        }
        return Task.CompletedTask;
    }

    void SafeCallback(Action callback)
    {
        try { callback(); }
        catch (Exception e)
            when (e is not (OutOfMemoryException or StackOverflowException or AccessViolationException))
        {
            Error = $"event-callback:{e.GetType().Name}";
        }
    }

    void Name(ulong key, string path)
    {
        if (!string.IsNullOrWhiteSpace(path))
            RememberPath(key, path);
    }

    void Create(FileIOCreateTraceData data)
    {
        var path = data.FileName;
        if (string.IsNullOrWhiteSpace(path))
            path = _paths.GetValueOrDefault(data.FileObject) ?? "<unavailable>";
        if (path != "<unavailable>")
            RememberPath(data.FileObject, path);
        var created = (int)data.CreateDisposition == 2;
        Emit(
            created ? FileEventKind.Created : FileEventKind.Opened,
            path,
            data.FileObject,
            data.ProcessID,
            created ? "create" : "open"
        );
    }

    void Rename(string path, ulong key, ulong alternateKey, int pid)
    {
        var current = string.IsNullOrWhiteSpace(path)
            ? _paths.GetValueOrDefault(key) ?? _paths.GetValueOrDefault(alternateKey)
            : path;
        _previousPaths.TryRemove(key, out var previous);
        if (previous is null)
            _previousPaths.TryRemove(alternateKey, out previous);
        previous ??= _paths.GetValueOrDefault(key) ?? _paths.GetValueOrDefault(alternateKey);
        if (string.IsNullOrWhiteSpace(current))
            current = previous ?? "<unavailable>";
        if (current != "<unavailable>")
        {
            RememberPath(key, current);
            RememberPath(alternateKey, current);
        }
        var kind =
            previous is not null
                && Path.GetDirectoryName(previous) != Path.GetDirectoryName(current)
                ? FileEventKind.Moved
                : FileEventKind.Renamed;
        Enqueue(kind, current, previous, current, key, pid, "rename");
    }

    void Emit(
        FileEventKind kind,
        string path,
        ulong key,
        int pid,
        string op,
        ulong alternateKey = 0
    )
    {
        if (string.IsNullOrWhiteSpace(path))
            path =
                _paths.GetValueOrDefault(key)
                ?? _paths.GetValueOrDefault(alternateKey)
                ?? "<unavailable>";
        else
        {
            RememberPath(key, path);
            RememberPath(alternateKey, path);
        }
        var resolved = kind == FileEventKind.Created ? WindowsFileIdentity(path) : null;
        if (resolved is not null)
            RememberIdentity(key, resolved);
        Enqueue(kind, path, null, null, key, pid, op);
    }

    void RememberPath(ulong key, string path)
    {
        if (key == 0)
            return;
        if (_paths.Count >= MaximumTrackedFileObjects && !_paths.ContainsKey(key))
        {
            Interlocked.Increment(ref _overflow);
            return;
        }
        if (_paths.TryGetValue(key, out var previous)
            && !previous.Equals(path, StringComparison.OrdinalIgnoreCase))
            _previousPaths[key] = previous;
        _paths[key] = path;
    }

    void RememberIdentity(ulong key, string identity)
    {
        if (key == 0)
            return;
        if (_identities.Count >= MaximumTrackedFileObjects && !_identities.ContainsKey(key))
        {
            Interlocked.Increment(ref _overflow);
            return;
        }
        _identities[key] = identity;
    }

    void Forget(ulong key)
    {
        if (key == 0)
            return;
        _paths.TryRemove(key, out _);
        _previousPaths.TryRemove(key, out _);
        _identities.TryRemove(key, out _);
    }

    void Enqueue(
        FileEventKind kind,
        string path,
        string? previous,
        string? destination,
        ulong key,
        int pid,
        string op
    )
    {
        if (pid == Environment.ProcessId)
            return;
        var seq = Interlocked.Increment(ref _native);
        if (Interlocked.Increment(ref _queued) > MaximumBufferedNativeEvents)
        {
            Interlocked.Decrement(ref _queued);
            Interlocked.Increment(ref _overflow);
            return;
        }
        _events.Enqueue(
            new(
                kind,
                path,
                previous,
                destination,
                _identities.GetValueOrDefault(key),
                null,
                null,
                pid,
                null,
                null,
                null,
                null,
                DateTimeOffset.UtcNow,
                $"{SessionName}:{seq}",
                op,
                null,
                seq
            )
        );
    }

    public Task<IReadOnlyList<NativeFileEvent>> PollAsync(CancellationToken ct)
    {
        var list = new List<NativeFileEvent>();
        // Bound each durable-ingest slice so file pressure cannot delay heartbeats,
        // policy refresh, updates, or other telemetry partitions for minutes.
        while (list.Count < 250 && _events.TryDequeue(out var x))
        {
            Interlocked.Decrement(ref _queued);
            list.Add(x);
        }
        return Task.FromResult<IReadOnlyList<NativeFileEvent>>(list);
    }

    public async Task StopAsync(CancellationToken ct)
    {
        _session?.Stop();
        if (_reader is not null)
            try
            {
                await _reader.WaitAsync(TimeSpan.FromSeconds(5), ct);
            }
            catch (Exception e)
                when (e is System.Runtime.InteropServices.COMException or TimeoutException)
            { }
        _session?.Dispose();
        _session = null;
        RemoveOwner();
        State = "stopped";
    }

    bool OwnedStale()
    {
        try
        {
            if (!File.Exists(_owner))
                return false;
            using var d = JsonDocument.Parse(File.ReadAllText(_owner));
            if (d.RootElement.GetProperty("sessionName").GetString() != SessionName)
                return false;
            var pid = d.RootElement.GetProperty("ownerPid").GetInt32();
            if (pid == Environment.ProcessId)
                return true;
            try
            {
                using var p = System.Diagnostics.Process.GetProcessById(pid);
                return p.HasExited;
            }
            catch (ArgumentException)
            {
                return true;
            }
        }
        catch
        {
            return false;
        }
    }

    void WriteOwner()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_owner)!);
        using var s = new FileStream(
            _owner,
            FileMode.Create,
            FileAccess.Write,
            FileShare.Read,
            4096,
            FileOptions.WriteThrough
        );
        JsonSerializer.Serialize(
            s,
            new
            {
                sessionName = SessionName,
                ownerPid = Environment.ProcessId,
                createdAt = DateTimeOffset.UtcNow,
            }
        );
        s.Flush(true);
    }

    void RemoveOwner()
    {
        try
        {
            if (File.Exists(_owner))
            {
                using var d = JsonDocument.Parse(File.ReadAllText(_owner));
                if (d.RootElement.GetProperty("ownerPid").GetInt32() == Environment.ProcessId)
                    File.Delete(_owner);
            }
        }
        catch { }
    }

    public async ValueTask DisposeAsync() => await StopAsync(CancellationToken.None);

    static string? WindowsFileIdentity(string path)
    {
        if (!OperatingSystem.IsWindows() || path == "<unavailable>")
            return null;
        try
        {
            using var handle = File.OpenHandle(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete
            );
            if (!GetFileInformationByHandle(handle, out var info))
                return null;
            var index = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
            return $"{info.VolumeSerialNumber:x8}:{index:x16}";
        }
        catch (Exception e)
            when (e is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle,
        out ByHandleFileInformation information
    );
}

sealed partial class LinuxFalcoFileCollector(string path) : IFileCollector
{
    long _offset,
        _lost;
    readonly HashSet<string> _seen = [];
    readonly Dictionary<string, (long Device, long Inode)> _identityByPath = new(
        StringComparer.Ordinal
    );
    readonly Dictionary<string, long> _identityGenerations = new(StringComparer.Ordinal);
    public string Type => "linux.falco-json";
    public string Version => "1.0.0";
    public string Platform => "linux";
    public long LostEvents => _lost;
    public string State { get; private set; } = "stopped";
    public string? Error { get; private set; }

    public Task StartAsync(CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (!File.Exists(path))
            File.WriteAllText(path, "");
        _offset = new FileInfo(path).Length;
        State = "healthy";
        return Task.CompletedTask;
    }

    public async Task<IReadOnlyList<NativeFileEvent>> PollAsync(CancellationToken ct)
    {
        var list = new List<NativeFileEvent>();
        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete
            );
            if (stream.Length < _offset)
            {
                _offset = 0;
                _lost++;
            }
            stream.Position = _offset;
            using var reader = new StreamReader(stream);
            // Bound each poll so an existing or high-volume Falco stream cannot monopolize
            // the agent loop, starve uploads/heartbeats, or allocate an unbounded event list.
            var scannedLines = 0;
            while (scannedLines++ < 5000 && await reader.ReadLineAsync(ct) is { } line)
            {
                _offset = stream.Position;
                using var doc = JsonDocument.Parse(line);
                if (
                    !doc.RootElement.TryGetProperty("rule", out var rule)
                    || rule.GetString() != "Platform File Mutation"
                )
                    continue;
                var fields = doc.RootElement.GetProperty("output_fields");
                string? S(string name)
                {
                    if (
                        !fields.TryGetProperty(name, out var value)
                        || value.ValueKind == JsonValueKind.Null
                    )
                        return null;
                    var result = value.ToString();
                    return string.IsNullOrWhiteSpace(result) || result == "<NA>" ? null : result;
                }
                var op = S("evt.type") ?? "unknown";
                var deviceText = S("fd.dev");
                var dev = long.TryParse(deviceText, out var parsedDev)
                    ? parsedDev
                    : long.TryParse(
                        deviceText,
                        NumberStyles.HexNumber,
                        CultureInfo.InvariantCulture,
                        out parsedDev
                    )
                        ? parsedDev
                        : 0;
                var inode = long.TryParse(S("fd.ino"), out var parsedInode) ? parsedInode : 0;
                var source = S("fd.name")
                    ?? S("evt.abspath.src")
                    ?? S("evt.arg.oldpath")
                    ?? S("evt.arg.path")
                    ?? S("evt.arg.name")
                    ?? "<unavailable>";
                var isRename = op is "rename" or "renameat" or "renameat2";
                var destination = isRename
                    ? S("evt.abspath.dst") ?? S("evt.arg.newpath")
                    : null;
                if (
                    (dev == 0 || inode == 0)
                    && _identityByPath.TryGetValue(source, out var remembered)
                )
                {
                    dev = remembered.Device;
                    inode = remembered.Inode;
                }
                var native = $"{dev}:{inode}";
                var generation = _identityGenerations.GetValueOrDefault(native);
                var collectorFileId = dev != 0 && inode != 0
                    ? $"linux:{dev}:{inode}:generation:{generation}"
                    : null;
                var renamedKind = destination is not null
                    && !string.Equals(
                        Path.GetDirectoryName(source),
                        Path.GetDirectoryName(destination),
                        StringComparison.Ordinal
                    )
                        ? FileEventKind.Moved
                        : FileEventKind.Renamed;
                var kind = op switch
                {
                    "unlink" or "unlinkat" => FileEventKind.Deleted,
                    "rename" or "renameat" or "renameat2" => renamedKind,
                    "chmod" or "fchmod" or "fchmodat" or "chown" or "fchown" or "fchownat" =>
                        FileEventKind.MetadataChanged,
                    "write" or "pwrite" or "pwrite64" or "truncate" or "ftruncate" =>
                        FileEventKind.Modified,
                    _ => (S("evt.arg.flags")?.Contains("O_F_CREATED", StringComparison.Ordinal)
                        == true)
                        || _seen.Add($"{native}:{generation}")
                            ? FileEventKind.Created
                            : FileEventKind.Modified,
                };
                var seq = long.TryParse(S("evt.num"), out var parsedSeq) ? parsedSeq : 0;
                var pid = int.TryParse(S("proc.pid"), out var parsedPid) ? parsedPid : 0;
                if (dev != 0 && inode != 0)
                {
                    if (
                        kind is FileEventKind.Renamed or FileEventKind.Moved
                        && destination is not null
                    )
                    {
                        _identityByPath.Remove(source);
                        _identityByPath[destination] = (dev, inode);
                    }
                    else if (kind == FileEventKind.Deleted)
                        _identityByPath.Remove(source);
                    else
                        _identityByPath[source] = (dev, inode);
                }
                list.Add(
                    new(
                        kind,
                        destination ?? source,
                        kind is FileEventKind.Renamed or FileEventKind.Moved ? source : null,
                        destination,
                        collectorFileId,
                        dev == 0 ? null : dev,
                        inode == 0 ? null : inode,
                        pid == 0 ? null : pid,
                        S("proc.name"),
                        S("proc.exepath"),
                        S("user.uid"),
                        S("container.id"),
                        doc.RootElement.TryGetProperty("time", out var time)
                        && DateTimeOffset.TryParse(time.GetString(), out var at)
                            ? at
                            : DateTimeOffset.UtcNow,
                        $"falco:{seq}",
                        op,
                        S("evt.rawres"),
                        seq
                    )
                );
                if (kind == FileEventKind.Deleted && collectorFileId is not null)
                    _identityGenerations[native] = generation + 1;
            }
        }
        catch (Exception e) when (e is IOException or JsonException)
        {
            Error = e.GetType().Name;
            State = "degraded";
        }
        return list;
    }

    public Task StopAsync(CancellationToken ct)
    {
        State = "stopped";
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [GeneratedRegex("([a-zA-Z0-9_.]+)=([^ ]*)")]
    private static partial Regex Pairs();
}

sealed class FileTelemetryPipeline : IAsyncDisposable
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly AgentOptions _options;
    readonly IFileCollector _collector;
    readonly string _queue;
    readonly DurableFileHashQueue _hashQueue;
    long _sequence;
    long _queueBytes;
    long _excludedEvents;
    long _droppedEvents;
    bool _hashRecoveryComplete;
    CancellationTokenRegistration _shutdownRegistration;
    int _shutdownRegistered;
    FileTelemetryPolicy _policy = new(
        Enabled: false,
        ExcludedPaths: ["/proc/", "/sys/", "/dev/", "/run/", "/var/log/", "/var/lib/docker/overlay2/"]
    );
    public string CollectorState => _collector.State;
    public string CurrentPolicyKey { get; private set; } = "implicit";
    public long QueueDepth =>
        Directory.Exists(_queue) ? Directory.EnumerateFiles(_queue, "*.json").LongCount() : 0;

    public FileTelemetryPipeline(AgentOptions options, long sequence)
    {
        _options = options;
        _collector = FileCollectorFactory.Create(options);
        _queue = Path.Combine(options.DataDirectory, "file-queue");
        Directory.CreateDirectory(_queue);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(
                _queue,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            );
        _hashQueue = new(options.DataDirectory, _queue, options.Environment);
        RecoverQueue();
        _queueBytes = Directory.EnumerateFiles(_queue, "*.json").Sum(x => new FileInfo(x).Length);
        _sequence = Math.Max(
            sequence,
            Directory
                .EnumerateFiles(_queue, "*.json")
                .Select(x => long.TryParse(Path.GetFileName(x).Split('-')[0], out var n) ? n : 0)
                .DefaultIfEmpty()
                .Max()
        );
        _collector.StartAsync(default).GetAwaiter().GetResult();
    }

    public Task<IReadOnlyDictionary<string, string[]>> ApplyPolicyAsync(
        FileTelemetryPolicy policy,
        Guid id,
        int version
    )
    {
        var errors = FilePolicyValidation.Validate(policy).ToDictionary(x => x.Key, x => x.Value);
        var compatible =
            policy.CollectorSource == "auto" || policy.CollectorSource == _collector.Type;
        if (!compatible)
            errors["collectorSource"] =
            [
                "Policy collector does not match the active production collector.",
            ];
        if (errors.Count == 0)
        {
            _policy = policy;
            CurrentPolicyKey = $"{id:D}:{version}";
        }
        return Task.FromResult<IReadOnlyDictionary<string, string[]>>(errors);
    }

    public async Task<long> RunOnceAsync(
        AgentState state,
        Func<AgentState, HttpClient> clientFactory,
        Func<long, CancellationToken, Task> checkpoint,
        CancellationToken ct
    )
    {
        if (Interlocked.Exchange(ref _shutdownRegistered, 1) == 0)
            _shutdownRegistration = ct.Register(() =>
                _collector.DisposeAsync().AsTask().GetAwaiter().GetResult()
            );
        var checkpointRequired = false;
        foreach (var n in await _collector.PollAsync(ct))
        {
            if (!_policy.Enabled || !PolicyAllows(n.Kind) || Excluded(n.Path))
            {
                Interlocked.Increment(ref _excludedEvents);
                continue;
            }
            var sequence = Interlocked.Increment(ref _sequence);
            var (observation, hashSnapshot) = Normalize(state, n, sequence);
            try
            {
                await Persist(observation, ct);
                if (hashSnapshot is not null && observation.Hash.State == FileHashState.Pending)
                    await _hashQueue.EnqueueAsync(
                        observation,
                        hashSnapshot,
                        _policy.MaximumHashBytes,
                        ct
                    );
                _collector.AcknowledgePersisted(n.SourceEventId);
                LocalTestFailpoint.Hit("file-queue-after-rename-before-state", _options.Environment);
            }
            catch (IOException)
            {
                Interlocked.Increment(ref _droppedEvents);
            }
            LocalTestFailpoint.Hit("file-queue-before-index-update", _options.Environment);
            checkpointRequired = true;
            LocalTestFailpoint.Hit("file-queue-after-index-update", _options.Environment);
        }
        if (checkpointRequired) await checkpoint(_sequence, ct);
        if (_policy.HashingEnabled)
        {
            if (!_hashRecoveryComplete)
            {
                await _hashQueue.RecoverPendingAsync(_policy.MaximumHashBytes, ct);
                _hashRecoveryComplete = true;
            }
            await _hashQueue.ProcessAsync(
                $"{state.TenantId}:{state.EndpointId:D}",
                _policy.HashesPerMinute,
                4,
                ct
            );
        }
        else
            _hashRecoveryComplete = false;
        var ready = new List<(string Path, FileObservation Observation)>();
        foreach (var path in Directory.EnumerateFiles(_queue, "*.json").OrderBy(x => x))
        {
            var queued = await ReadQueueRecord(path, ct);
            if (queued is null)
                continue;
            if (queued.Hash.State == FileHashState.Pending)
                break;
            ready.Add((path, queued));
            if (ready.Count >= _policy.MaximumBatchEvents)
                break;
        }
        var files = ready.Select(x => x.Path).ToArray();
        if (files.Length > 0)
            LocalTestFailpoint.Hit("file-batch-after-selection", _options.Environment);
        if (files.Length == 0)
            return _sequence;
        var events = ready.Select(x => x.Observation).ToList();
        if (events.Count == 0)
            return _sequence;
        var bytes = JsonSerializer.SerializeToUtf8Bytes(events, Json);
        var batch = new FileEventBatch(
            Guid.NewGuid(),
            state.EndpointId,
            state.AgentId,
            state.InstallationId,
            events.Min(x => x.Sequence),
            events.Max(x => x.Sequence),
            events,
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()
        );
        var canonical = JsonSerializer.SerializeToUtf8Bytes(batch, Json);
        LocalTestFailpoint.Hit("file-batch-after-canonical", _options.Environment);
        await using var compressed = new MemoryStream();
        await using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, true))
        {
            for (var offset = 0; offset < canonical.Length; offset += 1024)
            {
                var length = Math.Min(1024, canonical.Length - offset);
                await gzip.WriteAsync(canonical.AsMemory(offset, length), ct);
                LocalTestFailpoint.Hit("file-batch-during-compression", _options.Environment);
            }
        }
        LocalTestFailpoint.Hit("file-batch-after-compression", _options.Environment);
        LocalTestFailpoint.Hit("file-batch-after-integrity", _options.Environment);
        using var content = new ByteArrayContent(compressed.ToArray());
        content.Headers.ContentType = new("application/json");
        content.Headers.ContentEncoding.Add("gzip");
        content.Headers.Add(
            "X-Uncompressed-Length",
            canonical.Length.ToString(CultureInfo.InvariantCulture)
        );
        var postAcknowledgementDepth = Math.Max(0, QueueDepth - events.Count);
        content.Headers.Add(
            "X-Queue-Depth",
            postAcknowledgementDepth.ToString(CultureInfo.InvariantCulture)
        );
        var oldest = postAcknowledgementDepth == 0
            ? 0
            : Math.Max(
                0,
                (long)(DateTimeOffset.UtcNow - File.GetCreationTimeUtc(files[^1])).TotalSeconds
            );
        content.Headers.Add("X-Queue-Oldest-Age", oldest.ToString(CultureInfo.InvariantCulture));
        content.Headers.Add("X-Excluded-Events", Interlocked.Read(ref _excludedEvents).ToString(CultureInfo.InvariantCulture));
        var hashMetrics = _hashQueue.Metrics;
        content.Headers.Add("X-Hash-Failures", hashMetrics.Failures.ToString(CultureInfo.InvariantCulture));
        content.Headers.Add(
            "X-Hash-Metrics",
            Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(hashMetrics, Json))
        );
        content.Headers.Add("X-Dropped-Events", Interlocked.Read(ref _droppedEvents).ToString(CultureInfo.InvariantCulture));
        content.Headers.Add(
            "X-Falco-Lost-Events",
            _collector.LostEvents.ToString(CultureInfo.InvariantCulture)
        );
        content.Headers.Add(
            "X-ETW-Lost-Events",
            _collector.LostEvents.ToString(CultureInfo.InvariantCulture)
        );
        using var client = clientFactory(state);
        LocalTestFailpoint.Hit("file-batch-before-transport", _options.Environment);
        using var response = await client.PostAsync("/agent/v1/file-event-batches", content, ct);
        response.EnsureSuccessStatusCode();
        LocalTestFailpoint.Hit("file-batch-after-commit-before-ack", _options.Environment);
        var ack =
            await response.Content.ReadFromJsonAsync<FileBatchAcknowledgement>(Json, ct)
            ?? throw new InvalidDataException("File batch acknowledgement is invalid.");
        var batchMetricsPath = Environment.GetEnvironmentVariable(
            "PLATFORM_FILE_BATCH_METRICS_PATH"
        );
        if (!string.IsNullOrWhiteSpace(batchMetricsPath))
        {
            var metrics = JsonSerializer.Serialize(
                new
                {
                    recordedAt = DateTimeOffset.UtcNow,
                    eventCount = events.Count,
                    acceptedCount = ack.AcceptedEventIds.Count,
                    duplicateCount = ack.DuplicateEventIds.Count,
                    uncompressedBytes = canonical.Length,
                    compressedBytes = compressed.Length,
                },
                Json
            );
            await File.AppendAllTextAsync(batchMetricsPath, metrics + Environment.NewLine, ct);
        }
        var done = ack.AcceptedEventIds.Concat(ack.DuplicateEventIds).ToHashSet();
        var rejected = ack.RejectedEventIds.ToHashSet();
        LocalTestFailpoint.Hit("file-batch-during-ack-cleanup", _options.Environment);
        foreach (var file in files)
        {
            var x = await ReadQueueRecord(file, ct);
            if (x is null)
                continue;
            if (done.Contains(x.EventId))
            {
                var length = new FileInfo(file).Length;
                File.Delete(file);
                Interlocked.Add(ref _queueBytes, -length);
            }
            else if (rejected.Contains(x.EventId))
            {
                var length = new FileInfo(file).Length;
                Quarantine(file, "server-rejected");
                Interlocked.Add(ref _queueBytes, -length);
            }
        }
        return _sequence;
    }

    bool Excluded(string path) =>
        SafetyExcluded(path)
        || (_policy.IncludedPaths?.Length > 0
            && !_policy.IncludedPaths.Any(x =>
                path.StartsWith(
                    x,
                    OperatingSystem.IsWindows()
                        ? StringComparison.OrdinalIgnoreCase
                        : StringComparison.Ordinal
                )
            ))
        || _policy.ExcludedPaths?.Any(x =>
            path.StartsWith(
                x,
                OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal
            )
        ) == true
        || _policy.ExcludedExtensions?.Contains(
            Path.GetExtension(path),
            OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal
        ) == true;

    bool SafetyExcluded(string path)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path))
            return false;
        return IsWithin(path, _options.DataDirectory) || IsWithin(path, AppContext.BaseDirectory);
    }

    static bool IsWithin(string candidate, string root)
    {
        try
        {
            var fullCandidate = Path.GetFullPath(candidate).TrimEnd(Path.DirectorySeparatorChar);
            var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
            return fullCandidate.Equals(fullRoot, StringComparison.OrdinalIgnoreCase)
                || fullCandidate.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    bool PolicyAllows(FileEventKind kind) =>
        kind switch
        {
            FileEventKind.Created => _policy.CreateEnabled,
            FileEventKind.Modified => _policy.ModifyEnabled,
            FileEventKind.Deleted => _policy.DeleteEnabled,
            FileEventKind.Renamed => _policy.RenameEnabled,
            FileEventKind.Moved => _policy.MoveEnabled,
            FileEventKind.Opened => _policy.OpenEnabled,
            FileEventKind.MetadataChanged => _policy.MetadataChangeEnabled,
            _ => true,
        };

    (FileObservation Observation, NativeFileSnapshot? HashSnapshot) Normalize(
        AgentState s,
        NativeFileEvent n,
        long sequence
    )
    {
        var original = n.PreviousPath ?? n.Path;
        var current = n.DestinationPath ?? n.Path;
        var info = TryInfo(current);
        var hashRequested = _policy.HashingEnabled && FileHashSafety.ShouldRequest(n.Kind);
        var hashSnapshot = hashRequested
            ? NativeFileSnapshotReader.TryRead(current)
            : null;
        var identity = hashSnapshot?.Identity ?? new FileNativeIdentity(
            null,
            n.FileId,
            n.DeviceId,
            n.Inode,
            null,
            info?.LinkTarget is not null,
            null
        );
        var entity = FileObservation.StableEntityId(s.EndpointId, identity, current, n.ObservedAt);
        var hash = !hashRequested
            ? new FileHashMetadata()
            : hashSnapshot is null
                ? new(
                    FileHashState.Unavailable,
                    FailureReason: "file-unavailable",
                    RequestedAt: DateTimeOffset.UtcNow,
                    PolicyVersion: CurrentPolicyKey
                )
                : new(
                    FileHashState.Pending,
                    RequestedAt: DateTimeOffset.UtcNow,
                    PolicyVersion: CurrentPolicyKey,
                    SizeAtHash: hashSnapshot.Size,
                    ModifiedAtHash: hashSnapshot.ModifiedAt,
                    NativeIdentityBefore: hashSnapshot.Identity,
                    ChangeTimeAtHash: hashSnapshot.ChangedAt,
                    CacheResult: "pending"
                );
        var name = Path.GetFileName(current);
        var observation = new FileObservation(
            Guid.NewGuid(),
            "file-event.v1",
            n.Kind,
            s.EndpointId,
            s.AgentId,
            s.InstallationId,
            $"{_collector.Type}:{Environment.MachineName}",
            _collector.Type,
            _collector.Version,
            _collector.Platform,
            n.SourceEventId,
            sequence,
            n.ObservedAt,
            "file-normalization.v1",
            Convert
                .ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(n.SourceEventId)))
                .ToLowerInvariant(),
            null,
            System.Diagnostics.Activity.Current?.TraceId.ToString(),
            identity.FileId is null && identity.Inode is null
                ? ["native-identity-unavailable"]
                : [],
            identity.FileId is null && identity.Inode is null ? "medium" : "high",
            entity,
            identity,
            original,
            current,
            n.PreviousPath,
            n.DestinationPath,
            name,
            Path.GetDirectoryName(current) ?? "",
            Path.GetExtension(current).TrimStart('.'),
            Path.IsPathRooted(current) ? "absolute" : "relative",
            current == "<unavailable>" ? "unavailable" : "preserved",
            !OperatingSystem.IsWindows(),
            current.Contains(':') && OperatingSystem.IsWindows()
                ? current[(current.IndexOf(':') + 1)..]
                : null,
            current.StartsWith("\\\\", StringComparison.Ordinal),
            n.ContainerId,
            new(
                info?.Exists == true ? info.Length : null,
                info?.CreationTimeUtc,
                info?.LastWriteTimeUtc,
                info?.LastAccessTimeUtc,
                info?.Attributes.ToString(),
                null,
                null,
                null,
                null,
                info?.Attributes.HasFlag(FileAttributes.Hidden),
                info?.Attributes.HasFlag(FileAttributes.System),
                info?.IsReadOnly,
                info?.Attributes.HasFlag(FileAttributes.Temporary)
            ),
            hash,
            n.ProcessId is null
                ? null
                : new(
                    null,
                    n.ProcessId,
                    n.ProcessName,
                    n.ProcessPath,
                    null,
                    null,
                    n.UserId,
                    "native-collector",
                    "high"
                ),
            n.UserId,
            n.UserId,
            n.Outcome,
            n.NativeOperation
        );
        return (observation, hashSnapshot);
    }

    static FileInfo? TryInfo(string path)
    {
        try
        {
            var info = new FileInfo(path);
            _ = info.Exists;
            _ = info.Length;
            _ = info.CreationTimeUtc;
            _ = info.LastWriteTimeUtc;
            _ = info.LastAccessTimeUtc;
            _ = info.Attributes;
            _ = info.IsReadOnly;
            _ = info.LinkTarget;
            return info;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    async Task Persist(FileObservation x, CancellationToken ct)
    {
        var final = Path.Combine(_queue, $"{x.Sequence:D20}-{x.EventId:N}.json");
        var tmp = final + ".tmp";
        var bytes = JsonSerializer.SerializeToUtf8Bytes(x, Json);
        if (Interlocked.Read(ref _queueBytes) + bytes.LongLength > _policy.MaximumQueueBytes)
            throw new IOException("file-queue-capacity-exceeded");
        LocalTestFailpoint.Hit("file-queue-before-temp-write", _options.Environment);
        await using (
            var s = new FileStream(
                tmp,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough
            )
        )
        {
            var split = Math.Max(1, bytes.Length / 2);
            await s.WriteAsync(bytes.AsMemory(0, split), ct);
            LocalTestFailpoint.Hit("file-queue-during-temp-write", _options.Environment);
            await s.WriteAsync(bytes.AsMemory(split), ct);
            LocalTestFailpoint.Hit("file-queue-after-write-before-flush", _options.Environment);
            await s.FlushAsync(ct);
            s.Flush(true);
        }
        LocalTestFailpoint.Hit("file-queue-after-flush-before-rename", _options.Environment);
        var committing = final + ".committing";
        File.Move(tmp, committing);
        LocalTestFailpoint.Hit("file-queue-rename-boundary", _options.Environment);
        File.Move(committing, final);
        Interlocked.Add(ref _queueBytes, bytes.LongLength);
    }

    void RecoverQueue()
    {
        foreach (
            var tmp in Directory
                .EnumerateFiles(_queue, "*.tmp")
                .Concat(Directory.EnumerateFiles(_queue, "*.committing"))
                .ToArray()
        )
        {
            try
            {
                ValidateQueueRecord(
                    JsonSerializer.Deserialize<FileObservation>(File.ReadAllText(tmp), Json)
                );
                var final = tmp.EndsWith(".committing", StringComparison.Ordinal)
                    ? tmp[..^11]
                    : tmp[..^4];
                if (!File.Exists(final))
                    File.Move(tmp, final);
                else
                    Quarantine(tmp, "duplicate-commit");
            }
            catch (Exception e) when (e is IOException or JsonException or InvalidDataException)
            {
                Quarantine(tmp, e.GetType().Name);
            }
        }
        foreach (var file in Directory.EnumerateFiles(_queue, "*.json"))
            try
            {
                ValidateQueueRecord(
                    JsonSerializer.Deserialize<FileObservation>(File.ReadAllText(file), Json)
                );
            }
            catch (Exception e) when (e is IOException or JsonException or InvalidDataException)
            {
                Quarantine(file, e.GetType().Name);
            }
    }

    async Task<FileObservation?> ReadQueueRecord(string file, CancellationToken ct)
    {
        try
        {
            var item = JsonSerializer.Deserialize<FileObservation>(
                    await File.ReadAllTextAsync(file, ct),
                    Json
                );
            ValidateQueueRecord(item);
            return item;
        }
        catch (Exception e) when (e is IOException or JsonException or InvalidDataException)
        {
            Quarantine(file, e.GetType().Name);
            return null;
        }
    }

    static void ValidateQueueRecord(FileObservation? item)
    {
        if (
            item is null
            || item.EventId == Guid.Empty
            || item.EndpointId == Guid.Empty
            || item.AgentId == Guid.Empty
            || item.Sequence <= 0
            || item.SchemaVersion != "file-event.v1"
            || string.IsNullOrWhiteSpace(item.FileEntityId)
        )
            throw new InvalidDataException("invalid-file-queue-record");
    }

    void Quarantine(string file, string reason)
    {
        var directory = Path.Combine(_queue, "quarantine");
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(
                directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            );
        var target = Path.Combine(
            directory,
            $"{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.bad"
        );
        try
        {
            LocalTestFailpoint.Hit("file-queue-before-quarantine-move", _options.Environment);
            File.Move(file, target);
            LocalTestFailpoint.Hit("file-queue-during-quarantine-move", _options.Environment);
            File.WriteAllText(target + ".reason", reason);
            Interlocked.Increment(ref _droppedEvents);
            foreach (
                var stale in Directory
                    .EnumerateFiles(directory)
                    .OrderByDescending(File.GetCreationTimeUtc)
                    .Skip(2000)
            )
                File.Delete(stale);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            Interlocked.Increment(ref _droppedEvents);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _shutdownRegistration.DisposeAsync();
        await _collector.DisposeAsync();
    }
}
