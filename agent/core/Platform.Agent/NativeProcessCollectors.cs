using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using OpenSecurityPlatform.Foundation;

static class WindowsKernelImageHub
{
    static readonly object Gate = new();
    static event Action<TraceEvent, bool>? Image;
    public static bool Active { get; private set; }
    public static void SetActive(bool value) { lock (Gate) Active = value; }
    public static void Publish(TraceEvent data, bool unload)
    {
        Action<TraceEvent, bool>? handlers; lock (Gate) handlers = Image;
        if (handlers is null) return;
        foreach (Action<TraceEvent, bool> handler in handlers.GetInvocationList())
            try { handler(data, unload); } catch { }
    }
    public static void Subscribe(Action<TraceEvent, bool> handler) { lock (Gate) Image += handler; }
    public static void Unsubscribe(Action<TraceEvent, bool> handler) { lock (Gate) Image -= handler; }
}

static class WindowsKernelThreadHub
{
    static readonly object Gate = new();
    static event Action<ThreadTraceData>? ThreadStart;
    public static bool Active { get; private set; }
    public static void SetActive(bool value) { lock (Gate) Active = value; }
    public static void Publish(ThreadTraceData data)
    {
        Action<ThreadTraceData>? handlers; lock (Gate) handlers = ThreadStart;
        if (handlers is null) return;
        foreach (Action<ThreadTraceData> handler in handlers.GetInvocationList())
            try { handler(data); } catch { }
    }
    public static void Subscribe(Action<ThreadTraceData> handler) { lock (Gate) ThreadStart += handler; }
    public static void Unsubscribe(Action<ThreadTraceData> handler) { lock (Gate) ThreadStart -= handler; }
}

static class ProcessCollectorFactory
{
    public static IProcessCollector Create(AgentOptions options)
    {
        var configured = Environment
            .GetEnvironmentVariable("PLATFORM_PROCESS_COLLECTOR")
            ?.Trim()
            .ToLowerInvariant();
        if (OperatingSystem.IsWindows())
            return configured is null or "etw"
                ? new WindowsEtwProcessCollector(options.Environment, options.DataDirectory)
                : new UnsupportedProcessCollector($"windows.{configured}");
        if (OperatingSystem.IsLinux())
        {
            if (configured == "procfs" || options.Environment is "development" or "evaluation")
                return new LinuxProcfsProcessCollector();
            return configured is null or "falco"
                ? new LinuxFalcoProcessCollector(
                    Environment.GetEnvironmentVariable("PLATFORM_FALCO_JSON_PATH")
                        ?? "/var/run/platform-falco/process-events.jsonl"
                )
                : new UnsupportedProcessCollector($"linux.{configured}");
        }
        return OperatingSystem.IsMacOS()
            ? new MacEndpointSecurityProcessCollector(
                Environment.GetEnvironmentVariable("PLATFORM_MACOS_ES_JSON_PATH")
                    ?? "/Library/Application Support/OpenSecurityPlatform/process-events.jsonl"
            )
            : new UnsupportedProcessCollector("unknown.unsupported");
    }
}

sealed class WindowsEtwProcessCollector(
    string environment = "production",
    string dataDirectory = "agent-data"
) : IProcessCollector
{
    private const string SessionName = "OpenSecurityPlatform-ProcessLifecycle-v1";
    private readonly ConcurrentQueue<NativeProcessEvent> _events = new();
    private readonly ConcurrentDictionary<int, NativeProcessEvent> _active = new();
    private DateTimeOffset _lastInventoryAt = DateTimeOffset.MinValue;
    private TraceEventSession? _session;
    private Task? _reader;
    private readonly string _ownershipMarker = Path.Combine(
        dataDirectory,
        "etw-session-owner.json"
    );
    private ProcessCollectorHealth _health = new("stopped", null, 0, 0, 0, 0, 0, 0, 0, 0, null);

    public string Type => "windows.etw.kernel-process";
    public string Version => "1.0.0";
    public string Platform => "windows";
    public string SourceType => "etw-kernel-process";
    public string[] Capabilities =>
        ["process.start", "process.exit", "startup-inventory", "native-sequence", "loss-counter"];
    public ProcessCollectorHealth Health => _health;

    public Task StartAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
        {
            _health = _health with { State = "unsupported", Error = "ETW requires Windows." };
            return Task.CompletedTask;
        }
        try
        {
            var failureMarker = Environment.GetEnvironmentVariable("PLATFORM_ETW_FAILURE_MARKER");
            if (
                environment != "production"
                && !string.IsNullOrWhiteSpace(failureMarker)
                && File.Exists(failureMarker)
            )
                throw new InvalidOperationException("Injected ETW provider enablement failure.");
            if (
                TraceEventSession
                    .GetActiveSessionNames()
                    .Contains(SessionName, StringComparer.Ordinal)
            )
            {
                if (!OwnedStaleSession())
                    throw new InvalidOperationException(
                        "ETW session-name conflict: the active session is not demonstrably owned by this platform installation."
                    );
                using var stale = new TraceEventSession(SessionName);
                stale.Stop();
                _health = _health with { RestartCount = _health.RestartCount + 1 };
            }
            _session = new TraceEventSession(SessionName)
            {
                StopOnDispose = true,
                BufferSizeMB = 64,
            };
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process
                    | KernelTraceEventParser.Keywords.ImageLoad
                    | KernelTraceEventParser.Keywords.Thread
            );
            // Do not use Source.Kernel here. Its default parser enables the unbounded
            // FileNameToObject history tracker even though this session only consumes
            // process, image, and thread events. Kernel sessions can observe the union
            // of enabled kernel keywords, so high-volume file telemetry otherwise
            // accumulates in the process collector's parser state indefinitely.
            var parser = new KernelTraceEventParser(
                _session.Source,
                KernelTraceEventParser.ParserTrackingOptions.None
            );
            parser.ProcessStart += OnStart;
            parser.ProcessStop += OnStop;
            parser.ImageLoad += data => WindowsKernelImageHub.Publish(data, false);
            parser.ImageUnload += data => WindowsKernelImageHub.Publish(data, true);
            parser.ThreadStart += WindowsKernelThreadHub.Publish;
            _reader = Task.Run(() => _session.Source.Process(), CancellationToken.None);
            CaptureStartupInventory();
            WriteOwnershipMarker();
            WindowsKernelImageHub.SetActive(true);
            WindowsKernelThreadHub.SetActive(true);
            _health = _health with { State = "healthy", Error = null };
        }
        catch (Exception e)
        {
            _health = _health with
            {
                State = "failed",
                CollectionErrors = _health.CollectionErrors + 1,
                Error = $"{e.GetType().Name}: {e.Message}",
            };
        }
        return Task.CompletedTask;
    }

    private void OnStart(ProcessTraceData data)
    {
        try
        {
            var observed = DateTimeOffset.UtcNow;
            var start = new NativeProcessEvent(
                ProcessEventKind.Started,
                data.ProcessID,
                data.ParentID > 0 ? data.ParentID : null,
                new DateTimeOffset(data.TimeStamp.ToUniversalTime()),
                observed,
                $"windows:{data.TimeStamp.ToUniversalTime().Ticks}",
                Empty(data.ProcessName) ?? Empty(data.ImageFileName),
                Empty(data.ImageFileName),
                Empty(data.CommandLine),
                null,
                null,
                null,
                null,
                null,
                null,
                $"{SessionName}:start:{data.ProcessID}:{data.TimeStampRelativeMSec:F6}",
                (long)(data.TimeStampRelativeMSec * 1000)
            );
            _active[data.ProcessID] = start;
            _events.Enqueue(start);
            Count(start);
        }
        catch (Exception e)
        {
            _health = _health with
            {
                CollectionErrors = _health.CollectionErrors + 1,
                Error = e.GetType().Name,
            };
        }
    }

    private void CaptureStartupInventory()
    {
        const uint snapshotProcesses = 0x00000002;
        var snapshot = CreateToolhelp32Snapshot(snapshotProcesses, 0);
        if (snapshot == new nint(-1))
        {
            _health = _health with { CollectionErrors = _health.CollectionErrors + 1, Error = $"startup-inventory:{Marshal.GetLastWin32Error()}" };
            return;
        }
        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            var values = new List<NativeProcessEvent>();
            if (Process32First(snapshot, ref entry))
            {
                do
                {
                    if (entry.ProcessId == 0 || values.Count >= 4096)
                        continue;
                    try
                    {
                        using var process = Process.GetProcessById((int)entry.ProcessId);
                        var start = new DateTimeOffset(process.StartTime.ToUniversalTime());
                        string? path = null;
                        try { path = process.MainModule?.FileName; } catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException) { }
                        string? session = null;
                        try { session = process.SessionId.ToString(CultureInfo.InvariantCulture); } catch (InvalidOperationException) { }
                        values.Add(new(
                            ProcessEventKind.Started,
                            (int)entry.ProcessId,
                            entry.ParentProcessId > 0 ? (int)entry.ParentProcessId : null,
                            start,
                            DateTimeOffset.UtcNow,
                            $"windows:{start.UtcTicks}",
                            Empty(process.ProcessName) ?? Empty(entry.ExecutableFile),
                            Empty(path),
                            null,
                            null,
                            session,
                            null,
                            null,
                            null,
                            "startup-inventory",
                            $"{SessionName}:inventory:{entry.ProcessId}:{start.UtcTicks}"
                        ));
                    }
                    catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
                    {
                        // The process exited or denied metadata access during the bounded snapshot.
                    }
                    entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
                } while (Process32Next(snapshot, ref entry));
            }
            foreach (var item in values.OrderBy(x => x.StartTime).ThenBy(x => x.Pid))
            {
                if (_active.TryGetValue(item.Pid, out var current)
                    && current.StartTime == item.StartTime)
                    continue;
                _active[item.Pid] = item;
                _events.Enqueue(item);
                Count(item);
            }
            _lastInventoryAt = DateTimeOffset.UtcNow;
        }
        finally
        {
            CloseHandle(snapshot);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public nint DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExecutableFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(nint snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(nint snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);

    private void OnStop(ProcessTraceData data)
    {
        try
        {
            var observed = DateTimeOffset.UtcNow;
            _active.TryRemove(data.ProcessID, out var start);
            var item = new NativeProcessEvent(
            ProcessEventKind.Exited,
            data.ProcessID,
            start?.ParentPid,
            start?.StartTime ?? new DateTimeOffset(data.TimeStamp.ToUniversalTime()),
            observed,
            start?.StartKey ?? $"{data.ProcessID}:unknown-start",
            start?.Name ?? Empty(data.ProcessName),
            start?.Path,
            start?.CommandLine,
            start?.UserId,
            start?.SessionId,
            null,
            observed,
            data.ExitStatus,
            start is null ? "start-not-observed" : null,
            $"{SessionName}:stop:{data.ProcessID}:{data.TimeStampRelativeMSec:F6}",
            (long)(data.TimeStampRelativeMSec * 1000)
        );
            _events.Enqueue(item);
            Count(item);
        }
        catch (Exception e)
        {
            _health = _health with { CollectionErrors = _health.CollectionErrors + 1, Error = e.GetType().Name };
        }
    }

    private void Count(NativeProcessEvent item) =>
        _health = _health with
        {
            LastSourceEvent = item.ObservedAt,
            SourceEvents = _health.SourceEvents + 1,
            StartEvents = _health.StartEvents + (item.Kind == ProcessEventKind.Started ? 1 : 0),
            ExitEvents = _health.ExitEvents + (item.Kind == ProcessEventKind.Exited ? 1 : 0),
            LostEvents = ReadLostEvents(),
        };

    public Task<IReadOnlyList<NativeProcessEvent>> PollAsync(CancellationToken ct)
    {
        // ETW sessions can begin after long-lived Windows services, and a provider
        // transition can occasionally leave a start event outside the session.
        // Periodically reconcile the bounded native process table so those live
        // parents receive the same PID+start-time identity as ordinary ETW starts.
        if (DateTimeOffset.UtcNow - _lastInventoryAt >= TimeSpan.FromSeconds(30))
            CaptureStartupInventory();
        var values = new List<NativeProcessEvent>();
        while (values.Count < 250 && _events.TryDequeue(out var item))
            values.Add(item);
        _health = _health with { LostEvents = ReadLostEvents() };
        return Task.FromResult<IReadOnlyList<NativeProcessEvent>>(values);
    }

    public async Task StopAsync(CancellationToken ct)
    {
        WindowsKernelImageHub.SetActive(false);
        WindowsKernelThreadHub.SetActive(false);
        _session?.Stop();
        if (_reader is not null)
        {
            try
            {
                await _reader.WaitAsync(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
            }
            catch (System.Runtime.InteropServices.COMException)
            {
                // ProcessTrace can report the closed real-time session while stopping.
            }
        }
        _session?.Dispose();
        _session = null;
        RemoveOwnershipMarker();
        _health = _health with { State = "stopped" };
    }

    public async ValueTask DisposeAsync() => await StopAsync(CancellationToken.None);

    private long ReadLostEvents()
    {
        try
        {
            return _session?.EventsLost ?? _health.LostEvents;
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            return _health.LostEvents;
        }
    }

    private static string? Empty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private bool OwnedStaleSession()
    {
        try
        {
            if (!File.Exists(_ownershipMarker))
                return false;
            using var document = JsonDocument.Parse(File.ReadAllText(_ownershipMarker));
            var root = document.RootElement;
            if (
                root.GetProperty("sessionName").GetString() != SessionName
                || !root.TryGetProperty("ownerPid", out var pidValue)
            )
                return false;
            var ownerPid = pidValue.GetInt32();
            if (ownerPid == Environment.ProcessId)
                return true;
            try
            {
                using var owner = Process.GetProcessById(ownerPid);
                return owner.HasExited;
            }
            catch (ArgumentException)
            {
                return true;
            }
        }
        catch (Exception e) when (e is IOException or JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    private void WriteOwnershipMarker()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_ownershipMarker)!);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                sessionName = SessionName,
                ownerPid = Environment.ProcessId,
                createdAt = DateTimeOffset.UtcNow,
            }
        );
        using var stream = new FileStream(
            _ownershipMarker,
            FileMode.Create,
            FileAccess.Write,
            FileShare.Read,
            4096,
            FileOptions.WriteThrough
        );
        stream.Write(bytes);
        stream.Flush(true);
    }

    private void RemoveOwnershipMarker()
    {
        try
        {
            if (!File.Exists(_ownershipMarker))
                return;
            using var document = JsonDocument.Parse(File.ReadAllText(_ownershipMarker));
            if (
                document.RootElement.TryGetProperty("ownerPid", out var pid)
                && pid.GetInt32() == Environment.ProcessId
            )
                File.Delete(_ownershipMarker);
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            // A stale marker is safe: a future owner still verifies that its process no longer exists.
        }
    }
}

sealed class LinuxFalcoProcessCollector(string path) : IProcessCollector
{
    private readonly Dictionary<int, NativeProcessEvent> _active = [];
    private long _offset;
    private ProcessCollectorHealth _health = new("stopped", null, 0, 0, 0, 0, 0, 0, 0, 0, null);

    public string Type => "linux.falco-json";
    public string Version => "1.0.0";
    public string Platform => "linux";
    public string SourceType => "falco-json-output";
    public string[] Capabilities => ["process.start", "process.exit", "container", "loss-counter"];
    public ProcessCollectorHealth Health => _health;

    public Task StartAsync(CancellationToken ct)
    {
        var directory = Path.GetDirectoryName(path);
        if (directory is not null)
            Directory.CreateDirectory(directory);
        _offset = File.Exists(path) ? new FileInfo(path).Length : 0;
        _health = _health with
        {
            State = File.Exists(path) ? "healthy" : "degraded",
            Error = File.Exists(path) ? null : $"Falco JSON output is unavailable at {path}.",
        };
        return Task.CompletedTask;
    }

    public async Task<IReadOnlyList<NativeProcessEvent>> PollAsync(CancellationToken ct)
    {
        if (!File.Exists(path))
        {
            _health = _health with { State = "degraded", Error = "Falco output unavailable." };
            return [];
        }
        var output = new List<NativeProcessEvent>();
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete
        );
        if (stream.Length < _offset)
        {
            _offset = 0;
            _health = _health with { RestartCount = _health.RestartCount + 1 };
        }
        stream.Position = _offset;
        using var reader = new StreamReader(stream);
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (line.Length is 0 or > 1024 * 1024)
            {
                _health = _health with { ParseErrors = _health.ParseErrors + 1 };
                continue;
            }
            try
            {
                using var json = JsonDocument.Parse(line);
                var root = json.RootElement;
                var rule = Text(root, "rule");
                if (rule is not ("Platform Process Start" or "Platform Process Exit"))
                    continue;
                var fields = root.GetProperty("output_fields");
                var pid = Integer(fields, "proc.vpid");
                if (pid <= 0)
                    pid = Integer(fields, "proc.pid");
                if (pid <= 0)
                    throw new JsonException("proc.pid missing");
                var observed = DateTimeOffset.UtcNow;
                var sourceTime = DateTimeOffset.TryParse(Text(root, "time"), out var timestamp)
                    ? timestamp
                    : observed;
                var kind =
                    rule == "Platform Process Start"
                        ? ProcessEventKind.Started
                        : ProcessEventKind.Exited;
                _active.TryGetValue(pid, out var known);
                var startTime =
                    kind == ProcessEventKind.Started ? sourceTime : known?.StartTime ?? sourceTime;
                var startKey =
                    Text(fields, "proc.pid.ts") ?? known?.StartKey ?? $"{pid}:{startTime.UtcTicks}";
                var item = new NativeProcessEvent(
                    kind,
                    pid,
                    NullableInteger(fields, "proc.pvpid")
                        ?? NullableInteger(fields, "proc.ppid")
                        ?? known?.ParentPid,
                    startTime,
                    observed,
                    startKey,
                    Text(fields, "proc.name") ?? known?.Name,
                    Text(fields, "proc.exepath") ?? known?.Path,
                    Text(fields, "proc.cmdline") ?? known?.CommandLine,
                    Text(fields, "user.uid") ?? known?.UserId,
                    Text(fields, "proc.tty") ?? known?.SessionId,
                    Text(fields, "container.id") ?? known?.ContainerId,
                    kind == ProcessEventKind.Exited ? sourceTime : null,
                    NullableInteger(fields, "evt.rawres"),
                    kind == ProcessEventKind.Exited && known is null ? "start-not-observed" : null,
                    Text(fields, "evt.source_id") ?? $"falco:{sourceTime.UtcTicks}:{pid}:{kind}",
                    NullableLong(fields, "evt.num")
                );
                if (kind == ProcessEventKind.Started)
                    _active[pid] = item;
                else
                    _active.Remove(pid);
                output.Add(item);
                _health = _health with
                {
                    State = "healthy",
                    Error = null,
                    LastSourceEvent = observed,
                    SourceEvents = _health.SourceEvents + 1,
                    StartEvents = _health.StartEvents + (kind == ProcessEventKind.Started ? 1 : 0),
                    ExitEvents = _health.ExitEvents + (kind == ProcessEventKind.Exited ? 1 : 0),
                };
            }
            catch (Exception e)
                when (e is JsonException or InvalidOperationException or FormatException)
            {
                _health = _health with
                {
                    ParseErrors = _health.ParseErrors + 1,
                    Error = e.GetType().Name,
                };
            }
        }
        _offset = stream.Position;
        return output;
    }

    private static string? Text(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var field) || field.ValueKind == JsonValueKind.Null)
            return null;
        var text = field.ToString();
        return string.IsNullOrWhiteSpace(text) || text == "<NA>" ? null : text;
    }

    private static int Integer(JsonElement value, string name) =>
        int.TryParse(
            Text(value, name),
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var result
        )
            ? result
            : 0;

    private static int? NullableInteger(JsonElement value, string name) =>
        int.TryParse(
            Text(value, name),
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var result
        )
            ? result
            : null;

    private static long? NullableLong(JsonElement value, string name) =>
        long.TryParse(
            Text(value, name),
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var result
        )
            ? result
            : null;
}

sealed class MacEndpointSecurityProcessCollector(string path) : IProcessCollector
{
    private readonly Dictionary<int, NativeProcessEvent> _active = [];
    private long _offset;
    public string Type => "macos.endpoint-security";
    public string Version => "source-1.0.0";
    public string Platform => "macos";
    public string SourceType => "endpoint-security-notify-exec-exit";
    public string[] Capabilities =>
        ["process.start", "process.exit", "native-sequence", "external-entitlement-required"];
    public ProcessCollectorHealth Health { get; private set; } =
        new("stopped", null, 0, 0, 0, 0, 0, 0, 0, 0, null);

    public Task StartAsync(CancellationToken ct)
    {
        _offset = File.Exists(path) ? new FileInfo(path).Length : 0;
        Health = Health with
        {
            State =
                !OperatingSystem.IsMacOS() ? "unsupported"
                : File.Exists(path) ? "healthy"
                : "external-entitlement-required",
            Error = File.Exists(path)
                ? null
                : "The Endpoint Security native companion must be signed with com.apple.developer.endpoint-security.client.",
        };
        return Task.CompletedTask;
    }

    public async Task<IReadOnlyList<NativeProcessEvent>> PollAsync(CancellationToken ct)
    {
        if (!File.Exists(path))
            return [];
        var values = new List<NativeProcessEvent>();
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete
        );
        if (stream.Length < _offset)
        {
            _offset = 0;
            Health = Health with { RestartCount = Health.RestartCount + 1 };
        }
        stream.Position = _offset;
        using var reader = new StreamReader(stream);
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                var pid = root.GetProperty("pid").GetInt32();
                var observed = DateTimeOffset.TryParse(Text(root, "observedAt"), out var time)
                    ? time
                    : DateTimeOffset.UtcNow;
                var kind =
                    Text(root, "kind") == "started"
                        ? ProcessEventKind.Started
                        : ProcessEventKind.Exited;
                _active.TryGetValue(pid, out var known);
                var item = new NativeProcessEvent(
                    kind,
                    pid,
                    root.TryGetProperty("parentPid", out var parent)
                        ? parent.GetInt32()
                        : known?.ParentPid,
                    known?.StartTime ?? observed,
                    observed,
                    Text(root, "startKey") ?? known?.StartKey ?? $"{pid}:{observed.UtcTicks}",
                    Path.GetFileName(Text(root, "path")),
                    Text(root, "path") ?? known?.Path,
                    null,
                    Text(root, "userId") ?? known?.UserId,
                    null,
                    null,
                    kind == ProcessEventKind.Exited ? observed : null,
                    root.TryGetProperty("exitCode", out var exit) ? exit.GetInt32() : null,
                    kind == ProcessEventKind.Exited && known is null ? "start-not-observed" : null,
                    Text(root, "sourceEventId"),
                    root.TryGetProperty("sequence", out var sequence)
                        ? (long?)sequence.GetUInt64()
                        : null,
                    root.TryGetProperty("sequenceGap", out var gap) ? (long)gap.GetUInt64() : 0
                );
                if (kind == ProcessEventKind.Started)
                    _active[pid] = item;
                else
                    _active.Remove(pid);
                values.Add(item);
                Health = Health with
                {
                    State = "healthy",
                    LastSourceEvent = observed,
                    SourceEvents = Health.SourceEvents + 1,
                    StartEvents = Health.StartEvents + (kind == ProcessEventKind.Started ? 1 : 0),
                    ExitEvents = Health.ExitEvents + (kind == ProcessEventKind.Exited ? 1 : 0),
                    SequenceGaps = Health.SequenceGaps + item.LostEvents,
                };
            }
            catch (Exception e)
                when (e is JsonException or InvalidOperationException or FormatException)
            {
                Health = Health with
                {
                    ParseErrors = Health.ParseErrors + 1,
                    Error = e.GetType().Name,
                };
            }
        }
        _offset = stream.Position;
        return values;
    }

    private static string? Text(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
