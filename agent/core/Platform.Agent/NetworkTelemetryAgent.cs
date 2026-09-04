using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using OpenSecurityPlatform.Foundation;

sealed record NativeNetworkEvent(NetworkEventKind Kind, string Protocol, string LocalAddress,
    int LocalPort, string? RemoteAddress, int? RemotePort, NetworkDirection Direction,
    NetworkConnectionState State, int ProcessId, int ThreadId, int Status,
    DateTimeOffset ObservedAt, string NativeOperation, string NativeEventId,
    string? NativeConnectionId = null, string? NetworkNamespace = null,
    DateTimeOffset? ProcessStartTime = null, string? User = null, string? ProcessName = null);

interface INetworkCollector : IAsyncDisposable
{
    string Type { get; }
    string Version { get; }
    string State { get; }
    string? Error { get; }
    long LostEvents { get; }
    string[] KnownLimitations { get; }
    Task StartAsync(CancellationToken ct);
    Task<IReadOnlyList<NativeNetworkEvent>> PollAsync(CancellationToken ct);
}

sealed class WindowsEtwNetworkCollector(string dataDirectory) : INetworkCollector
{
    internal const string SessionName = "OpenSecurityPlatform-NetworkLifecycle-v1";
    const int MaximumBufferedNativeEvents = 100_000;
    readonly ConcurrentQueue<NativeNetworkEvent> _events = [];
    readonly string _owner = Path.Combine(dataDirectory, "etw-network-session-owner.json");
    TraceEventSession? _session; Task? _reader; long _native, _queued, _overflow;
    public string Type => "windows.etw-network";
    public string Version => "1.0.0";
    public string State { get; private set; } = "stopped";
    public string? Error { get; private set; }
    public long LostEvents { get { try { return (_session?.EventsLost ?? 0) + Interlocked.Read(ref _overflow); } catch { return Interlocked.Read(ref _overflow); } } }
    public string[] KnownLimitations => ["Windows kernel TCP/IP ETW does not expose a canonical listener-start/listener-stop lifecycle on every supported Windows build.", "UDP is operation-level datagram observation; it is not represented as a stateful connection."];

    public Task StartAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) { State = "unsupported"; Error = "Windows network ETW requires Windows."; return Task.CompletedTask; }
        try
        {
            if (TraceEventSession.GetActiveSessionNames().Contains(SessionName, StringComparer.Ordinal))
            {
                if (!OwnedStale()) throw new InvalidOperationException("ETW network session-name conflict is not demonstrably platform-owned.");
                using var stale = new TraceEventSession(SessionName); stale.Stop();
            }
            _session = new TraceEventSession(SessionName) { StopOnDispose = true, BufferSizeMB = 64 };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP | KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Thread);
            var p = new KernelTraceEventParser(_session.Source, KernelTraceEventParser.ParserTrackingOptions.ThreadToProcess);
            p.TcpIpConnect += d => Emit(d, NetworkEventKind.ConnectionAttempted, NetworkDirection.Outbound, NetworkConnectionState.Attempted, "TCP", "connect");
            p.TcpIpConnectIPV6 += d => Emit(d, NetworkEventKind.ConnectionAttempted, NetworkDirection.Outbound, NetworkConnectionState.Attempted, "TCP", "connect-v6");
            p.TcpIpAccept += d => Emit(d, NetworkEventKind.ConnectionEstablished, NetworkDirection.Inbound, NetworkConnectionState.Established, "TCP", "accept");
            p.TcpIpAcceptIPV6 += d => Emit(d, NetworkEventKind.ConnectionEstablished, NetworkDirection.Inbound, NetworkConnectionState.Established, "TCP", "accept-v6");
            p.TcpIpDisconnect += d => Emit(d, NetworkEventKind.ConnectionClosed, NetworkDirection.Unknown, NetworkConnectionState.Closed, "TCP", "disconnect");
            p.TcpIpDisconnectIPV6 += d => Emit(d, NetworkEventKind.ConnectionClosed, NetworkDirection.Unknown, NetworkConnectionState.Closed, "TCP", "disconnect-v6");
            p.TcpIpFail += d => Emit(d, NetworkEventKind.ConnectionFailed, NetworkDirection.Outbound, NetworkConnectionState.Failed, "TCP", "connect-fail");
            p.UdpIpSend += d => Emit(d, NetworkEventKind.DatagramObserved, NetworkDirection.Outbound, NetworkConnectionState.Unknown, "UDP", "send");
            p.UdpIpSendIPV6 += d => Emit(d, NetworkEventKind.DatagramObserved, NetworkDirection.Outbound, NetworkConnectionState.Unknown, "UDP", "send-v6");
            p.UdpIpRecv += d => Emit(d, NetworkEventKind.DatagramObserved, NetworkDirection.Inbound, NetworkConnectionState.Unknown, "UDP", "receive");
            p.UdpIpRecvIPV6 += d => Emit(d, NetworkEventKind.DatagramObserved, NetworkDirection.Inbound, NetworkConnectionState.Unknown, "UDP", "receive-v6");
            _reader = Task.Run(() => _session.Source.Process(), CancellationToken.None);
            WriteOwner(); State = "healthy";
        }
        catch (Exception e) { State = "failed"; Error = $"{e.GetType().Name}: {e.Message}"; }
        return Task.CompletedTask;
    }

    void Emit(TraceEvent d, NetworkEventKind kind, NetworkDirection direction, NetworkConnectionState state, string protocol, string operation)
    {
        try
        {
            var local = Address(d, "saddr") ?? Address(d, "LocalAddress") ?? "0.0.0.0";
            var remote = Address(d, "daddr") ?? Address(d, "RemoteAddress");
            var localPort = Number(d, "sport") ?? Number(d, "LocalPort") ?? 0;
            var remotePort = Number(d, "dport") ?? Number(d, "RemotePort");
            if (direction == NetworkDirection.Inbound) (local, remote, localPort, remotePort) = (remote ?? local, local, remotePort ?? 0, localPort);
            var sequence = Interlocked.Increment(ref _native);
            if (Interlocked.Increment(ref _queued) > MaximumBufferedNativeEvents)
            {
                Interlocked.Decrement(ref _queued);
                Interlocked.Increment(ref _overflow);
                return;
            }
            var nativeConnectionId = Text(d, "connid") ?? Text(d, "ConnectionId");
            if (nativeConnectionId is "0" or "18446744069414584320") nativeConnectionId = null;
            _events.Enqueue(new(kind, protocol, local, localPort, remote, remotePort, direction,
                state, d.ProcessID, d.ThreadID, Number(d, "status") ?? 0,
                new DateTimeOffset(d.TimeStamp.ToUniversalTime()), operation,
                $"{SessionName}:{d.ID}:{d.ProcessID}:{d.ThreadID}:{d.TimeStampRelativeMSec:F6}:{sequence}",
                nativeConnectionId));
        }
        catch (Exception e) when (e is ArgumentException or FormatException or OverflowException) { Error = $"event-normalization:{e.GetType().Name}"; }
    }
    static object? Payload(TraceEvent d, string name) { try { return d.PayloadByName(name); } catch (ArgumentException) { return null; } }
    static string? Text(TraceEvent d, string name) => Payload(d, name)?.ToString() is { Length: > 0 } x ? x : null;
    static int? Number(TraceEvent d, string name) => int.TryParse(Text(d, name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var x) ? x : null;
    static string? Address(TraceEvent d, string name)
    {
        var value = Payload(d, name); if (value is null) return null; if (value is IPAddress ip) return ip.ToString();
        if (IPAddress.TryParse(value.ToString(), out var parsed)) return parsed.ToString();
        if (value is uint v4) return new IPAddress(BitConverter.GetBytes(v4)).ToString(); return null;
    }
    public Task<IReadOnlyList<NativeNetworkEvent>> PollAsync(CancellationToken ct) { var list = new List<NativeNetworkEvent>(); while (list.Count < 100 && _events.TryDequeue(out var x)) { Interlocked.Decrement(ref _queued); list.Add(x); } return Task.FromResult<IReadOnlyList<NativeNetworkEvent>>(list); }
    bool OwnedStale() { try { if (!File.Exists(_owner)) return false; using var d = JsonDocument.Parse(File.ReadAllText(_owner)); if (d.RootElement.GetProperty("sessionName").GetString() != SessionName) return false; var pid = d.RootElement.GetProperty("ownerPid").GetInt32(); if (pid == Environment.ProcessId) return true; try { using var p = Process.GetProcessById(pid); return p.HasExited; } catch (ArgumentException) { return true; } } catch { return false; } }
    void WriteOwner() { Directory.CreateDirectory(Path.GetDirectoryName(_owner)!); using var s = new FileStream(_owner, FileMode.Create, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough); JsonSerializer.Serialize(s, new { sessionName = SessionName, ownerPid = Environment.ProcessId, createdAt = DateTimeOffset.UtcNow }); s.Flush(true); }
    void RemoveOwner() { try { if (File.Exists(_owner)) { using var d = JsonDocument.Parse(File.ReadAllText(_owner)); if (d.RootElement.GetProperty("ownerPid").GetInt32() == Environment.ProcessId) File.Delete(_owner); } } catch { } }
    public async ValueTask DisposeAsync() { _session?.Stop(); if (_reader is not null) try { await _reader.WaitAsync(TimeSpan.FromSeconds(5)); } catch (Exception e) when (e is System.Runtime.InteropServices.COMException or TimeoutException) { } _session?.Dispose(); RemoveOwner(); State = "stopped"; }
}

sealed class LinuxFalcoNetworkCollector(string path) : INetworkCollector
{
    long _offset, _lost;
    public string Type => "linux.falco-json"; public string Version => "1.0.0";
    public string State { get; private set; } = "stopped"; public string? Error { get; private set; }
    public long LostEvents => _lost;
    public string[] KnownLimitations => ["Falco syscall events are operation observations and kernel/version/rule coverage can make lifecycle correlation partial.", "UDP is operation-level datagram observation; no packet or payload content is captured."];
    public Task StartAsync(CancellationToken ct) { Directory.CreateDirectory(Path.GetDirectoryName(path)!); if (!File.Exists(path)) File.WriteAllText(path, ""); _offset = new FileInfo(path).Length; State = "healthy"; return Task.CompletedTask; }
    public async Task<IReadOnlyList<NativeNetworkEvent>> PollAsync(CancellationToken ct)
    {
        var list = new List<NativeNetworkEvent>();
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length < _offset) { _offset = 0; _lost++; }
            stream.Position = _offset; using var reader = new StreamReader(stream); var scanned = 0;
            while (scanned++ < 500 && await reader.ReadLineAsync(ct) is { } line)
            {
                _offset = stream.Position; using var doc = JsonDocument.Parse(line); var root = doc.RootElement;
                if (!root.TryGetProperty("output_fields", out var f)) continue;
                string? S(string name) => f.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null && v.ToString() is { } x && x is not ("" or "<NA>") ? x : null;
                var op = (S("evt.type") ?? "").ToLowerInvariant(); if (op is not ("connect" or "accept" or "bind" or "listen" or "close" or "sendto" or "recvfrom")) continue;
                var protocol = (S("fd.l4proto") ?? "").ToUpperInvariant(); if (protocol is not ("TCP" or "UDP")) continue;
                var localAddress = S("fd.lip") ?? S("fd.sip") ?? "0.0.0.0"; var remoteAddress = S("fd.rip") ?? S("fd.cip");
                var localPort = Parse(S("fd.lport") ?? S("fd.sport")); var remotePort = ParseNullable(S("fd.rport") ?? S("fd.cport"));
                var status = Parse(S("evt.rawres"));
                var kind = op switch { "connect" when status < 0 => NetworkEventKind.ConnectionFailed, "connect" => NetworkEventKind.ConnectionEstablished, "accept" when status >= 0 => NetworkEventKind.ConnectionEstablished, "bind" or "listen" when status >= 0 => NetworkEventKind.ListenerStarted, "close" when status >= 0 => NetworkEventKind.ConnectionClosed, "sendto" or "recvfrom" when protocol == "UDP" && status >= 0 => NetworkEventKind.DatagramObserved, _ => NetworkEventKind.OperationObserved };
                var direction = op is "accept" or "recvfrom" ? NetworkDirection.Inbound : op is "bind" or "listen" ? NetworkDirection.Local : op == "close" ? NetworkDirection.Unknown : NetworkDirection.Outbound;
                var state = kind switch { NetworkEventKind.ConnectionAttempted => NetworkConnectionState.Attempted, NetworkEventKind.ConnectionEstablished => NetworkConnectionState.Established, NetworkEventKind.ConnectionFailed => NetworkConnectionState.Failed, NetworkEventKind.ListenerStarted => NetworkConnectionState.Listening, NetworkEventKind.ConnectionClosed => NetworkConnectionState.Closed, _ => NetworkConnectionState.Unknown };
                var pid = Parse(S("proc.pid")); var pidStart = EpochNanoseconds(S("proc.pid.ts")); var fd = S("fd.num"); var nativeConnection = fd is null ? null : $"linux:{pid}:{pidStart?.UtcTicks.ToString(CultureInfo.InvariantCulture) ?? "unknown"}:{fd}";
                list.Add(new(kind, protocol, localAddress, localPort, remoteAddress, remotePort, direction, state, pid, Parse(S("thread.tid")), status, DateTimeOffset.TryParse(root.TryGetProperty("time", out var time) ? time.ToString() : null, out var observed) ? observed : DateTimeOffset.UtcNow, op, $"falco:{S("evt.num") ?? Guid.NewGuid().ToString("N")}", nativeConnection, S("container.id"), pidStart, S("user.uid"), S("proc.name")));
            }
            State = "healthy"; Error = null;
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { State = "degraded"; Error = e.GetType().Name; }
        return list;
    }
    static int Parse(string? value) => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var x) ? x : 0;
    static int? ParseNullable(string? value) => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var x) ? x : null;
    static DateTimeOffset? EpochNanoseconds(string? value) { if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ns) || ns <= 0) return null; try { return DateTimeOffset.FromUnixTimeMilliseconds(ns / 1_000_000).AddTicks(ns % 1_000_000 / 100); } catch (ArgumentOutOfRangeException) { return null; } }
    public ValueTask DisposeAsync() { State = "stopped"; return ValueTask.CompletedTask; }
}

sealed class UnsupportedNetworkCollector : INetworkCollector
{
    public string Type => "unsupported"; public string Version => "1.0.0"; public string State => "unsupported"; public string? Error => "Network telemetry is not supported on this platform."; public long LostEvents => 0; public string[] KnownLimitations => ["Collector unavailable on this platform."]; public Task StartAsync(CancellationToken ct) => Task.CompletedTask; public Task<IReadOnlyList<NativeNetworkEvent>> PollAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<NativeNetworkEvent>>([]); public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

sealed class NetworkTelemetryPipeline : IAsyncDisposable
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly AgentOptions _options; readonly INetworkCollector _collector; readonly string _queue, _quarantine;
    NetworkTelemetryPolicy _policy = new(); long _sequence, _queueBytes, _dropped, _excluded, _attributionFailures, _lifecycleFailures, _nativeEvents, _normalizedEvents, _batches, _uploadFailures, _acceptedEvents, _duplicateEvents, _rejectedEvents;
    DateTimeOffset? _lastSource, _lastUpload; string _uploadResult = "not-attempted";
    public string CurrentPolicyKey { get; private set; } = "network-policy.v1:0";
    public string CollectorType => _collector.Type; public string CollectorState => _collector.State;
    public NetworkTelemetryPipeline(AgentOptions options, long sequence)
    {
        _options = options; _collector = string.Equals(Environment.GetEnvironmentVariable("PLATFORM_TELEMETRY_DRAIN_ONLY"), "true", StringComparison.OrdinalIgnoreCase) ? new UnsupportedNetworkCollector() : OperatingSystem.IsWindows() ? new WindowsEtwNetworkCollector(options.DataDirectory) : OperatingSystem.IsLinux() ? new LinuxFalcoNetworkCollector(Environment.GetEnvironmentVariable("PLATFORM_FALCO_EVENT_PATH") ?? "/var/run/falco/events.jsonl") : new UnsupportedNetworkCollector();
        _queue = Path.Combine(options.DataDirectory, "network-queue"); _quarantine = Path.Combine(_queue, "quarantine"); Directory.CreateDirectory(_queue); Protect(_queue); Recover();
        _queueBytes = Directory.EnumerateFiles(_queue, "*.json").Sum(x => new FileInfo(x).Length); _sequence = Math.Max(sequence, Directory.EnumerateFiles(_queue, "*.json").Select(x => long.TryParse(Path.GetFileName(x).Split('-')[0], out var n) ? n : 0).DefaultIfEmpty().Max()); _collector.StartAsync(default).GetAwaiter().GetResult();
    }
    public Task<IReadOnlyDictionary<string, string[]>> ApplyPolicyAsync(NetworkTelemetryPolicy policy, Guid id, int version)
    { var errors = NetworkPolicyValidation.Validate(policy); if (errors.Count == 0) { _policy = policy; CurrentPolicyKey = $"{id:D}:{version}"; } return Task.FromResult(errors); }
    public async Task<long> RunOnceAsync(AgentState state, Func<AgentState, HttpClient> clientFactory, Func<long, CancellationToken, Task> checkpoint, CancellationToken ct)
    {
        var checkpointRequired = false;
        foreach (var native in await _collector.PollAsync(ct))
        {
            Interlocked.Increment(ref _nativeEvents); _lastSource = native.ObservedAt; if (!_policy.Enabled || !Allowed(native)) { Interlocked.Increment(ref _excluded); continue; }
            var sequence = Interlocked.Increment(ref _sequence); var observation = Normalize(state, native, sequence); if (observation is null) { Interlocked.Increment(ref _dropped); checkpointRequired = true; continue; }
            Interlocked.Increment(ref _normalizedEvents);
            try { await Persist(observation, ct); } catch (IOException) { Interlocked.Increment(ref _dropped); }
            checkpointRequired = true;
        }
        if (checkpointRequired) await checkpoint(_sequence, ct);
        var depth = Depth;
        if (depth > 0 && (depth >= _policy.MaximumBatchEvents || _lastUpload is null || DateTimeOffset.UtcNow - _lastUpload >= TimeSpan.FromSeconds(_policy.FlushSeconds))) await Upload(state, clientFactory, ct);
        return _sequence;
    }
    bool Allowed(NativeNetworkEvent n)
    {
        if (n.Protocol == "TCP" && !_policy.TcpEnabled || n.Protocol == "UDP" && !_policy.UdpEnabled) return false;
        if (n.Kind == NetworkEventKind.ConnectionAttempted && !_policy.AttemptsEnabled || n.Kind == NetworkEventKind.ConnectionEstablished && !_policy.EstablishedEnabled || n.Kind == NetworkEventKind.ConnectionFailed && !_policy.FailedEnabled || n.Kind == NetworkEventKind.ConnectionClosed && !_policy.ClosedEnabled || n.Direction == NetworkDirection.Inbound && !_policy.InboundEnabled || n.Kind is NetworkEventKind.ListenerStarted or NetworkEventKind.ListenerStopped && !_policy.ListenerEnabled) return false;
        if (_policy.IncludedProtocols is { Length: > 0 } && !_policy.IncludedProtocols.Contains(n.Protocol, StringComparer.OrdinalIgnoreCase)) return false;
        if (_policy.IncludedPorts is { Length: > 0 } && !_policy.IncludedPorts.Any(x => Port(x, n.LocalPort) || n.RemotePort is { } rp && Port(x, rp))) return false;
        if (_policy.ExcludedPorts?.Any(x => Port(x, n.LocalPort) || n.RemotePort is { } rp && Port(x, rp)) == true) return false;
        if (_policy.IncludedCidrs is { Length: > 0 } && !_policy.IncludedCidrs.Any(x => Cidr(x, n.LocalAddress) || n.RemoteAddress is { } remote && Cidr(x, remote))) return false;
        if (_policy.ExcludedCidrs?.Any(x => Cidr(x, n.LocalAddress) || n.RemoteAddress is { } remote && Cidr(x, remote)) == true) return false;
        if (_policy.ExcludedProcesses?.Any(x => Wild(n.ProcessName ?? "", x)) == true || _policy.ExcludedUsers?.Any(x => Wild(n.User ?? "", x)) == true) return false;
        foreach (var r in _policy.ExclusionRules?.Where(x => x.Enabled) ?? []) if (r.Category switch { "address" => Wild(n.LocalAddress, r.Pattern) || Wild(n.RemoteAddress ?? "", r.Pattern), "port" => Port(r.Pattern, n.LocalPort) || n.RemotePort is { } rp && Port(r.Pattern, rp), "protocol" => n.Protocol.Equals(r.Pattern, StringComparison.OrdinalIgnoreCase), "direction" => n.Direction.ToString().Equals(r.Pattern, StringComparison.OrdinalIgnoreCase), _ => false }) return false;
        return true;
    }
    NetworkObservation? Normalize(AgentState s, NativeNetworkEvent n, long sequence)
    {
        if (!NetworkSocketEndpoint.TryCreate(n.LocalAddress, n.LocalPort, out var local)) return null;
        var localEndpoint = local!;
        NetworkSocketEndpoint? remote = null; if (n.RemoteAddress is not null && n.RemotePort is { } port) NetworkSocketEndpoint.TryCreate(n.RemoteAddress, port, out remote);
        var quality = new List<string>(); if (n.RemoteAddress is not null && remote is null) quality.Add("remote-address-invalid"); if (OperatingSystem.IsWindows() && n.NativeConnectionId is not null) quality.Add("native-connection-id-not-identity-safe");
        var process = Process(n.ProcessId, n.ThreadId, n.ProcessStartTime, n.User, n.ProcessName, s.EndpointId, _collector.Type); if (process is null) { quality.Add("process-unavailable"); Interlocked.Increment(ref _attributionFailures); }
        var lifecycle = n.Protocol == "UDP" ? NetworkLifecycleCompleteness.EventOnly : n.Kind is NetworkEventKind.ConnectionAttempted or NetworkEventKind.ConnectionEstablished or NetworkEventKind.ConnectionClosed ? NetworkLifecycleCompleteness.Partial : NetworkLifecycleCompleteness.EventOnly;
        if (lifecycle == NetworkLifecycleCompleteness.Partial) Interlocked.Increment(ref _lifecycleFailures);
        var identityNativeConnectionId = OperatingSystem.IsWindows() ? null : n.NativeConnectionId;
        var entity = NetworkObservation.StableConnectionEntityId(s.EndpointId, s.InstallationId, identityNativeConnectionId, process?.ProcessEntityId, process?.ProcessStartTime, localEndpoint, remote, n.Protocol, n.ObservedAt, sequence);
        return new(Guid.NewGuid(), "network-event.v1", n.Kind, s.EndpointId, s.AgentId, s.InstallationId, $"{_collector.Type}:{Environment.MachineName}", _collector.Type, _collector.Version, OperatingSystem.IsWindows() ? "windows" : "linux", _collector.Type, OperatingSystem.IsWindows() ? "9e814aad-3204-11d2-9a82-006008a86939" : null, n.NativeEventId, null, null, n.Status, n.NativeOperation, sequence, n.ObservedAt, "network-normalization.v1", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(n.NativeEventId))).ToLowerInvariant(), null, Activity.Current?.TraceId.ToString(), quality.ToArray(), quality.Count == 0 ? "high" : "medium", entity, localEndpoint, remote, n.Protocol, n.Protocol == "TCP" ? "stream" : "datagram", n.Direction, n.State, n.Status == 0 ? "success-or-not-reported" : "native-failure", n.Status == 0 ? null : n.Status, n.Status == 0 ? null : "native-status", n.NativeConnectionId, null, n.NetworkNamespace, n.Kind == NetworkEventKind.ConnectionAttempted ? n.ObservedAt : null, n.Kind == NetworkEventKind.ConnectionClosed ? n.ObservedAt : null, null, lifecycle, process is null ? "unattributed" : process.Confidence, process, process?.User, null);
    }
    async Task Upload(AgentState s, Func<AgentState, HttpClient> clientFactory, CancellationToken ct)
    {
        var items = new List<(string Path, NetworkObservation Event)>(); foreach (var path in Directory.EnumerateFiles(_queue, "*.json").OrderBy(x => x)) { var value = await Read(path, ct); if (value is not null) items.Add((path, value)); if (items.Count >= _policy.MaximumBatchEvents) break; }
        if (items.Count == 0) return; var events = items.Select(x => x.Event).ToArray(); var eventBytes = JsonSerializer.SerializeToUtf8Bytes(events, Json); var batch = new NetworkEventBatch(Guid.NewGuid(), s.EndpointId, s.AgentId, s.InstallationId, events.Min(x => x.Sequence), events.Max(x => x.Sequence), events, Convert.ToHexString(SHA256.HashData(eventBytes)).ToLowerInvariant()); var canonical = JsonSerializer.SerializeToUtf8Bytes(batch, Json); byte[] compressed;
        await using (var output = new MemoryStream()) { await using (var gzip = new GZipStream(output, CompressionLevel.Fastest, true)) await gzip.WriteAsync(canonical, ct); compressed = output.ToArray(); }
        batch = batch with { UncompressedBytes = canonical.Length, CompressedBytes = compressed.Length }; canonical = JsonSerializer.SerializeToUtf8Bytes(batch, Json); await using (var output = new MemoryStream()) { await using (var gzip = new GZipStream(output, CompressionLevel.Fastest, true)) await gzip.WriteAsync(canonical, ct); compressed = output.ToArray(); }
        if (compressed.Length > 1024 * 1024) { _uploadResult = "compressed-batch-too-large"; return; }
        using var content = new ByteArrayContent(compressed); content.Headers.ContentType = new("application/json"); content.Headers.ContentEncoding.Add("gzip"); content.Headers.Add("X-Uncompressed-Length", canonical.Length.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Queue-Depth", Depth.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Queue-Oldest-Age", Oldest.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Dropped-Events", _dropped.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Excluded-Events", _excluded.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Source-Losses", _collector.LostEvents.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Attribution-Failures", _attributionFailures.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Lifecycle-Correlation-Failures", _lifecycleFailures.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Native-Source-Events", _nativeEvents.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Normalized-Events", _normalizedEvents.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Batches", _batches.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Upload-Failures", _uploadFailures.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Accepted-Events", _acceptedEvents.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Duplicate-Events", _duplicateEvents.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Rejected-Events", _rejectedEvents.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Policy-Version", CurrentPolicyKey); content.Headers.Add("X-Known-Limitations", string.Join(';', _collector.KnownLimitations)); if (PolicyVersion is { } v) content.Headers.Add("X-Applied-Policy-Version", v.ToString(CultureInfo.InvariantCulture));
        using var client = clientFactory(s); using var response = await client.PostAsync("/agent/v1/network-event-batches", content, ct); if (!response.IsSuccessStatusCode) { Interlocked.Increment(ref _uploadFailures); _uploadResult = $"http-{(int)response.StatusCode}"; response.EnsureSuccessStatusCode(); }
        LocalTestFailpoint.Hit("network-batch-after-transport-before-ack", _options.Environment);
        var ack = await response.Content.ReadFromJsonAsync<NetworkBatchAcknowledgement>(Json, ct) ?? throw new InvalidDataException("Network acknowledgement invalid."); Interlocked.Increment(ref _batches); Interlocked.Add(ref _acceptedEvents, ack.AcceptedEventIds.Count); Interlocked.Add(ref _duplicateEvents, ack.DuplicateEventIds.Count); Interlocked.Add(ref _rejectedEvents, ack.RejectedEventIds.Count); var done = ack.AcceptedEventIds.Concat(ack.DuplicateEventIds).ToHashSet(); var rejected = ack.RejectedEventIds.ToHashSet(); foreach (var item in items) if (done.Contains(item.Event.EventId)) { var length = new FileInfo(item.Path).Length; File.Delete(item.Path); Interlocked.Add(ref _queueBytes, -length); } else if (rejected.Contains(item.Event.EventId)) { var length = new FileInfo(item.Path).Length; Quarantine(item.Path, "server-rejected"); Interlocked.Add(ref _queueBytes, -length); }
        _lastUpload = DateTimeOffset.UtcNow; _uploadResult = "accepted";
    }
    async Task Persist(NetworkObservation x, CancellationToken ct) { var bytes = JsonSerializer.SerializeToUtf8Bytes(x, Json); if (Interlocked.Read(ref _queueBytes) + bytes.Length > _policy.MaximumQueueBytes) throw new IOException("network-queue-capacity-exceeded"); var final = Path.Combine(_queue, $"{x.Sequence:D20}-{x.EventId:N}.json"); var temp = final + ".tmp"; LocalTestFailpoint.Hit("network-queue-before-temp-write", _options.Environment); await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { await stream.WriteAsync(bytes, ct); await stream.FlushAsync(ct); stream.Flush(true); } LocalTestFailpoint.Hit("network-queue-after-flush-before-rename", _options.Environment); File.Move(temp, final + ".committing"); LocalTestFailpoint.Hit("network-queue-rename-boundary", _options.Environment); File.Move(final + ".committing", final); Interlocked.Add(ref _queueBytes, bytes.Length); }
    async Task<NetworkObservation?> Read(string path, CancellationToken ct) { try { return JsonSerializer.Deserialize<NetworkObservation>(await File.ReadAllBytesAsync(path, ct), Json) ?? throw new JsonException(); } catch (Exception e) when (e is JsonException or IOException) { Quarantine(path, e.GetType().Name); return null; } }
    void Recover() { foreach (var p in Directory.EnumerateFiles(_queue, "*.tmp").Concat(Directory.EnumerateFiles(_queue, "*.committing")).ToArray()) try { _ = JsonSerializer.Deserialize<NetworkObservation>(File.ReadAllText(p), Json) ?? throw new JsonException(); var final = p.EndsWith(".committing", StringComparison.Ordinal) ? p[..^11] : p[..^4]; if (!File.Exists(final)) File.Move(p, final); else Quarantine(p, "duplicate-commit"); } catch (Exception e) when (e is JsonException or IOException) { Quarantine(p, e.GetType().Name); } }
    void Quarantine(string path, string reason) { try { Directory.CreateDirectory(_quarantine); var target = Path.Combine(_quarantine, $"{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.bad"); File.Move(path, target, true); File.WriteAllText(target + ".reason", reason); Interlocked.Increment(ref _dropped); } catch { Interlocked.Increment(ref _dropped); } }
    static NetworkProcessRelationship? Process(int pid, int thread, DateTimeOffset? nativeStart, string? nativeUser, string? nativeName, Guid endpoint, string source) { if (pid <= 0) return null; if (nativeStart is { } started) return new(ProcessIdentity.Create(endpoint, pid, started, $"{source}:{started.UtcTicks}"), pid, started, nativeName, null, null, nativeUser, null, thread, source, "high-native-identity"); try { using var p = System.Diagnostics.Process.GetProcessById(pid); started = new DateTimeOffset(p.StartTime.ToUniversalTime()); return new(ProcessIdentity.Create(endpoint, pid, started, $"{source}:{started.UtcTicks}"), pid, started, nativeName ?? p.ProcessName, Try(() => p.MainModule?.FileName), null, nativeUser ?? Try(() => p.StartInfo.UserName), Try(() => p.SessionId), thread, source, "high"); } catch { return new(null, pid, null, nativeName, null, null, nativeUser, null, thread, source, "pid-only"); } }
    static T? Try<T>(Func<T> value) { try { return value(); } catch { return default; } }
    static bool Port(string range, int port) { var p = range.Split('-'); return int.TryParse(p[0], out var from) && (p.Length == 1 ? port == from : int.TryParse(p[1], out var to) && port >= from && port <= to); }
    static bool Cidr(string range, string address) { var p = range.Split('/'); if (p.Length != 2 || !IPAddress.TryParse(p[0], out var network) || !IPAddress.TryParse(address, out var candidate) || network.AddressFamily != candidate.AddressFamily || !int.TryParse(p[1], out var prefix)) return false; var n = network.GetAddressBytes(); var c = candidate.GetAddressBytes(); for (var i = 0; i < n.Length; i++) { var bits = Math.Clamp(prefix - i * 8, 0, 8); if (bits == 0) break; var mask = (byte)(0xff << (8 - bits)); if ((n[i] & mask) != (c[i] & mask)) return false; } return true; }
    static bool Wild(string value, string pattern) { var parts = pattern.Split('*'); var at = 0; foreach (var part in parts) { if (part.Length == 0) continue; at = value.IndexOf(part, at, StringComparison.OrdinalIgnoreCase); if (at < 0) return false; at += part.Length; } return true; }
    static void Protect(string path) { if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
    int? PolicyVersion => int.TryParse(CurrentPolicyKey.Split(':').LastOrDefault(), out var v) ? v : null;
    public long Depth => Directory.EnumerateFiles(_queue, "*.json").LongCount();
    public long Oldest { get { var f = Directory.EnumerateFiles(_queue, "*.json").Select(x => new FileInfo(x)).ToArray(); return f.Length == 0 ? 0 : (long)Math.Max(0, (DateTimeOffset.UtcNow - f.Min(x => x.CreationTimeUtc)).TotalSeconds); } }
    public async ValueTask DisposeAsync() => await _collector.DisposeAsync();
}
