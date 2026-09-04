using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;
using OpenSecurityPlatform.Foundation;

sealed record NativeTokenSnapshot(int ProcessId, DateTimeOffset ProcessStart, string? ImagePath,
    string? UserSid, int? SessionId, string TokenType, string? ImpersonationLevel,
    string ElevationType, bool Elevated, string IntegrityLevel, string? IntegritySid,
    bool Restricted, bool AppContainer, bool VirtualizationAllowed, bool VirtualizationEnabled,
    string[] Privileges, GroupIdentity[] Groups, string Fingerprint);
sealed record NativeIdentityEvent(IdentityEventKind Kind, DateTimeOffset ObservedAt,
    IdentityNativeEvidence Native, IReadOnlyDictionary<string, string> Data,
    NativeTokenSnapshot? Token = null, string[]? Quality = null);

interface IIdentityCollector : IAsyncDisposable
{
    string SecurityState { get; }
    string SessionState { get; }
    string TokenState { get; }
    bool Elevated { get; }
    long LostEvents { get; }
    string[] KnownLimitations { get; }
    Task StartAsync(CancellationToken ct);
    Task<IReadOnlyList<NativeIdentityEvent>> PollAsync(CancellationToken ct);
}

[SupportedOSPlatform("windows")]
sealed class WindowsIdentityCollector : IIdentityCollector
{
    const string SecurityChannel = "Security";
    const string SessionChannel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
    const int MaximumBuffered = 100_000;
    readonly ConcurrentQueue<NativeIdentityEvent> _events = [];
    readonly Dictionary<int, string> _tokenFingerprints = [];
    EventLogWatcher? _securityWatcher, _sessionWatcher;
    DateTimeOffset _nextTokenSnapshot = DateTimeOffset.MinValue;
    long _queued, _overflow;
    public string SecurityState { get; private set; } = "stopped";
    public string SessionState { get; private set; } = "stopped";
    public string TokenState { get; private set; } = "stopped";
    public bool Elevated => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    public long LostEvents => Interlocked.Read(ref _overflow);
    public string[] KnownLimitations =>
    [
        "Security auditing policy determines which event IDs are observable.",
        "Token observations are bounded process state snapshots, not token-creation callbacks.",
        "RDP transport peer fields identify the session peer and are not asserted as user ownership.",
        "Token linked-token identity and arbitrary token assignment are not exposed without a supported native event."
    ];

    public Task StartAsync(CancellationToken ct)
    {
        try
        {
            _securityWatcher = new EventLogWatcher(new EventLogQuery(SecurityChannel, PathType.LogName,
                "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=4648 or EventID=4672 or EventID=4673 or EventID=4674 or EventID=4688)]]"));
            _securityWatcher.EventRecordWritten += OnSecurity;
            _securityWatcher.Enabled = true;
            SecurityState = "healthy";
        }
        catch (Exception e) when (e is EventLogException or UnauthorizedAccessException)
        { SecurityState = $"failed:{e.GetType().Name}"; }
        try
        {
            using var configuration = new EventLogConfiguration(SessionChannel);
            if (!configuration.IsEnabled) SessionState = "channel-disabled";
            else
            {
                _sessionWatcher = new EventLogWatcher(new EventLogQuery(SessionChannel, PathType.LogName,
                    "*[System[(EventID=21 or EventID=22 or EventID=23 or EventID=24 or EventID=25 or EventID=39 or EventID=40)]]"));
                _sessionWatcher.EventRecordWritten += OnSession;
                _sessionWatcher.Enabled = true;
                SessionState = "healthy";
            }
        }
        catch (Exception e) when (e is EventLogException or UnauthorizedAccessException)
        { SessionState = $"failed:{e.GetType().Name}"; }
        TokenState = Elevated ? "healthy" : "degraded:not-elevated";
        _nextTokenSnapshot = DateTimeOffset.UtcNow;
        return Task.CompletedTask;
    }

    void OnSecurity(object? sender, EventRecordWrittenEventArgs args)
    {
        if (args.EventException is not null) { Interlocked.Increment(ref _overflow); return; }
        using var record = args.EventRecord;
        if (record is null) return;
        try
        {
            var data = Fields(record);
            var kind = record.Id switch
            {
                4624 => IdentityEventKind.LogonStarted,
                4625 => IdentityEventKind.LogonFailed,
                4634 or 4647 => IdentityEventKind.Logoff,
                4648 => IdentityEventKind.ExplicitCredentialsObserved,
                4672 => IdentityEventKind.PrivilegeAssigned,
                4673 or 4674 => IdentityEventKind.PrivilegeUsed,
                4688 => IdentityEventKind.TokenAssigned,
                _ => IdentityEventKind.GroupContextObserved
            };
            Enqueue(new(kind, record.TimeCreated is { } at ? new DateTimeOffset(at.ToUniversalTime()) : DateTimeOffset.UtcNow,
                Native(record, record.Id switch { 4624 => "successful-logon", 4625 => "failed-logon", 4634 => "logoff", 4647 => "user-initiated-logoff", 4648 => "explicit-credentials", 4672 => "special-privileges-assigned", 4673 => "privileged-service-called", 4674 => "privileged-object-operation", 4688 => "process-created-token-context", _ => "identity-event" }, data), data));
        }
        catch (Exception e) when (e is EventLogException or InvalidOperationException or System.Xml.XmlException)
        { Interlocked.Increment(ref _overflow); }
    }

    void OnSession(object? sender, EventRecordWrittenEventArgs args)
    {
        if (args.EventException is not null) { Interlocked.Increment(ref _overflow); return; }
        using var record = args.EventRecord;
        if (record is null) return;
        try
        {
            var data = Fields(record);
            var kind = record.Id switch
            {
                21 or 22 => IdentityEventKind.SessionCreated,
                23 => IdentityEventKind.SessionEnded,
                _ => IdentityEventKind.SessionStateChanged
            };
            Enqueue(new(kind, record.TimeCreated is { } at ? new DateTimeOffset(at.ToUniversalTime()) : DateTimeOffset.UtcNow,
                Native(record, record.Id switch { 21 => "session-logon", 22 => "shell-start", 23 => "session-logoff", 24 => "session-disconnect", 25 => "session-reconnect", 39 => "session-arbitration-disconnect", 40 => "session-arbitration-reconnect", _ => "session-state" }, data), data));
        }
        catch (Exception e) when (e is EventLogException or InvalidOperationException or System.Xml.XmlException)
        { Interlocked.Increment(ref _overflow); }
    }

    public Task<IReadOnlyList<NativeIdentityEvent>> PollAsync(CancellationToken ct)
    {
        if (DateTimeOffset.UtcNow >= _nextTokenSnapshot)
        {
            CaptureTokens();
            _nextTokenSnapshot = DateTimeOffset.UtcNow.AddSeconds(30);
        }
        var result = new List<NativeIdentityEvent>();
        while (result.Count < 5000 && _events.TryDequeue(out var item))
        { Interlocked.Decrement(ref _queued); result.Add(item); }
        return Task.FromResult<IReadOnlyList<NativeIdentityEvent>>(result);
    }

    void CaptureTokens()
    {
        var observed = new HashSet<int>();
        foreach (var process in Process.GetProcesses().OrderBy(x => x.Id).Take(512))
        {
            using (process)
            {
                try
                {
                    var snapshot = TokenInspector.TryRead(process);
                    if (snapshot is null) continue;
                    observed.Add(process.Id);
                    if (_tokenFingerprints.GetValueOrDefault(process.Id) == snapshot.Fingerprint) continue;
                    _tokenFingerprints[process.Id] = snapshot.Fingerprint;
                    var data = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["ProcessId"] = process.Id.ToString(CultureInfo.InvariantCulture),
                        ["UserSid"] = snapshot.UserSid ?? "",
                        ["SessionId"] = snapshot.SessionId?.ToString(CultureInfo.InvariantCulture) ?? "",
                        ["TokenType"] = snapshot.TokenType,
                        ["ElevationType"] = snapshot.ElevationType,
                        ["Elevated"] = snapshot.Elevated.ToString(CultureInfo.InvariantCulture),
                        ["IntegrityLevel"] = snapshot.IntegrityLevel
                    };
                    var raw = IdentitySafety.EvidenceHash(data);
                    Enqueue(new(IdentityEventKind.TokenObserved, DateTimeOffset.UtcNow,
                        new("ProcessTokenSnapshot", "Windows Token API", null, 0, null, null, null, null, null,
                            "bounded-token-state-observation", null, raw), data, snapshot));
                }
                catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
                { }
            }
        }
        foreach (var pid in _tokenFingerprints.Keys.Where(x => !observed.Contains(x)).ToArray()) _tokenFingerprints.Remove(pid);
    }

    void Enqueue(NativeIdentityEvent value)
    {
        if (Interlocked.Increment(ref _queued) > MaximumBuffered)
        { Interlocked.Decrement(ref _queued); Interlocked.Increment(ref _overflow); return; }
        _events.Enqueue(value);
    }

    static Dictionary<string, string> Fields(EventRecord record)
    {
        var document = XDocument.Parse(record.ToXml(), LoadOptions.None);
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var ordinal = 0;
        foreach (var element in document.Descendants(ns + "EventData").Elements(ns + "Data"))
        {
            var name = element.Attribute("Name")?.Value ?? $"Field{ordinal}";
            result[name] = Bound(element.Value, 32767);
            ordinal++;
        }
        foreach (var element in document.Descendants(ns + "UserData").Descendants().Where(x => !x.HasElements))
            result[element.Name.LocalName] = Bound(element.Value, 32767);
        return result;
    }
    static string Bound(string value, int maximum) => value.Length <= maximum ? value : value[..maximum];
    static IdentityNativeEvidence Native(EventRecord record, string operation, IReadOnlyDictionary<string, string> data)
    {
        var hash = IdentitySafety.EvidenceHash(new { record.Id, record.RecordId, record.ProviderName, data });
        return new(record.LogName ?? "unknown", record.ProviderName ?? "unknown", record.ProviderId?.ToString(),
            record.Id, record.Version, record.Level, record.Opcode, record.Task, record.RecordId,
            operation, data.GetValueOrDefault("Status"), hash);
    }

    public ValueTask DisposeAsync()
    {
        if (_securityWatcher is not null) { _securityWatcher.Enabled = false; _securityWatcher.Dispose(); }
        if (_sessionWatcher is not null) { _sessionWatcher.Enabled = false; _sessionWatcher.Dispose(); }
        SecurityState = SessionState = TokenState = "stopped";
        return ValueTask.CompletedTask;
    }
}

sealed class UnsupportedIdentityCollector : IIdentityCollector
{
    public string SecurityState => "unsupported"; public string SessionState => "unsupported";
    public string TokenState => "unsupported"; public bool Elevated => false; public long LostEvents => 0;
    public string[] KnownLimitations => ["Windows identity telemetry is unsupported on this platform."];
    public Task StartAsync(CancellationToken ct) => Task.CompletedTask;
    public Task<IReadOnlyList<NativeIdentityEvent>> PollAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<NativeIdentityEvent>>([]);
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

sealed class IdentityTelemetryPipeline : IAsyncDisposable
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly AgentOptions _options; readonly IIdentityCollector _collector; readonly string _queue; readonly string _checkpoint;
    readonly Dictionary<string, (string Entity, DateTimeOffset First, bool Ended)> _logons = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<int, (string Entity, DateTimeOffset First, long Generation, bool Ended)> _sessions = [];
    IdentityTelemetryPolicy _policy = new(); long _sequence, _queueBytes, _drops, _excluded,
        _success, _failed, _logoffs, _sessionEvents, _rdp, _tokens, _privileges, _relationshipFailures,
        _missingLogon; DateTimeOffset? _lastSource, _lastUpload;
    public string CurrentPolicyKey { get; private set; } = "implicit";
    public long QueueDepth => Directory.Exists(_queue) ? Directory.EnumerateFiles(_queue, "*.json").LongCount() : 0;
    public IdentityTelemetryPipeline(AgentOptions options, long sequence)
    {
        _options = options; _sequence = sequence; _collector = string.Equals(Environment.GetEnvironmentVariable("PLATFORM_TELEMETRY_DRAIN_ONLY"), "true", StringComparison.OrdinalIgnoreCase) ? new UnsupportedIdentityCollector() : OperatingSystem.IsWindows() ? new WindowsIdentityCollector() : new UnsupportedIdentityCollector();
        _queue = Path.Combine(options.DataDirectory, "identity-queue"); _checkpoint = Path.Combine(_queue, "sequence.chk"); Directory.CreateDirectory(_queue); Recover();
        _queueBytes = Directory.EnumerateFiles(_queue, "*.json").Sum(x => new FileInfo(x).Length);
        _sequence = Math.Max(_sequence, ReadCheckpoint());
        _sequence = Math.Max(_sequence, Directory.EnumerateFiles(_queue, "*.json").Select(x => long.TryParse(Path.GetFileName(x).Split('-')[0], out var n) ? n : 0).DefaultIfEmpty().Max());
        _collector.StartAsync(default).GetAwaiter().GetResult();
    }
    public Task<IReadOnlyDictionary<string, string[]>> ApplyPolicyAsync(IdentityTelemetryPolicy policy, Guid id, int version)
    { var errors = IdentitySafety.Validate(policy).ToDictionary(x => x.Key, x => x.Value); if (errors.Count == 0) { _policy = policy; CurrentPolicyKey = $"{id:D}:{version}"; } return Task.FromResult<IReadOnlyDictionary<string, string[]>>(errors); }
    public async Task<long> RunOnceAsync(AgentState state, Func<AgentState, HttpClient> clientFactory,
        Func<long, CancellationToken, Task> checkpoint, CancellationToken ct)
    {
        foreach (var native in await _collector.PollAsync(ct))
        {
            _lastSource = native.ObservedAt;
            if (!_policy.Enabled || !Allowed(native)) { Interlocked.Increment(ref _excluded); continue; }
            var observation = Normalize(state, native, Interlocked.Increment(ref _sequence));
            try { await Persist(observation, ct); await WriteCheckpoint(_sequence, ct); await checkpoint(_sequence, ct); }
            catch (IOException) { Interlocked.Increment(ref _drops); }
        }
        if (QueueDepth > 0 && (_lastUpload is null || DateTimeOffset.UtcNow - _lastUpload >= TimeSpan.FromSeconds(_policy.FlushSeconds)))
            for (var drain = 0; drain < 8 && QueueDepth > 0; drain++) await Upload(state, clientFactory, ct);
        return _sequence;
    }
    bool Allowed(NativeIdentityEvent value)
    {
        if (value.Kind == IdentityEventKind.LogonStarted && !_policy.SuccessfulLogons || value.Kind == IdentityEventKind.LogonFailed && !_policy.FailedLogons || value.Kind == IdentityEventKind.Logoff && !_policy.Logoffs || value.Kind is IdentityEventKind.SessionCreated or IdentityEventKind.SessionEnded or IdentityEventKind.SessionStateChanged && !_policy.SessionState || value.Kind is IdentityEventKind.PrivilegeAssigned or IdentityEventKind.PrivilegeUsed && !_policy.SpecialPrivileges || value.Kind is IdentityEventKind.TokenObserved or IdentityEventKind.TokenAssigned && !_policy.TokenState) return false;
        var type = Int(value.Data, "LogonType");
        if (_policy.IncludedLogonTypes is { Length: > 0 } && type is not null && !_policy.IncludedLogonTypes.Contains(type.Value) || _policy.ExcludedLogonTypes?.Contains(type ?? -1) == true) return false;
        var sid = First(value.Data, "TargetUserSid", "SubjectUserSid", "UserSid"); var account = First(value.Data, "TargetUserName", "SubjectUserName", "User"); var domain = First(value.Data, "TargetDomainName", "SubjectDomainName", "DomainName");
        if (_policy.ExcludedSids?.Contains(sid ?? "", StringComparer.OrdinalIgnoreCase) == true || _policy.ExcludedAccounts?.Contains(account ?? "", StringComparer.OrdinalIgnoreCase) == true || _policy.ExcludedDomains?.Contains(domain ?? "", StringComparer.OrdinalIgnoreCase) == true || _policy.ExcludeMachineAccounts && account?.EndsWith('$') == true || _policy.ExcludeServiceAccounts && sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20") return false;
        return true;
    }

    IdentityObservation Normalize(AgentState state, NativeIdentityEvent n, long sequence)
    {
        var data = n.Data; var sid = First(data, "TargetUserSid", "SubjectUserSid", "UserSid", "UserSID");
        var name = First(data, "TargetUserName", "SubjectUserName", "User", "UserName"); var domain = First(data, "TargetDomainName", "SubjectDomainName", "DomainName");
        var account = sid is null && name is null ? null : new AccountIdentity(sid, name, domain,
            string.IsNullOrWhiteSpace(domain) ? name : $"{domain}\\{name}", name?.EndsWith('$'), sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20", SidType(sid), "native");
        var logonId = First(data, "TargetLogonId", "SubjectLogonId", "LogonId"); var logonType = Int(data, "LogonType");
        LogonIdentity? logon = null;
        if (n.Kind is IdentityEventKind.LogonStarted or IdentityEventKind.LogonFailed or IdentityEventKind.Logoff or IdentityEventKind.ExplicitCredentialsObserved or IdentityEventKind.PrivilegeAssigned or IdentityEventKind.PrivilegeUsed or IdentityEventKind.TokenAssigned)
        {
            var key = $"{logonId ?? "unknown"}:{sid ?? "unknown"}"; var existing = _logons.GetValueOrDefault(key);
            var isStart = n.Kind == IdentityEventKind.LogonStarted; var isEnd = n.Kind == IdentityEventKind.Logoff;
            if (existing.Entity is null || existing.Ended && isStart) existing = (IdentitySafety.LogonEntityId(state.EndpointId, state.InstallationId, logonId, sid, n.ObservedAt), n.ObservedAt, false);
            if (isEnd) existing.Ended = true; _logons[key] = existing;
            logon = new(existing.Entity, logonId, logonType, logonType is null ? null : IdentitySafety.LogonTypeLabel(logonType.Value), First(data, "AuthenticationPackageName"), First(data, "LogonProcessName"), First(data, "WorkstationName"), First(data, "WorkstationName", "ClientName"), _policy.SourceIpMetadata ? Ip(First(data, "IpAddress", "Address")) : null, Int(data, "IpPort"), First(data, "LinkedLogonId"), n.Kind == IdentityEventKind.LogonFailed ? "failure" : n.Kind == IdentityEventKind.LogonStarted ? "success" : "observed", First(data, "Status"), First(data, "SubStatus"), First(data, "FailureReason"), existing.First, n.ObservedAt, isStart ? n.ObservedAt : null, isEnd ? n.ObservedAt : null, !isStart && existing.First == n.ObservedAt || !isEnd && existing.Ended);
        }
        WindowsSessionIdentity? session = null; var sessionId = Int(data, "SessionID", "SessionId", "TargetSessionId");
        if (n.Kind is IdentityEventKind.SessionCreated or IdentityEventKind.SessionEnded or IdentityEventKind.SessionStateChanged)
        {
            var id = sessionId ?? -1; var existing = _sessions.GetValueOrDefault(id); var start = n.Kind == IdentityEventKind.SessionCreated; var end = n.Kind == IdentityEventKind.SessionEnded;
            if (existing.Entity is null || existing.Ended && start) { var generation = existing.Generation + 1; existing = (IdentitySafety.SessionEntityId(state.EndpointId, state.InstallationId, sessionId, generation), n.ObservedAt, generation, false); }
            if (end) existing.Ended = true; _sessions[id] = existing; var address = _policy.SourceIpMetadata ? Ip(First(data, "Address", "ClientAddress")) : null;
            session = new(existing.Entity, sessionId, sessionId, "RDP", address is not null, address, First(data, "ClientName"), n.Native.NativeOperation, existing.First, n.ObservedAt, start ? n.ObservedAt : null, end ? n.ObservedAt : null, existing.Generation); Interlocked.Increment(ref _sessionEvents); Interlocked.Increment(ref _rdp);
        }
        TokenIdentity? token = null; IdentityProcessRelationship? process = null; var privileges = Array.Empty<PrivilegeIdentity>(); var groups = Array.Empty<GroupIdentity>();
        if (n.Token is { } t)
        {
            var processEntity = ProcessIdentity.Create(state.EndpointId, t.ProcessId, t.ProcessStart, $"windows:{t.ProcessStart.UtcTicks}");
            process = new(processEntity, t.ProcessId, t.ProcessStart, t.ImagePath, t.SessionId, "process-token-handle", "high", true);
            token = new(IdentitySafety.TokenEntityId(state.EndpointId, processEntity, t.TokenType, t.UserSid), "bounded-state-snapshot", t.TokenType, t.ImpersonationLevel, t.ElevationType, t.Elevated, t.IntegrityLevel, t.IntegritySid, t.Restricted, t.AppContainer, t.VirtualizationAllowed, t.VirtualizationEnabled, t.SessionId, "Windows Token API", null, n.ObservedAt, n.ObservedAt);
            privileges = t.Privileges.Take(_policy.MaximumPrivileges).Select(x => new PrivilegeIdentity(x, "present", null, null, null, null, "token-state")).ToArray(); groups = _policy.GroupContext ? t.Groups.Take(_policy.MaximumGroups).ToArray() : []; Interlocked.Increment(ref _tokens); Interlocked.Add(ref _privileges, privileges.Length);
        }
        else if (n.Kind is IdentityEventKind.PrivilegeAssigned or IdentityEventKind.PrivilegeUsed)
        {
            privileges = (First(data, "PrivilegeList", "Privilege") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(IdentitySafety.ValidPrivilege).Take(_policy.MaximumPrivileges).Select(x => new PrivilegeIdentity(x, n.Kind == IdentityEventKind.PrivilegeUsed ? "used" : "assigned", null, null, null, n.Kind == IdentityEventKind.PrivilegeUsed, "security-event-log")).ToArray(); Interlocked.Add(ref _privileges, privileges.Length);
        }
        if (process is null && Int(data, "ProcessId", "NewProcessId") is { } pid && pid > 0)
        {
            try { using var p = Process.GetProcessById(pid); var started = new DateTimeOffset(p.StartTime.ToUniversalTime()); process = new(ProcessIdentity.Create(state.EndpointId, pid, started, $"windows:{started.UtcTicks}"), pid, started, Try(() => p.MainModule?.FileName), Try(() => p.SessionId), "native-pid-plus-process-start", "high", true); }
            catch { Interlocked.Increment(ref _relationshipFailures); }
        }
        var quality = new List<string>(n.Quality ?? []); if (sid is null && account is not null) quality.Add("account-sid-unavailable"); if (logon is not null && logon.LogonId is null) { quality.Add("logon-id-unavailable"); Interlocked.Increment(ref _missingLogon); }
        switch (n.Kind) { case IdentityEventKind.LogonStarted: Interlocked.Increment(ref _success); break; case IdentityEventKind.LogonFailed: Interlocked.Increment(ref _failed); break; case IdentityEventKind.Logoff: Interlocked.Increment(ref _logoffs); break; }
        return new(Guid.NewGuid(), "identity-event.v1", n.Kind, state.EndpointId, state.AgentId, state.InstallationId,
            $"{_collector.GetType().Name}:{Environment.MachineName}", n.Native.Provider, "1.0.0", "windows", n.Native,
            sequence, n.ObservedAt, null, null, "identity-normalization.v1", IdentitySafety.EvidenceHash(new { n.Native, data }), quality.Distinct(StringComparer.Ordinal).ToArray(), quality.Count == 0 ? "complete" : "partial", account, logon, session, token, privileges, groups, process, account?.CanonicalName);
    }

    public IdentityTelemetryHealth Health(Guid endpoint) => new(endpoint, _policy.Enabled, _collector.SecurityState,
        _collector.SessionState, _collector.TokenState, _lastSource, null, _success, _failed, _logoffs,
        _sessionEvents, _rdp, _tokens, _privileges, _relationshipFailures, _missingLogon,
        _collector.LostEvents, 0, QueueDepth, Oldest(), _drops, _excluded, 0, 0, CurrentPolicyKey,
        ParseVersion(), false, _lastUpload, _sequence, _collector.Elevated, _collector.KnownLimitations);
    async Task Persist(IdentityObservation value, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, Json); if (Interlocked.Read(ref _queueBytes) + bytes.Length > _policy.MaximumQueueBytes) throw new IOException("identity-queue-capacity-exceeded");
        var final = Path.Combine(_queue, $"{value.Sequence:D20}-{value.EventId:N}.json"); var temp = final + ".tmp";
        await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { await stream.WriteAsync(bytes, ct); await stream.FlushAsync(ct); stream.Flush(true); }
        File.Move(temp, final + ".committing"); File.Move(final + ".committing", final); Interlocked.Add(ref _queueBytes, bytes.Length);
    }
    async Task Upload(AgentState state, Func<AgentState, HttpClient> clientFactory, CancellationToken ct)
    {
        var items = new List<(string Path, IdentityObservation Event)>();
        foreach (var path in Directory.EnumerateFiles(_queue, "*.json").OrderBy(x => x))
        {
            try
            {
                var value = JsonSerializer.Deserialize<IdentityObservation>(await File.ReadAllBytesAsync(path, ct), Json);
                if (value is not null) items.Add((path, value));
                else QuarantineCorrupt(path, "empty-payload");
            }
            catch (Exception e) when (e is JsonException or IOException)
            {
                QuarantineCorrupt(path, e is JsonException ? "invalid-json" : "read-failure");
            }
            if (items.Count >= _policy.MaximumBatchEvents) break;
        }
        if (items.Count == 0) return; var events = items.Select(x => x.Event).ToArray(); var eventBytes = JsonSerializer.SerializeToUtf8Bytes(events, Json); var draft = new IdentityEventBatch(Guid.NewGuid(), state.EndpointId, state.AgentId, state.InstallationId, events.Min(x => x.Sequence), events.Max(x => x.Sequence), events, Convert.ToHexString(SHA256.HashData(eventBytes)).ToLowerInvariant()); var canonical = JsonSerializer.SerializeToUtf8Bytes(draft, Json);
        await using var compressed = new MemoryStream(); await using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, true)) await gzip.WriteAsync(canonical, ct); using var content = new ByteArrayContent(compressed.ToArray()); content.Headers.ContentType = new("application/json"); content.Headers.ContentEncoding.Add("gzip"); content.Headers.Add("X-Uncompressed-Length", canonical.Length.ToString(CultureInfo.InvariantCulture)); content.Headers.Add("X-Identity-Health", Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(Health(state.EndpointId), Json)));
        using var client = clientFactory(state); using var response = await client.PostAsync("/agent/v1/identity-event-batches", content, ct); response.EnsureSuccessStatusCode(); var ack = await response.Content.ReadFromJsonAsync<IdentityBatchAcknowledgement>(Json, ct) ?? throw new InvalidDataException("Identity acknowledgement invalid."); var done = ack.AcceptedEventIds.Concat(ack.DuplicateEventIds).ToHashSet(); foreach (var item in items.Where(x => done.Contains(x.Event.EventId))) { var length = new FileInfo(item.Path).Length; File.Delete(item.Path); Interlocked.Add(ref _queueBytes, -length); }
        foreach (var item in items.Where(x => ack.RejectedEventIds.ContainsKey(x.Event.EventId))) { var length = new FileInfo(item.Path).Length; var quarantine = Path.Combine(_queue, "quarantine"); Directory.CreateDirectory(quarantine); var reason = new string(ack.RejectedEventIds[item.Event.EventId].Where(char.IsLetterOrDigit).Take(64).ToArray()); File.Move(item.Path, Path.Combine(quarantine, $"{Path.GetFileNameWithoutExtension(item.Path)}.rejected-{reason}.json"), true); Interlocked.Add(ref _queueBytes, -length); }
        _lastUpload = DateTimeOffset.UtcNow;
    }
    void QuarantineCorrupt(string path, string reason)
    {
        var length = new FileInfo(path).Length; var quarantine = Path.Combine(_queue, "quarantine"); Directory.CreateDirectory(quarantine);
        File.Move(path, Path.Combine(quarantine, $"{Path.GetFileNameWithoutExtension(path)}.corrupt-{reason}.json"), true);
        Interlocked.Add(ref _queueBytes, -length); Interlocked.Increment(ref _drops);
    }
    long ReadCheckpoint() { try { return long.TryParse(File.ReadAllText(_checkpoint), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? Math.Max(0, value) : 0; } catch (IOException) { return 0; } }
    async Task WriteCheckpoint(long value, CancellationToken ct) { var temp = _checkpoint + ".tmp"; await File.WriteAllTextAsync(temp, value.ToString(CultureInfo.InvariantCulture), ct); File.Move(temp, _checkpoint, true); }
    void Recover() { foreach (var path in Directory.EnumerateFiles(_queue, "*.tmp").Concat(Directory.EnumerateFiles(_queue, "*.committing")).ToArray()) { try { var final = path.EndsWith(".committing", StringComparison.Ordinal) ? path[..^11] : path[..^4]; if (!File.Exists(final)) File.Move(path, final); else File.Delete(path); } catch (IOException) { } } }
    long Oldest() { var files = Directory.EnumerateFiles(_queue, "*.json").Select(x => new FileInfo(x)).ToArray(); return files.Length == 0 ? 0 : (long)Math.Max(0, (DateTimeOffset.UtcNow - files.Min(x => x.CreationTimeUtc)).TotalSeconds); }
    int? ParseVersion() => int.TryParse(CurrentPolicyKey.Split(':').LastOrDefault(), out var value) ? value : null;
    static string? First(IReadOnlyDictionary<string, string> data, params string[] names) { foreach (var name in names) if (data.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) && value != "-") return value; return null; }
    static int? Int(IReadOnlyDictionary<string, string> data, params string[] names) { var value = First(data, names); if (value is null) return null; if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && int.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex)) return hex; return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) ? number : null; }
    static string? Ip(string? value) => IPAddress.TryParse(value, out var address) ? address.ToString() : null;
    static string? SidType(string? sid) => sid switch { "S-1-5-18" => "LocalSystem", "S-1-5-19" => "LocalService", "S-1-5-20" => "NetworkService", null => null, _ when sid.EndsWith("-500", StringComparison.Ordinal) => "Administrator", _ => "Account" };
    static T? Try<T>(Func<T> value) { try { return value(); } catch { return default; } }
    public async ValueTask DisposeAsync() => await _collector.DisposeAsync();
}

[SupportedOSPlatform("windows")]
static class TokenInspector
{
    const uint TokenQuery = 0x0008;
    enum TokenInformationClass { TokenUser = 1, TokenGroups = 2, TokenPrivileges = 3, TokenType = 8, TokenImpersonationLevel = 9, TokenSessionId = 12, TokenElevationType = 18, TokenElevation = 20, TokenHasRestrictions = 21, TokenVirtualizationAllowed = 23, TokenVirtualizationEnabled = 24, TokenIntegrityLevel = 25, TokenIsAppContainer = 29 }
    [StructLayout(LayoutKind.Sequential)] struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct LuidAndAttributes { public long Luid; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(SafeAccessTokenHandle token, TokenInformationClass infoClass, IntPtr info, int length, out int returnLength);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool LookupPrivilegeName(string? system, ref long luid, [Out] char[]? name, ref int length);
    public static NativeTokenSnapshot? TryRead(Process process)
    {
        if (!OpenProcessToken(process.Handle, TokenQuery, out var token)) return null; using (token)
        {
            var sid = Sid(token, TokenInformationClass.TokenUser); var session = Int(token, TokenInformationClass.TokenSessionId); var typeValue = Int(token, TokenInformationClass.TokenType); var impersonation = typeValue == 2 ? Impersonation(Int(token, TokenInformationClass.TokenImpersonationLevel)) : null; var elevationType = Elevation(Int(token, TokenInformationClass.TokenElevationType)); var elevated = Int(token, TokenInformationClass.TokenElevation) == 1; var integritySid = Sid(token, TokenInformationClass.TokenIntegrityLevel); var integrity = Integrity(integritySid); var privileges = Privileges(token); var groups = Groups(token); var started = new DateTimeOffset(process.StartTime.ToUniversalTime()); var path = Try(() => process.MainModule?.FileName); var fingerprint = IdentitySafety.EvidenceHash(new { process.Id, started, sid, session, typeValue, impersonation, elevationType, elevated, integritySid, privileges, groups });
            return new(process.Id, started, path, sid, session, typeValue == 2 ? "impersonation" : "primary", impersonation, elevationType, elevated, integrity, integritySid, Int(token, TokenInformationClass.TokenHasRestrictions) == 1, Int(token, TokenInformationClass.TokenIsAppContainer) == 1, Int(token, TokenInformationClass.TokenVirtualizationAllowed) == 1, Int(token, TokenInformationClass.TokenVirtualizationEnabled) == 1, privileges, groups, fingerprint);
        }
    }
    static T? WithBuffer<T>(SafeAccessTokenHandle token, TokenInformationClass kind, Func<IntPtr, int, T> read)
    {
        GetTokenInformation(token, kind, IntPtr.Zero, 0, out var needed);
        if (needed <= 0 || needed > 16 * 1024 * 1024) return default;
        var pointer = Marshal.AllocHGlobal(needed);
        try { return GetTokenInformation(token, kind, pointer, needed, out _) ? read(pointer, needed) : default; }
        finally { Marshal.FreeHGlobal(pointer); }
    }
    static int? Int(SafeAccessTokenHandle token, TokenInformationClass kind) => WithBuffer<int?>(token, kind, (pointer, length) => length >= 4 ? Marshal.ReadInt32(pointer) : null);
    static string? Sid(SafeAccessTokenHandle token, TokenInformationClass kind) => WithBuffer<string?>(token, kind, (pointer, _) =>
    {
        var sidPointer = Marshal.ReadIntPtr(pointer);
        if (sidPointer == IntPtr.Zero) return null;
        try { return new SecurityIdentifier(sidPointer).Value; } catch (ArgumentException) { return null; }
    });
    static string[] Privileges(SafeAccessTokenHandle token) => WithBuffer<string[]>(token, TokenInformationClass.TokenPrivileges, (pointer, length) =>
    {
        if (length < 4) return [];
        var count = Math.Min(Marshal.ReadInt32(pointer), 512); var size = Marshal.SizeOf<LuidAndAttributes>(); var offset = IntPtr.Size == 8 ? 8 : 4; var result = new List<string>();
        for (var i = 0; i < count && offset + size <= length; i++, offset += size) { var entry = Marshal.PtrToStructure<LuidAndAttributes>(IntPtr.Add(pointer, offset)); var nameLength = 0; LookupPrivilegeName(null, ref entry.Luid, null, ref nameLength); if (nameLength is <= 0 or > 256) continue; var buffer = new char[nameLength + 1]; if (LookupPrivilegeName(null, ref entry.Luid, buffer, ref nameLength)) { var name = new string(buffer, 0, nameLength); if (IdentitySafety.ValidPrivilege(name)) result.Add(name); } }
        return result.Distinct(StringComparer.Ordinal).ToArray();
    }) ?? [];
    static GroupIdentity[] Groups(SafeAccessTokenHandle token) => WithBuffer<GroupIdentity[]>(token, TokenInformationClass.TokenGroups, (pointer, length) =>
    {
        if (length < 4) return [];
        var count = Math.Min(Marshal.ReadInt32(pointer), 1024); var size = Marshal.SizeOf<SidAndAttributes>(); var offset = IntPtr.Size == 8 ? 8 : 4; var result = new List<GroupIdentity>();
        for (var i = 0; i < count && offset + size <= length; i++, offset += size) { var entry = Marshal.PtrToStructure<SidAndAttributes>(IntPtr.Add(pointer, offset)); try { var sid = new SecurityIdentifier(entry.Sid).Value; result.Add(new(sid, null, entry.Attributes, "token-state")); } catch (ArgumentException) { } }
        return result.ToArray();
    }) ?? [];
    static string Elevation(int? value) => value switch { 1 => "Default", 2 => "Full", 3 => "Limited", _ => "Unknown" };
    static string? Impersonation(int? value) => value switch { 0 => "Anonymous", 1 => "Identification", 2 => "Impersonation", 3 => "Delegation", _ => null };
    static string Integrity(string? sid) { if (sid is null) return "Unknown"; var last = sid.Split('-').LastOrDefault(); return int.TryParse(last, NumberStyles.Integer, CultureInfo.InvariantCulture, out var level) ? level switch { < 4096 => "Untrusted", < 8192 => "Low", < 12288 => "Medium", < 16384 => "High", >= 16384 => "System" } : "Unknown"; }
    static T? Try<T>(Func<T> value) { try { return value(); } catch { return default; } }
}
