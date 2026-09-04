using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO.Compression;
using System.Management;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using OpenSecurityPlatform.Foundation;

sealed record NativeServiceSnapshot(string Name, string? DisplayName, string? Type, string? StartupType,
    string? ErrorControl, string? BinaryPath, string? Account, string? Description,
    string[] Dependencies, bool Driver, bool Interactive, string Fingerprint);
sealed record NativeConfigurationSnapshot(string Category, string Subtype, string NativeIdentity,
    string? NamespaceOrLocation, string Name, string? RegistryPath, string? RegistryView,
    string? Scope, string? FilePath, string? ActionPath, string? Arguments, string? Principal,
    string? TriggerMetadata, string? ConsumerMetadata, string? BindingIdentity,
    string? FilterIdentity, string? ConsumerIdentity, string Fingerprint);
sealed record NativePersistenceEvent(PersistenceObjectKind ObjectKind, PersistenceEventKind Kind,
    DateTimeOffset ObservedAt, NativeEventIdentity Identity, IReadOnlyDictionary<string, string> Data,
    NativeServiceSnapshot? ServiceSnapshot = null, string? TaskXml = null, long Generation = 0,
    string[]? Quality = null, NativeConfigurationSnapshot? ConfigurationSnapshot = null);

interface IPersistenceCollector : IAsyncDisposable
{
    string ServiceState { get; }
    string TaskState { get; }
    string ConfigurationState { get; }
    bool Elevated { get; }
    long LostEvents { get; }
    string[] KnownLimitations { get; }
    Task StartAsync(CancellationToken ct);
    Task<IReadOnlyList<NativePersistenceEvent>> PollAsync(CancellationToken ct);
}

[SupportedOSPlatform("windows")]
sealed class WindowsServiceTaskCollector(string dataDirectory) : IPersistenceCollector
{
    const string TaskChannel = "Microsoft-Windows-TaskScheduler/Operational";
    const string TaskProvider = "Microsoft-Windows-TaskScheduler";
    const string ScmProvider = "Service Control Manager";
    const int MaximumBufferedEvents = 50_000;
    readonly ConcurrentQueue<NativePersistenceEvent> _events = [];
    readonly Dictionary<string, NativeServiceSnapshot> _services = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, uint> _serviceStates = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, long> _serviceGenerations = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, long> _taskGenerations = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, NativeConfigurationSnapshot> _configurations = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, long> _configurationGenerations = new(StringComparer.OrdinalIgnoreCase);
    readonly string _generationPath = Path.Combine(dataDirectory, "persistence-generations.json");
    EventLogWatcher? _serviceWatcher, _taskWatcher;
    DateTimeOffset _lastConfigurationSnapshot = DateTimeOffset.MinValue;
    DateTimeOffset _lastStateSnapshot = DateTimeOffset.MinValue;
    DateTimeOffset _lastPersistenceConfigurationSnapshot = DateTimeOffset.MinValue;
    long _queued, _overflow;

    public string ServiceState { get; private set; } = "stopped";
    public string TaskState { get; private set; } = "stopped";
    public string ConfigurationState { get; private set; } = "stopped";
    public bool Elevated => OperatingSystem.IsWindows() && new System.Security.Principal.WindowsPrincipal(
        System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    public long LostEvents => Interlocked.Read(ref _overflow);
    public string[] KnownLimitations =>
    [
        "Service deletion and full configuration deltas are native registry snapshot boundaries, not SCM actor events.",
        "SCM state events do not identify the initiating user.",
        "Task process relationships require Task Scheduler event 129 and may remain PID-only after a short-lived process exits."
    ];

    public Task StartAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) { ServiceState = TaskState = "unsupported"; return Task.CompletedTask; }
        LoadGenerations();
        foreach (var item in CaptureServices()) _services[item.Key] = item.Value;
        foreach (var item in CaptureServiceStates(_services.Keys)) _serviceStates[item.Key] = item.Value;
        try { foreach (var item in CaptureConfigurations()) _configurations[item.Key] = item.Value; ConfigurationState = "healthy"; }
        catch (Exception exception) when (exception is ManagementException or UnauthorizedAccessException or SecurityException or COMException) { ConfigurationState = $"degraded:{exception.GetType().Name}"; }
        try
        {
            _serviceWatcher = new EventLogWatcher(new EventLogQuery("System", PathType.LogName,
                "*[System[Provider[@Name='Service Control Manager'] and (EventID=7036 or EventID=7040 or EventID=7045)]]"));
            _serviceWatcher.EventRecordWritten += OnService;
            _serviceWatcher.Enabled = true;
            ServiceState = "healthy";
        }
        catch (EventLogException) { ServiceState = "failed"; }
        try
        {
            using var cfg = new EventLogConfiguration(TaskChannel);
            if (!cfg.IsEnabled) { TaskState = "channel-disabled"; }
            else
            {
                _taskWatcher = new EventLogWatcher(new EventLogQuery(TaskChannel, PathType.LogName,
                    "*[System[(EventID=100 or EventID=102 or EventID=106 or EventID=129 or EventID=140 or EventID=141 or EventID=142 or EventID=200 or EventID=201)]]"));
                _taskWatcher.EventRecordWritten += OnTask;
                _taskWatcher.Enabled = true;
                TaskState = "healthy";
            }
        }
        catch (EventLogException) { TaskState = "failed"; }
        _lastConfigurationSnapshot = _lastStateSnapshot = _lastPersistenceConfigurationSnapshot = DateTimeOffset.UtcNow;
        return Task.CompletedTask;
    }

    void OnService(object? sender, EventRecordWrittenEventArgs args)
    {
        if (args.EventException is not null) { Interlocked.Increment(ref _overflow); return; }
        using var record = args.EventRecord;
        if (record is null) return;
        try
        {
            var data = EventData(record);
            var kind = record.Id switch
            {
                7045 => PersistenceEventKind.ServiceCreated,
                7040 => PersistenceEventKind.ServiceConfigurationChanged,
                7036 when State(data) == "running" => PersistenceEventKind.ServiceStarted,
                7036 when State(data) == "stopped" => PersistenceEventKind.ServiceStopped,
                _ => PersistenceEventKind.ServiceStateChanged
            };
            var name = ServiceName(data);
            var generation = Generation(_serviceGenerations, name, kind == PersistenceEventKind.ServiceCreated);
            Enqueue(new(PersistenceObjectKind.Service, kind, record.TimeCreated is { } t ? new(t.ToUniversalTime()) : DateTimeOffset.UtcNow,
                Identity(record, record.Id == 7045 ? "install" : record.Id == 7040 ? "start-type-change" : "state-transition", State(data)), data,
                Snapshot(name), Generation: generation));
        }
        catch (Exception exception) when (exception is EventLogException or XmlException or InvalidOperationException or ArgumentException)
        { Interlocked.Increment(ref _overflow); }
    }

    void OnTask(object? sender, EventRecordWrittenEventArgs args)
    {
        if (args.EventException is not null) { Interlocked.Increment(ref _overflow); return; }
        using var record = args.EventRecord;
        if (record is null) return;
        try
        {
            var data = EventData(record);
            var kind = record.Id switch
            {
                106 => PersistenceEventKind.ScheduledTaskRegistered,
                140 => PersistenceEventKind.ScheduledTaskUpdated,
                141 => PersistenceEventKind.ScheduledTaskDeleted,
                142 => PersistenceEventKind.ScheduledTaskDisabled,
                100 or 200 or 129 => PersistenceEventKind.ScheduledTaskExecutionStarted,
                102 or 201 => PersistenceEventKind.ScheduledTaskExecutionCompleted,
                _ => PersistenceEventKind.ScheduledTaskUpdated
            };
            var path = Value(data, "TaskName") ?? "";
            var generation = Generation(_taskGenerations, path, kind == PersistenceEventKind.ScheduledTaskRegistered);
            var xml = kind is PersistenceEventKind.ScheduledTaskRegistered or PersistenceEventKind.ScheduledTaskUpdated ? TryTaskXml(path) : null;
            Enqueue(new(PersistenceObjectKind.ScheduledTask, kind, record.TimeCreated is { } t ? new(t.ToUniversalTime()) : DateTimeOffset.UtcNow,
                Identity(record, kind.ToString(), Value(data, "ResultCode")), data, TaskXml: xml,
                Generation: generation, Quality: record.Id is 100 or 200 ? ["execution-start-evidence"] : []));
            if (kind == PersistenceEventKind.ScheduledTaskDeleted) SaveGenerations();
        }
        catch (Exception exception) when (exception is EventLogException or XmlException or InvalidOperationException or ArgumentException)
        { Interlocked.Increment(ref _overflow); }
    }

    public Task<IReadOnlyList<NativePersistenceEvent>> PollAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        if (now - _lastConfigurationSnapshot >= TimeSpan.FromSeconds(5))
        {
            CompareServiceSnapshot();
            _lastConfigurationSnapshot = now;
        }
        if (now - _lastStateSnapshot >= TimeSpan.FromMilliseconds(250)) { CompareServiceStates(); _lastStateSnapshot = now; }
        if (now - _lastPersistenceConfigurationSnapshot >= TimeSpan.FromSeconds(5))
        {
            ComparePersistenceConfigurations();
            _lastPersistenceConfigurationSnapshot = now;
        }
        var result = new List<NativePersistenceEvent>();
        while (result.Count < 200 && _events.TryDequeue(out var item)) { Interlocked.Decrement(ref _queued); result.Add(item); }
        return Task.FromResult<IReadOnlyList<NativePersistenceEvent>>(result);
    }

    void CompareServiceSnapshot()
    {
        var next = CaptureServices();
        foreach (var item in next)
        {
            if (!_services.TryGetValue(item.Key, out var before))
            {
                var generation = Generation(_serviceGenerations, item.Key, true);
                Enqueue(SnapshotEvent(PersistenceEventKind.ServiceCreated, item.Value, generation, "key-appeared", ["snapshot-boundary"]));
            }
            else if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(before.Fingerprint), Encoding.ASCII.GetBytes(item.Value.Fingerprint)))
            {
                var generation = Generation(_serviceGenerations, item.Key, false);
                Enqueue(SnapshotEvent(PersistenceEventKind.ServiceConfigurationChanged, item.Value, generation, "configuration-delta", ["snapshot-boundary"]));
            }
        }
        foreach (var item in _services.Where(x => !next.ContainsKey(x.Key)))
        {
            var generation = Generation(_serviceGenerations, item.Key, false);
            Enqueue(SnapshotEvent(PersistenceEventKind.ServiceDeleted, item.Value, generation, "key-disappeared", ["snapshot-boundary"]));
        }
        _services.Clear(); foreach (var item in next) _services[item.Key] = item.Value;
        SaveGenerations();
    }

    void CompareServiceStates()
    {
        var next = CaptureServiceStates(_services.Keys);
        foreach (var item in next)
        {
            if (_serviceStates.TryGetValue(item.Key, out var before) && before != item.Value)
            {
                var kind = item.Value == 4 ? PersistenceEventKind.ServiceStarted
                    : item.Value == 1 ? PersistenceEventKind.ServiceStopped
                    : PersistenceEventKind.ServiceStateChanged;
                var status = item.Value switch { 1 => "stopped", 2 => "start-pending", 3 => "stop-pending", 4 => "running", 5 => "continue-pending", 6 => "pause-pending", 7 => "paused", _ => $"native:{item.Value}" };
                if (Snapshot(item.Key) is { } snapshot)
                    Enqueue(new(PersistenceObjectKind.Service, kind, DateTimeOffset.UtcNow,
                        new("Service Control Manager API", "Windows Service Control Manager", null, 0, 1, null, null, null, null,
                            "status-snapshot-transition", status),
                        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["ServiceName"] = item.Key, ["State"] = status },
                        snapshot, Generation: Generation(_serviceGenerations, item.Key, false), Quality: ["snapshot-boundary"]));
            }
        }
        _serviceStates.Clear(); foreach (var item in next) _serviceStates[item.Key] = item.Value;
    }

    static Dictionary<string, uint> CaptureServiceStates(IEnumerable<string> names)
    {
        var result = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
        using var manager = OpenScManager(null, null, 0x0001); if (manager.IsInvalid) return result;
        foreach (var name in names)
        {
            using var service = OpenScService(manager, name, 0x0004); if (service.IsInvalid) continue;
            var size = Marshal.SizeOf<CollectorServiceStatusProcess>();
            if (QueryScServiceStatusEx(service, 0, out var status, size, out _)) result[name] = status.CurrentState;
        }
        return result;
    }

    [StructLayout(LayoutKind.Sequential)] struct CollectorServiceStatusProcess { public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags; }
    sealed class CollectorScHandle : SafeHandleZeroOrMinusOneIsInvalid { CollectorScHandle() : base(true) { } protected override bool ReleaseHandle() => CloseScServiceHandle(handle); }
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenSCManagerW")] static extern CollectorScHandle OpenScManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenServiceW")] static extern CollectorScHandle OpenScService(CollectorScHandle manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "QueryServiceStatusEx")] static extern bool QueryScServiceStatusEx(CollectorScHandle service, int infoLevel, out CollectorServiceStatusProcess status, int size, out int needed);
    [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle")] static extern bool CloseScServiceHandle(IntPtr handle);

    static NativePersistenceEvent SnapshotEvent(PersistenceEventKind kind, NativeServiceSnapshot snapshot,
        long generation, string operation, string[] quality) => new(PersistenceObjectKind.Service, kind,
            DateTimeOffset.UtcNow, new("HKLM\\SYSTEM\\CurrentControlSet\\Services", "Windows Registry API", null,
                0, 1, null, null, null, null, operation, null),
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["ServiceName"] = snapshot.Name },
            snapshot, Generation: generation, Quality: quality);

    static Dictionary<string, NativeServiceSnapshot> CaptureServices()
    {
        var result = new Dictionary<string, NativeServiceSnapshot>(StringComparer.OrdinalIgnoreCase);
        using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
        if (root is null) return result;
        foreach (var name in root.GetSubKeyNames().Where(x => PersistenceSafety.SafeName(x, 256)))
        {
            try { using var key = root.OpenSubKey(name, false); if (key is null) continue; var snapshot = ReadSnapshot(name, key); result[name] = snapshot; }
            catch (Exception exception) when (exception is SecurityException or UnauthorizedAccessException or IOException) { }
        }
        return result;
    }

    static NativeServiceSnapshot ReadSnapshot(string name, RegistryKey key)
    {
        string? S(string value) => key.GetValue(value, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString();
        int? I(string value) => key.GetValue(value) is int number ? number : null;
        var typeValue = I("Type"); var startValue = I("Start"); var errorValue = I("ErrorControl");
        var dependencies = key.GetValue("DependOnService") is string[] values ? values.Where(x => PersistenceSafety.SafeName(x, 1024)).Take(64).ToArray() : [];
        var snapshot = new NativeServiceSnapshot(name, S("DisplayName"), ServiceType(typeValue), StartType(startValue),
            ErrorControl(errorValue), S("ImagePath"), S("ObjectName"), S("Description"), dependencies,
            typeValue is 1 or 2, typeValue is { } type && (type & 0x100) != 0, "");
        return snapshot with { Fingerprint = PersistenceSafety.EvidenceHash(snapshot with { Fingerprint = "" }) };
    }

    static string? ServiceType(int? value) => value switch { 1 => "kernel-driver", 2 => "file-system-driver", 16 => "own-process", 32 => "shared-process", 272 => "interactive-own-process", 288 => "interactive-shared-process", null => null, _ => $"native:{value}" };
    static string? StartType(int? value) => value switch { 0 => "boot", 1 => "system", 2 => "automatic", 3 => "manual", 4 => "disabled", null => null, _ => $"native:{value}" };
    static string? ErrorControl(int? value) => value switch { 0 => "ignore", 1 => "normal", 2 => "severe", 3 => "critical", null => null, _ => $"native:{value}" };
    NativeServiceSnapshot? Snapshot(string name) => _services.TryGetValue(name, out var value) ? value : CaptureOne(name);
    static NativeServiceSnapshot? CaptureOne(string name) { try { using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}", false); return key is null ? null : ReadSnapshot(name, key); } catch { return null; } }

    void ComparePersistenceConfigurations()
    {
        Dictionary<string, NativeConfigurationSnapshot> next;
        try { next = CaptureConfigurations(); ConfigurationState = "healthy"; }
        catch (Exception exception) when (exception is ManagementException or UnauthorizedAccessException or SecurityException or COMException)
        { ConfigurationState = $"degraded:{exception.GetType().Name}"; Interlocked.Increment(ref _overflow); return; }
        foreach (var item in next)
        {
            if (!_configurations.TryGetValue(item.Key, out var before)) EmitConfiguration(item.Value, ConfigurationKind(item.Value, "created"), true, "state-appeared");
            else if (!string.Equals(before.Fingerprint, item.Value.Fingerprint, StringComparison.Ordinal)) EmitConfiguration(item.Value, ConfigurationKind(item.Value, "modified"), false, "state-changed");
        }
        foreach (var item in _configurations.Where(x => !next.ContainsKey(x.Key))) EmitConfiguration(item.Value, ConfigurationKind(item.Value, "deleted"), false, "state-disappeared");
        _configurations.Clear(); foreach (var item in next) _configurations[item.Key] = item.Value;
        SaveGenerations();
    }

    void EmitConfiguration(NativeConfigurationSnapshot snapshot, PersistenceEventKind kind, bool begin, string operation)
    {
        var generation = Generation(_configurationGenerations, snapshot.NativeIdentity, begin);
        var provider = snapshot.Category.StartsWith("wmi-", StringComparison.Ordinal) ? "Windows Management Instrumentation repository"
            : snapshot.Category == "startup-item" ? "Windows File System API" : "Windows Registry API";
        var source = snapshot.NamespaceOrLocation ?? snapshot.RegistryPath ?? snapshot.FilePath ?? "Windows persistence configuration";
        Enqueue(new(PersistenceObjectKind.PersistenceConfiguration, kind, DateTimeOffset.UtcNow,
            new(source, provider, null, 0, 1, null, null, null, null, operation, null),
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["ObjectName"] = snapshot.Name },
            Generation: generation, Quality: ["snapshot-boundary"], ConfigurationSnapshot: snapshot));
    }

    static PersistenceEventKind ConfigurationKind(NativeConfigurationSnapshot value, string operation) => (value.Category, operation) switch
    {
        ("wmi-filter", "created") => PersistenceEventKind.WmiFilterCreated,
        ("wmi-filter", "modified") => PersistenceEventKind.WmiFilterModified,
        ("wmi-filter", _) => PersistenceEventKind.WmiFilterDeleted,
        ("wmi-consumer", "created") => PersistenceEventKind.WmiConsumerCreated,
        ("wmi-consumer", "modified") => PersistenceEventKind.WmiConsumerModified,
        ("wmi-consumer", _) => PersistenceEventKind.WmiConsumerDeleted,
        ("wmi-binding", "created") => PersistenceEventKind.WmiBindingCreated,
        ("wmi-binding", "deleted") => PersistenceEventKind.WmiBindingDeleted,
        ("com-registration", "created") => PersistenceEventKind.ComRegistrationCreated,
        ("com-registration", "modified") => PersistenceEventKind.ComRegistrationModified,
        ("com-registration", _) => PersistenceEventKind.ComRegistrationDeleted,
        ("startup-item", "created") => PersistenceEventKind.StartupItemCreated,
        ("startup-item", "modified") => PersistenceEventKind.StartupItemModified,
        ("startup-item", _) => PersistenceEventKind.StartupItemDeleted,
        (_, "created") => PersistenceEventKind.AutorunCreated,
        (_, "modified") => PersistenceEventKind.AutorunModified,
        (_, "deleted") => PersistenceEventKind.AutorunDeleted,
        _ => PersistenceEventKind.PersistenceConfigurationObserved
    };

    static Dictionary<string, NativeConfigurationSnapshot> CaptureConfigurations()
    {
        var result = new Dictionary<string, NativeConfigurationSnapshot>(StringComparer.OrdinalIgnoreCase);
        CaptureWmi(result); CaptureRegistryPersistence(result); CaptureStartupFolders(result);
        return result;
    }

    static void CaptureWmi(Dictionary<string, NativeConfigurationSnapshot> result)
    {
        var scope = new ManagementScope(@"\\.\root\subscription"); scope.Connect();
        CaptureWmiClass(scope, "__EventFilter", "wmi-filter", result);
        CaptureWmiClass(scope, "__EventConsumer", "wmi-consumer", result);
        CaptureWmiClass(scope, "__FilterToConsumerBinding", "wmi-binding", result);
    }

    static void CaptureWmiClass(ManagementScope scope, string className, string category,
        Dictionary<string, NativeConfigurationSnapshot> result)
    {
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM {className}"));
        using var objects = searcher.Get(); var count = 0;
        foreach (ManagementBaseObject item in objects)
        {
            using (item)
            {
                if (++count > 4096) break;
                var native = Text(item, "__RELPATH") ?? Text(item, "__PATH") ?? $"{className}:{count}";
                var name = Text(item, "Name") ?? native; var subtype = Text(item, "__CLASS") ?? className;
                var command = Text(item, "ExecutablePath") ?? Text(item, "CommandLineTemplate");
                var arguments = Text(item, "CommandLineTemplate") ?? Text(item, "ScriptText");
                var filter = Text(item, "Filter"); var consumer = Text(item, "Consumer");
                var snapshot = new NativeConfigurationSnapshot(category, subtype, native, @"root\subscription", name,
                    null, null, "machine", null, command, arguments, Sid(item["CreatorSID"]),
                    Text(item, "Query") ?? Text(item, "EventNamespace"), subtype, native, filter, consumer, "");
                snapshot = snapshot with { Fingerprint = PersistenceSafety.EvidenceHash(snapshot with { Fingerprint = "" }) };
                result[$"{category}:{native}"] = snapshot;
            }
        }
    }

    static string? Text(ManagementBaseObject value, string name)
    { try { return value.Properties[name]?.Value?.ToString(); } catch (ManagementException) { return null; } }
    static string? Sid(object? value) => value is byte[] bytes && bytes.Length <= 256 ? Convert.ToHexString(bytes).ToLowerInvariant() : null;

    static void CaptureRegistryPersistence(Dictionary<string, NativeConfigurationSnapshot> result)
    {
        var targets = new (RegistryHive Hive, RegistryView View, string Path, string Category, string Subtype, string[]? Names)[]
        {
            (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\Run", "autorun", "run", null),
            (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "autorun", "run-once", null),
            (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "autorun", "policy-run", null),
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows\CurrentVersion\Run", "autorun", "run", null),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"Software\Microsoft\Windows\CurrentVersion\Run", "autorun", "run", null),
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "startup-configuration", "winlogon", ["Shell","Userinit"]),
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows NT\CurrentVersion\Windows", "startup-configuration", "appinit", ["AppInit_DLLs","LoadAppInit_DLLs"]),
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls", "startup-configuration", "appcert", null),
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SYSTEM\CurrentControlSet\Control\Lsa", "startup-configuration", "lsa-package", ["Authentication Packages","Security Packages"]),
            (RegistryHive.CurrentUser, RegistryView.Default, @"Software\OpenSecurityPlatform\Sprint9\IFEO", "startup-configuration", "ifeo-test-scope", null)
        };
        foreach (var target in targets) CaptureRegistryValues(result, target.Hive, target.View, target.Path, target.Category, target.Subtype, target.Names);
        CaptureRegistrySubkeys(result, RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "ifeo", ["Debugger", "GlobalFlag", "VerifierDlls"]);
        CaptureRegistrySubkeys(result, RegistryHive.LocalMachine, RegistryView.Registry32, @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "ifeo", ["Debugger", "GlobalFlag", "VerifierDlls"]);
        CaptureCom(result);
    }

    static void CaptureRegistryValues(Dictionary<string, NativeConfigurationSnapshot> result, RegistryHive hive,
        RegistryView view, string path, string category, string subtype, string[]? names)
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, view); using var key = root.OpenSubKey(path, false); if (key is null) return;
            var hiveName = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM"; var scope = hive == RegistryHive.CurrentUser ? "user" : "machine";
            foreach (var name in key.GetValueNames().Where(x => names is null || names.Contains(x, StringComparer.OrdinalIgnoreCase)).Take(1024))
            {
                var raw = ValueText(key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                var native = $"{hiveName}\\{path}::{name}@{view}"; var snapshot = new NativeConfigurationSnapshot(category, subtype, native,
                    $"{hiveName}\\{path}", name.Length == 0 ? "(Default)" : name, $"{hiveName}\\{path}", view.ToString(), scope,
                    null, raw, raw, null, null, null, null, null, null, "");
                snapshot = snapshot with { Fingerprint = PersistenceSafety.EvidenceHash(snapshot with { Fingerprint = "" }) }; result[$"{category}:{native}"] = snapshot;
            }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException or IOException) { }
    }

    static void CaptureRegistrySubkeys(Dictionary<string, NativeConfigurationSnapshot> result, RegistryHive hive,
        RegistryView view, string path, string subtype, string[] names)
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, view); using var parent = root.OpenSubKey(path, false); if (parent is null) return;
            foreach (var childName in parent.GetSubKeyNames().Take(2048))
            {
                using var child = parent.OpenSubKey(childName, false); if (child is null) continue;
                foreach (var valueName in names.Where(x => child.GetValueNames().Contains(x, StringComparer.OrdinalIgnoreCase)))
                    CaptureRegistryValues(result, hive, view, $@"{path}\{childName}", "startup-configuration", subtype, [valueName]);
            }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException or IOException) { }
    }

    static void CaptureCom(Dictionary<string, NativeConfigurationSnapshot> result)
    {
        CaptureCom(result, RegistryHive.CurrentUser, RegistryView.Default);
        CaptureCom(result, RegistryHive.LocalMachine, RegistryView.Registry64);
        CaptureCom(result, RegistryHive.LocalMachine, RegistryView.Registry32);
    }

    static void CaptureCom(Dictionary<string, NativeConfigurationSnapshot> result, RegistryHive hive, RegistryView view)
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, view); using var classes = root.OpenSubKey(@"Software\Classes", false); if (classes is null) return;
            var hiveName = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM"; var scope = hive == RegistryHive.CurrentUser ? "user" : "machine";
            using var clsid = classes.OpenSubKey("CLSID", false);
            if (clsid is not null) foreach (var id in clsid.GetSubKeyNames().Take(2048)) foreach (var subtype in new[] { "InprocServer32", "LocalServer32", "TreatAs" })
                    { using var key = clsid.OpenSubKey($"{id}\\{subtype}", false); if (key is null) continue; AddCom(result, $@"{hiveName}\Software\Classes\CLSID\{id}\{subtype}", id, subtype, ValueText(key.GetValue(null)), view, scope); }
            foreach (var progId in classes.GetSubKeyNames().Where(x => !x.Equals("CLSID", StringComparison.OrdinalIgnoreCase)).Take(2048))
            { using var key = classes.OpenSubKey($"{progId}\\shell\\open\\command", false); if (key is null) continue; AddCom(result, $@"{hiveName}\Software\Classes\{progId}\shell\open\command", progId, "shell-open-command", ValueText(key.GetValue(null)), view, scope); }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException or IOException) { }
    }

    static void AddCom(Dictionary<string, NativeConfigurationSnapshot> result, string path, string name, string subtype, string? action, RegistryView view, string scope)
    {
        var snapshot = new NativeConfigurationSnapshot("com-registration", subtype, $"{path}@{view}", path, name, path, view.ToString(), scope, null, action, action, null, null, null, null, null, null, "");
        snapshot = snapshot with { Fingerprint = PersistenceSafety.EvidenceHash(snapshot with { Fingerprint = "" }) }; result[$"com-registration:{snapshot.NativeIdentity}"] = snapshot;
    }

    static void CaptureStartupFolders(Dictionary<string, NativeConfigurationSnapshot> result)
    {
        foreach (var (folder, scope) in new[] { (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "user"), (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "machine") })
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) continue;
            try { foreach (var path in Directory.EnumerateFiles(folder).Take(1024)) { var file = new FileInfo(path); var native = path.Normalize(NormalizationForm.FormKC); var snapshot = new NativeConfigurationSnapshot("startup-item", Path.GetExtension(path).TrimStart('.').ToLowerInvariant(), native, folder, file.Name, null, null, scope, path, path, null, null, null, null, null, null, null, $"{file.Length}:{file.LastWriteTimeUtc.Ticks}"); result[$"startup-item:{native}"] = snapshot; } }
            catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException or IOException) { }
        }
    }

    static string? ValueText(object? value) => value switch { null => null, string text => text, string[] values => string.Join(';', values), byte[] bytes => $"binary:{bytes.Length}", _ => Convert.ToString(value, CultureInfo.InvariantCulture) };

    static Dictionary<string, string> EventData(EventRecord record)
    {
        var xml = record.ToXml();
        if (xml.Length > 262144) throw new XmlException("event-xml-size-limit");
        using var sr = new StringReader(xml);
        using var reader = XmlReader.Create(sr, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 262144 });
        var doc = XDocument.Load(reader, LoadOptions.None); XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); var ordinal = 0;
        foreach (var item in doc.Descendants(ns + "EventData").Elements(ns + "Data").Take(64))
        { var name = item.Attribute("Name")?.Value ?? $"param{++ordinal}"; if (item.Value.Length <= 32767 && !item.Value.Any(char.IsControl)) result[name] = item.Value; }
        return result;
    }
    static NativeEventIdentity Identity(EventRecord record, string operation, string? status) => new(
        record.LogName ?? "", record.ProviderName ?? "", record.ProviderId?.ToString("D"), record.Id,
        record.Version, record.Level, record.Opcode, record.Task, record.RecordId, operation, status);
    static string Value(IReadOnlyDictionary<string, string> values, string name) => values.TryGetValue(name, out var value) ? value : "";
    static string? State(IReadOnlyDictionary<string, string> values) => Value(values, "param2") is { Length: > 0 } state ? state.ToLowerInvariant() : null;
    static string ServiceName(IReadOnlyDictionary<string, string> values) => Value(values, "ServiceName") is { Length: > 0 } name ? name : Value(values, "param4") is { Length: > 0 } canonical ? canonical : Value(values, "param1");
    static long Generation(Dictionary<string, long> values, string name, bool begin) { if (!values.TryGetValue(name, out var value)) value = 0; if (begin) value++; values[name] = value; return value; }
    void Enqueue(NativePersistenceEvent value) { if (Interlocked.Increment(ref _queued) > MaximumBufferedEvents) { Interlocked.Decrement(ref _queued); Interlocked.Increment(ref _overflow); return; } _events.Enqueue(value); }

    static string? TryTaskXml(string taskPath)
    {
        if (!PersistenceSafety.SafeName(taskPath)) return null;
        object? service = null, folder = null, task = null;
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service"); if (type is null) return null;
            service = Activator.CreateInstance(type); dynamic scheduler = service!; scheduler.Connect();
            var slash = taskPath.LastIndexOf('\\'); var folderPath = slash <= 0 ? "\\" : taskPath[..slash]; var name = taskPath[(slash + 1)..];
            folder = scheduler.GetFolder(folderPath); task = ((dynamic)folder).GetTask(name); return ((dynamic)task).Xml as string;
        }
        catch (Exception exception) when (exception is COMException or IOException or UnauthorizedAccessException or InvalidOperationException) { return null; }
        finally { Release(task); Release(folder); Release(service); }
    }
    static void Release(object? value) { if (value is not null && Marshal.IsComObject(value)) Marshal.FinalReleaseComObject(value); }
    void LoadGenerations() { try { if (!File.Exists(_generationPath)) return; var state = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, long>>>(File.ReadAllText(_generationPath)); if (state?.GetValueOrDefault("services") is { } s) foreach (var x in s) _serviceGenerations[x.Key] = x.Value; if (state?.GetValueOrDefault("tasks") is { } t) foreach (var x in t) _taskGenerations[x.Key] = x.Value; if (state?.GetValueOrDefault("configurations") is { } c) foreach (var x in c) _configurationGenerations[x.Key] = x.Value; } catch (Exception e) when (e is IOException or JsonException) { } }
    void SaveGenerations() { try { Directory.CreateDirectory(Path.GetDirectoryName(_generationPath)!); var temp = _generationPath + ".tmp"; File.WriteAllText(temp, JsonSerializer.Serialize(new Dictionary<string, Dictionary<string, long>> { ["services"] = _serviceGenerations, ["tasks"] = _taskGenerations, ["configurations"] = _configurationGenerations })); File.Move(temp, _generationPath, true); } catch (IOException) { } }
    public ValueTask DisposeAsync() { if (_serviceWatcher is not null) { _serviceWatcher.Enabled = false; _serviceWatcher.EventRecordWritten -= OnService; _serviceWatcher.Dispose(); } if (_taskWatcher is not null) { _taskWatcher.Enabled = false; _taskWatcher.EventRecordWritten -= OnTask; _taskWatcher.Dispose(); } SaveGenerations(); ServiceState = TaskState = ConfigurationState = "stopped"; return ValueTask.CompletedTask; }
}

sealed class UnsupportedPersistenceCollector : IPersistenceCollector
{
    public string ServiceState => "unsupported"; public string TaskState => "unsupported";
    public string ConfigurationState => "unsupported";
    public bool Elevated => false; public long LostEvents => 0;
    public string[] KnownLimitations => ["Windows service and scheduled-task telemetry is not applicable on this platform."];
    public Task StartAsync(CancellationToken ct) => Task.CompletedTask;
    public Task<IReadOnlyList<NativePersistenceEvent>> PollAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<NativePersistenceEvent>>([]);
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

sealed class ServiceTaskTelemetryPipeline : IAsyncDisposable
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly AgentOptions _options; readonly IPersistenceCollector _collector;
    readonly string _queue, _quarantine; PersistenceTelemetryPolicy _policy = new();
    long _sequence, _queueBytes, _source, _normalizationFailures, _relationshipFailures,
        _queueDrops, _excluded, _duplicates, _rejections; DateTimeOffset? _lastUpload; bool _started;
    public string CurrentPolicyKey { get; private set; } = "persistence-policy.v1:0";
    public string ServiceState => _collector.ServiceState; public string TaskState => _collector.TaskState; public string ConfigurationState => _collector.ConfigurationState;
    public long Depth => Directory.EnumerateFiles(_queue, "*.json").LongCount();
    public long Oldest => Directory.EnumerateFiles(_queue, "*.json").Select(x => new FileInfo(x)).DefaultIfEmpty().Max(x => x is null ? 0 : (long)Math.Max(0, (DateTimeOffset.UtcNow - x.CreationTimeUtc).TotalSeconds));

    public ServiceTaskTelemetryPipeline(AgentOptions options, long sequence)
    {
        _options = options; _collector = string.Equals(Environment.GetEnvironmentVariable("PLATFORM_TELEMETRY_DRAIN_ONLY"), "true", StringComparison.OrdinalIgnoreCase) ? new UnsupportedPersistenceCollector() : OperatingSystem.IsWindows() ? new WindowsServiceTaskCollector(options.DataDirectory) : new UnsupportedPersistenceCollector();
        _queue = Path.Combine(options.DataDirectory, "persistence-queue"); _quarantine = Path.Combine(_queue, "quarantine"); Directory.CreateDirectory(_queue); Recover();
        _queueBytes = Directory.EnumerateFiles(_queue, "*.json").Sum(x => new FileInfo(x).Length);
        _sequence = Math.Max(sequence, Directory.EnumerateFiles(_queue, "*.json").Select(x => long.TryParse(Path.GetFileName(x).Split('-')[0], out var n) ? n : 0).DefaultIfEmpty().Max());
    }
    public Task<IReadOnlyDictionary<string, string[]>> ApplyPolicyAsync(PersistenceTelemetryPolicy policy, Guid id, int version) { var errors = PersistenceSafety.Validate(policy); if (errors.Count == 0) { _policy = policy; CurrentPolicyKey = $"{id:D}:{version}"; } return Task.FromResult(errors); }
    public string[] Capabilities() => [$"service.lifecycle.v1:{ServiceState}", $"scheduled-task.lifecycle.v1:{TaskState}", $"persistence.configuration.v1:{ConfigurationState}", "persistence.queue.v1", $"scheduled-task.xml:{_policy.CaptureTaskXml.ToString().ToLowerInvariant()}"];

    public async Task<long> RunOnceAsync(AgentState state, Func<AgentState, HttpClient> clientFactory,
        Func<long, CancellationToken, Task> checkpoint, CancellationToken ct)
    {
        if (!_started) { await _collector.StartAsync(ct); _started = true; }
        var changed = false;
        foreach (var native in await _collector.PollAsync(ct))
        {
            Interlocked.Increment(ref _source); if (!Allowed(native)) { Interlocked.Increment(ref _excluded); continue; }
            var sequence = Interlocked.Increment(ref _sequence); var value = Normalize(state, native, sequence);
            if (value is null) { Interlocked.Increment(ref _normalizationFailures); changed = true; continue; }
            try { await Persist(value, ct); } catch (IOException) { Interlocked.Increment(ref _queueDrops); }
            changed = true;
        }
        if (changed) await checkpoint(_sequence, ct);
        if (Depth > 0 && (Depth >= _policy.MaximumBatchEvents || _lastUpload is null || DateTimeOffset.UtcNow - _lastUpload >= TimeSpan.FromSeconds(_policy.FlushSeconds))) await Upload(state, clientFactory, ct);
        return _sequence;
    }

    bool Allowed(NativePersistenceEvent value)
    {
        if (value.ObjectKind == PersistenceObjectKind.Service)
        {
            if (!_policy.ServicesEnabled || value.ServiceSnapshot?.Driver == true && !_policy.DriverServices) return false;
            if (value.Kind == PersistenceEventKind.ServiceCreated && !_policy.ServiceCreation || value.Kind == PersistenceEventKind.ServiceDeleted && !_policy.ServiceDeletion || value.Kind == PersistenceEventKind.ServiceConfigurationChanged && !_policy.ServiceConfiguration || value.Kind is PersistenceEventKind.ServiceStarted or PersistenceEventKind.ServiceStopped or PersistenceEventKind.ServiceStateChanged && !_policy.ServiceStateChanges) return false;
            var name = value.ServiceSnapshot?.Name ?? value.Data.GetValueOrDefault("ServiceName", "");
            if (_policy.IncludedServiceNames is { Length: > 0 } && !_policy.IncludedServiceNames.Any(x => Match(name, x)) || _policy.ExcludedServiceNames?.Any(x => Match(name, x)) == true) return false;
            if ((_policy.ExclusionRules ?? []).Any(rule => rule.Enabled && rule.Category switch
            {
                "service-name" => name.Equals(rule.Pattern, StringComparison.OrdinalIgnoreCase),
                "service-type" => (value.ServiceSnapshot?.Type ?? "").Equals(rule.Pattern, StringComparison.OrdinalIgnoreCase),
                "service-executable" => Match(value.ServiceSnapshot?.BinaryPath ?? "", rule.Pattern),
                "user" => Match(value.Data.GetValueOrDefault("AccountName", ""), rule.Pattern),
                _ => false
            })) return false;
        }
        else if (value.ObjectKind == PersistenceObjectKind.ScheduledTask)
        {
            if (!_policy.TasksEnabled) return false;
            if (value.Kind == PersistenceEventKind.ScheduledTaskRegistered && !_policy.TaskRegistration || value.Kind == PersistenceEventKind.ScheduledTaskUpdated && !_policy.TaskUpdates || value.Kind == PersistenceEventKind.ScheduledTaskDeleted && !_policy.TaskDeletion || value.Kind is PersistenceEventKind.ScheduledTaskEnabled or PersistenceEventKind.ScheduledTaskDisabled && !_policy.TaskEnableDisable || value.Kind is PersistenceEventKind.ScheduledTaskExecutionStarted or PersistenceEventKind.ScheduledTaskExecutionCompleted && !_policy.TaskExecutionEvents) return false;
            var path = value.Data.GetValueOrDefault("TaskName", "");
            if (_policy.IncludedTaskPaths is { Length: > 0 } && !_policy.IncludedTaskPaths.Any(x => Match(path, x)) || _policy.ExcludedTaskPaths?.Any(x => Match(path, x)) == true) return false;
            if ((_policy.ExclusionRules ?? []).Any(rule => rule.Enabled && rule.Category switch
            {
                "task-path" => path.Equals(rule.Pattern, StringComparison.OrdinalIgnoreCase),
                "task-path-prefix" => path.StartsWith(rule.Pattern, StringComparison.OrdinalIgnoreCase),
                "task-name" => path[(path.LastIndexOf('\\') + 1)..].Equals(rule.Pattern, StringComparison.OrdinalIgnoreCase),
                "task-action" => Match(value.Data.GetValueOrDefault("ActionName", value.Data.GetValueOrDefault("Path", "")), rule.Pattern),
                "process" => Match(value.Data.GetValueOrDefault("ProcessID", value.Data.GetValueOrDefault("EnginePID", "")), rule.Pattern),
                "user" => Match(value.Data.GetValueOrDefault("UserContext", value.Data.GetValueOrDefault("UserName", "")), rule.Pattern),
                _ => false
            })) return false;
        }
        else
        {
            var configuration = value.ConfigurationSnapshot; if (configuration is null) return false;
            if (configuration.Category.StartsWith("wmi-", StringComparison.Ordinal) && !_policy.WmiSubscriptionsEnabled ||
                configuration.Category == "com-registration" && !_policy.ComRegistrationEnabled ||
                configuration.Category == "startup-item" && !_policy.StartupFolderEnabled ||
                configuration.Category is "autorun" or "startup-configuration" && !_policy.AutorunStartupEnabled ||
                configuration.Subtype.StartsWith("ifeo", StringComparison.Ordinal) && !_policy.IfeoMetadataEnabled ||
                configuration.Subtype == "winlogon" && !_policy.WinlogonMetadataEnabled ||
                configuration.Subtype is "appinit" or "appcert" && !_policy.AppInitAppCertMetadataEnabled ||
                configuration.Subtype == "lsa-package" && !_policy.LsaPackageMetadataEnabled) return false;
            var path = configuration.RegistryPath ?? configuration.FilePath ?? configuration.NamespaceOrLocation ?? "";
            if (_policy.IncludedPersistenceCategories is { Length: > 0 } && !_policy.IncludedPersistenceCategories.Contains(configuration.Category, StringComparer.OrdinalIgnoreCase) ||
                _policy.ExcludedPersistenceCategories?.Contains(configuration.Category, StringComparer.OrdinalIgnoreCase) == true ||
                _policy.IncludedPersistencePaths is { Length: > 0 } && !_policy.IncludedPersistencePaths.Any(x => Match(path, x)) ||
                _policy.ExcludedPersistencePaths?.Any(x => Match(path, x)) == true) return false;
            if ((_policy.ExclusionRules ?? []).Any(rule => rule.Enabled && rule.Category switch
            {
                "persistence-category" => configuration.Category.Equals(rule.Pattern, StringComparison.OrdinalIgnoreCase),
                "persistence-path" => Match(path, rule.Pattern),
                "wmi-namespace" => Match(configuration.NamespaceOrLocation ?? "", rule.Pattern),
                "wmi-object" => Match(configuration.NativeIdentity, rule.Pattern),
                "user" => Match(configuration.Principal ?? "", rule.Pattern),
                _ => false
            })) return false;
        }
        return true;
    }

    PersistenceObservation? Normalize(AgentState state, NativePersistenceEvent native, long sequence)
    {
        if (native.ObjectKind == PersistenceObjectKind.Service)
        {
            var snapshot = native.ServiceSnapshot; var name = snapshot?.Name ?? native.Data.GetValueOrDefault("ServiceName") ?? native.Data.GetValueOrDefault("param4") ?? native.Data.GetValueOrDefault("param1");
            if (!PersistenceSafety.SafeName(name, 256)) return null;
            var process = native.Kind is PersistenceEventKind.ServiceStarted or PersistenceEventKind.ServiceStateChanged && _policy.ServiceProcessRelationships ? ServiceProcess(state.EndpointId, name!) : null;
            if (_policy.ServiceProcessRelationships && native.Kind == PersistenceEventKind.ServiceStarted && process?.ProcessEntityId is null) Interlocked.Increment(ref _relationshipFailures);
            var binary = _policy.ActionMetadata ? PersistenceSafety.BoundAndRedact(snapshot?.BinaryPath, _policy) : null;
            var serviceType = snapshot?.Type ?? native.Data.GetValueOrDefault("ServiceType");
            var service = new ServiceEvidence(PersistenceSafety.EntityId(state.EndpointId, state.InstallationId, native.ObjectKind, name!, native.Generation), name!,
                snapshot?.DisplayName ?? native.Data.GetValueOrDefault("param1"), serviceType,
                native.Identity.NativeStatus, snapshot?.StartupType ?? native.Data.GetValueOrDefault("StartType"), snapshot?.ErrorControl,
                binary, NormalizeCommandPath(binary), snapshot?.Account ?? native.Data.GetValueOrDefault("AccountName"), snapshot?.Description,
                snapshot?.Dependencies ?? [], snapshot?.Driver ?? PersistenceSafety.IsDriverServiceType(serviceType), snapshot?.Interactive, name,
                native.Kind == PersistenceEventKind.ServiceCreated ? native.ObservedAt : null,
                native.Kind == PersistenceEventKind.ServiceDeleted ? native.ObservedAt : null, 1, process);
            return Observation(state, native, sequence, service, null, process?.User);
        }
        if (native.ObjectKind == PersistenceObjectKind.PersistenceConfiguration)
        {
            var snapshot = native.ConfigurationSnapshot; if (snapshot is null || !PersistenceSafety.SafeName(snapshot.Name) || !PersistenceSafety.SafeName(snapshot.NativeIdentity)) return null;
            var configurationQuality = (native.Quality ?? []).ToList();
            if (snapshot.RegistryPath is not null || snapshot.FilePath is not null) configurationQuality.Add("raw-evidence-reference-resolution-pending");
            var action = _policy.ActionMetadata ? PersistenceSafety.BoundAndRedact(snapshot.ActionPath, _policy) : null;
            var arguments = _policy.CaptureArguments ? PersistenceSafety.BoundAndRedact(snapshot.Arguments, _policy) : null;
            var redacted = _policy.CaptureArguments && !string.Equals(arguments, snapshot.Arguments, StringComparison.Ordinal);
            var configuration = new PersistenceConfigurationEvidence(
                PersistenceSafety.EntityId(state.EndpointId, state.InstallationId, native.ObjectKind, snapshot.NativeIdentity, native.Generation),
                snapshot.Category, snapshot.Subtype, snapshot.NativeIdentity, snapshot.NamespaceOrLocation, snapshot.Name,
                snapshot.RegistryPath, snapshot.RegistryView, snapshot.Scope, snapshot.FilePath, action, arguments,
                snapshot.Principal, _policy.TriggerMetadata ? PersistenceSafety.BoundAndRedact(snapshot.TriggerMetadata, _policy) : null,
                _policy.ActionMetadata ? PersistenceSafety.BoundAndRedact(snapshot.ConsumerMetadata, _policy) : null,
                snapshot.BindingIdentity, snapshot.FilterIdentity, snapshot.ConsumerIdentity, [], null, null, null,
                $"windows.persistence.{snapshot.Category}", "1.0.0", snapshot.Category.StartsWith("wmi-", StringComparison.Ordinal) ? "high" : "state-snapshot",
                false, native.ObservedAt, native.ObservedAt,
                native.Kind is PersistenceEventKind.WmiFilterCreated or PersistenceEventKind.WmiConsumerCreated or PersistenceEventKind.WmiBindingCreated or PersistenceEventKind.ComRegistrationCreated or PersistenceEventKind.AutorunCreated or PersistenceEventKind.StartupItemCreated ? native.ObservedAt : null,
                native.Kind is PersistenceEventKind.WmiFilterDeleted or PersistenceEventKind.WmiConsumerDeleted or PersistenceEventKind.WmiBindingDeleted or PersistenceEventKind.ComRegistrationDeleted or PersistenceEventKind.AutorunDeleted or PersistenceEventKind.StartupItemDeleted ? native.ObservedAt : null,
                native.Generation, native.Kind.ToString().EndsWith("Deleted", StringComparison.Ordinal) ? "deleted" : "configured", redacted);
            return Observation(state, native with { Quality = configurationQuality.ToArray() }, sequence, null, null, snapshot.Principal, configuration);
        }
        var path = native.Data.GetValueOrDefault("TaskName"); if (!PersistenceSafety.SafeName(path)) return null;
        var slash = path!.LastIndexOf('\\'); var folder = slash <= 0 ? "\\" : path[..slash]; var namePart = path[(slash + 1)..];
        ScheduledTaskAction[] actions = []; ScheduledTaskTrigger[] triggers = []; string? xmlHash = null; var quality = (native.Quality ?? []).ToList();
        if (native.TaskXml is { } xml && !PersistenceSafety.TryParseTaskXml(xml, _policy, out actions, out triggers, out xmlHash, out var error)) quality.Add(error!);
        if (!_policy.ActionMetadata) actions = []; if (!_policy.TriggerMetadata) triggers = [];
        int? pid = int.TryParse(native.Data.GetValueOrDefault("ProcessID") ?? native.Data.GetValueOrDefault("EnginePID"), out var parsed) ? parsed : null;
        var relationship = _policy.TaskProcessRelationships && pid is { } p ? ProcessRelationship(state.EndpointId, p, "Microsoft-Windows-TaskScheduler/event-129-or-200") : null;
        if (_policy.TaskProcessRelationships && native.Kind == PersistenceEventKind.ScheduledTaskExecutionStarted && relationship is null) quality.Add("process-attribution-not-observable-in-this-event");
        var task = new ScheduledTaskEvidence(PersistenceSafety.EntityId(state.EndpointId, state.InstallationId, native.ObjectKind, path, native.Generation), namePart, path, folder, path, 1,
            native.Kind == PersistenceEventKind.ScheduledTaskDisabled ? false : native.Kind == PersistenceEventKind.ScheduledTaskEnabled ? true : null,
            null, native.Data.GetValueOrDefault("UserContext") ?? native.Data.GetValueOrDefault("UserName"), null, null, null,
            actions, triggers, native.Data.GetValueOrDefault("InstanceId") ?? native.Data.GetValueOrDefault("TaskInstanceId"), native.Data.GetValueOrDefault("ResultCode"),
            native.Kind == PersistenceEventKind.ScheduledTaskRegistered ? native.ObservedAt : null,
            native.Kind == PersistenceEventKind.ScheduledTaskDeleted ? native.ObservedAt : null, relationship, xmlHash);
        return Observation(state, native with { Quality = quality.ToArray() }, sequence, null, task, task.Principal);
    }

    static PersistenceObservation Observation(AgentState state, NativePersistenceEvent native, long sequence,
        ServiceEvidence? service, ScheduledTaskEvidence? task, string? user,
        PersistenceConfigurationEvidence? configuration = null)
    {
        var evidence = new { native.Identity, native.Data, native.Generation };
        return new(Guid.NewGuid(), "persistence-event.v1", native.ObjectKind, native.Kind, state.EndpointId, state.AgentId,
            state.InstallationId, $"windows-persistence:{Environment.MachineName}", native.ObjectKind == PersistenceObjectKind.PersistenceConfiguration ? configuration?.Category.StartsWith("wmi-", StringComparison.Ordinal) == true ? "windows.wmi-subscription-snapshot" : configuration?.Category == "startup-item" ? "windows.startup-folder-snapshot" : "windows.registry-persistence-snapshot" : native.Identity.Provider == "Windows Registry API" ? "windows.services-registry-snapshot" : native.Identity.Channel == "Service Control Manager API" ? "windows.scm-status-snapshot" : native.ObjectKind == PersistenceObjectKind.Service ? "windows.scm-eventlog" : "windows.task-scheduler-eventlog",
            "1.0.0", "windows", native.Identity, sequence, native.ObservedAt, null, null,
            "persistence-normalization.v1", PersistenceSafety.EvidenceHash(evidence), native.Quality ?? [],
            native.Quality is { Length: > 0 } ? "partial" : "complete", service, task, user,
            Configuration: configuration);
    }

    async Task Upload(AgentState state, Func<AgentState, HttpClient> clientFactory, CancellationToken ct)
    {
        var items = new List<(string Path, PersistenceObservation Event)>(); foreach (var path in Directory.EnumerateFiles(_queue, "*.json").OrderBy(x => x)) { var value = await Read(path, ct); if (value is not null) items.Add((path, value)); if (items.Count >= _policy.MaximumBatchEvents) break; }
        if (items.Count == 0) return; var events = items.Select(x => x.Event).ToArray(); var eventBytes = JsonSerializer.SerializeToUtf8Bytes(events, Json);
        var batch = new PersistenceEventBatch(Guid.NewGuid(), state.EndpointId, state.AgentId, state.InstallationId, events.Min(x => x.Sequence), events.Max(x => x.Sequence), events, Convert.ToHexString(SHA256.HashData(eventBytes)).ToLowerInvariant());
        var canonical = JsonSerializer.SerializeToUtf8Bytes(batch, Json); if (canonical.Length > _policy.MaximumBatchBytes) return;
        byte[] compressed; await using (var output = new MemoryStream()) { await using (var gzip = new GZipStream(output, CompressionLevel.Fastest, true)) await gzip.WriteAsync(canonical, ct); compressed = output.ToArray(); }
        if (compressed.Length > 1048576) return; using var content = new ByteArrayContent(compressed); content.Headers.ContentType = new("application/json"); content.Headers.ContentEncoding.Add("gzip");
        void H(string key, long value) => content.Headers.Add(key, value.ToString(CultureInfo.InvariantCulture));
        H("X-Uncompressed-Length", canonical.Length); H("X-Source-Events", _source); H("X-Normalization-Failures", _normalizationFailures); H("X-Relationship-Failures", _relationshipFailures); H("X-Source-Gaps", _collector.LostEvents); H("X-Queue-Depth", Depth); H("X-Queue-Age", Oldest); H("X-Queue-Drops", _queueDrops); H("X-Excluded", _excluded); H("X-Duplicates", _duplicates); H("X-Rejections", _rejections);
        content.Headers.Add("X-Policy-Version", CurrentPolicyKey); content.Headers.Add("X-Elevated", _collector.Elevated.ToString()); content.Headers.Add("X-Service-Collector-State", ServiceState); content.Headers.Add("X-Task-Collector-State", TaskState); content.Headers.Add("X-Configuration-Collector-State", ConfigurationState); content.Headers.Add("X-Known-Limitations", string.Join(';', _collector.KnownLimitations));
        if (int.TryParse(CurrentPolicyKey.Split(':').Last(), out var appliedVersion)) content.Headers.Add("X-Applied-Policy-Version", appliedVersion.ToString(CultureInfo.InvariantCulture));
        using var client = clientFactory(state); using var response = await client.PostAsync("/agent/v1/persistence-event-batches", content, ct); response.EnsureSuccessStatusCode();
        var ack = await response.Content.ReadFromJsonAsync<PersistenceBatchAcknowledgement>(Json, ct) ?? throw new InvalidDataException("Persistence acknowledgement invalid.");
        Interlocked.Add(ref _duplicates, ack.DuplicateEventIds.Count); Interlocked.Add(ref _rejections, ack.RejectedEventIds.Count); var done = ack.AcceptedEventIds.Concat(ack.DuplicateEventIds).ToHashSet();
        foreach (var item in items) if (done.Contains(item.Event.EventId)) { var length = new FileInfo(item.Path).Length; File.Delete(item.Path); Interlocked.Add(ref _queueBytes, -length); }
        foreach (var item in items.Where(x => ack.RejectedEventIds.ContainsKey(x.Event.EventId))) { var length = new FileInfo(item.Path).Length; Quarantine(item.Path, $"server-rejected:{ack.RejectedEventIds[item.Event.EventId]}"); Interlocked.Add(ref _queueBytes, -length); }
        _lastUpload = DateTimeOffset.UtcNow;
    }
    async Task Persist(PersistenceObservation value, CancellationToken ct) { var bytes = JsonSerializer.SerializeToUtf8Bytes(value, Json); if (Interlocked.Read(ref _queueBytes) + bytes.Length > _policy.MaximumQueueBytes) throw new IOException("persistence-queue-capacity-exceeded"); var final = Path.Combine(_queue, $"{value.Sequence:D20}-{value.EventId:N}.json"); var temp = final + ".tmp"; await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { await stream.WriteAsync(bytes, ct); await stream.FlushAsync(ct); stream.Flush(true); } File.Move(temp, final + ".committing"); File.Move(final + ".committing", final); Interlocked.Add(ref _queueBytes, bytes.Length); }
    async Task<PersistenceObservation?> Read(string path, CancellationToken ct) { try { return JsonSerializer.Deserialize<PersistenceObservation>(await File.ReadAllBytesAsync(path, ct), Json) ?? throw new JsonException(); } catch (Exception e) when (e is JsonException or IOException) { Quarantine(path, e.GetType().Name); return null; } }
    void Recover() { foreach (var path in Directory.EnumerateFiles(_queue, "*.tmp").Concat(Directory.EnumerateFiles(_queue, "*.committing")).ToArray()) try { _ = JsonSerializer.Deserialize<PersistenceObservation>(File.ReadAllText(path), Json) ?? throw new JsonException(); var final = path.EndsWith(".committing", StringComparison.Ordinal) ? path[..^11] : path[..^4]; if (!File.Exists(final)) File.Move(path, final); else Quarantine(path, "duplicate-commit"); } catch (Exception e) when (e is JsonException or IOException) { Quarantine(path, e.GetType().Name); } }
    void Quarantine(string path, string reason) { try { Directory.CreateDirectory(_quarantine); var target = Path.Combine(_quarantine, $"{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.bad"); File.Move(path, target, true); File.WriteAllText(target + ".reason", reason); } finally { Interlocked.Increment(ref _queueDrops); } }
    static string? NormalizeCommandPath(string? command) { if (string.IsNullOrWhiteSpace(command)) return null; var value = command.Trim(); if (value.StartsWith('"')) { var end = value.IndexOf('"', 1); if (end > 1) value = value[1..end]; } else { var space = value.IndexOf(' '); if (space > 0) value = value[..space]; } return value.Replace('/', '\\').ToLowerInvariant(); }
    static bool Match(string value, string pattern) { var parts = pattern.Trim().Split('*', StringSplitOptions.RemoveEmptyEntries); if (parts.Length == 0) return false; var cursor = 0; foreach (var part in parts) { var normalized = part.Trim('?'); var index = value.IndexOf(normalized, cursor, StringComparison.OrdinalIgnoreCase); if (index < 0) return false; cursor = index + normalized.Length; } return true; }
    static PersistenceProcessRelationship? ProcessRelationship(Guid endpoint, int pid, string source) { if (pid <= 0) return null; try { using var process = Process.GetProcessById(pid); var start = new DateTimeOffset(process.StartTime.ToUniversalTime()); return new(ProcessIdentity.Create(endpoint, pid, start, $"{source}:{start.UtcTicks}"), pid, start, null, process.SessionId, source, "high", "native-pid-plus-process-start"); } catch { return new(null, pid, null, null, null, source, "pid-only", "native-pid", true); } }
    static PersistenceProcessRelationship? ServiceProcess(Guid endpoint, string name)
    {
        var manager = OpenSCManager(null, null, 0x0001); if (manager.IsInvalid) return null;
        using (manager) { var service = OpenService(manager, name, 0x0004); if (service.IsInvalid) return null; using (service) { var size = Marshal.SizeOf<ServiceStatusProcess>(); if (!QueryServiceStatusEx(service, 0, out var status, size, out _)) return null; return status.ProcessId == 0 ? null : ProcessRelationship(endpoint, unchecked((int)status.ProcessId), "windows.scm-query-service-status-ex"); } }
    }
    [StructLayout(LayoutKind.Sequential)] struct ServiceStatusProcess { public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags; }
    sealed class ScHandle : SafeHandleZeroOrMinusOneIsInvalid { ScHandle() : base(true) { } protected override bool ReleaseHandle() => CloseServiceHandle(handle); }
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern ScHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern ScHandle OpenService(ScHandle manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool QueryServiceStatusEx(ScHandle service, int infoLevel, out ServiceStatusProcess status, int size, out int needed);
    [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
    public async ValueTask DisposeAsync() => await _collector.DisposeAsync();
}
