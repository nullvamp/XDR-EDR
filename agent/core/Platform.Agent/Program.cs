using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenSecurityPlatform.Foundation;

if (args.Length == 1 && args[0] == "--authorized-uninstall-cleanup")
{
    Environment.ExitCode = await ReleaseLifecycleCleanup.RunAsync();
    return;
}
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
    options.ServiceName = Environment.GetEnvironmentVariable("PLATFORM_AGENT_SERVICE_NAME")
        ?? ProductRelease.WindowsServiceName
);
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(o => o.TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'");
var agentOptions = AgentOptions.Load();
if (string.Equals(Environment.GetEnvironmentVariable("PLATFORM_AGENT_UPDATE_SELF_TEST"), "true", StringComparison.OrdinalIgnoreCase))
{
    Environment.ExitCode = await AgentUpdateSelfTest.RunAsync(Environment.GetEnvironmentVariable("PLATFORM_AGENT_UPDATE_SELF_TEST_ROOT"), Environment.GetEnvironmentVariable("PLATFORM_AGENT_UPDATE_SELF_TEST_OUTPUT"));
    return;
}
if (string.Equals(Environment.GetEnvironmentVariable("PLATFORM_SELF_PROTECTION_SELF_TEST"), "true", StringComparison.OrdinalIgnoreCase))
{
    Environment.ExitCode = await AgentSelfProtectionSelfTest.RunAsync(Environment.GetEnvironmentVariable("PLATFORM_SELF_PROTECTION_SELF_TEST_ROOT"), Environment.GetEnvironmentVariable("PLATFORM_SELF_PROTECTION_SELF_TEST_OUTPUT"));
    return;
}
if (string.Equals(Environment.GetEnvironmentVariable("PLATFORM_FILE_RESPONSE_SELF_TEST"), "true", StringComparison.OrdinalIgnoreCase))
{
    Environment.ExitCode = await WindowsFileQuarantine.RunSelfTestAsync(agentOptions.DataDirectory,
        Environment.GetEnvironmentVariable("PLATFORM_FILE_RESPONSE_SELF_TEST_ROOT"),
        Environment.GetEnvironmentVariable("PLATFORM_FILE_RESPONSE_SELF_TEST_OUTPUT"));
    return;
}
if (string.Equals(Environment.GetEnvironmentVariable("PLATFORM_PROCESS_RESPONSE_SELF_TEST"), "true", StringComparison.OrdinalIgnoreCase))
{
    Environment.ExitCode = await WindowsProcessResponse.RunSelfTestAsync(
        agentOptions.DataDirectory,
        Environment.GetEnvironmentVariable("PLATFORM_PROCESS_RESPONSE_FIXTURE"),
        Environment.GetEnvironmentVariable("PLATFORM_PROCESS_RESPONSE_SELF_TEST_OUTPUT"));
    return;
}
if (string.Equals(Environment.GetEnvironmentVariable("PLATFORM_RESPONSE_WORKER_SELF_TEST"), "true", StringComparison.OrdinalIgnoreCase))
{
    Environment.ExitCode = await EndpointResponseWorkerSelfTest.RunAsync(
        agentOptions.DataDirectory,
        Environment.GetEnvironmentVariable("PLATFORM_RESPONSE_WORKER_SELF_TEST_OUTPUT"));
    return;
}
if (string.Equals(Environment.GetEnvironmentVariable("PLATFORM_MODULE_COLLECTOR_SELF_TEST"), "true", StringComparison.OrdinalIgnoreCase))
{
    Environment.ExitCode = await ModuleCollectorSelfTest.RunAsync(
        agentOptions.DataDirectory,
        Environment.GetEnvironmentVariable("PLATFORM_MODULE_COLLECTOR_SELF_TEST_OUTPUT"));
    return;
}
if (string.Equals(Environment.GetEnvironmentVariable("PLATFORM_DNS_COLLECTOR_SELF_TEST"), "true", StringComparison.OrdinalIgnoreCase))
{
    Environment.ExitCode = await DnsCollectorSelfTest.RunAsync(agentOptions.DataDirectory,
        Environment.GetEnvironmentVariable("PLATFORM_DNS_COLLECTOR_SELF_TEST_OUTPUT"));
    return;
}
if (
    string.Equals(
        Environment.GetEnvironmentVariable("PLATFORM_NETWORK_COLLECTOR_SELF_TEST"),
        "true",
        StringComparison.OrdinalIgnoreCase
    )
)
{
    Environment.ExitCode = await NetworkCollectorSelfTest.RunAsync(
        agentOptions.DataDirectory,
        Environment.GetEnvironmentVariable("PLATFORM_NETWORK_COLLECTOR_SELF_TEST_OUTPUT")
    );
    return;
}
if (
    string.Equals(
        Environment.GetEnvironmentVariable("PLATFORM_REGISTRY_COLLECTOR_SELF_TEST"),
        "true",
        StringComparison.OrdinalIgnoreCase
    )
)
{
    Environment.ExitCode = await RegistryCollectorSelfTest.RunAsync(
        agentOptions.DataDirectory,
        Environment.GetEnvironmentVariable("PLATFORM_REGISTRY_COLLECTOR_SELF_TEST_OUTPUT")
    );
    return;
}
if (
    string.Equals(
        Environment.GetEnvironmentVariable("PLATFORM_WINDOWS_FILE_COLLECTOR_PRIVILEGE_SELF_TEST"),
        "true",
        StringComparison.OrdinalIgnoreCase
    )
)
{
    Environment.ExitCode = await WindowsFileCollectorSelfTest.RunPrivilegeAsync(
        Environment.GetEnvironmentVariable("PLATFORM_WINDOWS_FILE_COLLECTOR_PRIVILEGE_SELF_TEST_OUTPUT")
    );
    return;
}
if (
    string.Equals(
        Environment.GetEnvironmentVariable("PLATFORM_WINDOWS_FILE_COLLECTOR_SELF_TEST"),
        "true",
        StringComparison.OrdinalIgnoreCase
    )
)
{
    Environment.ExitCode = await WindowsFileCollectorSelfTest.RunAsync(
        Environment.GetEnvironmentVariable("PLATFORM_WINDOWS_FILE_COLLECTOR_SELF_TEST_OUTPUT")
    );
    return;
}
if (
    string.Equals(
        Environment.GetEnvironmentVariable("PLATFORM_CREDENTIAL_STORE_SELF_TEST"),
        "true",
        StringComparison.OrdinalIgnoreCase
    )
)
{
    Environment.ExitCode = await CredentialStoreSelfTest.RunAsync(
        Environment.GetEnvironmentVariable("PLATFORM_CREDENTIAL_STORE_SELF_TEST_OUTPUT")
    );
    return;
}
if (
    string.Equals(
        Environment.GetEnvironmentVariable("PLATFORM_FILE_DISK_SELF_TEST"),
        "true",
        StringComparison.OrdinalIgnoreCase
    )
)
{
    Environment.ExitCode = await FileDiskSelfTest.RunAsync(
        Environment.GetEnvironmentVariable("PLATFORM_FILE_DISK_SELF_TEST_ROOT"),
        Environment.GetEnvironmentVariable("PLATFORM_FILE_DISK_SELF_TEST_OUTPUT")
    );
    return;
}
if (
    string.Equals(
        Environment.GetEnvironmentVariable("PLATFORM_FILE_HASH_SELF_TEST"),
        "true",
        StringComparison.OrdinalIgnoreCase
    )
)
{
    Environment.ExitCode = await FileHashSelfTest.RunAsync(
        Environment.GetEnvironmentVariable("PLATFORM_FILE_HASH_SELF_TEST_OUTPUT")
    );
    return;
}
if (
    string.Equals(
        Environment.GetEnvironmentVariable("PLATFORM_FILE_HASH_PROFILE_SELF_TEST"),
        "true",
        StringComparison.OrdinalIgnoreCase
    )
)
{
    Environment.ExitCode = await FileHashProfileSelfTest.RunAsync(
        Environment.GetEnvironmentVariable("PLATFORM_FILE_HASH_PROFILE_OUTPUT")
    );
    return;
}
if (
    string.Equals(
        Environment.GetEnvironmentVariable("PLATFORM_PROCESS_COLLECTOR_SELF_TEST"),
        "true",
        StringComparison.OrdinalIgnoreCase
    )
)
{
    Environment.ExitCode = await ProcessCollectorSelfTest.RunAsync();
    return;
}
if (
    string.Equals(
        Environment.GetEnvironmentVariable("PLATFORM_CREDENTIAL_STORE_SELF_TEST"),
        "true",
        StringComparison.OrdinalIgnoreCase
    )
)
{
    var store = AgentCredentialStore.Create(agentOptions);
    var expected = new AgentState(
        Guid.NewGuid(),
        Guid.NewGuid(),
        Guid.NewGuid().ToString("N"),
        "self-test",
        "self-test",
        DateTimeOffset.UtcNow.AddMinutes(5),
        7
    );
    await store.SaveAsync(expected, default);
    var actual = await store.LoadAsync(default);
    if (actual != expected)
        throw new InvalidOperationException("Credential-store round-trip validation failed.");
    Console.WriteLine("Credential-store round-trip validation passed.");
    return;
}
builder.Services.AddSingleton(agentOptions);
builder.Services.AddSingleton<IAgentCredentialStore>(AgentCredentialStore.Create(agentOptions));
builder
    .Services.AddHttpClient("control", client => client.Timeout = TimeSpan.FromSeconds(15))
    .ConfigurePrimaryHttpMessageHandler(() => ServerAuthenticatedHandler(agentOptions));
if (!string.Equals(Environment.GetEnvironmentVariable("PLATFORM_RESPONSE_ONLY"), "true", StringComparison.OrdinalIgnoreCase))
    builder.Services.AddHostedService<AgentWorker>();
builder.Services.AddHostedService<EndpointResponseWorker>();
builder.Services.AddHostedService<EndpointLiveResponseWorker>();
await builder.Build().RunAsync();

static HttpClientHandler ServerAuthenticatedHandler(AgentOptions options)
{
    var handler = new HttpClientHandler();
    if (options.ControlPlaneUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
    {
        if (!File.Exists(options.CaCertificatePath))
            throw new InvalidOperationException(
                "The control-plane CA certificate is required for HTTPS."
            );
        var root = new X509Certificate2(options.CaCertificatePath);
        handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
        {
            if (certificate is null)
                return false;
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(new X509Certificate2(certificate));
        };
    }
    return handler;
}

sealed record AgentOptions(
    string ControlPlaneUrl,
    Guid? TokenId,
    string TokenSecret,
    string DataDirectory,
    string CaCertificatePath,
    string Environment,
    string CredentialStore,
    bool ForceCertificateRotation,
    string? ConfigurationPath
)
{
    static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };
    public static AgentOptions Load()
    {
        var path = System.Environment.GetEnvironmentVariable("PLATFORM_AGENT_CONFIG");
        if (string.IsNullOrWhiteSpace(path) && OperatingSystem.IsWindows())
            path = Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData), "OpenSecurityPlatform", "Agent", "agent-config.json");
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions { MaxDepth = 8 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Agent configuration root must be an object.");
            foreach (var property in document.RootElement.EnumerateObject())
                values[property.Name] = property.Value.ValueKind is JsonValueKind.String ? property.Value.GetString() : property.Value.GetRawText();
        }
        string Config(string env, string key, string fallback) => System.Environment.GetEnvironmentVariable(env) is { Length: > 0 } value ? value : values.GetValueOrDefault(key) ?? fallback;
        return new(
            Config("PLATFORM_CONTROL_PLANE_URL", "controlPlaneUrl", "http://localhost:8080"),
            Guid.TryParse(
                Config("PLATFORM_ENROLLMENT_TOKEN_ID", "enrollmentTokenId", ""),
                out var id
            )
                ? id
                : null,
            Config("PLATFORM_ENROLLMENT_TOKEN_SECRET", "enrollmentTokenSecret", ""),
            Config("PLATFORM_AGENT_DATA", "dataDirectory", "agent-data"),
            Config("PLATFORM_CA_CERT_PATH", "caCertificatePath", "ca.crt"),
            Config("PLATFORM_ENVIRONMENT", "environment", "production"),
            Config("PLATFORM_AGENT_CREDENTIAL_STORE", "credentialStore", "platform"),
            bool.TryParse(Config("PLATFORM_FORCE_CERTIFICATE_ROTATION", "forceCertificateRotation", "false"), out var force) && force,
            path
        );
    }

    public void RemoveOneTimeEnrollmentSecret()
    {
        if (string.IsNullOrWhiteSpace(ConfigurationPath) || !File.Exists(ConfigurationPath)) return;
        using var document = JsonDocument.Parse(File.ReadAllText(ConfigurationPath));
        var sanitized = document.RootElement.EnumerateObject().Where(x => !x.NameEquals("enrollmentTokenSecret") && !x.NameEquals("enrollmentTokenId")).ToDictionary(x => x.Name, x => x.Value.Clone(), StringComparer.OrdinalIgnoreCase);
        var temporary = ConfigurationPath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(sanitized, IndentedJson));
        File.Move(temporary, ConfigurationPath, true);
    }

    static string Get(string key, string fallback) =>
        System.Environment.GetEnvironmentVariable(key) is { Length: > 0 } value ? value : fallback;
}

sealed record AgentState(
    Guid EndpointId,
    Guid AgentId,
    string InstallationId,
    string ClientCertificatePfx,
    string CaCertificatePem,
    DateTimeOffset CredentialExpiresAt,
    long Sequence,
    bool ForcedRotationCompleted = false,
    long ProcessSequence = 0,
    long FileSequence = 0,
    long RegistrySequence = 0,
    long NetworkSequence = 0,
    long DnsSequence = 0,
    long ModuleSequence = 0,
    long PersistenceSequence = 0,
    long IdentitySequence = 0,
    long ExecutionSequence = 0,
    string TenantId = ""
);

sealed class AgentWorker(
    AgentOptions options,
    IAgentCredentialStore credentialStore,
    IHttpClientFactory clients,
    ILogger<AgentWorker> log
) : BackgroundService
{
    private readonly string _statePath = Path.Combine(options.DataDirectory, "state.json");
    private AgentState? _state;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        Directory.CreateDirectory(options.DataDirectory);
        var client = clients.CreateClient("control");
        client.BaseAddress = new Uri(options.ControlPlaneUrl);
        var failures = 0;
        ProcessTelemetryPipeline? telemetry = null;
        FileTelemetryPipeline? fileTelemetry = null;
        RegistryTelemetryPipeline? registryTelemetry = null;
        NetworkTelemetryPipeline? networkTelemetry = null;
        DnsTelemetryPipeline? dnsTelemetry = null;
        ModuleTelemetryPipeline? moduleTelemetry = null;
        ServiceTaskTelemetryPipeline? persistenceTelemetry = null;
        IdentityTelemetryPipeline? identityTelemetry = null;
        ExecutionTelemetryPipeline? executionTelemetry = null;
        string? lastCollectorHealth = null;
        var nextHeartbeat = DateTimeOffset.MinValue;
        var selfProtection = new AgentSelfProtectionClient(options, log);
        var agentUpdates = new AgentUpdateClient(options, log);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                _state ??= await LoadOrEnroll(client, ct);
                telemetry ??= new(options, _state.ProcessSequence);
                fileTelemetry ??= new(options, _state.FileSequence);
                registryTelemetry ??= new(options, _state.RegistrySequence);
                if (networkTelemetry is null)
                {
                    networkTelemetry = new(options, _state.NetworkSequence);
                    log.LogInformation(
                        "Telemetry collector startup states: network={NetworkState}; registry={RegistryState}; registryDiagnostic={RegistryError}",
                        networkTelemetry.CollectorState,
                        registryTelemetry.CollectorRuntimeState,
                        registryTelemetry.CollectorError
                    );
                    ct.Register(() =>
                        networkTelemetry.DisposeAsync().AsTask().GetAwaiter().GetResult()
                    );
                }
                if (dnsTelemetry is null)
                {
                    dnsTelemetry = new(options, _state.DnsSequence);
                    log.LogInformation("DNS telemetry collector startup state: {DnsState}", dnsTelemetry.CollectorState);
                    ct.Register(() => dnsTelemetry.DisposeAsync().AsTask().GetAwaiter().GetResult());
                    await Task.Delay(TimeSpan.FromMilliseconds(500), ct);
                }
                if (moduleTelemetry is null)
                {
                    moduleTelemetry = new(options, _state.ModuleSequence);
                    log.LogInformation("Module telemetry collector startup state: {ModuleState}", moduleTelemetry.CollectorState);
                    ct.Register(() => moduleTelemetry.DisposeAsync().AsTask().GetAwaiter().GetResult());
                    await Task.Delay(TimeSpan.FromMilliseconds(500), ct);
                }
                if (persistenceTelemetry is null)
                {
                    persistenceTelemetry = new(options, _state.PersistenceSequence);
                    log.LogInformation("Persistence telemetry collector startup states: service={ServiceState}; task={TaskState}; configuration={ConfigurationState}", persistenceTelemetry.ServiceState, persistenceTelemetry.TaskState, persistenceTelemetry.ConfigurationState);
                    ct.Register(() => persistenceTelemetry.DisposeAsync().AsTask().GetAwaiter().GetResult());
                }
                if (identityTelemetry is null)
                {
                    identityTelemetry = new(options, _state.IdentitySequence);
                    log.LogInformation("Identity telemetry pipeline initialized; elevated={Elevated}", identityTelemetry.Health(_state.EndpointId).Elevated);
                    ct.Register(() => identityTelemetry.DisposeAsync().AsTask().GetAwaiter().GetResult());
                }
                if (executionTelemetry is null)
                {
                    executionTelemetry = new(options, _state.ExecutionSequence);
                    log.LogInformation("Execution telemetry pipeline initialized; elevated={Elevated}", executionTelemetry.Health(_state.EndpointId).Elevated);
                    ct.Register(() => executionTelemetry.DisposeAsync().AsTask().GetAwaiter().GetResult());
                }
                if (
                    _state.CredentialExpiresAt <= DateTimeOffset.UtcNow.AddHours(4)
                    || (options.ForceCertificateRotation && !_state.ForcedRotationCompleted)
                )
                    _state = await Renew(_state, ct);
                try
                {
                    var executionSequence = await executionTelemetry.RunOnceAsync(
                        _state, AuthenticatedClient,
                        async (sequence, token) =>
                        {
                            if (_state is not null && sequence != _state.ExecutionSequence)
                            { _state = _state with { ExecutionSequence = sequence }; await Save(_state, token); }
                        }, ct);
                    if (executionSequence != _state.ExecutionSequence)
                    { _state = _state with { ExecutionSequence = executionSequence }; await Save(_state, ct); }
                }
                catch (Exception e) when (e is HttpRequestException or IOException)
                { log.LogWarning("Execution telemetry partition failed without blocking other collectors: {ErrorType}", e.GetType().Name); }
                try
                {
                    var identitySequence = await identityTelemetry.RunOnceAsync(
                        _state, AuthenticatedClient,
                        async (sequence, token) =>
                        {
                            if (_state is not null && sequence != _state.IdentitySequence)
                            { _state = _state with { IdentitySequence = sequence }; await Save(_state, token); }
                        }, ct);
                    if (identitySequence != _state.IdentitySequence)
                    { _state = _state with { IdentitySequence = identitySequence }; await Save(_state, ct); }
                }
                catch (Exception e) when (e is HttpRequestException or IOException)
                { log.LogWarning("Identity telemetry partition failed without blocking other collectors: {ErrorType}", e.GetType().Name); }
                try
                {
                    var persistenceSequence = await persistenceTelemetry.RunOnceAsync(
                        _state, AuthenticatedClient,
                        async (sequence, token) =>
                        {
                            if (_state is not null && sequence != _state.PersistenceSequence)
                            { _state = _state with { PersistenceSequence = sequence }; await Save(_state, token); }
                        }, ct);
                    if (persistenceSequence != _state.PersistenceSequence)
                    { _state = _state with { PersistenceSequence = persistenceSequence }; await Save(_state, ct); }
                }
                catch (Exception e) when (e is HttpRequestException or IOException)
                { log.LogWarning("Service/task telemetry partition failed without blocking other collectors: {ErrorType}", e.GetType().Name); }
                try
                {
                    var moduleSequence = await moduleTelemetry.RunOnceAsync(
                        _state, AuthenticatedClient,
                        async (sequence, token) =>
                        {
                            if (_state is not null && sequence != _state.ModuleSequence)
                            { _state = _state with { ModuleSequence = sequence }; await Save(_state, token); }
                        }, ct);
                    if (moduleSequence != _state.ModuleSequence)
                    { _state = _state with { ModuleSequence = moduleSequence }; await Save(_state, ct); }
                }
                catch (Exception e) when (e is HttpRequestException or IOException)
                { log.LogWarning("Module telemetry partition failed without blocking other collectors: {ErrorType}", e.GetType().Name); }
                try
                {
                    var dnsSequence = await dnsTelemetry.RunOnceAsync(
                        _state, AuthenticatedClient,
                        async (sequence, token) =>
                        {
                            if (_state is not null && sequence != _state.DnsSequence)
                            { _state = _state with { DnsSequence = sequence }; await Save(_state, token); }
                        }, ct);
                    if (dnsSequence != _state.DnsSequence)
                    { _state = _state with { DnsSequence = dnsSequence }; await Save(_state, ct); }
                }
                catch (Exception e) when (e is HttpRequestException or IOException)
                { log.LogWarning("DNS telemetry partition failed without blocking other collectors: {ErrorType}", e.GetType().Name); }
                try
                {
                    var networkSequence = await networkTelemetry.RunOnceAsync(
                        _state,
                        AuthenticatedClient,
                        async (sequence, token) =>
                        {
                            if (_state is not null && sequence != _state.NetworkSequence)
                            {
                                _state = _state with { NetworkSequence = sequence };
                                await Save(_state, token);
                            }
                        },
                        ct
                    );
                    if (networkSequence != _state.NetworkSequence)
                    {
                        _state = _state with { NetworkSequence = networkSequence };
                        await Save(_state, ct);
                    }
                }
                catch (Exception e) when (e is HttpRequestException or IOException)
                { log.LogWarning("Network telemetry partition failed without blocking other collectors: {ErrorType}", e.GetType().Name); }
                try
                {
                    var processSequence = await telemetry.RunOnceAsync(
                        _state,
                        AuthenticatedClient,
                        async (sequence, token) =>
                        {
                            if (_state is not null && sequence != _state.ProcessSequence)
                            {
                                _state = _state with { ProcessSequence = sequence };
                                await Save(_state, token);
                            }
                        },
                        ct
                    );
                    if (telemetry.CollectorHealth.State != lastCollectorHealth)
                    {
                        lastCollectorHealth = telemetry.CollectorHealth.State;
                        if (
                            lastCollectorHealth == "healthy"
                            || lastCollectorHealth == "policy-disabled"
                        )
                            log.LogInformation(
                                "Process collector health changed to {CollectorHealth}",
                                lastCollectorHealth
                            );
                        else
                            log.LogWarning(
                                "Process collector health changed to {CollectorHealth}; collection errors {CollectionErrors}; diagnostic {CollectorError}",
                                lastCollectorHealth,
                                telemetry.CollectorHealth.CollectionErrors,
                                telemetry.CollectorHealth.Error
                            );
                    }
                    if (processSequence != _state.ProcessSequence)
                    {
                        _state = _state with { ProcessSequence = processSequence };
                        await Save(_state, ct);
                    }
                }
                catch (Exception e) when (e is HttpRequestException or IOException)
                {
                    log.LogWarning("Process telemetry partition failed without blocking other collectors: {ErrorType}", e.GetType().Name);
                }
                try
                {
                    var fileSequence = await fileTelemetry.RunOnceAsync(
                        _state,
                        AuthenticatedClient,
                        async (sequence, token) =>
                        {
                            if (_state is not null && sequence != _state.FileSequence)
                            {
                                _state = _state with { FileSequence = sequence };
                                await Save(_state, token);
                            }
                        },
                        ct
                    );
                    if (fileSequence != _state.FileSequence)
                    {
                        _state = _state with { FileSequence = fileSequence };
                        await Save(_state, ct);
                    }
                }
                catch (Exception e) when (e is HttpRequestException or IOException)
                {
                    log.LogWarning("File telemetry partition failed without blocking other collectors: {ErrorType}", e.GetType().Name);
                }
                try
                {
                    var registrySequence = await registryTelemetry.RunOnceAsync(
                        _state,
                        AuthenticatedClient,
                        async (sequence, token) =>
                        {
                            if (_state is not null && sequence != _state.RegistrySequence)
                            {
                                _state = _state with { RegistrySequence = sequence };
                                await Save(_state, token);
                            }
                        },
                        ct
                    );
                    if (registrySequence != _state.RegistrySequence)
                    {
                        _state = _state with { RegistrySequence = registrySequence };
                        await Save(_state, ct);
                    }
                }
                catch (Exception e) when (e is HttpRequestException or IOException)
                {
                    log.LogWarning("Registry telemetry partition failed without blocking other collectors: {ErrorType}", e.GetType().Name);
                }
                if (DateTimeOffset.UtcNow >= nextHeartbeat)
                {
                    await selfProtection.RunOnceAsync(_state, AuthenticatedClient, ct);
                    await agentUpdates.RunOnceAsync(_state, AuthenticatedClient, ct);
                    await SyncNetworkPolicy(_state, networkTelemetry, ct);
                    await SyncDnsPolicy(_state, dnsTelemetry, ct);
                    await SyncModulePolicy(_state, moduleTelemetry, ct);
                    await SyncPersistencePolicy(_state, persistenceTelemetry, ct);
                    await SyncIdentityPolicy(_state, identityTelemetry, ct);
                    await SyncExecutionPolicy(_state, executionTelemetry, ct);
                    await SyncProcessPolicy(_state, telemetry, ct);
                    await SyncFilePolicy(_state, fileTelemetry, ct);
                    await SyncRegistryPolicy(_state, registryTelemetry, ct);
                    var next = _state.Sequence + 1;
                    var platform = Platform();
                    var inventory = new InventorySummary(
                        Environment.MachineName,
                        platform,
                        RuntimeInformation.OSDescription,
                        RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(),
                        [],
                        []
                    );
                    var heartbeat = new HeartbeatRequest(
                        _state.EndpointId,
                        _state.AgentId,
                        next,
                        DateTimeOffset.UtcNow,
                        Environment.TickCount64 / 1000,
                        ProductRelease.Version,
                        "1.2",
                        platform,
                        RuntimeInformation.OSDescription,
                        null,
                        "1",
                        Capabilities(telemetry, networkTelemetry, dnsTelemetry, moduleTelemetry, persistenceTelemetry, identityTelemetry, executionTelemetry),
                        telemetry.CollectorHealth.State switch
                        {
                            "healthy" => "healthy",
                            "policy-disabled" => "policy-disabled",
                            _ => "degraded",
                        },
                        telemetry.QueueStatus.Depth,
                        telemetry.QueueStatus.Depth == 0 ? null : telemetry.QueueStatus.OldestAge,
                        null,
                        Environment.WorkingSet,
                        inventory
                    );
                    using var authenticated = AuthenticatedClient(_state);
                    using var response = await authenticated.PostAsJsonAsync(
                        "/agent/v1/checkins",
                        heartbeat,
                        ct
                    );
                    response.EnsureSuccessStatusCode();
                    _state = _state with { Sequence = next };
                    await Save(_state, ct);
                    failures = 0;
                    nextHeartbeat = DateTimeOffset.UtcNow.AddSeconds(30);
                    log.LogInformation(
                        "Authenticated heartbeat {Sequence} accepted for endpoint {EndpointId}",
                        next,
                        _state.EndpointId
                    );
                }
                await Task.Delay(TimeSpan.FromMilliseconds(500), ct);
            }
            catch (Exception e)
                when (e is HttpRequestException
                    or TaskCanceledException
                    or IOException
                    or UnauthorizedAccessException)
            {
                failures = Math.Min(failures + 1, 8);
                var delay = TimeSpan.FromSeconds(
                    Math.Min(60, Math.Pow(2, failures)) + Random.Shared.NextDouble()
                );
                log.LogWarning(
                    e,
                    "Agent transient failure ({ErrorType}: {ErrorMessage}); retrying in {DelaySeconds:F1}s",
                    e.GetType().Name,
                    e.Message,
                    delay.TotalSeconds
                );
                await Task.Delay(delay, ct);
            }
        }
    }

    private async Task<AgentState> LoadOrEnroll(HttpClient client, CancellationToken ct)
    {
        if (await credentialStore.LoadAsync(ct) is { } secured)
            return secured;
        if (File.Exists(_statePath))
        {
            var existing = JsonSerializer.Deserialize<AgentState>(
                await File.ReadAllTextAsync(_statePath, ct)
            );
            if (existing is { ClientCertificatePfx.Length: > 0, CaCertificatePem.Length: > 0 })
            {
                await credentialStore.SaveAsync(existing, ct);
                File.Move(_statePath, _statePath + ".migrated", true);
                return existing;
            }
            File.Move(_statePath, _statePath + ".legacy", true);
            log.LogWarning(
                "Legacy bearer-token state was quarantined; certificate enrollment is required."
            );
        }
        if (options.TokenId is null || options.TokenSecret.Length < 32)
            throw new InvalidOperationException(
                "One-time enrollment token ID and secret are required for first start."
            );
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var installation = Guid.NewGuid().ToString("N");
        var certificateRequest = new CertificateRequest(
            $"CN={installation}",
            key,
            HashAlgorithmName.SHA256
        );
        certificateRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true)
        );
        var request = new EnrollmentRequest(
            options.TokenId.Value,
            options.TokenSecret,
            installation,
            Guid.NewGuid().ToString("N"),
            Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant(),
            DateTimeOffset.UtcNow,
            "1.1",
            ProductRelease.Version,
            Platform(),
            RuntimeInformation.OSDescription,
            RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(),
            Environment.MachineName,
            certificateRequest.CreateSigningRequestPem(),
            Capabilities()
        );
        using var response = await client.PostAsJsonAsync("/agent/v1/register", request, ct);
        response.EnsureSuccessStatusCode();
        var envelope =
            await response.Content.ReadFromJsonAsync<ApiEnvelope<EnrollmentResult>>(
                cancellationToken: ct
            ) ?? throw new InvalidDataException("Enrollment response is invalid.");
        using var publicCertificate = X509Certificate2.CreateFromPem(
            envelope.Data.AgentCertificatePem
        );
        using var certificate = publicCertificate.CopyWithPrivateKey(key);
        var state = new AgentState(
            envelope.Data.EndpointId,
            envelope.Data.AgentId,
            installation,
            Convert.ToBase64String(certificate.Export(X509ContentType.Pkcs12)),
            envelope.Data.CaCertificatePem,
            envelope.Data.CredentialExpiresAt,
            0,
            TenantId: envelope.Data.TenantId
        );
        await Save(state, ct);
        options.RemoveOneTimeEnrollmentSecret();
        log.LogInformation(
            "Endpoint enrolled as {EndpointId}; enrollment secret was not persisted",
            state.EndpointId
        );
        return state;
    }

    private async Task<AgentState> Renew(AgentState state, CancellationToken ct)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            $"CN={state.InstallationId}",
            key,
            HashAlgorithmName.SHA256
        );
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true)
        );
        using var client = AuthenticatedClient(state);
        using var response = await client.PostAsJsonAsync(
            "/agent/v1/certificates:renew",
            new CertificateRenewalRequest(request.CreateSigningRequestPem()),
            ct
        );
        response.EnsureSuccessStatusCode();
        var envelope =
            await response.Content.ReadFromJsonAsync<ApiEnvelope<CertificateRenewalResult>>(
                cancellationToken: ct
            ) ?? throw new InvalidDataException("Certificate renewal response is invalid.");
        using var publicCertificate = X509Certificate2.CreateFromPem(
            envelope.Data.AgentCertificatePem
        );
        using var certificate = publicCertificate.CopyWithPrivateKey(key);
        var renewed = state with
        {
            ClientCertificatePfx = Convert.ToBase64String(
                certificate.Export(X509ContentType.Pkcs12)
            ),
            CaCertificatePem = envelope.Data.CaCertificatePem,
            CredentialExpiresAt = envelope.Data.CredentialExpiresAt,
            ForcedRotationCompleted = true,
        };
        await Save(renewed, ct);
        log.LogInformation(
            "Agent certificate rotated; expires {CredentialExpiresAt}",
            renewed.CredentialExpiresAt
        );
        return renewed;
    }

    private HttpClient AuthenticatedClient(AgentState state)
    {
        var handler = new HttpClientHandler();
        handler.ClientCertificates.Add(
            new X509Certificate2(
                Convert.FromBase64String(state.ClientCertificatePfx),
                (string?)null,
                X509KeyStorageFlags.MachineKeySet
            )
        );
        if (options.ControlPlaneUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            var root = X509Certificate2.CreateFromPem(state.CaCertificatePem);
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
            {
                if (certificate is null)
                    return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(root);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(new X509Certificate2(certificate));
            };
        }
        return new HttpClient(handler)
        {
            BaseAddress = new Uri(options.ControlPlaneUrl),
            Timeout = TimeSpan.FromSeconds(15),
        };
    }

    private Task Save(AgentState state, CancellationToken ct) =>
        credentialStore.SaveAsync(state, ct);

    private async Task SyncProcessPolicy(
        AgentState state,
        ProcessTelemetryPipeline telemetry,
        CancellationToken ct
    )
    {
        using var client = AuthenticatedClient(state);
        var effective = await client.GetFromJsonAsync<EffectiveProcessPolicy>(
            "/agent/v1/process-policy",
            ct
        );
        if (
            effective is null
            || $"{effective.Policy.Id:D}:{effective.Policy.Version}" == telemetry.CurrentPolicyKey
        )
            return;
        var errors = await telemetry.ApplyPolicyAsync(
            effective.Policy.Policy,
            effective.Policy.Id,
            effective.Policy.Version,
            ct
        );
        var validationError = errors.Count == 0 ? null : JsonSerializer.Serialize(errors);
        using var response = await client.PostAsJsonAsync(
            "/agent/v1/process-policy:acknowledge",
            new ProcessPolicyAcknowledgement(
                effective.Policy.Id,
                effective.Policy.Version,
                errors.Count == 0,
                validationError,
                DateTimeOffset.UtcNow
            ),
            ct
        );
        response.EnsureSuccessStatusCode();
        log.LogInformation(
            "Process policy {PolicyVersion} {Outcome}",
            effective.Policy.Version,
            errors.Count == 0 ? "applied" : "rejected"
        );
    }

    private async Task SyncFilePolicy(
        AgentState state,
        FileTelemetryPipeline telemetry,
        CancellationToken ct
    )
    {
        using var client = AuthenticatedClient(state);
        var effective = await client.GetFromJsonAsync<EffectiveFilePolicy>(
            "/agent/v1/file-policy",
            ct
        );
        if (
            effective is null
            || $"{effective.Policy.Id:D}:{effective.Policy.Version}" == telemetry.CurrentPolicyKey
        )
            return;
        var errors = await telemetry.ApplyPolicyAsync(
            effective.Policy.Policy,
            effective.Policy.Id,
            effective.Policy.Version
        );
        using var response = await client.PostAsJsonAsync(
            "/agent/v1/file-policy:acknowledge",
            new FilePolicyAcknowledgement(
                effective.Policy.Id,
                effective.Policy.Version,
                errors.Count == 0,
                errors.Count == 0 ? null : JsonSerializer.Serialize(errors),
                DateTimeOffset.UtcNow
            ),
            ct
        );
        response.EnsureSuccessStatusCode();
        log.LogInformation(
            "File policy {PolicyVersion} {Outcome}",
            effective.Policy.Version,
            errors.Count == 0 ? "applied" : "rejected"
        );
    }

    private async Task SyncRegistryPolicy(
        AgentState state,
        RegistryTelemetryPipeline telemetry,
        CancellationToken ct
    )
    {
        using var client = AuthenticatedClient(state);
        var effective = await client.GetFromJsonAsync<EffectiveRegistryPolicy>(
            "/agent/v1/registry-policy",
            ct
        );
        if (
            effective is null
            || $"{effective.Policy.Id:D}:{effective.Policy.Version}" == telemetry.CurrentPolicyKey
        )
            return;
        var errors = await telemetry.ApplyPolicyAsync(
            effective.Policy.Policy,
            effective.Policy.Id,
            effective.Policy.Version
        );
        using var response = await client.PostAsJsonAsync(
            "/agent/v1/registry-policy:acknowledge",
            new RegistryPolicyAcknowledgement(
                effective.Policy.Id,
                effective.Policy.Version,
                errors.Count == 0,
                errors.Count == 0 ? null : JsonSerializer.Serialize(errors),
                DateTimeOffset.UtcNow
            ),
            ct
        );
        response.EnsureSuccessStatusCode();
        log.LogInformation(
            "Registry policy {PolicyVersion} {Outcome}",
            effective.Policy.Version,
            errors.Count == 0 ? "applied" : "rejected"
        );
    }

    private async Task SyncNetworkPolicy(
        AgentState state,
        NetworkTelemetryPipeline telemetry,
        CancellationToken ct
    )
    {
        using var client = AuthenticatedClient(state);
        var effective = await client.GetFromJsonAsync<EffectiveNetworkPolicy>(
            "/agent/v1/network-policy",
            ct
        );
        if (
            effective is null
            || $"{effective.Policy.Id:D}:{effective.Policy.Version}" == telemetry.CurrentPolicyKey
        )
            return;
        var errors = await telemetry.ApplyPolicyAsync(
            effective.Policy.Policy,
            effective.Policy.Id,
            effective.Policy.Version
        );
        using var response = await client.PostAsJsonAsync(
            "/agent/v1/network-policy:acknowledge",
            new NetworkPolicyAcknowledgement(
                effective.Policy.Id,
                effective.Policy.Version,
                errors.Count == 0,
                errors.Count == 0 ? null : JsonSerializer.Serialize(errors),
                DateTimeOffset.UtcNow
            ),
            ct
        );
        response.EnsureSuccessStatusCode();
        log.LogInformation(
            "Network policy {PolicyVersion} {Outcome}",
            effective.Policy.Version,
            errors.Count == 0 ? "applied" : "rejected"
        );
    }

    private async Task SyncDnsPolicy(AgentState state, DnsTelemetryPipeline telemetry, CancellationToken ct)
    {
        using var client = AuthenticatedClient(state);
        var effective = await client.GetFromJsonAsync<EffectiveDnsPolicy>("/agent/v1/dns-policy", ct);
        if (effective is null || $"{effective.Policy.Id:D}:{effective.Policy.Version}" == telemetry.CurrentPolicyKey) return;
        var errors = await telemetry.ApplyPolicyAsync(effective.Policy.Policy, effective.Policy.Id, effective.Policy.Version);
        using var response = await client.PostAsJsonAsync("/agent/v1/dns-policy:acknowledge",
            new DnsPolicyAcknowledgement(effective.Policy.Id, effective.Policy.Version,
                errors.Count == 0, errors.Count == 0 ? null : JsonSerializer.Serialize(errors), DateTimeOffset.UtcNow), ct);
        response.EnsureSuccessStatusCode();
        log.LogInformation("DNS policy {PolicyVersion} {Outcome}", effective.Policy.Version, errors.Count == 0 ? "applied" : "rejected");
    }

    private async Task SyncModulePolicy(AgentState state, ModuleTelemetryPipeline telemetry, CancellationToken ct)
    {
        using var client = AuthenticatedClient(state);
        var effective = await client.GetFromJsonAsync<EffectiveModulePolicy>("/agent/v1/module-policy", ct);
        if (effective is null || $"{effective.Policy.Id:D}:{effective.Policy.Version}" == telemetry.CurrentPolicyKey) return;
        var errors = await telemetry.ApplyPolicyAsync(effective.Policy.Policy, effective.Policy.Id, effective.Policy.Version);
        using var response = await client.PostAsJsonAsync("/agent/v1/module-policy:acknowledge",
            new ModulePolicyAcknowledgement(effective.Policy.Id, effective.Policy.Version,
                errors.Count == 0, errors.Count == 0 ? null : JsonSerializer.Serialize(errors), DateTimeOffset.UtcNow), ct);
        response.EnsureSuccessStatusCode();
        log.LogInformation("Module policy {PolicyVersion} {Outcome}", effective.Policy.Version, errors.Count == 0 ? "applied" : "rejected");
    }

    private async Task SyncPersistencePolicy(AgentState state, ServiceTaskTelemetryPipeline telemetry, CancellationToken ct)
    {
        using var client = AuthenticatedClient(state);
        var effective = await client.GetFromJsonAsync<EffectivePersistencePolicy>("/agent/v1/persistence-policy", ct);
        if (effective is null || $"{effective.Policy.Id:D}:{effective.Policy.Version}" == telemetry.CurrentPolicyKey) return;
        var errors = await telemetry.ApplyPolicyAsync(effective.Policy.Policy, effective.Policy.Id, effective.Policy.Version);
        using var response = await client.PostAsJsonAsync("/agent/v1/persistence-policy:acknowledge",
            new PersistencePolicyAcknowledgement(effective.Policy.Id, effective.Policy.Version,
                errors.Count == 0, errors.Count == 0 ? null : JsonSerializer.Serialize(errors), DateTimeOffset.UtcNow), ct);
        response.EnsureSuccessStatusCode();
        log.LogInformation("Service/task policy {PolicyVersion} {Outcome}", effective.Policy.Version, errors.Count == 0 ? "applied" : "rejected");
    }

    private async Task SyncIdentityPolicy(AgentState state, IdentityTelemetryPipeline telemetry, CancellationToken ct)
    {
        using var client = AuthenticatedClient(state);
        var effective = await client.GetFromJsonAsync<EffectiveIdentityPolicy>("/agent/v1/identity-policy", ct);
        if (effective is null || $"{effective.Policy.Id:D}:{effective.Policy.Version}" == telemetry.CurrentPolicyKey) return;
        var errors = await telemetry.ApplyPolicyAsync(effective.Policy.Policy, effective.Policy.Id, effective.Policy.Version);
        using var response = await client.PostAsJsonAsync("/agent/v1/identity-policy:acknowledge",
            new IdentityPolicyAcknowledgement(effective.Policy.Id, effective.Policy.Version,
                errors.Count == 0, errors.Count == 0 ? null : JsonSerializer.Serialize(errors), DateTimeOffset.UtcNow), ct);
        response.EnsureSuccessStatusCode();
        log.LogInformation("Identity policy {PolicyVersion} {Outcome}", effective.Policy.Version, errors.Count == 0 ? "applied" : "rejected");
    }

    private async Task SyncExecutionPolicy(AgentState state, ExecutionTelemetryPipeline telemetry, CancellationToken ct)
    {
        using var client = AuthenticatedClient(state);
        var effective = await client.GetFromJsonAsync<EffectiveExecutionPolicy>("/agent/v1/execution-policy", ct);
        if (effective is null || $"{effective.Policy.Id:D}:{effective.Policy.Version}" == telemetry.CurrentPolicyKey) return;
        var errors = await telemetry.ApplyPolicyAsync(effective.Policy.Policy, effective.Policy.Id, effective.Policy.Version);
        using var response = await client.PostAsJsonAsync("/agent/v1/execution-policy:acknowledge",
            new ExecutionPolicyAcknowledgement(effective.Policy.Id, effective.Policy.Version, errors.Count == 0,
                errors.Count == 0 ? null : JsonSerializer.Serialize(errors), DateTimeOffset.UtcNow), ct);
        response.EnsureSuccessStatusCode();
        log.LogInformation("Execution policy {PolicyVersion} {Outcome}", effective.Policy.Version, errors.Count == 0 ? "applied" : "rejected");
    }

    private static string Platform() =>
        OperatingSystem.IsWindows() ? "windows"
        : OperatingSystem.IsMacOS() ? "macos"
        : "linux";

    private static string[] Capabilities(
        ProcessTelemetryPipeline? telemetry = null,
        NetworkTelemetryPipeline? network = null,
        DnsTelemetryPipeline? dns = null,
        ModuleTelemetryPipeline? module = null,
        ServiceTaskTelemetryPipeline? persistence = null,
        IdentityTelemetryPipeline? identity = null,
        ExecutionTelemetryPipeline? execution = null
    ) =>
        [
            "registration.v1.1",
            "heartbeat.v1.2",
            "inventory-summary.v1",
            .. (
                telemetry?.Capabilities()
                ?? [$"process.start.v1:{CollectorType()}", $"process.exit.v1:{CollectorType()}"]
            ),
            "process.queue.v1",
            "process.hashing:false",
            "process.signature:false",
            $"file.create.v1:{FileCollectorType()}",
            $"file.modify.v1:{FileCollectorType()}",
            $"file.delete.v1:{FileCollectorType()}",
            $"file.rename.v1:{FileCollectorType()}",
            "file.queue.v1",
            $"registry.key.create.v1:{RegistryCollectorType()}",
            $"registry.key.delete.v1:{RegistryCollectorType()}",
            $"registry.value.set.v1:{RegistryCollectorType()}",
            $"registry.value.delete.v1:{RegistryCollectorType()}",
            "registry.queue.v1",
            $"network.tcp.lifecycle.v1:{network?.CollectorType ?? NetworkCollectorType()}",
            $"network.udp.operation.v1:{network?.CollectorType ?? NetworkCollectorType()}",
            "network.queue.v1",
            "network.payload:false",
            $"dns.query.v1:{dns?.CollectorType ?? DnsCollectorType()}",
            $"dns.response.v1:{dns?.CollectorType ?? DnsCollectorType()}",
            "dns.queue.v1",
            "dns.packet-payload:false",
            "network.tls-http:false",
            .. (module?.Capabilities() ?? [$"module.image-load.v1:{ModuleCollectorType()}", $"module.driver-load.v1:{ModuleCollectorType()}", "module.queue.v1"]),
            .. (persistence?.Capabilities() ?? ["service.lifecycle.v1:windows", "scheduled-task.lifecycle.v1:windows", "persistence.queue.v1"]),
            "identity.logon.v1:windows-security-event-log",
            "identity.session.v1:windows-terminal-services",
            "identity.token-state.v1:windows-token-api",
            "identity.queue.v1",
            "execution.thread.v1:windows-kernel-thread-etw",
            "execution.handle-request.v1:windows-security-event-log",
            "execution.memory-contents:false",
            "execution.memory-write.v1:not-observable-by-source",
            "execution.apc.v1:not-observable-by-source",
            "execution.section.v1:not-observable-by-source",
            "execution.queue.v1",
            "response.worker.v1:bounded",
            "response.endpoint.status.v1:safe",
            "response.process.list.v1:safe",
            "response.network.connections.v1:safe",
            "response.service.status.v1:safe",
            "response.file.metadata.v1:platform-data-only",
            "response.collect.diagnostic.v1:safe",
        ];

    private static string CollectorType() =>
        OperatingSystem.IsLinux()
            ? (
                Environment.GetEnvironmentVariable("PLATFORM_PROCESS_COLLECTOR") is "procfs"
                    ? "linux.procfs-evaluation"
                    : "linux.falco-json"
            )
        : OperatingSystem.IsWindows() ? "windows.etw"
        : "macos.endpoint-security";

    private static string FileCollectorType() =>
        OperatingSystem.IsWindows() ? "windows.etw-file"
        : OperatingSystem.IsLinux() ? "linux.falco-json"
        : "macos.endpoint-security";

    private static string RegistryCollectorType() =>
        OperatingSystem.IsWindows() ? "windows.etw-registry" : "unsupported";

    private static string NetworkCollectorType() =>
        OperatingSystem.IsWindows() ? "windows.etw-network"
        : OperatingSystem.IsLinux() ? "linux.falco-json"
        : "unsupported";

    private static string DnsCollectorType() =>
        OperatingSystem.IsWindows() ? "windows.dns-client-etw"
        : OperatingSystem.IsLinux() ? "linux.unsupported"
        : "unsupported";

    private static string ModuleCollectorType() =>
        OperatingSystem.IsWindows() ? "windows.kernel-image-etw"
        : OperatingSystem.IsLinux() ? "linux.unsupported"
        : "unsupported";
}
