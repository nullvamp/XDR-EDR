using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Npgsql;
using OpenSecurityPlatform.Foundation;
using OpenSecurityPlatform.Infrastructure;

var options = PlatformOptions.FromEnvironment();
options.Validate();
if (options.AdapterMode == "development")
    Directory.CreateDirectory(options.DataDirectory);
var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(o => o.TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'");
builder.Services.AddSingleton(options);
builder.Services.AddSingleton<JwtService>();
builder.Services.AddSingleton<PlatformMetrics>();
builder.Services.AddSingleton<PlatformClientCatalog>();
builder.Services.AddSingleton<ArtifactTransferStore>();
builder.Services.AddSingleton<ToolPackageStore>();
if (options.AdapterMode == "production")
{
    builder.Services.AddSingleton(_ => new CertificateAuthority(
        options.CertificateAuthorityPath!,
        options.CertificateAuthorityPassword
    ));
    builder.Services.AddSingleton<IEndpointRepository>(_ => new PostgresEndpointRepository(
        options.DatabaseUrl!
    ));
    builder.Services.AddSingleton<IProcessTelemetryRepository>(
        _ => new PostgresProcessTelemetryRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<IProcessPolicyRepository>(
        _ => new PostgresProcessPolicyRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<IFileTelemetryRepository>(
        _ => new PostgresFileTelemetryRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<IFilePolicyRepository>(_ => new PostgresFilePolicyRepository(
        options.DatabaseUrl!
    ));
    builder.Services.AddSingleton<IFileExportRepository>(_ => new PostgresFileExportRepository(
        options.DatabaseUrl!
    ));
    builder.Services.AddSingleton<IRegistryTelemetryRepository>(
        _ => new PostgresRegistryTelemetryRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<IRegistryPolicyRepository>(
        _ => new PostgresRegistryPolicyRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<IRegistryExportRepository>(
        _ => new PostgresRegistryExportRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<INetworkTelemetryRepository>(
        _ => new PostgresNetworkTelemetryRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<INetworkPolicyRepository>(
        _ => new PostgresNetworkPolicyRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<INetworkExportRepository>(
        _ => new PostgresNetworkExportRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<IDnsTelemetryRepository>(
        _ => new PostgresDnsTelemetryRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<IDnsPolicyRepository>(
        _ => new PostgresDnsPolicyRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<IDnsExportRepository>(
        _ => new PostgresDnsExportRepository(options.DatabaseUrl!)
    );
    builder.Services.AddSingleton<IModuleTelemetryRepository>(_ => new PostgresModuleTelemetryRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IModulePolicyRepository>(_ => new PostgresModulePolicyRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IModuleExportRepository>(_ => new PostgresModuleExportRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IPersistenceTelemetryRepository>(_ => new PostgresPersistenceTelemetryRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IPersistencePolicyRepository>(_ => new PostgresPersistencePolicyRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IPersistenceExportRepository>(_ => new PostgresPersistenceExportRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IIdentityTelemetryRepository>(_ => new PostgresIdentityTelemetryRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IIdentityPolicyRepository>(_ => new PostgresIdentityPolicyRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IIdentityExportRepository>(_ => new PostgresIdentityExportRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IExecutionTelemetryRepository>(_ => new PostgresExecutionTelemetryRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IExecutionPolicyRepository>(_ => new PostgresExecutionPolicyRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IExecutionExportRepository>(_ => new PostgresExecutionExportRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IDetectionRepository>(_ => new PostgresDetectionRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IDetectionEventSource>(_ => new PostgresDetectionEventSource(options.DatabaseUrl!));
    builder.Services.AddSingleton<ICorrelationRepository>(_ => new PostgresCorrelationRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IInvestigationRepository>(_ => new PostgresInvestigationRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IAlertIncidentRepository>(_ => new PostgresAlertIncidentRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IResponseActionRepository>(_ => new PostgresResponseActionRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IIsolationRepository>(p => new PostgresIsolationRepository(options.DatabaseUrl!, p.GetRequiredService<IResponseActionRepository>()));
    builder.Services.AddSingleton<ILiveResponseRepository>(_ => new PostgresLiveResponseRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<PostgresThreatIntelligenceRepository>(_ => new(options.DatabaseUrl!));
    builder.Services.AddSingleton<IThreatIntelligenceRepository>(p => p.GetRequiredService<PostgresThreatIntelligenceRepository>());
    builder.Services.AddSingleton<IThreatBackmatchProcessor>(p => p.GetRequiredService<PostgresThreatIntelligenceRepository>());
    builder.Services.AddSingleton<ITunnelAnalyticsRepository>(_ => new PostgresTunnelAnalyticsRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<PostgresPlaybookRepository>(_ => new(options.DatabaseUrl!));
    builder.Services.AddSingleton<IPlaybookRepository>(p => p.GetRequiredService<PostgresPlaybookRepository>());
    builder.Services.AddSingleton<IPlaybookWorkSource>(p => p.GetRequiredService<PostgresPlaybookRepository>());
    builder.Services.AddSingleton<IAgentProtectionRepository>(_ => new PostgresAgentProtectionRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IFleetUpdateRepository>(_ => new PostgresFleetUpdateRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IHighAvailabilityRepository>(_ => new PostgresHighAvailabilityRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IArtifactTransferStateRepository>(_ => new PostgresArtifactTransferStateRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<ICapacityRetentionRepository>(_ => new PostgresCapacityRetentionRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IAiInvestigationRepository>(_ => new PostgresAiInvestigationRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IAiEngineeringRepository>(_ => new PostgresAiEngineeringRepository(options.DatabaseUrl!));
    builder.Services.AddSingleton<IAdministrationStateStore>(_ => new PostgresAdministrationStateStore(options.DatabaseUrl!));
    builder.Services.AddSingleton<IForensicWorkspaceStore>(_ => new PostgresForensicWorkspaceStore(options.DatabaseUrl!));
    builder.Services.AddSingleton<NatsMessageBus>(p =>
        new(
            options.MessageBusUrl!,
            options.ServiceName,
            p.GetRequiredService<ILogger<NatsMessageBus>>()
        )
    );
    builder.Services.AddSingleton<IMessageBus>(p => p.GetRequiredService<NatsMessageBus>());
    var objectUri = new Uri(options.ObjectStoreUrl!);
    builder.Services.AddSingleton<MinioObjectStorage>(_ =>
        new(
            objectUri.Authority,
            options.ObjectStoreAccessKey,
            options.ObjectStoreSecretKey,
            options.ObjectStoreBucket,
            objectUri.Scheme == "https"
        )
    );
    builder.Services.AddSingleton<IObjectStorage>(p => new InventoriedObjectStorage(p.GetRequiredService<MinioObjectStorage>(), options.DatabaseUrl!));
    builder.Services.AddSingleton<IEndpointProjection>(p => new OpenSearchEndpointProjection(
        p.GetRequiredService<IHttpClientFactory>().CreateClient(),
        options.SearchUrl!,
        options.SearchUsername,
        options.SearchPassword
    ));
    builder.Services.AddSingleton<OpenSearchProcessProjection>(p =>
        new(
            p.GetRequiredService<IHttpClientFactory>().CreateClient(),
            options.SearchUrl!,
            options.SearchUsername,
            options.SearchPassword
        )
    );
    builder.Services.AddSingleton<IProcessProjection>(p =>
        p.GetRequiredService<OpenSearchProcessProjection>()
    );
    builder.Services.AddSingleton<OpenSearchFileProjection>(p =>
        new(
            p.GetRequiredService<IHttpClientFactory>().CreateClient(),
            options.SearchUrl!,
            options.SearchUsername,
            options.SearchPassword
        )
    );
    builder.Services.AddSingleton<IFileProjection>(p =>
        p.GetRequiredService<OpenSearchFileProjection>()
    );
    builder.Services.AddSingleton<OpenSearchRegistryProjection>(p =>
        new(
            p.GetRequiredService<IHttpClientFactory>().CreateClient(),
            options.SearchUrl!,
            options.SearchUsername,
            options.SearchPassword
        )
    );
    builder.Services.AddSingleton<IRegistryProjection>(p =>
        p.GetRequiredService<OpenSearchRegistryProjection>()
    );
    builder.Services.AddSingleton<OpenSearchNetworkProjection>(p =>
        new(
            p.GetRequiredService<IHttpClientFactory>().CreateClient(),
            options.SearchUrl!,
            options.SearchUsername,
            options.SearchPassword
        )
    );
    builder.Services.AddSingleton<INetworkProjection>(p =>
        p.GetRequiredService<OpenSearchNetworkProjection>()
    );
    builder.Services.AddSingleton<OpenSearchDnsProjection>(p =>
        new(
            p.GetRequiredService<IHttpClientFactory>().CreateClient(),
            options.SearchUrl!, options.SearchUsername, options.SearchPassword
        )
    );
    builder.Services.AddSingleton<IDnsProjection>(p => p.GetRequiredService<OpenSearchDnsProjection>());
    builder.Services.AddSingleton<OpenSearchModuleProjection>(p => new(p.GetRequiredService<IHttpClientFactory>().CreateClient(), options.SearchUrl!, options.SearchUsername, options.SearchPassword));
    builder.Services.AddSingleton<IModuleProjection>(p => p.GetRequiredService<OpenSearchModuleProjection>());
    builder.Services.AddSingleton<OpenSearchPersistenceProjection>(p => new(p.GetRequiredService<IHttpClientFactory>().CreateClient(), options.SearchUrl!, options.SearchUsername, options.SearchPassword));
    builder.Services.AddSingleton<IPersistenceProjection>(p => p.GetRequiredService<OpenSearchPersistenceProjection>());
    builder.Services.AddSingleton<OpenSearchIdentityProjection>(p => new(p.GetRequiredService<IHttpClientFactory>().CreateClient(), options.SearchUrl!, options.SearchUsername, options.SearchPassword));
    builder.Services.AddSingleton<IIdentityProjection>(p => p.GetRequiredService<OpenSearchIdentityProjection>());
    builder.Services.AddSingleton<OpenSearchExecutionProjection>(p => new(p.GetRequiredService<IHttpClientFactory>().CreateClient(), options.SearchUrl!, options.SearchUsername, options.SearchPassword));
    builder.Services.AddSingleton<IExecutionProjection>(p => p.GetRequiredService<OpenSearchExecutionProjection>());
    builder.Services.AddSingleton<OpenSearchDetectionProjection>(p => new(p.GetRequiredService<IHttpClientFactory>().CreateClient(), options.SearchUrl!, options.SearchUsername, options.SearchPassword));
    builder.Services.AddSingleton<IDetectionProjection>(p => p.GetRequiredService<OpenSearchDetectionProjection>());
    builder.Services.AddSingleton<OpenSearchCorrelationProjection>(p => new(p.GetRequiredService<IHttpClientFactory>().CreateClient(), options.SearchUrl!, options.SearchUsername ?? "", options.SearchPassword ?? ""));
    builder.Services.AddSingleton<ICorrelationProjection>(p => p.GetRequiredService<OpenSearchCorrelationProjection>());
    builder.Services.AddSingleton<OpenSearchThreatIntelligenceProjection>(p => new(p.GetRequiredService<IHttpClientFactory>().CreateClient(), options.SearchUrl!, options.SearchUsername, options.SearchPassword));
    builder.Services.AddSingleton<IThreatIntelligenceProjection>(p => p.GetRequiredService<OpenSearchThreatIntelligenceProjection>());
    builder.Services.AddSingleton<OpenSearchTunnelAnalyticsProjection>(p => new(p.GetRequiredService<IHttpClientFactory>().CreateClient(), options.SearchUrl!, options.SearchUsername, options.SearchPassword));
    builder.Services.AddSingleton<ITunnelAnalyticsProjection>(p => p.GetRequiredService<OpenSearchTunnelAnalyticsProjection>());
}
else
{
    builder.Services.AddSingleton<IEndpointRepository>(_ => new FileEndpointRepository(
        options.DataDirectory
    ));
    builder.Services.AddSingleton<FileProcessTelemetryRepository>();
    builder.Services.AddSingleton<IProcessTelemetryRepository>(p =>
        p.GetRequiredService<FileProcessTelemetryRepository>()
    );
    builder.Services.AddSingleton<IMessageBus>(_ => new DurableFileMessageBus(
        options.DataDirectory
    ));
    builder.Services.AddSingleton<IObjectStorage>(_ => new FileObjectStorage(
        options.DataDirectory
    ));
    builder.Services.AddSingleton<IEndpointProjection, FileEndpointProjection>();
    builder.Services.AddSingleton<IProcessProjection>(p =>
        p.GetRequiredService<FileProcessTelemetryRepository>()
    );
    builder.Services.AddSingleton<IProcessPolicyRepository, FileProcessPolicyRepository>();
    builder.Services.AddSingleton<FileFileTelemetryRepository>();
    builder.Services.AddSingleton<IFileTelemetryRepository>(p =>
        p.GetRequiredService<FileFileTelemetryRepository>()
    );
    builder.Services.AddSingleton<IFileProjection>(p =>
        p.GetRequiredService<FileFileTelemetryRepository>()
    );
    builder.Services.AddSingleton<IFilePolicyRepository, FileFilePolicyRepository>();
    builder.Services.AddSingleton<IFileExportRepository, FileFileExportRepository>();
    builder.Services.AddSingleton<FileRegistryTelemetryRepository>();
    builder.Services.AddSingleton<IRegistryTelemetryRepository>(p =>
        p.GetRequiredService<FileRegistryTelemetryRepository>()
    );
    builder.Services.AddSingleton<IRegistryProjection>(p =>
        p.GetRequiredService<FileRegistryTelemetryRepository>()
    );
    builder.Services.AddSingleton<IRegistryPolicyRepository, FileRegistryPolicyRepository>();
    builder.Services.AddSingleton<IRegistryExportRepository, FileRegistryExportRepository>();
    builder.Services.AddSingleton<FileNetworkTelemetryRepository>();
    builder.Services.AddSingleton<INetworkTelemetryRepository>(p =>
        p.GetRequiredService<FileNetworkTelemetryRepository>()
    );
    builder.Services.AddSingleton<INetworkProjection>(p =>
        p.GetRequiredService<FileNetworkTelemetryRepository>()
    );
    builder.Services.AddSingleton<INetworkPolicyRepository, FileNetworkPolicyRepository>();
    builder.Services.AddSingleton<INetworkExportRepository, FileNetworkExportRepository>();
    builder.Services.AddSingleton<FileDnsTelemetryRepository>();
    builder.Services.AddSingleton<IDnsTelemetryRepository>(p => p.GetRequiredService<FileDnsTelemetryRepository>());
    builder.Services.AddSingleton<IDnsProjection>(p => p.GetRequiredService<FileDnsTelemetryRepository>());
    builder.Services.AddSingleton<IDnsPolicyRepository, FileDnsPolicyRepository>();
    builder.Services.AddSingleton<IDnsExportRepository, FileDnsExportRepository>();
    builder.Services.AddSingleton<FileModuleTelemetryRepository>();
    builder.Services.AddSingleton<IModuleTelemetryRepository>(p => p.GetRequiredService<FileModuleTelemetryRepository>());
    builder.Services.AddSingleton<IModuleProjection>(p => p.GetRequiredService<FileModuleTelemetryRepository>());
    builder.Services.AddSingleton<IModulePolicyRepository, FileModulePolicyRepository>();
    builder.Services.AddSingleton<IModuleExportRepository, FileModuleExportRepository>();
    builder.Services.AddSingleton<FilePersistenceTelemetryRepository>();
    builder.Services.AddSingleton<IPersistenceTelemetryRepository>(p => p.GetRequiredService<FilePersistenceTelemetryRepository>());
    builder.Services.AddSingleton<IPersistenceProjection>(p => p.GetRequiredService<FilePersistenceTelemetryRepository>());
    builder.Services.AddSingleton<IPersistencePolicyRepository, FilePersistencePolicyRepository>();
    builder.Services.AddSingleton<IPersistenceExportRepository, FilePersistenceExportRepository>();
    builder.Services.AddSingleton<FileIdentityTelemetryRepository>();
    builder.Services.AddSingleton<IIdentityTelemetryRepository>(p => p.GetRequiredService<FileIdentityTelemetryRepository>());
    builder.Services.AddSingleton<IIdentityProjection>(p => p.GetRequiredService<FileIdentityTelemetryRepository>());
    builder.Services.AddSingleton<IIdentityPolicyRepository, FileIdentityPolicyRepository>();
    builder.Services.AddSingleton<IIdentityExportRepository, FileIdentityExportRepository>();
    builder.Services.AddSingleton<FileExecutionTelemetryRepository>();
    builder.Services.AddSingleton<IExecutionTelemetryRepository>(p => p.GetRequiredService<FileExecutionTelemetryRepository>());
    builder.Services.AddSingleton<IExecutionProjection>(p => p.GetRequiredService<FileExecutionTelemetryRepository>());
    builder.Services.AddSingleton<IExecutionPolicyRepository, FileExecutionPolicyRepository>();
    builder.Services.AddSingleton<IExecutionExportRepository, FileExecutionExportRepository>();
    builder.Services.AddSingleton<FileDetectionRepository>();
    builder.Services.AddSingleton<IDetectionRepository>(p => p.GetRequiredService<FileDetectionRepository>());
    builder.Services.AddSingleton<IDetectionProjection>(p => p.GetRequiredService<FileDetectionRepository>());
    builder.Services.AddSingleton<IDetectionEventSource, EmptyDetectionEventSource>();
    builder.Services.AddSingleton<FileCorrelationRepository>();
    builder.Services.AddSingleton<ICorrelationRepository>(p => p.GetRequiredService<FileCorrelationRepository>());
    builder.Services.AddSingleton<ICorrelationProjection>(p => p.GetRequiredService<FileCorrelationRepository>());
    builder.Services.AddSingleton<IInvestigationRepository, FileInvestigationRepository>();
    builder.Services.AddSingleton<IAlertIncidentRepository, FileAlertIncidentRepository>();
    builder.Services.AddSingleton<IResponseActionRepository, FileResponseActionRepository>();
    builder.Services.AddSingleton<IIsolationRepository>(p => new FileIsolationRepository(p.GetRequiredService<IResponseActionRepository>()));
    builder.Services.AddSingleton<ILiveResponseRepository, FileLiveResponseRepository>();
    builder.Services.AddSingleton<FileThreatIntelligenceRepository>();
    builder.Services.AddSingleton<IThreatIntelligenceRepository>(p => p.GetRequiredService<FileThreatIntelligenceRepository>());
    builder.Services.AddSingleton<IThreatIntelligenceProjection>(p => p.GetRequiredService<FileThreatIntelligenceRepository>());
    builder.Services.AddSingleton<FileTunnelAnalyticsRepository>();
    builder.Services.AddSingleton<ITunnelAnalyticsRepository>(p => p.GetRequiredService<FileTunnelAnalyticsRepository>());
    builder.Services.AddSingleton<ITunnelAnalyticsProjection>(p => p.GetRequiredService<FileTunnelAnalyticsRepository>());
    builder.Services.AddSingleton<IPlaybookRepository, FilePlaybookRepository>();
    builder.Services.AddSingleton<IPlaybookWorkSource, EmptyPlaybookWorkSource>();
    builder.Services.AddSingleton<IAgentProtectionRepository, FileAgentProtectionRepository>();
    builder.Services.AddSingleton<IFleetUpdateRepository, FileFleetUpdateRepository>();
    builder.Services.AddSingleton<IHighAvailabilityRepository, FileHighAvailabilityRepository>();
    builder.Services.AddSingleton<IArtifactTransferStateRepository, FileArtifactTransferStateRepository>();
    builder.Services.AddSingleton<ICapacityRetentionRepository, FileCapacityRetentionRepository>();
    builder.Services.AddSingleton<IAiInvestigationRepository, FileAiInvestigationRepository>();
    builder.Services.AddSingleton<IAiEngineeringRepository, FileAiEngineeringRepository>();
    builder.Services.AddSingleton<IAdministrationStateStore, FileAdministrationStateStore>();
    builder.Services.AddSingleton<IForensicWorkspaceStore, FileForensicWorkspaceStore>();
}
if (options.AdapterMode == "development" && !string.IsNullOrWhiteSpace(options.CertificateAuthorityPath))
    builder.Services.AddSingleton(_ => new CertificateAuthority(options.CertificateAuthorityPath, options.CertificateAuthorityPassword));
builder.Services.AddSingleton<AdministrationService>();
builder.Services.AddSingleton<ForensicWorkspaceService>();
builder.Services.AddSingleton<IAiProvider, LocalEvidenceAiProvider>();
builder.Services.AddSingleton<AiRequestLimiter>();
builder.Services.AddSingleton<IPlaybookActionExecutor, PlaybookActionExecutor>();
builder.Services.AddSingleton<DependencyTransitionAudit>();
builder.Services.AddHostedService<ServiceRegistrar>();
builder.Services.AddHostedService<SchemaCompatibilityGuard>();
builder.Services.AddHostedService<ServiceInstanceHeartbeat>();
if (options.AdapterMode == "development")
    builder.Services.AddHostedService<MigrationRunner>();
builder.Services.AddHostedService<InfrastructureInitializer>();
// These workers coordinate shared durable infrastructure and must have one owner.
// Running a copy in every logical API service multiplies PostgreSQL/NATS consumers,
// can process the same export concurrently, and exhausts the database connection limit.
if (string.Equals(options.ServiceName, "gateway", StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddLeasedWorker<OutboxPublisher>("outbox-publisher");
    builder.Services.AddLeasedWorker<EndpointLifecycleWorker>("endpoint-lifecycle");
    builder.Services.AddLeasedWorker<NatsEndpointProjectionConsumer>("telemetry-projection");
    builder.Services.AddLeasedWorker<FileExportWorker>("file-export");
    builder.Services.AddLeasedWorker<RegistryExportWorker>("registry-export");
    builder.Services.AddLeasedWorker<NetworkExportWorker>("network-export");
    builder.Services.AddLeasedWorker<DnsExportWorker>("dns-export");
    builder.Services.AddLeasedWorker<ModuleExportWorker>("module-export");
    builder.Services.AddLeasedWorker<PersistenceExportWorker>("persistence-export");
    builder.Services.AddLeasedWorker<IdentityExportWorker>("identity-export");
    builder.Services.AddLeasedWorker<ExecutionExportWorker>("execution-export");
    builder.Services.AddLeasedWorker<PersistenceEvidenceReconciliationWorker>("evidence-reconciliation");
    builder.Services.AddLeasedWorker<ResponseLifecycleWorker>("response-lifecycle");
    builder.Services.AddLeasedWorker<LiveResponseLifecycleWorker>("live-response-lifecycle");
    builder.Services.AddLeasedWorker<ThreatBackmatchWorker>("threat-backmatch");
    builder.Services.AddLeasedWorker<PlaybookWorker>("playbook");
    builder.Services.AddLeasedCoordinator("detection-replay");
    builder.Services.AddLeasedCoordinator("alert-incident-lifecycle");
    builder.Services.AddLeasedCoordinator("forensic-collection");
    builder.Services.AddLeasedCoordinator("artifact-transfer");
    builder.Services.AddLeasedCoordinator("update-rollout");
    builder.Services.AddLeasedCoordinator("cleanup-retention");
    builder.Services.AddLeasedCoordinator("projection-rebuild");
}
builder.Services.AddHttpClient();
builder.WebHost.ConfigureKestrel(k =>
{
    k.AddServerHeader = false;
    if (options.AdapterMode == "production")
    {
        k.ListenAnyIP(8080);
        k.ListenAnyIP(
            8443,
            listen =>
                listen.UseHttps(
                    new HttpsConnectionAdapterOptions
                    {
                        ServerCertificate = new X509Certificate2(
                            options.ServerCertificatePath!,
                            options.ServerCertificatePassword
                        ),
                        ClientCertificateMode = ClientCertificateMode.AllowCertificate,
                        ClientCertificateValidation = (_, _, _) => true,
                    }
                )
        );
    }
});
var app = builder.Build();
app.MapProjectionRepairRoutes(options);

app.Lifetime.ApplicationStopping.Register(() =>
    app.Logger.LogInformation("Service {Service} shutting down gracefully", options.ServiceName)
);
app.Use(async (context, next) =>
{
    context.Response.OnStarting(() =>
    {
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["X-Frame-Options"] = "DENY";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
        context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'";
        if (context.Request.Path.StartsWithSegments("/api") || context.Request.Path.StartsWithSegments("/agent") || context.Request.Path.StartsWithSegments("/internal"))
            context.Response.Headers.CacheControl = "no-store";
        return Task.CompletedTask;
    });
    await next(context);
});
app.UseMiddleware<RequestContextMiddleware>();
app.UseMiddleware<AuthenticationMiddleware>();
app.UseMiddleware<TenantFairnessMiddleware>();

app.MapGet(
    "/health/live",
    () =>
        Results.Json(
            new
            {
                status = "healthy",
                service = options.ServiceName,
                instance = options.InstanceId,
                time = DateTimeOffset.UtcNow,
            }
        )
);
app.MapGet(
    "/health/ready",
    async (
        IMessageBus bus,
        IEndpointRepository repository,
        IEndpointProjection search,
        IObjectStorage storage,
        PlatformMetrics metrics,
        DependencyTransitionAudit dependencyAudit,
        CancellationToken ct
    ) =>
    {
        // Probe concurrently so readiness remains bounded by the slowest dependency
        // instead of the sum of every timeout during a compound outage.
        var databaseProbe = DependencyHealth.Probe(repository.HealthAsync, TimeSpan.FromSeconds(5), ct);
        var messageBusProbe = DependencyHealth.Probe(token => bus.HealthAsync(token).AsTask(), TimeSpan.FromSeconds(2), ct);
        var searchProbe = DependencyHealth.Probe(search.HealthAsync, TimeSpan.FromSeconds(2), ct);
        var objectStorageProbe = DependencyHealth.Probe(storage.HealthAsync, TimeSpan.FromSeconds(2), ct);
        await Task.WhenAll(databaseProbe, messageBusProbe, searchProbe, objectStorageProbe);
        var database = databaseProbe.Result;
        var messageBus = messageBusProbe.Result;
        var searchReady = searchProbe.Result;
        var objectStorage = objectStorageProbe.Result;
        metrics.Dependencies(database, messageBus, searchReady, objectStorage);
        await dependencyAudit.ObserveAsync(new Dictionary<string, bool> { ["postgresql"] = database, ["nats"] = messageBus, ["opensearch"] = searchReady, ["minio"] = objectStorage }, ct);
        var degraded = !messageBus || !searchReady || !objectStorage;
        return database
            ? Results.Json(
                new
                {
                    status = degraded ? "ready_degraded" : "ready",
                    degraded,
                    dependencies = new
                    {
                        database = "healthy",
                        messageBus = messageBus ? "healthy" : "degraded; transactional outbox retained",
                        search = searchReady ? "healthy" : "degraded; PostgreSQL authority remains available",
                        objectStorage = objectStorage ? "healthy" : "degraded; evidence actions unavailable",
                    },
                }
            )
            : Results.Json(new { status = "not_ready", degraded = true, dependencies = new { database = "unavailable", messageBus = messageBus ? "healthy" : "unavailable", search = searchReady ? "healthy" : "unavailable", objectStorage = objectStorage ? "healthy" : "unavailable" } }, statusCode: 503);
    }
);
app.MapGet(
    "/metrics",
    async (PlatformMetrics metrics, IFleetUpdateRepository fleet, IHighAvailabilityRepository ha, IArtifactTransferStateRepository transfers, ICapacityRetentionRepository capacity, CancellationToken ct) =>
    {
        var health = await fleet.HealthAsync(options.BootstrapTenantId, ct);
        return Results.Text(metrics.Render() + metrics.RenderProcess() + metrics.RenderModule()
            + FleetUpdateRoutes.Metrics(health) + await HighAvailabilityRoutes.Metrics(ha, transfers, ct) + await CapacityRetentionRoutes.Metrics(capacity, ct), "text/plain; version=0.0.4");
    }
);
app.MapGet("/api/v1/openapi.json", () => Results.Json(OpenApiDocument.Build(options.ServiceName)));

MapAuthentication(app);
MapPlatformClients(app);
MapAgent(app);
MapEndpoints(app);
MapProcesses(app);
MapProcessPolicies(app);
MapFileTelemetry(app);
MapRegistryTelemetry(app);
NetworkRoutes.Map(app);
DnsRoutes.Map(app);
ModuleRoutes.Map(app);
PersistenceRoutes.Map(app);
IdentityRoutes.Map(app);
ExecutionRoutes.Map(app);
DetectionRoutes.Map(app);
CorrelationRoutes.Map(app);
InvestigationRoutes.Map(app);
AlertIncidentRoutes.Map(app);
ResponseRoutes.Map(app);
ArtifactTransferRoutes.Map(app);
HighAvailabilityRoutes.Map(app);
CapacityRetentionRoutes.Map(app);
AiInvestigationRoutes.Map(app);
AiEngineeringRoutes.MapAiEngineeringRoutes(app);
ToolPackageRoutes.Map(app);
IsolationRoutes.Map(app);
ProcessResponseRoutes.Map(app);
FileResponseRoutes.Map(app);
PersistenceResponseRoutes.Map(app);
ForensicCollectionRoutes.Map(app);
ForensicWorkspaceRoutes.Map(app);
LiveResponseRoutes.Map(app);
ThreatIntelligenceRoutes.Map(app);
TunnelAnalyticsRoutes.Map(app);
PlaybookRoutes.Map(app);
AgentProtectionRoutes.Map(app);
FleetUpdateRoutes.Map(app);
MapObjectStorage(app);
MapServiceRegistry(app);
MapContractRoutes(app);
AdministrationRoutes.Map(app);
MapFrontend(app);

app.Logger.LogInformation(
    "Starting {Service} instance {Instance} in {Environment}/{Region}",
    options.ServiceName,
    options.InstanceId,
    options.Environment,
    options.Region
);
await app.RunAsync();

static void MapAuthentication(WebApplication app)
{
    app.MapPost(
        "/api/v1/auth/token",
        async (LoginRequest input, JwtService jwt, AdministrationService administration, CancellationToken ct) =>
        {
            if (
                input.Username != Environment.GetEnvironmentVariable("PLATFORM_BOOTSTRAP_USER")
                || input.Password
                    != Environment.GetEnvironmentVariable("PLATFORM_BOOTSTRAP_PASSWORD")
            )
            {
                await administration.RecordAuthenticationFailureAsync(jwt.Options.BootstrapTenantId, input.Username, "invalid bootstrap credential", ct);
                return Results.Problem(
                    statusCode: 401,
                    title: "Invalid credentials",
                    extensions: new Dictionary<string, object?>
                    {
                        { "code", "AUTHENTICATION_REQUIRED" },
                    }
                );
            }
            var tenant = jwt.Options.BootstrapTenantId;
            var permissions = new[]
            {
                "platform:admin",
                "agent:enroll",
                "endpoint:read",
                "process:read",
                "process:tree:read",
                "process:timeline:read",
                "process:health:read",
                "process:export",
                "process:projection:rebuild",
                "system:admin",
                "policy:read",
                "case:read",
                "hunt:execute",
                "hunt:save",
                "hunt:share",
                "hunt:export",
                "investigation:tree:read",
                "investigation:graph:read",
                "investigation:story:read",
                "investigation:evidence:read",
                "alert:read",
                "alert:acknowledge",
                "alert:assign",
                "alert:status:change",
                "alert:disposition:set",
                "alert:notes:add",
                "alert:close",
                "alert:reopen",
                "alert:export",
                "incident:read",
                "incident:create",
                "incident:assign",
                "incident:modify",
                "incident:alerts:link",
                "incident:merge",
                "incident:split",
                "incident:close",
                "incident:reopen",
                "incident:export",
                "triage:grouping:configure",
                "triage:sla:configure",
                "triage:audit:read",
                "response:read",
                "response:request:safe",
                "response:request:elevated",
                "response:approve:elevated",
                "response:cancel",
                "response:output:read",
                "response:artifact:download",
                "response:audit:read",
                "response:policy:admin",
                "isolation:request",
                "isolation:approve",
                "isolation:unisolate",
                "isolation:status:read",
                "isolation:policy:admin",
                "isolation:cancel",
                "isolation:audit:read",
                "process-response:terminate",
                "process-response:suspend",
                "process-response:resume",
                "process-response:tree-terminate",
                "process-response:approve",
                "process-response:read",
                "process-response:history:read",
                "process-response:policy:admin",
                "file-response:quarantine",
                "file-response:restore",
                "file-response:delete",
                "file-response:approve",
                "file-response:read",
                "file-response:history:read",
                "file-response:policy:admin",
                "persistence-response:request",
                "persistence-response:registry:remove",
                "persistence-response:registry:restore",
                "persistence-response:service:stop",
                "persistence-response:service:disable",
                "persistence-response:service:delete",
                "persistence-response:service:restore",
                "persistence-response:task:disable",
                "persistence-response:task:delete",
                "persistence-response:task:restore",
                "persistence-response:wmi:remove",
                "persistence-response:wmi:restore",
                "persistence-response:remove",
                "persistence-response:restore",
                "persistence-response:approve",
                "persistence-response:read",
                "persistence-response:history:read",
                "persistence-response:policy:admin",
                "forensics:request:quick",
                "forensics:request:eventlog",
                "forensics:request:registry",
                "forensics:request:file",
                "forensics:request:sensitive",
                "forensics:approve:sensitive",
                "forensics:cancel",
                "forensics:read",
                "forensics:evidence:download:sensitive",
                "forensics:manifest:export",
                "forensics:profiles:read",
                "forensics:profiles:admin",
                "forensics:retention:admin",
                "forensics:custody:read",
                "forensics:health:read",
                "live:open",
                "live:read",
                "live:execute:safe",
                "live:execute:shell",
                "live:execute:powershell",
                "live:execute:cmd",
                "live:file:upload",
                "live:file:download",
                "live:cwd:change",
                "live:close:own",
                "live:close:any",
                "live:approve:elevated",
                "live:cancel",
                "live:transcript:read",
                "live:transcript:export",
                "live:policy:admin",
                "plugin:read",
            };
            var bootstrap = await administration.BootstrapPrincipalAsync(tenant, input.Username, ct);
            var effective = await administration.EffectivePermissionsAsync(tenant, bootstrap.PrincipalId, ct);
            permissions = effective.Permissions.Select(x => x.Permission).Append("authenticated").Distinct(StringComparer.Ordinal).ToArray();
            var session = await administration.EffectiveConfigurationAsync(tenant, "session.inactivity_minutes", null, null, ct);
            var accessLifetime = TimeSpan.FromMinutes(session.EffectiveValue.GetInt32());
            return Results.Json(
                new
                {
                    access_token = jwt.Issue(
                        bootstrap.PrincipalId.ToString("D"),
                        tenant,
                        permissions,
                        accessLifetime
                    ),
                    refresh_token = jwt.Issue(
                        bootstrap.PrincipalId.ToString("D"),
                        tenant,
                        new[] { "token:refresh" },
                        TimeSpan.FromHours(8),
                        "refresh"
                    ),
                    token_type = "Bearer",
                    expires_in = (int)accessLifetime.TotalSeconds,
                }
            );
        }
    );
    app.MapPost(
        "/api/v1/auth/refresh",
        async (RefreshRequest input, JwtService jwt, AdministrationService administration, CancellationToken ct) =>
        {
            if (jwt.Validate(input.RefreshToken) is not { Type: "refresh" } p)
                return Results.Unauthorized();
            var managed = await administration.ResolveManagedPrincipalAsync(p, ct);
            if (managed is null)
                return Results.Unauthorized();
            var session = await administration.EffectiveConfigurationAsync(managed.TenantId, "session.inactivity_minutes", null, null, ct);
            var accessLifetime = TimeSpan.FromMinutes(session.EffectiveValue.GetInt32());
            return Results.Json(new
            {
                access_token = jwt.Issue(managed.Subject, managed.TenantId,
                    managed.Permissions.Append("authenticated"), accessLifetime, managed.Type),
                token_type = "Bearer",
                expires_in = (int)accessLifetime.TotalSeconds,
            });
        }
    );
    app.MapGet(
            "/api/v1/session",
            (HttpContext c) =>
                Results.Json(
                    new ApiEnvelope<object>(
                        new
                        {
                            subject = c.User.Identity?.Name,
                            tenant = c.Items["tenant"],
                            permissions = c.Items["permissions"],
                        },
                        new(c.TraceIdentifier)
                    )
                )
        )
        .RequirePermission("authenticated");
}

static void MapPlatformClients(WebApplication app)
{
    app.MapGet("/api/v1/platform/clients", async (HttpContext c, PlatformClientCatalog clients, IEndpointRepository endpoints, CancellationToken ct) =>
    {
        var principal = (PrincipalContext)c.Items["principal"]!;
        var selected = c.Items["tenant"]!.ToString()!;
        var values = new List<object>();
        foreach (var client in clients.All)
        {
            var page = await endpoints.ListEndpointsAsync(client.ClientId, 500, null, null, null, ct);
            values.Add(new { client.ClientId, client.Name, selected = client.ClientId == selected, endpointCount = page.Items.Count, hasMoreEndpoints = page.NextCursor is not null });
        }
        return Results.Ok(new ApiEnvelope<object>(new { items = values, superAdministrator = principal.Permissions.Contains("platform:admin") }, new(c.TraceIdentifier, "1.0")));
    }).RequirePermission("platform:admin");
}

static void MapAgent(WebApplication app)
{
    app.MapPost(
        "/agent/v1/register",
        async (
            EnrollmentRequest request,
            HttpContext c,
            IEndpointRepository repository,
            PlatformOptions options,
            PlatformMetrics metrics,
            CancellationToken ct
        ) =>
        {
            if (options.AdapterMode == "production" && !c.Request.IsHttps)
                return Results.Json(
                    new ApiError(
                        "HTTPS_REQUIRED",
                        "Enrollment requires HTTPS",
                        400,
                        c.TraceIdentifier
                    ),
                    statusCode: 400
                );
            var errors = EndpointValidation.Validate(request, DateTimeOffset.UtcNow);
            if (errors.Count > 0)
                return Results.ValidationProblem(errors.ToDictionary());
            try
            {
                var started = Stopwatch.GetTimestamp();
                var authority = c.RequestServices.GetRequiredService<CertificateAuthority>();
                var result = await repository.EnrollAsync(
                    request,
                    EnrollmentSecrets.RequestHash(request),
                    authority.Issue,
                    System.Text.Encoding.UTF8.GetBytes(options.EnrollmentPepper),
                    ct
                );
                metrics.Enrollment(Stopwatch.GetElapsedTime(started));
                return Results.Created(
                    $"/api/v1/endpoints/{result.EndpointId}",
                    new ApiEnvelope<EnrollmentResult>(result, new(c.TraceIdentifier, "1.1"))
                );
            }
            catch (EnrollmentConflictException e)
            {
                return Results.Json(
                    new ApiError(e.Code, "Enrollment rejected", 409, c.TraceIdentifier, false),
                    statusCode: 409
                );
            }
        }
    );
    app.MapPost(
            "/agent/v1/certificates:renew",
            async (
                CertificateRenewalRequest input,
                HttpContext c,
                IEndpointRepository repository,
                IServiceProvider services,
                CancellationToken ct
            ) =>
            {
                var authority = services.GetService<CertificateAuthority>();
                if (authority is null)
                    return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                var principal = (PrincipalContext?)c.Items["principal"];
                var current = await c.Connection.GetClientCertificateAsync(ct);
                if (
                    principal is null
                    || principal.Type != "agent"
                    || current is null
                    || input.CertificateSigningRequest.Length is < 128 or > 16384
                )
                    return Results.Unauthorized();
                var ids = principal.Subject.Split(':');
                if (ids.Length != 2 || !Guid.TryParse(ids[1], out var agentId))
                    return Results.Unauthorized();
                var issued = authority.Issue(
                    input.CertificateSigningRequest,
                    principal.TenantId,
                    principal.Subject
                );
                await repository.RotateCredentialAsync(
                    principal.TenantId,
                    agentId,
                    current.Thumbprint,
                    issued,
                    input.CertificateSigningRequest,
                    ct
                );
                return Results.Ok(
                    new ApiEnvelope<CertificateRenewalResult>(
                        new(issued.CertificatePem, issued.CaCertificatePem, issued.NotAfter),
                        new(c.TraceIdentifier, "1.1")
                    )
                );
            }
        )
        .RequirePermission("agent:heartbeat");
    app.MapPost(
            "/agent/v1/checkins",
            async (
                HeartbeatRequest input,
                HttpContext c,
                IEndpointRepository repository,
                PlatformOptions options,
                PlatformMetrics metrics,
                CancellationToken ct
            ) =>
            {
                if (options.AdapterMode == "production" && !c.Request.IsHttps)
                    return Results.Json(
                        new ApiError(
                            "MTLS_REQUIRED",
                            "Heartbeat requires mutual TLS",
                            401,
                            c.TraceIdentifier
                        ),
                        statusCode: 401
                    );
                var errors = EndpointValidation.Validate(input, DateTimeOffset.UtcNow);
                if (errors.Count > 0)
                    return Results.ValidationProblem(errors);
                var principal = (PrincipalContext?)c.Items["principal"];
                if (
                    principal is null
                    || principal.Type != "agent"
                    || principal.Subject != $"{input.EndpointId}:{input.AgentId}"
                )
                    return Results.Unauthorized();
                try
                {
                    var started = Stopwatch.GetTimestamp();
                    var endpoint = await repository.RecordHeartbeatAsync(
                        principal.TenantId,
                        input,
                        ct
                    );
                    metrics.Heartbeat(Stopwatch.GetElapsedTime(started));
                    return Results.Ok(
                        new ApiEnvelope<object>(
                            new
                            {
                                endpoint_revision = endpoint.Revision,
                                configuration_version = input.ConfigurationVersion ?? "1",
                                jobs = Array.Empty<object>(),
                            },
                            new(c.TraceIdentifier, "1.1")
                        )
                    );
                }
                catch (EnrollmentConflictException e)
                {
                    return Results.Json(
                        new ApiError(e.Code, "Heartbeat rejected", 409, c.TraceIdentifier),
                        statusCode: 409
                    );
                }
            }
        )
        .RequirePermission("agent:heartbeat");
    app.MapGet(
            "/agent/v1/process-policy",
            async (HttpContext c, IProcessPolicyRepository policies, CancellationToken ct) =>
            {
                var principal = (PrincipalContext?)c.Items["principal"];
                if (principal is null || principal.Type != "agent")
                    return Results.Unauthorized();
                var ids = principal.Subject.Split(':');
                if (ids.Length != 2 || !Guid.TryParse(ids[0], out var endpointId))
                    return Results.Unauthorized();
                return Results.Ok(
                    await policies.EffectiveAsync(principal.TenantId, endpointId, ct)
                );
            }
        )
        .RequirePermission("agent:heartbeat");
    app.MapPost(
            "/agent/v1/process-policy:acknowledge",
            async (
                ProcessPolicyAcknowledgement input,
                HttpContext c,
                IProcessPolicyRepository policies,
                CancellationToken ct
            ) =>
            {
                var principal = (PrincipalContext?)c.Items["principal"];
                if (principal is null || principal.Type != "agent")
                    return Results.Unauthorized();
                var ids = principal.Subject.Split(':');
                if (ids.Length != 2 || !Guid.TryParse(ids[0], out var endpointId))
                    return Results.Unauthorized();
                await policies.AcknowledgeAsync(principal.TenantId, endpointId, input, ct);
                return Results.Accepted();
            }
        )
        .RequirePermission("agent:heartbeat");
    app.MapPost(
            "/agent/v1/process-event-batches",
            async (
                HttpContext c,
                IProcessTelemetryRepository repository,
                PlatformMetrics metrics,
                CancellationToken ct
            ) =>
            {
                if (!c.Request.IsHttps || c.Request.ContentLength is > 1024 * 1024)
                    return Results.Json(
                        new ApiError(
                            "PROCESS_BATCH_SIZE",
                            "Compressed process batch exceeds policy",
                            413,
                            c.TraceIdentifier
                        ),
                        statusCode: 413
                    );
                var principal = (PrincipalContext?)c.Items["principal"];
                if (principal is null || principal.Type != "agent")
                    return Results.Unauthorized();
                if (
                    !long.TryParse(c.Request.Headers["X-Uncompressed-Length"], out var expected)
                    || expected is < 1 or > 4 * 1024 * 1024
                    || !string.Equals(
                        c.Request.Headers.ContentEncoding,
                        "gzip",
                        StringComparison.OrdinalIgnoreCase
                    )
                )
                    return Results.Json(
                        new ApiError(
                            "PROCESS_COMPRESSION_INVALID",
                            "A bounded gzip process batch is required",
                            400,
                            c.TraceIdentifier
                        ),
                        statusCode: 400
                    );
                try
                {
                    await using var gzip = new GZipStream(
                        c.Request.Body,
                        CompressionMode.Decompress,
                        false
                    );
                    await using var bounded = new MemoryStream();
                    var buffer = new byte[81920];
                    int read;
                    long total = 0;
                    while ((read = await gzip.ReadAsync(buffer, ct)) > 0)
                    {
                        total += read;
                        if (total > 4 * 1024 * 1024 || total > expected)
                            return Results.Json(
                                new ApiError(
                                    "PROCESS_DECOMPRESSION_LIMIT",
                                    "Process batch exceeded its declared limit",
                                    413,
                                    c.TraceIdentifier
                                ),
                                statusCode: 413
                            );
                        await bounded.WriteAsync(buffer.AsMemory(0, read), ct);
                    }
                    if (total != expected)
                        return Results.BadRequest(
                            new ApiError(
                                "PROCESS_LENGTH_MISMATCH",
                                "Process batch length did not match its declaration",
                                400,
                                c.TraceIdentifier
                            )
                        );
                    var batch = JsonSerializer.Deserialize<ProcessEventBatch>(
                        bounded.ToArray(),
                        ProcessJson.Options
                    );
                    if (batch is null)
                        return Results.BadRequest();
                    var ids = principal.Subject.Split(':');
                    if (
                        ids.Length != 2
                        || !Guid.TryParse(ids[0], out var endpointId)
                        || !Guid.TryParse(ids[1], out var agentId)
                        || batch.EndpointId != endpointId
                        || batch.AgentId != agentId
                    )
                        return Results.Unauthorized();
                    var validation = ProcessTelemetryValidation.Validate(
                        batch,
                        DateTimeOffset.UtcNow
                    );
                    var actualHash = Convert
                        .ToHexString(
                            SHA256.HashData(
                                JsonSerializer.SerializeToUtf8Bytes(
                                    batch.Events,
                                    ProcessJson.Options
                                )
                            )
                        )
                        .ToLowerInvariant();
                    if (
                        !CryptographicOperations.FixedTimeEquals(
                            Encoding.ASCII.GetBytes(actualHash),
                            Encoding.ASCII.GetBytes(batch.ContentSha256.ToLowerInvariant())
                        )
                    )
                        return Results.BadRequest(
                            new ApiError(
                                "PROCESS_INTEGRITY_INVALID",
                                "Process event integrity validation failed",
                                400,
                                c.TraceIdentifier
                            )
                        );
                    if (validation.Count > 0)
                        return Results.ValidationProblem(validation.ToDictionary());
                    static long Header(HttpContext context, string name) =>
                        long.TryParse(context.Request.Headers[name], out var value)
                            ? Math.Max(0, value)
                            : 0;
                    var health = new ProcessTelemetryHealth(
                        endpointId,
                        true,
                        batch.Events[0].CollectorType,
                        batch.Events[0].CollectorVersion,
                        batch.Events.Max(x => x.ObservedAt),
                        Header(c, "X-Queue-Depth"),
                        Header(c, "X-Queue-Oldest-Age"),
                        Header(c, "X-Dropped-Events"),
                        c.Request.Headers["X-Drop-Reason"].FirstOrDefault(),
                        "accepted",
                        c.Request.Headers["X-Policy-Version"].FirstOrDefault()
                        ?? "process-policy.v1",
                        0,
                        Header(c, "X-Excluded-Events"),
                        Guid.TryParse(c.Request.Headers["X-Exclusion-Rule"], out var exclusionRule)
                            ? exclusionRule
                            : null,
                        c.Request.Headers["X-Exclusion-Category"].FirstOrDefault(),
                        DateTimeOffset.TryParse(
                            c.Request.Headers["X-Exclusion-At"],
                            out var exclusionAt
                        )
                            ? exclusionAt
                            : null
                    );
                    var result = await repository.IngestAsync(
                        principal.TenantId,
                        batch,
                        health,
                        ct
                    );
                    metrics.ProcessIngest(
                        result,
                        Stopwatch.GetElapsedTime(
                            c.Items.TryGetValue("request-start", out var start)
                            && start is long ticks
                                ? ticks
                                : Stopwatch.GetTimestamp()
                        )
                    );
                    return Results.Ok(result.Acknowledgement);
                }
                catch (Exception e) when (e is InvalidDataException or JsonException)
                {
                    return Results.BadRequest(
                        new ApiError(
                            "PROCESS_BATCH_INVALID",
                            "Process batch could not be parsed",
                            400,
                            c.TraceIdentifier
                        )
                    );
                }
            }
        )
        .RequirePermission("agent:heartbeat");
    app.MapPost(
            "/agent/v1/file-event-batches",
            async (HttpContext c, IFileTelemetryRepository repository, CancellationToken ct) =>
            {
                if (!c.Request.IsHttps || c.Request.ContentLength is > 1024 * 1024)
                    return Results.Json(
                        new ApiError(
                            "FILE_BATCH_SIZE",
                            "Compressed file batch exceeds policy",
                            413,
                            c.TraceIdentifier
                        ),
                        statusCode: 413
                    );
                var principal = (PrincipalContext?)c.Items["principal"];
                if (principal is null || principal.Type != "agent")
                    return Results.Unauthorized();
                if (
                    !long.TryParse(c.Request.Headers["X-Uncompressed-Length"], out var expected)
                    || expected is < 1 or > 4 * 1024 * 1024
                    || !string.Equals(
                        c.Request.Headers.ContentEncoding,
                        "gzip",
                        StringComparison.OrdinalIgnoreCase
                    )
                )
                    return Results.BadRequest(
                        new ApiError(
                            "FILE_COMPRESSION_INVALID",
                            "A bounded gzip file batch is required",
                            400,
                            c.TraceIdentifier
                        )
                    );
                try
                {
                    await using var gzip = new GZipStream(
                        c.Request.Body,
                        CompressionMode.Decompress,
                        false
                    );
                    await using var bounded = new MemoryStream();
                    var buffer = new byte[81920];
                    long total = 0;
                    int read;
                    while ((read = await gzip.ReadAsync(buffer, ct)) > 0)
                    {
                        total += read;
                        if (total > expected || total > 4 * 1024 * 1024)
                            return Results.Json(
                                new ApiError(
                                    "FILE_DECOMPRESSION_LIMIT",
                                    "File batch exceeded its declared limit",
                                    413,
                                    c.TraceIdentifier
                                ),
                                statusCode: 413
                            );
                        await bounded.WriteAsync(buffer.AsMemory(0, read), ct);
                    }
                    if (total != expected)
                        return Results.BadRequest(
                            new ApiError(
                                "FILE_LENGTH_MISMATCH",
                                "File batch length did not match its declaration",
                                400,
                                c.TraceIdentifier
                            )
                        );
                    var batch = JsonSerializer.Deserialize<FileEventBatch>(
                        bounded.ToArray(),
                        ProcessJson.Options
                    );
                    if (batch is null || batch.Events.Count is < 1 or > 1000)
                        return Results.BadRequest();
                    var ids = principal.Subject.Split(':');
                    if (
                        ids.Length != 2
                        || !Guid.TryParse(ids[0], out var endpointId)
                        || !Guid.TryParse(ids[1], out var agentId)
                        || batch.EndpointId != endpointId
                        || batch.AgentId != agentId
                    )
                        return Results.Unauthorized();
                    var actual = Convert
                        .ToHexString(
                            SHA256.HashData(
                                JsonSerializer.SerializeToUtf8Bytes(
                                    batch.Events,
                                    ProcessJson.Options
                                )
                            )
                        )
                        .ToLowerInvariant();
                    if (
                        !CryptographicOperations.FixedTimeEquals(
                            Encoding.ASCII.GetBytes(actual),
                            Encoding.ASCII.GetBytes(batch.ContentSha256.ToLowerInvariant())
                        )
                    )
                        return Results.BadRequest(
                            new ApiError(
                                "FILE_INTEGRITY_INVALID",
                                "File event integrity validation failed",
                                400,
                                c.TraceIdentifier
                            )
                        );
                    static long H(HttpContext x, string name) =>
                        long.TryParse(x.Request.Headers[name], out var value)
                            ? Math.Max(0, value)
                            : 0;
                    static FileHashMetrics? HM(HttpContext x)
                    {
                        var encoded = x.Request.Headers["X-Hash-Metrics"].FirstOrDefault();
                        if (string.IsNullOrWhiteSpace(encoded) || encoded.Length > 16384)
                            return null;
                        try
                        {
                            return JsonSerializer.Deserialize<FileHashMetrics>(
                                Convert.FromBase64String(encoded),
                                ProcessJson.Options
                            );
                        }
                        catch (Exception e) when (e is FormatException or JsonException)
                        {
                            return null;
                        }
                    }
                    var health = new FileTelemetryHealth(
                        endpointId,
                        true,
                        batch.Events[0].CollectorType,
                        batch.Events[0].CollectorVersion,
                        batch.Events.Max(x => x.ObservedAt),
                        H(c, "X-Queue-Depth"),
                        H(c, "X-Queue-Oldest-Age"),
                        H(c, "X-Dropped-Events"),
                        H(c, "X-Excluded-Events"),
                        H(c, "X-Source-Gaps"),
                        H(c, "X-Watch-Errors"),
                        H(c, "X-Journal-Resets"),
                        H(c, "X-ETW-Lost-Events"),
                        H(c, "X-Falco-Lost-Events"),
                        H(c, "X-Hash-Failures"),
                        H(c, "X-Signature-Failures"),
                        "accepted",
                        c.Request.Headers["X-Policy-Version"].FirstOrDefault() ?? "file-policy.v1",
                        batch.LastSequence,
                        HM(c)
                    );
                    var result = await repository.IngestAsync(
                        principal.TenantId,
                        batch,
                        health,
                        ct
                    );
                    return Results.Ok(result.Acknowledgement);
                }
                catch (Exception e) when (e is InvalidDataException or JsonException)
                {
                    return Results.BadRequest(
                        new ApiError(
                            "FILE_BATCH_INVALID",
                            "File batch could not be parsed",
                            400,
                            c.TraceIdentifier
                        )
                    );
                }
            }
        )
        .RequirePermission("agent:heartbeat");
    app.MapPost(
        "/agent/v1/event-batches",
        () =>
            Results.Json(
                new ApiError(
                    "EVENT_TYPE_UNSUPPORTED",
                    "Use the versioned process-event batch route",
                    400,
                    Guid.NewGuid().ToString()
                ),
                statusCode: 400
            )
    ).RequirePermission("agent:heartbeat");
    app.MapPost("/agent/v1/job-results", () => Results.Accepted()).RequirePermission("agent:heartbeat");
    app.MapPost(
        "/agent/v1/artifacts:initiate",
        () => Results.Accepted(value: new { upload_id = Guid.NewGuid(), expires_in = 900 })
    ).RequirePermission("agent:heartbeat");
    app.MapPost(
        "/agent/v1/artifacts/{id}:complete",
        (string id) => Results.Ok(new { id, status = "verified" })
    ).RequirePermission("agent:heartbeat");
}

static void MapRegistryTelemetry(WebApplication app)
{
    static bool CanReadSensitive(HttpContext c)
    {
        var permissions = (IReadOnlySet<string>?)c.Items["permissions"];
        return permissions?.Contains("registry:sensitive:read") == true
            || permissions?.Contains("platform:admin") == true
            || permissions?.Contains("system:admin") == true;
    }
    static RegistryObservation ProtectObservation(RegistryObservation value, HttpContext c) =>
        CanReadSensitive(c) || value.Value.Preview is null
            ? value
            : value with
            {
                Value = value.Value with
                {
                    Preview = null,
                    FailureReason = "sensitive-preview-permission-required",
                },
            };
    static RegistryEventPage ProtectPage(RegistryEventPage page, HttpContext c) =>
        page with { Items = page.Items.Select(x => ProtectObservation(x, c)).ToArray() };
    static RegistryValueView ProtectValue(RegistryValueView value, HttpContext c) =>
        CanReadSensitive(c) || value.Value.Preview is null
            ? value
            : value with
            {
                Value = value.Value with
                {
                    Preview = null,
                    FailureReason = "sensitive-preview-permission-required",
                },
            };
    static (DateTimeOffset From, DateTimeOffset To) Range(HttpRequest r)
    {
        var now = DateTimeOffset.UtcNow; var from = DateTimeOffset.TryParse(r.Query["from"], out var f) ? f : now.AddHours(-24); var to = DateTimeOffset.TryParse(r.Query["to"], out var t) ? t : now;
        if (to <= from || to - from > TimeSpan.FromDays(30)) throw new EnrollmentConflictException("TIME_RANGE_INVALID", "Registry queries require a positive range of at most 30 days."); return (from, to);
    }
    static RegistrySearchRequest Query(HttpRequest r, Guid? endpoint = null)
    {
        var range = Range(r); return new(endpoint ?? (Guid.TryParse(r.Query["endpointId"], out var id) ? id : null), range.From, range.To, r.Query["hive"].FirstOrDefault(), r.Query["path"].FirstOrDefault(), r.Query["valueName"].FirstOrDefault(), Enum.TryParse<RegistryEventKind>(r.Query["operation"], true, out var operation) ? operation : null, r.Query["process"].FirstOrDefault(), r.Query["user"].FirstOrDefault(), r.Query["valueType"].FirstOrDefault(), r.Query["collector"].FirstOrDefault(), r.Query["dataQuality"].FirstOrDefault(), r.Query["contentHash"].FirstOrDefault(), int.TryParse(r.Query["pageSize"], out var size) ? Math.Clamp(size, 1, 500) : 100, r.Query["cursor"].FirstOrDefault());
    }
    static long Header(HttpContext c, string name) => long.TryParse(c.Request.Headers[name], out var value) ? Math.Max(0, value) : 0;
    app.MapPost("/agent/v1/registry-event-batches", async (HttpContext c, IRegistryTelemetryRepository repository, CancellationToken ct) =>
    {
        if (!c.Request.IsHttps || c.Request.ContentLength is > 1024 * 1024) return Results.Json(new ApiError("REGISTRY_BATCH_SIZE", "Compressed registry batch exceeds policy", 413, c.TraceIdentifier), statusCode: 413);
        var principal = (PrincipalContext?)c.Items["principal"]; if (principal is null || principal.Type != "agent") return Results.Unauthorized();
        if (!long.TryParse(c.Request.Headers["X-Uncompressed-Length"], out var expected) || expected is < 1 or > 4 * 1024 * 1024 || !string.Equals(c.Request.Headers.ContentEncoding, "gzip", StringComparison.OrdinalIgnoreCase)) return Results.BadRequest(new ApiError("REGISTRY_COMPRESSION_INVALID", "A bounded gzip registry batch is required", 400, c.TraceIdentifier));
        try
        {
            await using var gzip = new GZipStream(c.Request.Body, CompressionMode.Decompress, false); await using var bounded = new MemoryStream(); var buffer = new byte[81920]; long total = 0; int read; while ((read = await gzip.ReadAsync(buffer, ct)) > 0) { total += read; if (total > expected || total > 4 * 1024 * 1024) return Results.Json(new ApiError("REGISTRY_DECOMPRESSION_LIMIT", "Registry batch exceeded its declared limit", 413, c.TraceIdentifier), statusCode: 413); await bounded.WriteAsync(buffer.AsMemory(0, read), ct); }
            if (total != expected) return Results.BadRequest(new ApiError("REGISTRY_LENGTH_MISMATCH", "Registry batch length did not match its declaration", 400, c.TraceIdentifier));
            var batch = JsonSerializer.Deserialize<RegistryEventBatch>(bounded.ToArray(), ProcessJson.Options); if (batch is null || batch.Events.Count is < 1 or > 1000 || batch.FirstSequence != batch.Events.Min(x => x.Sequence) || batch.LastSequence != batch.Events.Max(x => x.Sequence)) return Results.BadRequest(new ApiError("REGISTRY_BATCH_INVALID", "Registry batch contract is invalid", 400, c.TraceIdentifier));
            var ids = principal.Subject.Split(':'); if (ids.Length != 2 || !Guid.TryParse(ids[0], out var endpoint) || !Guid.TryParse(ids[1], out var agent) || batch.EndpointId != endpoint || batch.AgentId != agent) return Results.Unauthorized();
            var actual = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(batch.Events, ProcessJson.Options))).ToLowerInvariant(); if (batch.ContentSha256.Length != 64 || !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(batch.ContentSha256.ToLowerInvariant()))) return Results.BadRequest(new ApiError("REGISTRY_INTEGRITY_INVALID", "Registry event integrity validation failed", 400, c.TraceIdentifier));
            var health = new RegistryTelemetryHealth(endpoint, true, batch.Events[0].CollectorSource, batch.Events[0].CollectorVersion, batch.Events.Max(x => x.ObservedAt), null, Header(c, "X-Queue-Depth"), Header(c, "X-Queue-Oldest-Age"), Header(c, "X-Dropped-Events"), Header(c, "X-Excluded-Events"), Header(c, "X-ETW-Lost-Events"), 0, Header(c, "X-Handle-Resolution-Failures"), Header(c, "X-Path-Resolution-Failures"), Header(c, "X-Capture-Attempts"), Header(c, "X-Capture-Skips"), Header(c, "X-Capture-Failures"), Header(c, "X-Redacted-Values"), "accepted", c.Request.Headers["X-Policy-Version"].FirstOrDefault() ?? "registry-policy.v1", int.TryParse(c.Request.Headers["X-Applied-Policy-Version"], out var version) ? version : null, false, DateTimeOffset.UtcNow, batch.LastSequence);
            var result = await repository.IngestAsync(principal.TenantId, batch, health, ct); return Results.Ok(result.Acknowledgement);
        }
        catch (Exception e) when (e is InvalidDataException or JsonException) { return Results.BadRequest(new ApiError("REGISTRY_BATCH_INVALID", "Registry batch could not be parsed", 400, c.TraceIdentifier)); }
    }).RequirePermission("agent:heartbeat");
    app.MapGet("/agent/v1/registry-policy", async (HttpContext c, IRegistryPolicyRepository p, CancellationToken ct) => { var principal = (PrincipalContext)c.Items["principal"]!; var ids = principal.Subject.Split(':'); return ids.Length == 2 && Guid.TryParse(ids[0], out var endpoint) ? Results.Ok(await p.EffectiveAsync(principal.TenantId, endpoint, ct)) : Results.Unauthorized(); }).RequirePermission("agent:heartbeat");
    app.MapPost("/agent/v1/registry-policy:acknowledge", async (HttpContext c, RegistryPolicyAcknowledgement a, IRegistryPolicyRepository p, CancellationToken ct) => { var principal = (PrincipalContext)c.Items["principal"]!; var ids = principal.Subject.Split(':'); if (ids.Length != 2 || !Guid.TryParse(ids[0], out var endpoint)) return Results.Unauthorized(); if (a.PolicyId == Guid.Empty) return Results.Accepted(); await p.AcknowledgeAsync(principal.TenantId, endpoint, a, ct); return Results.Accepted(); }).RequirePermission("agent:heartbeat");

    app.MapGet("/api/v1/registry-events", async (HttpContext c, IRegistryProjection p, CancellationToken ct) => { try { return Results.Ok(new ApiEnvelope<RegistryEventPage>(ProtectPage(await p.SearchAsync(c.Items["tenant"]!.ToString()!, Query(c.Request), ct), c), new(c.TraceIdentifier, "1.0"))); } catch (EnrollmentConflictException e) { return Results.BadRequest(new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)); } }).RequirePermission("registry:read");
    app.MapGet("/api/v1/registry-events/{eventId:guid}", async (Guid eventId, HttpContext c, IRegistryTelemetryRepository r, CancellationToken ct) => await r.GetEventAsync(c.Items["tenant"]!.ToString()!, eventId, ct) is { } value ? Results.Ok(new ApiEnvelope<RegistryObservation>(ProtectObservation(value, c), new(c.TraceIdentifier, "1.0"))) : Results.NotFound()).RequirePermission("registry:details:read");
    app.MapGet("/api/v1/endpoints/{endpointId:guid}/registry-keys/{entityId}", async (Guid endpointId, string entityId, HttpContext c, IRegistryTelemetryRepository r, CancellationToken ct) => entityId.Length == 64 && await r.GetKeyAsync(c.Items["tenant"]!.ToString()!, endpointId, entityId, ct) is { } value ? Results.Ok(new ApiEnvelope<RegistryKeyView>(value, new(c.TraceIdentifier, "1.0"))) : Results.NotFound()).RequirePermission("registry:path:read");
    app.MapGet("/api/v1/endpoints/{endpointId:guid}/registry-values/{entityId}", async (Guid endpointId, string entityId, HttpContext c, IRegistryTelemetryRepository r, CancellationToken ct) => entityId.Length == 64 && await r.GetValueAsync(c.Items["tenant"]!.ToString()!, endpointId, entityId, ct) is { } value ? Results.Ok(new ApiEnvelope<RegistryValueView>(ProtectValue(value, c), new(c.TraceIdentifier, "1.0"))) : Results.NotFound()).RequirePermission("registry:value-metadata:read");
    app.MapGet("/api/v1/endpoints/{endpointId:guid}/registry-keys/{entityId}/history", async (Guid endpointId, string entityId, HttpContext c, IRegistryTelemetryRepository r, CancellationToken ct) => { var range = Range(c.Request); return Results.Ok(new ApiEnvelope<RegistryEventPage>(ProtectPage(await r.KeyHistoryAsync(c.Items["tenant"]!.ToString()!, endpointId, entityId, range.From, range.To, Math.Clamp(int.TryParse(c.Request.Query["pageSize"], out var n) ? n : 100, 1, 500), ct), c), new(c.TraceIdentifier, "1.0"))); }).RequirePermission("registry:read");
    app.MapGet("/api/v1/endpoints/{endpointId:guid}/registry-values/{entityId}/history", async (Guid endpointId, string entityId, HttpContext c, IRegistryTelemetryRepository r, CancellationToken ct) => { var range = Range(c.Request); return Results.Ok(new ApiEnvelope<RegistryEventPage>(ProtectPage(await r.ValueHistoryAsync(c.Items["tenant"]!.ToString()!, endpointId, entityId, range.From, range.To, Math.Clamp(int.TryParse(c.Request.Query["pageSize"], out var n) ? n : 100, 1, 500), ct), c), new(c.TraceIdentifier, "1.0"))); }).RequirePermission("registry:read");
    app.MapGet("/api/v1/endpoints/{endpointId:guid}/registry-timeline", async (Guid endpointId, HttpContext c, IRegistryTelemetryRepository r, CancellationToken ct) => Results.Ok(new ApiEnvelope<RegistryEventPage>(ProtectPage(await r.EndpointTimelineAsync(c.Items["tenant"]!.ToString()!, endpointId, Query(c.Request, endpointId), ct), c), new(c.TraceIdentifier, "1.0")))).RequirePermission("registry:read");
    app.MapGet("/api/v1/endpoints/{endpointId:guid}/processes/{processId}/registry", async (Guid endpointId, string processId, HttpContext c, IRegistryTelemetryRepository r, CancellationToken ct) => { var range = Range(c.Request); return Results.Ok(new ApiEnvelope<RegistryEventPage>(ProtectPage(await r.ProcessRegistryAsync(c.Items["tenant"]!.ToString()!, endpointId, processId, range.From, range.To, 100, ct), c), new(c.TraceIdentifier, "1.0"))); }).RequirePermission("registry:relationship:read");
    app.MapGet("/api/v1/endpoints/{endpointId:guid}/registry-telemetry-health", async (Guid endpointId, HttpContext c, IRegistryTelemetryRepository r, CancellationToken ct) => await r.HealthAsync(c.Items["tenant"]!.ToString()!, endpointId, ct) is { } h ? Results.Ok(new ApiEnvelope<RegistryTelemetryHealth>(h, new(c.TraceIdentifier, "1.0"))) : Results.NotFound()).RequirePermission("registry:health:read");
    app.MapPost("/api/v1/registry-events/projections:rebuild", async (HttpContext c, IRegistryTelemetryRepository r, IRegistryProjection p, CancellationToken ct) => Results.Ok(new ApiEnvelope<ProcessProjectionRebuildResult>(await p.RebuildAsync(await r.ListAllAsync(ct), ct), new(c.TraceIdentifier, "1.0")))).RequirePermission("system:admin");
    app.MapGet("/api/v1/registry-events/projections:progress", (HttpContext c, IRegistryProjection p) => Results.Ok(new ApiEnvelope<RegistryProjectionRebuildProgress>(p.GetRebuildProgress(), new(c.TraceIdentifier, "1.0")))).RequirePermission("system:admin");
    app.MapGet("/api/v1/registry-events:export", async (HttpContext c, IRegistryProjection p, CancellationToken ct) => { var page = await p.SearchAsync(c.Items["tenant"]!.ToString()!, Query(c.Request) with { PageSize = 500 }, ct); static string Csv(string? value) { var safe = value ?? string.Empty; if (safe.Length > 0 && "=+-@\t\r".Contains(safe[0])) safe = "'" + safe; return '"' + safe.Replace("\"", "\"\"") + '"'; } var csv = string.Equals(c.Request.Query["format"], "csv", StringComparison.OrdinalIgnoreCase); var output = csv ? "schema_version,event_id,observed_at,operation,endpoint_id,hive,key_path,value_name,value_type,process,user,capture_state,data_quality\n" + string.Join('\n', page.Items.Select(x => string.Join(',', Csv("registry-export.v1"), Csv(x.EventId.ToString()), Csv(x.ObservedAt.ToString("O")), Csv(x.Kind.ToString()), Csv(x.EndpointId.ToString()), Csv(x.Hive), Csv(x.KeyPath), Csv(x.ValueName), Csv(x.Value.ValueType), Csv(x.Process?.ProcessEntityId), Csv(x.UserSid), Csv(x.Value.CaptureMode.ToString()), Csv(string.Join(';', x.DataQualityFlags))))) + '\n' : string.Join('\n', page.Items.Select(x => JsonSerializer.Serialize(x))) + '\n'; var bytes = Encoding.UTF8.GetBytes(output); c.Response.Headers["X-Export-Schema"] = "registry-export.v1"; c.Response.Headers["X-Export-Records"] = page.Items.Count.ToString(System.Globalization.CultureInfo.InvariantCulture); c.Response.Headers["X-Content-SHA256"] = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); return Results.File(bytes, csv ? "text/csv" : "application/x-ndjson", csv ? "registry-telemetry.csv" : "registry-telemetry.jsonl"); }).RequirePermission("registry:export");
    app.MapPost("/api/v1/registry-exports", async (RegistryExportCreateRequest input, HttpContext c, IRegistryExportRepository exports, CancellationToken ct) => { var format = input.Format.ToLowerInvariant(); if (format is not ("jsonl" or "csv")) return Results.BadRequest(new ApiError("EXPORT_FORMAT_INVALID", "Format must be jsonl or csv.", 400, c.TraceIdentifier)); if (input.MaximumRecords is < 1 or > 10000) return Results.BadRequest(new ApiError("EXPORT_LIMIT_INVALID", "Maximum records must be between 1 and 10000.", 400, c.TraceIdentifier)); var now = DateTimeOffset.UtcNow; var query = input.Query with { From = input.Query.From ?? now.AddHours(-24), To = input.Query.To ?? now, Cursor = null, PageSize = input.MaximumRecords }; if (query.To <= query.From || query.To - query.From > TimeSpan.FromDays(30)) return Results.BadRequest(new ApiError("TIME_RANGE_INVALID", "Export range must be positive and at most 30 days.", 400, c.TraceIdentifier)); var fields = input.Fields ?? []; if (fields.Length > 0 && fields.Distinct().Count() != RegistryExportWorker.EffectiveFields(fields).Length) return Results.BadRequest(new ApiError("EXPORT_FIELDS_INVALID", "One or more registry export fields are unsupported.", 400, c.TraceIdentifier)); var principal = (PrincipalContext)c.Items["principal"]!; var value = await exports.CreateAsync(principal.TenantId, principal.Subject, input with { Format = format, Query = query, Fields = fields }, ct); return Results.Accepted($"/api/v1/registry-exports/{value.Id}", new ApiEnvelope<RegistryExportJob>(value, new(c.TraceIdentifier, "1.0"))); }).RequirePermission("registry:export");
    app.MapGet("/api/v1/registry-exports/{id:guid}", async (Guid id, HttpContext c, IRegistryExportRepository exports, CancellationToken ct) => await exports.GetAsync(c.Items["tenant"]!.ToString()!, id, ct) is { } value ? Results.Ok(new ApiEnvelope<RegistryExportJob>(value, new(c.TraceIdentifier, "1.0"))) : Results.NotFound()).RequirePermission("registry:export");
    app.MapGet("/api/v1/registry-exports/{id:guid}/metadata", async (Guid id, HttpContext c, IRegistryExportRepository exports, IObjectStorage objects, CancellationToken ct) => await exports.GetAsync(c.Items["tenant"]!.ToString()!, id, ct) is { State: FileExportState.Completed } value ? Results.Stream(await objects.DownloadAsync(value.TenantId, value.MetadataObjectId.ToString("D"), ct), "application/json") : Results.NotFound()).RequirePermission("registry:export");
    app.MapGet("/api/v1/registry-exports/{id:guid}/manifest", async (Guid id, HttpContext c, IRegistryExportRepository exports, IObjectStorage objects, CancellationToken ct) => await exports.GetAsync(c.Items["tenant"]!.ToString()!, id, ct) is { State: FileExportState.Completed } value ? Results.Stream(await objects.DownloadAsync(value.TenantId, value.ManifestObjectId.ToString("D"), ct), "application/json") : Results.NotFound()).RequirePermission("registry:export");
    app.MapGet("/api/v1/registry-exports/{id:guid}/content", async (Guid id, HttpContext c, IRegistryExportRepository exports, IObjectStorage objects, CancellationToken ct) => { var principal = (PrincipalContext)c.Items["principal"]!; if (await exports.GetAsync(principal.TenantId, id, ct) is not { State: FileExportState.Completed } value) return Results.NotFound(); await exports.AuditDownloadAsync(principal.TenantId, id, principal.Subject, ct); return Results.Stream(await objects.DownloadAsync(value.TenantId, value.OutputObjectId.ToString("D"), ct), value.Format == "csv" ? "text/csv" : "application/x-ndjson"); }).RequirePermission("registry:export");
    app.MapPost("/api/v1/registry-exports/{id:guid}/download-url", async (Guid id, FileExportDownloadRequest input, HttpContext c, IRegistryExportRepository exports, PlatformOptions platform, CancellationToken ct) => { var tenant = c.Items["tenant"]!.ToString()!; if (await exports.GetAsync(tenant, id, ct) is not { State: FileExportState.Completed } value) return Results.NotFound(); var expires = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(input.ExpiresInSeconds, 5, 300)); var token = FileExportDownloadToken.Create(tenant, value.Id, expires, platform.JwtSigningKey); return Results.Ok(new ApiEnvelope<object>(new { url = $"{c.Request.Scheme}://{c.Request.Host}/api/v1/registry-exports/{id:D}/download?token={Uri.EscapeDataString(token)}", expiresAt = expires }, new(c.TraceIdentifier, "1.0"))); }).RequirePermission("registry:export");
    app.MapGet("/api/v1/registry-exports/{id:guid}/download", async (Guid id, string token, PlatformOptions platform, IRegistryExportRepository exports, IObjectStorage objects, CancellationToken ct) => { if (!FileExportDownloadToken.TryValidate(token, platform.JwtSigningKey, out var tenant, out var tokenId) || tokenId != id || await exports.GetAsync(tenant, id, ct) is not { State: FileExportState.Completed } value) return Results.NotFound(); await exports.AuditDownloadAsync(tenant, id, "presigned-url", ct); return Results.Stream(await objects.DownloadAsync(tenant, value.OutputObjectId.ToString("D"), ct), value.Format == "csv" ? "text/csv" : "application/x-ndjson"); });

    app.MapGet("/api/v1/registry-telemetry/policies", async (HttpContext c, IRegistryPolicyRepository p, CancellationToken ct) => Results.Ok(new ApiEnvelope<IReadOnlyList<RegistryPolicyVersion>>(await p.ListAsync(c.Items["tenant"]!.ToString()!, ct), new(c.TraceIdentifier, "1.0")))).RequirePermission("registry:policy:manage");
    app.MapPost("/api/v1/registry-telemetry/policies", async (HttpContext c, RegistryPolicyCreateRequest input, IRegistryPolicyRepository p, CancellationToken ct) => { var errors = RegistryPolicyValidation.Validate(input.Policy); if (errors.Count > 0) return Results.ValidationProblem(errors.ToDictionary()); var principal = (PrincipalContext)c.Items["principal"]!; var value = await p.CreateAsync(principal.TenantId, principal.Subject, input.Name, input.Policy, ct); return Results.Created($"/api/v1/registry-telemetry/policies/{value.Id}", new ApiEnvelope<RegistryPolicyVersion>(value, new(c.TraceIdentifier, "1.0"))); }).RequirePermission("registry:policy:manage");
    app.MapGet("/api/v1/endpoints/{endpointId:guid}/registry-policy", async (Guid endpointId, HttpContext c, IRegistryPolicyRepository p, CancellationToken ct) => Results.Ok(new ApiEnvelope<EffectiveRegistryPolicy>(await p.EffectiveAsync(c.Items["tenant"]!.ToString()!, endpointId, ct), new(c.TraceIdentifier, "1.0")))).RequirePermission("registry:policy:manage");
    app.MapPost("/api/v1/registry-telemetry/policies/{id:guid}:assign", async (Guid id, HttpContext c, RegistryPolicyAssignRequest input, IRegistryPolicyRepository p, CancellationToken ct) => { try { var principal = (PrincipalContext)c.Items["principal"]!; await p.AssignAsync(principal.TenantId, id, input.EndpointId, principal.Subject, ct); return Results.Accepted(); } catch (EnrollmentConflictException e) { return Results.BadRequest(new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)); } }).RequirePermission("registry:policy:manage");
    app.MapPost("/api/v1/registry-telemetry/policies/{id:guid}:rollback", async (Guid id, HttpContext c, RegistryPolicyRollbackRequest input, IRegistryPolicyRepository p, CancellationToken ct) => { try { var principal = (PrincipalContext)c.Items["principal"]!; var value = await p.RollbackAsync(principal.TenantId, id, input.Version, principal.Subject, ct); return Results.Ok(new ApiEnvelope<RegistryPolicyVersion>(value, new(c.TraceIdentifier, "1.0"))); } catch (EnrollmentConflictException e) { return Results.BadRequest(new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)); } }).RequirePermission("registry:policy:manage");
    app.MapGet("/api/v1/registry-telemetry/policies/{id:guid}/exclusions", async (Guid id, HttpContext c, IRegistryPolicyRepository p, CancellationToken ct) => (await p.ListAsync(c.Items["tenant"]!.ToString()!, ct)).FirstOrDefault(x => x.Id == id) is { } value ? Results.Ok(new ApiEnvelope<IReadOnlyList<RegistryExclusionRule>>(value.Policy.ExclusionRules?.ToArray() ?? [], new(c.TraceIdentifier, "1.0"))) : Results.NotFound()).RequirePermission("registry:exclusion:manage");
    app.MapPost("/api/v1/registry-telemetry/policies/{id:guid}/exclusions", async (Guid id, RegistryExclusionMutationRequest input, HttpContext c, IRegistryPolicyRepository p, CancellationToken ct) => { var principal = (PrincipalContext)c.Items["principal"]!; var source = (await p.ListAsync(principal.TenantId, ct)).FirstOrDefault(x => x.Id == id); if (source is null) return Results.NotFound(); var rule = new RegistryExclusionRule(Guid.NewGuid(), input.Category, input.Pattern, input.Enabled, input.Reason, principal.Subject, DateTimeOffset.UtcNow); var policy = source.Policy with { ExclusionRules = [.. (source.Policy.ExclusionRules ?? []), rule] }; var errors = RegistryPolicyValidation.Validate(policy); if (errors.Count > 0) return Results.ValidationProblem(errors.ToDictionary()); var created = await p.CreateAsync(principal.TenantId, principal.Subject, source.Name, policy, ct); return Results.Created($"/api/v1/registry-telemetry/policies/{created.Id}/exclusions/{rule.Id}", new ApiEnvelope<RegistryPolicyVersion>(created, new(c.TraceIdentifier, "1.0"))); }).RequirePermission("registry:exclusion:manage");
    app.MapPut("/api/v1/registry-telemetry/policies/{id:guid}/exclusions/{ruleId:guid}", async (Guid id, Guid ruleId, RegistryExclusionMutationRequest input, HttpContext c, IRegistryPolicyRepository p, CancellationToken ct) => { var principal = (PrincipalContext)c.Items["principal"]!; var source = (await p.ListAsync(principal.TenantId, ct)).FirstOrDefault(x => x.Id == id); if (source is null) return Results.NotFound(); var rules = source.Policy.ExclusionRules?.ToArray() ?? []; var index = Array.FindIndex(rules, x => x.Id == ruleId); if (index < 0) return Results.NotFound(); rules[index] = rules[index] with { Category = input.Category, Pattern = input.Pattern, Enabled = input.Enabled, Reason = input.Reason }; var policy = source.Policy with { ExclusionRules = rules }; var errors = RegistryPolicyValidation.Validate(policy); if (errors.Count > 0) return Results.ValidationProblem(errors.ToDictionary()); var created = await p.CreateAsync(principal.TenantId, principal.Subject, source.Name, policy, ct); return Results.Ok(new ApiEnvelope<RegistryPolicyVersion>(created, new(c.TraceIdentifier, "1.0"))); }).RequirePermission("registry:exclusion:manage");
    app.MapDelete("/api/v1/registry-telemetry/policies/{id:guid}/exclusions/{ruleId:guid}", async (Guid id, Guid ruleId, HttpContext c, IRegistryPolicyRepository p, CancellationToken ct) => { var principal = (PrincipalContext)c.Items["principal"]!; var source = (await p.ListAsync(principal.TenantId, ct)).FirstOrDefault(x => x.Id == id); if (source is null) return Results.NotFound(); var existing = source.Policy.ExclusionRules?.ToArray() ?? []; if (!existing.Any(x => x.Id == ruleId)) return Results.NotFound(); var policy = source.Policy with { ExclusionRules = existing.Where(x => x.Id != ruleId).ToArray() }; var created = await p.CreateAsync(principal.TenantId, principal.Subject, source.Name, policy, ct); return Results.Ok(new ApiEnvelope<RegistryPolicyVersion>(created, new(c.TraceIdentifier, "1.0"))); }).RequirePermission("registry:exclusion:manage");
}

static void MapFileTelemetry(WebApplication app)
{
    static (DateTimeOffset From, DateTimeOffset To) Range(HttpRequest r)
    {
        var now = DateTimeOffset.UtcNow;
        var from = DateTimeOffset.TryParse(r.Query["from"], out var f) ? f : now.AddHours(-24);
        var to = DateTimeOffset.TryParse(r.Query["to"], out var t) ? t : now;
        if (to <= from || to - from > TimeSpan.FromDays(30))
            throw new EnrollmentConflictException(
                "TIME_RANGE_INVALID",
                "File queries require a positive range of at most 30 days."
            );
        return (from, to);
    }
    static FileSearchRequest Query(HttpRequest r, Guid? endpoint = null)
    {
        var range = Range(r);
        long? L(string n) => long.TryParse(r.Query[n], out var v) ? v : null;
        return new(
            endpoint ?? (Guid.TryParse(r.Query["endpointId"], out var id) ? id : null),
            range.From,
            range.To,
            Enum.TryParse<FileEventKind>(r.Query["operation"], true, out var operation)
                ? operation
                : null,
            r.Query["filename"].FirstOrDefault(),
            r.Query["path"].FirstOrDefault(),
            r.Query["directory"].FirstOrDefault(),
            r.Query["extension"].FirstOrDefault(),
            r.Query["process"].FirstOrDefault(),
            r.Query["user"].FirstOrDefault(),
            r.Query["sha256"].FirstOrDefault(),
            Enum.TryParse<ProcessSignatureState>(r.Query["signature"], true, out var signature)
                ? signature
                : null,
            L("minimumSize"),
            L("maximumSize"),
            r.Query["collector"].FirstOrDefault(),
            r.Query["container"].FirstOrDefault(),
            r.Query["dataQuality"].FirstOrDefault(),
            int.TryParse(r.Query["pageSize"], out var size) ? size : 100,
            r.Query["cursor"].FirstOrDefault(),
            r.Query["previousPath"].FirstOrDefault(),
            r.Query["nativeFileId"].FirstOrDefault(),
            r.Query["volumeId"].FirstOrDefault(),
            L("deviceId"),
            L("inode")
        );
    }
    app.MapGet(
            "/api/v1/files",
            async (
                HttpContext c,
                IFileProjection p,
                IFileTelemetryRepository repository,
                CancellationToken ct
            ) =>
            {
                try
                {
                    var query = Query(c.Request);
                    var nativeQuery = !string.IsNullOrWhiteSpace(query.PreviousPath)
                        || !string.IsNullOrWhiteSpace(query.NativeFileId)
                        || !string.IsNullOrWhiteSpace(query.VolumeId)
                        || query.DeviceId is not null
                        || query.Inode is not null;
                    return Results.Ok(
                        new ApiEnvelope<FilePage>(
                            nativeQuery
                                ? await repository.SearchAsync(
                                    c.Items["tenant"]!.ToString()!,
                                    query,
                                    ct
                                )
                                : await p.SearchAsync(
                                    c.Items["tenant"]!.ToString()!,
                                    query,
                                    ct
                                ),
                            new(c.TraceIdentifier, "1.0")
                        )
                    );
                }
                catch (EnrollmentConflictException e)
                {
                    return Results.BadRequest(
                        new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)
                    );
                }
            }
        )
        .RequirePermission("file:read");
    app.MapGet(
            "/api/v1/file-events/{eventId:guid}",
            async (
                Guid eventId,
                HttpContext c,
                IFileTelemetryRepository r,
                CancellationToken ct
            ) =>
                await r.GetEventAsync(c.Items["tenant"]!.ToString()!, eventId, ct) is { } value
                    ? Results.Ok(
                        new ApiEnvelope<FileObservation>(value, new(c.TraceIdentifier, "1.0"))
                    )
                    : Results.NotFound()
        )
        .RequirePermission("file:read");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/files/{entityId}",
            async (
                Guid endpointId,
                string entityId,
                HttpContext c,
                IFileTelemetryRepository r,
                CancellationToken ct
            ) =>
                entityId.Length == 64
                && await r.GetAsync(c.Items["tenant"]!.ToString()!, endpointId, entityId, ct)
                    is { } value
                    ? Results.Ok(
                        new ApiEnvelope<FileEntityView>(value, new(c.TraceIdentifier, "1.0"))
                    )
                    : Results.NotFound()
        )
        .RequirePermission("file:read");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/files/{entityId}/history",
            async (
                Guid endpointId,
                string entityId,
                HttpContext c,
                IFileTelemetryRepository r,
                CancellationToken ct
            ) =>
            {
                var x = Range(c.Request);
                return Results.Ok(
                    new ApiEnvelope<FileEventPage>(
                        await r.HistoryAsync(
                            c.Items["tenant"]!.ToString()!,
                            endpointId,
                            entityId,
                            x.From,
                            x.To,
                            Math.Clamp(
                                int.TryParse(c.Request.Query["pageSize"], out var n) ? n : 100,
                                1,
                                500
                            ),
                            ct
                        ),
                        new(c.TraceIdentifier, "1.0")
                    )
                );
            }
        )
        .RequirePermission("file:read");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/file-timeline",
            async (
                Guid endpointId,
                HttpContext c,
                IFileTelemetryRepository r,
                CancellationToken ct
            ) =>
            {
                var x = Range(c.Request);
                return Results.Ok(
                    new ApiEnvelope<FileEventPage>(
                        await r.EndpointTimelineAsync(
                            c.Items["tenant"]!.ToString()!,
                            endpointId,
                            x.From,
                            x.To,
                            100,
                            ct
                        ),
                        new(c.TraceIdentifier, "1.0")
                    )
                );
            }
        )
        .RequirePermission("file:read");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/processes/{processId}/files",
            async (
                Guid endpointId,
                string processId,
                HttpContext c,
                IFileTelemetryRepository r,
                CancellationToken ct
            ) =>
            {
                var x = Range(c.Request);
                return Results.Ok(
                    new ApiEnvelope<FileEventPage>(
                        await r.ProcessFilesAsync(
                            c.Items["tenant"]!.ToString()!,
                            endpointId,
                            processId,
                            x.From,
                            x.To,
                            100,
                            ct
                        ),
                        new(c.TraceIdentifier, "1.0")
                    )
                );
            }
        )
        .RequirePermission("file:relationship:read");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/file-telemetry-health",
            async (
                Guid endpointId,
                HttpContext c,
                IFileTelemetryRepository r,
                CancellationToken ct
            ) =>
                await r.HealthAsync(c.Items["tenant"]!.ToString()!, endpointId, ct) is { } h
                    ? Results.Ok(
                        new ApiEnvelope<FileTelemetryHealth>(h, new(c.TraceIdentifier, "1.0"))
                    )
                    : Results.NotFound()
        )
        .RequirePermission("file:health:read");
    app.MapPost(
            "/api/v1/files/projections:rebuild",
            async (
                HttpContext c,
                IFileTelemetryRepository r,
                IFileProjection p,
                CancellationToken ct
            ) =>
                Results.Ok(
                    new ApiEnvelope<ProcessProjectionRebuildResult>(
                        await p.RebuildAsync(await r.ListAllAsync(ct), ct),
                        new(c.TraceIdentifier, "1.0")
                    )
                )
        )
        .RequirePermission("system:admin");
    app.MapGet(
            "/api/v1/files/projections:progress",
            (HttpContext c, IFileProjection p) =>
                Results.Ok(
                    new ApiEnvelope<FileProjectionRebuildProgress>(
                        p.GetRebuildProgress(),
                        new(c.TraceIdentifier, "1.0")
                    )
                )
        )
        .RequirePermission("system:admin");
    app.MapGet(
            "/api/v1/files:export",
            async (HttpContext c, IFileProjection p, CancellationToken ct) =>
            {
                var page = await p.SearchAsync(
                    c.Items["tenant"]!.ToString()!,
                    Query(c.Request) with
                    {
                        PageSize = 500,
                    },
                    ct
                );
                static string Csv(string? value)
                {
                    var safe = value ?? string.Empty;
                    if (safe.Length > 0 && "=+-@\t\r".Contains(safe[0]))
                        safe = "'" + safe;
                    return '"' + safe.Replace("\"", "\"\"") + '"';
                }
                var csv = string.Equals(c.Request.Query["format"], "csv", StringComparison.OrdinalIgnoreCase);
                var output = csv
                    ? "schema_version,endpoint_id,file_entity_id,last_observed,state,path,sha256,collector,data_quality\n"
                        + string.Join('\n', page.Items.Select(x => string.Join(',',
                            Csv("file-export.v1"), Csv(x.EndpointId.ToString()), Csv(x.FileEntityId),
                            Csv(x.LastObserved.ToString("O")), Csv(x.State.ToString()), Csv(x.CurrentPath),
                            Csv(x.Hash.Sha256), Csv(x.CollectorType), Csv(string.Join(';', x.DataQualityFlags))))) + '\n'
                    : string.Join('\n', page.Items.Select(x => JsonSerializer.Serialize(x))) + '\n';
                var bytes = Encoding.UTF8.GetBytes(output);
                c.Response.Headers["X-Export-Schema"] = "file-export.v1";
                c.Response.Headers["X-Export-Records"] = page.Items.Count.ToString(
                    System.Globalization.CultureInfo.InvariantCulture
                );
                c.Response.Headers["X-Content-SHA256"] = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                return Results.File(bytes, csv ? "text/csv" : "application/x-ndjson", csv ? "file-telemetry.csv" : "file-telemetry.jsonl");
            }
        )
        .RequirePermission("file:export");
    app.MapPost(
            "/api/v1/file-exports",
            async (
                FileExportCreateRequest input,
                HttpContext c,
                IFileExportRepository exports,
                CancellationToken ct
            ) =>
            {
                var format = input.Format.ToLowerInvariant();
                if (format is not ("jsonl" or "csv"))
                    return Results.BadRequest(
                        new ApiError("EXPORT_FORMAT_INVALID", "Format must be jsonl or csv.", 400, c.TraceIdentifier)
                    );
                if (input.MaximumRecords is < 1 or > 500)
                    return Results.BadRequest(
                        new ApiError("EXPORT_LIMIT_INVALID", "Maximum records must be between 1 and 500.", 400, c.TraceIdentifier)
                    );
                var now = DateTimeOffset.UtcNow;
                var query = input.Query with
                {
                    From = input.Query.From ?? now.AddHours(-24),
                    To = input.Query.To ?? now,
                    Cursor = null,
                    PageSize = input.MaximumRecords,
                };
                if (query.To <= query.From || query.To - query.From > TimeSpan.FromDays(30))
                    return Results.BadRequest(
                        new ApiError("TIME_RANGE_INVALID", "Export time range must be positive and at most 30 days.", 400, c.TraceIdentifier)
                    );
                var requestedFields = input.Fields ?? [];
                if (
                    requestedFields.Length > 0
                    && requestedFields.Distinct().Count()
                        != FileExportWorker.EffectiveFields(requestedFields).Length
                )
                    return Results.BadRequest(
                        new ApiError("EXPORT_FIELDS_INVALID", "One or more export fields are unsupported.", 400, c.TraceIdentifier)
                    );
                var principal = (PrincipalContext)c.Items["principal"]!;
                var value = await exports.CreateAsync(
                    principal.TenantId,
                    principal.Subject,
                    input with { Format = format, Query = query, Fields = requestedFields },
                    ct
                );
                return Results.Accepted(
                    $"/api/v1/file-exports/{value.Id}",
                    new ApiEnvelope<FileExportJob>(value, new(c.TraceIdentifier, "1.0"))
                );
            }
        )
        .RequirePermission("file:export");
    app.MapGet(
            "/api/v1/file-exports/{id:guid}",
            async (Guid id, HttpContext c, IFileExportRepository exports, CancellationToken ct) =>
                await exports.GetAsync(c.Items["tenant"]!.ToString()!, id, ct) is { } value
                    ? Results.Ok(new ApiEnvelope<FileExportJob>(value, new(c.TraceIdentifier, "1.0")))
                    : Results.NotFound()
        )
        .RequirePermission("file:export");
    app.MapGet(
            "/api/v1/file-exports/{id:guid}/metadata",
            async (
                Guid id,
                HttpContext c,
                IFileExportRepository exports,
                IObjectStorage objects,
                CancellationToken ct
            ) =>
                await exports.GetAsync(c.Items["tenant"]!.ToString()!, id, ct) is
                { State: FileExportState.Completed } value
                    ? Results.Stream(
                        await objects.DownloadAsync(value.TenantId, value.MetadataObjectId.ToString("D"), ct),
                        "application/json"
                    )
                    : Results.NotFound()
        )
        .RequirePermission("file:export");
    app.MapGet(
            "/api/v1/file-exports/{id:guid}/manifest",
            async (
                Guid id,
                HttpContext c,
                IFileExportRepository exports,
                IObjectStorage objects,
                CancellationToken ct
            ) =>
                await exports.GetAsync(c.Items["tenant"]!.ToString()!, id, ct) is
                { State: FileExportState.Completed } value
                    ? Results.Stream(
                        await objects.DownloadAsync(value.TenantId, value.ManifestObjectId.ToString("D"), ct),
                        "application/json"
                    )
                    : Results.NotFound()
        )
        .RequirePermission("file:export");
    app.MapGet(
            "/api/v1/file-exports/{id:guid}/content",
            async (
                Guid id,
                HttpContext c,
                IFileExportRepository exports,
                IObjectStorage objects,
                CancellationToken ct
            ) =>
            {
                var principal = (PrincipalContext)c.Items["principal"]!;
                if (await exports.GetAsync(principal.TenantId, id, ct) is not
                    { State: FileExportState.Completed } value)
                    return Results.NotFound();
                await exports.AuditDownloadAsync(principal.TenantId, id, principal.Subject, ct);
                return Results.Stream(
                    await objects.DownloadAsync(value.TenantId, value.OutputObjectId.ToString("D"), ct),
                    value.Format == "csv" ? "text/csv" : "application/x-ndjson"
                );
            }
        )
        .RequirePermission("file:export");
    app.MapPost(
            "/api/v1/file-exports/{id:guid}/download-url",
            async (
                Guid id,
                FileExportDownloadRequest input,
                HttpContext c,
                IFileExportRepository exports,
                PlatformOptions platform,
                CancellationToken ct
            ) =>
            {
                var tenant = c.Items["tenant"]!.ToString()!;
                if (await exports.GetAsync(tenant, id, ct) is not
                    { State: FileExportState.Completed } value)
                    return Results.NotFound();
                var seconds = Math.Clamp(input.ExpiresInSeconds, 5, 300);
                var expires = DateTimeOffset.UtcNow.AddSeconds(seconds);
                var token = FileExportDownloadToken.Create(tenant, value.Id, expires, platform.JwtSigningKey);
                var url = $"{c.Request.Scheme}://{c.Request.Host}/api/v1/file-exports/{id:D}/download?token={Uri.EscapeDataString(token)}";
                return Results.Ok(
                    new ApiEnvelope<object>(new { url, expiresAt = expires }, new(c.TraceIdentifier, "1.0"))
                );
            }
        )
        .RequirePermission("file:export");
    app.MapGet(
        "/api/v1/file-exports/{id:guid}/download",
        async (
            Guid id,
            string token,
            PlatformOptions platform,
            IFileExportRepository exports,
            IObjectStorage objects,
            CancellationToken ct
        ) =>
        {
            if (!FileExportDownloadToken.TryValidate(token, platform.JwtSigningKey, out var tenant, out var tokenId)
                || tokenId != id
                || await exports.GetAsync(tenant, id, ct) is not
                { State: FileExportState.Completed } value)
                return Results.NotFound();
            await exports.AuditDownloadAsync(tenant, id, "presigned-url", ct);
            return Results.Stream(
                await objects.DownloadAsync(tenant, value.OutputObjectId.ToString("D"), ct),
                value.Format == "csv" ? "text/csv" : "application/x-ndjson"
            );
        }
    );
    app.MapGet(
            "/agent/v1/file-policy",
            async (HttpContext c, IFilePolicyRepository p, CancellationToken ct) =>
            {
                var principal = (PrincipalContext)c.Items["principal"]!;
                var ids = principal.Subject.Split(':');
                return ids.Length == 2 && Guid.TryParse(ids[0], out var endpoint)
                    ? Results.Ok(await p.EffectiveAsync(principal.TenantId, endpoint, ct))
                    : Results.Unauthorized();
            }
        )
        .RequirePermission("agent:heartbeat");
    app.MapPost(
            "/agent/v1/file-policy:acknowledge",
            async (
                HttpContext c,
                FilePolicyAcknowledgement a,
                IFilePolicyRepository p,
                CancellationToken ct
            ) =>
            {
                var principal = (PrincipalContext)c.Items["principal"]!;
                var ids = principal.Subject.Split(':');
                if (ids.Length != 2 || !Guid.TryParse(ids[0], out var endpoint))
                    return Results.Unauthorized();
                await p.AcknowledgeAsync(principal.TenantId, endpoint, a, ct);
                return Results.Accepted();
            }
        )
        .RequirePermission("agent:heartbeat");
    app.MapGet(
            "/api/v1/file-telemetry/policies",
            async (HttpContext c, IFilePolicyRepository p, CancellationToken ct) =>
                Results.Ok(
                    new ApiEnvelope<IReadOnlyList<FilePolicyVersion>>(
                        await p.ListAsync(c.Items["tenant"]!.ToString()!, ct),
                        new(c.TraceIdentifier, "1.0")
                    )
                )
        )
        .RequirePermission("file:policy:manage");
    app.MapGet(
            "/api/v1/file-telemetry/policies/{id:guid}/versions/{version:int}",
            async (
                Guid id,
                int version,
                HttpContext c,
                IFilePolicyRepository p,
                CancellationToken ct
            ) =>
                (await p.ListAsync(c.Items["tenant"]!.ToString()!, ct)).FirstOrDefault(x =>
                    x.Id == id && x.Version == version
                ) is { } value
                    ? Results.Ok(
                        new ApiEnvelope<FilePolicyVersion>(value, new(c.TraceIdentifier, "1.0"))
                    )
                    : Results.NotFound()
        )
        .RequirePermission("file:policy:manage");
    app.MapGet(
            "/api/v1/file-telemetry/policies/{id:guid}/exclusions",
            async (
                Guid id,
                HttpContext c,
                IFilePolicyRepository p,
                CancellationToken ct
            ) =>
                (await p.ListAsync(c.Items["tenant"]!.ToString()!, ct)).FirstOrDefault(x =>
                    x.Id == id
                ) is { } value
                    ? Results.Ok(
                        new ApiEnvelope<IReadOnlyList<FileExclusionRule>>(
                            value.Policy.ExclusionRules?.ToArray() ?? [],
                            new(c.TraceIdentifier, "1.0")
                        )
                    )
                    : Results.NotFound()
        )
        .RequirePermission("file:policy:manage");
    app.MapPost(
            "/api/v1/file-telemetry/policies/{id:guid}/exclusions",
            async (
                Guid id,
                FileExclusionMutationRequest input,
                HttpContext c,
                IFilePolicyRepository p,
                CancellationToken ct
            ) =>
            {
                var principal = (PrincipalContext)c.Items["principal"]!;
                var source = (await p.ListAsync(principal.TenantId, ct)).FirstOrDefault(x =>
                    x.Id == id
                );
                if (source is null)
                    return Results.NotFound();
                var rule = new FileExclusionRule(
                    Guid.NewGuid(),
                    input.Category,
                    input.Pattern,
                    input.Enabled
                );
                var policy = source.Policy with
                {
                    ExclusionRules =
                    [.. (source.Policy.ExclusionRules ?? []), rule],
                };
                var errors = FilePolicyValidation.Validate(policy);
                if (errors.Count > 0)
                    return Results.ValidationProblem(errors.ToDictionary());
                var created = await p.CreateAsync(
                    principal.TenantId,
                    principal.Subject,
                    source.Name,
                    policy,
                    ct
                );
                return Results.Created(
                    $"/api/v1/file-telemetry/policies/{created.Id}/exclusions/{rule.Id}",
                    new ApiEnvelope<FilePolicyVersion>(created, new(c.TraceIdentifier, "1.0"))
                );
            }
        )
        .RequirePermission("file:policy:manage");
    app.MapPut(
            "/api/v1/file-telemetry/policies/{id:guid}/exclusions/{ruleId:guid}",
            async (
                Guid id,
                Guid ruleId,
                FileExclusionMutationRequest input,
                HttpContext c,
                IFilePolicyRepository p,
                CancellationToken ct
            ) =>
            {
                var principal = (PrincipalContext)c.Items["principal"]!;
                var source = (await p.ListAsync(principal.TenantId, ct)).FirstOrDefault(x =>
                    x.Id == id
                );
                if (source is null || source.Policy.ExclusionRules?.Any(x => x.Id == ruleId) != true)
                    return Results.NotFound();
                var rules = source.Policy.ExclusionRules
                    .Select(x =>
                        x.Id == ruleId
                            ? new FileExclusionRule(ruleId, input.Category, input.Pattern, input.Enabled)
                            : x
                    )
                    .ToArray();
                var policy = source.Policy with { ExclusionRules = rules };
                var errors = FilePolicyValidation.Validate(policy);
                if (errors.Count > 0)
                    return Results.ValidationProblem(errors.ToDictionary());
                var created = await p.CreateAsync(
                    principal.TenantId,
                    principal.Subject,
                    source.Name,
                    policy,
                    ct
                );
                return Results.Ok(
                    new ApiEnvelope<FilePolicyVersion>(created, new(c.TraceIdentifier, "1.0"))
                );
            }
        )
        .RequirePermission("file:policy:manage");
    app.MapDelete(
            "/api/v1/file-telemetry/policies/{id:guid}/exclusions/{ruleId:guid}",
            async (
                Guid id,
                Guid ruleId,
                HttpContext c,
                IFilePolicyRepository p,
                CancellationToken ct
            ) =>
            {
                var principal = (PrincipalContext)c.Items["principal"]!;
                var source = (await p.ListAsync(principal.TenantId, ct)).FirstOrDefault(x =>
                    x.Id == id
                );
                if (source is null || source.Policy.ExclusionRules?.Any(x => x.Id == ruleId) != true)
                    return Results.NotFound();
                var policy = source.Policy with
                {
                    ExclusionRules = source.Policy.ExclusionRules
                        .Where(x => x.Id != ruleId)
                        .ToArray(),
                };
                var created = await p.CreateAsync(
                    principal.TenantId,
                    principal.Subject,
                    source.Name,
                    policy,
                    ct
                );
                return Results.Ok(
                    new ApiEnvelope<FilePolicyVersion>(created, new(c.TraceIdentifier, "1.0"))
                );
            }
        )
        .RequirePermission("file:policy:manage");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/file-policy",
            async (
                Guid endpointId,
                HttpContext c,
                IFilePolicyRepository p,
                CancellationToken ct
            ) =>
                Results.Ok(
                    new ApiEnvelope<EffectiveFilePolicy>(
                        await p.EffectiveAsync(c.Items["tenant"]!.ToString()!, endpointId, ct),
                        new(c.TraceIdentifier, "1.0")
                    )
                )
        )
        .RequirePermission("file:policy:manage");
    app.MapPost(
            "/api/v1/file-telemetry/policies",
            async (
                HttpContext c,
                FilePolicyCreateRequest input,
                IFilePolicyRepository p,
                CancellationToken ct
            ) =>
            {
                var errors = FilePolicyValidation.Validate(input.Policy);
                if (errors.Count > 0)
                    return Results.ValidationProblem(errors.ToDictionary());
                var principal = (PrincipalContext)c.Items["principal"]!;
                var value = await p.CreateAsync(
                    principal.TenantId,
                    principal.Subject,
                    input.Name,
                    input.Policy,
                    ct
                );
                return Results.Created(
                    $"/api/v1/file-telemetry/policies/{value.Id}",
                    new ApiEnvelope<FilePolicyVersion>(value, new(c.TraceIdentifier, "1.0"))
                );
            }
        )
        .RequirePermission("file:policy:manage");
    app.MapPost(
            "/api/v1/file-telemetry/policies/{id:guid}:assign",
            async (
                Guid id,
                HttpContext c,
                FilePolicyAssignRequest input,
                IFilePolicyRepository p,
                CancellationToken ct
            ) =>
            {
                try
                {
                    var principal = (PrincipalContext)c.Items["principal"]!;
                    await p.AssignAsync(
                        principal.TenantId,
                        id,
                        input.EndpointId,
                        principal.Subject,
                        ct
                    );
                    return Results.Accepted();
                }
                catch (EnrollmentConflictException e)
                {
                    return Results.BadRequest(
                        new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)
                    );
                }
            }
        )
        .RequirePermission("file:policy:manage");
    app.MapPost(
            "/api/v1/file-telemetry/policies/{id:guid}:rollback",
            async (
                Guid id,
                HttpContext c,
                FilePolicyRollbackRequest input,
                IFilePolicyRepository p,
                CancellationToken ct
            ) =>
            {
                try
                {
                    var principal = (PrincipalContext)c.Items["principal"]!;
                    var value = await p.RollbackAsync(
                        principal.TenantId,
                        id,
                        input.Version,
                        principal.Subject,
                        ct
                    );
                    return Results.Ok(
                        new ApiEnvelope<FilePolicyVersion>(
                            value,
                            new(c.TraceIdentifier, "1.0")
                        )
                    );
                }
                catch (EnrollmentConflictException e)
                {
                    return Results.BadRequest(
                        new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)
                    );
                }
            }
        )
        .RequirePermission("file:policy:manage");
}

static void MapProcessPolicies(WebApplication app)
{
    app.MapGet(
            "/api/v1/process-telemetry/policies",
            async (HttpContext c, IProcessPolicyRepository policies, CancellationToken ct) =>
                Results.Ok(
                    new ApiEnvelope<IReadOnlyList<ProcessPolicyVersion>>(
                        await policies.ListAsync(c.Items["tenant"]!.ToString()!, ct),
                        new(c.TraceIdentifier, "1.0")
                    )
                )
        )
        .RequirePermission("process:health:read");
    app.MapPost(
            "/api/v1/process-telemetry/policies",
            async (
                CreateProcessPolicyRequest input,
                HttpContext c,
                IProcessPolicyRepository policies,
                CancellationToken ct
            ) =>
            {
                try
                {
                    var value = await policies.CreateAsync(
                        c.Items["tenant"]!.ToString()!,
                        c.User.Identity!.Name!,
                        input.Name,
                        input.Policy,
                        ct
                    );
                    return Results.Created(
                        $"/api/v1/process-telemetry/policies/{value.Id}",
                        new ApiEnvelope<ProcessPolicyVersion>(value, new(c.TraceIdentifier, "1.0"))
                    );
                }
                catch (EnrollmentConflictException e)
                {
                    return Results.BadRequest(
                        new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)
                    );
                }
            }
        )
        .RequirePermission("platform:admin");
    app.MapPost(
            "/api/v1/process-telemetry/policies/{policyId:guid}:assign",
            async (
                Guid policyId,
                AssignProcessPolicyRequest input,
                HttpContext c,
                IProcessPolicyRepository policies,
                CancellationToken ct
            ) =>
            {
                try
                {
                    await policies.AssignAsync(
                        c.Items["tenant"]!.ToString()!,
                        policyId,
                        input.EndpointId,
                        c.User.Identity!.Name!,
                        ct
                    );
                    return Results.Accepted();
                }
                catch (EnrollmentConflictException e)
                {
                    return Results.BadRequest(
                        new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)
                    );
                }
            }
        )
        .RequirePermission("platform:admin");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/process-policy",
            async (
                Guid endpointId,
                HttpContext c,
                IProcessPolicyRepository policies,
                CancellationToken ct
            ) =>
                Results.Ok(
                    new ApiEnvelope<EffectiveProcessPolicy>(
                        await policies.EffectiveAsync(
                            c.Items["tenant"]!.ToString()!,
                            endpointId,
                            ct
                        ),
                        new(c.TraceIdentifier, "1.0")
                    )
                )
        )
        .RequirePermission("process:health:read");
    app.MapPost(
            "/api/v1/process-telemetry/policies/{policyId:guid}:rollback",
            async (
                Guid policyId,
                RollbackProcessPolicyRequest input,
                HttpContext c,
                IProcessPolicyRepository policies,
                CancellationToken ct
            ) =>
            {
                try
                {
                    return Results.Ok(
                        new ApiEnvelope<ProcessPolicyVersion>(
                            await policies.RollbackAsync(
                                c.Items["tenant"]!.ToString()!,
                                policyId,
                                input.Version,
                                c.User.Identity!.Name!,
                                ct
                            ),
                            new(c.TraceIdentifier, "1.0")
                        )
                    );
                }
                catch (EnrollmentConflictException e)
                {
                    return Results.BadRequest(
                        new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)
                    );
                }
            }
        )
        .RequirePermission("platform:admin");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/process-exclusion-metrics",
            async (
                Guid endpointId,
                HttpContext c,
                IProcessPolicyRepository policies,
                CancellationToken ct
            ) =>
                Results.Ok(
                    new ApiEnvelope<IReadOnlyList<ProcessExclusionMetric>>(
                        await policies.ExclusionMetricsAsync(
                            c.Items["tenant"]!.ToString()!,
                            endpointId,
                            ct
                        ),
                        new(c.TraceIdentifier, "1.0")
                    )
                )
        )
        .RequirePermission("process:health:read");
    app.MapPost(
            "/api/v1/process-telemetry/exclusions:preview",
            (ProcessExclusionRule input, HttpContext c) =>
            {
                var errors = ProcessPolicyValidation.Validate(
                    new ProcessTelemetryPolicy(ExclusionRules: [input])
                );
                return errors.Count == 0
                    ? Results.Ok(
                        new ApiEnvelope<object>(
                            new
                            {
                                input.Id,
                                input.Category,
                                input.Pattern,
                                valid = true,
                            },
                            new(c.TraceIdentifier, "1.0")
                        )
                    )
                    : Results.ValidationProblem(errors.ToDictionary());
            }
        )
        .RequirePermission("platform:admin");
}

static void MapProcesses(WebApplication app)
{
    static ProcessSearchRequest Query(HttpRequest request, Guid? endpoint = null)
    {
        var now = DateTimeOffset.UtcNow;
        var from = DateTimeOffset.TryParse(request.Query["from"], out var parsedFrom)
            ? parsedFrom
            : now.AddHours(-24);
        var to = DateTimeOffset.TryParse(request.Query["to"], out var parsedTo) ? parsedTo : now;
        if (to <= from || to - from > TimeSpan.FromDays(30))
            throw new EnrollmentConflictException(
                "TIME_RANGE_INVALID",
                "Process queries require a positive range of at most 30 days."
            );
        int? Int(string name) => int.TryParse(request.Query[name], out var value) ? value : null;
        return new(
            endpoint ?? (Guid.TryParse(request.Query["endpointId"], out var id) ? id : null),
            from,
            to,
            request.Query["name"].FirstOrDefault(),
            request.Query["path"].FirstOrDefault(),
            request.Query["commandLine"].FirstOrDefault(),
            Int("pid"),
            Int("parentPid"),
            request.Query["user"].FirstOrDefault(),
            request.Query["sha256"].FirstOrDefault(),
            Enum.TryParse<ProcessSignatureState>(
                request.Query["signature"],
                true,
                out var signature
            )
                ? signature
                : null,
            request.Query["state"].FirstOrDefault(),
            Int("pageSize") ?? 100,
            request.Query["cursor"].FirstOrDefault()
        );
    }
    app.MapGet(
            "/api/v1/processes",
            async (HttpContext c, IProcessProjection projection, CancellationToken ct) =>
            {
                try
                {
                    return Results.Ok(
                        new ApiEnvelope<ProcessPage>(
                            await projection.SearchAsync(
                                c.Items["tenant"]!.ToString()!,
                                Query(c.Request),
                                ct
                            ),
                            new(c.TraceIdentifier, "1.0")
                        )
                    );
                }
                catch (EnrollmentConflictException e)
                {
                    return Results.BadRequest(
                        new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)
                    );
                }
            }
        )
        .RequirePermission("process:read");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/processes/{entityId}",
            async (
                Guid endpointId,
                string entityId,
                HttpContext c,
                IProcessTelemetryRepository repository,
                CancellationToken ct
            ) =>
                entityId.Length == 64
                && await repository.GetAsync(
                    c.Items["tenant"]!.ToString()!,
                    endpointId,
                    entityId,
                    ct
                )
                    is { } value
                    ? Results.Ok(
                        new ApiEnvelope<ProcessEntityView>(value, new(c.TraceIdentifier, "1.0"))
                    )
                    : Results.NotFound()
        )
        .RequirePermission("process:read");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/processes/{entityId}/tree",
            async (
                Guid endpointId,
                string entityId,
                int? depth,
                HttpContext c,
                IProcessTelemetryRepository repository,
                CancellationToken ct
            ) =>
                await repository.TreeAsync(
                    c.Items["tenant"]!.ToString()!,
                    endpointId,
                    entityId,
                    Math.Clamp(depth ?? 4, 0, 8),
                    ct
                )
                    is { } tree
                    ? Results.Ok(
                        new ApiEnvelope<ProcessTreeNode>(tree, new(c.TraceIdentifier, "1.0"))
                    )
                    : Results.NotFound()
        )
        .RequirePermission("process:tree:read");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/processes/{entityId}/lineage",
            async (
                Guid endpointId,
                string entityId,
                int? ancestorDepth,
                int? descendantDepth,
                HttpContext c,
                IProcessTelemetryRepository repository,
                CancellationToken ct
            ) =>
                await repository.LineageAsync(
                    c.Items["tenant"]!.ToString()!,
                    endpointId,
                    entityId,
                    Math.Clamp(ancestorDepth ?? 12, 0, 16),
                    Math.Clamp(descendantDepth ?? 6, 0, 8),
                    ct
                ) is { } lineage
                    ? Results.Ok(
                        new ApiEnvelope<ProcessLineageView>(
                            lineage,
                            new(c.TraceIdentifier, "1.0")
                        )
                    )
                    : Results.NotFound()
        )
        .RequirePermission("process:tree:read");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/process-timeline",
            async (
                Guid endpointId,
                HttpContext c,
                IProcessTelemetryRepository repository,
                CancellationToken ct
            ) =>
            {
                try
                {
                    var query = Query(c.Request, endpointId);
                    return Results.Ok(
                        new ApiEnvelope<object>(
                            new
                            {
                                items = await repository.TimelineAsync(
                                    c.Items["tenant"]!.ToString()!,
                                    endpointId,
                                    query.From,
                                    query.To,
                                    query.PageSize,
                                    ct
                                ),
                            },
                            new(c.TraceIdentifier, "1.0")
                        )
                    );
                }
                catch (EnrollmentConflictException e)
                {
                    return Results.BadRequest(
                        new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)
                    );
                }
            }
        )
        .RequirePermission("process:timeline:read");
    app.MapGet(
            "/api/v1/endpoints/{endpointId:guid}/process-telemetry-health",
            async (
                Guid endpointId,
                HttpContext c,
                IProcessTelemetryRepository repository,
                CancellationToken ct
            ) =>
                await repository.HealthAsync(c.Items["tenant"]!.ToString()!, endpointId, ct)
                    is { } health
                    ? Results.Ok(
                        new ApiEnvelope<ProcessTelemetryHealth>(
                            health,
                            new(c.TraceIdentifier, "1.0")
                        )
                    )
                    : Results.NotFound()
        )
        .RequirePermission("process:health:read");
    app.MapPost(
            "/api/v1/processes/projections:rebuild",
            async (
                HttpContext c,
                IProcessTelemetryRepository repository,
                IProcessProjection projection,
                CancellationToken ct
            ) =>
                Results.Ok(
                    new ApiEnvelope<ProcessProjectionRebuildResult>(
                        await projection.RebuildAsync(await repository.ListAllAsync(ct), ct),
                        new(c.TraceIdentifier, "1.0")
                    )
                )
        )
        .RequirePermission("system:admin");
    app.MapGet(
            "/api/v1/processes:export",
            async (HttpContext c, IProcessProjection projection, CancellationToken ct) =>
            {
                try
                {
                    var query = Query(c.Request) with
                    {
                        PageSize = Math.Min(
                            1000,
                            int.TryParse(c.Request.Query["limit"], out var limit) ? limit : 1000
                        ),
                        Cursor = null,
                    };
                    var page = await projection.SearchAsync(
                        c.Items["tenant"]!.ToString()!,
                        query,
                        ct
                    );
                    var exportedAt = DateTimeOffset.UtcNow;
                    var lines = new List<string>
                    {
                        JsonSerializer.Serialize(
                            new
                            {
                                type = "manifest",
                                schema = "process.export.v1",
                                exportedAt,
                                query = new
                                {
                                    query.EndpointId,
                                    query.From,
                                    query.To,
                                },
                                count = page.Items.Count,
                            }
                        ),
                    };
                    lines.AddRange(
                        page.Items.Select(x =>
                            JsonSerializer.Serialize(
                                new
                                {
                                    type = "process",
                                    schema = "process.entity.v1",
                                    data = x,
                                }
                            )
                        )
                    );
                    var bytes = Encoding.UTF8.GetBytes(string.Join('\n', lines) + "\n");
                    var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                    c.Response.Headers["X-Export-SHA256"] = hash;
                    c.Response.Headers["Content-Disposition"] =
                        $"attachment; filename=process-export-{exportedAt:yyyyMMddHHmmss}.jsonl";
                    return Results.Bytes(bytes, "application/x-ndjson");
                }
                catch (EnrollmentConflictException e)
                {
                    return Results.BadRequest(
                        new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)
                    );
                }
            }
        )
        .RequirePermission("process:export");
}

static void MapEndpoints(WebApplication app)
{
    app.MapPost(
            "/api/v1/enrollment-tokens",
            async (
                EnrollmentTokenCreate input,
                HttpContext c,
                IEndpointRepository repository,
                PlatformOptions options,
                CancellationToken ct
            ) =>
            {
                var tenant = c.Items["tenant"]!.ToString()!;
                try
                {
                    var value = await repository.CreateEnrollmentTokenAsync(
                        tenant,
                        c.User.Identity!.Name!,
                        input,
                        System.Text.Encoding.UTF8.GetBytes(options.EnrollmentPepper),
                        ct
                    );
                    return Results.Created(
                        $"/api/v1/enrollment-tokens/{value.Metadata.Id}",
                        new ApiEnvelope<EnrollmentTokenSecret>(value, new(c.TraceIdentifier))
                    );
                }
                catch (EnrollmentConflictException e)
                {
                    return Results.Json(
                        new ApiError(e.Code, "Token policy rejected", 400, c.TraceIdentifier),
                        statusCode: 400
                    );
                }
            }
        )
        .RequirePermission("agent:enroll");
    app.MapGet(
            "/api/v1/enrollment-tokens",
            async (HttpContext c, IEndpointRepository repository, CancellationToken ct) =>
                Results.Ok(
                    new ApiEnvelope<object>(
                        new
                        {
                            items = await repository.ListEnrollmentTokensAsync(
                                c.Items["tenant"]!.ToString()!,
                                ct
                            ),
                        },
                        new(c.TraceIdentifier)
                    )
                )
        )
        .RequirePermission("agent:enroll");
    app.MapPost(
            "/api/v1/enrollment-tokens/{id:guid}:revoke",
            async (Guid id, HttpContext c, IEndpointRepository repository, CancellationToken ct) =>
                await repository.RevokeEnrollmentTokenAsync(
                    c.Items["tenant"]!.ToString()!,
                    id,
                    c.User.Identity!.Name!,
                    ct
                )
                    ? Results.NoContent()
                    : Results.NotFound()
        )
        .RequirePermission("agent:enroll");
    app.MapGet(
            "/api/v1/endpoints",
            async (
                int? pageSize,
                string? cursor,
                string? search,
                EndpointStatus? status,
                HttpContext c,
                IEndpointProjection projection,
                CancellationToken ct
            ) =>
                Results.Ok(
                    new ApiEnvelope<EndpointPage>(
                        await projection.SearchAsync(
                            c.Items["tenant"]!.ToString()!,
                            pageSize ?? 100,
                            cursor,
                            search,
                            status,
                            ct
                        ),
                        new(c.TraceIdentifier)
                    )
                )
        )
        .RequirePermission("endpoint:read");
    app.MapGet(
            "/api/v1/endpoints/{id:guid}",
            async (Guid id, HttpContext c, IEndpointRepository repository, CancellationToken ct) =>
                await repository.GetEndpointAsync(c.Items["tenant"]!.ToString()!, id, ct)
                    is { } value
                    ? Results.Ok(new ApiEnvelope<EndpointView>(value, new(c.TraceIdentifier)))
                    : Results.NotFound()
        )
        .RequirePermission("endpoint:read");
    app.MapGet(
            "/api/v1/endpoints/{id:guid}/status-history",
            async (Guid id, HttpContext c, IEndpointRepository repository, CancellationToken ct) =>
                Results.Ok(
                    new ApiEnvelope<object>(
                        new
                        {
                            items = await repository.ListEndpointStatusHistoryAsync(
                                c.Items["tenant"]!.ToString()!,
                                id,
                                ct
                            ),
                        },
                        new(c.TraceIdentifier)
                    )
                )
        )
        .RequirePermission("endpoint:read");
    app.MapPost(
            "/api/v1/endpoints/{id:guid}:disable",
            async (
                Guid id,
                LifecycleAction input,
                HttpContext c,
                IEndpointRepository repository,
                CancellationToken ct
            ) =>
                await repository.SetEndpointAdministrativeStateAsync(
                    c.Items["tenant"]!.ToString()!,
                    id,
                    EndpointStatus.Disabled,
                    c.User.Identity!.Name!,
                    input.Reason,
                    ct
                )
                    ? Results.NoContent()
                    : Results.NotFound()
        )
        .RequirePermission("platform:admin");
    app.MapPost(
            "/api/v1/endpoints/{id:guid}:revoke",
            async (
                Guid id,
                LifecycleAction input,
                HttpContext c,
                IEndpointRepository repository,
                CancellationToken ct
            ) =>
                await repository.SetEndpointAdministrativeStateAsync(
                    c.Items["tenant"]!.ToString()!,
                    id,
                    EndpointStatus.Revoked,
                    c.User.Identity!.Name!,
                    input.Reason,
                    ct
                )
                    ? Results.NoContent()
                    : Results.NotFound()
        )
        .RequirePermission("platform:admin");
    app.MapPost(
            "/api/v1/endpoints/projections:rebuild",
            async (
                HttpContext c,
                IEndpointRepository repository,
                IEndpointProjection projection,
                PlatformMetrics metrics,
                CancellationToken ct
            ) =>
            {
                var result = await projection.RebuildAsync(
                    await repository.ListAllEndpointsForProjectionAsync(ct),
                    ct
                );
                metrics.Projection(result.Duration, result.Documents);
                return Results.Ok(
                    new ApiEnvelope<ProjectionRebuildResult>(result, new(c.TraceIdentifier))
                );
            }
        )
        .RequirePermission("platform:admin");
    app.MapGet(
            "/api/v1/endpoints/projections:rebuild",
            (HttpContext c, IEndpointProjection projection) =>
                Results.Ok(
                    new ApiEnvelope<ProjectionRebuildProgress>(
                        projection.GetRebuildProgress(),
                        new(c.TraceIdentifier)
                    )
                )
        )
        .RequirePermission("platform:admin");
}

static void MapObjectStorage(WebApplication app)
{
    app.MapPut(
            "/internal/v1/objects/{objectId}",
            async (
                string objectId,
                HttpContext c,
                IObjectStorage storage,
                PlatformMetrics metrics,
                CancellationToken ct
            ) =>
            {
                var tenant = c.Items["tenant"]?.ToString() ?? "root";
                var hash = c.Request.Headers["X-Content-SHA256"].ToString();
                if (hash.Length != 64)
                    return Results.BadRequest(
                        new { code = "VALIDATION_FAILED", detail = "X-Content-SHA256 is required" }
                    );
                var m = await storage.UploadAsync(
                    tenant,
                    objectId,
                    c.Request.Body,
                    c.Request.ContentType ?? "application/octet-stream",
                    hash,
                    ct
                );
                metrics.ObjectOperation();
                return Results.Ok(m);
            }
        )
        .RequirePermission("platform:admin");
    app.MapGet(
            "/internal/v1/objects/{objectId}",
            async (
                string objectId,
                HttpContext c,
                IObjectStorage storage,
                PlatformMetrics metrics,
                CancellationToken ct
            ) =>
            {
                var tenant = c.Items["tenant"]?.ToString() ?? "root";
                if (await storage.HeadAsync(tenant, objectId, ct) is null)
                    return Results.NotFound();
                var s = await storage.DownloadAsync(tenant, objectId, ct);
                metrics.ObjectOperation();
                return Results.Stream(s, "application/octet-stream");
            }
        )
        .RequirePermission("platform:admin");
    app.MapDelete(
            "/internal/v1/objects/{objectId}",
            async (
                string objectId,
                HttpContext c,
                IObjectStorage storage,
                PlatformMetrics metrics,
                CancellationToken ct
            ) =>
            {
                var tenant = c.Items["tenant"]?.ToString() ?? "root";
                if (await storage.HeadAsync(tenant, objectId, ct) is null)
                    return Results.NotFound();
                await storage.DeleteAsync(tenant, objectId, ct);
                metrics.ObjectOperation();
                return Results.NoContent();
            }
        )
        .RequirePermission("platform:admin");
}

static void MapServiceRegistry(WebApplication app)
{
    var registry = new ConcurrentDictionary<string, ServiceRegistration>(StringComparer.Ordinal);
    app.MapPost(
        "/internal/v1/services/register",
        (ServiceRegistration value) =>
        {
            registry[$"{value.Name}:{value.InstanceId}"] = value;
            return Results.Accepted();
        }
    ).RequirePermission("service:register");
    app.MapGet("/internal/v1/services", () => Results.Ok(registry.Values.OrderBy(x => x.Name))).RequirePermission("system:admin");
}

static void MapContractRoutes(WebApplication app)
{
    string[] collection =
    {
        "organizations",
        "tenants",
        "workspaces",
        "users",
        "groups",
        "roles",
        "role-grants",
        "service-accounts",
        "approvals",
        "endpoint-groups",
        "policies",
        "policy-assignments",
        "agent-updates",
        "events",
        "cases",
        "artifacts",
        "indicators",
        "threat-feeds",
        "connectors",
        "marketplace/packages",
        "plugins/installations",
        "report-definitions",
        "report-runs",
        "dashboards",
        "audit-events",
        "usage",
        "health/integrations",
    };
    foreach (var resource in collection)
    {
        var path = "/api/v1/" + resource;
        app.MapGet(
                path,
                (HttpContext c) =>
                    Results.Ok(
                        new ApiEnvelope<object>(
                            new { items = Array.Empty<object>() },
                            new(c.TraceIdentifier)
                        )
                    )
            )
            .RequirePermission("authenticated");
        app.MapPost(
                path,
                (JsonElement body, HttpContext c) =>
                    Results.Created(
                        path + "/" + Guid.NewGuid(),
                        new ApiEnvelope<object>(
                            new
                            {
                                id = Guid.NewGuid(),
                                status = "accepted",
                                input = body,
                            },
                            new(c.TraceIdentifier)
                        )
                    )
            )
            .RequirePermission("platform:admin");
        app.MapGet(
                path + "/{id}",
                (string id, HttpContext c) =>
                    Results.Ok(
                        new ApiEnvelope<object>(
                            new { id, status = "empty" },
                            new(c.TraceIdentifier)
                        )
                    )
            )
            .RequirePermission("authenticated");
        app.MapPatch(
                path + "/{id}",
                (string id, JsonElement body, HttpContext c) =>
                    Results.Ok(
                        new ApiEnvelope<object>(
                            new
                            {
                                id,
                                status = "updated",
                                input = body,
                            },
                            new(c.TraceIdentifier)
                        )
                    )
            )
            .RequirePermission("platform:admin");
        app.MapDelete(
                path + "/{id}",
                (string id) => Results.Accepted(value: new { id, status = "deletion_pending" })
            )
            .RequirePermission("platform:admin");
    }
    string[] commands =
    {
        "policy-versions/{id}:validate",
        "policy-versions/{id}:publish",
        "agent-updates/{id}:pause",
        "agent-updates/{id}:rollback",
        "hunts/executions",
        "hunts/executions/{id}:cancel",
        "cases/{id}:export",
        "collection-plans",
        "collection-plans/{id}:execute",
        "artifacts/{id}:promote-to-evidence",
        "evidence/{id}:export",
        "evidence/{id}:verify",
        "indicators:bulk",
        "threat-feeds/{id}:sync",
        "connectors/{id}:test",
        "plugin-installations/{id}:upgrade",
        "plugin-installations/{id}:disable",
        "ai/sessions",
        "ai/sessions/{id}/messages",
        "audit/exports",
    };
    foreach (var command in commands)
        app.MapPost(
                "/api/v1/" + command,
                (JsonElement body, HttpContext c) =>
                    Results.Accepted(
                        value: new ApiEnvelope<object>(
                            new
                            {
                                operation_id = Guid.NewGuid(),
                                status = "accepted",
                                input = body,
                            },
                            new(c.TraceIdentifier)
                        )
                    )
            )
            .RequirePermission("platform:admin");
    app.MapGet(
            "/api/v1/timeline",
            (HttpContext c) =>
                Results.Ok(
                    new ApiEnvelope<object>(
                        new { items = Array.Empty<object>() },
                        new(c.TraceIdentifier)
                    )
                )
        )
        .RequirePermission("authenticated");
    app.MapGet(
            "/api/v1/entities/{id}/graph",
            (string id) =>
                Results.Ok(
                    new
                    {
                        id,
                        nodes = Array.Empty<object>(),
                        edges = Array.Empty<object>(),
                    }
                )
        )
        .RequirePermission("authenticated");
    app.MapGet(
            "/api/v1/response-jobs/{id}",
            (string id) => Results.Ok(new { id, status = "accepted" })
        )
        .RequirePermission("authenticated");
    app.MapGet(
            "/api/v1/evidence/{id}/manifest",
            (string id) => Results.Ok(new { id, hashes = Array.Empty<object>() })
        )
        .RequirePermission("authenticated");
    app.MapGet(
            "/api/v1/ai/messages/{id}/citations",
            (string id) => Results.Ok(new { id, citations = Array.Empty<object>() })
        )
        .RequirePermission("authenticated");
    string[] detailGets =
    {
        "endpoints/{id}/agents",
        "endpoints/{id}/inventory/software",
        "endpoints/{id}/inventory/hardware",
        "endpoints/{id}/effective-configuration",
        "hunts/executions/{id}",
        "cases/{id}",
        "evidence/{id}/manifest",
        "report-runs/{id}",
    };
    foreach (var detail in detailGets)
        app.MapGet(
                "/api/v1/" + detail,
                (HttpContext c) =>
                    Results.Ok(
                        new ApiEnvelope<object>(
                            new { items = Array.Empty<object>() },
                            new(c.TraceIdentifier)
                        )
                    )
            )
            .RequirePermission("authenticated");
    string[] nestedPosts =
    {
        "agents/{id}:revoke",
        "policies/{id}/versions",
        "policy-versions/{id}:validate",
        "policy-versions/{id}:publish",
        "policy-assignments",
        "agent-updates",
        "cases/{id}/investigations",
        "cases/{id}/tasks",
        "cases/{id}/comments",
        "report-runs",
        "service-accounts/{id}/credentials",
        "approvals/{id}/decision",
    };
    foreach (var nested in nestedPosts)
        app.MapPost(
                "/api/v1/" + nested,
                (JsonElement body, HttpContext c) =>
                    Results.Accepted(
                        value: new ApiEnvelope<object>(
                            new
                            {
                                operation_id = Guid.NewGuid(),
                                status = "accepted",
                                input = body,
                            },
                            new(c.TraceIdentifier)
                        )
                    )
            )
            .RequirePermission("platform:admin");
}

static void MapFrontend(WebApplication app)
{
    var configured = Environment.GetEnvironmentVariable("PLATFORM_FRONTEND_ROOT");
    var local = Path.Combine(app.Environment.ContentRootPath, "frontend");
    var root = Path.GetFullPath(
        configured
            ?? (
                Directory.Exists(local)
                    ? local
                    : Path.Combine(app.Environment.ContentRootPath, "..", "..", "frontend")
            )
    );
    app.MapGet("/", () => Results.File(Path.Combine(root, "index.html"), "text/html"));
    app.MapGet("/app.js", () => Results.File(Path.Combine(root, "app.js"), "text/javascript"));
    app.MapGet("/styles.css", () => Results.File(Path.Combine(root, "styles.css"), "text/css"));
    app.MapGet("/accessibility.css", () => Results.File(Path.Combine(root, "accessibility.css"), "text/css"));
    app.MapGet("/live-response.css", () => Results.File(Path.Combine(root, "live-response.css"), "text/css"));
    app.MapGet("/containment.css", () => Results.File(Path.Combine(root, "containment.css"), "text/css"));
    app.MapGet("/design-system.css", () => Results.File(Path.Combine(root, "design-system.css"), "text/css"));
    app.MapGet("/soc-v2.css", () => Results.File(Path.Combine(root, "soc-v2.css"), "text/css"));
    app.MapFallback(
        (HttpContext context) =>
            context.Request.Method is "GET" or "HEAD"
                ? Results.File(Path.Combine(root, "index.html"), "text/html")
                : Results.NotFound()
    );
}

sealed record LoginRequest(string Username, string Password, string TenantId = "root");

sealed record RefreshRequest(string RefreshToken);

sealed record LifecycleAction(string Reason);

sealed record CreateProcessPolicyRequest(string Name, ProcessTelemetryPolicy Policy);

sealed record AssignProcessPolicyRequest(Guid? EndpointId);

sealed record RollbackProcessPolicyRequest(int Version);

static class ProcessJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web);
}

sealed class RequestContextMiddleware(RequestDelegate next, PlatformMetrics metrics)
{
    public async Task InvokeAsync(HttpContext c)
    {
        c.TraceIdentifier =
            c.Request.Headers["X-Request-ID"].FirstOrDefault() ?? Guid.NewGuid().ToString();
        c.Response.Headers["X-Request-ID"] = c.TraceIdentifier;
        var started = Stopwatch.GetTimestamp();
        c.Items["request-start"] = started;
        using var activity = PlatformTelemetry.Activities.StartActivity(
            $"{c.Request.Method} {c.Request.Path}",
            ActivityKind.Server
        );
        activity?.SetTag("http.request.method", c.Request.Method);
        activity?.SetTag("url.path", c.Request.Path);
        try
        {
            await next(c);
        }
        catch (EnrollmentConflictException e)
        {
            c.Response.StatusCode = 400;
            await c.Response.WriteAsJsonAsync(
                new ApiError(e.Code, e.Message, 400, c.TraceIdentifier)
            );
        }
        catch (JsonException)
        {
            c.Response.StatusCode = 400;
            await c.Response.WriteAsJsonAsync(
                new ApiError("REQUEST_INVALID", "Request encoding is invalid", 400, c.TraceIdentifier)
            );
        }
        catch (KeyNotFoundException)
        {
            c.Response.StatusCode = 404;
            await c.Response.WriteAsJsonAsync(
                new ApiError("NOT_FOUND", "The requested tenant-scoped object was not found", 404, c.TraceIdentifier)
            );
        }
        catch (NpgsqlException e)
        {
            metrics.Error();
            c.Response.StatusCode = 503;
            c.Response.Headers.RetryAfter = "3";
            await c.Response.WriteAsJsonAsync(new ApiError(
                "DATABASE_TEMPORARILY_UNAVAILABLE",
                "Authoritative storage is temporarily unavailable; retry the idempotent request after the advertised delay",
                503,
                c.TraceIdentifier,
                true));
            c.RequestServices.GetRequiredService<ILogger<RequestContextMiddleware>>()
                .LogWarning("Database request degraded {RequestId}: {ErrorType}", c.TraceIdentifier, e.GetType().Name);
        }
        catch (Exception e)
        {
            metrics.Error();
            c.Response.StatusCode = 500;
            await c.Response.WriteAsJsonAsync(
                new ApiError(
                    "INTERNAL_ERROR",
                    "Unexpected server error",
                    500,
                    c.TraceIdentifier,
                    false
                )
            );
            c.RequestServices.GetRequiredService<ILogger<RequestContextMiddleware>>()
                .LogError(e, "Unhandled request failure {RequestId}", c.TraceIdentifier);
        }
        finally
        {
            metrics.Request(c.Response.StatusCode, Stopwatch.GetElapsedTime(started));
        }
    }
}

sealed record PlatformClient(string ClientId, string Name);

sealed class PlatformClientCatalog
{
    public IReadOnlyList<PlatformClient> All { get; }

    public PlatformClientCatalog(PlatformOptions options)
    {
        var clients = new Dictionary<string, PlatformClient>(StringComparer.Ordinal);
        foreach (var entry in options.ManagedClients.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = entry.IndexOf('=');
            if (separator <= 0 || !Guid.TryParse(entry[..separator], out var id) || string.IsNullOrWhiteSpace(entry[(separator + 1)..]))
                throw new InvalidOperationException("PLATFORM_MANAGED_CLIENTS entries must use UUID=Client name separated by semicolons.");
            var clientId = id.ToString("D");
            clients[clientId] = new(clientId, entry[(separator + 1)..].Trim());
        }
        var bootstrap = Guid.Parse(options.BootstrapTenantId).ToString("D");
        clients.TryAdd(bootstrap, new(bootstrap, "Primary client"));
        All = clients.Values.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public bool Contains(string clientId) => All.Any(x => x.ClientId == clientId);
}

sealed class AuthenticationMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext c, JwtService jwt, AdministrationService administration, PlatformClientCatalog clients)
    {
        PrincipalContext? p = null;
        var certificate = await c.Connection.GetClientCertificateAsync();
        var authority = c.RequestServices.GetService<CertificateAuthority>();
        if (certificate is not null && authority is not null)
        {
            p = authority.Validate(certificate);
            if (p is not null)
            {
                var repository = c.RequestServices.GetRequiredService<IEndpointRepository>();
                if (
                    !await repository.IsCredentialActiveAsync(
                        p.TenantId,
                        certificate.Thumbprint,
                        c.RequestAborted
                    )
                )
                    p = null;
            }
        }
        var auth = c.Request.Headers.Authorization.ToString();
        if (p is null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            p = jwt.Validate(auth[7..]);
        else if (p is null && auth.StartsWith("ApiKey ", StringComparison.OrdinalIgnoreCase))
            p = await administration.AuthenticateCredentialAsync(auth[7..], c.RequestAborted);
        if (p is not null && certificate is null)
            p = await administration.ResolveManagedPrincipalAsync(p, c.RequestAborted);
        if (p is not null && certificate is null && p.Permissions.Contains("platform:admin") && c.Request.Headers["X-Platform-Client"].FirstOrDefault() is { } selected)
        {
            if (!Guid.TryParse(selected, out var clientId) || !clients.Contains(clientId.ToString("D")))
            {
                c.Response.StatusCode = StatusCodes.Status403Forbidden;
                await c.Response.WriteAsJsonAsync(new ApiError("PLATFORM_CLIENT_FORBIDDEN", "The selected client is not in this super-administrator's managed client catalog.", 403, c.TraceIdentifier), c.RequestAborted);
                return;
            }
            p = p with { TenantId = clientId.ToString("D") };
        }
        if (p is not null)
        {
            var identity = new System.Security.Claims.ClaimsIdentity(
                new[]
                {
                    new System.Security.Claims.Claim(
                        System.Security.Claims.ClaimTypes.Name,
                        p.Subject
                    ),
                },
                "platform"
            );
            c.User = new(identity);
            c.Items["tenant"] = p.TenantId;
            c.Items["permissions"] = p.Permissions;
            c.Items["principal"] = p;
        }
        await next(c);
    }
}

static class PermissionExtensions
{
    public static RouteHandlerBuilder RequirePermission(
        this RouteHandlerBuilder route,
        string permission
    )
    {
        PermissionRegistry.Register(permission);
        return route.WithMetadata(new RequiredPermissionMetadata(permission)).AddEndpointFilter(
            async (context, next) =>
            {
                var c = context.HttpContext;
                if (!c.User.Identity?.IsAuthenticated ?? true)
                    return Results.Unauthorized();
                var p = (IReadOnlySet<string>?)c.Items["permissions"];
                if (
                    permission != "authenticated"
                    && (p is null || !p.Contains(permission))
                )
                {
                    var principal = (PrincipalContext?)c.Items["principal"];
                    var endpointValue = c.Request.RouteValues["endpointId"]?.ToString();
                    if (principal is null || !Guid.TryParse(principal.Subject, out var principalId) || !Guid.TryParse(endpointValue, out var endpointId))
                        return Results.StatusCode(StatusCodes.Status403Forbidden);
                    var fleet = c.RequestServices.GetRequiredService<IFleetUpdateRepository>();
                    var groups = (await fleet.GroupsAsync(principal.TenantId, c.RequestAborted)).Where(x => x.ExplicitMembers.Contains(endpointId)).Select(x => x.GroupId).ToHashSet();
                    foreach (var value in (await fleet.MetadataAsync(principal.TenantId, c.RequestAborted)).Where(x => x.EndpointId == endpointId).SelectMany(x => x.GroupIds))
                        if (Guid.TryParse(value, out var groupId)) groups.Add(groupId);
                    if (!await c.RequestServices.GetRequiredService<AdministrationService>().IsScopedPermissionAllowedAsync(principal.TenantId, principalId, permission, endpointId, groups, c.RequestAborted))
                        return Results.StatusCode(StatusCodes.Status403Forbidden);
                }
                return await next(context);
            }
        );
    }
}

sealed class PlatformMetrics
{
    private long _requests,
        _errors,
        _durationTicks,
        _stale,
        _offline,
        _enrollments,
        _enrollmentTicks,
        _heartbeats,
        _heartbeatTicks,
        _projections,
        _projectionTicks,
        _projectionDocuments,
        _natsConsumed,
        _natsErrors,
        _outboxPublished,
        _outboxFailed,
        _outboxQueue,
        _objectOperations,
        _databaseReady,
        _natsReady,
        _searchReady,
        _storageReady,
        _processAccepted,
        _processDuplicates,
        _processRejected,
        _processGaps,
        _processIngestTicks,
        _networkAccepted,
        _networkDuplicates,
        _networkRejected,
        _networkGaps,
        _networkIngestTicks,
        _dnsAccepted,
        _dnsDuplicates,
        _dnsRejected,
        _dnsGaps,
        _dnsIngestTicks,
        _dnsSearches,
        _dnsSearchTicks,
        _dnsProjections,
        _dnsProjectionDelayTicks,
        _moduleSearches,
        _moduleSearchTicks,
        _moduleProjections,
        _moduleProjectionDelayTicks,
        _identitySearches,
        _identitySearchTicks,
        _identityProjections,
        _identityProjectionDelayTicks;

    public void Request(int status, TimeSpan duration)
    {
        Interlocked.Increment(ref _requests);
        Interlocked.Add(ref _durationTicks, duration.Ticks);
        if (status >= 500)
            Error();
    }

    public void Error() => Interlocked.Increment(ref _errors);

    public void Lifecycle(LifecycleSweepResult result)
    {
        Interlocked.Add(ref _stale, result.Stale);
        Interlocked.Add(ref _offline, result.Offline);
    }

    public void Enrollment(TimeSpan duration)
    {
        Interlocked.Increment(ref _enrollments);
        Interlocked.Add(ref _enrollmentTicks, duration.Ticks);
    }

    public void Heartbeat(TimeSpan duration)
    {
        Interlocked.Increment(ref _heartbeats);
        Interlocked.Add(ref _heartbeatTicks, duration.Ticks);
    }

    public void Projection(TimeSpan duration, long documents = 1)
    {
        Interlocked.Increment(ref _projections);
        Interlocked.Add(ref _projectionTicks, duration.Ticks);
        Interlocked.Add(ref _projectionDocuments, documents);
    }

    public void NatsConsumed() => Interlocked.Increment(ref _natsConsumed);

    public void NatsError() => Interlocked.Increment(ref _natsErrors);

    public void Outbox(int queue, bool? delivered = null)
    {
        Interlocked.Exchange(ref _outboxQueue, queue);
        if (delivered is true)
            Interlocked.Increment(ref _outboxPublished);
        else if (delivered is false)
            Interlocked.Increment(ref _outboxFailed);
    }

    public void ObjectOperation() => Interlocked.Increment(ref _objectOperations);

    public void Dependencies(bool database, bool nats, bool search, bool storage)
    {
        Interlocked.Exchange(ref _databaseReady, database ? 1 : 0);
        Interlocked.Exchange(ref _natsReady, nats ? 1 : 0);
        Interlocked.Exchange(ref _searchReady, search ? 1 : 0);
        Interlocked.Exchange(ref _storageReady, storage ? 1 : 0);
    }

    public void ProcessIngest(ProcessIngestResult result, TimeSpan duration)
    {
        Interlocked.Add(ref _processAccepted, result.Accepted);
        Interlocked.Add(ref _processDuplicates, result.Duplicates);
        Interlocked.Add(ref _processRejected, result.Rejected);
        Interlocked.Add(ref _processGaps, result.SequenceGaps);
        Interlocked.Add(ref _processIngestTicks, duration.Ticks);
    }

    public string RenderProcess() =>
        $"platform_process_events_accepted_total {Interlocked.Read(ref _processAccepted)}\nplatform_process_events_duplicate_total {Interlocked.Read(ref _processDuplicates)}\nplatform_process_events_rejected_total {Interlocked.Read(ref _processRejected)}\nplatform_process_sequence_gaps_total {Interlocked.Read(ref _processGaps)}\nplatform_process_ingestion_duration_seconds_sum {TimeSpan.FromTicks(Interlocked.Read(ref _processIngestTicks)).TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)}\nplatform_network_events_accepted_total {Interlocked.Read(ref _networkAccepted)}\nplatform_network_events_duplicate_total {Interlocked.Read(ref _networkDuplicates)}\nplatform_network_events_rejected_total {Interlocked.Read(ref _networkRejected)}\nplatform_network_sequence_gaps_total {Interlocked.Read(ref _networkGaps)}\nplatform_network_ingestion_duration_seconds_sum {TimeSpan.FromTicks(Interlocked.Read(ref _networkIngestTicks)).TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)}\nplatform_dns_events_accepted_total {Interlocked.Read(ref _dnsAccepted)}\nplatform_dns_events_duplicate_total {Interlocked.Read(ref _dnsDuplicates)}\nplatform_dns_events_rejected_total {Interlocked.Read(ref _dnsRejected)}\nplatform_dns_sequence_gaps_total {Interlocked.Read(ref _dnsGaps)}\nplatform_dns_ingestion_duration_seconds_sum {TimeSpan.FromTicks(Interlocked.Read(ref _dnsIngestTicks)).TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)}\nplatform_dns_search_operations_total {Interlocked.Read(ref _dnsSearches)}\nplatform_dns_search_duration_seconds_sum {TimeSpan.FromTicks(Interlocked.Read(ref _dnsSearchTicks)).TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)}\nplatform_dns_projection_operations_total {Interlocked.Read(ref _dnsProjections)}\nplatform_dns_projection_delay_seconds_sum {TimeSpan.FromTicks(Interlocked.Read(ref _dnsProjectionDelayTicks)).TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)}\n";

    public void NetworkIngest(NetworkIngestResult result, TimeSpan duration)
    {
        Interlocked.Add(ref _networkAccepted, result.Accepted);
        Interlocked.Add(ref _networkDuplicates, result.Duplicates);
        Interlocked.Add(ref _networkRejected, result.Rejected);
        Interlocked.Add(ref _networkGaps, result.SequenceGaps);
        Interlocked.Add(ref _networkIngestTicks, duration.Ticks);
    }

    public string RenderModule() =>
        $"platform_module_search_operations_total {Interlocked.Read(ref _moduleSearches)}\nplatform_module_search_duration_seconds_sum {TimeSpan.FromTicks(Interlocked.Read(ref _moduleSearchTicks)).TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)}\nplatform_module_projection_operations_total {Interlocked.Read(ref _moduleProjections)}\nplatform_module_projection_delay_seconds_sum {TimeSpan.FromTicks(Interlocked.Read(ref _moduleProjectionDelayTicks)).TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)}\n";

    public void DnsIngest(DnsIngestResult result, TimeSpan duration)
    {
        Interlocked.Add(ref _dnsAccepted, result.Accepted);
        Interlocked.Add(ref _dnsDuplicates, result.Duplicates);
        Interlocked.Add(ref _dnsRejected, result.Rejected);
        Interlocked.Add(ref _dnsGaps, result.SequenceGaps);
        Interlocked.Add(ref _dnsIngestTicks, duration.Ticks);
    }

    public void DnsSearch(TimeSpan duration)
    {
        Interlocked.Increment(ref _dnsSearches);
        Interlocked.Add(ref _dnsSearchTicks, duration.Ticks);
    }

    public void DnsProjection(DateTimeOffset observedAt)
    {
        Interlocked.Increment(ref _dnsProjections);
        Interlocked.Add(ref _dnsProjectionDelayTicks, (DateTimeOffset.UtcNow - observedAt).Ticks);
    }

    public void ModuleSearch(TimeSpan duration)
    {
        Interlocked.Increment(ref _moduleSearches);
        Interlocked.Add(ref _moduleSearchTicks, duration.Ticks);
    }

    public void ModuleProjection(DateTimeOffset observedAt)
    {
        Interlocked.Increment(ref _moduleProjections);
        Interlocked.Add(ref _moduleProjectionDelayTicks, Math.Max(0, (DateTimeOffset.UtcNow - observedAt).Ticks));
    }

    public void IdentitySearch(TimeSpan duration)
    {
        Interlocked.Increment(ref _identitySearches);
        Interlocked.Add(ref _identitySearchTicks, duration.Ticks);
    }

    public void IdentityProjection(DateTimeOffset observedAt)
    {
        Interlocked.Increment(ref _identityProjections);
        Interlocked.Add(ref _identityProjectionDelayTicks, Math.Max(0, (DateTimeOffset.UtcNow - observedAt).Ticks));
    }

    public (double? ProjectionMilliseconds, double? SearchMilliseconds) IdentityLatency()
    {
        var projections = Interlocked.Read(ref _identityProjections);
        var searches = Interlocked.Read(ref _identitySearches);
        return (projections == 0 ? null : TimeSpan.FromTicks(Interlocked.Read(ref _identityProjectionDelayTicks) / projections).TotalMilliseconds,
            searches == 0 ? null : TimeSpan.FromTicks(Interlocked.Read(ref _identitySearchTicks) / searches).TotalMilliseconds);
    }

    public string Render()
    {
        static string S(long ticks) =>
            TimeSpan
                .FromTicks(ticks)
                .TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return $"# TYPE platform_http_requests_total counter\nplatform_http_requests_total {Interlocked.Read(ref _requests)}\n# TYPE platform_http_errors_total counter\nplatform_http_errors_total {Interlocked.Read(ref _errors)}\n# TYPE platform_http_duration_seconds_sum counter\nplatform_http_duration_seconds_sum {S(Interlocked.Read(ref _durationTicks))}\n# TYPE platform_enrollments_total counter\nplatform_enrollments_total {Interlocked.Read(ref _enrollments)}\nplatform_enrollment_duration_seconds_sum {S(Interlocked.Read(ref _enrollmentTicks))}\n# TYPE platform_heartbeats_total counter\nplatform_heartbeats_total {Interlocked.Read(ref _heartbeats)}\nplatform_heartbeat_duration_seconds_sum {S(Interlocked.Read(ref _heartbeatTicks))}\nplatform_projection_operations_total {Interlocked.Read(ref _projections)}\nplatform_projection_duration_seconds_sum {S(Interlocked.Read(ref _projectionTicks))}\nplatform_projection_documents_total {Interlocked.Read(ref _projectionDocuments)}\nplatform_endpoint_stale_transitions_total {Interlocked.Read(ref _stale)}\nplatform_endpoint_offline_transitions_total {Interlocked.Read(ref _offline)}\nplatform_nats_messages_consumed_total {Interlocked.Read(ref _natsConsumed)}\nplatform_nats_redelivery_errors_total {Interlocked.Read(ref _natsErrors)}\nplatform_outbox_published_total {Interlocked.Read(ref _outboxPublished)}\nplatform_outbox_failed_total {Interlocked.Read(ref _outboxFailed)}\n# TYPE platform_outbox_queue_depth gauge\nplatform_outbox_queue_depth {Interlocked.Read(ref _outboxQueue)}\nplatform_minio_operations_total {Interlocked.Read(ref _objectOperations)}\nplatform_database_ready {Interlocked.Read(ref _databaseReady)}\nplatform_database_pool_max_connections 40\nplatform_nats_ready {Interlocked.Read(ref _natsReady)}\nplatform_opensearch_ready {Interlocked.Read(ref _searchReady)}\nplatform_minio_ready {Interlocked.Read(ref _storageReady)}\n";
    }
}

sealed class EndpointLifecycleWorker(
    IEndpointRepository repository,
    PlatformMetrics metrics,
    ILogger<EndpointLifecycleWorker> logger
) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await repository.SweepEndpointLifecycleAsync(
                    TimeSpan.FromMinutes(2),
                    TimeSpan.FromMinutes(10),
                    ct
                );
                metrics.Lifecycle(result);
                if (result.Stale + result.Offline > 0)
                    logger.LogInformation(
                        "Endpoint lifecycle sweep transitioned {Stale} stale and {Offline} offline",
                        result.Stale,
                        result.Offline
                    );
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                logger.LogWarning("Endpoint lifecycle sweep failed: {ErrorType}", e.GetType().Name);
            }
            await Task.Delay(TimeSpan.FromSeconds(15), ct);
        }
    }
}

sealed class NatsEndpointProjectionConsumer(
    IMessageBus bus,
    IEndpointRepository repository,
    IEndpointProjection projection,
    IProcessTelemetryRepository processRepository,
    IProcessProjection processProjection,
    IFileTelemetryRepository fileRepository,
    IFileProjection fileProjection,
    IRegistryTelemetryRepository registryRepository,
    IRegistryProjection registryProjection,
    INetworkTelemetryRepository networkRepository,
    INetworkProjection networkProjection,
    IDnsTelemetryRepository dnsRepository,
    IDnsProjection dnsProjection,
    IModuleTelemetryRepository moduleRepository,
    IModuleProjection moduleProjection,
    IPersistenceTelemetryRepository persistenceRepository,
    IPersistenceProjection persistenceProjection,
    IIdentityTelemetryRepository identityRepository,
    IIdentityProjection identityProjection,
    IExecutionTelemetryRepository executionRepository,
    IExecutionProjection executionProjection,
    IDetectionRepository detectionRepository,
    IDetectionProjection detectionProjection,
    ICorrelationRepository correlationRepository,
    ICorrelationProjection correlationProjection,
    IInvestigationRepository investigationRepository,
    IThreatIntelligenceRepository threatRepository,
    IThreatIntelligenceProjection threatProjection,
    PlatformMetrics metrics,
    ILogger<NatsEndpointProjectionConsumer> logger
) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (bus is not NatsMessageBus nats)
            return;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await nats.ConsumeEndpointEventsAsync(
                    async (message, token) =>
                    {
                        var started = Stopwatch.GetTimestamp();
                        var data = message.Data;
                        if (message.Type.StartsWith("finding.", StringComparison.Ordinal))
                        {
                            if (data.TryGetProperty("findingId", out var findingElement)
                                && findingElement.TryGetGuid(out var findingId)
                                && await detectionRepository.GetFindingAsync(message.TenantId, findingId, token) is { } finding)
                                await detectionProjection.UpsertAsync(finding, token);
                            metrics.NatsConsumed();
                            return;
                        }
                        if (message.Type.StartsWith("correlation.finding.", StringComparison.Ordinal))
                        {
                            if (data.TryGetProperty("correlatedFindingId", out var correlationElement)
                                && correlationElement.TryGetGuid(out var correlationId)
                                && await correlationRepository.GetFindingAsync(message.TenantId, correlationId, token) is { } correlated)
                            {
                                await correlationProjection.UpsertAsync(correlated, token);
                                var nodes = new List<InvestigationEntity>
                                {
                                    new(message.TenantId, correlated.CorrelatedFindingId.ToString("D"), InvestigationEntityType.CorrelatedFinding, correlated.EndpointId, correlated.RuleName, correlated.FirstSeen, correlated.LastSeen, new Dictionary<string, string?> { ["mitreTechnique"] = correlated.MitreTechnique, ["processEntityId"] = correlated.CorrelationKey, ["status"] = correlated.CompletionState.ToString() }, correlated.EvidenceEventIds.Concat(correlated.ChildFindingIds).Distinct().ToArray(), correlated.MatchedSteps.SelectMany(x => x.EvidenceReferences).Distinct().ToArray(), $"correlation-engine:{correlated.EngineVersion}", correlated.TelemetryQuality, correlated.IncompleteEvidence)
                                };
                                var edges = new List<InvestigationRelationship>();
                                foreach (var childId in correlated.ChildFindingIds)
                                {
                                    if (await detectionRepository.GetFindingAsync(message.TenantId, childId, token) is not { } child) continue;
                                    nodes.Add(new(message.TenantId, child.FindingId.ToString("D"), InvestigationEntityType.DetectionFinding, child.EndpointId, child.RuleName, child.FirstSeen, child.LastSeen, new Dictionary<string, string?> { ["processEntityId"] = child.ProcessEntityId, ["entityId"] = child.EntityId, ["status"] = child.Status }, child.MatchingEventIds, child.EvidenceReferences, $"detection-engine:{child.EngineVersion}", child.TelemetryQuality, child.MissingTelemetry.Length > 0));
                                    edges.Add(new(InvestigationSafety.StableId(message.TenantId, correlated.CorrelatedFindingId.ToString("D"), child.FindingId.ToString("D"), "contains"), message.TenantId, correlated.CorrelatedFindingId.ToString("D"), InvestigationEntityType.CorrelatedFinding, child.FindingId.ToString("D"), InvestigationEntityType.DetectionFinding, "contains", child.MatchingEventIds, child.EvidenceReferences, child.FirstSeen, child.LastSeen, correlated.Confidence, "correlation-exact-child-finding", correlated.IncompleteEvidence, 1));
                                }
                                await investigationRepository.UpsertAsync(message.TenantId, nodes, edges, token);
                            }
                            metrics.NatsConsumed();
                            return;
                        }
                        if (message.Type.StartsWith("threat.indicator.", StringComparison.Ordinal))
                        {
                            if (data.TryGetProperty("indicatorId", out var indicatorElement)
                                && indicatorElement.TryGetGuid(out var indicatorId)
                                && await threatRepository.GetAsync(message.TenantId, indicatorId,
                                    data.TryGetProperty("version", out var versionElement) && versionElement.TryGetInt32(out var version) ? version : null, token) is { } indicator)
                                await threatProjection.UpsertIndicatorAsync(indicator, token);
                            metrics.NatsConsumed(); return;
                        }
                        if (message.Type.StartsWith("threat.match.", StringComparison.Ordinal))
                        {
                            if (data.TryGetProperty("matchId", out var matchElement)
                                && matchElement.TryGetGuid(out var matchId))
                            {
                                var page = await threatRepository.SearchMatchesAsync(message.TenantId, new(PageSize: 500), token);
                                if (page.Items.FirstOrDefault(x => x.MatchId == matchId) is { } match)
                                {
                                    await threatProjection.UpsertMatchAsync(match, token);
                                    if (await threatRepository.GetAsync(message.TenantId, match.IndicatorId, match.IndicatorVersion, token) is { } indicator)
                                    {
                                        var indicatorNode = new InvestigationEntity(message.TenantId, indicator.IndicatorId.ToString("D"), InvestigationEntityType.ThreatIndicator, null, $"{indicator.Type}: {indicator.CanonicalValue}", indicator.FirstSeen ?? indicator.ValidFrom, indicator.LastSeen ?? indicator.UpdatedAt, new Dictionary<string, string?> { ["sourceId"] = indicator.SourceId.ToString("D"), ["indicatorVersion"] = indicator.Version.ToString(System.Globalization.CultureInfo.InvariantCulture), ["confidence"] = indicator.Confidence.ToString(System.Globalization.CultureInfo.InvariantCulture), ["active"] = indicator.ActiveAt(DateTimeOffset.UtcNow).ToString() }, [], [indicator.Provenance], $"threat-intelligence:{indicator.NormalizationVersion}", [], false);
                                        var matchNode = new InvestigationEntity(message.TenantId, match.MatchId.ToString("D"), InvestigationEntityType.ThreatMatch, match.EndpointId, $"IOC match: {match.MatchedField}", match.FirstSeen, match.LastSeen, new Dictionary<string, string?> { ["indicatorId"] = match.IndicatorId.ToString("D"), ["processEntityId"] = match.ProcessEntityId, ["entityId"] = match.EntityId, ["matchedField"] = match.MatchedField, ["matchedValue"] = match.MatchedValue, ["mode"] = match.Mode.ToString() }, [match.EvidenceEventId], [match.EvidenceReference], $"threat-intelligence:{match.EngineVersion}", match.TelemetryQuality, false);
                                        var edge = new InvestigationRelationship(InvestigationSafety.StableId(message.TenantId, match.MatchId.ToString("D"), indicator.IndicatorId.ToString("D"), "matched-indicator"), message.TenantId, match.MatchId.ToString("D"), InvestigationEntityType.ThreatMatch, indicator.IndicatorId.ToString("D"), InvestigationEntityType.ThreatIndicator, "matched-indicator", [match.EvidenceEventId], [match.EvidenceReference], match.FirstSeen, match.LastSeen, match.Confidence, "exact-ioc-evidence", false, 1);
                                        await investigationRepository.UpsertAsync(message.TenantId, [matchNode, indicatorNode], [edge], token);
                                        var fields = new Dictionary<string, string?> { ["iocMatch.indicatorId"] = match.IndicatorId.ToString("D"), ["iocMatch.indicatorVersion"] = match.IndicatorVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), ["iocMatch.sourceId"] = match.SourceId.ToString("D"), ["iocMatch.type"] = match.MatchType.ToString(), ["iocMatch.field"] = match.MatchedField, ["iocMatch.value"] = match.MatchedValue, ["iocMatch.excluded"] = match.Excluded.ToString(), ["processEntityId"] = match.ProcessEntityId };
                                        var observation = new CorrelationObservation(match.MatchId, message.TenantId, CorrelationInputKind.Event, DetectionDomain.ThreatIntelligence, match.LastSeen, DateTimeOffset.UtcNow, match.EndpointId, match.ProcessEntityId, null, match.EntityId, null, null, fields, match.EvidenceReference, false, false, [], match.TelemetryQuality, match.Confidence);
                                        await investigationRepository.UpsertObservationAsync(message.TenantId, observation, token);
                                        if (!match.Excluded) await correlationRepository.EvaluateAsync(message.TenantId, observation, match.Mode == ThreatMatchMode.Live ? DetectionExecutionMode.Live : DetectionExecutionMode.Simulation, null, null, null, match.Mode == ThreatMatchMode.Live, token);
                                    }
                                }
                            }
                            metrics.NatsConsumed(); return;
                        }
                        if (
                            !data.TryGetProperty("endpointId", out var id)
                            || !id.TryGetGuid(out var endpointId)
                        )
                            return;
                        if (message.Type.StartsWith("process.", StringComparison.Ordinal))
                        {
                            if (
                                data.TryGetProperty("processEntityId", out var entity)
                                && entity.GetString() is { Length: 64 } entityId
                                && await processRepository.GetAsync(
                                    message.TenantId,
                                    endpointId,
                                    entityId,
                                    token
                                )
                                    is { } process
                            )
                            {
                                await processProjection.UpsertAsync(process, message.Id, token);
                                await Detect(message.TenantId, DetectionDomain.Process, process.StartEventId, process.EndpointId, process.StartTime, process, $"postgresql://platform/process_entities/{process.ProcessEntityId}", token);
                            }
                        }
                        else if (message.Type.StartsWith("file.", StringComparison.Ordinal))
                        {
                            if (data.TryGetProperty("eventId", out var fileEvent)
                                && fileEvent.TryGetGuid(out var fileEventId)
                                && await fileRepository.GetEventAsync(message.TenantId, fileEventId, token) is { } fileObservation)
                                await Detect(message.TenantId, DetectionDomain.File, fileObservation.EventId, fileObservation.EndpointId, fileObservation.ObservedAt, fileObservation, $"postgresql://platform/file_events/{fileObservation.EventId:D}", token);
                            if (
                                data.TryGetProperty("fileEntityId", out var entity)
                                && entity.GetString() is { Length: 64 } entityId
                                && await fileRepository.GetAsync(
                                    message.TenantId,
                                    endpointId,
                                    entityId,
                                    token
                                )
                                    is { } file
                            )
                                await fileProjection.UpsertAsync(file, message.Id, token);
                        }
                        else if (message.Type.StartsWith("registry.", StringComparison.Ordinal))
                        {
                            if (
                                data.TryGetProperty("eventId", out var registryEvent)
                                && registryEvent.TryGetGuid(out var registryEventId)
                                && await registryRepository.GetEventAsync(
                                    message.TenantId,
                                    registryEventId,
                                    token
                                ) is { } observation
                            )
                            {
                                await registryProjection.UpsertAsync(
                                    message.TenantId,
                                    observation,
                                    token
                                );
                                await Detect(message.TenantId, DetectionDomain.Registry, observation.EventId, observation.EndpointId, observation.ObservedAt, observation, $"postgresql://platform/registry_events/{observation.EventId:D}", token);
                            }
                        }
                        else if (message.Type.StartsWith("network.", StringComparison.Ordinal))
                        {
                            if (
                                data.TryGetProperty("eventId", out var networkEvent)
                                && networkEvent.TryGetGuid(out var networkEventId)
                                && await networkRepository.GetEventAsync(
                                    message.TenantId,
                                    networkEventId,
                                    token
                                ) is { } observation
                            )
                            {
                                await networkProjection.UpsertAsync(
                                    message.TenantId,
                                    observation,
                                    token
                                );
                                await Detect(message.TenantId, DetectionDomain.Network, observation.EventId, observation.EndpointId, observation.ObservedAt, observation, $"postgresql://platform/network_events/{observation.EventId:D}", token);
                            }
                        }
                        else if (message.Type.StartsWith("dns.", StringComparison.Ordinal))
                        {
                            if (data.TryGetProperty("eventId", out var dnsEvent)
                                && dnsEvent.TryGetGuid(out var dnsEventId)
                                && await dnsRepository.GetEventAsync(message.TenantId, dnsEventId, token) is { } observation)
                            {
                                await dnsProjection.UpsertAsync(message.TenantId, observation, token);
                                await Detect(message.TenantId, DetectionDomain.Dns, observation.EventId, observation.EndpointId, observation.ObservedAt, observation, $"postgresql://platform/dns_events/{observation.EventId:D}", token);
                                metrics.DnsProjection(observation.ObservedAt);
                            }
                        }
                        else if (message.Type.StartsWith("module.", StringComparison.Ordinal))
                        {
                            if (data.TryGetProperty("eventId", out var moduleEvent)
                                && moduleEvent.TryGetGuid(out var moduleEventId)
                                && await moduleRepository.GetAsync(message.TenantId, moduleEventId, token) is { } module)
                            {
                                await moduleProjection.UpsertAsync(message.TenantId, module, token);
                                await Detect(message.TenantId, DetectionDomain.Module, module.EventId, module.EndpointId, module.ObservedAt, module, $"postgresql://platform/module_events/{module.EventId:D}", token);
                                metrics.ModuleProjection(module.ObservedAt);
                            }
                        }
                        else if (message.Type.StartsWith("persistence.", StringComparison.Ordinal))
                        {
                            if (data.TryGetProperty("eventId", out var persistenceEvent)
                                && persistenceEvent.TryGetGuid(out var persistenceEventId)
                                && await persistenceRepository.GetAsync(message.TenantId, persistenceEventId, token) is { } persistence)
                            {
                                await persistenceProjection.UpsertAsync(message.TenantId, persistence, token);
                                await Detect(message.TenantId, DetectionDomain.Persistence, persistence.EventId, persistence.EndpointId, persistence.ObservedAt, persistence, $"postgresql://platform/persistence_events/{persistence.EventId:D}", token);
                            }
                        }
                        else if (message.Type.StartsWith("identity.", StringComparison.Ordinal))
                        {
                            if (data.TryGetProperty("eventId", out var identityEvent)
                                && identityEvent.TryGetGuid(out var identityEventId)
                                && await identityRepository.GetAsync(message.TenantId, identityEventId, token) is { } identity)
                            {
                                await identityProjection.UpsertAsync(message.TenantId, identity, token);
                                await Detect(message.TenantId, DetectionDomain.Identity, identity.EventId, identity.EndpointId, identity.ObservedAt, identity, $"postgresql://platform/identity_events/{identity.EventId:D}", token);
                                metrics.IdentityProjection(identity.ObservedAt);
                            }
                        }
                        else if (message.Type.StartsWith("execution.", StringComparison.Ordinal))
                        {
                            if (data.TryGetProperty("eventId", out var executionEvent)
                                && executionEvent.TryGetGuid(out var executionEventId)
                                && await executionRepository.GetAsync(message.TenantId, executionEventId, token) is { } execution)
                            {
                                await executionProjection.UpsertAsync(message.TenantId, execution, token);
                                await Detect(message.TenantId, DetectionDomain.Execution, execution.EventId, execution.EndpointId, execution.ObservedAt, execution, $"postgresql://platform/execution_events/{execution.EventId:D}", token);
                            }
                        }
                        else if (
                            await repository.GetEndpointAsync(
                                message.TenantId,
                                endpointId,
                                token
                            ) is
                            { } endpoint
                        )
                            await projection.UpsertAsync(endpoint, message.Id, token);
                        metrics.NatsConsumed();
                        metrics.Projection(Stopwatch.GetElapsedTime(started));
                    },
                    ct
                );
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                metrics.NatsError();
                logger.LogWarning(
                    "NATS projection consumer interrupted: {ErrorType}",
                    e.GetType().Name
                );
                await Task.Delay(TimeSpan.FromSeconds(2), ct);
            }
        }
    }

    async Task Detect<T>(string tenant, DetectionDomain domain, Guid eventId, Guid endpoint, DateTimeOffset observedAt, T canonical, string reference, CancellationToken ct)
    {
        var evidence = DetectionEvidenceMapper.FromCanonical(tenant, domain, eventId, endpoint, observedAt, canonical, reference);
        var observation = new CorrelationObservation(evidence.EventId, tenant, CorrelationInputKind.Event, domain, evidence.EventTime, DateTimeOffset.UtcNow, evidence.EndpointId, evidence.ProcessEntityId, evidence.Fields.GetValueOrDefault("parentProcessEntityId"), evidence.EntityId, null, null, evidence.Fields, evidence.EvidenceReference, evidence.Late, evidence.Incomplete, evidence.MissingTelemetry, evidence.Quality, 0);
        await investigationRepository.UpsertObservationAsync(tenant, observation, ct);
        await correlationRepository.EvaluateAsync(tenant, observation, DetectionExecutionMode.Live, null, null, null, true, ct);
        var detection = await detectionRepository.EvaluateAsync(tenant, evidence, DetectionExecutionMode.Live, null, null, null, true, ct);
        if (detection.Finding is { } finding)
        {
            var findingObservation = new CorrelationObservation(finding.FindingId, tenant, CorrelationInputKind.DetectionFinding, domain, finding.LastSeen, DateTimeOffset.UtcNow, finding.EndpointId, finding.ProcessEntityId, evidence.Fields.GetValueOrDefault("parentProcessEntityId"), finding.EntityId, finding.FindingId, finding.DetectionId, evidence.Fields, $"postgresql://platform/detection_findings/{finding.FindingId:D}", false, false, finding.MissingTelemetry, finding.TelemetryQuality, finding.Confidence);
            await investigationRepository.UpsertObservationAsync(tenant, findingObservation, ct);
            await correlationRepository.EvaluateAsync(tenant, findingObservation, DetectionExecutionMode.Live, null, null, null, true, ct);
        }
        try
        {
            IReadOnlyList<ThreatEvidence> candidates = canonical switch
            {
                FileObservation value => ThreatEvidenceMapper.FromFile(value, reference),
                NetworkObservation value => ThreatEvidenceMapper.FromNetwork(value, reference),
                DnsObservation value => ThreatEvidenceMapper.FromDns(value, reference),
                ModuleObservation value => ThreatEvidenceMapper.FromModule(value, reference),
                ProcessEntityView value => ThreatEvidenceMapper.FromProcess(value, reference),
                _ => []
            };
            if (candidates.Count > 0)
                await threatRepository.MatchAsync(tenant, candidates, ThreatMatchMode.Live, ct);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            logger.LogWarning("Threat intelligence matching isolated from telemetry ingestion: {ErrorType}", e.GetType().Name);
        }
    }
}

sealed class ThreatBackmatchWorker(IServiceProvider services,
    ILogger<ThreatBackmatchWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var processor = services.GetService<IThreatBackmatchProcessor>(); if (processor is null) return;
        while (!ct.IsCancellationRequested)
        {
            try { if (!await processor.ProcessNextAsync(ct)) await Task.Delay(TimeSpan.FromSeconds(2), ct); }
            catch (Exception e) when (e is not OperationCanceledException) { logger.LogWarning("Bounded threat backmatch worker isolated failure: {ErrorType}", e.GetType().Name); await Task.Delay(TimeSpan.FromSeconds(2), ct); }
        }
    }
}

sealed class ServiceRegistrar(
    PlatformOptions options,
    IHttpClientFactory clients,
    JwtService jwt,
    ILogger<ServiceRegistrar> logger
) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(options.RegistryUrl))
            return;
        var client = clients.CreateClient();
        var reg = new ServiceRegistration(
            options.ServiceName,
            options.InstanceId,
            Environment.GetEnvironmentVariable("ASPNETCORE_URLS") ?? "http://localhost:8080",
            options.Region,
            DateTimeOffset.UtcNow
        );
        while (!ct.IsCancellationRequested)
        {
            try
            {
                client.DefaultRequestHeaders.Authorization = new("Bearer", jwt.Issue($"service:{options.InstanceId}", options.BootstrapTenantId, ["service:register"], TimeSpan.FromMinutes(5), "service"));
                using var response = await client.PostAsJsonAsync(
                    options.RegistryUrl.TrimEnd('/') + "/internal/v1/services/register",
                    reg,
                    ct
                );
                if (!response.IsSuccessStatusCode)
                    logger.LogWarning("Registry returned {Status}", response.StatusCode);
            }
            catch (HttpRequestException e)
            {
                logger.LogWarning("Service registration unavailable: {Message}", e.Message);
            }
            await Task.Delay(TimeSpan.FromSeconds(20), ct);
        }
    }
}

sealed class MigrationRunner(PlatformOptions options, ILogger<MigrationRunner> logger)
    : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        var root = Path.Combine(options.DataDirectory, "migrations");
        Directory.CreateDirectory(root);
        var marker = Path.Combine(root, "0001-sprint-zero.applied");
        if (!File.Exists(marker))
        {
            await File.WriteAllTextAsync(
                marker,
                $"applied={DateTimeOffset.UtcNow:O}\nrollback=drop sprint-zero logical schemas",
                ct
            );
            logger.LogInformation("Applied migration 0001-sprint-zero");
        }
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}

sealed class InfrastructureInitializer(
    IMessageBus bus,
    IServiceProvider services,
    IEndpointProjection projection,
    IProcessProjection processProjection,
    IFileProjection fileProjection,
    IRegistryProjection registryProjection,
    INetworkProjection networkProjection,
    IDnsProjection dnsProjection,
    IModuleProjection moduleProjection
    , IPersistenceProjection persistenceProjection
    , IIdentityProjection identityProjection
    , IExecutionProjection executionProjection
    , IDetectionProjection detectionProjection
    , ICorrelationProjection correlationProjection
    , IThreatIntelligenceProjection threatProjection
    , ITunnelAnalyticsProjection tunnelProjection
) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        if (bus is NatsMessageBus nats)
            await nats.ConnectAsync(ct);
        if (services.GetService<MinioObjectStorage>() is { } minioStorage)
            await minioStorage.EnsureBucketAsync(ct);
        if (projection is OpenSearchEndpointProjection search)
            await search.EnsureIndexAsync(ct);
        if (processProjection is OpenSearchProcessProjection processes)
            await processes.EnsureAsync(ct);
        if (fileProjection is OpenSearchFileProjection files)
            await files.EnsureAsync(ct);
        if (registryProjection is OpenSearchRegistryProjection registry)
            await registry.EnsureAsync(ct);
        if (networkProjection is OpenSearchNetworkProjection network)
            await network.EnsureAsync(ct);
        if (dnsProjection is OpenSearchDnsProjection dns)
            await dns.EnsureAsync(ct);
        if (moduleProjection is OpenSearchModuleProjection modules)
            await modules.EnsureAsync(ct);
        if (persistenceProjection is OpenSearchPersistenceProjection persistence)
            await persistence.EnsureAsync(ct);
        if (identityProjection is OpenSearchIdentityProjection identity)
            await identity.EnsureAsync(ct);
        if (executionProjection is OpenSearchExecutionProjection execution)
            await execution.EnsureAsync(ct);
        await detectionProjection.EnsureAsync(ct);
        await correlationProjection.EnsureAsync(ct);
        await threatProjection.EnsureAsync(ct);
        await tunnelProjection.EnsureAsync(ct);
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}

sealed class OutboxPublisher(
    IEndpointRepository repository,
    IMessageBus bus,
    PlatformMetrics metrics,
    ILogger<OutboxPublisher> logger
) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await RunCycleAsync(ct);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                logger.LogWarning(e, "Outbox publisher work cycle temporarily unavailable");
                await Task.Delay(TimeSpan.FromSeconds(1), ct);
            }
        }
    }

    private async Task RunCycleAsync(CancellationToken ct)
    {
        var batch = await repository.LeaseOutboxAsync(50, TimeSpan.FromSeconds(30), ct);
        metrics.Outbox(batch.Count);
        await BoundedAsync.ForEachAsync(
            batch,
            8,
            async (item, token) =>
            {
                try
                {
                    await bus.PublishAsync(
                        new TypedMessage<JsonElement>(
                            item.Type,
                            item.Version,
                            item.Id.ToString(),
                            item.TenantId,
                            item.CreatedAt,
                            JsonSerializer.Deserialize<JsonElement>(item.Payload),
                            item.TraceId
                        ),
                        token
                    );
                    await repository.MarkOutboxPublishedAsync(item.Id, token);
                    metrics.Outbox(batch.Count, true);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    metrics.Outbox(batch.Count, false);
                    logger.LogWarning(
                        "Outbox delivery {EventId} failed: {ErrorType}",
                        item.Id,
                        e.GetType().Name
                    );
                    await repository.MarkOutboxFailedAsync(
                        item.Id,
                        "dependency-unavailable",
                        10,
                        token
                    );
                }
            },
            ct
        );
        await Task.Delay(
            batch.Count == 0 ? TimeSpan.FromSeconds(2) : TimeSpan.FromMilliseconds(100),
            ct
        );
    }
}

static class OpenApiDocument
{
    public static object Build(string service) =>
        new
        {
            openapi = "3.1.0",
            info = new { title = $"Open Security Platform - {service}", version = "1.0.0" },
            servers = new[] { new { url = "/" } },
            paths = new Dictionary<string, object>
            {
                {
                    "/health/live",
                    new
                    {
                        get = new
                        {
                            operationId = "healthLive",
                            responses = new Dictionary<string, object>
                            {
                                { "200", new { description = "Healthy" } },
                            },
                        },
                    }
                },
                {
                    "/health/ready",
                    new
                    {
                        get = new
                        {
                            operationId = "healthReady",
                            responses = new Dictionary<string, object>
                            {
                                { "200", new { description = "Ready" } },
                                { "503", new { description = "Not ready" } },
                            },
                        },
                    }
                },
                {
                    "/api/v1/session",
                    new
                    {
                        get = new
                        {
                            operationId = "getSession",
                            security = new[]
                            {
                                new Dictionary<string, string[]>
                                {
                                    { "bearerAuth", Array.Empty<string>() },
                                },
                            },
                            responses = new Dictionary<string, object>
                            {
                                { "200", new { description = "Session" } },
                            },
                        },
                    }
                },
                {
                    "/api/v1/processes",
                    new { get = Operation("searchProcesses", "Tenant-scoped process search") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/processes/{entityId}",
                    new { get = Operation("getProcess", "Process execution details") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/processes/{entityId}/tree",
                    new { get = Operation("getProcessTree", "Bounded process lineage tree") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/process-timeline",
                    new { get = Operation("getProcessTimeline", "Endpoint process timeline") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/process-telemetry-health",
                    new
                    {
                        get = Operation(
                            "getProcessTelemetryHealth",
                            "Process telemetry loss and queue health"
                        ),
                    }
                },
                {
                    "/api/v1/processes:export",
                    new { get = Operation("exportProcesses", "Integrity-manifest JSONL export") }
                },
                {
                    "/api/v1/processes/projections:rebuild",
                    new
                    {
                        post = Operation(
                            "rebuildProcessProjection",
                            "Rebuild the process search projection"
                        ),
                    }
                },
                {
                    "/api/v1/network-events",
                    new { get = Operation("searchNetworkEvents", "Tenant-scoped bounded endpoint network evidence search") }
                },
                {
                    "/api/v1/network-events/{eventId}",
                    new { get = Operation("getNetworkEvent", "Native and normalized network event details") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/network-connections/{entityId}/history",
                    new { get = Operation("getNetworkConnectionHistory", "Bounded connection evidence history") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/network-timeline",
                    new { get = Operation("getEndpointNetworkTimeline", "Endpoint network evidence timeline") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/processes/{entityId}/network",
                    new { get = Operation("getProcessNetworkEvents", "Process-bound network evidence") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/network-listeners",
                    new { get = Operation("getNetworkListeners", "Observed endpoint listener entities") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/network-telemetry-health",
                    new { get = Operation("getNetworkTelemetryHealth", "Network source, loss, attribution, queue, and policy health") }
                },
                {
                    "/api/v1/network-events/projections:rebuild",
                    new { post = Operation("rebuildNetworkProjection", "Versioned network projection rebuild and alias switch") }
                },
                {
                    "/api/v1/network-exports",
                    new { post = Operation("createNetworkExport", "Create tenant-bound bounded asynchronous network export") }
                },
                {
                    "/api/v1/network-telemetry/policies",
                    new { get = Operation("listNetworkPolicies", "List immutable network policies"), post = Operation("createNetworkPolicy", "Create validated network policy version") }
                },
                {
                    "/api/v1/dns-events",
                    new { get = Operation("searchDnsEvents", "Tenant-scoped bounded DNS evidence search") }
                },
                {
                    "/api/v1/dns-events/{eventId}",
                    new { get = Operation("getDnsEvent", "Native and normalized DNS event details") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/dns-transactions/{transactionId}/history",
                    new { get = Operation("getDnsTransactionHistory", "Bounded DNS transaction evidence history") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/processes/{processId}/dns",
                    new { get = Operation("getProcessDnsEvents", "Process-attributed DNS evidence") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/dns-timeline",
                    new { get = Operation("getEndpointDnsTimeline", "Endpoint DNS evidence timeline") }
                },
                {
                    "/api/v1/endpoints/{endpointId}/dns-telemetry-health",
                    new { get = Operation("getDnsTelemetryHealth", "DNS source, loss, attribution, queue, and policy health") }
                },
                {
                    "/api/v1/dns-events:export",
                    new { get = Operation("exportDnsEvents", "Bounded DNS JSONL or CSV export with integrity hash") }
                },
                {
                    "/api/v1/dns-exports",
                    new { post = Operation("createDnsExport", "Create tenant-bound bounded asynchronous DNS export") }
                },
                {
                    "/api/v1/dns-exports/{id}",
                    new { get = Operation("getDnsExport", "Get tenant-bound DNS export status") }
                },
                {
                    "/api/v1/dns-telemetry/policies",
                    new { get = Operation("listDnsPolicies", "List immutable DNS policies"), post = Operation("createDnsPolicy", "Create validated DNS policy version") }
                },
            },
            components = new
            {
                securitySchemes = new
                {
                    bearerAuth = new
                    {
                        type = "http",
                        scheme = "bearer",
                        bearerFormat = "JWT",
                    },
                    apiKeyAuth = new
                    {
                        type = "apiKey",
                        @in = "header",
                        name = "Authorization",
                    },
                },
            },
        };

    private static object Operation(string operationId, string description) =>
        new
        {
            operationId,
            description,
            security = new[]
            {
                new Dictionary<string, string[]> { { "bearerAuth", Array.Empty<string>() } },
            },
            responses = new Dictionary<string, object>
            {
                { "200", new { description = "Success" } },
                { "400", new { description = "Invalid request" } },
                { "401", new { description = "Authentication required" } },
                { "403", new { description = "Permission denied" } },
            },
        };
}

sealed record FilePolicyCreateRequest(string Name, FileTelemetryPolicy Policy);
sealed record FileExclusionMutationRequest(string Category, string Pattern, bool Enabled = true);
sealed record FileExportDownloadRequest(int ExpiresInSeconds = 30);

sealed record FilePolicyAssignRequest(Guid? EndpointId);

sealed record FilePolicyRollbackRequest(int Version);
sealed record RegistryPolicyCreateRequest(string Name, RegistryTelemetryPolicy Policy);
sealed record RegistryPolicyAssignRequest(Guid? EndpointId);
sealed record RegistryPolicyRollbackRequest(int Version);
sealed record RegistryExclusionMutationRequest(
    string Category,
    string Pattern,
    bool Enabled = true,
    string Reason = ""
);
