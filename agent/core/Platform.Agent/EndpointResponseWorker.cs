using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Json;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenSecurityPlatform.Foundation;

sealed class EndpointResponseWorker(
    AgentOptions options,
    IAgentCredentialStore credentialStore,
    ILogger<EndpointResponseWorker> log
) : BackgroundService
{
    const int QueueCapacity = 32;
    const int Consumers = 2;
    readonly Channel<(AgentState State, SignedResponseActionEnvelope Action)> _queue =
        Channel.CreateBounded<(AgentState, SignedResponseActionEnvelope)>(new BoundedChannelOptions(QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = true,
        });
    readonly ConcurrentDictionary<Guid, byte> _scheduled = new();
    readonly ConcurrentDictionary<Guid, byte> _cancelRequested = new();
    readonly ConcurrentDictionary<Guid, CancellationTokenSource> _running = new();
    readonly ResponseReplayStore _replay = new(Path.Combine(options.DataDirectory, "response-replay.json"));
    readonly WindowsNetworkIsolation _isolation = new(options.DataDirectory);
    readonly WindowsProcessResponse _processResponse = new(options.DataDirectory);
    readonly WindowsFileQuarantine _fileQuarantine = new(options.DataDirectory);
    readonly WindowsPersistenceRemediation _persistenceRemediation = new(options.DataDirectory);
    readonly WindowsForensicCollector _forensicCollector = new(options.DataDirectory);

    public override void Dispose()
    {
        _replay.Dispose();
        _fileQuarantine.Dispose();
        _persistenceRemediation.Dispose();
        _forensicCollector.Dispose();
        base.Dispose();
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var consumers = Enumerable.Range(0, Consumers).Select(_ => Consume(ct)).ToArray();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var state = await credentialStore.LoadAsync(ct);
                if (state is null)
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), ct);
                    continue;
                }
                try
                {
                    using var client = Client(state);
                    client.DefaultRequestHeaders.Add("X-Agent-Installation-Id", state.InstallationId);
                    var envelope = await client.GetFromJsonAsync<ApiEnvelope<SignedResponseActionEnvelope[]>>(
                        "/agent/v1/response-actions", ct);
                    foreach (var action in envelope?.Data ?? [])
                    {
                        if (await _replay.ContainsCompletedAsync(action.ActionId, ct) ||
                            !_scheduled.TryAdd(action.ActionId, 0))
                            continue;
                        await _queue.Writer.WriteAsync((state, action), ct);
                    }
                    var cancellations = await client.GetFromJsonAsync<ApiEnvelope<ResponseCancellationInstruction[]>>(
                        "/agent/v1/response-actions/cancellations", ct);
                    foreach (var cancellation in cancellations?.Data ?? [])
                        await HandleCancellation(client, state, cancellation, ct);
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
                {
                    log.LogWarning("Response channel poll deferred: {Reason}", ex.Message);
                }
                await Task.Delay(TimeSpan.FromMilliseconds(250), ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        finally
        {
            _queue.Writer.TryComplete();
            await Task.WhenAll(consumers);
        }
    }

    async Task Consume(CancellationToken ct)
    {
        await foreach (var item in _queue.Reader.ReadAllAsync(ct))
        {
            try { await Execute(item.State, item.Action, ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            catch (Exception ex) { log.LogError(ex, "Safe response action {ActionId} failed", item.Action.ActionId); }
            finally { _scheduled.TryRemove(item.Action.ActionId, out _); }
        }
    }

    async Task Execute(AgentState state, SignedResponseActionEnvelope action, CancellationToken serviceToken)
    {
        Validate(state, action);
        if (!await _replay.TryStartAsync(action.ActionId, action.Nonce, action.ParameterHash, serviceToken))
            return;
        using var client = Client(state);
        client.DefaultRequestHeaders.Add("X-Agent-Installation-Id", state.InstallationId);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(serviceToken);
        _running[action.ActionId] = timeout;
        timeout.CancelAfter(TimeSpan.FromSeconds(action.TimeoutSeconds));
        try
        {
            if (_cancelRequested.ContainsKey(action.ActionId))
            {
                await Transition(client, action, ResponseActionState.Cancelled, "analyst cancellation acknowledged before execution", serviceToken);
                await _replay.CompleteAsync(action.ActionId, "cancelled-before-execution", serviceToken);
                return;
            }
            await Transition(client, action, ResponseActionState.Acknowledged, "authenticated action accepted", serviceToken);
            if (_cancelRequested.ContainsKey(action.ActionId))
            {
                await Transition(client, action, ResponseActionState.Cancelled, "analyst cancellation acknowledged before execution", serviceToken);
                await _replay.CompleteAsync(action.ActionId, "cancelled-before-execution", serviceToken);
                return;
            }
            await Transition(client, action, ResponseActionState.Running, "bounded safe executor started", serviceToken);
            var started = DateTimeOffset.UtcNow;
            ResponseExecution execution;
            try { execution = await RunSafeAction(state, action, timeout.Token); }
            catch (OperationCanceledException) when (!serviceToken.IsCancellationRequested && _cancelRequested.ContainsKey(action.ActionId))
            {
                execution = new(ResponseActionState.Cancelled, JsonSerializer.SerializeToElement(new { cancelled = true }), [], 0,
                    ResponseFailureCategory.None, "Analyst cancellation acknowledged.");
            }
            catch (OperationCanceledException) when (!serviceToken.IsCancellationRequested)
            {
                execution = new(ResponseActionState.Failed, JsonSerializer.SerializeToElement(new { timedOut = true }), [], 0,
                    ResponseFailureCategory.Timeout, "Local action deadline elapsed.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                var diagnostic = ex.Message.Replace('\r', ' ').Replace('\n', ' ');
                if (diagnostic.Length > 512) diagnostic = diagnostic[..512];
                execution = new(ResponseActionState.Failed,
                    JsonSerializer.SerializeToElement(new { error = ex.GetType().Name, diagnostic }), [], 0,
                    ResponseFailureCategory.Execution, "Safe action could not be completed.");
            }
            var completed = DateTimeOffset.UtcNow;
            var hash = Convert.ToHexString(SHA256.HashData(ResponseSafety.CanonicalJson(execution.Structured))).ToLowerInvariant();
            var result = new ResponseResult(action.ActionId, state.EndpointId, state.InstallationId,
                action.ActionType, action.ActionVersion, started, completed, execution.State, execution.State == ResponseActionState.Succeeded ? 0 : 1,
                execution.Structured, "not-captured", "not-captured", 0, 0, false, execution.Records, hash, [],
                execution.Failure, execution.FailureReason, ProductRelease.Version, Environment.UserName,
                IsElevated() ? "high" : "standard", action.ActionId.ToString("D"));
            var preparedArtifacts = await PrepareArtifacts(client, action.ActionId, execution.Artifacts, serviceToken);
            using var response = await PostResultWithRetry(client, action.ActionId,
                new ResponseAgentResultUpload(result, preparedArtifacts), serviceToken);
            response.EnsureSuccessStatusCode();
            await _replay.CompleteAsync(action.ActionId, hash, serviceToken);
            if (action.ActionType == ForensicCollectionSafety.ActionType) await _forensicCollector.CompleteAsync(action.ActionId);
            foreach (var artifact in execution.Artifacts.Where(x => x.LocalPath is not null))
                try { File.Delete(artifact.LocalPath!); } catch (IOException) { }
        }
        finally
        {
            _running.TryRemove(action.ActionId, out _);
            _cancelRequested.TryRemove(action.ActionId, out _);
        }
    }

    static async Task<ResponseArtifactUpload[]> PrepareArtifacts(HttpClient client, Guid actionId,
        ResponseArtifactUpload[] artifacts, CancellationToken ct)
    {
        var prepared = new List<ResponseArtifactUpload>(artifacts.Length);
        foreach (var artifact in artifacts)
        {
            if (artifact.LocalPath is null) { prepared.Add(artifact); continue; }
            var transferred = await ArtifactTransferClient.UploadFileAsync(client, "response-action", actionId,
                artifact.ArtifactId, artifact.LocalPath, artifact.Name, artifact.MediaType, null, ct);
            if (!string.Equals(transferred.Sha256, artifact.Sha256, StringComparison.OrdinalIgnoreCase) ||
                transferred.Status.Size != artifact.Size) throw new InvalidDataException("Prepared artifact transfer does not match acquired evidence.");
            prepared.Add(artifact with { ContentBase64 = null, TransferId = transferred.Status.TransferId, LocalPath = null });
        }
        return prepared.ToArray();
    }

    static async Task<HttpResponseMessage> PostResultWithRetry(HttpClient client, Guid actionId,
        ResponseAgentResultUpload upload, CancellationToken ct)
    {
        Exception? lastFailure = null;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            try
            {
                var response = await client.PostAsJsonAsync($"/agent/v1/response-actions/{actionId:D}:result", upload, ct);
                if (response.IsSuccessStatusCode || (int)response.StatusCode < 500) return response;
                lastFailure = new HttpRequestException($"Result upload returned HTTP {(int)response.StatusCode}.");
                response.Dispose();
            }
            catch (Exception ex) when ((ex is HttpRequestException or TaskCanceledException) && !ct.IsCancellationRequested)
            {
                lastFailure = ex;
            }
            if (attempt < 3) await Task.Delay(TimeSpan.FromSeconds(attempt + 1), ct);
        }
        throw new HttpRequestException("Response result upload did not recover within its bounded retry window.", lastFailure);
    }

    async Task HandleCancellation(HttpClient client, AgentState state, ResponseCancellationInstruction cancellation, CancellationToken ct)
    {
        if (cancellation.TenantId != state.TenantId || cancellation.EndpointId != state.EndpointId ||
            cancellation.AgentId != state.AgentId || cancellation.AgentInstallationId != state.InstallationId)
            throw new InvalidDataException("Response cancellation binding is invalid.");
        _cancelRequested[cancellation.ActionId] = 0;
        if (_running.TryGetValue(cancellation.ActionId, out var running)) { running.Cancel(); return; }
        if (_scheduled.ContainsKey(cancellation.ActionId)) return;
        using var response = await client.PostAsJsonAsync($"/agent/v1/response-actions/{cancellation.ActionId:D}:transition",
            new ResponseAgentTransition(cancellation.ActionId, cancellation.AgentInstallationId, cancellation.Nonce,
                cancellation.ParameterHash, ResponseActionState.Cancelled, DateTimeOffset.UtcNow,
                "analyst cancellation acknowledged after reconnect"), ct);
        response.EnsureSuccessStatusCode();
        _cancelRequested.TryRemove(cancellation.ActionId, out _);
    }

    static void Validate(AgentState state, SignedResponseActionEnvelope action)
    {
        if (!string.Equals(action.TenantId, state.TenantId, StringComparison.Ordinal) ||
            action.EndpointId != state.EndpointId || action.AgentId != state.AgentId ||
            action.AgentInstallationId != state.InstallationId || action.ExpiresAt <= DateTimeOffset.UtcNow ||
            action.IssuedAt > DateTimeOffset.UtcNow.AddMinutes(2))
            throw new InvalidDataException("Response action binding or lifetime is invalid.");
        var definition = ResponseSafety.GetDefinition(action.ActionType, action.ActionVersion);
        var platform = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsLinux() ? "linux" : "macos";
        if (!definition.SupportedPlatforms.Contains(platform, StringComparer.OrdinalIgnoreCase))
            throw new PlatformNotSupportedException("Action is not allowed on this platform.");
        ResponseSafety.ValidateParameters(definition, action.Parameters);
        if (!ResponseSafety.VerifyEnvelope(action, state.CaCertificatePem))
            throw new CryptographicException("Response action signature is invalid.");
    }

    static async Task Transition(HttpClient client, SignedResponseActionEnvelope action,
        ResponseActionState state, string reason, CancellationToken ct)
    {
        using var response = await client.PostAsJsonAsync($"/agent/v1/response-actions/{action.ActionId:D}:transition",
            new ResponseAgentTransition(action.ActionId, action.AgentInstallationId, action.Nonce,
                action.ParameterHash, state, DateTimeOffset.UtcNow, reason), ct);
        response.EnsureSuccessStatusCode();
    }

    async Task<ResponseExecution> RunSafeAction(AgentState state, SignedResponseActionEnvelope action, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return action.ActionType switch
        {
            "endpoint.status" => Status(action),
            "process.list" => Processes(state.EndpointId, action.Parameters),
            "network.connections" => Connections(action.Parameters),
            "service.status" => OperatingSystem.IsWindows() ? Service(action.Parameters) : throw new PlatformNotSupportedException(),
            "file.metadata" => await FileMetadata(action.Parameters, ct),
            "collect.diagnostic" => Diagnostic(),
            "endpoint.isolate" => Isolation(await _isolation.IsolateAsync(state, action, ct)),
            "endpoint.unisolate" => Isolation(await _isolation.UnisolateAsync(state, action, ct)),
            "endpoint.isolation_status" => Isolation(await _isolation.StatusAsync(state, action, ct)),
            "process.terminate" or "process.suspend" or "process.resume" or "process_tree.terminate" or "process.response_status" => ProcessAction(await _processResponse.ExecuteAsync(action.ActionType, action.Parameters, ct)),
            "file.quarantine" or "file.restore" or "file.delete" or "file.quarantine_status" or "file.quarantine_metadata" => FileAction(await _fileQuarantine.ExecuteAsync(state, action, ct)),
            "registry.value.remove" or "registry.value.restore" or "registry.key.remove" or "registry.remediation_status" or
            "service.stop" or "service.disable" or "service.delete" or "service.restore" or
            "scheduled_task.disable" or "scheduled_task.delete" or "scheduled_task.restore" or
            "wmi.binding.remove" or "wmi.consumer.remove" or "wmi.filter.remove" or "wmi.persistence.restore" or
            "persistence.remove" or "persistence.restore" or "persistence.remediation_status" => PersistenceAction(await _persistenceRemediation.ExecuteAsync(state, action, ct)),
            ForensicCollectionSafety.ActionType => ForensicAction(await _forensicCollector.ExecuteAsync(state, action, ct)),
            _ => throw new InvalidOperationException("Action is outside the compiled allowlist."),
        };
    }

    static ResponseExecution Isolation(EndpointIsolationSnapshot snapshot)
    {
        var succeeded = snapshot.EffectiveState is EndpointIsolationState.Isolated or EndpointIsolationState.NotIsolated;
        return new(succeeded ? ResponseActionState.Succeeded : ResponseActionState.Failed,
            JsonSerializer.SerializeToElement(snapshot), [], 1,
            succeeded ? ResponseFailureCategory.None : ResponseFailureCategory.Execution, snapshot.FailureReason);
    }

    static ResponseExecution ProcessAction(WindowsProcessResponse.ProcessExecution result) =>
        new(result.State, result.Structured, [], result.Records, result.Failure, result.FailureReason);

    static ResponseExecution FileAction(WindowsFileQuarantine.Execution result) =>
        new(result.State, result.Structured, result.Artifacts, result.Records, result.Failure, result.FailureReason);

    static ResponseExecution PersistenceAction(WindowsPersistenceRemediation.Execution result) =>
        new(result.State, result.Structured, result.Artifacts, result.Records, result.Failure, result.FailureReason);

    static ResponseExecution ForensicAction(WindowsForensicCollector.Execution result) =>
        new(result.State, result.Structured, result.Artifacts, result.Records, result.Failure, result.FailureReason);

    ResponseExecution Status(SignedResponseActionEnvelope action)
    {
        var value = JsonSerializer.SerializeToElement(new
        {
            machine = Environment.MachineName,
            platform = OperatingSystem.IsWindows() ? "windows" : "linux",
            architecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(),
            agentVersion = ProductRelease.Version,
            processId = Environment.ProcessId,
            uptimeSeconds = Environment.TickCount64 / 1000,
            elevated = IsElevated(),
            responseQueueCapacity = QueueCapacity,
            responseQueueDepth = _scheduled.Count,
            responseWorkers = Consumers,
            activePolicyVersions = new { response = action.PolicyVersion, telemetry = "independent-heartbeat" },
            timestamp = DateTimeOffset.UtcNow,
        });
        return new(ResponseActionState.Succeeded, value, [], 1, ResponseFailureCategory.None, null);
    }

    static ResponseExecution Processes(Guid endpointId, JsonElement parameters)
    {
        var maximum = parameters.TryGetProperty("maximumRecords", out var m) ? m.GetInt32() : 100;
        var records = Process.GetProcesses().OrderBy(x => x.Id).Take(maximum).Select(x =>
        {
            try
            {
                DateTimeOffset? started = null; string? image = null; int? session = null;
                try { started = new DateTimeOffset(x.StartTime.ToUniversalTime()); } catch { }
                try { image = x.MainModule?.FileName; } catch { }
                try { session = x.SessionId; } catch { }
                var entity = started is null ? null : ProcessIdentity.Create(endpointId, x.Id, started.Value, $"response:{started.Value.UtcTicks}");
                return (object)new
                {
                    pid = x.Id,
                    processEntityId = entity,
                    name = x.ProcessName,
                    image,
                    startTime = started,
                    user = (string?)null,
                    sessionId = session,
                    accessible = true
                };
            }
            catch
            {
                return (object)new
                {
                    pid = x.Id,
                    processEntityId = (string?)null,
                    name = "unavailable",
                    image = (string?)null,
                    startTime = (DateTimeOffset?)null,
                    user = (string?)null,
                    sessionId = (int?)null,
                    accessible = false
                };
            }
            finally { x.Dispose(); }
        }).ToArray();
        return new(ResponseActionState.Succeeded, JsonSerializer.SerializeToElement(new { processes = records }), [], records.Length, ResponseFailureCategory.None, null);
    }

    static ResponseExecution Connections(JsonElement parameters)
    {
        var maximum = parameters.TryGetProperty("maximumRecords", out var m) ? m.GetInt32() : 100;
        var protocol = parameters.TryGetProperty("protocol", out var p) ? p.GetString()! : "all";
        var values = new List<object>(maximum);
        var properties = IPGlobalProperties.GetIPGlobalProperties();
        if (protocol is "all" or "tcp")
            values.AddRange(properties.GetActiveTcpConnections().Take(maximum).Select(x => (object)new
            { protocol = "tcp", local = x.LocalEndPoint.ToString(), remote = x.RemoteEndPoint.ToString(), state = x.State.ToString() }));
        if (values.Count < maximum && protocol is ("all" or "udp"))
            values.AddRange(properties.GetActiveUdpListeners().Take(maximum - values.Count).Select(x => (object)new
            { protocol = "udp", local = x.ToString(), remote = (string?)null, state = "listening" }));
        return new(ResponseActionState.Succeeded, JsonSerializer.SerializeToElement(new { connections = values }), [], values.Count, ResponseFailureCategory.None, null);
    }

    [SupportedOSPlatform("windows")]
    static ResponseExecution Service(JsonElement parameters)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var name = parameters.GetProperty("serviceName").GetString()!;
        using var searcher = new System.Management.ManagementObjectSearcher(
            $"SELECT Name,DisplayName,State,StartMode,ProcessId FROM Win32_Service WHERE Name='{name.Replace("'", "''", StringComparison.Ordinal)}'");
        var values = searcher.Get().Cast<System.Management.ManagementObject>().Take(1).Select(x => new
        { name = x["Name"]?.ToString(), displayName = x["DisplayName"]?.ToString(), state = x["State"]?.ToString(), startMode = x["StartMode"]?.ToString(), processId = x["ProcessId"]?.ToString() }).ToArray();
        return new(ResponseActionState.Succeeded, JsonSerializer.SerializeToElement(new { services = values }), [], values.Length, ResponseFailureCategory.None, null);
    }

    async Task<ResponseExecution> FileMetadata(JsonElement parameters, CancellationToken ct)
    {
        var requested = Path.GetFullPath(parameters.GetProperty("path").GetString()!);
        var root = Path.GetFullPath(options.DataDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!requested.StartsWith(root, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new UnauthorizedAccessException("File query is outside the platform data root.");
        var info = new FileInfo(requested);
        var nativeIdentity = info.Exists && OperatingSystem.IsWindows() ? WindowsFileIdentity(requested) : null;
        string? hash = null;
        var hashState = "not-requested";
        if (info.Exists && parameters.TryGetProperty("includeHash", out var include) && include.GetBoolean())
        {
            var maximum = parameters.TryGetProperty("maximumHashBytes", out var m) ? m.GetInt32() : 1024 * 1024;
            if (info.Length > maximum) throw new InvalidOperationException("File exceeds the bounded hash policy.");
            var beforeLength = info.Length; var beforeWrite = info.LastWriteTimeUtc; var beforeIdentity = nativeIdentity;
            await using var stream = new FileStream(requested, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).ToLowerInvariant();
            info.Refresh(); var afterIdentity = OperatingSystem.IsWindows() ? WindowsFileIdentity(requested) : null;
            if (!info.Exists || info.Length != beforeLength || info.LastWriteTimeUtc != beforeWrite || beforeIdentity != afterIdentity)
                throw new InvalidOperationException("File changed or was replaced during the bounded hash operation.");
            nativeIdentity = afterIdentity; hashState = "succeeded-race-safe";
        }
        var value = JsonSerializer.SerializeToElement(new
        {
            path = requested,
            exists = info.Exists,
            size = info.Exists ? info.Length : 0,
            creationTimeUtc = info.Exists ? info.CreationTimeUtc : (DateTime?)null,
            lastAccessTimeUtc = info.Exists ? info.LastAccessTimeUtc : (DateTime?)null,
            lastWriteTimeUtc = info.Exists ? info.LastWriteTimeUtc : (DateTime?)null,
            nativeIdentity,
            sha256 = hash,
            hashState
        });
        return new(ResponseActionState.Succeeded, value, [], 1, ResponseFailureCategory.None, null);
    }

    [SupportedOSPlatform("windows")]
    static string? WindowsFileIdentity(string path)
    {
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (!GetFileInformationByHandle(handle, out var value)) return null;
            var fileId = ((ulong)value.FileIndexHigh << 32) | value.FileIndexLow;
            return $"{value.VolumeSerialNumber.ToString("x8", CultureInfo.InvariantCulture)}:{fileId.ToString("x16", CultureInfo.InvariantCulture)}";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException) { return null; }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle, out ByHandleFileInformation information);

    ResponseExecution Diagnostic()
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = "platform-diagnostic.v1",
            generatedAt = DateTimeOffset.UtcNow,
            machine = Environment.MachineName,
            agentVersion = ProductRelease.Version,
            response = new { queueCapacity = QueueCapacity, workers = Consumers },
            dataDirectoryAccessible = Directory.Exists(options.DataDirectory)
        });
        var id = Guid.NewGuid();
        var artifact = new ResponseArtifactUpload(id, "platform-diagnostic.json", "application/json",
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), Convert.ToBase64String(bytes));
        return new(ResponseActionState.Succeeded, JsonSerializer.SerializeToElement(new { artifactId = id, size = bytes.Length }), [artifact], 1, ResponseFailureCategory.None, null);
    }

    HttpClient Client(AgentState state)
    {
        var handler = new HttpClientHandler();
        handler.ClientCertificates.Add(new X509Certificate2(Convert.FromBase64String(state.ClientCertificatePfx),
            (string?)null, X509KeyStorageFlags.MachineKeySet));
        if (options.ControlPlaneUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            var root = X509Certificate2.CreateFromPem(state.CaCertificatePem);
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
            {
                if (certificate is null) return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(root);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(new X509Certificate2(certificate));
            };
        }
        return new HttpClient(handler) { BaseAddress = new Uri(options.ControlPlaneUrl), Timeout = TimeSpan.FromSeconds(20) };
    }

    static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return string.Equals(Environment.UserName, "root", StringComparison.Ordinal);
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    sealed record ResponseExecution(ResponseActionState State, JsonElement Structured,
        ResponseArtifactUpload[] Artifacts, int Records, ResponseFailureCategory Failure, string? FailureReason);
}

sealed class ResponseReplayStore(string path) : IDisposable
{
    const long MaximumReplayBytes = 4 * 1024 * 1024;
    readonly SemaphoreSlim _gate = new(1, 1);
    Dictionary<Guid, ReplayEntry>? _entries;

    public async Task<bool> ContainsCompletedAsync(Guid id, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try { await Load(ct); return _entries!.TryGetValue(id, out var x) && x.Completed; }
        finally { _gate.Release(); }
    }

    public async Task<bool> TryStartAsync(Guid id, string nonce, string parameterHash, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await Load(ct);
            if (_entries!.TryGetValue(id, out var existing) &&
                (existing.Completed || existing.Nonce != nonce || existing.ParameterHash != parameterHash)) return false;
            _entries[id] = new(nonce, parameterHash, false, null, DateTimeOffset.UtcNow);
            await Save(ct); return true;
        }
        finally { _gate.Release(); }
    }

    public async Task CompleteAsync(Guid id, string resultHash, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await Load(ct);
            if (_entries!.TryGetValue(id, out var existing)) _entries[id] = existing with { Completed = true, ResultHash = resultHash };
            if (_entries.Count > 4096)
                _entries = _entries.OrderByDescending(x => x.Value.UpdatedAt).Take(4096).ToDictionary(x => x.Key, x => x.Value);
            await Save(ct);
        }
        finally { _gate.Release(); }
    }

    async Task Load(CancellationToken ct)
    {
        if (_entries is not null) return;
        var backup = path + ".bak";
        if (!File.Exists(path) && !File.Exists(backup)) { _entries = []; return; }
        Exception? failure = null;
        foreach (var candidate in new[] { path, backup })
        {
            if (!File.Exists(candidate)) continue;
            try
            {
                var info = new FileInfo(candidate);
                if (info.Length is <= 0 or > MaximumReplayBytes) throw new InvalidDataException("Replay state size is invalid.");
                _entries = JsonSerializer.Deserialize<Dictionary<Guid, ReplayEntry>>(
                    await File.ReadAllTextAsync(candidate, ct)) ?? throw new InvalidDataException("Replay state is empty.");
                return;
            }
            catch (Exception ex) when (ex is IOException or JsonException or InvalidDataException)
            {
                failure = ex;
            }
        }
        throw new InvalidDataException("Response replay state and its recovery copy are unreadable; response execution is disabled.", failure);
    }

    async Task Save(CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + ".tmp";
        var bytes = JsonSerializer.SerializeToUtf8Bytes(_entries);
        if (bytes.Length > MaximumReplayBytes) throw new InvalidDataException("Response replay state exceeds its storage bound.");
        await using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None, 4096,
            FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            await stream.WriteAsync(bytes, ct);
            await stream.FlushAsync(ct);
            stream.Flush(true);
        }
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        if (File.Exists(path)) File.Replace(temporary, path, path + ".bak", true);
        else File.Move(temporary, path);
    }

    public void Dispose()
    {
        _gate.Dispose();
        GC.SuppressFinalize(this);
    }

    sealed record ReplayEntry(string Nonce, string ParameterHash, bool Completed, string? ResultHash, DateTimeOffset UpdatedAt);
}

static class EndpointResponseWorkerSelfTest
{
    static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

    public static async Task<int> RunAsync(string dataDirectory, string? output)
    {
        var root = Path.GetFullPath(Path.Combine(dataDirectory, "response-worker-self-test"));
        Directory.CreateDirectory(root);
        var replayPath = Path.Combine(root, "replay.json");
        foreach (var candidate in new[] { replayPath, replayPath + ".bak", replayPath + ".tmp" }) File.Delete(candidate);
        var id = Guid.NewGuid();
        bool first;
        bool duplicate;
        using (var replay = new ResponseReplayStore(replayPath))
        {
            first = await replay.TryStartAsync(id, "nonce", "hash", default);
            await replay.CompleteAsync(id, "result", default);
            duplicate = await replay.TryStartAsync(id, "nonce", "hash", default);
            await replay.TryStartAsync(Guid.NewGuid(), "second-nonce", "second-hash", default);
        }
        await File.WriteAllBytesAsync(replayPath, [0, 0, 0, 0]);
        using var recoveredReplay = new ResponseReplayStore(replayPath);
        var recovered = await recoveredReplay.ContainsCompletedAsync(id, default);
        var report = new
        {
            schemaVersion = "response-worker-self-test.v1",
            platform = Environment.OSVersion.ToString(),
            architecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
            elevated = IsElevated(),
            safeActions = ResponseSafety.Definitions.Keys.Order().ToArray(),
            noShellExecutor = true,
            queueCapacity = 32,
            workers = 2,
            durableReplayFirstAccepted = first,
            durableReplayDuplicateRejected = !duplicate,
            crashRecoveryCopyAccepted = recovered,
            result = first && !duplicate && recovered ? "PASS" : "FAIL",
            timestamp = DateTimeOffset.UtcNow
        };
        var json = JsonSerializer.Serialize(report, IndentedJson);
        if (!string.IsNullOrWhiteSpace(output)) await File.WriteAllTextAsync(output, json);
        Console.WriteLine(json);
        return first && !duplicate && recovered ? 0 : 1;
    }

    static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return Environment.UserName == "root";
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}
