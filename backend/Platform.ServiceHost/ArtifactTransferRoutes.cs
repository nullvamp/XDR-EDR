using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

sealed class ArtifactTransferStore
{
    readonly string _root;
    readonly IObjectStorage _objects;
    readonly IArtifactTransferStateRepository _states;
    readonly ConcurrentDictionary<Guid, SemaphoreSlim> _locks = new();
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public ArtifactTransferStore(PlatformOptions options, IObjectStorage objects, IArtifactTransferStateRepository states)
    {
        _root = Path.Combine(options.DataDirectory, "artifact-transfers");
        Directory.CreateDirectory(_root);
        _objects = objects;
        _states = states;
    }

    public async Task<ArtifactTransferStatus> StartAsync(string tenant, Guid endpoint, Guid agent, string installation,
        ArtifactTransferStart start, CancellationToken ct)
    {
        ArtifactTransferSafety.Validate(start);
        var gate = _locks.GetOrAdd(start.TransferId, _ => new(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var existing = await _states.GetAsync(start.TransferId, ct);
            if (existing is not null)
            {
                Bind(existing, tenant, endpoint, agent, installation, start);
                if (existing.State == ArtifactTransferState.Verifying && existing.ObjectId is null)
                {
                    var resumed = existing with { State = ArtifactTransferState.Receiving, FailureReason = null, UpdatedAt = DateTimeOffset.UtcNow, Version = existing.Version + 1 };
                    if (await _states.CompareExchangeAsync(resumed, existing.Version, ct)) existing = resumed;
                    else existing = await _states.GetAsync(start.TransferId, ct) ?? throw new InvalidOperationException("Transfer disappeared during recovery.");
                }
                return Status(existing);
            }
            var active = await _states.CountActiveAsync(tenant, endpoint, ct);
            if (active >= ArtifactTransferSafety.MaximumConcurrentTransfersPerEndpoint)
                throw new EnrollmentConflictException("ARTIFACT_TRANSFER_CONCURRENCY", "The endpoint already has the maximum number of active transfers.");
            var now = DateTimeOffset.UtcNow;
            var value = new ArtifactTransferRecord(tenant, endpoint, agent, installation, start, ArtifactTransferState.Receiving,
                0, 0, [], null, null, now, now, 1);
            Directory.CreateDirectory(TransferRoot(start.TransferId));
            if (await _states.CreateAsync(value, ct)) return Status(value);
            var raced = await _states.GetAsync(start.TransferId, ct) ?? throw new InvalidOperationException("Transfer creation race lost without shared state.");
            Bind(raced, tenant, endpoint, agent, installation, start); return Status(raced);
        }
        finally { gate.Release(); }
    }

    public async Task<ArtifactChunkAcknowledgement> PutChunkAsync(string tenant, Guid endpoint, Guid agent, string installation,
        Guid transferId, int index, Stream content, long contentLength, string expectedHash, CancellationToken ct)
    {
        var gate = _locks.GetOrAdd(transferId, _ => new(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var value = await Required(transferId, ct); Bind(value, tenant, endpoint, agent, installation);
            if (value.State != ArtifactTransferState.Receiving) throw new EnrollmentConflictException("ARTIFACT_TRANSFER_STATE", "Transfer is not receiving chunks.");
            var remaining = value.Start.Size - value.ReceivedBytes;
            var required = index < value.ReceivedChunks ? Math.Min(value.Start.ChunkSize, value.Start.Size - (long)index * value.Start.ChunkSize) : Math.Min(value.Start.ChunkSize, remaining);
            if (contentLength != required || expectedHash.Length != 64 || !expectedHash.All(Uri.IsHexDigit))
                throw new EnrollmentConflictException("ARTIFACT_CHUNK_BOUNDS", "Chunk length or digest is invalid.");
            if (index < value.ReceivedChunks)
            {
                await using var existingChunk = new FileStream(ChunkPath(transferId, index), FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, true);
                var actual = Convert.ToHexString(await SHA256.HashDataAsync(existingChunk, ct)).ToLowerInvariant();
                if (existingChunk.Length != required || !string.Equals(actual, expectedHash, StringComparison.OrdinalIgnoreCase))
                    throw new EnrollmentConflictException("ARTIFACT_CHUNK_REPLAY", "Acknowledged chunk replay does not match stored content.");
                return new(transferId, index, value.ReceivedBytes, value.ReceivedChunks, actual);
            }
            if (index != value.ReceivedChunks) throw new EnrollmentConflictException("ARTIFACT_CHUNK_ORDER", "Chunk index does not match the resumable acknowledgement cursor.");
            var target = ChunkPath(transferId, index); var temporary = target + ".upload";
            try
            {
                await using var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    128 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[128 * 1024]; long written = 0;
                while (written < required)
                {
                    var read = await content.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, required - written)), ct);
                    if (read == 0) throw new EndOfStreamException("Artifact chunk ended early.");
                    await output.WriteAsync(buffer.AsMemory(0, read), ct); hash.AppendData(buffer, 0, read); written += read;
                }
                await output.FlushAsync(ct); output.Flush(true);
                var actual = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
                if (!CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(actual), System.Text.Encoding.ASCII.GetBytes(expectedHash.ToLowerInvariant())))
                    throw new CryptographicException("Artifact chunk hash verification failed.");
                File.Move(temporary, target, false);
                var updated = value with
                {
                    ReceivedBytes = value.ReceivedBytes + written,
                    ReceivedChunks = value.ReceivedChunks + 1,
                    ChunkHashes = value.ChunkHashes.Append(actual).ToArray(),
                    UpdatedAt = DateTimeOffset.UtcNow,
                    Version = value.Version + 1
                };
                HighAvailabilitySafety.ValidateTransferAdvance(value, updated);
                if (!await _states.CompareExchangeAsync(updated, value.Version, ct))
                {
                    var winner = await Required(transferId, ct);
                    if (winner.ReceivedChunks <= index || winner.ChunkHashes.Count <= index || !string.Equals(winner.ChunkHashes[index], actual, StringComparison.OrdinalIgnoreCase))
                        throw new EnrollmentConflictException("ARTIFACT_TRANSFER_FENCED", "Another gateway advanced this transfer with conflicting state.");
                    return new(transferId, index, winner.ReceivedBytes, winner.ReceivedChunks, actual);
                }
                return new(transferId, index, updated.ReceivedBytes, updated.ReceivedChunks, actual);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        finally { gate.Release(); }
    }

    public async Task<ArtifactTransferStatus> CompleteAsync(string tenant, Guid endpoint, Guid agent, string installation,
        ArtifactTransferCompletion completion, CancellationToken ct)
    {
        var gate = _locks.GetOrAdd(completion.TransferId, _ => new(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var value = await Required(completion.TransferId, ct); Bind(value, tenant, endpoint, agent, installation);
            if (value.State == ArtifactTransferState.Completed) return Status(value);
            if (value.State != ArtifactTransferState.Receiving || completion.Size != value.Start.Size ||
                !string.Equals(completion.Sha256, value.Start.Sha256, StringComparison.OrdinalIgnoreCase) || value.ReceivedBytes != value.Start.Size)
                throw new EnrollmentConflictException("ARTIFACT_TRANSFER_INCOMPLETE", "Transfer cannot complete before every bound byte is acknowledged.");
            var claimed = value with { State = ArtifactTransferState.Verifying, UpdatedAt = DateTimeOffset.UtcNow, Version = value.Version + 1 };
            HighAvailabilitySafety.ValidateTransferAdvance(value, claimed);
            if (!await _states.CompareExchangeAsync(claimed, value.Version, ct)) throw new EnrollmentConflictException("ARTIFACT_TRANSFER_FENCED", "Another gateway owns transfer finalization.");
            value = claimed;
            var assembled = Path.Combine(TransferRoot(completion.TransferId), "assembled.bin");
            try
            {
                await using (var output = new FileStream(assembled, FileMode.Create, FileAccess.ReadWrite, FileShare.None, 256 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan))
                {
                    for (var i = 0; i < value.ReceivedChunks; i++)
                        await using (var input = new FileStream(ChunkPath(completion.TransferId, i), FileMode.Open, FileAccess.Read, FileShare.Read, 256 * 1024, true))
                            await input.CopyToAsync(output, 256 * 1024, ct);
                    output.Position = 0;
                    var actual = Convert.ToHexString(await SHA256.HashDataAsync(output, ct)).ToLowerInvariant();
                    if (!CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(actual), System.Text.Encoding.ASCII.GetBytes(value.Start.Sha256.ToLowerInvariant())))
                        throw new CryptographicException("Final artifact hash verification failed.");
                    output.Position = 0; var objectId = Guid.NewGuid().ToString("D");
                    await _objects.UploadAsync(tenant, objectId, output, value.Start.MediaType, actual, ct);
                    var completed = value with { State = ArtifactTransferState.Completed, ObjectId = objectId, UpdatedAt = DateTimeOffset.UtcNow, Version = value.Version + 1 };
                    HighAvailabilitySafety.ValidateTransferAdvance(value, completed);
                    if (!await _states.CompareExchangeAsync(completed, value.Version, ct)) throw new EnrollmentConflictException("ARTIFACT_TRANSFER_FENCED", "Transfer finalization ownership was lost.");
                    value = completed;
                }
                foreach (var file in Directory.EnumerateFiles(TransferRoot(completion.TransferId), "*.chunk")) File.Delete(file);
                return Status(value);
            }
            catch (Exception ex) when (ex is IOException or CryptographicException or InvalidOperationException)
            {
                var failed = value with { State = ArtifactTransferState.Failed, FailureReason = ex.GetType().Name, UpdatedAt = DateTimeOffset.UtcNow, Version = value.Version + 1 };
                HighAvailabilitySafety.ValidateTransferAdvance(value, failed);
                await _states.CompareExchangeAsync(failed, value.Version, CancellationToken.None); throw;
            }
            finally { if (File.Exists(assembled)) File.Delete(assembled); }
        }
        finally { gate.Release(); }
    }

    public async Task<ArtifactTransferStatus?> GetAsync(string tenant, Guid transferId, CancellationToken ct)
    { var value = await _states.GetAsync(transferId, ct); return value is not null && value.TenantId == tenant ? Status(value) : null; }

    public async Task<ArtifactTransferStatus> AgentStatusAsync(string tenant, Guid endpoint, Guid agent, string installation, Guid transferId, CancellationToken ct)
    { var value = await Required(transferId, ct); Bind(value, tenant, endpoint, agent, installation); return Status(value); }

    public async Task<IReadOnlyList<ArtifactTransferStatus>> OwnerAsync(string tenant, Guid owner, CancellationToken ct)
    {
        return (await _states.ListOwnerAsync(tenant, owner, ct)).Select(Status).OrderBy(x => x.CreatedAt).ToArray();
    }

    public async Task<(ArtifactTransferStatus Status, Stream Content)?> DownloadAsync(string tenant, Guid transferId, CancellationToken ct)
    {
        var value = await _states.GetAsync(transferId, ct);
        if (value is null || value.TenantId != tenant || value.State != ArtifactTransferState.Completed || value.ObjectId is null) return null;
        return (Status(value), await _objects.DownloadAsync(tenant, value.ObjectId, ct));
    }

    static ArtifactTransferStatus Status(ArtifactTransferRecord x) => new(ArtifactTransferSafety.SchemaVersion, x.Start.TransferId,
        x.Start.OwnerType, x.Start.OwnerId, x.Start.ArtifactId, x.State, x.Start.Size, x.ReceivedBytes, x.Start.ChunkSize,
        x.ReceivedChunks, x.Start.Size == 0 ? 0 : (int)((x.Start.Size + x.Start.ChunkSize - 1) / x.Start.ChunkSize),
        x.Start.Sha256, x.ObjectId, x.FailureReason, x.CreatedAt, x.UpdatedAt);
    static void Bind(ArtifactTransferRecord x, string tenant, Guid endpoint, Guid agent, string installation, ArtifactTransferStart? start = null)
    {
        if (x.TenantId != tenant || x.EndpointId != endpoint || x.AgentId != agent || x.InstallationId != installation ||
            start is not null && x.Start != start) throw new EnrollmentConflictException("ARTIFACT_TRANSFER_BINDING", "Transfer identity binding is invalid.");
    }
    async Task<ArtifactTransferRecord> Required(Guid id, CancellationToken ct) => await _states.GetAsync(id, ct) ?? throw new KeyNotFoundException("Artifact transfer does not exist.");
    string TransferRoot(Guid id) => Path.Combine(_root, id.ToString("D"));
    string ChunkPath(Guid id, int index) => Path.Combine(TransferRoot(id), index.ToString("D8", System.Globalization.CultureInfo.InvariantCulture) + ".chunk");
}

sealed class FileArtifactTransferStateRepository : IArtifactTransferStateRepository, IDisposable
{
    readonly string root; readonly SemaphoreSlim gate = new(1, 1); static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public FileArtifactTransferStateRepository(PlatformOptions o) { root = Path.Combine(o.DataDirectory, "artifact-transfer-state"); Directory.CreateDirectory(root); }
    string PathOf(Guid id) => Path.Combine(root, id.ToString("D") + ".json");
    public async Task<ArtifactTransferRecord?> GetAsync(Guid id, CancellationToken ct) { var p = PathOf(id); return File.Exists(p) ? JsonSerializer.Deserialize<ArtifactTransferRecord>(await File.ReadAllTextAsync(p, ct), Json) : null; }
    public async Task<bool> CreateAsync(ArtifactTransferRecord x, CancellationToken ct) { await gate.WaitAsync(ct); try { if (File.Exists(PathOf(x.Start.TransferId))) return false; await Save(x, ct); return true; } finally { gate.Release(); } }
    public async Task<bool> CompareExchangeAsync(ArtifactTransferRecord x, long expected, CancellationToken ct) { await gate.WaitAsync(ct); try { var old = await GetAsync(x.Start.TransferId, ct); if (old?.Version != expected) return false; await Save(x, ct); return true; } finally { gate.Release(); } }
    public async Task<int> CountActiveAsync(string t, Guid e, CancellationToken ct) => (await ListAsync(ct)).Count(x => x.TenantId == t && x.EndpointId == e && x.State is ArtifactTransferState.Receiving or ArtifactTransferState.Verifying);
    public async Task<IReadOnlyList<ArtifactTransferRecord>> ListOwnerAsync(string t, Guid o, CancellationToken ct) => (await ListAsync(ct)).Where(x => x.TenantId == t && x.Start.OwnerId == o).ToArray();
    public async Task<IReadOnlyList<ArtifactTransferRecord>> ListAsync(CancellationToken ct) { var x = new List<ArtifactTransferRecord>(); foreach (var p in Directory.EnumerateFiles(root, "*.json")) try { if (JsonSerializer.Deserialize<ArtifactTransferRecord>(await File.ReadAllTextAsync(p, ct), Json) is { } v) x.Add(v); } catch (JsonException) { } return x; }
    async Task Save(ArtifactTransferRecord x, CancellationToken ct) { var p = PathOf(x.Start.TransferId); var tmp = p + ".tmp"; await File.WriteAllTextAsync(tmp, JsonSerializer.Serialize(x, Json), ct); File.Move(tmp, p, true); }
    public void Dispose() { gate.Dispose(); GC.SuppressFinalize(this); }
}

static class ArtifactTransferRoutes
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/agent/v1/artifact-transfers", Start).RequirePermission("agent:heartbeat");
        app.MapGet("/agent/v1/artifact-transfers/{id:guid}", AgentStatus).RequirePermission("agent:heartbeat");
        app.MapPut("/agent/v1/artifact-transfers/{id:guid}/chunks/{index:int}", Chunk).RequirePermission("agent:heartbeat");
        app.MapPost("/agent/v1/artifact-transfers/{id:guid}:complete", Complete).RequirePermission("agent:heartbeat");
        app.MapGet("/api/v1/artifact-transfers/{id:guid}", Status).RequirePermission("forensics:read");
        app.MapGet("/api/v1/artifact-transfers", Owner).RequirePermission("forensics:read");
        app.MapGet("/api/v1/artifact-transfers/{id:guid}/content", Content).RequirePermission("response:artifact:download");
    }
    static bool Agent(HttpContext c, out PrincipalContext p, out Guid endpoint, out Guid agent, out string installation)
    { p = (PrincipalContext?)c.Items["principal"] ?? new("", "", new HashSet<string>(), ""); endpoint = agent = Guid.Empty; installation = c.Request.Headers["X-Agent-Installation-Id"].FirstOrDefault() ?? ""; var ids = p.Subject.Split(':'); return p.Type == "agent" && ids.Length == 2 && Guid.TryParse(ids[0], out endpoint) && Guid.TryParse(ids[1], out agent) && installation.Length > 0; }
    static async Task<IResult> Start(ArtifactTransferStart input, HttpContext c, ArtifactTransferStore store,
        IResponseActionRepository responses, ILiveResponseRepository live, CancellationToken ct)
    {
        if (!Agent(c, out var p, out var endpoint, out var agent, out var installation)) return Results.Unauthorized();
        var ownerValid = false;
        if (input.OwnerType == "response-action")
        {
            var action = await responses.GetAsync(p.TenantId, input.OwnerId, ct);
            ownerValid = action is not null && action.EndpointId == endpoint && action.AgentId == agent &&
                action.AgentInstallationId == installation && action.State is ResponseActionState.Running or ResponseActionState.CancelRequested;
        }
        else if (input.OwnerType == "live-response")
        {
            foreach (var session in await live.ListAsync(p.TenantId, endpoint, ct))
                if (session.AgentId == agent && session.AgentInstallationId == installation &&
                    session.Commands.Any(x => x.CommandId == input.OwnerId && x.State is LiveCommandState.Running or LiveCommandState.CancelRequested))
                { ownerValid = true; break; }
        }
        if (!ownerValid) return Results.Problem(statusCode: 409, title: "ARTIFACT_TRANSFER_OWNER",
            detail: "Transfer owner is not an active action bound to this endpoint installation.");
        return Results.Ok(new ApiEnvelope<object>(await store.StartAsync(p.TenantId, endpoint, agent, installation, input, ct), new(c.TraceIdentifier, "1.0")));
    }
    static async Task<IResult> AgentStatus(Guid id, HttpContext c, ArtifactTransferStore store, CancellationToken ct)
    { if (!Agent(c, out var p, out var endpoint, out var agent, out var installation)) return Results.Unauthorized(); return Results.Ok(new ApiEnvelope<object>(await store.AgentStatusAsync(p.TenantId, endpoint, agent, installation, id, ct), new(c.TraceIdentifier, "1.0"))); }
    static async Task<IResult> Chunk(Guid id, int index, HttpContext c, ArtifactTransferStore store, CancellationToken ct)
    { if (!Agent(c, out var p, out var endpoint, out var agent, out var installation)) return Results.Unauthorized(); var hash = c.Request.Headers["X-Chunk-SHA256"].FirstOrDefault() ?? ""; var length = c.Request.ContentLength ?? -1; return Results.Ok(new ApiEnvelope<object>(await store.PutChunkAsync(p.TenantId, endpoint, agent, installation, id, index, c.Request.Body, length, hash, ct), new(c.TraceIdentifier, "1.0"))); }
    static async Task<IResult> Complete(Guid id, ArtifactTransferCompletion input, HttpContext c, ArtifactTransferStore store, CancellationToken ct)
    { if (id != input.TransferId || !Agent(c, out var p, out var endpoint, out var agent, out var installation)) return Results.Unauthorized(); return Results.Ok(new ApiEnvelope<object>(await store.CompleteAsync(p.TenantId, endpoint, agent, installation, input, ct), new(c.TraceIdentifier, "1.0"))); }
    static async Task<IResult> Status(Guid id, HttpContext c, ArtifactTransferStore store, CancellationToken ct) => await store.GetAsync(c.Items["tenant"]!.ToString()!, id, ct) is { } value ? Results.Ok(new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0"))) : Results.NotFound();
    static async Task<IResult> Owner(Guid ownerId, HttpContext c, ArtifactTransferStore store, CancellationToken ct) =>
        Results.Ok(new ApiEnvelope<object>(await store.OwnerAsync(c.Items["tenant"]!.ToString()!, ownerId, ct), new(c.TraceIdentifier, "1.0")));
    static async Task<IResult> Content(Guid id, HttpContext c, ArtifactTransferStore store, CancellationToken ct) => await store.DownloadAsync(c.Items["tenant"]!.ToString()!, id, ct) is { } value ? Results.Stream(value.Content, value.Status.State == ArtifactTransferState.Completed ? "application/octet-stream" : "application/octet-stream", enableRangeProcessing: true) : Results.NotFound();
}
