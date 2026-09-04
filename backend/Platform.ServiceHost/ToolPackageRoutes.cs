using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

sealed class ToolPackageStore : IDisposable
{
    readonly string _path; readonly IObjectStorage _objects; readonly SemaphoreSlim _gate = new(1, 1);
    Dictionary<(string Tenant, Guid Id), ApprovedToolPackage>? _packages;
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    public ToolPackageStore(PlatformOptions options, IObjectStorage objects) { _path = Path.Combine(options.DataDirectory, "approved-tool-packages.json"); _objects = objects; }
    async Task Load(CancellationToken ct) { if (_packages is not null) return; if (!File.Exists(_path)) { _packages = []; return; } _packages = (JsonSerializer.Deserialize<ApprovedToolPackage[]>(await File.ReadAllTextAsync(_path, ct), Json) ?? []).ToDictionary(x => (x.TenantId, x.PackageId)); }
    async Task Save(CancellationToken ct) { var temp = _path + ".tmp"; await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(_packages!.Values, Json), ct); File.Move(temp, _path, true); }
    public async Task<ApprovedToolPackage> CreateAsync(string tenant, string actor, string name, string version,
        string fileName, long size, string sha, string? signer, bool allowUnsigned, Stream content, CancellationToken ct)
    {
        ToolPackageSafety.Validate(name, version, fileName, size, sha, signer, allowUnsigned);
        await _gate.WaitAsync(ct); try
        {
            await Load(ct); var duplicate = _packages!.Values.FirstOrDefault(x => x.TenantId == tenant && x.Sha256.Equals(sha, StringComparison.OrdinalIgnoreCase) && x.State == "approved");
            if (duplicate is not null) return duplicate;
            var id = Guid.NewGuid(); var stored = await _objects.UploadAsync(tenant, id.ToString("D"), content, "application/octet-stream", sha, ct);
            if (stored.Size != size) { await _objects.DeleteAsync(tenant, id.ToString("D"), CancellationToken.None); throw new EnrollmentConflictException("TOOL_PACKAGE_SIZE", "Stored tool package size does not match declared size."); }
            var value = new ApprovedToolPackage(id, tenant, name, version, fileName, size, sha.ToLowerInvariant(), signer?.ToLowerInvariant(), allowUnsigned, id.ToString("D"), "approved", actor, DateTimeOffset.UtcNow);
            _packages[(tenant, id)] = value; await Save(ct); return value;
        }
        finally { _gate.Release(); }
    }
    public async Task<ApprovedToolPackage?> GetAsync(string tenant, Guid id, CancellationToken ct) { await _gate.WaitAsync(ct); try { await Load(ct); return _packages!.GetValueOrDefault((tenant, id)); } finally { _gate.Release(); } }
    public async Task<IReadOnlyList<ApprovedToolPackage>> ListAsync(string tenant, CancellationToken ct) { await _gate.WaitAsync(ct); try { await Load(ct); return _packages!.Values.Where(x => x.TenantId == tenant).OrderBy(x => x.Name).ThenByDescending(x => x.CreatedAt).ToArray(); } finally { _gate.Release(); } }
    public async Task<Stream?> DownloadAsync(string tenant, Guid id, CancellationToken ct) => await GetAsync(tenant, id, ct) is { State: "approved" } x ? await _objects.DownloadAsync(tenant, x.ObjectId, ct) : null;
    public async Task<ApprovedToolPackage?> RevokeAsync(string tenant, Guid id, CancellationToken ct) { await _gate.WaitAsync(ct); try { await Load(ct); if (!_packages!.TryGetValue((tenant, id), out var value)) return null; value = value with { State = "revoked", RevokedAt = DateTimeOffset.UtcNow }; _packages[(tenant, id)] = value; await Save(ct); return value; } finally { _gate.Release(); } }
    public void Dispose() => _gate.Dispose();
}

static class ToolPackageRoutes
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/api/v1/live-response/tool-packages", Create).RequirePermission("live:file:upload");
        app.MapGet("/api/v1/live-response/tool-packages", List).RequirePermission("live:file:upload");
        app.MapPost("/api/v1/live-response/tool-packages/{id:guid}:revoke", Revoke).RequirePermission("live:file:upload");
        app.MapGet("/agent/v1/live-response/tool-packages/{id:guid}", AgentMetadata).RequirePermission("agent:heartbeat");
        app.MapGet("/agent/v1/live-response/tool-packages/{id:guid}/content", AgentContent).RequirePermission("agent:heartbeat");
    }
    static string Tenant(HttpContext c) => c.Items["tenant"]!.ToString()!;
    static async Task<IResult> Create(HttpContext c, ToolPackageStore store, CancellationToken ct)
    {
        string H(string name) => c.Request.Headers[name].FirstOrDefault() ?? "";
        var name = H("X-Tool-Name"); var version = H("X-Tool-Version"); var file = H("X-Tool-FileName");
        var sha = H("X-Tool-SHA256"); var signer = H("X-Tool-Signer"); var unsigned = H("X-Tool-Allow-Unsigned") == "true";
        var size = c.Request.ContentLength ?? -1; var actor = ((PrincipalContext)c.Items["principal"]!).Subject;
        var value = await store.CreateAsync(Tenant(c), actor, name, version, file, size, sha,
            string.IsNullOrWhiteSpace(signer) ? null : signer, unsigned, c.Request.Body, ct);
        return Results.Created($"/api/v1/live-response/tool-packages/{value.PackageId:D}", new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0")));
    }
    static async Task<IResult> List(HttpContext c, ToolPackageStore store, CancellationToken ct) => Results.Ok(new ApiEnvelope<object>(await store.ListAsync(Tenant(c), ct), new(c.TraceIdentifier, "1.0")));
    static async Task<IResult> Revoke(Guid id, HttpContext c, ToolPackageStore store, CancellationToken ct) => await store.RevokeAsync(Tenant(c), id, ct) is { } value ? Results.Ok(new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0"))) : Results.NotFound();
    static async Task<IResult> AgentMetadata(Guid id, HttpContext c, ToolPackageStore store, CancellationToken ct) => await store.GetAsync(Tenant(c), id, ct) is { State: "approved" } value ? Results.Ok(new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0"))) : Results.NotFound();
    static async Task<IResult> AgentContent(Guid id, HttpContext c, ToolPackageStore store, CancellationToken ct) => await store.DownloadAsync(Tenant(c), id, ct) is { } stream ? Results.Stream(stream, "application/octet-stream", enableRangeProcessing: true) : Results.NotFound();
}
