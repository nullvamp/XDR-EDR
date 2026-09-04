using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class OpenSearchFileProjection : IFileProjection, IDisposable
{
    public const string Alias = "platform-files";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _client;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private FileProjectionRebuildProgress _progress = new(
        Guid.Empty,
        Alias,
        "global",
        "idle",
        DateTimeOffset.UnixEpoch,
        DateTimeOffset.UnixEpoch,
        null,
        0,
        0,
        0,
        Alias,
        null,
        false
    );

    public OpenSearchFileProjection(
        HttpClient client,
        string baseUrl,
        string? username,
        string? password
    )
    {
        client.BaseAddress = new(baseUrl);
        client.Timeout = TimeSpan.FromSeconds(15);
        if (!string.IsNullOrWhiteSpace(username))
            client.DefaultRequestHeaders.Authorization = new(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))
            );
        _client = client;
    }

    public async Task EnsureAsync(CancellationToken ct)
    {
        using var found = await _client.GetAsync($"_alias/{Alias}", ct);
        if (found.IsSuccessStatusCode)
            return;
        var index = $"{Alias}-v1";
        using (var create = await _client.PutAsJsonAsync(index, Definition(), ct))
            create.EnsureSuccessStatusCode();
        using var add = await _client.PostAsJsonAsync(
            "_aliases",
            new { actions = new[] { new { add = new { index, alias = Alias } } } },
            ct
        );
        add.EnsureSuccessStatusCode();
    }

    public async Task UpsertAsync(FileEntityView file, string eventId, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            using var r = await _client.PutAsJsonAsync(
                $"{Alias}/_doc/{file.TenantId}-{file.EndpointId}-{file.FileEntityId}",
                Document(file, eventId),
                ct
            );
            r.EnsureSuccessStatusCode();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<FilePage> SearchAsync(
        string tenantId,
        FileSearchRequest q,
        CancellationToken ct
    )
    {
        var filters = new List<object> { new { term = new { tenant_id = tenantId } } };
        if (q.EndpointId is not null)
            filters.Add(new { term = new { endpoint_id = q.EndpointId } });
        if (q.Operation is not null)
            filters.Add(
                new { term = new { operation = q.Operation.ToString()!.ToLowerInvariant() } }
            );
        if (!string.IsNullOrWhiteSpace(q.Extension))
            filters.Add(new { term = new { extension = q.Extension.TrimStart('.') } });
        if (!string.IsNullOrWhiteSpace(q.Sha256))
            filters.Add(new { term = new { sha256 = q.Sha256 } });
        var terms = new[]
        {
            q.FileName,
            q.Path,
            q.Directory,
            q.Process,
            q.User,
            q.Container,
            q.DataQuality,
        }
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(Escape)
            .ToArray();
        var body = new Dictionary<string, object?>
        {
            { "size", Math.Clamp(q.PageSize, 1, 500) },
            {
                "query",
                new
                {
                    @bool = new
                    {
                        filter = filters,
                        must = terms.Length == 0
                            ? Array.Empty<object>()
                            : new object[]
                            {
                                new
                                {
                                    simple_query_string = new
                                    {
                                        query = string.Join(' ', terms),
                                        fields = new[]
                                        {
                                            "file_name",
                                            "current_path",
                                            "directory_path",
                                            "process",
                                            "user_name",
                                            "container_id",
                                            "data_quality",
                                        },
                                        default_operator = "and",
                                    },
                                },
                            },
                    },
                }
            },
            {
                "sort",
                new object[]
                {
                    new { last_observed = new { order = "desc" } },
                    new { file_entity_id = new { order = "desc" } },
                }
            },
        };
        if (!string.IsNullOrWhiteSpace(q.Cursor))
            body["search_after"] = JsonSerializer.Deserialize<object[]>(
                TenantCursor.Unprotect(tenantId, q.Cursor)
            );
        using var response = await _client.PostAsJsonAsync($"{Alias}/_search", body, ct);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var values = new List<FileEntityView>();
        string? cursor = null;
        foreach (
            var hit in doc.RootElement.GetProperty("hits").GetProperty("hits").EnumerateArray()
        )
        {
            values.Add(
                JsonSerializer.Deserialize<FileEntityView>(
                    hit.GetProperty("_source").GetProperty("file").GetRawText(),
                    Json
                )!
            );
            cursor = TenantCursor.Protect(tenantId, hit.GetProperty("sort").GetRawText());
        }
        return new(values, cursor);
    }

    public async Task<ProcessProjectionRebuildResult> RebuildAsync(
        IReadOnlyList<FileEntityView> files,
        CancellationToken ct
    )
    {
        await _gate.WaitAsync(ct);
        var rebuildId = Guid.NewGuid();
        var startedAt = DateTimeOffset.UtcNow;
        var index = $"{Alias}-v{startedAt:yyyyMMddHHmmss}";
        _progress = new(
            rebuildId,
            index,
            "global",
            "running",
            startedAt,
            startedAt,
            null,
            files.Count,
            0,
            0,
            Alias,
            null,
            true
        );
        try
        {
            var started = System.Diagnostics.Stopwatch.GetTimestamp();
            using (var create = await _client.PutAsJsonAsync(index, Definition(), ct))
                create.EnsureSuccessStatusCode();
            var indexed = 0;
            foreach (var batch in files.Chunk(500))
            {
                var b = new StringBuilder();
                foreach (var f in batch)
                {
                    b.AppendLine(
                        JsonSerializer.Serialize(
                            new
                            {
                                index = new
                                {
                                    _index = index,
                                    _id = $"{f.TenantId}-{f.EndpointId}-{f.FileEntityId}",
                                },
                            },
                            Json
                        )
                    );
                    b.AppendLine(JsonSerializer.Serialize(Document(f, "rebuild"), Json));
                }
                using var content = new StringContent(
                    b.ToString(),
                    Encoding.UTF8,
                    "application/x-ndjson"
                );
                using var bulk = await _client.PostAsync("_bulk", content, ct);
                bulk.EnsureSuccessStatusCode();
                indexed += batch.Length;
                _progress = _progress with
                {
                    IndexedCount = indexed,
                    UpdatedAt = DateTimeOffset.UtcNow,
                };
            }
            using (var refresh = await _client.PostAsync($"{index}/_refresh", null, ct))
                refresh.EnsureSuccessStatusCode();
            var actions = new List<object>();
            using (var current = await _client.GetAsync($"_alias/{Alias}", ct))
            {
                if (current.IsSuccessStatusCode)
                {
                    using var d = JsonDocument.Parse(await current.Content.ReadAsStringAsync(ct));
                    foreach (var old in d.RootElement.EnumerateObject())
                        actions.Add(new { remove = new { index = old.Name, alias = Alias } });
                }
            }
            actions.Add(new { add = new { index, alias = Alias } });
            using (var swap = await _client.PostAsJsonAsync("_aliases", new { actions }, ct))
                swap.EnsureSuccessStatusCode();
            var count = await _client.GetFromJsonAsync<JsonElement>($"{index}/_count", ct);
            var actual = count.GetProperty("count").GetInt32();
            if (actual != files.Count)
                throw new InvalidOperationException("File projection rebuild count mismatch.");
            var completed = DateTimeOffset.UtcNow;
            _progress = _progress with
            {
                State = "completed",
                IndexedCount = actual,
                CurrentAlias = index,
                UpdatedAt = completed,
                CompletedAt = completed,
                RollbackAvailable = true,
            };
            return new(index, actual, System.Diagnostics.Stopwatch.GetElapsedTime(started), true);
        }
        catch (Exception e)
        {
            var failed = DateTimeOffset.UtcNow;
            _progress = _progress with
            {
                State = "failed",
                FailureCount = _progress.FailureCount + 1,
                UpdatedAt = failed,
                CompletedAt = failed,
                ErrorSummary = e.GetType().Name,
            };
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }

    public FileProjectionRebuildProgress GetRebuildProgress() => _progress;

    public async Task<bool> HealthAsync(CancellationToken ct)
    {
        try
        {
            using var r = await _client.GetAsync("_cluster/health", ct);
            return r.IsSuccessStatusCode;
        }
        catch (HttpRequestException)
        {
            return false;
        }
    }

    private static object Document(FileEntityView f, string eventId) =>
        new
        {
            tenant_id = f.TenantId,
            endpoint_id = f.EndpointId,
            file_entity_id = f.FileEntityId,
            file_name = Path.GetFileName(f.CurrentPath),
            current_path = f.CurrentPath,
            directory_path = Path.GetDirectoryName(f.CurrentPath),
            extension = Path.GetExtension(f.CurrentPath).TrimStart('.'),
            operation = f.State.ToString().ToLowerInvariant(),
            process = f.LatestProcess?.ProcessEntityId,
            user_name = f.UserName,
            container_id = f.LatestProcess?.Path,
            sha256 = f.Hash.Sha256,
            signature_state = f.Hash.SignatureState.ToString().ToLowerInvariant(),
            last_observed = f.LastObserved,
            data_quality = f.DataQualityFlags,
            event_id = eventId,
            file = f,
        };

    private static object Definition() =>
        new
        {
            settings = new { index = new { number_of_shards = 1, number_of_replicas = 0 } },
            mappings = new
            {
                dynamic = "strict",
                properties = new Dictionary<string, object>
                {
                    { "tenant_id", new { type = "keyword" } },
                    { "endpoint_id", new { type = "keyword" } },
                    { "file_entity_id", new { type = "keyword" } },
                    {
                        "file_name",
                        new { type = "text", fields = new { keyword = new { type = "keyword" } } }
                    },
                    {
                        "current_path",
                        new { type = "text", fields = new { keyword = new { type = "keyword" } } }
                    },
                    { "directory_path", new { type = "text" } },
                    { "extension", new { type = "keyword" } },
                    { "operation", new { type = "keyword" } },
                    { "process", new { type = "keyword" } },
                    { "user_name", new { type = "keyword" } },
                    { "container_id", new { type = "keyword" } },
                    { "sha256", new { type = "keyword" } },
                    { "signature_state", new { type = "keyword" } },
                    { "last_observed", new { type = "date" } },
                    { "data_quality", new { type = "keyword" } },
                    { "event_id", new { type = "keyword" } },
                    { "file", new { type = "object", enabled = false } },
                },
            },
        };

    private static string Escape(string? value) =>
        string.Concat(
            (value ?? "")
                .Take(256)
                .Select(c =>
                    char.IsLetterOrDigit(c)
                    || char.IsWhiteSpace(c)
                    || c is '.' or '_' or '-' or '/' or '\\'
                        ? c
                        : ' '
                )
        );

    public void Dispose() => _gate.Dispose();
}
