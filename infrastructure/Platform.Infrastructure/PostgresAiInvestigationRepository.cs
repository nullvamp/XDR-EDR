using System.Text.Json;
using Npgsql;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresAiInvestigationRepository(string connectionString) : IAiInvestigationRepository, IAsyncDisposable
{
    readonly NpgsqlDataSource data = NpgsqlDataSource.Create(connectionString);
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<AiPolicy> PolicyAsync(string tenant, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("SELECT document::text FROM platform.ai_policies WHERE tenant_id=$1 ORDER BY version DESC LIMIT 1", c); q.Parameters.AddWithValue(Guid.Parse(tenant));
        return await q.ExecuteScalarAsync(ct) is string value ? JsonSerializer.Deserialize<AiPolicy>(value, Json)! : AiInvestigationSafety.DefaultPolicy(tenant);
    }
    public async Task<AiPolicy> PutPolicyAsync(string tenant, string actor, AiPolicyRequest request, CancellationToken ct)
    {
        AiInvestigationSafety.Validate(request); var prior = await PolicyAsync(tenant, ct); var now = DateTimeOffset.UtcNow;
        var x = new AiPolicy(prior.PolicyId, tenant, prior.Version + 1, request.Enabled, request.DataMode, request.ProviderId, request.AllowedModels, request.AllowedEvidenceTypes, request.RedactPersonalData, request.RedactSecrets, request.MaximumEvidenceItems, request.MaximumEvidenceBytes, request.MaximumOutputCharacters, request.MaximumRequestsPerMinute, request.MaximumConcurrentRequests, request.MaximumProviderRetries, request.PromptRetentionDays, request.ResponseRetentionDays, now, actor, prior.PolicyHash, ""); x = x with { TimeoutSeconds = request.TimeoutSeconds, ContextTokenLimit = request.ContextTokenLimit, Determinism = request.Determinism, AllowedUseCases = request.AllowedUseCases ?? ["investigation"], PolicyHash = AiInvestigationSafety.Hash(x with { PolicyHash = "" }) };
        await Execute("INSERT INTO platform.ai_policies(tenant_id,policy_id,version,policy_hash,created_at,document) VALUES($1,$2,$3,$4,$5,$6::jsonb)", ct, Guid.Parse(tenant), x.PolicyId, x.Version, x.PolicyHash, now, Serialize(x)); return x;
    }
    public async Task<AiConversation> CreateConversationAsync(string tenant, string actor, string contextType, string contextId, string title, CancellationToken ct)
    {
        if (!new[] { "incident", "alert", "process", "entity", "detection", "correlation", "ioc", "tunnel", "forensic" }.Contains(contextType, StringComparer.Ordinal) || string.IsNullOrWhiteSpace(contextId) || contextId.Length > 512 || string.IsNullOrWhiteSpace(title) || title.Length > 200) throw new EnrollmentConflictException("AI_CONVERSATION_INVALID", "Conversation context, identity, or title is invalid.");
        var now = DateTimeOffset.UtcNow; var x = new AiConversation(Guid.NewGuid(), tenant, contextType, contextId, AiInvestigationSafety.PlainText(title), actor, now, now, 1); await Execute("INSERT INTO platform.ai_conversations(tenant_id,conversation_id,context_type,context_id,created_at,updated_at,document) VALUES($1,$2,$3,$4,$5,$5,$6::jsonb)", ct, Guid.Parse(tenant), x.ConversationId, contextType, contextId, now, Serialize(x)); return x;
    }
    public async Task<AiConversation?> ConversationAsync(string tenant, Guid id, CancellationToken ct) => await One<AiConversation>("SELECT document::text FROM platform.ai_conversations WHERE tenant_id=$1 AND conversation_id=$2", ct, Guid.Parse(tenant), id);
    public async Task<IReadOnlyList<AiConversation>> ConversationsAsync(string tenant, int limit, CancellationToken ct) => await Many<AiConversation>("SELECT document::text FROM platform.ai_conversations WHERE tenant_id=$1 ORDER BY updated_at DESC LIMIT $2", ct, Guid.Parse(tenant), Math.Clamp(limit, 1, 200));
    public async Task<AiMessage> AppendMessageAsync(AiMessage message, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); await using var tx = await c.BeginTransactionAsync(ct);
        await using var q = new NpgsqlCommand("INSERT INTO platform.ai_messages(tenant_id,message_id,conversation_id,client_request_id,role,created_at,document) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb) ON CONFLICT(tenant_id,conversation_id,client_request_id) DO NOTHING", c, tx); Add(q, Guid.Parse(message.TenantId), message.MessageId, message.ConversationId, message.ClientRequestId, message.Role.ToString(), message.CreatedAt, Serialize(message)); var inserted = await q.ExecuteNonQueryAsync(ct);
        if (inserted == 0) { await tx.RollbackAsync(ct); return (await One<AiMessage>("SELECT document::text FROM platform.ai_messages WHERE tenant_id=$1 AND conversation_id=$2 AND client_request_id=$3", ct, Guid.Parse(message.TenantId), message.ConversationId, message.ClientRequestId))!; }
        await using var u = new NpgsqlCommand("UPDATE platform.ai_conversations SET updated_at=$3,document=jsonb_set(jsonb_set(document,'{updatedAt}',to_jsonb($3::timestamptz)),'{version}',to_jsonb((document->>'version')::int+1)) WHERE tenant_id=$1 AND conversation_id=$2", c, tx); Add(u, Guid.Parse(message.TenantId), message.ConversationId, message.CreatedAt); await u.ExecuteNonQueryAsync(ct); await tx.CommitAsync(ct); return message;
    }
    public async Task<IReadOnlyList<AiMessage>> MessagesAsync(string tenant, Guid conversationId, CancellationToken ct) => await Many<AiMessage>("SELECT document::text FROM platform.ai_messages WHERE tenant_id=$1 AND conversation_id=$2 ORDER BY created_at,message_id", ct, Guid.Parse(tenant), conversationId);
    public Task SaveEvidenceAsync(AiEvidencePackage package, CancellationToken ct) => Execute("INSERT INTO platform.ai_evidence_packages(tenant_id,package_id,context_type,context_id,package_hash,created_at,item_count,evidence_bytes,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) ON CONFLICT(tenant_id,package_id) DO NOTHING", ct, Guid.Parse(package.TenantId), package.PackageId, package.ContextType, package.ContextId, package.PackageHash, package.CreatedAt, package.Items.Length, package.Truncation.IncludedBytes, Serialize(package));
    public async Task<AiEvidencePackage?> EvidenceAsync(string tenant, Guid packageId, CancellationToken ct) => await One<AiEvidencePackage>("SELECT document::text FROM platform.ai_evidence_packages WHERE tenant_id=$1 AND package_id=$2", ct, Guid.Parse(tenant), packageId);
    public async Task<AiNoteDraft> SaveDraftAsync(AiNoteDraft draft, CancellationToken ct) { await Execute("INSERT INTO platform.ai_note_drafts(tenant_id,draft_id,conversation_id,context_type,context_id,accepted,created_at,document) VALUES($1,$2,$3,$4,$5,false,$6,$7::jsonb)", ct, Guid.Parse(draft.TenantId), draft.DraftId, draft.ConversationId, draft.ContextType, draft.ContextId, draft.CreatedAt, Serialize(draft)); return draft; }
    public async Task<AiNoteDraft?> DraftAsync(string tenant, Guid draftId, CancellationToken ct) => await One<AiNoteDraft>("SELECT document::text FROM platform.ai_note_drafts WHERE tenant_id=$1 AND draft_id=$2", ct, Guid.Parse(tenant), draftId);
    public async Task<AiNoteDraft> AcceptDraftAsync(string tenant, Guid draftId, string actor, Guid noteId, CancellationToken ct)
    {
        var x = await DraftAsync(tenant, draftId, ct) ?? throw new KeyNotFoundException(); if (x.Accepted) return x; x = x with { Accepted = true, AcceptedBy = actor, AcceptedAt = DateTimeOffset.UtcNow, AcceptedNoteId = noteId };
        await Execute("UPDATE platform.ai_note_drafts SET accepted=true,document=$3::jsonb WHERE tenant_id=$1 AND draft_id=$2 AND accepted=false", ct, Guid.Parse(tenant), draftId, Serialize(x)); return x;
    }
    public Task RecordAuditAsync(AiAuditEvent value, CancellationToken ct) => Execute("INSERT INTO platform.ai_audit(tenant_id,audit_id,actor,action,object_type,object_id,occurred_at,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)", ct, Guid.Parse(value.TenantId), value.AuditId, value.Actor, value.Action, value.ObjectType, value.ObjectId, value.OccurredAt, Serialize(value));
    public async Task<IReadOnlyList<AiAuditEvent>> AuditAsync(string tenant, int limit, CancellationToken ct) => await Many<AiAuditEvent>("SELECT document::text FROM platform.ai_audit WHERE tenant_id=$1 ORDER BY occurred_at DESC LIMIT $2", ct, Guid.Parse(tenant), Math.Clamp(limit, 1, 500));
    public async Task<AiOperationalMetrics> MetricsAsync(string tenant, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("SELECT count(*) FILTER(WHERE action='ai.analysis.requested'),count(*) FILTER(WHERE action='ai.analysis.succeeded'),count(*) FILTER(WHERE action LIKE 'ai.analysis.failed%'),count(*) FILTER(WHERE action='ai.citation.rejected'),count(*) FILTER(WHERE action='ai.policy.rejected'),coalesce((SELECT sum(item_count) FROM platform.ai_evidence_packages WHERE tenant_id=$1),0),coalesce((SELECT sum(evidence_bytes) FROM platform.ai_evidence_packages WHERE tenant_id=$1),0) FROM platform.ai_audit WHERE tenant_id=$1", c); q.Parameters.AddWithValue(Guid.Parse(tenant)); await using var r = await q.ExecuteReaderAsync(ct); await r.ReadAsync(ct); return new(r.GetInt64(0), r.GetInt64(1), r.GetInt64(2), r.GetInt64(3), r.GetInt64(4), r.GetInt64(5), r.GetInt64(6), 0, DateTimeOffset.UtcNow);
    }
    async Task<T?> One<T>(string sql, CancellationToken ct, params object[] args) { await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand(sql, c); Add(q, args); return await q.ExecuteScalarAsync(ct) is string x ? JsonSerializer.Deserialize<T>(x, Json) : default; }
    async Task<IReadOnlyList<T>> Many<T>(string sql, CancellationToken ct, params object[] args) { var values = new List<T>(); await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand(sql, c); Add(q, args); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) values.Add(JsonSerializer.Deserialize<T>(r.GetString(0), Json)!); return values; }
    async Task Execute(string sql, CancellationToken ct, params object[] args) { await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand(sql, c); Add(q, args); await q.ExecuteNonQueryAsync(ct); }
    static string Serialize<T>(T x) => JsonSerializer.Serialize(x, Json); static void Add(NpgsqlCommand q, params object[] values) { foreach (var x in values) q.Parameters.AddWithValue(x ?? DBNull.Value); }
    public async ValueTask DisposeAsync() { await data.DisposeAsync(); GC.SuppressFinalize(this); }
}
