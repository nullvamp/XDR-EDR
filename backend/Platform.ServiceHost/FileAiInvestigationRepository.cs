using System.Collections.Concurrent;
using OpenSecurityPlatform.Foundation;

sealed class FileAiInvestigationRepository : IAiInvestigationRepository
{
    readonly ConcurrentDictionary<string, List<AiPolicy>> policies = new();
    readonly ConcurrentDictionary<(string Tenant, Guid Id), AiConversation> conversations = new();
    readonly ConcurrentDictionary<(string Tenant, Guid Conversation), List<AiMessage>> messages = new();
    readonly ConcurrentDictionary<(string Tenant, Guid Id), AiEvidencePackage> evidence = new();
    readonly ConcurrentDictionary<(string Tenant, Guid Id), AiNoteDraft> drafts = new();
    readonly ConcurrentDictionary<string, List<AiAuditEvent>> audit = new();
    readonly ConcurrentDictionary<string, long[]> metrics = new();
    readonly object gate = new();

    public Task<AiPolicy> PolicyAsync(string tenant, CancellationToken ct) { lock (gate) return Task.FromResult(policies.GetValueOrDefault(tenant)?.OrderByDescending(x => x.Version).FirstOrDefault() ?? AiInvestigationSafety.DefaultPolicy(tenant)); }
    public async Task<AiPolicy> PutPolicyAsync(string tenant, string actor, AiPolicyRequest request, CancellationToken ct)
    {
        AiInvestigationSafety.Validate(request); var prior = await PolicyAsync(tenant, ct); var id = prior.PolicyId; var now = DateTimeOffset.UtcNow;
        var x = new AiPolicy(id, tenant, prior.Version + 1, request.Enabled, request.DataMode, request.ProviderId, request.AllowedModels, request.AllowedEvidenceTypes, request.RedactPersonalData, request.RedactSecrets, request.MaximumEvidenceItems, request.MaximumEvidenceBytes, request.MaximumOutputCharacters, request.MaximumRequestsPerMinute, request.MaximumConcurrentRequests, request.MaximumProviderRetries, request.PromptRetentionDays, request.ResponseRetentionDays, now, actor, prior.PolicyHash, "");
        x = x with { TimeoutSeconds = request.TimeoutSeconds, ContextTokenLimit = request.ContextTokenLimit, Determinism = request.Determinism, AllowedUseCases = request.AllowedUseCases ?? ["investigation"], PolicyHash = AiInvestigationSafety.Hash(x with { PolicyHash = "" }) }; lock (gate) policies.GetOrAdd(tenant, _ => []).Add(x); return x;
    }
    public Task<AiConversation> CreateConversationAsync(string tenant, string actor, string contextType, string contextId, string title, CancellationToken ct)
    {
        if (!AiInvestigationRoutesContext.Valid(contextType) || string.IsNullOrWhiteSpace(contextId) || contextId.Length > 512 || string.IsNullOrWhiteSpace(title) || title.Length > 200) throw new EnrollmentConflictException("AI_CONVERSATION_INVALID", "Conversation context, identity, or title is invalid.");
        var now = DateTimeOffset.UtcNow; var x = new AiConversation(Guid.NewGuid(), tenant, contextType, contextId, AiInvestigationSafety.PlainText(title), actor, now, now, 1); conversations[(tenant, x.ConversationId)] = x; return Task.FromResult(x);
    }
    public Task<AiConversation?> ConversationAsync(string tenant, Guid id, CancellationToken ct) => Task.FromResult(conversations.GetValueOrDefault((tenant, id)));
    public Task<IReadOnlyList<AiConversation>> ConversationsAsync(string tenant, int limit, CancellationToken ct) => Task.FromResult<IReadOnlyList<AiConversation>>(conversations.Where(x => x.Key.Tenant == tenant).Select(x => x.Value).OrderByDescending(x => x.UpdatedAt).Take(Math.Clamp(limit, 1, 200)).ToArray());
    public Task<AiMessage> AppendMessageAsync(AiMessage message, CancellationToken ct)
    {
        lock (gate)
        {
            if (!conversations.ContainsKey((message.TenantId, message.ConversationId))) throw new KeyNotFoundException(); var list = messages.GetOrAdd((message.TenantId, message.ConversationId), _ => []);
            var prior = list.FirstOrDefault(x => x.ClientRequestId == message.ClientRequestId); if (prior is not null) return Task.FromResult(prior);
            list.Add(message); var c = conversations[(message.TenantId, message.ConversationId)]; conversations[(message.TenantId, message.ConversationId)] = c with { UpdatedAt = message.CreatedAt, Version = c.Version + 1 }; return Task.FromResult(message);
        }
    }
    public Task<IReadOnlyList<AiMessage>> MessagesAsync(string tenant, Guid conversationId, CancellationToken ct) { lock (gate) return Task.FromResult<IReadOnlyList<AiMessage>>((messages.GetValueOrDefault((tenant, conversationId)) ?? []).OrderBy(x => x.CreatedAt).ToArray()); }
    public Task SaveEvidenceAsync(AiEvidencePackage package, CancellationToken ct) { evidence[(package.TenantId, package.PackageId)] = package; var m = metrics.GetOrAdd(package.TenantId, _ => new long[7]); Interlocked.Add(ref m[5], package.Items.Length); Interlocked.Add(ref m[6], package.Truncation.IncludedBytes); return Task.CompletedTask; }
    public Task<AiEvidencePackage?> EvidenceAsync(string tenant, Guid packageId, CancellationToken ct) => Task.FromResult(evidence.GetValueOrDefault((tenant, packageId)));
    public Task<AiNoteDraft> SaveDraftAsync(AiNoteDraft draft, CancellationToken ct) { drafts[(draft.TenantId, draft.DraftId)] = draft; return Task.FromResult(draft); }
    public Task<AiNoteDraft?> DraftAsync(string tenant, Guid draftId, CancellationToken ct) => Task.FromResult(drafts.GetValueOrDefault((tenant, draftId)));
    public Task<AiNoteDraft> AcceptDraftAsync(string tenant, Guid draftId, string actor, Guid noteId, CancellationToken ct) { lock (gate) { var x = drafts.GetValueOrDefault((tenant, draftId)) ?? throw new KeyNotFoundException(); if (x.Accepted) return Task.FromResult(x); x = x with { Accepted = true, AcceptedBy = actor, AcceptedAt = DateTimeOffset.UtcNow, AcceptedNoteId = noteId }; drafts[(tenant, draftId)] = x; return Task.FromResult(x); } }
    public Task RecordAuditAsync(AiAuditEvent value, CancellationToken ct) { lock (gate) audit.GetOrAdd(value.TenantId, _ => []).Add(value); return Task.CompletedTask; }
    public Task<IReadOnlyList<AiAuditEvent>> AuditAsync(string tenant, int limit, CancellationToken ct) { lock (gate) return Task.FromResult<IReadOnlyList<AiAuditEvent>>((audit.GetValueOrDefault(tenant) ?? []).OrderByDescending(x => x.OccurredAt).Take(Math.Clamp(limit, 1, 500)).ToArray()); }
    public Task<AiOperationalMetrics> MetricsAsync(string tenant, CancellationToken ct) { var x = metrics.GetOrAdd(tenant, _ => new long[7]); return Task.FromResult(new AiOperationalMetrics(x[0], x[1], x[2], x[3], x[4], x[5], x[6], 0, DateTimeOffset.UtcNow)); }
}

static class AiInvestigationRoutesContext
{
    public static readonly string[] All = ["incident", "alert", "process", "entity", "detection", "correlation", "ioc", "tunnel", "forensic"];
    public static bool Valid(string value) => All.Contains(value, StringComparer.Ordinal);
}
