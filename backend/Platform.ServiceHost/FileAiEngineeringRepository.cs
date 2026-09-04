using System.Collections.Concurrent;
using OpenSecurityPlatform.Foundation;

sealed class FileAiEngineeringRepository : IAiEngineeringRepository
{
    readonly ConcurrentDictionary<(string Tenant, Guid Id), AiHuntProposal> hunts = new();
    readonly ConcurrentDictionary<(string Tenant, Guid Id), AiRuleDraft> drafts = new();
    readonly ConcurrentDictionary<(string Tenant, Guid Id), AiHistoricalSimulation> simulations = new();
    readonly ConcurrentDictionary<string, List<AiEngineeringAudit>> audit = new();
    public Task<AiHuntProposal> SaveHuntAsync(AiHuntProposal value, CancellationToken ct) { hunts[(value.TenantId, value.ProposalId)] = value; return Task.FromResult(value); }
    public Task<AiHuntProposal?> HuntAsync(string tenant, Guid id, CancellationToken ct) => Task.FromResult(hunts.GetValueOrDefault((tenant, id)));
    public Task<IReadOnlyList<AiHuntProposal>> HuntsAsync(string tenant, int limit, CancellationToken ct) => Task.FromResult<IReadOnlyList<AiHuntProposal>>(hunts.Where(x => x.Key.Tenant == tenant).Select(x => x.Value).OrderByDescending(x => x.CreatedAt).Take(Math.Clamp(limit, 1, 200)).ToArray());
    public async Task<AiHuntProposal> UpdateHuntAsync(string tenant, Guid id, Func<AiHuntProposal, AiHuntProposal> update, CancellationToken ct) => await SaveHuntAsync(update(await HuntAsync(tenant, id, ct) ?? throw new KeyNotFoundException()), ct);
    public Task<AiRuleDraft> SaveDraftAsync(AiRuleDraft value, CancellationToken ct) { drafts[(value.TenantId, value.DraftId)] = value; return Task.FromResult(value); }
    public Task<AiRuleDraft?> DraftAsync(string tenant, Guid id, CancellationToken ct) => Task.FromResult(drafts.GetValueOrDefault((tenant, id)));
    public Task<IReadOnlyList<AiRuleDraft>> DraftsAsync(string tenant, int limit, CancellationToken ct) => Task.FromResult<IReadOnlyList<AiRuleDraft>>(drafts.Where(x => x.Key.Tenant == tenant).Select(x => x.Value).OrderByDescending(x => x.CreatedAt).Take(Math.Clamp(limit, 1, 200)).ToArray());
    public async Task<AiRuleDraft> UpdateDraftAsync(string tenant, Guid id, Func<AiRuleDraft, AiRuleDraft> update, CancellationToken ct) => await SaveDraftAsync(update(await DraftAsync(tenant, id, ct) ?? throw new KeyNotFoundException()), ct);
    public Task SaveSimulationAsync(AiHistoricalSimulation value, CancellationToken ct) { simulations[(value.TenantId, value.SimulationId)] = value; return Task.CompletedTask; }
    public Task<AiHistoricalSimulation?> SimulationAsync(string tenant, Guid id, CancellationToken ct) => Task.FromResult(simulations.GetValueOrDefault((tenant, id)));
    public Task SaveComparisonAsync(AiRuleComparison value, CancellationToken ct) => Task.CompletedTask;
    public Task RecordAuditAsync(AiEngineeringAudit value, CancellationToken ct) { lock (audit) { if (!audit.TryGetValue(value.TenantId, out var list)) audit[value.TenantId] = list = []; list.Add(value); } return Task.CompletedTask; }
    public Task<IReadOnlyList<AiEngineeringAudit>> AuditAsync(string tenant, int limit, CancellationToken ct) { lock (audit) return Task.FromResult<IReadOnlyList<AiEngineeringAudit>>(audit.GetValueOrDefault(tenant)?.OrderByDescending(x => x.OccurredAt).Take(Math.Clamp(limit, 1, 500)).ToArray() ?? []); }
}
