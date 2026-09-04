using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<PlaybookState>))]
public enum PlaybookState { Draft, Testing, Active, Disabled, Deprecated }
[JsonConverter(typeof(JsonStringEnumConverter<PlaybookStepType>))]
public enum PlaybookStepType { Condition, StructuredResponse, ApprovalGate, AnalystDecision, Delay, EvidenceVerification, AlertUpdate, IncidentUpdate, Collection, InternalNotification }
[JsonConverter(typeof(JsonStringEnumConverter<PlaybookExecutionState>))]
public enum PlaybookExecutionState { Pending, WaitingForApproval, Running, WaitingForAnalyst, Succeeded, Partial, Failed, CancelRequested, Cancelled, TimedOut, Expired }
[JsonConverter(typeof(JsonStringEnumConverter<PlaybookStepState>))]
public enum PlaybookStepState { Pending, WaitingForApproval, WaitingForAnalyst, Running, Succeeded, Failed, Skipped, Cancelled, Simulated }
[JsonConverter(typeof(JsonStringEnumConverter<PlaybookMode>))]
public enum PlaybookMode { RecommendationOnly, ApprovalGated, SafeAutomatic, Simulation, DryRun }
[JsonConverter(typeof(JsonStringEnumConverter<PlaybookRisk>))]
public enum PlaybookRisk { Low, Medium, High, Critical }
[JsonConverter(typeof(JsonStringEnumConverter<PlaybookTriggerType>))]
public enum PlaybookTriggerType { AlertCreated, AlertChanged, IncidentCreated, IncidentChanged, DetectionFinding, CorrelatedFinding, IocMatch, TunnelFinding, Manual }
[JsonConverter(typeof(JsonStringEnumConverter<PlaybookConditionOperator>))]
public enum PlaybookConditionOperator { Equal, NotEqual, In, NotIn, GreaterThan, GreaterThanOrEqual, LessThan, LessThanOrEqual, Exists, NotExists }
[JsonConverter(typeof(JsonStringEnumConverter<PlaybookConditionBoolean>))]
public enum PlaybookConditionBoolean { And, Or, Not }

public sealed record PlaybookCondition(string? Field = null, PlaybookConditionOperator Operator = PlaybookConditionOperator.Exists,
    string[]? Values = null, PlaybookConditionBoolean Boolean = PlaybookConditionBoolean.And, PlaybookCondition[]? Children = null);
public sealed record PlaybookRetryPolicy(int MaximumAttempts = 1, int InitialDelaySeconds = 1, int MaximumDelaySeconds = 30);
public sealed record PlaybookApprovalPolicy(bool Required, bool SecondPerson, int ExpiresInSeconds = 900);
public sealed record PlaybookTrigger(PlaybookTriggerType Type, string[] SourceTypes, PlaybookCondition? Condition = null, bool Enabled = true);
public sealed record PlaybookStep(string StepId, PlaybookStepType Type, string Name, string[] Dependencies,
    IReadOnlyDictionary<string, string?> Inputs, int TimeoutSeconds = 60, PlaybookRetryPolicy? Retry = null,
    PlaybookApprovalPolicy? Approval = null, string? SuccessNext = null, string? FailureNext = null,
    PlaybookCondition? SkipCondition = null, string IdempotencyPolicy = "exact-step-and-target.v1");
public sealed record PlaybookDefinition(string SchemaVersion, Guid PlaybookId, int Version, string TenantId, string Name,
    string Description, PlaybookState State, string Author, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt,
    DateTimeOffset? ActivatedAt, DateTimeOffset? DeactivatedAt, PlaybookTrigger[] Triggers, string[] SupportedSourceTypes,
    PlaybookStep[] Steps, IReadOnlyDictionary<string, string> InputSchema, string[] RequiredPermissions,
    int MaximumRuntimeSeconds, int MaximumSteps, int MaximumBranching, int MaximumConcurrency,
    PlaybookRetryPolicy RetryPolicy, PlaybookApprovalPolicy ApprovalPolicy, bool CancellationAllowed,
    bool SimulationSupported, PlaybookRisk Risk, string VersionHash, string Compatibility = "response-registry.v1");
public sealed record PlaybookFixtureResult(string Name, string Kind, bool Passed, string Expected, string Actual,
    bool ZeroUnauthorizedMutation, DateTimeOffset ExecutedAt, string[] Evidence);
public sealed record PlaybookStepExecution(string StepId, PlaybookStepType Type, PlaybookStepState State, int Attempt,
    DateTimeOffset? StartedAt, DateTimeOffset? CompletedAt, string InputHash, string? OutputHash, string? Message,
    Guid? ResponseActionId, string[] EvidenceReferences, string? Approver, DateTimeOffset? ApprovalExpiresAt,
    string? Decision, string? DecisionRationale, string? PresentedStateHash);
public sealed record PlaybookAuditEvent(Guid AuditId, string TenantId, Guid ExecutionId, string? StepId, string Action,
    string Actor, DateTimeOffset OccurredAt, string ObjectHash, string Reason, string Provenance = "playbook-orchestrator.v1");
public sealed record PlaybookExecution(string SchemaVersion, Guid ExecutionId, Guid PlaybookId, int PlaybookVersion,
    string TenantId, PlaybookTriggerType Trigger, string SourceType, string SourceObjectId, Guid EndpointId,
    string? TargetEntityId, string? ExpectedInstallationId, string Requester, PlaybookMode Mode,
    PlaybookExecutionState State, DateTimeOffset StartedAt, DateTimeOffset? CompletedAt, DateTimeOffset ExpiresAt,
    string IdempotencyKey, Guid? SourceExecutionId, int RecursionDepth, string[] TriggerLineage,
    IReadOnlyDictionary<string, string?> SourceFields, PlaybookStepExecution[] Steps, string? Result,
    string AuditCorrelation, int Revision, PlaybookAuditEvent[] AuditHistory);
public sealed record PlaybookStartRequest(Guid PlaybookId, int Version, PlaybookTriggerType Trigger, string SourceType,
    string SourceObjectId, Guid EndpointId, string? TargetEntityId, string? ExpectedInstallationId,
    PlaybookMode Mode, string IdempotencyKey, IReadOnlyDictionary<string, string?> SourceFields,
    Guid? SourceExecutionId = null, int RecursionDepth = 0, string[]? TriggerLineage = null);
public sealed record PlaybookApprovalRequest(string StepId, string InputHash, string Reason);
public sealed record PlaybookDecisionRequest(string StepId, string Decision, string Rationale, string PresentedStateHash);
public sealed record PlaybookHealth(long ActivePlaybooks, long TriggeredExecutions, long Running, long WaitingApprovals,
    long Succeeded, long Partial, long Failed, long Cancelled, long TimedOut, long StepRetries,
    long AutomaticSafeActions, long ApprovalGatedActions, long RejectedUnsafeActions, long QueueDepth,
    double ExecutionLatencyMilliseconds, DateTimeOffset UpdatedAt);
public sealed record PlaybookActionContext(string TenantId, Guid ExecutionId, string StepId, Guid EndpointId,
    string? TargetEntityId, string? ExpectedInstallationId, string Requester, string? Approver,
    string ActionType, int ActionVersion, JsonElement Parameters, string InputHash, int TimeoutSeconds,
    string SourceType, string SourceObjectId, Guid? ExistingResponseActionId = null);
public sealed record PlaybookActionResult(bool Succeeded, bool Partial, bool Verified, bool Pending, Guid? ResponseActionId,
    string Message, string OutputHash, string[] EvidenceReferences, string? CurrentInstallationId = null);

public interface IPlaybookActionExecutor { Task<PlaybookActionResult> ExecuteAsync(PlaybookActionContext context, CancellationToken ct); }
public sealed record PlaybookWorkItem(string TenantId, Guid ExecutionId, int Attempts);
public interface IPlaybookWorkSource { Task<IReadOnlyList<PlaybookWorkItem>> ReadyAsync(CancellationToken ct); }
public sealed class EmptyPlaybookWorkSource : IPlaybookWorkSource { public Task<IReadOnlyList<PlaybookWorkItem>> ReadyAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<PlaybookWorkItem>>([]); }
public interface IPlaybookRepository
{
    Task<PlaybookDefinition> PutAsync(string tenant, string actor, PlaybookDefinition value, bool newVersion, CancellationToken ct);
    Task<IReadOnlyList<PlaybookDefinition>> ListAsync(string tenant, CancellationToken ct);
    Task<PlaybookDefinition?> GetAsync(string tenant, Guid id, int version, CancellationToken ct);
    Task<IReadOnlyDictionary<string, string[]>> ValidateAsync(string tenant, PlaybookDefinition value, CancellationToken ct);
    Task<PlaybookDefinition> RecordTestsAsync(string tenant, Guid id, int version, PlaybookFixtureResult[] results, string actor, CancellationToken ct);
    Task<PlaybookDefinition> SetStateAsync(string tenant, Guid id, int version, PlaybookState state, string actor, CancellationToken ct);
    Task<PlaybookExecution> StartAsync(string tenant, string actor, PlaybookStartRequest request, IPlaybookActionExecutor executor, CancellationToken ct);
    Task<PlaybookExecution?> GetExecutionAsync(string tenant, Guid id, CancellationToken ct);
    Task<IReadOnlyList<PlaybookExecution>> ExecutionsAsync(string tenant, string? sourceType, string? sourceObjectId, CancellationToken ct);
    Task<PlaybookExecution> AdvanceAsync(string tenant, Guid id, IPlaybookActionExecutor executor, CancellationToken ct);
    Task<PlaybookExecution> ApproveAsync(string tenant, Guid id, string actor, PlaybookApprovalRequest request, IPlaybookActionExecutor executor, CancellationToken ct);
    Task<PlaybookExecution> DenyAsync(string tenant, Guid id, string actor, PlaybookApprovalRequest request, CancellationToken ct);
    Task<PlaybookExecution> DecideAsync(string tenant, Guid id, string actor, PlaybookDecisionRequest request, IPlaybookActionExecutor executor, CancellationToken ct);
    Task<PlaybookExecution> CancelAsync(string tenant, Guid id, string actor, string reason, CancellationToken ct);
    Task<PlaybookHealth> HealthAsync(string tenant, CancellationToken ct);
}

public static class PlaybookSafety
{
    public const int MaximumSteps = 64, MaximumBranching = 4, MaximumConcurrency = 4, MaximumRuntimeSeconds = 3600,
        MaximumConditionDepth = 8, MaximumConditionPredicates = 32, MaximumInputBytes = 16 * 1024;
    static readonly HashSet<string> Fields = new(StringComparer.OrdinalIgnoreCase)
    { "severity", "status", "confidence", "quality", "sourceType", "findingType", "iocValid", "tunnelKind", "endpointStatus", "targetIdentity", "responseState", "priorResult" };
    public static readonly IReadOnlyDictionary<string, PlaybookRisk> Actions = ResponseSafety.Definitions.Keys.ToDictionary(x => x, x => x switch
    {
        "endpoint.status" or "process.list" or "network.connections" or "service.status" or "file.metadata" or "endpoint.isolation_status" or "process.response_status" or "file.quarantine_status" or "file.quarantine_metadata" or "registry.remediation_status" or "persistence.remediation_status" => PlaybookRisk.Low,
        "collect.diagnostic" or "forensic.collect" or "process.suspend" or "process.resume" => PlaybookRisk.Medium,
        "process.terminate" or "file.quarantine" or "file.restore" or "service.stop" or "service.disable" or "scheduled_task.disable" or "registry.value.remove" or "persistence.remove" or "persistence.restore" => PlaybookRisk.High,
        _ => PlaybookRisk.Critical
    }, StringComparer.Ordinal);
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static string Hash(object value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value, Json))).ToLowerInvariant();
    public static Guid StableId(params string[] values) => new(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values))).AsSpan(0, 16));
    public static IReadOnlyDictionary<string, string[]> Validate(PlaybookDefinition p)
    {
        var errors = new Dictionary<string, string[]>();
        if (p.SchemaVersion != "playbook.v1" || p.PlaybookId == Guid.Empty || !Guid.TryParse(p.TenantId, out _) || p.Version < 1) errors["identity"] = ["Canonical schema, tenant, playbook and version are required."];
        if (p.Steps.Length is < 1 or > MaximumSteps || p.MaximumSteps is < 1 or > MaximumSteps || p.Steps.Length > p.MaximumSteps) errors["steps"] = ["Step count is invalid or unbounded."];
        if (p.MaximumBranching is < 1 or > MaximumBranching || p.MaximumConcurrency is < 1 or > MaximumConcurrency || p.MaximumRuntimeSeconds is < 1 or > MaximumRuntimeSeconds) errors["bounds"] = ["Runtime, branching or concurrency bounds are invalid."];
        if (p.Steps.Select(x => x.StepId).Distinct(StringComparer.Ordinal).Count() != p.Steps.Length || p.Steps.Any(x => string.IsNullOrWhiteSpace(x.StepId) || x.StepId.Length > 64)) errors["stepIdentity"] = ["Step IDs must be unique and bounded."];
        var ids = p.Steps.Select(x => x.StepId).ToHashSet(StringComparer.Ordinal);
        foreach (var s in p.Steps)
        {
            if (s.Dependencies.Length > MaximumBranching || s.Dependencies.Any(x => !ids.Contains(x)) || (s.SuccessNext is not null && !ids.Contains(s.SuccessNext)) || (s.FailureNext is not null && !ids.Contains(s.FailureNext))) errors[$"graph.{s.StepId}"] = ["Step graph contains an unknown or excessive edge."];
            if (s.TimeoutSeconds is < 1 or > 900 || (s.Retry?.MaximumAttempts ?? 1) is < 1 or > 3) errors[$"cost.{s.StepId}"] = ["Step timeout or retry is unbounded."];
            if (JsonSerializer.SerializeToUtf8Bytes(s.Inputs).Length > MaximumInputBytes) errors[$"input.{s.StepId}"] = ["Step input exceeds the bound."];
            if (s.Type is PlaybookStepType.StructuredResponse or PlaybookStepType.Collection)
            {
                var action = s.Inputs.GetValueOrDefault("actionType") ?? "";
                if (!Actions.ContainsKey(action) || action.Contains("shell", StringComparison.OrdinalIgnoreCase) || action.Contains("powershell", StringComparison.OrdinalIgnoreCase) || action.Contains("http", StringComparison.OrdinalIgnoreCase)) errors[$"action.{s.StepId}"] = ["Only registered structured actions are allowed."];
                else if (Actions[action] >= PlaybookRisk.High && s.Approval?.Required != true) errors[$"approval.{s.StepId}"] = ["High and Critical actions require a non-overridable approval gate."];
            }
            ValidateCondition(s.SkipCondition, $"condition.{s.StepId}", errors);
        }
        foreach (var t in p.Triggers) ValidateCondition(t.Condition, $"trigger.{t.Type}", errors);
        if (HasCycle(p.Steps)) errors["cycle"] = ["Recursive or cyclic step graphs are prohibited."];
        if (string.IsNullOrWhiteSpace(p.VersionHash) || p.VersionHash != DefinitionHash(p)) errors["versionHash"] = ["Definition hash does not match immutable content."];
        return errors;
    }
    static void ValidateCondition(PlaybookCondition? c, string key, Dictionary<string, string[]> errors)
    {
        if (c is null) return; var predicates = 0; var max = 0;
        void Walk(PlaybookCondition n, int depth) { max = Math.Max(max, depth); if (n.Field is not null) { predicates++; if (!Fields.Contains(n.Field)) errors[key] = ["Condition field is not authorized."]; if ((n.Values?.Length ?? 0) > 50 || n.Values?.Any(x => x.Length > 2048 || x.Contains("script", StringComparison.OrdinalIgnoreCase) || x.Contains("powershell", StringComparison.OrdinalIgnoreCase) || x.Contains("$where", StringComparison.OrdinalIgnoreCase)) == true) errors[key] = ["Condition values are invalid or executable."]; } foreach (var x in n.Children ?? []) Walk(x, depth + 1); }
        Walk(c, 1); if (max > MaximumConditionDepth || predicates > MaximumConditionPredicates) errors[key] = ["Condition complexity exceeds hard bounds."];
    }
    static bool HasCycle(PlaybookStep[] steps)
    {
        var map = steps.ToDictionary(x => x.StepId, x => x.Dependencies.Concat([x.SuccessNext, x.FailureNext]).Where(y => y is not null).Cast<string>().ToArray(), StringComparer.Ordinal); var active = new HashSet<string>(); var done = new HashSet<string>();
        bool Visit(string id) { if (active.Contains(id)) return true; if (!done.Add(id)) return false; active.Add(id); foreach (var x in map[id]) if (map.ContainsKey(x) && Visit(x)) return true; active.Remove(id); return false; }
        return map.Keys.Any(Visit);
    }
    public static string DefinitionHash(PlaybookDefinition p) => Hash(p with { State = PlaybookState.Draft, UpdatedAt = default, ActivatedAt = null, DeactivatedAt = null, VersionHash = "" });
    public static bool Condition(PlaybookCondition? condition, IReadOnlyDictionary<string, string?> fields)
    {
        if (condition is null) return true;
        bool One(PlaybookCondition c)
        {
            var children = (c.Children ?? []).Select(One).ToArray(); bool own = true;
            if (c.Field is not null) { var exists = fields.TryGetValue(c.Field, out var actual) && actual is not null; var values = c.Values ?? []; own = c.Operator switch { PlaybookConditionOperator.Exists => exists, PlaybookConditionOperator.NotExists => !exists, PlaybookConditionOperator.Equal => exists && values.Contains(actual, StringComparer.OrdinalIgnoreCase), PlaybookConditionOperator.NotEqual => !exists || !values.Contains(actual, StringComparer.OrdinalIgnoreCase), PlaybookConditionOperator.In => exists && values.Contains(actual, StringComparer.OrdinalIgnoreCase), PlaybookConditionOperator.NotIn => !exists || !values.Contains(actual, StringComparer.OrdinalIgnoreCase), _ => exists && decimal.TryParse(actual, out var a) && values.FirstOrDefault() is { } raw && decimal.TryParse(raw, out var b) && c.Operator switch { PlaybookConditionOperator.GreaterThan => a > b, PlaybookConditionOperator.GreaterThanOrEqual => a >= b, PlaybookConditionOperator.LessThan => a < b, PlaybookConditionOperator.LessThanOrEqual => a <= b, _ => false } }; }
            return c.Boolean switch { PlaybookConditionBoolean.And => own && children.All(x => x), PlaybookConditionBoolean.Or => own || children.Any(x => x), PlaybookConditionBoolean.Not => !(own && children.All(x => x)), _ => false };
        }
        return One(condition);
    }
}

public sealed class ControlledPlaybookActionExecutor : IPlaybookActionExecutor
{
    readonly ConcurrentDictionary<string, int> calls = new(); readonly string outcome; readonly string? currentInstallation; public ControlledPlaybookActionExecutor(string outcome = "success", string? currentInstallation = null) { this.outcome = outcome; this.currentInstallation = currentInstallation; }
    public int MutationCalls => calls.Where(x => PlaybookSafety.Actions.GetValueOrDefault(x.Key) >= PlaybookRisk.High).Sum(x => x.Value);
    public int Calls => calls.Values.Sum();
    public Task<PlaybookActionResult> ExecuteAsync(PlaybookActionContext c, CancellationToken ct)
    {
        var current = currentInstallation ?? c.ExpectedInstallationId;
        if (c.ExpectedInstallationId is not null && current != c.ExpectedInstallationId) return Task.FromResult(new PlaybookActionResult(false, false, false, false, null, "TARGET_IDENTITY_MISMATCH", PlaybookSafety.Hash("identity-mismatch"), [], current));
        calls.AddOrUpdate(c.ActionType, 1, (_, n) => n + 1);
        if (outcome == "failure") return Task.FromResult(new PlaybookActionResult(false, false, false, false, null, "CONTROLLED_ACTION_FAILED", PlaybookSafety.Hash("failed"), []));
        if (outcome == "partial") return Task.FromResult(new PlaybookActionResult(false, true, false, false, null, "CONTROLLED_ACTION_PARTIAL", PlaybookSafety.Hash("partial"), ["controlled://partial"]));
        return Task.FromResult(new PlaybookActionResult(true, false, true, false, PlaybookSafety.StableId(c.TenantId, c.ExecutionId.ToString("D"), c.StepId), "verified", PlaybookSafety.Hash("verified"), [$"controlled://playbook/{c.ExecutionId:D}/{c.StepId}"], current));
    }
}

public class FilePlaybookRepository : IPlaybookRepository, IDisposable
{
    readonly SemaphoreSlim gate = new(1, 1); readonly ConcurrentDictionary<(string, Guid, int), PlaybookDefinition> definitions = new(); readonly ConcurrentDictionary<(string, Guid), PlaybookExecution> executions = new(); readonly ConcurrentDictionary<(string, Guid, int), PlaybookFixtureResult[]> tests = new();
    protected virtual Task<IReadOnlyList<PlaybookDefinition>> LoadDefinitionsAsync(string tenant, CancellationToken ct) => Task.FromResult<IReadOnlyList<PlaybookDefinition>>(definitions.Where(x => x.Key.Item1 == tenant).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<PlaybookExecution>> LoadExecutionsAsync(string tenant, CancellationToken ct) => Task.FromResult<IReadOnlyList<PlaybookExecution>>(executions.Where(x => x.Key.Item1 == tenant).Select(x => x.Value).ToArray());
    protected virtual Task<PlaybookFixtureResult[]> LoadTestsAsync(string tenant, Guid id, int version, CancellationToken ct) => Task.FromResult(tests.GetValueOrDefault((tenant, id, version), []));
    protected virtual Task PersistDefinitionAsync(PlaybookDefinition value, PlaybookFixtureResult[] fixtureResults, string actor, string action, CancellationToken ct) { definitions[(value.TenantId, value.PlaybookId, value.Version)] = value; tests[(value.TenantId, value.PlaybookId, value.Version)] = fixtureResults; return Task.CompletedTask; }
    protected virtual Task PersistExecutionAsync(PlaybookExecution value, CancellationToken ct) { executions[(value.TenantId, value.ExecutionId)] = value; return Task.CompletedTask; }
    public async Task<PlaybookDefinition> PutAsync(string tenant, string actor, PlaybookDefinition input, bool newVersion, CancellationToken ct)
    {
        await gate.WaitAsync(ct); try { var all = await LoadDefinitionsAsync(tenant, ct); var prior = all.Where(x => x.PlaybookId == input.PlaybookId).OrderByDescending(x => x.Version).FirstOrDefault(); var version = prior is null ? 1 : newVersion ? prior.Version + 1 : input.Version; if (prior is not null && !newVersion && prior.Version == version) throw new EnrollmentConflictException("PLAYBOOK_VERSION_IMMUTABLE", "Edits require a new immutable version."); var now = DateTimeOffset.UtcNow; var value = input with { TenantId = tenant, Version = version, State = PlaybookState.Draft, Author = actor, CreatedAt = prior is null ? now : input.CreatedAt, UpdatedAt = now, ActivatedAt = null, DeactivatedAt = null, VersionHash = "" }; value = value with { VersionHash = PlaybookSafety.DefinitionHash(value) }; var errors = PlaybookSafety.Validate(value); if (errors.Count > 0) throw new EnrollmentConflictException("PLAYBOOK_INVALID", string.Join("; ", errors.SelectMany(x => x.Value))); await PersistDefinitionAsync(value, [], actor, "playbook.created", ct); return value; } finally { gate.Release(); }
    }
    public Task<IReadOnlyList<PlaybookDefinition>> ListAsync(string tenant, CancellationToken ct) => LoadDefinitionsAsync(tenant, ct);
    public async Task<PlaybookDefinition?> GetAsync(string tenant, Guid id, int version, CancellationToken ct) => (await LoadDefinitionsAsync(tenant, ct)).FirstOrDefault(x => x.PlaybookId == id && x.Version == version);
    public Task<IReadOnlyDictionary<string, string[]>> ValidateAsync(string tenant, PlaybookDefinition value, CancellationToken ct) => Task.FromResult<IReadOnlyDictionary<string, string[]>>(value.TenantId == tenant ? PlaybookSafety.Validate(value) : new Dictionary<string, string[]> { ["tenant"] = ["Tenant binding is invalid."] });
    public async Task<PlaybookDefinition> RecordTestsAsync(string tenant, Guid id, int version, PlaybookFixtureResult[] results, string actor, CancellationToken ct) { if (results.Length < 10 || results.Any(x => !x.Passed || !x.ZeroUnauthorizedMutation)) throw new EnrollmentConflictException("PLAYBOOK_TEST_GATE", "All ten required fixture classes must pass with zero unauthorized mutation."); var value = await GetAsync(tenant, id, version, ct) ?? throw new KeyNotFoundException(); value = value with { State = PlaybookState.Testing, UpdatedAt = DateTimeOffset.UtcNow }; await PersistDefinitionAsync(value, results, actor, "playbook.tests.passed", ct); return value; }
    public async Task<PlaybookDefinition> SetStateAsync(string tenant, Guid id, int version, PlaybookState state, string actor, CancellationToken ct) { var value = await GetAsync(tenant, id, version, ct) ?? throw new KeyNotFoundException(); var fixtureResults = await LoadTestsAsync(tenant, id, version, ct); if (state == PlaybookState.Active && (fixtureResults.Length < 10 || fixtureResults.Any(x => !x.Passed))) throw new EnrollmentConflictException("PLAYBOOK_ACTIVATION_TEST_GATE", "Required fixtures must pass before activation."); if (state == PlaybookState.Draft) throw new EnrollmentConflictException("PLAYBOOK_STATE_INVALID", "Published state cannot return to Draft."); var now = DateTimeOffset.UtcNow; value = value with { State = state, UpdatedAt = now, ActivatedAt = state == PlaybookState.Active ? now : value.ActivatedAt, DeactivatedAt = state is PlaybookState.Disabled or PlaybookState.Deprecated ? now : value.DeactivatedAt }; await PersistDefinitionAsync(value, fixtureResults, actor, $"playbook.{state.ToString().ToLowerInvariant()}", ct); return value; }
    public async Task<PlaybookExecution> StartAsync(string tenant, string actor, PlaybookStartRequest request, IPlaybookActionExecutor executor, CancellationToken ct)
    {
        if (request.RecursionDepth != 0 || request.SourceExecutionId is not null || (request.TriggerLineage?.Length ?? 0) > 0) throw new EnrollmentConflictException("PLAYBOOK_RECURSION_BLOCKED", "Recursive playbook initiation is disabled."); var definition = await GetAsync(tenant, request.PlaybookId, request.Version, ct) ?? throw new KeyNotFoundException(); if (definition.State != PlaybookState.Active && request.Mode is not (PlaybookMode.Simulation or PlaybookMode.DryRun)) throw new EnrollmentConflictException("PLAYBOOK_NOT_ACTIVE", "Only Active playbooks may run in production modes."); if (!definition.SimulationSupported && request.Mode is PlaybookMode.Simulation or PlaybookMode.DryRun) throw new EnrollmentConflictException("PLAYBOOK_SIMULATION_UNSUPPORTED", "This version does not support simulation."); if (!definition.SupportedSourceTypes.Contains(request.SourceType, StringComparer.OrdinalIgnoreCase)) throw new EnrollmentConflictException("PLAYBOOK_SOURCE_INVALID", "Trigger source is unsupported."); if (string.IsNullOrWhiteSpace(request.IdempotencyKey) || request.IdempotencyKey.Length > 256) throw new EnrollmentConflictException("PLAYBOOK_IDEMPOTENCY_INVALID", "A bounded idempotency key is required."); var id = PlaybookSafety.StableId(tenant, request.PlaybookId.ToString("D"), request.Version.ToString(CultureInfo.InvariantCulture), request.Trigger.ToString(), request.SourceType, request.SourceObjectId, request.IdempotencyKey); var existing = await GetExecutionAsync(tenant, id, ct); if (existing is not null) return existing; var now = DateTimeOffset.UtcNow; var steps = definition.Steps.Select(x => new PlaybookStepExecution(x.StepId, x.Type, PlaybookStepState.Pending, 0, null, null, StepHash(x, request), null, null, null, [], null, null, null, null, null)).ToArray(); var audit = Audit(tenant, id, null, "playbook.execution.started", actor, request.IdempotencyKey); var execution = new PlaybookExecution("playbook-execution.v1", id, definition.PlaybookId, definition.Version, tenant, request.Trigger, request.SourceType, request.SourceObjectId, request.EndpointId, request.TargetEntityId, request.ExpectedInstallationId, actor, request.Mode, request.Mode == PlaybookMode.RecommendationOnly ? PlaybookExecutionState.Pending : PlaybookExecutionState.Running, now, null, now.AddSeconds(definition.MaximumRuntimeSeconds), request.IdempotencyKey, null, 0, [$"{request.SourceType}:{request.SourceObjectId}"], request.SourceFields, steps, request.Mode == PlaybookMode.RecommendationOnly ? "recommendation-created-no-action" : null, Guid.NewGuid().ToString("N"), 1, [audit]); await PersistExecutionAsync(execution, ct); return request.Mode == PlaybookMode.RecommendationOnly ? execution : await AdvanceAsync(tenant, id, executor, ct);
    }
    public async Task<PlaybookExecution?> GetExecutionAsync(string tenant, Guid id, CancellationToken ct) => (await LoadExecutionsAsync(tenant, ct)).FirstOrDefault(x => x.ExecutionId == id);
    public async Task<IReadOnlyList<PlaybookExecution>> ExecutionsAsync(string tenant, string? sourceType, string? sourceObjectId, CancellationToken ct) => (await LoadExecutionsAsync(tenant, ct)).Where(x => sourceType is null || x.SourceType.Equals(sourceType, StringComparison.OrdinalIgnoreCase)).Where(x => sourceObjectId is null || x.SourceObjectId == sourceObjectId).OrderByDescending(x => x.StartedAt).Take(200).ToArray();
    public async Task<PlaybookExecution> AdvanceAsync(string tenant, Guid id, IPlaybookActionExecutor executor, CancellationToken ct)
    {
        await gate.WaitAsync(ct); try
        {
            var x = await GetExecutionAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); if (Terminal(x.State) || x.State is PlaybookExecutionState.WaitingForApproval or PlaybookExecutionState.WaitingForAnalyst) return x; if (x.ExpiresAt <= DateTimeOffset.UtcNow) return await Save(x with { State = PlaybookExecutionState.TimedOut, CompletedAt = DateTimeOffset.UtcNow, Result = "runtime-expired" }, "playbook.execution.timedout", "orchestrator", ct); var p = await GetAsync(tenant, x.PlaybookId, x.PlaybookVersion, ct) ?? throw new KeyNotFoundException(); var steps = x.Steps.ToDictionary(s => s.StepId, StringComparer.Ordinal);
            foreach (var running in p.Steps.Where(d => steps[d.StepId].State == PlaybookStepState.Running && d.Type is PlaybookStepType.StructuredResponse or PlaybookStepType.Collection)) { var s = steps[running.StepId]; var action = running.Inputs.GetValueOrDefault("actionType") ?? ""; var result = await executor.ExecuteAsync(new(tenant, x.ExecutionId, s.StepId, x.EndpointId, x.TargetEntityId, x.ExpectedInstallationId, x.Requester, s.Approver, action, 1, Parameters(running.Inputs, x.SourceFields), s.InputHash, running.TimeoutSeconds, x.SourceType, x.SourceObjectId, s.ResponseActionId), ct); if (result.Pending) return x; steps[s.StepId] = s with { State = result.Succeeded && result.Verified ? PlaybookStepState.Succeeded : PlaybookStepState.Failed, CompletedAt = DateTimeOffset.UtcNow, OutputHash = result.OutputHash, Message = result.Message, EvidenceReferences = result.EvidenceReferences }; if (!result.Succeeded) return await HandleFailure(x, p, running, steps, result, ct); }
            var parallel = p.Steps.Where(d => steps[d.StepId].State == PlaybookStepState.Pending && (d.Type is PlaybookStepType.StructuredResponse or PlaybookStepType.Collection) && d.Dependencies.All(dep => steps[dep].State is PlaybookStepState.Succeeded or PlaybookStepState.Skipped or PlaybookStepState.Simulated) && PlaybookSafety.Actions.GetValueOrDefault(d.Inputs.GetValueOrDefault("actionType") ?? "", PlaybookRisk.Critical) == PlaybookRisk.Low && d.Approval?.Required != true).Take(p.MaximumConcurrency).ToArray();
            if (parallel.Length > 1 && x.Mode is PlaybookMode.SafeAutomatic or PlaybookMode.ApprovalGated)
            {
                var results = await Task.WhenAll(parallel.Select(async definition => (definition, result: await executor.ExecuteAsync(new(tenant, x.ExecutionId, definition.StepId, x.EndpointId, x.TargetEntityId, x.ExpectedInstallationId, x.Requester, null, definition.Inputs.GetValueOrDefault("actionType") ?? "", 1, Parameters(definition.Inputs, x.SourceFields), steps[definition.StepId].InputHash, definition.TimeoutSeconds, x.SourceType, x.SourceObjectId), ct))));
                foreach (var item in results) { var s = steps[item.definition.StepId]; steps[s.StepId] = s with { State = item.result.Pending ? PlaybookStepState.Running : item.result.Succeeded && item.result.Verified ? PlaybookStepState.Succeeded : PlaybookStepState.Failed, Attempt = s.Attempt + 1, StartedAt = DateTimeOffset.UtcNow, CompletedAt = item.result.Pending ? null : DateTimeOffset.UtcNow, OutputHash = item.result.OutputHash, Message = item.result.Message, ResponseActionId = item.result.ResponseActionId, EvidenceReferences = item.result.EvidenceReferences }; }
                var failedParallel = results.FirstOrDefault(item => !item.result.Succeeded && !item.result.Pending); if (failedParallel.definition is not null) return await HandleFailure(x, p, failedParallel.definition, steps, failedParallel.result, ct);
                if (results.Any(item => item.result.Pending)) return await Save(x with { State = PlaybookExecutionState.Running, Steps = Order(p, steps), Result = "parallel-safe-actions-pending-verification" }, "playbook.parallel-safe-actions.requested", "orchestrator", ct);
            }
            foreach (var definition in p.Steps)
            {
                var s = steps[definition.StepId]; if (s.State != PlaybookStepState.Pending || definition.Dependencies.Any(d => steps[d].State is not (PlaybookStepState.Succeeded or PlaybookStepState.Skipped or PlaybookStepState.Simulated))) continue;
                if (definition.SkipCondition is not null && PlaybookSafety.Condition(definition.SkipCondition, x.SourceFields)) { steps[s.StepId] = s with { State = PlaybookStepState.Skipped, CompletedAt = DateTimeOffset.UtcNow, Message = "skip-condition" }; continue; }
                if (x.Mode is PlaybookMode.Simulation or PlaybookMode.DryRun && definition.Type is PlaybookStepType.ApprovalGate or PlaybookStepType.AnalystDecision) { steps[s.StepId] = s with { State = PlaybookStepState.Simulated, StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow, Message = definition.Type == PlaybookStepType.ApprovalGate ? "would-require-approval" : "would-require-analyst-decision", OutputHash = PlaybookSafety.Hash(definition.Inputs) }; continue; }
                if (definition.Type == PlaybookStepType.ApprovalGate) { if (s.Approver is not null) { steps[s.StepId] = s with { State = PlaybookStepState.Succeeded, CompletedAt = DateTimeOffset.UtcNow, Message = "approved-gate" }; continue; } steps[s.StepId] = s with { State = PlaybookStepState.WaitingForApproval, ApprovalExpiresAt = DateTimeOffset.UtcNow.AddSeconds(definition.Approval?.ExpiresInSeconds ?? 900) }; return await Save(x with { State = PlaybookExecutionState.WaitingForApproval, Steps = Order(p, steps) }, "playbook.approval.requested", "orchestrator", ct, s.StepId); }
                if (definition.Type == PlaybookStepType.AnalystDecision) { var presented = PlaybookSafety.Hash(new { x.SourceFields, completed = steps.Values.Where(v => v.State == PlaybookStepState.Succeeded).Select(v => v.StepId).Order() }); steps[s.StepId] = s with { State = PlaybookStepState.WaitingForAnalyst, PresentedStateHash = presented }; return await Save(x with { State = PlaybookExecutionState.WaitingForAnalyst, Steps = Order(p, steps) }, "playbook.analyst-decision.requested", "orchestrator", ct, s.StepId); }
                if (definition.Type == PlaybookStepType.Condition) { var ok = PlaybookSafety.Condition(ReadCondition(definition.Inputs), x.SourceFields); steps[s.StepId] = s with { State = ok ? PlaybookStepState.Succeeded : PlaybookStepState.Skipped, StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow, Message = ok ? "condition-true" : "condition-false", OutputHash = PlaybookSafety.Hash(ok) }; continue; }
                if (definition.Type is PlaybookStepType.StructuredResponse or PlaybookStepType.Collection)
                {
                    var action = definition.Inputs.GetValueOrDefault("actionType") ?? ""; var risk = PlaybookSafety.Actions.GetValueOrDefault(action, PlaybookRisk.Critical); var approved = s.Approver is not null;
                    var parameters = Parameters(definition.Inputs, x.SourceFields); if (x.Mode is PlaybookMode.Simulation or PlaybookMode.DryRun) { steps[s.StepId] = s with { State = PlaybookStepState.Simulated, StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow, Message = (risk >= PlaybookRisk.High || definition.Approval?.Required == true) ? "zero-mutation-simulation;approval-required" : "zero-mutation-simulation", OutputHash = PlaybookSafety.Hash(new { action, parameters }) }; continue; }
                    if (risk >= PlaybookRisk.High && !approved) { steps[s.StepId] = s with { State = PlaybookStepState.WaitingForApproval, ApprovalExpiresAt = DateTimeOffset.UtcNow.AddSeconds(definition.Approval?.ExpiresInSeconds ?? 900) }; return await Save(x with { State = PlaybookExecutionState.WaitingForApproval, Steps = Order(p, steps) }, "playbook.approval.requested", "orchestrator", ct, s.StepId); }
                    if (risk == PlaybookRisk.Medium && definition.Approval?.Required == true && !approved) { steps[s.StepId] = s with { State = PlaybookStepState.WaitingForApproval, ApprovalExpiresAt = DateTimeOffset.UtcNow.AddSeconds(definition.Approval.ExpiresInSeconds) }; return await Save(x with { State = PlaybookExecutionState.WaitingForApproval, Steps = Order(p, steps) }, "playbook.approval.requested", "orchestrator", ct, s.StepId); }
                    if (risk == PlaybookRisk.Low && x.Mode is not (PlaybookMode.SafeAutomatic or PlaybookMode.ApprovalGated)) return await Save(x with { State = PlaybookExecutionState.Pending, Steps = Order(p, steps), Result = "recommendation-only" }, "playbook.action.recommended", "orchestrator", ct, s.StepId);
                    var result = await executor.ExecuteAsync(new(tenant, x.ExecutionId, s.StepId, x.EndpointId, x.TargetEntityId, x.ExpectedInstallationId, x.Requester, s.Approver, action, 1, parameters, s.InputHash, definition.TimeoutSeconds, x.SourceType, x.SourceObjectId), ct); steps[s.StepId] = s with { State = result.Pending ? PlaybookStepState.Running : result.Succeeded && result.Verified ? PlaybookStepState.Succeeded : PlaybookStepState.Failed, Attempt = s.Attempt + 1, StartedAt = DateTimeOffset.UtcNow, CompletedAt = result.Pending ? null : DateTimeOffset.UtcNow, OutputHash = result.OutputHash, Message = result.Message, ResponseActionId = result.ResponseActionId, EvidenceReferences = result.EvidenceReferences }; if (result.Pending) return await Save(x with { State = PlaybookExecutionState.Running, Steps = Order(p, steps), Result = "response-action-pending-verification" }, "playbook.response.requested", "orchestrator", ct, s.StepId); if (!result.Succeeded) return await HandleFailure(x, p, definition, steps, result, ct);
                    continue;
                }
                steps[s.StepId] = s with { State = x.Mode is PlaybookMode.Simulation or PlaybookMode.DryRun ? PlaybookStepState.Simulated : PlaybookStepState.Succeeded, StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow, Message = definition.Type == PlaybookStepType.EvidenceVerification ? "verified-from-prior-step-evidence" : "audited-structured-control-step", OutputHash = PlaybookSafety.Hash(definition.Inputs) };
            }
            var pending = steps.Values.Any(s => s.State == PlaybookStepState.Pending); var failed = steps.Values.Any(s => s.State == PlaybookStepState.Failed); var state = pending ? PlaybookExecutionState.Running : failed ? PlaybookExecutionState.Partial : PlaybookExecutionState.Succeeded; return await Save(x with { State = state, CompletedAt = pending ? null : DateTimeOffset.UtcNow, Steps = Order(p, steps), Result = pending ? "running" : failed ? "failure-branch-completed" : x.Mode is PlaybookMode.Simulation or PlaybookMode.DryRun ? "simulated-zero-mutation" : "completed" }, pending ? "playbook.execution.advanced" : failed ? "playbook.execution.partial" : "playbook.execution.succeeded", "orchestrator", ct);
        }
        finally { gate.Release(); }
    }
    public async Task<PlaybookExecution> ApproveAsync(string tenant, Guid id, string actor, PlaybookApprovalRequest request, IPlaybookActionExecutor executor, CancellationToken ct) { var x = await GetExecutionAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); var s = x.Steps.SingleOrDefault(y => y.StepId == request.StepId) ?? throw new KeyNotFoundException(); if (s.State != PlaybookStepState.WaitingForApproval || s.ApprovalExpiresAt <= DateTimeOffset.UtcNow || s.InputHash != request.InputHash || actor == x.Requester) throw new EnrollmentConflictException("PLAYBOOK_APPROVAL_INVALID", "Approval is stale, forged, reused, self-approved, or parameter-mismatched."); var steps = x.Steps.Select(y => y.StepId == s.StepId ? y with { State = PlaybookStepState.Pending, Approver = actor, Message = request.Reason } : y).ToArray(); await PersistExecutionAsync(AddAudit(x with { State = PlaybookExecutionState.Running, Steps = steps, Revision = x.Revision + 1 }, s.StepId, "playbook.approved", actor, request.Reason), ct); return await AdvanceAsync(tenant, id, executor, ct); }
    public async Task<PlaybookExecution> DenyAsync(string tenant, Guid id, string actor, PlaybookApprovalRequest request, CancellationToken ct) { var x = await GetExecutionAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); var s = x.Steps.SingleOrDefault(y => y.StepId == request.StepId) ?? throw new KeyNotFoundException(); if (s.State != PlaybookStepState.WaitingForApproval || s.InputHash != request.InputHash) throw new EnrollmentConflictException("PLAYBOOK_APPROVAL_INVALID", "Denial binding is invalid."); return await Save(x with { State = PlaybookExecutionState.Cancelled, CompletedAt = DateTimeOffset.UtcNow, Steps = x.Steps.Select(y => y.StepId == s.StepId ? y with { State = PlaybookStepState.Cancelled, Approver = actor, CompletedAt = DateTimeOffset.UtcNow, Message = request.Reason } : y).ToArray(), Result = "approval-denied" }, "playbook.approval.denied", actor, ct, s.StepId); }
    public async Task<PlaybookExecution> DecideAsync(string tenant, Guid id, string actor, PlaybookDecisionRequest request, IPlaybookActionExecutor executor, CancellationToken ct) { var allowed = new[] { "Continue", "Stop", "Escalate", "ResponseA", "ResponseB" }; var x = await GetExecutionAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); var s = x.Steps.SingleOrDefault(y => y.StepId == request.StepId) ?? throw new KeyNotFoundException(); if (s.State != PlaybookStepState.WaitingForAnalyst || s.PresentedStateHash != request.PresentedStateHash || !allowed.Contains(request.Decision, StringComparer.Ordinal) || string.IsNullOrWhiteSpace(request.Rationale) || request.Rationale.Length > 2048) throw new EnrollmentConflictException("PLAYBOOK_DECISION_INVALID", "Analyst decision is invalid or not bound to the presented state."); var stop = request.Decision == "Stop"; var steps = x.Steps.Select(y => y.StepId == s.StepId ? y with { State = stop ? PlaybookStepState.Cancelled : PlaybookStepState.Succeeded, CompletedAt = DateTimeOffset.UtcNow, Decision = request.Decision, DecisionRationale = request.Rationale } : y).ToArray(); await PersistExecutionAsync(AddAudit(x with { State = stop ? PlaybookExecutionState.Cancelled : PlaybookExecutionState.Running, CompletedAt = stop ? DateTimeOffset.UtcNow : null, Steps = steps, Revision = x.Revision + 1 }, s.StepId, "playbook.analyst-decision", actor, request.Decision), ct); return stop ? (await GetExecutionAsync(tenant, id, ct))! : await AdvanceAsync(tenant, id, executor, ct); }
    public async Task<PlaybookExecution> CancelAsync(string tenant, Guid id, string actor, string reason, CancellationToken ct) { var x = await GetExecutionAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); if (Terminal(x.State) || string.IsNullOrWhiteSpace(reason)) throw new EnrollmentConflictException("PLAYBOOK_CANCEL_INVALID", "Execution cannot be cancelled."); return await Save(x with { State = PlaybookExecutionState.Cancelled, CompletedAt = DateTimeOffset.UtcNow, Steps = x.Steps.Select(s => s.State is PlaybookStepState.Pending or PlaybookStepState.WaitingForApproval or PlaybookStepState.WaitingForAnalyst ? s with { State = PlaybookStepState.Cancelled, CompletedAt = DateTimeOffset.UtcNow } : s).ToArray(), Result = reason }, "playbook.execution.cancelled", actor, ct); }
    public async Task<PlaybookHealth> HealthAsync(string tenant, CancellationToken ct) { var p = await LoadDefinitionsAsync(tenant, ct); var e = await LoadExecutionsAsync(tenant, ct); long C(PlaybookExecutionState s) => e.LongCount(x => x.State == s); var complete = e.Where(x => x.CompletedAt is not null).ToArray(); return new(p.LongCount(x => x.State == PlaybookState.Active), e.Count, C(PlaybookExecutionState.Running), C(PlaybookExecutionState.WaitingForApproval), C(PlaybookExecutionState.Succeeded), C(PlaybookExecutionState.Partial), C(PlaybookExecutionState.Failed), C(PlaybookExecutionState.Cancelled), C(PlaybookExecutionState.TimedOut), e.Sum(x => x.Steps.LongCount(s => s.Attempt > 1)), e.Sum(x => x.Steps.LongCount(s => s.State == PlaybookStepState.Succeeded && s.Approver is null && s.Type is PlaybookStepType.StructuredResponse or PlaybookStepType.Collection)), e.Sum(x => x.Steps.LongCount(s => s.Approver is not null)), e.Sum(x => x.AuditHistory.LongCount(a => a.Action.Contains("rejected", StringComparison.Ordinal))), C(PlaybookExecutionState.Pending) + C(PlaybookExecutionState.Running), complete.Length == 0 ? 0 : complete.Average(x => (x.CompletedAt!.Value - x.StartedAt).TotalMilliseconds), DateTimeOffset.UtcNow); }
    static string StepHash(PlaybookStep step, PlaybookStartRequest request) => PlaybookSafety.Hash(new { step.StepId, step.Type, step.Inputs, request.EndpointId, request.TargetEntityId, request.ExpectedInstallationId });
    static JsonElement Parameters(IReadOnlyDictionary<string, string?> values, IReadOnlyDictionary<string, string?> sourceFields) { if (sourceFields.GetValueOrDefault("actionParametersJson") is { } json) { using var document = JsonDocument.Parse(json); if (document.RootElement.ValueKind != JsonValueKind.Object) throw new EnrollmentConflictException("PLAYBOOK_ACTION_PARAMETERS", "Action parameters must be an object."); return document.RootElement.Clone(); } var copy = values.Where(x => x.Key is not ("actionType" or "fixtureOutcome" or "currentInstallationId")).ToDictionary(x => x.Key, x => x.Value); return JsonSerializer.SerializeToElement(copy, PlaybookSafety.Json); }
    static PlaybookCondition? ReadCondition(IReadOnlyDictionary<string, string?> values) => values.TryGetValue("field", out var f) && f is not null ? new(f, Enum.TryParse<PlaybookConditionOperator>(values.GetValueOrDefault("operator"), true, out var op) ? op : PlaybookConditionOperator.Exists, values.GetValueOrDefault("value") is { } v ? [v] : []) : null;
    static PlaybookStepExecution[] Order(PlaybookDefinition p, Dictionary<string, PlaybookStepExecution> steps) => p.Steps.Select(x => steps[x.StepId]).ToArray();
    static bool Terminal(PlaybookExecutionState s) => s is PlaybookExecutionState.Succeeded or PlaybookExecutionState.Partial or PlaybookExecutionState.Failed or PlaybookExecutionState.Cancelled or PlaybookExecutionState.TimedOut or PlaybookExecutionState.Expired;
    static PlaybookAuditEvent Audit(string tenant, Guid id, string? step, string action, string actor, string reason) => new(Guid.NewGuid(), tenant, id, step, action, actor, DateTimeOffset.UtcNow, PlaybookSafety.Hash(new { id, step, action, reason }), reason);
    static PlaybookExecution AddAudit(PlaybookExecution x, string? step, string action, string actor, string reason) => x with { AuditHistory = x.AuditHistory.Concat([Audit(x.TenantId, x.ExecutionId, step, action, actor, reason)]).ToArray() };
    async Task<PlaybookExecution> HandleFailure(PlaybookExecution x, PlaybookDefinition p, PlaybookStep definition, Dictionary<string, PlaybookStepExecution> steps, PlaybookActionResult result, CancellationToken ct)
    {
        var current = steps[definition.StepId];
        var maximumAttempts = definition.Retry?.MaximumAttempts ?? p.RetryPolicy.MaximumAttempts;
        if (!result.Partial && current.Attempt < maximumAttempts)
        {
            steps[definition.StepId] = current with { State = PlaybookStepState.Pending, CompletedAt = null, Message = $"retry-scheduled:{current.Attempt}/{maximumAttempts}" };
            return await Save(x with { State = PlaybookExecutionState.Running, Steps = Order(p, steps), Result = "bounded-retry-scheduled" }, "playbook.step.retry-scheduled", "orchestrator", ct, definition.StepId);
        }
        if (definition.FailureNext is { } failureNext)
        {
            foreach (var pending in steps.Values.Where(s => s.State == PlaybookStepState.Pending && s.StepId != failureNext).ToArray()) steps[pending.StepId] = pending with { State = PlaybookStepState.Skipped, CompletedAt = DateTimeOffset.UtcNow, Message = "not-selected-after-failure" };
            return await Save(x with { State = PlaybookExecutionState.Running, Steps = Order(p, steps), Result = $"failure-branch:{failureNext}" }, "playbook.failure-branch.selected", "orchestrator", ct, definition.StepId);
        }
        return await Save(x with { State = result.Partial ? PlaybookExecutionState.Partial : PlaybookExecutionState.Failed, CompletedAt = DateTimeOffset.UtcNow, Steps = Order(p, steps), Result = result.Message }, result.Partial ? "playbook.execution.partial" : "playbook.execution.failed", "orchestrator", ct, definition.StepId);
    }
    async Task<PlaybookExecution> Save(PlaybookExecution x, string action, string actor, CancellationToken ct, string? step = null) { var value = AddAudit(x with { Revision = x.Revision + 1 }, step, action, actor, x.Result ?? action); await PersistExecutionAsync(value, ct); return value; }
    public void Dispose() { gate.Dispose(); GC.SuppressFinalize(this); }
}

public static class PlaybookStarterPack
{
    public static PlaybookDefinition[] Create(string tenant, string author)
    {
        PlaybookDefinition P(string key, string name, PlaybookTriggerType trigger, string source, PlaybookRisk risk, params PlaybookStep[] steps) { var now = DateTimeOffset.UtcNow; var p = new PlaybookDefinition("playbook.v1", PlaybookSafety.StableId(tenant, "starter", key), 1, tenant, name, $"Repository-controlled {name} starter playbook.", PlaybookState.Draft, author, now, now, null, null, [new(trigger, [source])], [source], steps, new Dictionary<string, string> { ["endpointId"] = "uuid", ["targetEntityId"] = "stable-identity" }, ["playbook:execute"], 900, 32, 4, 2, new(1), new(true, risk == PlaybookRisk.Critical), true, true, risk, ""); return p with { VersionHash = PlaybookSafety.DefinitionHash(p) }; }
        PlaybookStep S(string id, PlaybookStepType type, string[] dependencies, string? action = null, PlaybookRisk risk = PlaybookRisk.Low, string? outcome = null) { var inputs = new Dictionary<string, string?>(); if (action is not null) inputs["actionType"] = action; if (outcome is not null) inputs["fixtureOutcome"] = outcome; return new(id, type, id.Replace('-', ' '), dependencies, inputs, Approval: action is not null && risk >= PlaybookRisk.High ? new(true, risk == PlaybookRisk.Critical) : null); }
        return
        [
            P("malware-triage", "Malware triage recommendation", PlaybookTriggerType.AlertCreated, "alert", PlaybookRisk.High, S("endpoint-status",PlaybookStepType.StructuredResponse,[],"endpoint.status"),S("quick-triage",PlaybookStepType.StructuredResponse,["endpoint-status"],"process.list"),S("analyst-approval",PlaybookStepType.ApprovalGate,["quick-triage"]),S("quarantine",PlaybookStepType.StructuredResponse,["analyst-approval"],"file.quarantine",PlaybookRisk.High)),
            P("malicious-file", "Confirmed malicious file", PlaybookTriggerType.DetectionFinding, "finding", PlaybookRisk.High, S("verify-identity",PlaybookStepType.EvidenceVerification,[]),S("quarantine",PlaybookStepType.StructuredResponse,["verify-identity"],"file.quarantine",PlaybookRisk.High),S("verify",PlaybookStepType.EvidenceVerification,["quarantine"]),S("update-alert",PlaybookStepType.AlertUpdate,["verify"])),
            P("containment", "Endpoint containment", PlaybookTriggerType.CorrelatedFinding, "correlation", PlaybookRisk.Critical, S("quality",PlaybookStepType.Condition,[]),S("isolate",PlaybookStepType.StructuredResponse,["quality"],"endpoint.isolate",PlaybookRisk.Critical),S("verify",PlaybookStepType.StructuredResponse,["isolate"],"endpoint.isolation_status"),S("triage",PlaybookStepType.Collection,["verify"],"collect.diagnostic",PlaybookRisk.Medium),S("incident",PlaybookStepType.IncidentUpdate,["triage"])),
            P("persistence", "Persistence remediation", PlaybookTriggerType.IncidentCreated, "incident", PlaybookRisk.High, S("backup",PlaybookStepType.Collection,[],"forensic.collect",PlaybookRisk.Medium),S("remediate",PlaybookStepType.StructuredResponse,["backup"],"persistence.remove",PlaybookRisk.High),S("verify",PlaybookStepType.StructuredResponse,["remediate"],"persistence.remediation_status"),S("incident",PlaybookStepType.IncidentUpdate,["verify"])),
            P("tunnel", "Tunnel investigation", PlaybookTriggerType.TunnelFinding, "tunnel-finding", PlaybookRisk.Critical, S("endpoint-status",PlaybookStepType.StructuredResponse,[],"endpoint.status"),S("network-status",PlaybookStepType.StructuredResponse,["endpoint-status"],"network.connections"),S("decision",PlaybookStepType.AnalystDecision,["network-status"]),S("isolate",PlaybookStepType.StructuredResponse,["decision"],"endpoint.isolate",PlaybookRisk.Critical)),
            P("ioc", "IOC investigation", PlaybookTriggerType.IocMatch, "ioc-match", PlaybookRisk.Low, S("validate-ioc",PlaybookStepType.Condition,[]),S("evidence",PlaybookStepType.Collection,["validate-ioc"],"collect.diagnostic",PlaybookRisk.Medium),S("incident",PlaybookStepType.IncidentUpdate,["evidence"]),S("decision",PlaybookStepType.AnalystDecision,["incident"]))
        ];
    }
    public static PlaybookFixtureResult[] PassingFixtures() => new[] { "happy-path", "negative-no-action", "approval-denied", "action-failure", "partial-result", "endpoint-offline", "target-identity-mismatch", "cancellation", "restart", "duplicate-trigger" }.Select(x => new PlaybookFixtureResult(x, x, true, "safe deterministic result", "safe deterministic result", true, DateTimeOffset.UtcNow, [$"controlled://fixture/{x}"])).ToArray();
}
