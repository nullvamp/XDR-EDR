using System.Collections.Concurrent;

namespace OpenSecurityPlatform.Foundation;

public sealed class FileDetectionRepository : IDetectionRepository, IDetectionProjection
{
    readonly object _gate = new();
    readonly List<DetectionDefinition> _rules = [];
    readonly List<DetectionAssignment> _assignments = [];
    readonly List<DetectionExclusion> _exclusions = [];
    readonly Dictionary<string, List<(string Name, string Kind, DetectionRuleTestResult Result)>> _tests = [];
    readonly Dictionary<string, DetectionEvidenceEvent> _windows = [];
    readonly HashSet<string> _processed = [];
    readonly List<DetectionFinding> _findings = [];
    readonly ConcurrentDictionary<string, DetectionRun> _runs = new();
    long _events, _ruleEvaluations, _matches, _suppressed, _excluded, _missing;

    public Task<IReadOnlyList<DetectionDefinition>> ListRulesAsync(string tenant, CancellationToken ct) { lock (_gate) return Task.FromResult<IReadOnlyList<DetectionDefinition>>(_rules.Where(x => x.TenantId == tenant).GroupBy(x => x.DetectionId).Select(x => x.MaxBy(v => v.DetectionVersion)!).OrderBy(x => x.Name).ToArray()); }
    public Task<IReadOnlyList<DetectionDefinition>> RuleHistoryAsync(string tenant, Guid id, CancellationToken ct) { lock (_gate) return Task.FromResult<IReadOnlyList<DetectionDefinition>>(_rules.Where(x => x.TenantId == tenant && x.DetectionId == id).OrderByDescending(x => x.DetectionVersion).ToArray()); }
    public Task<DetectionDefinition?> GetRuleAsync(string tenant, Guid id, int? version, CancellationToken ct) { lock (_gate) return Task.FromResult(_rules.Where(x => x.TenantId == tenant && x.DetectionId == id && (version is null || x.DetectionVersion == version)).MaxBy(x => x.DetectionVersion)); }
    public Task<DetectionDefinition> CreateRuleAsync(string tenant, string actor, DetectionDefinition definition, CancellationToken ct)
    {
        lock (_gate) { if (_rules.Any(x => x.TenantId == tenant && (x.DetectionId == definition.DetectionId || x.Name == definition.Name))) throw new EnrollmentConflictException("DETECTION_EXISTS", "Detection identity or name already exists in this tenant."); var value = Normalize(tenant, actor, definition, definition.DetectionId == Guid.Empty ? Guid.NewGuid() : definition.DetectionId, 1); _rules.Add(value); return Task.FromResult(value); }
    }
    public Task<DetectionDefinition> CreateVersionAsync(string tenant, string actor, Guid id, DetectionDefinition definition, CancellationToken ct)
    {
        lock (_gate) { var history = _rules.Where(x => x.TenantId == tenant && x.DetectionId == id).ToArray(); if (history.Length == 0) throw new KeyNotFoundException(); var value = Normalize(tenant, actor, definition, id, history.Max(x => x.DetectionVersion) + 1); _rules.Add(value); return Task.FromResult(value); }
    }
    public Task<DetectionDefinition> RecordValidationAsync(string tenant, Guid id, int version, IReadOnlyDictionary<string, string[]> errors, CancellationToken ct)
    {
        lock (_gate) { var index = _rules.FindIndex(x => x.TenantId == tenant && x.DetectionId == id && x.DetectionVersion == version); if (index < 0) throw new KeyNotFoundException(); var old = _rules[index]; var value = old with { LastValidationPassed = errors.Count == 0, LastValidatedAt = DateTimeOffset.UtcNow, Status = errors.Count == 0 ? DetectionRuleStatus.Testing : DetectionRuleStatus.Draft }; _rules[index] = value; return Task.FromResult(value); }
    }
    public Task RecordTestsAsync(string tenant, Guid id, int version, IReadOnlyList<(DetectionRuleTestCase Test, DetectionRuleTestResult Result)> tests, CancellationToken ct) { lock (_gate) _tests[$"{tenant}:{id}:{version}"] = tests.Select(x => (x.Test.Name, x.Test.Kind, x.Result)).ToList(); return Task.CompletedTask; }
    public Task<IReadOnlyList<(string Name, string Kind, DetectionRuleTestResult Result)>> ListTestsAsync(string tenant, Guid id, int version, CancellationToken ct) { lock (_gate) return Task.FromResult<IReadOnlyList<(string, string, DetectionRuleTestResult)>>(_tests.GetValueOrDefault($"{tenant}:{id}:{version}", []).ToArray()); }
    public Task<DetectionDefinition> ActivateAsync(string tenant, string actor, Guid id, int version, CancellationToken ct)
    {
        lock (_gate) { var index = _rules.FindIndex(x => x.TenantId == tenant && x.DetectionId == id && x.DetectionVersion == version); if (index < 0) throw new KeyNotFoundException(); var tests = _tests.GetValueOrDefault($"{tenant}:{id}:{version}", []); if (!_rules[index].LastValidationPassed || tests.Count == 0 || tests.Any(x => !x.Result.Passed)) throw new EnrollmentConflictException("DETECTION_ACTIVATION_BLOCKED", "Validation and every required fixture must pass before activation."); for (var i = 0; i < _rules.Count; i++) if (_rules[i].TenantId == tenant && _rules[i].DetectionId == id && _rules[i].Status == DetectionRuleStatus.Active) _rules[i] = _rules[i] with { Status = DetectionRuleStatus.Disabled, Enabled = false, DeactivatedAt = DateTimeOffset.UtcNow }; var value = _rules[index] with { Status = DetectionRuleStatus.Active, Enabled = true, ActivatedAt = DateTimeOffset.UtcNow }; _rules[index] = value; return Task.FromResult(value); }
    }
    public Task<DetectionDefinition> DisableAsync(string tenant, string actor, Guid id, CancellationToken ct) { lock (_gate) { var index = _rules.FindLastIndex(x => x.TenantId == tenant && x.DetectionId == id); if (index < 0) throw new KeyNotFoundException(); var value = _rules[index] with { Status = DetectionRuleStatus.Disabled, Enabled = false, DeactivatedAt = DateTimeOffset.UtcNow }; _rules[index] = value; return Task.FromResult(value); } }
    public Task<DetectionAssignment> AssignAsync(string tenant, string actor, DetectionAssignment assignment, CancellationToken ct) { lock (_gate) { if (!_rules.Any(x => x.TenantId == tenant && x.DetectionId == assignment.DetectionId && x.DetectionVersion == assignment.DetectionVersion)) throw new EnrollmentConflictException("DETECTION_ASSIGNMENT_INVALID", "Rule version is not in this tenant."); var value = assignment with { Id = assignment.Id == Guid.Empty ? Guid.NewGuid() : assignment.Id, TenantId = tenant, CreatedAt = DateTimeOffset.UtcNow, CreatedBy = actor }; _assignments.Add(value); return Task.FromResult(value); } }
    public Task<DetectionExclusion> CreateExclusionAsync(string tenant, string actor, DetectionExclusion exclusion, CancellationToken ct) { ValidateExclusion(exclusion); lock (_gate) { var value = exclusion with { Id = exclusion.Id == Guid.Empty ? Guid.NewGuid() : exclusion.Id, TenantId = tenant, Version = 1, CreatedBy = actor }; _exclusions.Add(value); return Task.FromResult(value); } }
    public Task<IReadOnlyList<DetectionExclusion>> ListExclusionsAsync(string tenant, CancellationToken ct) { lock (_gate) return Task.FromResult<IReadOnlyList<DetectionExclusion>>(_exclusions.Where(x => x.TenantId == tenant).ToArray()); }

    public Task<DetectionEvaluationResult> EvaluateAsync(string tenant, DetectionEvidenceEvent evidence, DetectionExecutionMode mode, Guid? id, int? version, Guid? runId, bool production, CancellationToken ct)
    {
        lock (_gate)
        {
            if (evidence.TenantId != tenant) throw new EnrollmentConflictException("DETECTION_TENANT_MISMATCH", "Evidence tenant binding is invalid.");
            _events++;
            var rules = _rules.Where(x => x.TenantId == tenant && x.Domain == evidence.Domain && (id is null ? x.Status == DetectionRuleStatus.Active && x.Enabled : x.DetectionId == id && (version is null || x.DetectionVersion == version))).ToArray();
            DetectionEvaluationResult? last = null;
            foreach (var rule in rules)
            {
                var processed = $"{tenant}:{rule.DetectionId}:{rule.DetectionVersion}:{mode}:{runId}:{evidence.EventId}"; if (!_processed.Add(processed)) { last = new(true, false, false, DetectionDsl.Evaluate(rule, evidence), null, "duplicate-event"); continue; }
                _ruleEvaluations++; var evaluation = DetectionDsl.Evaluate(rule, evidence); _missing += evaluation.MissingFields.Length; if (!evaluation.Matched) { last = new(false, false, false, evaluation, null, "conditions-not-matched"); continue; }
                _matches++;
                var exclusion = _exclusions.Where(x => x.TenantId == tenant && rule.ExclusionReferences.Contains(x.Id)).FirstOrDefault(x => DetectionDsl.MatchesExclusion(x, evidence, evidence.EventTime));
                if (exclusion is not null) { _excluded++; last = new(false, true, false, evaluation, null, exclusion.Reason); continue; }
                var windowKey = $"{tenant}:{rule.DetectionId}:{rule.DetectionVersion}:{mode}:{runId}:{evaluation.GroupKey}"; if (rule.RuleType == DetectionRuleType.Threshold) _windows[$"{windowKey}:{evidence.EventId}"] = evidence;
                var start = evidence.EventTime.AddSeconds(-Math.Max(1, rule.WindowSeconds)); var candidates = rule.RuleType == DetectionRuleType.Threshold ? _windows.Where(x => x.Key.StartsWith(windowKey + ":", StringComparison.Ordinal) && x.Value.EventTime >= start && x.Value.EventTime <= evidence.EventTime).Select(x => x.Value).OrderBy(x => x.EventTime).ThenBy(x => x.EventId).ToArray() : [evidence];
                var count = rule.DistinctCount ? candidates.Select(x => x.Fields.GetValueOrDefault(rule.DistinctField!)).Where(x => x is not null).Distinct(StringComparer.Ordinal).Count() : candidates.Length;
                if (count != rule.Threshold) { last = new(false, false, false, evaluation, null, "threshold-not-crossed"); continue; }
                var suppressionScope = rule.Suppression.Scope switch { "detection+process" => evidence.ProcessEntityId, "detection+entity" => evidence.EntityId, _ => evidence.EndpointId?.ToString("D") }; var prior = rule.Suppression.DurationMinutes > 0 ? _findings.LastOrDefault(x => x.TenantId == tenant && x.DetectionId == rule.DetectionId && (x.EndpointId?.ToString("D") == suppressionScope || x.ProcessEntityId == suppressionScope || x.EntityId == suppressionScope) && x.CreatedAt >= evidence.EventTime.AddMinutes(-rule.Suppression.DurationMinutes)) : null; var suppressed = prior is not null; if (suppressed) _suppressed++;
                var ids = candidates.Select(x => x.EventId).ToArray(); var findingId = DetectionDsl.DeterministicId($"{tenant}:{rule.DetectionId}:{rule.DetectionVersion}:{mode}:{evaluation.GroupKey}:{string.Join(',', ids)}");
                var finding = new DetectionFinding(findingId, tenant, rule.DetectionId, rule.DetectionVersion, rule.Name, rule.Severity, rule.Confidence, candidates[0].EventTime, candidates[^1].EventTime, count, evaluation.GroupKey, evidence.EndpointId, evidence.ProcessEntityId, evidence.EntityId, ids, candidates.Select(x => x.EvidenceReference).ToArray(), evaluation.Conditions.Where(x => x.Matched).ToArray(), suppressed, suppressed ? "bounded-duplicate-suppression" : null, prior?.FindingId, false, null, DetectionDsl.EngineVersion, mode, candidates.SelectMany(x => x.Quality ?? []).Distinct().ToArray(), evaluation.MissingFields.Concat(candidates.SelectMany(x => x.MissingTelemetry ?? [])).Distinct().ToArray(), DateTimeOffset.UtcNow);
                if (production && mode == DetectionExecutionMode.Live && !suppressed) _findings.Add(finding); last = new(false, false, suppressed, evaluation, finding, suppressed ? "suppressed" : null);
            }
            return Task.FromResult(last ?? new DetectionEvaluationResult(false, false, false, new(false, [], [], "none"), null, "no-applicable-rule"));
        }
    }
    public Task<DetectionFindingPage> SearchFindingsAsync(string tenant, DetectionFindingQuery q, CancellationToken ct) { if (!string.IsNullOrWhiteSpace(q.Cursor)) throw new EnrollmentConflictException("DETECTION_CURSOR_INVALID", "Finding cursor is invalid or unsupported."); lock (_gate) { var values = _findings.Where(x => x.TenantId == tenant && (q.DetectionId is null || x.DetectionId == q.DetectionId) && (q.EndpointId is null || x.EndpointId == q.EndpointId) && (q.MinimumSeverity is null || x.Severity >= q.MinimumSeverity) && (q.Suppressed is null || x.Suppressed == q.Suppressed) && (q.Mode is null || x.ExecutionMode == q.Mode) && (q.From is null || x.CreatedAt >= q.From) && (q.To is null || x.CreatedAt <= q.To)).OrderByDescending(x => x.CreatedAt).ThenByDescending(x => x.FindingId).Take(Math.Clamp(q.PageSize, 1, 500)).ToArray(); return Task.FromResult(new DetectionFindingPage(values, null)); } }
    public Task<DetectionFinding?> GetFindingAsync(string tenant, Guid id, CancellationToken ct) { lock (_gate) return Task.FromResult(_findings.FirstOrDefault(x => x.TenantId == tenant && x.FindingId == id)); }
    public Task<IReadOnlyList<DetectionFindingHistory>> FindingHistoryAsync(string tenant, Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            var finding = _findings.FirstOrDefault(x => x.TenantId == tenant && x.FindingId == id);
            return Task.FromResult<IReadOnlyList<DetectionFindingHistory>>(finding is null ? [] : [new(1, "created", "system:detection-engine", finding.CreatedAt, finding)]);
        }
    }
    public Task<DetectionRun> CreateRunAsync(string tenant, DetectionRun run, DetectionDefinition snapshot, CancellationToken ct) { if (run.TenantId != tenant || run.To <= run.From || run.To - run.From > TimeSpan.FromDays(7)) throw new EnrollmentConflictException("DETECTION_REPLAY_BOUNDS", "Replay must be tenant-bound and no longer than seven days."); _runs[$"{tenant}:{run.Id}"] = run; return Task.FromResult(run); }
    public Task<DetectionRun> CompleteRunAsync(string tenant, Guid id, long evaluated, long matches, long findings, string status, CancellationToken ct) { if (!_runs.TryGetValue($"{tenant}:{id}", out var run)) throw new KeyNotFoundException(); var value = run with { Status = status, EventsEvaluated = evaluated, Matches = matches, Findings = findings, CompletedAt = DateTimeOffset.UtcNow }; _runs[$"{tenant}:{id}"] = value; return Task.FromResult(value); }
    public Task<DetectionRun?> GetRunAsync(string tenant, Guid id, CancellationToken ct) => Task.FromResult(_runs.GetValueOrDefault($"{tenant}:{id}"));
    public Task<DetectionRun> CancelRunAsync(string tenant, Guid id, CancellationToken ct) { if (!_runs.TryGetValue($"{tenant}:{id}", out var run)) throw new KeyNotFoundException(); var value = run with { Status = "cancelled", CompletedAt = DateTimeOffset.UtcNow }; _runs[$"{tenant}:{id}"] = value; return Task.FromResult(value); }
    public Task<DetectionHealth> HealthAsync(string tenant, CancellationToken ct) { lock (_gate) return Task.FromResult(new DetectionHealth(_events, _ruleEvaluations, _matches, _findings.Count(x => x.TenantId == tenant), _suppressed, _excluded, 0, 0, _missing, 0, _runs.Count(x => x.Key.StartsWith(tenant + ":", StringComparison.Ordinal) && x.Value.Status == "queued"), 0, 0, 0, DateTimeOffset.UtcNow)); }
    public Task EnsureAsync(CancellationToken ct) => Task.CompletedTask;
    public Task UpsertAsync(DetectionFinding finding, CancellationToken ct) { lock (_gate) if (_findings.All(x => x.FindingId != finding.FindingId)) _findings.Add(finding); return Task.CompletedTask; }
    public Task<long> CountAsync(string tenant, CancellationToken ct) { lock (_gate) return Task.FromResult((long)_findings.Count(x => x.TenantId == tenant)); }
    public Task<bool> HealthAsync(CancellationToken ct) => Task.FromResult(true);
    static DetectionDefinition Normalize(string tenant, string actor, DetectionDefinition value, Guid id, int version) { var now = DateTimeOffset.UtcNow; return value with { SchemaVersion = "detection-rule.v1", TenantId = tenant, DetectionId = id, DetectionVersion = version, Status = DetectionRuleStatus.Draft, Enabled = false, Author = actor, CreatedAt = now, UpdatedAt = now, LastValidationPassed = false, LastValidatedAt = null, ActivatedAt = null, DeactivatedAt = null }; }
    public static void ValidateExclusion(DetectionExclusion value) { if (string.IsNullOrWhiteSpace(value.Field) || string.IsNullOrWhiteSpace(value.Value) || value.Value.Trim() is "*" or "**" || value.EndsAt <= value.StartsAt || value.EndsAt - value.StartsAt > TimeSpan.FromDays(90)) throw new EnrollmentConflictException("DETECTION_EXCLUSION_INVALID", "Exclusions must be exact, bounded to 90 days and cannot match all values."); }
}
