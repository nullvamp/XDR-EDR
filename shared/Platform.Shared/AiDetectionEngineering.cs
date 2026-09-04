using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<AiProposalState>))]
public enum AiProposalState { AiProposed, Validated, Rejected, Executed, SavedDraft }
[JsonConverter(typeof(JsonStringEnumConverter<AiDraftKind>))]
public enum AiDraftKind { Detection, Correlation }
[JsonConverter(typeof(JsonStringEnumConverter<CoverageSupportLevel>))]
public enum CoverageSupportLevel { Covered, PartiallyCovered, TelemetryAvailableNoDetection, TelemetryInsufficient, NotObservableBySource, NotValidated }

public sealed record AiHuntProposal(Guid ProposalId, string SchemaVersion, string TenantId, string Analyst,
    string SourcePrompt, string PromptHash, string NormalizedIntent, HuntDefinition Hunt,
    string[] EvidenceCitations, string[] Explanation, string[] MayMiss, string[] FalsePositiveConsiderations,
    string[] ExpectedResultTypes, int EstimatedCost, AiProposalState State, string ProviderId, string ModelId,
    string EvidencePackageHash, string ProposalHash, DateTimeOffset CreatedAt, DateTimeOffset? ExecutedAt = null,
    Guid? HuntRunId = null, int? ResultCount = null);

public sealed record AiFixtureProposal(string Name, string Kind, DetectionEvidenceEvent Event,
    int ExpectedMatches, bool ExpectedValid, string ExpectedOutcome);
public sealed record AiDetectionScorecard(int TelemetryCompleteness, int FieldReliability, int IdentitySafety,
    int FalsePositiveValidation, int PositiveFixtureCoverage, int NegativeFixtureCoverage,
    int ReplayDeterminism, int HistoricalVolume, int AttackMappingValidation, int PerformanceCost,
    string[] Evidence);
public sealed record AiRuleReview(string[] Strengths, string[] Risks, string[] UnsupportedFields,
    string[] UnsafeIdentityAssumptions, string[] BroadExclusions, string[] Recommendations,
    string Explanation, bool ProductionSafeToReview);
public sealed record AiRuleDraft(Guid DraftId, string SchemaVersion, string TenantId, string Analyst,
    AiDraftKind Kind, string SourcePrompt, string PromptHash, DetectionDefinition? Detection,
    CorrelationRule? Correlation, AiFixtureProposal[] Fixtures, AiRuleReview Review,
    AiDetectionScorecard Scorecard, string[] EvidenceCitations, string[] KnownGaps,
    string[] FalsePositiveConsiderations, string[] RequiredTelemetry, string ProviderId, string ModelId,
    string EvidencePackageHash, string DraftHash, AiProposalState State, DateTimeOffset CreatedAt,
    DateTimeOffset? DecidedAt = null, string? DecidedBy = null, string? DecisionReason = null,
    Guid? RepositoryRuleId = null, int? RepositoryRuleVersion = null);

public sealed record AiHistoricalSimulation(Guid SimulationId, string TenantId, Guid DraftId,
    DateTimeOffset From, DateTimeOffset To, int MaximumEvents, int EventsScanned, int Matches,
    int EndpointCount, string[] ExampleEvidenceReferences, string[] UnsupportedFields,
    long RuntimeMilliseconds, int EstimatedAlertVolume, string[] FalsePositiveClusters,
    DateTimeOffset CompletedAt);
public sealed record AiRuleComparison(Guid ComparisonId, string TenantId, Guid DraftId,
    Guid CurrentRuleId, int CurrentVersion, int NewMatches, int LostMatches, int UnchangedMatches,
    int AlertVolumeDelta, int EndpointImpact, int TenantImpact, int SeverityImpact,
    int ExcludedEvidenceImpact, DateTimeOffset CompletedAt);
public sealed record AiCoverageRecord(string Tactic, string Technique, string? SubTechnique,
    Guid[] RuleIds, Guid[] CorrelationIds, DetectionDomain[] TelemetrySources, string[] RequiredFields,
    CoverageSupportLevel SupportLevel, string ValidationStatus, string[] KnownLimitations,
    string[] EvidenceFixtures, DateTimeOffset? LastValidated, string EvidenceBasis);
public sealed record AiEngineeringAudit(Guid AuditId, string TenantId, string Actor, string Action,
    string ObjectType, Guid ObjectId, string ObjectHash, DateTimeOffset OccurredAt,
    IReadOnlyDictionary<string, string?> Detail);

public interface IAiEngineeringRepository
{
    Task<AiHuntProposal> SaveHuntAsync(AiHuntProposal value, CancellationToken ct);
    Task<AiHuntProposal?> HuntAsync(string tenant, Guid id, CancellationToken ct);
    Task<IReadOnlyList<AiHuntProposal>> HuntsAsync(string tenant, int limit, CancellationToken ct);
    Task<AiHuntProposal> UpdateHuntAsync(string tenant, Guid id, Func<AiHuntProposal, AiHuntProposal> update, CancellationToken ct);
    Task<AiRuleDraft> SaveDraftAsync(AiRuleDraft value, CancellationToken ct);
    Task<AiRuleDraft?> DraftAsync(string tenant, Guid id, CancellationToken ct);
    Task<IReadOnlyList<AiRuleDraft>> DraftsAsync(string tenant, int limit, CancellationToken ct);
    Task<AiRuleDraft> UpdateDraftAsync(string tenant, Guid id, Func<AiRuleDraft, AiRuleDraft> update, CancellationToken ct);
    Task SaveSimulationAsync(AiHistoricalSimulation value, CancellationToken ct);
    Task<AiHistoricalSimulation?> SimulationAsync(string tenant, Guid id, CancellationToken ct);
    Task SaveComparisonAsync(AiRuleComparison value, CancellationToken ct);
    Task RecordAuditAsync(AiEngineeringAudit value, CancellationToken ct);
    Task<IReadOnlyList<AiEngineeringAudit>> AuditAsync(string tenant, int limit, CancellationToken ct);
}

public static partial class AiEngineeringSafety
{
    public const int MaximumPromptCharacters = 4000;
    public const int MaximumHistoricalEvents = 10_000;
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    static readonly HashSet<string> VerifiedAttackTechniques = new(StringComparer.Ordinal)
    {
        "T1018", "T1053.005", "T1055", "T1059.001", "T1059.003", "T1060", "T1071.004",
        "T1078", "T1110", "T1204", "T1204.002", "T1543.003", "T1546.012", "T1562.001",
        "T1572", "T1574.002"
    };
    [GeneratedRegex(@"\b(?:select\s+.+\s+from|insert\s+into|update\s+.+\s+set|delete\s+from|_search\b|\$where|curl\b|cmd\.exe\s+/c|powershell(?:\.exe)?\s+-|invoke-expression|start-process)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex ExecutableSyntax();
    [GeneratedRegex(@"\b(?:auto[- ]?activate|disable\s+all\s+alerts|isolate\s+automatically|execute\s+live\s+response|bypass\s+tenant)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)] private static partial Regex ForbiddenIntent();
    [GeneratedRegex(@"(?i)exact\s+path\s+['""]?([^'""\r\n]{3,512})['""]?")] private static partial Regex ExactPathIntent();
    [GeneratedRegex(@"\b[a-fA-F0-9]{64}\b", RegexOptions.CultureInvariant)] private static partial Regex Sha256Intent();
    [GeneratedRegex(@"(?i)\b(?:domain|dns)\s+['""]?([a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])?)['""]?")] private static partial Regex DomainIntent();

    public static string Prompt(string value)
    {
        var prompt = AiInvestigationSafety.Question(value);
        if (ExecutableSyntax().IsMatch(prompt) || ForbiddenIntent().IsMatch(prompt))
            throw new EnrollmentConflictException("AI_ENGINEERING_UNSAFE_INTENT", "Arbitrary query, code, execution, tenant bypass, activation, or response intent is prohibited.");
        return prompt;
    }

    public static AiHuntProposal TranslateHunt(string tenant, string actor, string prompt,
        string[] citations, string evidencePackageHash, string provider = "local-evidence", string model = "local-evidence-v1")
    {
        prompt = Prompt(prompt); var now = DateTimeOffset.UtcNow; InvestigationEntityType[] types;
        HuntClause where; string[] joins = []; string normalized; string[] mayMiss;
        if (ExactPathIntent().Match(prompt) is { Success: true } path)
        {
            types = [InvestigationEntityType.Process]; where = Clause("path", HuntOperator.Equal, path.Groups[1].Value.Trim()); normalized = "exact process path"; mayMiss = ["Path normalization differences or unavailable path telemetry."];
        }
        else if (Sha256Intent().Match(prompt) is { Success: true } hash)
        {
            types = [InvestigationEntityType.File, InvestigationEntityType.Module]; where = Clause("sha256", HuntOperator.Equal, hash.Value.ToLowerInvariant()); normalized = "exact SHA-256 match"; mayMiss = ["Objects not hashed or telemetry outside the selected window."];
        }
        else if (DomainIntent().Match(prompt) is { Success: true } domain)
        {
            types = [InvestigationEntityType.Dns]; where = Clause("dnsName", HuntOperator.Equal, domain.Groups[1].Value.ToLowerInvariant()); normalized = "exact canonical DNS name"; mayMiss = ["Queries without process attribution or outside the selected window."];
        }
        else if (prompt.Contains("powershell", StringComparison.OrdinalIgnoreCase))
        {
            types = [InvestigationEntityType.Process]; where = Clause("path", HuntOperator.Contains, "powershell"); joins = ["parent-of"]; normalized = "PowerShell process with bounded ancestry pivot"; mayMiss = ["Parent executable name is not expressible as a same-row condition; inspect the bounded parent-of pivot."];
        }
        else if (prompt.Contains("persistence", StringComparison.OrdinalIgnoreCase))
        {
            types = [InvestigationEntityType.Persistence]; where = new(HuntBoolean.And, new("kind", HuntOperator.Exists, ["true"])); normalized = "persistence entities"; mayMiss = ["Persistence sources not observable or not collected."];
        }
        else throw new EnrollmentConflictException("AI_HUNT_NOT_EXPRESSIBLE", "NOT EXPRESSIBLE BY CURRENT DSL: the intent cannot be translated without arbitrary query behavior.");
        var id = Guid.NewGuid(); var hunt = new HuntDefinition("threat-hunt.v1", id, 1, tenant, $"AI proposed: {normalized}", "AI-proposed bounded hunt; analyst execution required.", types, now.AddDays(-7), now, where, 200, 5_000, joins.Length == 0 ? 0 : 1, joins, false, actor, [], now);
        var validation = InvestigationSafety.Validate(hunt); if (!validation.Valid) throw new EnrollmentConflictException("AI_HUNT_INVALID", string.Join(' ', validation.Errors.Values.SelectMany(x => x)));
        var value = new AiHuntProposal(id, "ai-hunt-proposal.v1", tenant, actor, prompt, Hash(prompt), normalized, hunt, citations.Distinct().Take(50).ToArray(), [$"Translate '{normalized}' into allowlisted threat-hunt.v1 predicates.", "Preview and explicit analyst execution are mandatory."], mayMiss, ["Legitimate activity matching the same exact fields or relationships."], types.Select(x => x.ToString()).ToArray(), validation.EstimatedCost, AiProposalState.Validated, provider, model, evidencePackageHash, "", now);
        return value with { ProposalHash = Hash(value with { ProposalHash = "" }) };
    }

    public static AiRuleDraft DraftDetection(string tenant, string actor, string prompt, DetectionDomain domain,
        string field, DetectionOperator op, string value, string technique, string[] citations,
        string evidencePackageHash, string provider = "local-evidence", string model = "local-evidence-v1")
    {
        prompt = Prompt(prompt); if (!VerifiedTechnique(technique)) throw new EnrollmentConflictException("AI_ATTACK_MAPPING_UNVERIFIED", "The ATT&CK mapping is not in the platform-verified technique inventory.");
        if (!DetectionDsl.AllowedFields(domain).Contains(field, StringComparer.Ordinal)) throw new EnrollmentConflictException("AI_DRAFT_UNSUPPORTED_FIELD", "NOT EXPRESSIBLE BY CURRENT DSL: the requested field is unavailable.");
        if (op == DetectionOperator.Glob && value is "*" or "**") throw new EnrollmentConflictException("AI_DRAFT_BROAD_MATCH", "Match-all detection logic is prohibited.");
        var now = DateTimeOffset.UtcNow; var id = Guid.NewGuid(); var condition = new DetectionCondition(Field: field, Operator: op, Value: value, CaseInsensitive: true);
        var rule = new DetectionDefinition("detection-rule.v1", id, 1, tenant, $"AI proposed {domain} {field} {id:N}", "AI-proposed draft; untrusted until explicit engineer review.", DetectionRuleStatus.Draft, false, actor, now, now, 50, 50, "ai-proposed", ["ai-proposed"], ["Discovery"], [technique], [domain.ToString()], DetectionRuleType.Event, domain, [], [field], 0, ["endpointId"], 1, false, null, condition, DetectionExecutionMode.Simulation, new(), [], "ai-fixture-proposal.v1", false);
        var errors = DetectionDsl.Validate(rule); if (errors.Count > 0) throw new EnrollmentConflictException("AI_DRAFT_COMPILE_FAILED", string.Join(' ', errors.Values.SelectMany(x => x)));
        var fixtures = Fixtures(rule); var review = Review(rule); var score = Score(rule, fixtures, review); var draft = new AiRuleDraft(id, "ai-rule-draft.v1", tenant, actor, AiDraftKind.Detection, prompt, Hash(prompt), rule, null, fixtures, review, score, citations.Distinct().Take(50).ToArray(), ["Historical environment-specific false-positive behavior requires simulation and analyst review."], ["Frequency alone does not establish benign intent."], [domain.ToString()], provider, model, evidencePackageHash, "", AiProposalState.Validated, now);
        return draft with { DraftHash = Hash(draft with { DraftHash = "" }) };
    }

    public static AiRuleDraft DraftCorrelation(string tenant, string actor, string prompt, CorrelationType type,
        DetectionDomain first, DetectionDomain second, string joinKey, string technique, string[] citations,
        string evidencePackageHash, string provider = "local-evidence", string model = "local-evidence-v1")
    {
        prompt = Prompt(prompt); if (!VerifiedTechnique(technique)) throw new EnrollmentConflictException("AI_ATTACK_MAPPING_UNVERIFIED", "The ATT&CK mapping is not in the platform-verified technique inventory.");
        if (joinKey is not ("endpointId" or "processEntityId" or "entityId" or "user")) throw new EnrollmentConflictException("AI_CORRELATION_JOIN_UNSAFE", "Correlation join key is not allowlisted or identity-safe.");
        var now = DateTimeOffset.UtcNow; var id = Guid.NewGuid(); var pack = CorrelationDsl.DeterministicId(tenant + ":ai-drafts"); var exists = new DetectionCondition(Field: joinKey, Operator: DetectionOperator.Exists);
        var rule = new CorrelationRule("correlation-rule.v1", id, 1, tenant, pack, 1, $"AI proposed {first} to {second} {id:N}", "AI-proposed correlation draft; explicit review required.", 50, 50, "ai-proposed", ["ai-proposed"], "Discovery", technique, null, [first, second], [], joinKey, type, 900, [joinKey], [new("first", 1, CorrelationInputKind.Event, first, exists), new("second", 2, CorrelationInputKind.Event, second, exists)], new(), [], new("Evidence-driven bounded sequence.", ["Expected administrative sequences."], "Constrain exact identity and simulate historically.", ["Shared infrastructure."], "Unvalidated AI proposal.", ["Source fields may be incomplete."]), CorrelationStatus.Draft, false, false, null, now, actor);
        var errors = CorrelationDsl.Validate(rule); if (errors.Count > 0) throw new EnrollmentConflictException("AI_CORRELATION_COMPILE_FAILED", string.Join(' ', errors.Values.SelectMany(x => x)));
        var review = new AiRuleReview(["Existing bounded correlation types and identity-safe join."], ["Historical ordering and benign administration require validation."], [], [], [], ["Run bounded simulation before repository save."], "Draft compiles but remains inactive and unvalidated.", true); var score = new AiDetectionScorecard(50, 50, 80, 0, 0, 0, 100, 0, ValidTechnique(technique) ? 100 : 0, 70, ["Existing correlation validator passed."]);
        var draft = new AiRuleDraft(id, "ai-rule-draft.v1", tenant, actor, AiDraftKind.Correlation, prompt, Hash(prompt), null, rule, [], review, score, citations.Distinct().Take(50).ToArray(), ["No production fixtures or historical validation yet."], ["Frequency and sequence alone do not establish malicious intent."], [first.ToString(), second.ToString()], provider, model, evidencePackageHash, "", AiProposalState.Validated, now);
        return draft with { DraftHash = Hash(draft with { DraftHash = "" }) };
    }

    public static AiRuleReview Review(DetectionDefinition rule)
    {
        var risks = new List<string>(); var unsupported = DetectionDsl.Validate(rule).GetValueOrDefault("fields") ?? [];
        var identity = new List<string>(); if (rule.RequiredFields.Contains("pid", StringComparer.OrdinalIgnoreCase) && !rule.RequiredFields.Contains("processEntityId", StringComparer.OrdinalIgnoreCase)) identity.Add("PID-only identity is unsafe across reuse.");
        if (rule.Condition.Operator == DetectionOperator.Glob && rule.Condition.Value is "*" or "**") risks.Add("Match-all logic creates uncontrolled false positives.");
        if (rule.GroupBy.Length == 0) risks.Add("Missing grouping may merge unrelated endpoints or entities.");
        if (rule.WindowSeconds > 86_400) risks.Add("Large time window increases state and false-positive cost.");
        return new(["Uses the bounded detection-rule.v1 contract."], [.. risks], unsupported, [.. identity], [], ["Use stable entity/endpoint grouping.", "Validate positive, negative, boundary, benign, missing-field, malformed, replay, and tenant cases."], risks.Count + unsupported.Length + identity.Count == 0 ? "No deterministic structural blocker; historical validation remains required." : "Structural risks require engineer remediation.", unsupported.Length == 0 && identity.Count == 0);
    }

    public static AiFixtureProposal[] Fixtures(DetectionDefinition rule)
    {
        var now = DateTimeOffset.UtcNow; var endpoint = Guid.NewGuid(); var matching = rule.Condition.Value ?? rule.Condition.Values?.FirstOrDefault() ?? "fixture";
        DetectionEvidenceEvent E(string kind, string? actual, string tenant, bool incomplete = false) => new(Guid.NewGuid(), tenant, rule.Domain, now, endpoint, "stable-process-fixture", "entity-fixture", actual is null ? new Dictionary<string, string?>() : new Dictionary<string, string?> { [rule.Condition.Field!] = actual, ["endpointId"] = endpoint.ToString("D") }, $"fixture://sprint31/{kind}", Incomplete: incomplete, MissingTelemetry: incomplete ? [rule.Condition.Field!] : [], Quality: incomplete ? ["missing-field"] : ["controlled"]);
        var other = Guid.NewGuid().ToString();
        return [new("positive", "positive", E("positive", matching, rule.TenantId), 1, true, "match"), new("negative", "negative", E("negative", "definitely-not-matching", rule.TenantId), 0, true, "no-match"), new("boundary", "boundary", E("boundary", matching, rule.TenantId), 1, true, "match-at-boundary"), new("benign", "benign", E("benign", "known-benign", rule.TenantId), 0, true, "no-match"), new("malformed", "malformed", E("malformed", new string('x', 4097), rule.TenantId), 0, false, "schema-rejected"), new("missing-field", "missing-field", E("missing", null, rule.TenantId, true), 0, true, "no-match-missing-field"), new("duplicate-replay", "duplicate/replay", E("duplicate", matching, rule.TenantId), 1, true, "idempotent-single-result"), new("tenant-isolation", "tenant-isolation", E("foreign", matching, other), 0, false, "tenant-rejected")];
    }

    public static IReadOnlyDictionary<string, string[]> ValidateFixtures(AiRuleDraft draft)
    {
        var errors = new Dictionary<string, string[]>(); if (draft.Detection is not { } rule) return errors;
        foreach (var fixture in draft.Fixtures)
        {
            var e = fixture.Event; var valid = e.TenantId == rule.TenantId && e.Domain == rule.Domain && e.EventId != Guid.Empty && e.EventTime != default && e.Fields.Count <= 64 && e.Fields.All(x => x.Key.Length <= 100 && (x.Value?.Length ?? 0) <= 4096) && e.EvidenceReference.Length <= 2048;
            if (valid != fixture.ExpectedValid) errors[fixture.Name] = ["Fixture validity differs from its declared expected validation outcome."];
            if (fixture.ExpectedValid) { var actual = DetectionDsl.Evaluate(rule, e).Matched ? 1 : 0; if (actual != fixture.ExpectedMatches) errors[fixture.Name] = [$"Expected {fixture.ExpectedMatches} matches but evaluated {actual}."]; }
        }
        return errors;
    }

    public static AiDetectionScorecard Score(DetectionDefinition rule, AiFixtureProposal[] fixtures, AiRuleReview review)
    {
        var valid = ValidateFixtures(new(Guid.Empty, "ai-rule-draft.v1", rule.TenantId, rule.Author, AiDraftKind.Detection, "", "", rule, null, fixtures, review, null!, [], [], [], [], "", "", "", "", AiProposalState.Validated, default)).Count == 0;
        return new(100, 80, rule.GroupBy.Contains("processEntityId") || rule.GroupBy.Contains("endpointId") ? 100 : 50, 0, valid ? 100 : 0, valid ? 100 : 0, 100, 0, rule.MitreTechniques.All(ValidTechnique) ? 100 : 0, rule.RuleType == DetectionRuleType.Event ? 90 : 70, ["Deterministic component values; no opaque aggregate score."]);
    }

    public static bool NarrowExclusion(string field, string value) => field is "path" or "sha256" or "signer" or "userSid" or "endpointId" or "processEntityId" && !string.IsNullOrWhiteSpace(value) && value is not "*" and not "**" && value.Length <= 512;
    public static AiCoverageRecord Coverage(MitreCoverageRow row, Guid[] ruleIds, Guid[] correlationIds, string[] fields, string[] fixtures, DateTimeOffset? validated, string[] limitations)
    {
        var level = !row.TelemetryAvailable ? CoverageSupportLevel.NotObservableBySource : row.ProductionActive && row.DetectionTested ? CoverageSupportLevel.Covered : row.DetectionImplemented && row.DetectionTested ? CoverageSupportLevel.PartiallyCovered : row.DetectionImplemented ? CoverageSupportLevel.NotValidated : CoverageSupportLevel.TelemetryAvailableNoDetection;
        return new(row.Tactic, row.Technique, row.SubTechnique, ruleIds, correlationIds, row.RequiredTelemetry, fields, level, row.DetectionTested ? "fixture-validated" : "not-validated", limitations, fixtures, validated, $"telemetryAvailable={row.TelemetryAvailable}; detectionImplemented={row.DetectionImplemented}; detectionTested={row.DetectionTested}; productionActive={row.ProductionActive}");
    }
    public static bool ValidTechnique(string value) => Regex.IsMatch(value, @"^T\d{4}(?:\.\d{3})?$", RegexOptions.CultureInvariant);
    public static bool VerifiedTechnique(string value) => ValidTechnique(value) && VerifiedAttackTechniques.Contains(value);
    public static string Hash(object value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value, Json))).ToLowerInvariant();
    static HuntClause Clause(string field, HuntOperator op, string value) => new(HuntBoolean.And, new(field, op, [value]));
}
