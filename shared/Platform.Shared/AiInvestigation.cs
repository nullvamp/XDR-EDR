using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<AiDataMode>))]
public enum AiDataMode { LocalOnly, RemoteRedacted, RemoteFull }
[JsonConverter(typeof(JsonStringEnumConverter<AiClaimKind>))]
public enum AiClaimKind { Observed, Derived, Inference, Ambiguous, Unknown }
[JsonConverter(typeof(JsonStringEnumConverter<AiConfidence>))]
public enum AiConfidence { High, Medium, Low, InsufficientEvidence }
[JsonConverter(typeof(JsonStringEnumConverter<AiMessageRole>))]
public enum AiMessageRole { Analyst, Assistant, System }

public sealed record AiPolicyRequest(bool Enabled, AiDataMode DataMode, string ProviderId,
    string[] AllowedModels, string[] AllowedEvidenceTypes, bool RedactPersonalData,
    bool RedactSecrets, int MaximumEvidenceItems, int MaximumEvidenceBytes,
    int MaximumOutputCharacters, int MaximumRequestsPerMinute, int MaximumConcurrentRequests,
    int MaximumProviderRetries, int PromptRetentionDays, int ResponseRetentionDays,
    int TimeoutSeconds = 30, int ContextTokenLimit = 32_000, decimal Determinism = 0,
    string[]? AllowedUseCases = null);
public sealed record AiPolicy(Guid PolicyId, string TenantId, int Version, bool Enabled,
    AiDataMode DataMode, string ProviderId, string[] AllowedModels, string[] AllowedEvidenceTypes,
    bool RedactPersonalData, bool RedactSecrets, int MaximumEvidenceItems, int MaximumEvidenceBytes,
    int MaximumOutputCharacters, int MaximumRequestsPerMinute, int MaximumConcurrentRequests,
    int MaximumProviderRetries, int PromptRetentionDays, int ResponseRetentionDays,
    DateTimeOffset CreatedAt, string CreatedBy, string PreviousHash, string PolicyHash,
    int TimeoutSeconds = 30, int ContextTokenLimit = 32_000, decimal Determinism = 0,
    string[]? AllowedUseCases = null);

public sealed record AiEvidenceItem(string CitationId, Guid EvidenceId, string TenantId,
    string ContextType, string ContextId, string EvidenceType, string Source, DateTimeOffset ObservedAt,
    Guid? EndpointId, string? EntityId, string Provenance, AiConfidence Confidence,
    bool Ambiguous, string SourceReference, IReadOnlyDictionary<string, string?> Fields);
public sealed record AiTruncationReport(int CandidateItems, int IncludedItems, int OmittedItems,
    long CandidateBytes, long IncludedBytes, string[] Reasons);
public sealed record AiEvidencePackage(string SchemaVersion, Guid PackageId, string TenantId,
    string ContextType, string ContextId, DateTimeOffset CreatedAt, string CreatedBy,
    int PolicyVersion, string PolicyHash, AiEvidenceItem[] Items, AiTruncationReport Truncation,
    string PackageHash);

public sealed record AiClaim(string ClaimId, AiClaimKind Kind, string Text, string[] Citations,
    AiConfidence Confidence, string ConfidenceBasis);
public sealed record AiAnalysis(string SchemaVersion, string ProviderId, string ModelId,
    AiClaim[] Claims, string[] SuggestedPivots, string[] AdvisoryRecommendations,
    string[] Unknowns, bool ReadOnly, DateTimeOffset GeneratedAt);
public sealed record AiProviderRequest(AiPolicy Policy, AiEvidencePackage Evidence,
    string Question, string Analyst, string RequestHash);
public sealed record AiProviderResult(bool Succeeded, AiAnalysis? Analysis, string? FailureCode,
    string? FailureDetail, long LatencyMilliseconds, int Attempts);
public sealed record AiProviderHealth(string ProviderId, bool Available, bool Local,
    string ModelId, string Detail, DateTimeOffset CheckedAt);

public interface IAiProvider
{
    string ProviderId { get; }
    Task<AiProviderResult> AnalyzeAsync(AiProviderRequest request, CancellationToken ct);
    Task<AiProviderHealth> HealthAsync(CancellationToken ct);
}

public sealed record AiConversation(Guid ConversationId, string TenantId, string ContextType,
    string ContextId, string Title, string CreatedBy, DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt, int Version);
public sealed record AiMessage(Guid MessageId, Guid ConversationId, string TenantId,
    AiMessageRole Role, string Content, AiClaim[] Claims, Guid? EvidencePackageId,
    string ClientRequestId, string ContentHash, DateTimeOffset CreatedAt, string CreatedBy);
public sealed record AiNoteDraft(Guid DraftId, Guid ConversationId, string TenantId,
    string ContextType, string ContextId, string Content, string[] Citations, string CreatedBy,
    DateTimeOffset CreatedAt, bool Accepted, string? AcceptedBy, DateTimeOffset? AcceptedAt,
    Guid? AcceptedNoteId);
public sealed record AiAuditEvent(Guid AuditId, string TenantId, string Actor, string Action,
    string ObjectType, Guid ObjectId, DateTimeOffset OccurredAt,
    IReadOnlyDictionary<string, string?> Detail);
public sealed record AiOperationalMetrics(long Requests, long Succeeded, long Failed,
    long CitationRejections, long PolicyRejections, long EvidenceItems, long EvidenceBytes,
    double LastLatencyMilliseconds, DateTimeOffset UpdatedAt);

public interface IAiInvestigationRepository
{
    Task<AiPolicy> PolicyAsync(string tenant, CancellationToken ct);
    Task<AiPolicy> PutPolicyAsync(string tenant, string actor, AiPolicyRequest request, CancellationToken ct);
    Task<AiConversation> CreateConversationAsync(string tenant, string actor, string contextType, string contextId, string title, CancellationToken ct);
    Task<AiConversation?> ConversationAsync(string tenant, Guid id, CancellationToken ct);
    Task<IReadOnlyList<AiConversation>> ConversationsAsync(string tenant, int limit, CancellationToken ct);
    Task<AiMessage> AppendMessageAsync(AiMessage message, CancellationToken ct);
    Task<IReadOnlyList<AiMessage>> MessagesAsync(string tenant, Guid conversationId, CancellationToken ct);
    Task SaveEvidenceAsync(AiEvidencePackage package, CancellationToken ct);
    Task<AiEvidencePackage?> EvidenceAsync(string tenant, Guid packageId, CancellationToken ct);
    Task<AiNoteDraft> SaveDraftAsync(AiNoteDraft draft, CancellationToken ct);
    Task<AiNoteDraft?> DraftAsync(string tenant, Guid draftId, CancellationToken ct);
    Task<AiNoteDraft> AcceptDraftAsync(string tenant, Guid draftId, string actor, Guid noteId, CancellationToken ct);
    Task RecordAuditAsync(AiAuditEvent value, CancellationToken ct);
    Task<IReadOnlyList<AiAuditEvent>> AuditAsync(string tenant, int limit, CancellationToken ct);
    Task<AiOperationalMetrics> MetricsAsync(string tenant, CancellationToken ct);
}

public static partial class AiInvestigationSafety
{
    public const int MaximumQuestionCharacters = 4000;
    public const int HardMaximumItems = 200;
    public const int HardMaximumEvidenceBytes = 1_048_576;
    public const int HardMaximumOutputCharacters = 32_000;
    public static readonly string[] EvidenceTypes = ["alert", "incident", "detection", "correlation", "endpoint", "process", "entity", "file", "network", "dns", "identity", "persistence", "ioc", "tunnel", "forensic", "response", "attack-story", "analyst-note"];
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    [GeneratedRegex(@"\[EVID-\d{4}\]", RegexOptions.CultureInvariant)] private static partial Regex CitationPattern();

    public static AiPolicy DefaultPolicy(string tenant)
    {
        var x = new AiPolicy(StableId(tenant, "policy"), tenant, 1, true, AiDataMode.LocalOnly,
            "local-evidence", ["local-evidence-v1"], EvidenceTypes, true, true, 100, 524_288,
            16_000, 30, 2, 0, 30, 90, DateTimeOffset.UnixEpoch, "system", "", "");
        x = x with { AllowedUseCases = ["investigation", "explanation", "note-draft"] };
        return x with { PolicyHash = Hash(x with { PolicyHash = "" }) };
    }
    public static void Validate(AiPolicyRequest x)
    {
        if (string.IsNullOrWhiteSpace(x.ProviderId) || x.ProviderId.Length > 100 ||
            x.AllowedModels is { Length: < 1 or > 20 } || x.AllowedModels.Any(v => string.IsNullOrWhiteSpace(v) || v.Length > 200) ||
            x.AllowedEvidenceTypes is { Length: < 1 or > 20 } || x.AllowedEvidenceTypes.Any(v => !EvidenceTypes.Contains(v, StringComparer.Ordinal)) ||
            x.MaximumEvidenceItems is < 1 or > HardMaximumItems || x.MaximumEvidenceBytes is < 1024 or > HardMaximumEvidenceBytes ||
            x.MaximumOutputCharacters is < 256 or > HardMaximumOutputCharacters || x.MaximumRequestsPerMinute is < 1 or > 1000 ||
            x.MaximumConcurrentRequests is < 1 or > 20 || x.MaximumProviderRetries is < 0 or > 3 ||
            x.PromptRetentionDays is < 0 or > 3650 || x.ResponseRetentionDays is < 0 or > 3650)
            throw new EnrollmentConflictException("AI_POLICY_INVALID", "AI policy contains an unsupported value or exceeds a hard bound.");
        if (x.TimeoutSeconds is < 1 or > 300 || x.ContextTokenLimit is < 512 or > 262_144 || x.Determinism is < 0 or > 1 ||
            x.AllowedUseCases is { Length: > 20 } || x.AllowedUseCases?.Any(v => string.IsNullOrWhiteSpace(v) || v.Length > 100) == true)
            throw new EnrollmentConflictException("AI_PROVIDER_LIMIT_INVALID", "Provider timeout, context, determinism, or use-case limit is invalid.");
        if (x.DataMode != AiDataMode.LocalOnly && (!x.RedactSecrets || x.DataMode == AiDataMode.RemoteRedacted && !x.RedactPersonalData))
            throw new EnrollmentConflictException("AI_REMOTE_REDACTION_REQUIRED", "Remote AI modes require secret redaction; REMOTE_REDACTED also requires personal-data redaction.");
    }
    public static string Question(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaximumQuestionCharacters)
            throw new EnrollmentConflictException("AI_QUESTION_BOUNDS", $"Question must contain 1-{MaximumQuestionCharacters} characters.");
        return PlainText(value);
    }
    public static string PlainText(string value)
    {
        var clean = value.Replace("\0", "", StringComparison.Ordinal).Replace("\r", " ", StringComparison.Ordinal).Trim();
        if (clean.Contains("<script", StringComparison.OrdinalIgnoreCase) || clean.Contains("javascript:", StringComparison.OrdinalIgnoreCase))
            throw new EnrollmentConflictException("AI_ACTIVE_CONTENT_REJECTED", "Active content is not accepted.");
        return clean;
    }
    public static AiEvidencePackage Package(string tenant, string actor, string contextType, string contextId,
        AiPolicy policy, IEnumerable<AiEvidenceItem> candidates)
    {
        if (policy.TenantId != tenant) throw new EnrollmentConflictException("TENANT_MISMATCH", "AI policy tenant mismatch.");
        var source = candidates.Where(x => x.TenantId == tenant && x.ContextId == contextId && policy.AllowedEvidenceTypes.Contains(x.EvidenceType, StringComparer.Ordinal)).OrderBy(x => x.ObservedAt).ThenBy(x => x.EvidenceId).ToArray();
        var included = new List<AiEvidenceItem>(); long bytes = 0; long contextTokens = 0; string? bound = null;
        foreach (var raw in source)
        {
            var item = raw with { CitationId = $"EVID-{included.Count + 1:0000}", Fields = SanitizeFields(raw.Fields, policy) };
            var serialized = JsonSerializer.Serialize(item, Json); var size = Encoding.UTF8.GetByteCount(serialized); var tokens = serialized.Length;
            if (included.Count >= policy.MaximumEvidenceItems) { bound = "evidence-item-limit"; break; }
            if (bytes + size > policy.MaximumEvidenceBytes) { bound = "evidence-byte-limit"; break; }
            if (contextTokens + tokens > policy.ContextTokenLimit) { bound = "context-token-limit"; break; }
            included.Add(item); bytes += size; contextTokens += tokens;
        }
        var reasons = new List<string>(); if (included.Count < source.Length) reasons.Add(bound ?? "policy-bound");
        var report = new AiTruncationReport(source.Length, included.Count, source.Length - included.Count,
            source.Sum(x => JsonSerializer.SerializeToUtf8Bytes(x, Json).LongLength), bytes, [.. reasons]);
        var package = new AiEvidencePackage("ai-evidence-package.v1", StableId(tenant, contextType, contextId, policy.Version.ToString(System.Globalization.CultureInfo.InvariantCulture), string.Join(',', included.Select(x => x.EvidenceId))), tenant, contextType, contextId, DateTimeOffset.UtcNow, actor, policy.Version, policy.PolicyHash, [.. included], report, "");
        return package with { PackageHash = Hash(package with { PackageHash = "", CreatedAt = default }) };
    }
    public static void ValidateCitations(AiAnalysis analysis, AiEvidencePackage evidence)
    {
        if (!analysis.ReadOnly) throw new EnrollmentConflictException("AI_RESPONSE_NOT_READ_ONLY", "AI response declared a non-read-only capability.");
        var ids = evidence.Items.Select(x => x.CitationId).ToHashSet(StringComparer.Ordinal);
        foreach (var claim in analysis.Claims)
        {
            PlainText(claim.Text);
            if (claim.Text.Length is < 1 or > 4000 || claim.Citations.Distinct(StringComparer.Ordinal).Count() != claim.Citations.Length || claim.Citations.Any(x => !ids.Contains(x)))
                throw new EnrollmentConflictException("AI_CITATION_INVALID", "AI response contains an invalid, duplicate, or out-of-package citation.");
            if (claim.Kind is AiClaimKind.Observed or AiClaimKind.Derived or AiClaimKind.Inference or AiClaimKind.Ambiguous && claim.Citations.Length == 0)
                throw new EnrollmentConflictException("AI_CITATION_REQUIRED", "Every material claim must cite included evidence.");
            var embedded = CitationPattern().Matches(claim.Text).Select(x => x.Value.Trim('[', ']')).ToArray();
            if (embedded.Any(x => !claim.Citations.Contains(x, StringComparer.Ordinal)))
                throw new EnrollmentConflictException("AI_CITATION_UNDECLARED", "Claim text contains an undeclared citation.");
        }
    }
    public static IReadOnlyDictionary<string, string?> SanitizeFields(IReadOnlyDictionary<string, string?> fields, AiPolicy policy) =>
        fields.Take(64).ToDictionary(x => PlainText(x.Key)[..Math.Min(100, PlainText(x.Key).Length)], x => Redact(x.Key, x.Value, policy), StringComparer.Ordinal);
    static string? Redact(string key, string? value, AiPolicy policy)
    {
        if (value is null) return null; var text = PlainText(value); if (text.Length > 2048) text = text[..2048] + "…";
        if (policy.RedactSecrets && (key.Contains("secret", StringComparison.OrdinalIgnoreCase) || key.Contains("token", StringComparison.OrdinalIgnoreCase) || key.Contains("password", StringComparison.OrdinalIgnoreCase) || key.Contains("authorization", StringComparison.OrdinalIgnoreCase))) return "[REDACTED_SECRET]";
        if (policy.RedactPersonalData && (key.Contains("email", StringComparison.OrdinalIgnoreCase) || key.Contains("user", StringComparison.OrdinalIgnoreCase))) return "[REDACTED_PERSONAL:" + Hash(text)[..12] + "]";
        return text;
    }
    public static string Hash(object value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value, Json))).ToLowerInvariant();
    public static Guid StableId(params string[] values) => new(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values)))[..16]);
}

public sealed class LocalEvidenceAiProvider : IAiProvider
{
    public string ProviderId => "local-evidence";
    public Task<AiProviderHealth> HealthAsync(CancellationToken ct) => Task.FromResult(new AiProviderHealth(ProviderId, true, true, "local-evidence-v1", "Deterministic local evidence renderer; no external transmission or generation model.", DateTimeOffset.UtcNow));
    public Task<AiProviderResult> AnalyzeAsync(AiProviderRequest request, CancellationToken ct)
    {
        var started = DateTimeOffset.UtcNow;
        if (!request.Policy.Enabled || request.Policy.DataMode != AiDataMode.LocalOnly || request.Policy.ProviderId != ProviderId)
            return Task.FromResult(new AiProviderResult(false, null, "AI_PROVIDER_POLICY_DENIED", "Local provider is not authorized by the active policy.", 0, 1));
        var claims = request.Evidence.Items.Take(20).Select((x, i) => new AiClaim($"CLAIM-{i + 1:0000}", x.Ambiguous ? AiClaimKind.Ambiguous : AiClaimKind.Observed,
            $"{Describe(x)} [{x.CitationId}].", [x.CitationId], x.Ambiguous ? AiConfidence.Low : x.Confidence,
            x.Ambiguous ? "Source marked this evidence ambiguous." : "Direct structured evidence included in the bounded package.")).ToList();
        if (request.Evidence.Items.Length > 1)
        {
            var cited = request.Evidence.Items.Take(20).Select(x => x.CitationId).ToArray();
            claims.Add(new("CLAIM-DERIVED", AiClaimKind.Derived, $"The bounded package contains {request.Evidence.Items.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)} included records ordered by authoritative observation time [{string.Join("] [", cited)}].", cited, AiConfidence.High, "Deterministic count and ordering from the validated evidence package."));
        }
        if (request.Evidence.Truncation.OmittedItems > 0) claims.Add(new("CLAIM-TRUNCATION", AiClaimKind.Unknown, $"The package omitted {request.Evidence.Truncation.OmittedItems} candidate evidence items due to configured bounds; completeness is unknown.", [], AiConfidence.InsufficientEvidence, "Evidence package truncation report."));
        if (claims.Count == 0) claims.Add(new("CLAIM-UNKNOWN", AiClaimKind.Unknown, "No authorized structured evidence was available for this context.", [], AiConfidence.InsufficientEvidence, "Empty bounded evidence package."));
        var citations = request.Evidence.Items.Take(5).Select(x => x.CitationId).ToArray();
        var analysis = new AiAnalysis("ai-analysis.v1", ProviderId, "local-evidence-v1", [.. claims],
            citations.Length == 0 ? [] : [$"Review the source records referenced by {string.Join(' ', citations.Select(x => $"[{x}]"))}."],
            ["Validate material conclusions against authoritative telemetry before changing incident state or taking response action."],
            ["Intent, unobserved activity, and facts outside the included time-bounded evidence remain unknown."], true, DateTimeOffset.UtcNow);
        AiInvestigationSafety.ValidateCitations(analysis, request.Evidence);
        return Task.FromResult(new AiProviderResult(true, analysis, null, null, Math.Max(0, (long)(DateTimeOffset.UtcNow - started).TotalMilliseconds), 1));
    }
    static string Describe(AiEvidenceItem x)
    {
        string? F(string name) => x.Fields.GetValueOrDefault(name);
        return x.EvidenceType switch
        {
            "alert" => $"Alert '{F("title") ?? "untitled"}' has status {F("status") ?? "unknown"}, severity {F("severity") ?? "unknown"}, and confidence {F("confidence") ?? "unknown"}",
            "incident" => $"Incident '{F("title") ?? "untitled"}' has status {F("status") ?? "unknown"}, severity {F("severity") ?? "unknown"}, and confidence {F("confidence") ?? "unknown"}",
            "detection" => $"Detection '{F("ruleName") ?? "unknown rule"}' recorded {F("eventCount") ?? "an unknown number of"} matching events with severity {F("severity") ?? "unknown"}",
            "correlation" => $"Correlation '{F("ruleName") ?? "unknown rule"}' completed for key {F("correlationKey") ?? "unknown"} with missing required telemetry '{F("missingTelemetry") ?? "none recorded"}'",
            "ioc" => $"IOC {F("type") ?? "unknown type"} '{F("value") ?? "redacted/unknown"}' has confidence {F("confidence") ?? "unknown"}; revoked={F("revoked") ?? "unknown"}, expired={F("expired") ?? "unknown"}. An IOC match alone does not prove compromise",
            "tunnel" => $"Tunnel analytic '{F("ruleName") ?? F("kind") ?? "unknown"}' recorded score {F("score") ?? "unknown"} with missing telemetry '{F("missingTelemetry") ?? "none recorded"}'; packet contents are not exposed by this evidence",
            "forensic" => $"Forensic evidence {F("artifactType") ?? F("profileId") ?? "collection"} has state/quality {F("state") ?? F("quality") ?? "unknown"}, race state {F("raceState") ?? "unknown"}, and truncation {F("truncated") ?? "unknown"}",
            "response" => $"Response action {F("actionType") ?? "unknown"} has authoritative state {F("state") ?? "unknown"} and approval state {F("approvalState") ?? "unknown"}",
            "attack-story" => $"Authoritative attack story contains {F("entityCount") ?? "an unknown number of"} entities, {F("relationshipCount") ?? "an unknown number of"} relationships, and {F("timelineCount") ?? "an unknown number of"} timeline entries",
            "entity" => $"Entity {x.EntityId ?? "unknown"} ({F("entityType") ?? "unknown type"}) was observed by {x.Source} at {x.ObservedAt:O}",
            _ => $"{x.EvidenceType} evidence from {x.Source} was observed at {x.ObservedAt:O}"
        };
    }
}
