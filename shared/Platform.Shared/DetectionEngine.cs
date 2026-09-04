using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<DetectionDomain>))]
public enum DetectionDomain { Process, File, Registry, Network, Dns, Module, Persistence, Identity, Execution, ThreatIntelligence, Tunnel }
[JsonConverter(typeof(JsonStringEnumConverter<DetectionRuleStatus>))]
public enum DetectionRuleStatus { Draft, Testing, Active, Disabled, Deprecated }
[JsonConverter(typeof(JsonStringEnumConverter<DetectionExecutionMode>))]
public enum DetectionExecutionMode { Live, HistoricalReplay, Simulation, DryRun }
[JsonConverter(typeof(JsonStringEnumConverter<DetectionRuleType>))]
public enum DetectionRuleType { Event, Entity, Threshold }
[JsonConverter(typeof(JsonStringEnumConverter<DetectionOperator>))]
public enum DetectionOperator { Equal, NotEqual, Contains, StartsWith, EndsWith, GreaterThan, GreaterThanOrEqual, LessThan, LessThanOrEqual, Cidr, ExactPath, Glob, Exists, In }
[JsonConverter(typeof(JsonStringEnumConverter<DetectionLogic>))]
public enum DetectionLogic { Predicate, And, Or, Not }

public sealed record DetectionCondition(
    DetectionLogic Logic = DetectionLogic.Predicate,
    string? Field = null,
    DetectionOperator Operator = DetectionOperator.Equal,
    string? Value = null,
    string[]? Values = null,
    bool CaseInsensitive = false,
    DetectionCondition[]? Children = null);

public sealed record DetectionSuppression(string Scope = "detection+endpoint", int DurationMinutes = 0);
public sealed record DetectionDefinition(
    string SchemaVersion,
    Guid DetectionId,
    int DetectionVersion,
    string TenantId,
    string Name,
    string Description,
    DetectionRuleStatus Status,
    bool Enabled,
    string Author,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    int Severity,
    int Confidence,
    string Category,
    string[] Tags,
    string[] MitreTactics,
    string[] MitreTechniques,
    string[] DataSources,
    DetectionRuleType RuleType,
    DetectionDomain Domain,
    string[] Prerequisites,
    string[] RequiredFields,
    int WindowSeconds,
    string[] GroupBy,
    int Threshold,
    bool DistinctCount,
    string? DistinctField,
    DetectionCondition Condition,
    DetectionExecutionMode EvaluationMode,
    DetectionSuppression Suppression,
    Guid[] ExclusionReferences,
    string TestFixtureVersion = "detection-fixture.v1",
    bool LastValidationPassed = false,
    DateTimeOffset? LastValidatedAt = null,
    DateTimeOffset? ActivatedAt = null,
    DateTimeOffset? DeactivatedAt = null);

public sealed record DetectionEvidenceEvent(
    Guid EventId,
    string TenantId,
    DetectionDomain Domain,
    DateTimeOffset EventTime,
    Guid? EndpointId,
    string? ProcessEntityId,
    string? EntityId,
    IReadOnlyDictionary<string, string?> Fields,
    string EvidenceReference,
    bool Late = false,
    bool Incomplete = false,
    string[]? MissingTelemetry = null,
    string[]? Quality = null);

public sealed record DetectionConditionResult(string Path, bool Matched, string? Field, string? ActualValue, string? ExpectedValue, string Operator);
public sealed record DetectionEvaluation(bool Matched, IReadOnlyList<DetectionConditionResult> Conditions, string[] MissingFields, string GroupKey);
public sealed record DetectionFinding(
    Guid FindingId, string TenantId, Guid DetectionId, int DetectionVersion, string RuleName,
    int Severity, int Confidence, DateTimeOffset FirstSeen, DateTimeOffset LastSeen, int EventCount,
    string GroupKey, Guid? EndpointId, string? ProcessEntityId, string? EntityId, Guid[] MatchingEventIds,
    string[] EvidenceReferences, DetectionConditionResult[] MatchedConditions, bool Suppressed,
    string? SuppressionReason, Guid? OriginalFindingId, bool Excluded, string? ExclusionReason,
    string EngineVersion, DetectionExecutionMode ExecutionMode, string[] TelemetryQuality,
    string[] MissingTelemetry, DateTimeOffset CreatedAt, string Status = "open");
public sealed record DetectionFindingHistory(long Sequence, string Action, string Actor, DateTimeOffset OccurredAt, DetectionFinding Snapshot);

public sealed record DetectionExclusion(Guid Id, string TenantId, int Version, string Name, string Field, string Value,
    bool CaseInsensitive, DateTimeOffset StartsAt, DateTimeOffset EndsAt, string Reason, string CreatedBy,
    bool ElevatedMatchAllConfirmation = false, long MatchCount = 0);
public sealed record DetectionAssignment(Guid Id, string TenantId, Guid DetectionId, int DetectionVersion,
    Guid? EndpointId, Guid? EndpointGroupId, bool Enabled, DateTimeOffset CreatedAt, string CreatedBy);
public sealed record DetectionRuleTestCase(string Name, string Kind, DetectionEvidenceEvent[] Events, int ExpectedFindings, Guid? ExclusionId = null);
public sealed record DetectionRuleTestResult(bool Passed, int ExpectedFindings, int ActualFindings, string[] Failures, DateTimeOffset CompletedAt);
public sealed record DetectionRun(Guid Id, string TenantId, Guid DetectionId, int DetectionVersion, DetectionExecutionMode Mode,
    DateTimeOffset From, DateTimeOffset To, string Status, long EventsTotal, long EventsEvaluated, long Matches,
    long Findings, bool ProductionFindings, DateTimeOffset CreatedAt, DateTimeOffset? CompletedAt = null, string? Error = null);
public sealed record DetectionHealth(long EventsEvaluated, long RulesEvaluated, long Matches, long Findings, long Suppressed,
    long Excluded, long EvaluationFailures, long CompileFailures, long MissingFields, long MissingTelemetry,
    long ReplayQueueDepth, double LastReplayDurationMilliseconds, double LastEvaluationLatencyMilliseconds,
    double LastProjectionLatencyMilliseconds, DateTimeOffset UpdatedAt);
public sealed record DetectionFindingQuery(Guid? DetectionId = null, Guid? EndpointId = null, int? MinimumSeverity = null,
    bool? Suppressed = null, DetectionExecutionMode? Mode = null, DateTimeOffset? From = null, DateTimeOffset? To = null,
    int PageSize = 100, string? Cursor = null);
public sealed record DetectionFindingPage(IReadOnlyList<DetectionFinding> Items, string? NextCursor);
public sealed record DetectionEvaluationResult(bool Duplicate, bool Excluded, bool Suppressed, DetectionEvaluation Evaluation,
    DetectionFinding? Finding, string? Reason);

public interface IDetectionRepository
{
    Task<IReadOnlyList<DetectionDefinition>> ListRulesAsync(string tenant, CancellationToken ct);
    Task<IReadOnlyList<DetectionDefinition>> RuleHistoryAsync(string tenant, Guid detectionId, CancellationToken ct);
    Task<DetectionDefinition?> GetRuleAsync(string tenant, Guid detectionId, int? version, CancellationToken ct);
    Task<DetectionDefinition> CreateRuleAsync(string tenant, string actor, DetectionDefinition definition, CancellationToken ct);
    Task<DetectionDefinition> CreateVersionAsync(string tenant, string actor, Guid detectionId, DetectionDefinition definition, CancellationToken ct);
    Task<DetectionDefinition> RecordValidationAsync(string tenant, Guid detectionId, int version, IReadOnlyDictionary<string, string[]> errors, CancellationToken ct);
    Task RecordTestsAsync(string tenant, Guid detectionId, int version, IReadOnlyList<(DetectionRuleTestCase Test, DetectionRuleTestResult Result)> tests, CancellationToken ct);
    Task<IReadOnlyList<(string Name, string Kind, DetectionRuleTestResult Result)>> ListTestsAsync(string tenant, Guid detectionId, int version, CancellationToken ct);
    Task<DetectionDefinition> ActivateAsync(string tenant, string actor, Guid detectionId, int version, CancellationToken ct);
    Task<DetectionDefinition> DisableAsync(string tenant, string actor, Guid detectionId, CancellationToken ct);
    Task<DetectionAssignment> AssignAsync(string tenant, string actor, DetectionAssignment assignment, CancellationToken ct);
    Task<DetectionExclusion> CreateExclusionAsync(string tenant, string actor, DetectionExclusion exclusion, CancellationToken ct);
    Task<IReadOnlyList<DetectionExclusion>> ListExclusionsAsync(string tenant, CancellationToken ct);
    Task<DetectionEvaluationResult> EvaluateAsync(string tenant, DetectionEvidenceEvent evidence, DetectionExecutionMode mode,
        Guid? detectionId, int? version, Guid? runId, bool productionFindings, CancellationToken ct);
    Task<DetectionFindingPage> SearchFindingsAsync(string tenant, DetectionFindingQuery query, CancellationToken ct);
    Task<DetectionFinding?> GetFindingAsync(string tenant, Guid findingId, CancellationToken ct);
    Task<IReadOnlyList<DetectionFindingHistory>> FindingHistoryAsync(string tenant, Guid findingId, CancellationToken ct);
    Task<DetectionRun> CreateRunAsync(string tenant, DetectionRun run, DetectionDefinition snapshot, CancellationToken ct);
    Task<DetectionRun> CompleteRunAsync(string tenant, Guid runId, long evaluated, long matches, long findings, string status, CancellationToken ct);
    Task<DetectionRun?> GetRunAsync(string tenant, Guid runId, CancellationToken ct);
    Task<DetectionRun> CancelRunAsync(string tenant, Guid runId, CancellationToken ct);
    Task<DetectionHealth> HealthAsync(string tenant, CancellationToken ct);
}
public interface IDetectionProjection
{
    Task EnsureAsync(CancellationToken ct);
    Task UpsertAsync(DetectionFinding finding, CancellationToken ct);
    Task<long> CountAsync(string tenant, CancellationToken ct);
    Task<bool> HealthAsync(CancellationToken ct);
}
public interface IDetectionEventSource
{
    Task<IReadOnlyList<DetectionEvidenceEvent>> LoadAsync(string tenant, DetectionDomain domain, DateTimeOffset fromInclusive, DateTimeOffset toInclusive, int limit, CancellationToken ct);
}
public sealed class EmptyDetectionEventSource : IDetectionEventSource
{
    public Task<IReadOnlyList<DetectionEvidenceEvent>> LoadAsync(string tenant, DetectionDomain domain, DateTimeOffset fromInclusive, DateTimeOffset toInclusive, int limit, CancellationToken ct) => Task.FromResult<IReadOnlyList<DetectionEvidenceEvent>>([]);
}

public static class DetectionEvidenceMapper
{
    static readonly IReadOnlyDictionary<DetectionDomain, IReadOnlyDictionary<string, string[]>> Aliases = new Dictionary<DetectionDomain, IReadOnlyDictionary<string, string[]>>
    {
        [DetectionDomain.Process] = Map(("path", ["originalPath", "imagePath", "executablePath", "path"]), ("commandLine", ["commandLine"]), ("processName", ["basename", "processName", "imageName", "executableName"]), ("parentPath", ["parentPath", "parentImage"]), ("user", ["user", "userName", "userSid"]), ("pid", ["processId", "pid"]), ("processEntityId", ["processEntityId"]), ("signed", ["signed", "isSigned"])),
        [DetectionDomain.File] = Map(("path", ["originalPath", "canonicalPath", "path"]), ("operation", ["operation", "kind"]), ("extension", ["extension"]), ("sha256", ["sha256", "value"]), ("processPath", ["processPath", "imagePath"]), ("user", ["user", "userSid"]), ("size", ["size", "fileSize"]), ("entityId", ["fileEntityId", "entityId"])),
        [DetectionDomain.Registry] = Map(("path", ["canonicalPath", "keyPath", "path"]), ("valueName", ["valueName"]), ("valueData", ["valueData", "capturedValue"]), ("operation", ["operation", "kind"]), ("processPath", ["processPath", "imagePath"]), ("user", ["user", "userSid"]), ("entityId", ["valueEntityId", "keyEntityId", "entityId"])),
        [DetectionDomain.Network] = Map(("destinationIp", ["destinationIp", "remoteAddress"]), ("destinationPort", ["destinationPort", "remotePort"]), ("sourceIp", ["sourceIp", "localAddress"]), ("sourcePort", ["sourcePort", "localPort"]), ("protocol", ["protocol"]), ("processPath", ["processPath", "imagePath"]), ("processEntityId", ["processEntityId"])),
        [DetectionDomain.Dns] = Map(("query", ["query", "originalName", "canonicalName"]), ("recordType", ["recordType", "queryType"]), ("responseCode", ["responseCode", "status"]), ("processPath", ["processPath", "imagePath"]), ("processEntityId", ["processEntityId"])),
        [DetectionDomain.Module] = Map(("path", ["originalPath", "canonicalPath", "path"]), ("basename", ["basename"]), ("sha256", ["sha256", "value"]), ("signerState", ["signerState", "verificationState"]), ("signer", ["subject", "signer"]), ("imageType", ["imageType"]), ("processPath", ["processPath", "imagePath"]), ("processEntityId", ["processEntityId"])),
        [DetectionDomain.Persistence] = Map(("kind", ["kind", "eventType"]), ("name", ["name", "serviceName", "taskName"]), ("path", ["path", "executablePath", "taskPath"]), ("command", ["command", "commandLine", "imagePath"]), ("operation", ["operation", "action"]), ("user", ["user", "userSid"]), ("entityId", ["entityId", "configurationEntityId"])),
        [DetectionDomain.Identity] = Map(("eventType", ["eventType", "kind"]), ("user", ["user", "userName", "accountName"]), ("userSid", ["userSid", "sid"]), ("logonType", ["logonType"]), ("status", ["status", "failureReason"]), ("sourceIp", ["sourceIp", "sourceAddress"]), ("processPath", ["processPath", "imagePath"]), ("entityId", ["entityId", "sessionEntityId", "logonEntityId"])),
        [DetectionDomain.Execution] = Map(("eventType", ["eventType", "kind"]), ("operation", ["nativeOperation", "operation"]), ("sourceProcess", ["sourceProcessEntityId"]), ("targetProcess", ["targetProcessEntityId"]), ("sourcePid", ["sourcePid"]), ("targetPid", ["targetPid"]), ("threadId", ["threadId"]), ("startAddress", ["startAddress"]), ("executableMemory", ["executable"]), ("entityId", ["threadEntityId", "regionEntityId", "sectionEntityId"]))
    };
    static Dictionary<string, string[]> Map(params (string Name, string[] Candidates)[] values) => values.ToDictionary(x => x.Name, x => x.Candidates, StringComparer.Ordinal);
    public static DetectionEvidenceEvent FromCanonical<T>(string tenant, DetectionDomain domain, Guid eventId, Guid? endpoint, DateTimeOffset observedAt, T canonical, string evidenceReference)
    {
        using var document = JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(canonical)); var leaves = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase); Visit(document.RootElement); var fields = new Dictionary<string, string?>(StringComparer.Ordinal); foreach (var alias in Aliases[domain]) fields[alias.Key] = alias.Value.Select(x => leaves.GetValueOrDefault(x)).FirstOrDefault(x => x is not null); if (domain == DetectionDomain.Process) { if (fields.GetValueOrDefault("processName") is { } processName && !Path.HasExtension(processName) && leaves.GetValueOrDefault("executablePath") is { } executablePath && Path.GetFileName(executablePath) is { Length: > 0 } fileName) fields["processName"] = fileName; var features = WindowsCommandLineFeatures.Extract(fields.GetValueOrDefault("commandLine"), fields.GetValueOrDefault("path")); fields["parentName"] = Path.GetFileName(fields.GetValueOrDefault("parentPath")); fields["interpreterType"] = features.InterpreterType; fields["encodedArgument"] = features.EncodedArgument.ToString().ToLowerInvariant(); fields["suspiciousSwitch"] = features.SuspiciousSwitch.ToString().ToLowerInvariant(); fields["retrievalIndicator"] = features.RetrievalIndicator.ToString().ToLowerInvariant(); fields["executionIndicator"] = features.ExecutionIndicator.ToString().ToLowerInvariant(); fields["hiddenIndicator"] = features.HiddenOrNonInteractive.ToString().ToLowerInvariant(); fields["obfuscationIndicator"] = features.ObfuscationIndicator.ToString().ToLowerInvariant(); fields["userWritableArgument"] = features.UserWritableArgument.ToString().ToLowerInvariant(); fields["interpreterNestingDepth"] = features.InterpreterNestingDepth.ToString(System.Globalization.CultureInfo.InvariantCulture); fields["urlCount"] = features.UrlCount.ToString(System.Globalization.CultureInfo.InvariantCulture); fields["suspiciousSwitchSet"] = features.SuspiciousSwitchSet; fields["filePathArgument"] = features.FilePathArgument; } else if (domain == DetectionDomain.File && fields.GetValueOrDefault("path") is { } filePath) fields["filePathArgument"] = filePath.Replace('/', '\\').ToLowerInvariant(); if (endpoint is not null) fields["endpointId"] = endpoint.Value.ToString("D"); var process = fields.GetValueOrDefault("processEntityId") ?? fields.GetValueOrDefault("sourceProcess") ?? fields.GetValueOrDefault("targetProcess"); var entity = fields.GetValueOrDefault("entityId") ?? process; var quality = leaves.Where(x => x.Key.Equals("qualityState", StringComparison.OrdinalIgnoreCase) || x.Key.Equals("dataQualityFlags", StringComparison.OrdinalIgnoreCase)).Select(x => x.Value).Where(x => x is not null).Cast<string>().ToArray(); return new(eventId, tenant, domain, observedAt, endpoint, process, entity, fields, evidenceReference, leaves.GetValueOrDefault("late")?.Equals("true", StringComparison.OrdinalIgnoreCase) == true, quality.Any(x => x.Contains("partial", StringComparison.OrdinalIgnoreCase) || x.Contains("incomplete", StringComparison.OrdinalIgnoreCase)), [], quality);
        void Visit(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object) foreach (var property in value.EnumerateObject()) { if (property.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array) Visit(property.Value); else if (!leaves.ContainsKey(property.Name)) leaves[property.Name] = property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : property.Value.GetRawText(); }
            else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) Visit(item);
        }
    }
}

public static class DetectionDsl
{
    public const string EngineVersion = "detection-engine.v1";
    public const int MaximumRuleBytes = 64 * 1024;
    public const int MaximumDepth = 8;
    public const int MaximumNodes = 64;
    public const int MaximumWindowSeconds = 7 * 24 * 60 * 60;
    public const int MaximumThreshold = 100_000;
    public const int MaximumGlobLength = 256;

    static readonly IReadOnlyDictionary<DetectionDomain, IReadOnlyDictionary<string, string>> Fields =
        new Dictionary<DetectionDomain, IReadOnlyDictionary<string, string>>
        {
            [DetectionDomain.Process] = Map("path", "commandLine", "processName", "parentPath", "parentName", "user", "pid", "endpointId", "processEntityId", "signed", "interpreterType", "encodedArgument", "suspiciousSwitch", "retrievalIndicator", "executionIndicator", "hiddenIndicator", "obfuscationIndicator", "userWritableArgument", "interpreterNestingDepth", "urlCount", "suspiciousSwitchSet", "filePathArgument"),
            [DetectionDomain.File] = Map("path", "operation", "extension", "sha256", "processPath", "user", "size", "endpointId", "entityId", "filePathArgument"),
            [DetectionDomain.Registry] = Map("path", "valueName", "valueData", "operation", "processPath", "user", "endpointId", "entityId"),
            [DetectionDomain.Network] = Map("destinationIp", "destinationPort", "sourceIp", "sourcePort", "protocol", "processPath", "endpointId", "processEntityId"),
            [DetectionDomain.Dns] = Map("query", "recordType", "responseCode", "processPath", "endpointId", "processEntityId"),
            [DetectionDomain.Module] = Map("path", "basename", "sha256", "signerState", "signer", "imageType", "processPath", "endpointId", "processEntityId"),
            [DetectionDomain.Persistence] = Map("kind", "name", "path", "command", "operation", "user", "endpointId", "entityId"),
            [DetectionDomain.Identity] = Map("eventType", "user", "userSid", "logonType", "status", "sourceIp", "processPath", "endpointId", "entityId"),
            [DetectionDomain.Execution] = Map("eventType", "operation", "sourceProcess", "targetProcess", "sourcePid", "targetPid", "threadId", "startAddress", "executableMemory", "endpointId", "entityId")
        };

    static Dictionary<string, string> Map(params string[] names) => names.ToDictionary(x => x, _ => "string", StringComparer.Ordinal);
    public static IReadOnlyCollection<string> AllowedFields(DetectionDomain domain) => Fields[domain].Keys.ToArray();

    public static IReadOnlyDictionary<string, string[]> Validate(DetectionDefinition rule)
    {
        var errors = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        void Error(string key, string value) { if (!errors.TryGetValue(key, out var list)) errors[key] = list = []; list.Add(value); }
        if (rule.SchemaVersion != "detection-rule.v1") Error("schemaVersion", "Only detection-rule.v1 is supported.");
        if (rule.DetectionId == Guid.Empty || rule.DetectionVersion < 1 || !Guid.TryParse(rule.TenantId, out _)) Error("identity", "Detection, version and tenant identity are required.");
        if (string.IsNullOrWhiteSpace(rule.Name) || rule.Name.Length > 200 || rule.Description.Length > 4000 || rule.Author.Length > 200) Error("metadata", "Rule metadata is missing or exceeds bounds.");
        if (rule.Severity is < 0 or > 100 || rule.Confidence is < 0 or > 100) Error("classification", "Severity and confidence must be 0-100.");
        if (rule.WindowSeconds is < 0 or > MaximumWindowSeconds || rule.Threshold is < 1 or > MaximumThreshold) Error("window", "Window or threshold exceeds bounded limits.");
        if (rule.RuleType == DetectionRuleType.Threshold && rule.WindowSeconds < 1) Error("window", "Threshold rules require an event-time window.");
        if (rule.GroupBy.Length > 4 || rule.RequiredFields.Length > 32 || rule.ExclusionReferences.Length > 64) Error("bounds", "Rule collections exceed bounded limits.");
        foreach (var field in rule.RequiredFields.Concat(rule.GroupBy).Append(rule.DistinctField).Where(x => x is not null).Cast<string>())
            if (!Fields[rule.Domain].ContainsKey(field)) Error("fields", $"Unknown or unauthorized field: {field}.");
        if (rule.DistinctCount && string.IsNullOrWhiteSpace(rule.DistinctField)) Error("distinctField", "Distinct count requires an allowlisted distinct field.");
        var nodes = 0;
        ValidateNode(rule.Condition, 1);
        if (nodes > MaximumNodes) Error("condition", "Condition node count exceeds the limit.");
        if (rule.MitreTechniques.Any(x => !ValidMitre(x))) Error("mitre", "MITRE technique identifiers must use T#### or T####.### format.");
        if (rule.Status == DetectionRuleStatus.Active && (!rule.Enabled || !rule.LastValidationPassed)) Error("activation", "Active rules must be enabled and have a passing immutable validation result.");
        if (JsonSerializer.SerializeToUtf8Bytes(rule).Length > MaximumRuleBytes) Error("size", "Serialized rule exceeds 64 KiB.");
        return errors.ToDictionary(x => x.Key, x => x.Value.ToArray(), StringComparer.Ordinal);

        void ValidateNode(DetectionCondition node, int depth)
        {
            nodes++;
            if (depth > MaximumDepth) { Error("condition", "Condition nesting exceeds eight levels."); return; }
            var children = node.Children ?? [];
            if (node.Logic == DetectionLogic.Predicate)
            {
                if (children.Length != 0 || string.IsNullOrWhiteSpace(node.Field) || !Fields[rule.Domain].ContainsKey(node.Field)) Error("condition", $"Invalid predicate field: {node.Field ?? "(missing)"}.");
                if (node.Operator != DetectionOperator.Exists && node.Value is null && (node.Values is null || node.Values.Length == 0)) Error("condition", "Predicate value is required.");
                if (node.Operator == DetectionOperator.In && (node.Values is null || node.Values.Length is < 1 or > 100)) Error("condition", "Set membership requires 1-100 values.");
                if (node.Operator == DetectionOperator.Glob && !SafeGlob(node.Value)) Error("condition", "Glob is empty, match-all, too long, or too complex.");
                if (node.Operator == DetectionOperator.Cidr && !ValidCidr(node.Value)) Error("condition", "CIDR value is invalid.");
                if (node.Value is { Length: > 4096 } || node.Values?.Any(x => x.Length > 4096) == true) Error("condition", "Predicate value exceeds bounds.");
            }
            else
            {
                var expected = node.Logic == DetectionLogic.Not ? 1 : 2;
                if (children.Length < expected || children.Length > 16 || node.Logic == DetectionLogic.Not && children.Length != 1) Error("condition", "Logical child count is invalid.");
                foreach (var child in children) ValidateNode(child, depth + 1);
            }
        }
    }

    public static DetectionEvaluation Evaluate(DetectionDefinition rule, DetectionEvidenceEvent evidence)
    {
        var results = new List<DetectionConditionResult>();
        var missing = rule.RequiredFields.Where(x => !evidence.Fields.TryGetValue(x, out var v) || v is null).Distinct(StringComparer.Ordinal).ToArray();
        var matched = rule.Domain == evidence.Domain && EvaluateNode(rule.Condition, "root");
        var group = string.Join('|', rule.GroupBy.Select(x => evidence.Fields.GetValueOrDefault(x) ?? "(missing)"));
        if (group.Length == 0) group = evidence.EndpointId?.ToString("D") ?? evidence.EntityId ?? "global";
        return new(matched && missing.Length == 0, results, missing, group);

        bool EvaluateNode(DetectionCondition node, string path)
        {
            var children = node.Children ?? [];
            if (node.Logic != DetectionLogic.Predicate)
            {
                var values = children.Select((x, i) => EvaluateNode(x, $"{path}.{i}")).ToArray();
                var logicalResult = node.Logic switch { DetectionLogic.And => values.All(x => x), DetectionLogic.Or => values.Any(x => x), DetectionLogic.Not => !values[0], _ => false };
                results.Add(new(path, logicalResult, null, null, null, node.Logic.ToString()));
                return logicalResult;
            }
            evidence.Fields.TryGetValue(node.Field!, out var actual);
            var comparison = node.CaseInsensitive ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            var expected = node.Value;
            var value = node.Operator switch
            {
                DetectionOperator.Exists => actual is not null,
                DetectionOperator.Equal => string.Equals(actual, expected, comparison),
                DetectionOperator.NotEqual => !string.Equals(actual, expected, comparison),
                DetectionOperator.Contains => actual?.Contains(expected ?? "", comparison) == true,
                DetectionOperator.StartsWith => actual?.StartsWith(expected ?? "", comparison) == true,
                DetectionOperator.EndsWith => actual?.EndsWith(expected ?? "", comparison) == true,
                DetectionOperator.GreaterThan => Number(actual, out var a) && Number(expected, out var b) && a > b,
                DetectionOperator.GreaterThanOrEqual => Number(actual, out var a) && Number(expected, out var b) && a >= b,
                DetectionOperator.LessThan => Number(actual, out var a) && Number(expected, out var b) && a < b,
                DetectionOperator.LessThanOrEqual => Number(actual, out var a) && Number(expected, out var b) && a <= b,
                DetectionOperator.Cidr => InCidr(actual, expected),
                DetectionOperator.ExactPath => EqualPath(actual, expected),
                DetectionOperator.Glob => Glob(actual, expected, node.CaseInsensitive),
                DetectionOperator.In => (node.Values ?? []).Any(x => string.Equals(actual, x, comparison)),
                _ => false
            };
            results.Add(new(path, value, node.Field, actual, expected ?? string.Join(',', node.Values ?? []), node.Operator.ToString()));
            return value;
        }
    }

    public static bool MatchesExclusion(DetectionExclusion exclusion, DetectionEvidenceEvent evidence, DateTimeOffset now)
        => now >= exclusion.StartsAt && now <= exclusion.EndsAt && evidence.Fields.TryGetValue(exclusion.Field, out var actual)
           && string.Equals(actual, exclusion.Value, exclusion.CaseInsensitive ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    public static string Hash(object value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value))).ToLowerInvariant();
    public static Guid DeterministicId(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        Span<byte> bytes = stackalloc byte[16]; hash.AsSpan(0, 16).CopyTo(bytes); return new Guid(bytes);
    }
    static bool Number(string? value, out decimal number) => decimal.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out number);
    static bool EqualPath(string? a, string? b) => a is not null && b is not null && string.Equals(NormalizePath(a), NormalizePath(b), StringComparison.OrdinalIgnoreCase);
    static string NormalizePath(string value) => value.Replace('/', '\\').TrimEnd('\\').Normalize(NormalizationForm.FormKC);
    static bool SafeGlob(string? value) => value is { Length: > 0 and <= MaximumGlobLength } && value is not "*" and not "**" && value.Count(x => x is '*' or '?') <= 8 && !value.Any(char.IsControl);
    static bool Glob(string? actual, string? pattern, bool insensitive)
    {
        if (actual is null || !SafeGlob(pattern)) return false;
        var source = insensitive ? actual.ToUpperInvariant() : actual;
        var target = insensitive ? pattern!.ToUpperInvariant() : pattern!;
        var rows = new bool[target.Length + 1]; rows[0] = true;
        for (var j = 1; j <= target.Length && target[j - 1] == '*'; j++) rows[j] = true;
        foreach (var character in source)
        {
            var next = new bool[target.Length + 1];
            for (var j = 1; j <= target.Length; j++) next[j] = target[j - 1] == '*' ? next[j - 1] || rows[j] : rows[j - 1] && (target[j - 1] == '?' || target[j - 1] == character);
            rows = next;
        }
        return rows[target.Length];
    }
    static bool ValidMitre(string value)
    {
        if (value.Length is not (5 or 9) || value[0] != 'T' || !value.AsSpan(1, 4).ToString().All(char.IsDigit)) return false;
        return value.Length == 5 || value[5] == '.' && value.AsSpan(6, 3).ToString().All(char.IsDigit);
    }
    static bool ValidCidr(string? value) => value is not null && ParseCidr(value, out _, out _);
    static bool InCidr(string? address, string? cidr)
    {
        if (!IPAddress.TryParse(address, out var ip) || cidr is null || !ParseCidr(cidr, out var network, out var prefix) || ip.AddressFamily != network.AddressFamily) return false;
        var a = ip.GetAddressBytes(); var n = network.GetAddressBytes();
        for (var i = 0; i < a.Length; i++) { var bits = Math.Clamp(prefix - i * 8, 0, 8); var mask = bits == 0 ? 0 : 0xff << (8 - bits) & 0xff; if ((a[i] & mask) != (n[i] & mask)) return false; }
        return true;
    }
    static bool ParseCidr(string value, out IPAddress network, out int prefix)
    {
        network = IPAddress.None; prefix = 0; var parts = value.Split('/', StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out network!) || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out prefix)) return false;
        return prefix >= 0 && prefix <= (network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
    }
}
