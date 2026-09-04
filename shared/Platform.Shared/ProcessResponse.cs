using System.Text.Json;
using System.Text.RegularExpressions;

namespace OpenSecurityPlatform.Foundation;

public enum ProcessResponseState
{
    Running, Suspended, Terminating, Terminated, ExitedBeforeAction,
    IdentityMismatch, AccessDenied, Partial, Failed, Unknown
}

public sealed record ProcessResponseTarget(
    string ProcessEntityId,
    int ProcessId,
    DateTimeOffset ProcessStartTime,
    string? ImagePath,
    string? Sha256,
    int Depth = 0);

public sealed record ProcessResponseRequest(
    string Reason,
    int ExpiresInSeconds = 300,
    Guid? SourceAlertId = null,
    Guid? SourceIncidentId = null,
    string? SourceEntityId = null);

public sealed record ProcessTreeResponseRequest(
    string Reason,
    int MaximumDepth = 4,
    int MaximumProcessCount = 64,
    int ExpiresInSeconds = 300,
    Guid? SourceAlertId = null,
    Guid? SourceIncidentId = null,
    string? SourceEntityId = null);

public sealed record ProcessResponsePreview(
    string SchemaVersion,
    Guid EndpointId,
    string AgentInstallationId,
    string ActionType,
    DateTimeOffset CapturedAt,
    string GraphSnapshotVersion,
    ProcessResponseTarget Root,
    ProcessResponseTarget[] Targets,
    string[] ProtectedTargets,
    int ChildCount,
    string? User,
    string? Session,
    string? Integrity,
    string? Signer,
    string? Hash,
    int NetworkActivityCount,
    int ActiveContextCount,
    string PlannedOrder);

public static partial class ProcessResponseSafety
{
    public const string SchemaVersion = "process-response.v1";
    public const int MaximumTreeDepth = 8;
    public const int MaximumTreeProcesses = 128;
    static readonly Regex Entity = EntityRegex();
    static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);
    static readonly HashSet<string> Actions =
    [
        "process.terminate", "process.suspend", "process.resume",
        "process_tree.terminate", "process.response_status"
    ];

    public static bool IsProcessAction(string actionType) => Actions.Contains(actionType);

    public static void ValidateActionParameters(string actionType, JsonElement value)
    {
        if (!IsProcessAction(actionType) || value.ValueKind != JsonValueKind.Object)
            throw new EnrollmentConflictException("PROCESS_RESPONSE_PARAMETERS", "A structured process-response object is required.");
        var allowed = actionType == "process_tree.terminate"
            ? new[] { "reason", "root", "targets", "capturedAt", "graphSnapshotVersion", "maximumDepth", "maximumProcessCount" }
            : new[] { "reason", "target" };
        var unknown = value.EnumerateObject().Select(x => x.Name).Except(allowed, StringComparer.Ordinal).FirstOrDefault();
        if (unknown is not null) throw new EnrollmentConflictException("PROCESS_RESPONSE_PARAMETER_UNKNOWN", "An unknown process-response parameter was rejected.");
        RequiredText(value, "reason", 1024);
        if (actionType == "process_tree.terminate")
        {
            ValidateTarget(value.GetProperty("root"));
            RequiredText(value, "graphSnapshotVersion", 128);
            if (!value.TryGetProperty("capturedAt", out var captured) || captured.ValueKind != JsonValueKind.String || !captured.TryGetDateTimeOffset(out _))
                throw new EnrollmentConflictException("PROCESS_RESPONSE_SNAPSHOT", "A valid graph capture time is required.");
            var depth = RequiredInt(value, "maximumDepth", 1, MaximumTreeDepth);
            var count = RequiredInt(value, "maximumProcessCount", 1, MaximumTreeProcesses);
            if (!value.TryGetProperty("targets", out var targets) || targets.ValueKind != JsonValueKind.Array || targets.GetArrayLength() is < 1 || targets.GetArrayLength() > count)
                throw new EnrollmentConflictException("PROCESS_RESPONSE_TREE_BOUNDS", "The pinned tree target set is missing or outside policy bounds.");
            var identities = new HashSet<string>(StringComparer.Ordinal);
            foreach (var target in targets.EnumerateArray())
            {
                ValidateTarget(target);
                var targetDepth = RequiredInt(target, "depth", 0, depth);
                _ = targetDepth;
                if (!identities.Add(target.GetProperty("processEntityId").GetString()!))
                    throw new EnrollmentConflictException("PROCESS_RESPONSE_TREE_DUPLICATE", "Duplicate tree targets are forbidden.");
            }
        }
        else ValidateTarget(value.GetProperty("target"));
    }

    public static JsonElement Parameters(string reason, ProcessResponseTarget target) =>
        JsonSerializer.SerializeToElement(new { reason, target }, WebJson);

    public static JsonElement TreeParameters(string reason, ProcessResponsePreview preview, int maximumDepth, int maximumProcessCount) =>
        JsonSerializer.SerializeToElement(new { reason, root = preview.Root, targets = preview.Targets, preview.CapturedAt, preview.GraphSnapshotVersion, maximumDepth, maximumProcessCount }, WebJson);

    static void ValidateTarget(JsonElement target)
    {
        if (target.ValueKind != JsonValueKind.Object) throw new EnrollmentConflictException("PROCESS_RESPONSE_TARGET", "A structured stable process target is required.");
        var allowed = new[] { "processEntityId", "processId", "processStartTime", "imagePath", "sha256", "depth" };
        if (target.EnumerateObject().Select(x => x.Name).Except(allowed, StringComparer.Ordinal).Any())
            throw new EnrollmentConflictException("PROCESS_RESPONSE_TARGET_UNKNOWN", "Unknown process target fields are forbidden.");
        var entity = RequiredText(target, "processEntityId", 64);
        if (!Entity.IsMatch(entity)) throw new EnrollmentConflictException("PROCESS_RESPONSE_ENTITY", "A canonical process entity ID is required; PID-only targeting is forbidden.");
        _ = RequiredInt(target, "processId", 1, int.MaxValue);
        if (!target.TryGetProperty("processStartTime", out var start) || start.ValueKind != JsonValueKind.String || !start.TryGetDateTimeOffset(out _))
            throw new EnrollmentConflictException("PROCESS_RESPONSE_START", "Process start identity is required.");
        if (target.TryGetProperty("imagePath", out var path) && path.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
            throw new EnrollmentConflictException("PROCESS_RESPONSE_PATH", "Image path is invalid.");
        if (target.TryGetProperty("sha256", out var hash) && hash.ValueKind != JsonValueKind.Null &&
            (hash.ValueKind != JsonValueKind.String || hash.GetString() is not { Length: 64 } text || !Entity.IsMatch(text)))
            throw new EnrollmentConflictException("PROCESS_RESPONSE_HASH", "Image hash is invalid.");
    }

    static string RequiredText(JsonElement value, string name, int maximum)
    {
        if (!value.TryGetProperty(name, out var item) || item.ValueKind != JsonValueKind.String || item.GetString() is not { } text ||
            string.IsNullOrWhiteSpace(text) || text.Length > maximum || text.Any(char.IsControl))
            throw new EnrollmentConflictException("PROCESS_RESPONSE_TEXT", $"{name} is invalid.");
        return text;
    }

    static int RequiredInt(JsonElement value, string name, int minimum, int maximum)
    {
        if (!value.TryGetProperty(name, out var item) || item.ValueKind != JsonValueKind.Number || !item.TryGetInt32(out var number) || number < minimum || number > maximum)
            throw new EnrollmentConflictException("PROCESS_RESPONSE_BOUNDS", $"{name} is outside safe bounds.");
        return number;
    }

    [GeneratedRegex("^[a-f0-9]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex EntityRegex();
}
