using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<FileQuarantineState>))]
public enum FileQuarantineState
{
    Requested, Acquiring, Quarantined, RestorePending, Restoring, Restored,
    DeletePending, Deleted, IdentityMismatch, Failed, Expired, Partial, Unknown
}

public sealed record FileResponseTarget(
    string FileEntityId,
    FileNativeIdentity NativeIdentity,
    string CanonicalPath,
    long Size,
    string? Sha256,
    DateTimeOffset ObservedAt,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? ModifiedAt);

public sealed record FileResponseRequest(
    string Reason,
    int ExpiresInSeconds = 300,
    Guid? SourceAlertId = null,
    Guid? SourceIncidentId = null,
    string? SourceEntityId = null);

public sealed record FileRestoreRequest(
    string Reason,
    int ExpiresInSeconds = 300,
    Guid? SourceAlertId = null,
    Guid? SourceIncidentId = null,
    string? SourceEntityId = null);

public sealed record FileResponsePreview(
    string SchemaVersion,
    Guid EndpointId,
    string AgentInstallationId,
    string ExpectedAction,
    FileResponseTarget Target,
    bool ProtectedPath,
    string ProtectionReason,
    int ProcessRelationshipCount,
    int ActiveContextCount,
    string FileInUseState,
    DateTimeOffset CapturedAt);

public sealed record FileQuarantineRecord(
    string SchemaVersion,
    Guid QuarantineId,
    Guid ActionId,
    string TenantId,
    Guid EndpointId,
    string AgentInstallationId,
    string FileEntityId,
    FileNativeIdentity OriginalNativeIdentity,
    string OriginalPath,
    string OriginalFileName,
    long OriginalSize,
    string Sha256,
    DateTimeOffset? OriginalCreationTime,
    DateTimeOffset? OriginalLastWriteTime,
    int OriginalAttributes,
    DateTimeOffset QuarantinedAt,
    DateTimeOffset RetainUntil,
    FileQuarantineState State,
    bool RestoreEligible,
    string StorageLocation,
    string IntegrityState,
    string RaceState,
    string MetadataState,
    string? FailureReason = null,
    DateTimeOffset? RestoredAt = null,
    DateTimeOffset? DeletedAt = null,
    FileNativeIdentity? RestoredNativeIdentity = null);

public static partial class FileResponseSafety
{
    public const string SchemaVersion = "file-response.v1";
    public const string PolicyVersion = "file-quarantine-policy.v1";
    public const long MaximumFileBytes = 8L * 1024 * 1024;
    public const long MaximumStoreBytes = 64L * 1024 * 1024;
    public const int MaximumStoreFiles = 64;
    public const int RetentionDays = 7;
    static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);
    static readonly Regex Entity = EntityRegex();
    static readonly Regex LocalWindowsPath = LocalWindowsPathRegex();
    static readonly HashSet<string> Actions =
    [
        "file.quarantine", "file.restore", "file.delete",
        "file.quarantine_status", "file.quarantine_metadata"
    ];

    public static bool IsFileResponseAction(string actionType) => Actions.Contains(actionType);

    public static JsonElement TargetParameters(string reason, FileResponseTarget target) =>
        JsonSerializer.SerializeToElement(new { reason, target }, WebJson);

    public static JsonElement QuarantineParameters(string reason, Guid quarantineId, FileResponseTarget target) =>
        JsonSerializer.SerializeToElement(new { reason, quarantineId, target, overwrite = false }, WebJson);

    public static JsonElement RecordParameters(string reason, Guid quarantineId) =>
        JsonSerializer.SerializeToElement(new { reason, quarantineId }, WebJson);

    public static void ValidateActionParameters(string actionType, JsonElement value)
    {
        if (!IsFileResponseAction(actionType) || value.ValueKind != JsonValueKind.Object)
            throw new EnrollmentConflictException("FILE_RESPONSE_PARAMETERS", "A structured file-response object is required.");
        var recordOnly = actionType is "file.quarantine_status" or "file.quarantine_metadata";
        var restore = actionType == "file.restore";
        var allowed = recordOnly ? new[] { "reason", "quarantineId" }
            : restore ? new[] { "reason", "quarantineId", "target", "overwrite" }
            : new[] { "reason", "target" };
        if (value.EnumerateObject().Select(x => x.Name).Except(allowed, StringComparer.Ordinal).Any())
            throw new EnrollmentConflictException("FILE_RESPONSE_PARAMETER_UNKNOWN", "Unknown file-response fields are forbidden.");
        RequiredText(value, "reason", 1024);
        if (recordOnly || restore)
        {
            if (!value.TryGetProperty("quarantineId", out var id) || id.ValueKind != JsonValueKind.String || !id.TryGetGuid(out _))
                throw new EnrollmentConflictException("FILE_RESPONSE_QUARANTINE_ID", "A valid quarantine identity is required.");
        }
        if (restore)
        {
            if (!value.TryGetProperty("overwrite", out var overwrite) || overwrite.ValueKind != JsonValueKind.False)
                throw new EnrollmentConflictException("FILE_RESPONSE_OVERWRITE", "Sprint 20 restore never overwrites an occupied destination.");
        }
        if (!recordOnly)
        {
            if (!value.TryGetProperty("target", out var target))
                throw new EnrollmentConflictException("FILE_RESPONSE_TARGET", "A structured stable file target is required.");
            ValidateTarget(target);
        }
    }

    public static void ValidateTarget(JsonElement target)
    {
        if (target.ValueKind != JsonValueKind.Object)
            throw new EnrollmentConflictException("FILE_RESPONSE_TARGET", "A structured stable file target is required.");
        var allowed = new[] { "fileEntityId", "nativeIdentity", "canonicalPath", "size", "sha256", "observedAt", "createdAt", "modifiedAt" };
        if (target.EnumerateObject().Select(x => x.Name).Except(allowed, StringComparer.Ordinal).Any())
            throw new EnrollmentConflictException("FILE_RESPONSE_TARGET_UNKNOWN", "Unknown file target fields are forbidden.");
        var entity = RequiredText(target, "fileEntityId", 64);
        if (!Entity.IsMatch(entity)) throw new EnrollmentConflictException("FILE_RESPONSE_ENTITY", "A canonical file entity is required; path-only targeting is forbidden.");
        var path = RequiredText(target, "canonicalPath", 1024);
        if (!LocalWindowsPath.IsMatch(path) || path.Contains("..", StringComparison.Ordinal) || path[2..].Contains(':'))
            throw new EnrollmentConflictException("FILE_RESPONSE_PATH", "Only canonical local Windows paths without traversal, streams, UNC, or device prefixes are accepted.");
        if (!target.TryGetProperty("size", out var size) || !size.TryGetInt64(out var bytes) || bytes is < 0 or > MaximumFileBytes)
            throw new EnrollmentConflictException("FILE_RESPONSE_SIZE", "File size is outside the bounded quarantine policy.");
        if (!target.TryGetProperty("nativeIdentity", out var native) || native.ValueKind != JsonValueKind.Object ||
            !native.TryGetProperty("volumeId", out var volume) || string.IsNullOrWhiteSpace(volume.GetString()) ||
            !native.TryGetProperty("fileId", out var file) || string.IsNullOrWhiteSpace(file.GetString()))
            throw new EnrollmentConflictException("FILE_RESPONSE_NATIVE_IDENTITY", "A native volume/file identity is required.");
        var nativeAllowed = new[] { "volumeId", "fileId", "deviceId", "inode", "parentDirectoryId", "symbolicLink", "hardLink", "mountId" };
        if (native.EnumerateObject().Select(x => x.Name).Except(nativeAllowed, StringComparer.Ordinal).Any())
            throw new EnrollmentConflictException("FILE_RESPONSE_NATIVE_IDENTITY", "Unknown native identity fields are forbidden.");
        if (native.TryGetProperty("symbolicLink", out var reparse) && reparse.ValueKind == JsonValueKind.True)
            throw new EnrollmentConflictException("FILE_RESPONSE_REPARSE", "Reparse-point targets are forbidden.");
        if (native.TryGetProperty("hardLink", out var hardLink) && hardLink.ValueKind == JsonValueKind.True)
            throw new EnrollmentConflictException("FILE_RESPONSE_HARDLINK", "Hard-link targets are forbidden.");
        if (target.TryGetProperty("sha256", out var hash) && hash.ValueKind != JsonValueKind.Null &&
            (hash.ValueKind != JsonValueKind.String || hash.GetString() is not { Length: 64 } text || !Entity.IsMatch(text)))
            throw new EnrollmentConflictException("FILE_RESPONSE_HASH", "SHA-256 is invalid.");
        if (!target.TryGetProperty("observedAt", out var observed) || observed.ValueKind != JsonValueKind.String || !observed.TryGetDateTimeOffset(out _))
            throw new EnrollmentConflictException("FILE_RESPONSE_OBSERVED", "The authoritative observation time is required.");
    }

    public static bool IsHardProtectedPath(string path, string? agentRoot = null)
    {
        var canonical = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
        if (!string.IsNullOrWhiteSpace(agentRoot) && canonical.StartsWith(Path.GetFullPath(agentRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return true;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(windows) && canonical.StartsWith(Path.GetFullPath(windows).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return true;
        return canonical.Equals(Path.GetPathRoot(canonical)?.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
    }

    static string RequiredText(JsonElement value, string name, int maximum)
    {
        if (!value.TryGetProperty(name, out var item) || item.ValueKind != JsonValueKind.String || item.GetString() is not { } text ||
            string.IsNullOrWhiteSpace(text) || text.Length > maximum || text.Any(char.IsControl))
            throw new EnrollmentConflictException("FILE_RESPONSE_TEXT", $"{name} is invalid.");
        return text;
    }

    [GeneratedRegex("^[a-f0-9]{64}$", RegexOptions.CultureInvariant)] private static partial Regex EntityRegex();
    [GeneratedRegex("^[A-Za-z]:[\\\\/][^*?\"<>|\\r\\n]+$", RegexOptions.CultureInvariant)] private static partial Regex LocalWindowsPathRegex();
}
