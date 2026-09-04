using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<PersistenceRemediationStage>))]
public enum PersistenceRemediationStage { Validating, BackingUp, MutationStarted, Verifying, Succeeded, Partial, Failed }

[JsonConverter(typeof(JsonStringEnumConverter<PersistenceRemediationState>))]
public enum PersistenceRemediationState
{
    Requested, BackingUp, BackupCreated, MutationStarted, Removed, Disabled, Stopped,
    Restoring, Restored, Partial, TargetIdentityMismatch, DestinationOccupied,
    SharedDependency, Protected, VerificationFailed, Failed, Unknown
}

[JsonConverter(typeof(JsonStringEnumConverter<PersistenceRemediationKind>))]
public enum PersistenceRemediationKind { RegistryValue, RegistryKey, Service, ScheduledTask, WmiFilter, WmiConsumer, WmiBinding, StartupFile, GenericRegistryConfiguration }

public sealed record PersistenceRemediationTarget(
    string PersistenceEntityId,
    Guid EvidenceEventId,
    PersistenceObjectKind ObjectKind,
    PersistenceRemediationKind RemediationKind,
    string Category,
    string CanonicalIdentity,
    long LifecycleGeneration,
    string ExpectedStateHash,
    string CurrentState,
    string[] EvidenceReferences,
    string? RegistryHive = null,
    string? RegistryView = null,
    string? RegistryKeyPath = null,
    string? RegistryValueName = null,
    string? RegistryValueEntityId = null,
    string? ServiceName = null,
    string? ServiceBinaryPath = null,
    string? ServiceStartType = null,
    string? ServiceAccount = null,
    bool? DriverService = null,
    string? TaskPath = null,
    string? TaskXmlSha256 = null,
    string? WmiNamespace = null,
    string? WmiClass = null,
    string? WmiRelativePath = null,
    string? FilterIdentity = null,
    string? ConsumerIdentity = null,
    string? FilePath = null,
    string? ExpectedValue = null);

public sealed record PersistenceRemediationRequest(
    string ActionType,
    string Reason,
    int ExpiresInSeconds = 300,
    Guid? SourceAlertId = null,
    Guid? SourceIncidentId = null,
    string? SourceEntityId = null);

public sealed record PersistenceRestoreRequest(
    string Reason,
    int ExpiresInSeconds = 300,
    Guid? SourceAlertId = null,
    Guid? SourceIncidentId = null,
    string? SourceEntityId = null);

public sealed record PersistenceRemediationPreview(
    string SchemaVersion,
    Guid EndpointId,
    string AgentInstallationId,
    PersistenceRemediationTarget Target,
    string[] SupportedActions,
    bool BackupSupported,
    bool RestoreSupported,
    bool Protected,
    string ProtectionReason,
    string[] Dependencies,
    int ProcessRelationshipCount,
    int ActiveContextCount,
    DateTimeOffset CapturedAt);

public sealed record PersistenceRemediationStep(
    PersistenceRemediationStage Stage,
    string Result,
    DateTimeOffset OccurredAt,
    string? Detail = null);

public sealed record PersistenceBackupRecord(
    Guid BackupId,
    string TenantId,
    Guid EndpointId,
    string AgentInstallationId,
    Guid SourceActionId,
    PersistenceRemediationTarget Target,
    string ContentSha256,
    long ContentBytes,
    string EncryptionState,
    string StorageLocation,
    DateTimeOffset CreatedAt,
    DateTimeOffset RetainUntil,
    bool RestoreEligible,
    PersistenceRemediationState State,
    string IntegrityState);

public sealed record PersistenceRemediationRecord(
    string SchemaVersion,
    Guid RemediationId,
    string TenantId,
    Guid EndpointId,
    string AgentInstallationId,
    string ActionType,
    PersistenceRemediationTarget? Target,
    Guid? BackupId,
    PersistenceRemediationState State,
    string? FailureReason,
    PersistenceRemediationStep[] Steps,
    PersistenceBackupRecord? Backup,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    string VerificationState,
    string HistoricalEvidenceState = "preserved");

public static class PersistenceResponseSafety
{
    static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);
    public const string SchemaVersion = "persistence-remediation.v1";
    public const string PolicyVersion = "persistence-remediation-policy.v1";
    public const int MaximumBackupBytes = 512 * 1024;
    public const long MaximumStoreBytes = 32L * 1024 * 1024;
    public const int MaximumStoreRecords = 128;
    public const int RetentionDays = 7;
    public static readonly string[] ActionTypes =
    [
        "registry.value.remove", "registry.value.restore", "registry.key.remove", "registry.remediation_status",
        "service.stop", "service.disable", "service.delete", "service.restore",
        "scheduled_task.disable", "scheduled_task.delete", "scheduled_task.restore",
        "wmi.binding.remove", "wmi.consumer.remove", "wmi.filter.remove", "wmi.persistence.restore",
        "persistence.remove", "persistence.restore", "persistence.remediation_status"
    ];

    public static bool IsAction(string action) => ActionTypes.Contains(action, StringComparer.Ordinal);
    public static bool IsRestore(string action) => action is "registry.value.restore" or "service.restore" or "scheduled_task.restore" or "wmi.persistence.restore" or "persistence.restore";
    public static bool IsStatus(string action) => action is "registry.remediation_status" or "persistence.remediation_status";

    public static JsonElement TargetParameters(string reason, PersistenceRemediationTarget target) =>
        JsonSerializer.SerializeToElement(new { reason, target }, WebJson);
    public static JsonElement BackupParameters(string reason, Guid backupId) =>
        JsonSerializer.SerializeToElement(new { reason, backupId }, WebJson);

    public static void ValidateActionParameters(string action, JsonElement parameters)
    {
        if (!IsAction(action) || parameters.ValueKind != JsonValueKind.Object)
            throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_ACTION", "Unsupported persistence remediation action.");
        var allowed = IsRestore(action) || IsStatus(action) ? new[] { "reason", "backupId" } : new[] { "reason", "target" };
        var properties = parameters.EnumerateObject().ToArray();
        if (properties.Select(x => x.Name).Except(allowed, StringComparer.Ordinal).Any())
            throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_PARAMETER", "Unknown persistence remediation parameter rejected.");
        var reason = RequiredText(parameters, "reason", 1024);
        if (reason.Trim().Length < 4) throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_REASON", "A meaningful remediation reason is required.");
        if (IsRestore(action) || IsStatus(action))
        {
            if (!parameters.TryGetProperty("backupId", out var id) || id.ValueKind != JsonValueKind.String || !Guid.TryParse(id.GetString(), out _))
                throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_BACKUP", "A canonical backup identity is required.");
            return;
        }
        if (!parameters.TryGetProperty("target", out var value) || value.ValueKind != JsonValueKind.Object)
            throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_TARGET", "An authoritative target object is required; name or path alone is forbidden.");
        var targetAllowed = new[] { "persistenceEntityId", "evidenceEventId", "objectKind", "remediationKind", "category", "canonicalIdentity", "lifecycleGeneration", "expectedStateHash", "currentState", "evidenceReferences", "registryHive", "registryView", "registryKeyPath", "registryValueName", "registryValueEntityId", "serviceName", "serviceBinaryPath", "serviceStartType", "serviceAccount", "driverService", "taskPath", "taskXmlSha256", "wmiNamespace", "wmiClass", "wmiRelativePath", "filterIdentity", "consumerIdentity", "filePath", "expectedValue" };
        if (value.EnumerateObject().Select(x => x.Name).Except(targetAllowed, StringComparer.Ordinal).Any())
            throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_TARGET", "Unknown target field rejected.");
        PersistenceRemediationTarget target;
        try { target = value.Deserialize<PersistenceRemediationTarget>(WebJson) ?? throw new JsonException(); }
        catch (JsonException) { throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_TARGET", "Target contract is malformed."); }
        ValidateTarget(action, target);
    }

    public static void ValidateTarget(string action, PersistenceRemediationTarget target)
    {
        if (target.PersistenceEntityId is null || target.PersistenceEntityId.Length != 64 || !Hex(target.PersistenceEntityId) || target.EvidenceEventId == Guid.Empty ||
            string.IsNullOrWhiteSpace(target.Category) || target.Category.Length > 128 || target.Category.Any(char.IsControl) ||
            string.IsNullOrWhiteSpace(target.CanonicalIdentity) || target.CanonicalIdentity.Length > 4096 || target.CanonicalIdentity.Any(char.IsControl) ||
            target.LifecycleGeneration < 1 || target.ExpectedStateHash is null || target.ExpectedStateHash.Length != 64 || !Hex(target.ExpectedStateHash) ||
            string.IsNullOrWhiteSpace(target.CurrentState) || target.EvidenceReferences is not { Length: > 0 and <= 64 } ||
            target.EvidenceReferences.Any(x => string.IsNullOrWhiteSpace(x) || x.Length > 2048 || x.Any(char.IsControl)))
            throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_IDENTITY", "Stable target identity, lifecycle generation, state hash and evidence are required.");
        switch (target.RemediationKind)
        {
            case PersistenceRemediationKind.RegistryValue:
            case PersistenceRemediationKind.RegistryKey:
            case PersistenceRemediationKind.GenericRegistryConfiguration:
                Required(target.RegistryHive, 8); Required(target.RegistryView, 32); Required(target.RegistryKeyPath, 2048);
                if (target.RemediationKind != PersistenceRemediationKind.RegistryKey) Required(target.RegistryValueName, 512);
                break;
            case PersistenceRemediationKind.Service:
                Required(target.ServiceName, 256); if (target.DriverService == true) throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_DRIVER", "Driver service remediation is not supported."); break;
            case PersistenceRemediationKind.ScheduledTask: Required(target.TaskPath, 1024); break;
            case PersistenceRemediationKind.WmiFilter:
            case PersistenceRemediationKind.WmiConsumer:
            case PersistenceRemediationKind.WmiBinding:
                Required(target.WmiNamespace, 256); Required(target.WmiClass, 128); Required(target.WmiRelativePath, 4096); break;
            case PersistenceRemediationKind.StartupFile: Required(target.FilePath, 2048); break;
        }
        if (action.StartsWith("service.", StringComparison.Ordinal) && target.RemediationKind != PersistenceRemediationKind.Service ||
            action.StartsWith("scheduled_task.", StringComparison.Ordinal) && target.RemediationKind != PersistenceRemediationKind.ScheduledTask ||
            action.StartsWith("wmi.", StringComparison.Ordinal) && target.RemediationKind is not (PersistenceRemediationKind.WmiBinding or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiFilter))
            throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_KIND", "Action and canonical target kind do not match.");
    }

    public static string StateHash(params string?[] values) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values.Select(x => x ?? "<null>"))))).ToLowerInvariant();
    static string RequiredText(JsonElement value, string name, int maximum) => value.TryGetProperty(name, out var x) && x.ValueKind == JsonValueKind.String && x.GetString() is { } text && text.Length is > 0 && text.Length <= maximum && !text.Any(char.IsControl) ? text : throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_PARAMETER", $"{name} is invalid.");
    static void Required(string? value, int maximum) { if (string.IsNullOrWhiteSpace(value) || value.Length > maximum || value.Any(char.IsControl)) throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_IDENTITY", "Target-specific stable identity is incomplete."); }
    static bool Hex(string value) => value.All(x => Uri.IsHexDigit(x));
}
