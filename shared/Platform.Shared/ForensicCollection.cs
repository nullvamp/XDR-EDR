using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<ForensicCollectionState>))]
public enum ForensicCollectionState { Draft, PendingApproval, Approved, Queued, Delivered, Running, Partial, Succeeded, Failed, CancelRequested, Cancelled, CancelledWithEvidence, Expired }
[JsonConverter(typeof(JsonStringEnumConverter<ForensicArtifactType>))]
public enum ForensicArtifactType { SystemInformation, ProcessInventory, UserSessionInventory, ServiceInventory, ScheduledTaskInventory, NetworkState, DnsState, InstalledSoftwareInventory, PersistenceSnapshot, File, Directory, WindowsEventLog, Registry }
[JsonConverter(typeof(JsonStringEnumConverter<ForensicItemState>))]
public enum ForensicItemState { Pending, Running, Acquired, Failed, Skipped, UnstableDuringAcquisition, Truncated, Cancelled }
[JsonConverter(typeof(JsonStringEnumConverter<ForensicRaceState>))]
public enum ForensicRaceState { NotApplicable, Stable, UnstableDuringAcquisition, IdentityUnavailable }
[JsonConverter(typeof(JsonStringEnumConverter<ForensicSensitivity>))]
public enum ForensicSensitivity { Internal, Restricted, High }

public sealed record ForensicFileTarget(string FileEntityId, FileNativeIdentity NativeIdentity, string CanonicalPath, long ExpectedSize, string? ExpectedSha256, DateTimeOffset ObservedAt);
public sealed record ForensicArtifactRequest(string RequestId, ForensicArtifactType ArtifactType, string? Source = null, ForensicFileTarget? FileTarget = null, int MaximumDepth = 0, int MaximumItems = 1, long MaximumBytes = 0, int MaximumRecords = 0, int LookbackMinutes = 0, string[]? AllowedExtensions = null, bool IncludeHidden = false, bool MetadataOnly = false);
public sealed record ForensicCollectionProfile(string SchemaVersion, string ProfileId, int Version, string Name, ForensicArtifactType[] ArtifactCategories, int MaximumItems, long MaximumBytes, int MaximumRuntimeSeconds, string[] PlatformRequirements, string PrivilegeRequirement, ForensicSensitivity Sensitivity, bool ApprovalRequired, string CollectionMethod, string CollectionMethodVersion, string ProfileHash);
public sealed record ForensicCollectionRequest(Guid EndpointId, string ProfileId, int ProfileVersion, ForensicArtifactRequest[] RequestedArtifacts, string Reason, int ExpiresInSeconds = 900, Guid? SourceAlertId = null, Guid? SourceIncidentId = null, string? SourceEntityId = null, bool SaveAsDraft = false, string PolicyVersion = "forensic-collection-policy.v1");
public sealed record ForensicCollectionPreview(string SchemaVersion, Guid EndpointId, string AgentInstallationId, ForensicCollectionProfile Profile, ForensicArtifactRequest[] RequestedArtifacts, int MaximumItems, long MaximumBytes, int MaximumRuntimeSeconds, bool ApprovalRequired, string[] Warnings, string RequestHash, DateTimeOffset CapturedAt);
public sealed record ForensicEvidenceItem(string SchemaVersion, Guid EvidenceItemId, Guid CollectionId, string RequestId, ForensicArtifactType ArtifactType, Guid SourceEndpointId, string SourceObject, string? NativeIdentity, string AcquisitionMethod, string AcquisitionToolVersion, DateTimeOffset ObservedAt, DateTimeOffset AcquisitionStartedAt, DateTimeOffset AcquisitionCompletedAt, long OriginalSize, long AcquiredSize, string? Sha256, JsonElement? PreMetadata, JsonElement? PostMetadata, ForensicRaceState RaceState, bool Truncated, string CollectionQuality, ForensicItemState State, string? FailureReason, Guid? ArtifactId, bool ManifestMember, ForensicSensitivity Sensitivity);
public sealed record ForensicCustodyEvent(Guid EventId, Guid CollectionId, string EventType, string Actor, DateTimeOffset OccurredAt, string IntegrityHash, string Summary, string Provenance = "technical-chain-of-custody.v1");
public sealed record ForensicCollectionManifest(string SchemaVersion, Guid CollectionId, string TenantId, Guid EndpointId, string AgentInstallationId, string AnalystId, string ProfileId, int ProfileVersion, string ProfileHash, string PolicyVersion, ForensicArtifactRequest[] RequestedScope, string[] ActualScope, DateTimeOffset StartedAt, DateTimeOffset CompletedAt, ForensicEvidenceItem[] EvidenceItems, int CollectedItems, int FailedItems, int SkippedItems, int UnstableItems, int TruncatedItems, long BytesCollected, string PlatformVersion, string PackageHash);
public sealed record ForensicCollectionResult(string SchemaVersion, Guid CollectionId, ForensicCollectionState State, ForensicEvidenceItem[] Items, Guid ManifestArtifactId, string ManifestHash, string PackageHash, long BytesCollected, int CollectedItems, int FailedItems, int SkippedItems, int UnstableItems, int TruncatedItems, bool CancellationObserved, string? FailureReason, string CollectionMethodVersion);

public static partial class ForensicCollectionSafety
{
    public const string SchemaVersion = "forensic-collection.v1";
    public const string ManifestSchemaVersion = "forensic-collection-manifest.v1";
    public const string ItemSchemaVersion = "forensic-evidence-item.v1";
    public const string PolicyVersion = "forensic-collection-policy.v1";
    public const string ActionType = "forensic.collect";
    public const int MaximumRequestedArtifacts = 32;
    public const int MaximumEvidenceItems = 64;
    public const int MaximumFiles = 32;
    public const int MaximumDirectoryDepth = 4;
    public const int MaximumEventRecords = 10_000;
    public const int MaximumRegistryEntries = 1_024;
    public const long MaximumSingleArtifactBytes = ArtifactTransferSafety.MaximumArtifactBytes;
    public const long MaximumCollectionBytes = 8L * 1024 * 1024 * 1024;
    public const int MaximumRuntimeSeconds = 14_400;
    public const int MaximumConcurrentJobsPerEndpoint = 2;
    public const int MaximumConcurrentJobsPerTenant = 16;
    public const int RetentionDays = 7;
    static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);
    static readonly Regex Identifier = IdentifierRegex();
    static readonly Regex LocalWindowsPath = LocalWindowsPathRegex();
    static readonly HashSet<string> ApprovedEventChannels = new(StringComparer.OrdinalIgnoreCase) { "Application", "System", "Security", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "Microsoft-Windows-Windows Defender/Operational" };
    static readonly HashSet<string> ApprovedRegistryRoots = new(StringComparer.OrdinalIgnoreCase) { "HKLM\\SOFTWARE", "HKLM\\SYSTEM", "HKCU\\SOFTWARE" };
    public static readonly IReadOnlyDictionary<string, ForensicCollectionProfile> Profiles = BuildProfiles();

    static Dictionary<string, ForensicCollectionProfile> BuildProfiles()
    {
        var values = new[]
        {
            Profile("quick-triage", "Quick Triage", [ForensicArtifactType.SystemInformation, ForensicArtifactType.ProcessInventory, ForensicArtifactType.UserSessionInventory, ForensicArtifactType.ServiceInventory, ForensicArtifactType.ScheduledTaskInventory, ForensicArtifactType.NetworkState, ForensicArtifactType.PersistenceSnapshot], 16, 4 * 1024 * 1024, 120, ForensicSensitivity.Internal, false, "windows-native-structured"),
            Profile("windows-event-evidence", "Windows Event Evidence", [ForensicArtifactType.WindowsEventLog], 8, 8 * 1024 * 1024, 180, ForensicSensitivity.Restricted, true, "windows-eventlog-export"),
            Profile("registry-triage", "Registry Triage", [ForensicArtifactType.Registry], 8, 8 * 1024 * 1024, 180, ForensicSensitivity.High, true, "windows-registry-structured-export"),
            Profile("file-evidence", "File Evidence", [ForensicArtifactType.File, ForensicArtifactType.Directory], 32, MaximumCollectionBytes, MaximumRuntimeSeconds, ForensicSensitivity.Restricted, true, "identity-bound-handle-copy+resumable-chunks"),
            Profile("endpoint-investigation", "Endpoint Investigation Package", Enum.GetValues<ForensicArtifactType>(), MaximumEvidenceItems, MaximumCollectionBytes, MaximumRuntimeSeconds, ForensicSensitivity.High, true, "bounded-forensic-collection")
        };
        return values.ToDictionary(x => x.ProfileId, StringComparer.Ordinal);
    }

    static ForensicCollectionProfile Profile(string id, string name, ForensicArtifactType[] categories, int items, long bytes, int runtime, ForensicSensitivity sensitivity, bool approval, string method)
    {
        var hashInput = JsonSerializer.SerializeToElement(new { id, version = 1, categories, items, bytes, runtime, sensitivity, approval, method }, WebJson);
        var hash = Convert.ToHexString(SHA256.HashData(ResponseSafety.CanonicalJson(hashInput))).ToLowerInvariant();
        return new("forensic-collection-profile.v1", id, 1, name, categories, items, bytes, runtime, ["windows"], "profile-dependent", sensitivity, approval, method, "1.0.0", hash);
    }

    public static JsonElement ActionParameters(Guid collectionId, string analystId, ForensicCollectionRequest request, ForensicCollectionProfile profile) => JsonSerializer.SerializeToElement(new { collectionId, analystId, request.Reason, profileId = profile.ProfileId, profileVersion = profile.Version, profileHash = profile.ProfileHash, requestedArtifacts = request.RequestedArtifacts, request.PolicyVersion }, WebJson);

    public static void ValidateActionParameters(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Error("FORENSIC_PARAMETERS", "A structured collection request is required.");
        string[] allowed = ["collectionId", "analystId", "reason", "profileId", "profileVersion", "profileHash", "requestedArtifacts", "policyVersion"];
        if (value.EnumerateObject().Select(x => x.Name).Except(allowed, StringComparer.Ordinal).Any()) throw Error("FORENSIC_PARAMETER_UNKNOWN", "Unknown collection fields are forbidden.");
        if (!value.TryGetProperty("collectionId", out var collection) || !collection.TryGetGuid(out _)) throw Error("FORENSIC_COLLECTION_ID", "A collection identity is required.");
        _ = RequiredText(value, "analystId", 256);
        var reason = RequiredText(value, "reason", 1024); if (reason.Trim().Length < 4) throw Error("FORENSIC_REASON", "A meaningful collection reason is required.");
        var profileId = RequiredText(value, "profileId", 64);
        if (!Profiles.TryGetValue(profileId, out var profile) || !value.TryGetProperty("profileVersion", out var version) || !version.TryGetInt32(out var v) || v != profile.Version || RequiredText(value, "profileHash", 64) != profile.ProfileHash) throw Error("FORENSIC_PROFILE", "The immutable collection profile identity, version, or hash is invalid.");
        if (RequiredText(value, "policyVersion", 64) != PolicyVersion) throw Error("FORENSIC_POLICY", "The collection policy version is unsupported.");
        if (!value.TryGetProperty("requestedArtifacts", out var requested) || requested.ValueKind != JsonValueKind.Array) throw Error("FORENSIC_SCOPE", "A bounded artifact scope is required.");
        ForensicArtifactRequest[] artifacts; try { artifacts = requested.Deserialize<ForensicArtifactRequest[]>(WebJson) ?? []; } catch (JsonException) { throw Error("FORENSIC_SCOPE", "The artifact scope is malformed."); }
        ValidateArtifacts(profile, artifacts);
    }

    public static void ValidateRequest(ForensicCollectionRequest request)
    {
        if (request.EndpointId == Guid.Empty || request.PolicyVersion != PolicyVersion || request.ExpiresInSeconds is < 60 or > 86_400 || string.IsNullOrWhiteSpace(request.Reason) || request.Reason.Length > 1024) throw Error("FORENSIC_REQUEST", "Collection request metadata is invalid.");
        if (!Profiles.TryGetValue(request.ProfileId, out var profile) || request.ProfileVersion != profile.Version) throw Error("FORENSIC_PROFILE", "Unknown collection profile or version.");
        ValidateArtifacts(profile, request.RequestedArtifacts);
    }

    public static void ValidateArtifacts(ForensicCollectionProfile profile, ForensicArtifactRequest[] artifacts)
    {
        if (artifacts is not { Length: > 0 and <= MaximumRequestedArtifacts } || artifacts.Length > profile.MaximumItems) throw Error("FORENSIC_ITEM_LIMIT", "Requested artifact count exceeds the profile bound.");
        if (artifacts.Select(x => x.RequestId).Distinct(StringComparer.Ordinal).Count() != artifacts.Length) throw Error("FORENSIC_REQUEST_ID", "Artifact request identities must be unique.");
        long requestedBytes = 0;
        foreach (var item in artifacts)
        {
            if (!Identifier.IsMatch(item.RequestId) || !profile.ArtifactCategories.Contains(item.ArtifactType)) throw Error("FORENSIC_ARTIFACT_TYPE", "Artifact type is not authorized by the selected profile.");
            if (item.MaximumItems is < 1 or > MaximumFiles || item.MaximumBytes is < 0 or > MaximumCollectionBytes || item.MaximumRecords is < 0 or > MaximumEventRecords || item.MaximumDepth is < 0 or > MaximumDirectoryDepth || item.LookbackMinutes is < 0 or > 43_200) throw Error("FORENSIC_ARTIFACT_BOUNDS", "Artifact bounds exceed policy.");
            requestedBytes = checked(requestedBytes + item.MaximumBytes);
            switch (item.ArtifactType)
            {
                case ForensicArtifactType.File: if (item.FileTarget is null) throw Error("FORENSIC_FILE_IDENTITY", "File collection requires an authoritative file entity and native identity."); ValidateFile(item.FileTarget); break;
                case ForensicArtifactType.Directory: ValidatePath(item.Source, false); if (item.MaximumDepth < 1 || item.MaximumBytes < 1) throw Error("FORENSIC_DIRECTORY_BOUNDS", "Directory collection requires explicit depth, file, and byte bounds."); if (item.AllowedExtensions is null || item.AllowedExtensions.Length is < 1 or > 32 || item.AllowedExtensions.Any(x => !Regex.IsMatch(x, "^\\.[A-Za-z0-9]{1,15}$"))) throw Error("FORENSIC_DIRECTORY_TYPES", "Directory collection requires bounded literal extensions."); break;
                case ForensicArtifactType.WindowsEventLog: if (item.Source is null || !ApprovedEventChannels.Contains(item.Source) || item.MaximumRecords < 1 || item.MaximumBytes < 1 || item.LookbackMinutes < 1) throw Error("FORENSIC_EVENTLOG_SCOPE", "Event Log collection requires an approved exact channel and bounded range."); break;
                case ForensicArtifactType.Registry: ValidateRegistry(item.Source, item.MetadataOnly); if (item.MaximumItems > MaximumRegistryEntries || item.MaximumBytes < 1) throw Error("FORENSIC_REGISTRY_BOUNDS", "Registry scope exceeds policy."); break;
                default: if (item.Source is not null || item.FileTarget is not null) throw Error("FORENSIC_STRUCTURED_SCOPE", "Structured inventories do not accept analyst-controlled source paths."); break;
            }
        }
        if (requestedBytes > profile.MaximumBytes || requestedBytes > MaximumCollectionBytes) throw Error("FORENSIC_BYTE_QUOTA", "Requested byte quota exceeds the selected profile.");
    }

    static void ValidateFile(ForensicFileTarget target)
    {
        if (target.FileEntityId.Length != 64 || !target.FileEntityId.All(Uri.IsHexDigit) || target.ExpectedSize is < 0 or > MaximumSingleArtifactBytes || string.IsNullOrWhiteSpace(target.NativeIdentity.VolumeId) || string.IsNullOrWhiteSpace(target.NativeIdentity.FileId) || target.NativeIdentity.SymbolicLink == true || target.NativeIdentity.HardLink == true) throw Error("FORENSIC_FILE_IDENTITY", "A bounded, non-link native file identity is required.");
        ValidatePath(target.CanonicalPath, true);
        if (target.ExpectedSha256 is not null && (target.ExpectedSha256.Length != 64 || !target.ExpectedSha256.All(Uri.IsHexDigit))) throw Error("FORENSIC_FILE_HASH", "Expected file hash is invalid.");
    }

    static void ValidatePath(string? path, bool file)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 1024 || !LocalWindowsPath.IsMatch(path) || path.Contains("..", StringComparison.Ordinal) || path.IndexOfAny(['*', '?']) >= 0 || path.StartsWith("\\\\", StringComparison.Ordinal) || path.StartsWith("\\\\?\\", StringComparison.Ordinal) || path[2..].Contains(':')) throw Error("FORENSIC_PATH", "Only exact local Windows paths without traversal, wildcards, streams, UNC, or device prefixes are allowed.");
        var root = Path.GetPathRoot(path); if (string.Equals(path.TrimEnd('\\', '/'), root?.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase)) throw Error("FORENSIC_ROOT_COLLECTION", "Volume-root collection is forbidden.");
        if (file && path.EndsWith('\\')) throw Error("FORENSIC_FILE_PATH", "File target must be an exact file path.");
    }

    static void ValidateRegistry(string? source, bool metadataOnly)
    {
        if (string.IsNullOrWhiteSpace(source) || source.Length > 1024 || source.Contains("..", StringComparison.Ordinal) || source.IndexOfAny(['*', '?']) >= 0) throw Error("FORENSIC_REGISTRY_SCOPE", "Registry target must be an exact approved key.");
        if (!ApprovedRegistryRoots.Any(root => source.Equals(root, StringComparison.OrdinalIgnoreCase) || source.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))) throw Error("FORENSIC_REGISTRY_SCOPE", "Registry target is outside approved roots.");
        if ((source.StartsWith("HKLM\\SAM", StringComparison.OrdinalIgnoreCase) || source.StartsWith("HKLM\\SECURITY", StringComparison.OrdinalIgnoreCase)) && !metadataOnly) throw Error("FORENSIC_SECRET_SCOPE", "Sensitive credential-bearing hives may only be represented as metadata.");
    }

    public static bool IsValidTransition(ForensicCollectionState from, ForensicCollectionState to) => (from, to) switch
    {
        (ForensicCollectionState.Draft, ForensicCollectionState.PendingApproval or ForensicCollectionState.Queued or ForensicCollectionState.Cancelled) => true,
        (ForensicCollectionState.PendingApproval, ForensicCollectionState.Approved or ForensicCollectionState.Cancelled or ForensicCollectionState.Expired) => true,
        (ForensicCollectionState.Approved, ForensicCollectionState.Queued or ForensicCollectionState.Cancelled or ForensicCollectionState.Expired) => true,
        (ForensicCollectionState.Queued, ForensicCollectionState.Delivered or ForensicCollectionState.Cancelled or ForensicCollectionState.Expired) => true,
        (ForensicCollectionState.Delivered, ForensicCollectionState.Running or ForensicCollectionState.CancelRequested or ForensicCollectionState.Expired) => true,
        (ForensicCollectionState.Running, ForensicCollectionState.Succeeded or ForensicCollectionState.Partial or ForensicCollectionState.Failed or ForensicCollectionState.CancelRequested or ForensicCollectionState.CancelledWithEvidence or ForensicCollectionState.Cancelled) => true,
        (ForensicCollectionState.CancelRequested, ForensicCollectionState.Cancelled or ForensicCollectionState.CancelledWithEvidence) => true,
        _ => false
    };

    public static string Hash(JsonElement value) => Convert.ToHexString(SHA256.HashData(ResponseSafety.CanonicalJson(value))).ToLowerInvariant();
    static string RequiredText(JsonElement value, string name, int maximum) { if (!value.TryGetProperty(name, out var item) || item.ValueKind != JsonValueKind.String || item.GetString() is not { } text || string.IsNullOrWhiteSpace(text) || text.Length > maximum || text.Any(char.IsControl)) throw Error("FORENSIC_TEXT", $"{name} is invalid."); return text; }
    static EnrollmentConflictException Error(string code, string detail) => new(code, detail);
    [GeneratedRegex("^[A-Za-z0-9_.-]{1,64}$", RegexOptions.CultureInvariant)] private static partial Regex IdentifierRegex();
    [GeneratedRegex("^[A-Za-z]:[\\\\/][^*?\"<>|\\r\\n]+$", RegexOptions.CultureInvariant)] private static partial Regex LocalWindowsPathRegex();
}
