using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<ArtifactTransferState>))]
public enum ArtifactTransferState { Receiving, Verifying, Completed, Failed, Cancelled, Expired }

public sealed record ArtifactTransferStart(
    Guid TransferId,
    string OwnerType,
    Guid OwnerId,
    Guid ArtifactId,
    string Name,
    string MediaType,
    long Size,
    string Sha256,
    int ChunkSize,
    string? NativeIdentity = null);

public sealed record ArtifactTransferStatus(
    string SchemaVersion,
    Guid TransferId,
    string OwnerType,
    Guid OwnerId,
    Guid ArtifactId,
    ArtifactTransferState State,
    long Size,
    long ReceivedBytes,
    int ChunkSize,
    int ReceivedChunks,
    int TotalChunks,
    string Sha256,
    string? ObjectId,
    string? FailureReason,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt)
{
    public int ProgressPercent => Size == 0 ? 100 : (int)Math.Min(100, ReceivedBytes * 100 / Size);
}

public sealed record ArtifactChunkAcknowledgement(Guid TransferId, int ChunkIndex, long ReceivedBytes, int NextChunkIndex, string ChunkSha256);
public sealed record ArtifactTransferCompletion(Guid TransferId, string Sha256, long Size);

public static class ArtifactTransferSafety
{
    public const string SchemaVersion = "artifact-transfer.v1";
    public const int DefaultChunkSize = 4 * 1024 * 1024;
    public const int MinimumChunkSize = 256 * 1024;
    public const int MaximumChunkSize = 16 * 1024 * 1024;
    public const long MaximumArtifactBytes = 4L * 1024 * 1024 * 1024;
    public const int MaximumConcurrentTransfersPerEndpoint = 2;

    public static void Validate(ArtifactTransferStart value)
    {
        if (value.TransferId == Guid.Empty || value.OwnerId == Guid.Empty || value.ArtifactId == Guid.Empty ||
            value.OwnerType is not ("live-response" or "response-action") || value.Size is < 0 or > MaximumArtifactBytes ||
            value.ChunkSize is < MinimumChunkSize or > MaximumChunkSize ||
            string.IsNullOrWhiteSpace(value.Name) || value.Name.Length > 255 || value.Name.Any(char.IsControl) ||
            string.IsNullOrWhiteSpace(value.MediaType) || value.MediaType.Length > 128 || value.MediaType.Any(char.IsControl) ||
            value.Sha256.Length != 64 || !value.Sha256.All(Uri.IsHexDigit) ||
            value.NativeIdentity?.Length > 256)
            throw new EnrollmentConflictException("ARTIFACT_TRANSFER_INVALID", "Artifact transfer metadata is invalid or outside hard bounds.");
    }
}
