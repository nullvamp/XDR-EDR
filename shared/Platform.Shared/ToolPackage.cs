namespace OpenSecurityPlatform.Foundation;

public sealed record ApprovedToolPackage(Guid PackageId, string TenantId, string Name, string Version, string FileName,
    long Size, string Sha256, string? ExpectedSignerThumbprint, bool AllowUnsigned, string ObjectId,
    string State, string CreatedBy, DateTimeOffset CreatedAt, DateTimeOffset? RevokedAt = null);

public static class ToolPackageSafety
{
    public const long MaximumPackageBytes = 2L * 1024 * 1024 * 1024;
    public static readonly string[] Extensions = [".exe", ".dll", ".ps1", ".zip"];
    public static void Validate(string name, string version, string fileName, long size, string sha256,
        string? signer, bool allowUnsigned)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 128 || name.Any(char.IsControl) ||
            string.IsNullOrWhiteSpace(version) || version.Length > 64 || version.Any(char.IsControl) ||
            string.IsNullOrWhiteSpace(fileName) || fileName != Path.GetFileName(fileName) || fileName.Length > 255 ||
            !Extensions.Contains(Path.GetExtension(fileName), StringComparer.OrdinalIgnoreCase) ||
            size is < 1 or > MaximumPackageBytes || sha256.Length != 64 || !sha256.All(Uri.IsHexDigit) ||
            signer is not null && (signer.Length is < 40 or > 128 || !signer.All(Uri.IsHexDigit)) ||
            allowUnsigned && signer is not null)
            throw new EnrollmentConflictException("TOOL_PACKAGE_INVALID", "Tool package metadata is invalid or outside policy.");
    }
}
