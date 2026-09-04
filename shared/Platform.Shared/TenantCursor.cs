using System.Security.Cryptography;
using System.Text;

namespace OpenSecurityPlatform.Foundation;

public static class TenantCursor
{
    public static string Protect(string tenantId, string value)
    {
        var payload = Base64Url(Encoding.UTF8.GetBytes($"{tenantId}|{value}"));
        return $"v1.{payload}.{Sign(payload)}";
    }

    public static string Unprotect(string tenantId, string cursor)
    {
        try
        {
            var parts = cursor.Split('.', 3);
            if (parts.Length != 3 || parts[0] != "v1")
                throw new FormatException();
            var expected = Sign(parts[1]);
            if (
                !CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expected),
                    Encoding.ASCII.GetBytes(parts[2])
                )
            )
                throw new FormatException();
            var decoded = Encoding.UTF8.GetString(FromBase64Url(parts[1]));
            var prefix = tenantId + "|";
            if (!decoded.StartsWith(prefix, StringComparison.Ordinal))
                throw new FormatException();
            return decoded[prefix.Length..];
        }
        catch (Exception e) when (e is FormatException or CryptographicException)
        {
            throw new EnrollmentConflictException(
                "CURSOR_INVALID",
                "Cursor is invalid for this tenant."
            );
        }
    }

    private static string Sign(string payload)
    {
        var key = Environment.GetEnvironmentVariable("PLATFORM_JWT_SIGNING_KEY");
        if (string.IsNullOrWhiteSpace(key))
            key = "local-development-cursor-key";
        return Base64Url(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), Encoding.ASCII.GetBytes(payload))
        );
    }

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }
}
