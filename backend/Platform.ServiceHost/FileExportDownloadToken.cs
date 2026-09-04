using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

static class FileExportDownloadToken
{
    sealed record Payload(string TenantId, Guid ExportId, long ExpiresAt);

    public static string Create(string tenantId, Guid exportId, DateTimeOffset expiresAt, string key)
    {
        var payload = Base64Url(
            JsonSerializer.SerializeToUtf8Bytes(
                new Payload(tenantId, exportId, expiresAt.ToUnixTimeSeconds())
            )
        );
        var signature = Base64Url(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), Encoding.ASCII.GetBytes(payload))
        );
        return payload + "." + signature;
    }

    public static bool TryValidate(
        string token,
        string key,
        out string tenantId,
        out Guid exportId
    )
    {
        tenantId = string.Empty;
        exportId = Guid.Empty;
        var parts = token.Split('.');
        if (parts.Length != 2)
            return false;
        byte[] supplied;
        try
        {
            supplied = Decode(parts[1]);
        }
        catch (FormatException)
        {
            return false;
        }
        var expected = HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(key),
            Encoding.ASCII.GetBytes(parts[0])
        );
        if (!CryptographicOperations.FixedTimeEquals(expected, supplied))
            return false;
        try
        {
            var value = JsonSerializer.Deserialize<Payload>(Decode(parts[0]));
            if (value is null || value.ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                return false;
            tenantId = value.TenantId;
            exportId = value.ExportId;
            return Guid.TryParse(tenantId, out _);
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            return false;
        }
    }

    static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    static byte[] Decode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }
}
