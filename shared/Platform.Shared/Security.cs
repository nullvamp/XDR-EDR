using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OpenSecurityPlatform.Foundation;

public sealed record PrincipalContext(
    string Subject,
    string TenantId,
    IReadOnlySet<string> Permissions,
    string Type
);

public static class PasswordHasher
{
    public static string Hash(string password, int iterations = 210_000)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA512,
            32
        );
        return $"pbkdf2-sha512${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string encoded)
    {
        var p = encoded.Split('$');
        if (p.Length != 4 || !int.TryParse(p[1], out var i))
            return false;
        try
        {
            var salt = Convert.FromBase64String(p[2]);
            var expected = Convert.FromBase64String(p[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                i,
                HashAlgorithmName.SHA512,
                expected.Length
            );
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

public sealed class JwtService
{
    private readonly byte[] _key;
    private readonly PlatformOptions _options;

    public JwtService(PlatformOptions options)
    {
        _options = options;
        if (options.JwtSigningKey.Length < 32)
            throw new InvalidOperationException(
                "PLATFORM_JWT_SIGNING_KEY must be at least 32 characters."
            );
        _key = Encoding.UTF8.GetBytes(options.JwtSigningKey);
    }

    public PlatformOptions Options => _options;

    public string Issue(
        string subject,
        string tenant,
        IEnumerable<string> permissions,
        TimeSpan lifetime,
        string type = "user"
    )
    {
        var header = Encode(
            JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", typ = "JWT" })
        );
        var now = DateTimeOffset.UtcNow;
        var payload = Encode(
            JsonSerializer.SerializeToUtf8Bytes(
                new
                {
                    iss = _options.JwtIssuer,
                    aud = _options.JwtAudience,
                    sub = subject,
                    tid = tenant,
                    per = permissions.ToArray(),
                    pty = type,
                    iat = now.ToUnixTimeSeconds(),
                    exp = now.Add(lifetime).ToUnixTimeSeconds(),
                    jti = Guid.NewGuid().ToString("N"),
                }
            )
        );
        return $"{header}.{payload}.{Sign(header + "." + payload)}";
    }

    public PrincipalContext? Validate(string token)
    {
        var parts = token.Split('.');
        if (
            parts.Length != 3
            || !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(Sign(parts[0] + "." + parts[1])),
                Encoding.ASCII.GetBytes(parts[2])
            )
        )
            return null;
        try
        {
            using var doc = JsonDocument.Parse(Decode(parts[1]));
            var r = doc.RootElement;
            if (
                r.GetProperty("iss").GetString() != _options.JwtIssuer
                || r.GetProperty("aud").GetString() != _options.JwtAudience
                || r.GetProperty("exp").GetInt64() <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            )
                return null;
            return new(
                r.GetProperty("sub").GetString()!,
                r.GetProperty("tid").GetString()!,
                r.GetProperty("per")
                    .EnumerateArray()
                    .Select(x => x.GetString()!)
                    .ToHashSet(StringComparer.Ordinal),
                r.GetProperty("pty").GetString()!
            );
        }
        catch (Exception e) when (e is JsonException or FormatException or KeyNotFoundException)
        {
            return null;
        }
    }

    private string Sign(string value)
    {
        using var h = new HMACSHA256(_key);
        return Encode(h.ComputeHash(Encoding.ASCII.GetBytes(value)));
    }

    private static string Encode(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Decode(string s) =>
        Convert.FromBase64String(
            s.Replace('-', '+').Replace('_', '/').PadRight(s.Length + (4 - s.Length % 4) % 4, '=')
        );
}

public sealed class ApiKeyStore
{
    private readonly Dictionary<string, (string Hash, PrincipalContext Principal)> _keys = new(
        StringComparer.Ordinal
    );
    private readonly object _gate = new();

    public string Issue(PrincipalContext principal)
    {
        var id = Guid.NewGuid().ToString("N");
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        lock (_gate)
            _keys[id] = (PasswordHasher.Hash(secret, 100_000), principal);
        return $"osp_{id}_{secret}";
    }

    public PrincipalContext? Validate(string value)
    {
        var p = value.Split('_', 3);
        if (p.Length != 3)
            return null;
        lock (_gate)
            return _keys.TryGetValue(p[1], out var v) && PasswordHasher.Verify(p[2], v.Hash)
                ? v.Principal
                : null;
    }
}

public sealed record SignedPluginManifest(
    string PackageId,
    string Version,
    string Publisher,
    string PayloadSha256,
    string Signature
);

public static class PluginSignatureVerifier
{
    public static bool Verify(SignedPluginManifest manifest, string trustedPublisherPublicKeyPem)
    {
        if (manifest.PayloadSha256.Length != 64 || manifest.Signature.Length == 0)
            return false;
        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(trustedPublisherPublicKeyPem);
            var signed = Encoding.UTF8.GetBytes(
                $"{manifest.PackageId}\n{manifest.Version}\n{manifest.Publisher}\n{manifest.PayloadSha256.ToLowerInvariant()}"
            );
            return key.VerifyData(
                signed,
                Convert.FromBase64String(manifest.Signature),
                HashAlgorithmName.SHA256
            );
        }
        catch (Exception e)
            when (e is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
    }
}
