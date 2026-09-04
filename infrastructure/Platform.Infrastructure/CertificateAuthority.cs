using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class CertificateAuthority : IDisposable
{
    public const string IdentityOid = "1.3.6.1.4.1.55555.1.1";
    private readonly X509Certificate2 _authority;

    public CertificateAuthority(string path, string password)
    {
        if (!File.Exists(path))
            throw new InvalidOperationException("Certificate authority file is unavailable.");
        _authority = new X509Certificate2(path, password, X509KeyStorageFlags.EphemeralKeySet);
        if (
            !_authority.HasPrivateKey
            || !_authority
                .Extensions.OfType<X509BasicConstraintsExtension>()
                .Any(x => x.CertificateAuthority)
        )
            throw new InvalidOperationException("Configured certificate authority is invalid.");
    }

    public IssuedAgentCertificate Issue(string csrPem, string tenantId, string subject)
    {
        CertificateRequest request;
        try
        {
            request = CertificateRequest.LoadSigningRequestPem(
                csrPem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
                null
            );
        }
        catch (CryptographicException)
        {
            throw new EnrollmentConflictException(
                "CSR_INVALID",
                "Certificate signing request is invalid."
            );
        }
        if (
            !request
                .CertificateExtensions.Cast<X509Extension>()
                .Any(x => x.Oid?.Value == "2.5.29.19")
        )
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, true)
            );
        if (
            !request
                .CertificateExtensions.Cast<X509Extension>()
                .Any(x => x.Oid?.Value == "2.5.29.15")
        )
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true)
            );
        if (
            !request
                .CertificateExtensions.Cast<X509Extension>()
                .Any(x => x.Oid?.Value == "2.5.29.37")
        )
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new("1.3.6.1.5.5.7.3.2") },
                    true
                )
            );
        request.CertificateExtensions.Add(
            new X509Extension(
                new Oid(IdentityOid),
                JsonSerializer.SerializeToUtf8Bytes(new { tenantId, subject }),
                false
            )
        );
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-2);
        var notAfter = DateTimeOffset.UtcNow.AddHours(24);
        using var issuerKey =
            _authority.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("The certificate authority must use RSA.");
        var generator = X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1);
        using var certificate = request.Create(
            _authority.SubjectName,
            generator,
            notBefore,
            notAfter,
            RandomNumberGenerator.GetBytes(20)
        );
        return new(
            certificate.ExportCertificatePem(),
            _authority.ExportCertificatePem(),
            certificate.Thumbprint,
            notAfter
        );
    }

    public PrincipalContext? Validate(X509Certificate2 certificate)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(_authority);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        if (
            DateTimeOffset.UtcNow < certificate.NotBefore
            || DateTimeOffset.UtcNow >= certificate.NotAfter
            || !chain.Build(certificate)
        )
            return null;
        var extension = certificate.Extensions[IdentityOid];
        if (extension is null)
            return null;
        try
        {
            using var document = JsonDocument.Parse(extension.RawData);
            var root = document.RootElement;
            return new(
                root.GetProperty("subject").GetString()!,
                root.GetProperty("tenantId").GetString()!,
                new HashSet<string>(["agent:heartbeat"]),
                "agent"
            );
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public SignedResponseActionEnvelope SignResponseAction(ResponseActionRecord action)
    {
        if (action.IssuedAt is not { } issued)
            throw new EnrollmentConflictException("RESPONSE_NOT_ISSUED", "Only queued response actions may be signed.");
        var unsigned = new SignedResponseActionEnvelope("response-action-envelope.v1", action.TenantId,
            action.EndpointId, action.AgentId, action.AgentInstallationId, action.ResponseActionId,
            action.ActionType, action.ActionVersion, action.Parameters, action.ParameterHash, issued,
            action.ExpiresAt, action.Nonce, action.PolicyVersion, action.TimeoutSeconds,
            "rsa-sha256-ca-v1", _authority.Thumbprint, "");
        using var key = _authority.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("The response signing authority must use RSA.");
        var signature = key.SignData(Encoding.UTF8.GetBytes(ResponseSafety.EnvelopePayload(unsigned)),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return unsigned with { Signature = Convert.ToBase64String(signature) };
    }

    public SignedLiveSessionEnvelope SignLiveSession(LiveSessionRecord session)
    {
        var unsigned = new SignedLiveSessionEnvelope("live-response-session-envelope.v1", session.TenantId,
            session.EndpointId, session.AgentId, session.AgentInstallationId, session.SessionId, session.AnalystId,
            session.Capabilities, session.CapabilityHash, session.PolicyVersion, DateTimeOffset.UtcNow,
            session.AbsoluteExpiresAt < session.ExpiresAt ? session.AbsoluteExpiresAt : session.ExpiresAt,
            session.Nonce, "rsa-sha256-ca-v1", _authority.Thumbprint, "");
        return unsigned with { Signature = Sign(LiveResponseSafety.SessionPayload(unsigned)) };
    }

    public SignedLiveCommandEnvelope SignLiveCommand(LiveCommandRecord command)
    {
        var unsigned = new SignedLiveCommandEnvelope("live-response-command-envelope.v1", command.TenantId,
            command.EndpointId, command.AgentId, command.AgentInstallationId, command.SessionId, command.CommandId,
            command.AnalystId, command.CommandType, command.ExactInput, command.InputHash, command.WorkingDirectory,
            command.TimeoutSeconds, DateTimeOffset.UtcNow, command.ExpiresAt, command.Nonce,
            command.UploadContentBase64, command.UploadSha256, command.Overwrite,
            "rsa-sha256-ca-v1", _authority.Thumbprint, "");
        return unsigned with { Signature = Sign(LiveResponseSafety.CommandPayload(unsigned)) };
    }

    public SignedProtectionPolicyEnvelope SignProtectionPolicy(AgentProtectionPolicy policy)
    {
        var unsigned = new SignedProtectionPolicyEnvelope(policy, DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(10), Guid.NewGuid().ToString("N"),
            "rsa-sha256-ca-v1", _authority.Thumbprint, "");
        return unsigned with { Signature = Sign(AgentProtectionSafety.PolicyPayload(unsigned)) };
    }

    public (string Algorithm, string KeyId, string Signature) SignMaintenance(MaintenanceAuthorization value) =>
        ("rsa-sha256-ca-v1", _authority.Thumbprint, Sign(AgentProtectionSafety.MaintenancePayload(value)));

    public (string CertificatePem, string Algorithm, string KeyId, string Signature) SignUpdateManifest(AgentUpdateManifest value) =>
        (_authority.ExportCertificatePem(), "rsa-sha256-ca-v1", _authority.Thumbprint,
            Sign(FleetUpdateSafety.PackagePayload(value)));

    public string AuthorityCertificatePem => _authority.ExportCertificatePem();

    string Sign(string payload)
    {
        using var key = _authority.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("The response signing authority must use RSA.");
        return Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));
    }

    public void Dispose() => _authority.Dispose();
}
