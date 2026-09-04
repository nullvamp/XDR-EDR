using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

if (args.Length != 2 || args[1].Length < 16)
    throw new ArgumentException(
        "Usage: Platform.Pki <output-directory> <pfx-password-at-least-16-characters>"
    );
Directory.CreateDirectory(args[0]);
using var caKey = RSA.Create(4096);
var caRequest = new CertificateRequest(
    "CN=Open Security Platform Local Root CA",
    caKey,
    HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1
);
caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
caRequest.CertificateExtensions.Add(
    new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true)
);
caRequest.CertificateExtensions.Add(
    new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false)
);
using var ca = caRequest.CreateSelfSigned(
    DateTimeOffset.UtcNow.AddMinutes(-5),
    DateTimeOffset.UtcNow.AddYears(10)
);
using var serverKey = RSA.Create(3072);
var serverRequest = new CertificateRequest(
    "CN=gateway",
    serverKey,
    HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1
);
serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
serverRequest.CertificateExtensions.Add(
    new X509KeyUsageExtension(
        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
        true
    )
);
serverRequest.CertificateExtensions.Add(
    new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true)
);
var san = new SubjectAlternativeNameBuilder();
san.AddDnsName("gateway");
san.AddDnsName("localhost");
san.AddIpAddress(IPAddress.Loopback);
serverRequest.CertificateExtensions.Add(san.Build());
using var issued = serverRequest.Create(
    ca,
    DateTimeOffset.UtcNow.AddMinutes(-5),
    DateTimeOffset.UtcNow.AddYears(2),
    RandomNumberGenerator.GetBytes(20)
);
using var server = issued.CopyWithPrivateKey(serverKey);
File.WriteAllBytes(Path.Combine(args[0], "ca.pfx"), ca.Export(X509ContentType.Pkcs12, args[1]));
File.WriteAllText(Path.Combine(args[0], "ca.crt"), ca.ExportCertificatePem());
File.WriteAllBytes(
    Path.Combine(args[0], "gateway.pfx"),
    server.Export(X509ContentType.Pkcs12, args[1])
);
Console.WriteLine("Generated CA and gateway certificates.");
