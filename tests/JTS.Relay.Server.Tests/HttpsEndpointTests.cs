using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Hosting;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class HttpsEndpointTests
{
    [Fact]
    public async Task ConfiguredPemHttpsStartsAndRequiresTheExactTestCertificatePin()
    {
        var directory = Directory.CreateTempSubdirectory("jts-relay-https-test-").FullName;
        try
        {
            using var identity = new TestIdentity();
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            names.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            var certificatePath = Path.Combine(directory, "tls.crt");
            var keyPath = Path.Combine(directory, "tls.key");
            await File.WriteAllTextAsync(certificatePath, certificate.ExportCertificatePem());
            await File.WriteAllTextAsync(keyPath, key.ExportPkcs8PrivateKeyPem());
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var options = new RelayOptions
            {
                DatabasePath = Path.Combine(directory, "relay.sqlite"),
                AllowLoopbackHttp = false, Devices = [identity.Options("controller")]
            };
            var configurationPath = Path.Combine(directory, "relay.json");
            await File.WriteAllTextAsync(configurationPath, JsonSerializer.Serialize(new
            {
                Relay = options,
                Kestrel = new { Endpoints = new { Https = new
                {
                    Url = "https://127.0.0.1:0",
                    Certificate = new { Path = certificatePath, KeyPath = keyPath }
                } } }
            }));
            await using var app = RelayApplication.Build(["--config", configurationPath]);
            await app.StartAsync();
            try
            {
                var origin = new Uri(app.Urls.Single());
                Assert.Equal("https", origin.Scheme);
                using var trusted = PinnedClient(origin, certificate.GetCertHash(HashAlgorithmName.SHA256));
                using var health = await trusted.GetAsync("/healthz");
                health.EnsureSuccessStatusCode();
                using var info = await trusted.GetAsync("/v1/info");
                info.EnsureSuccessStatusCode();
                using var json = JsonDocument.Parse(await info.Content.ReadAsStringAsync());
                Assert.Equal(1, json.RootElement.GetProperty("protocolVersion").GetInt32());
                using var wrongPin = PinnedClient(origin, RandomNumberGenerator.GetBytes(32));
                await Assert.ThrowsAsync<HttpRequestException>(() => wrongPin.GetAsync("/healthz"));
            }
            finally { await app.StopAsync(); }
        }
        finally { Directory.Delete(directory, true); }
    }

    private static HttpClient PinnedClient(Uri origin, byte[] expectedCertificateSha256)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                // Trust only this fresh test leaf. Preserve name, presence and validity checks;
                // do not disable TLS validation or modify the machine's trusted certificates.
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    certificate is X509Certificate2 peer &&
                    (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) == SslPolicyErrors.None &&
                    DateTime.UtcNow >= peer.NotBefore.ToUniversalTime() && DateTime.UtcNow <= peer.NotAfter.ToUniversalTime() &&
                    CryptographicOperations.FixedTimeEquals(expectedCertificateSha256,
                        peer.GetCertHash(HashAlgorithmName.SHA256))
            }
        };
        return new HttpClient(handler) { BaseAddress = origin, Timeout = TimeSpan.FromSeconds(10) };
    }
}
