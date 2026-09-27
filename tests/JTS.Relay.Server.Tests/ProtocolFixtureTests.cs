using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class ProtocolFixtureTests
{
    [Fact]
    public void PublishedCrossLanguageVectorMatchesCanonicalBytesAndP1363()
    {
        using var json = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures/auth-presence.json")));
        string Field(string name) => json.RootElement.GetProperty(name).GetString()!;
        var spki = Convert.FromBase64String(Field("publicKeySpkiBase64"));
        Assert.Equal(Field("deviceId"), Convert.ToHexStringLower(SHA256.HashData(spki)));
        var payload = Convert.FromBase64String(Field("payloadBase64"));
        var canonical = string.Join('\n', "JTS-RELAY-AUTH-V1", Field("deviceId"), Field("operation"),
            Field("challengeId"), Field("nonceBase64"), Convert.ToHexStringLower(SHA256.HashData(payload)));
        Assert.Equal(Field("canonicalUtf8"), canonical);
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(spki, out _);
        Assert.True(key.VerifyData(Encoding.UTF8.GetBytes(canonical), Convert.FromBase64String(Field("signatureBase64")),
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
}
