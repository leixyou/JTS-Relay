using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Protocol;

namespace JTS.Relay.Server.Tests;

internal sealed class TestIdentity : IDisposable
{
    public const string Origin = "https://relay.example.test:9443";
    public ECDsa Key { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public string Id => Convert.ToHexStringLower(SHA256.HashData(Key.ExportSubjectPublicKeyInfo()));
    public DeviceOptions Options(string role, params string[] peers) => new()
    {
        DeviceId = Id, PublicKeySpkiBase64 = Convert.ToBase64String(Key.ExportSubjectPublicKeyInfo()),
        Role = role, Peers = [.. peers]
    };
    public AuthEnvelope Sign(string operation, ChallengeResponse challenge, object payload, string origin = Origin)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var canonical = string.Join('\n', "JTS-RELAY-AUTH-V2", origin, Id, operation, challenge.ChallengeId,
            challenge.NonceBase64, Convert.ToHexStringLower(SHA256.HashData(bytes)));
        var signature = Key.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new(Id, challenge.ChallengeId, Convert.ToBase64String(bytes), Convert.ToBase64String(signature));
    }
    public void Dispose() => Key.Dispose();

    public Enrollment.EnrollmentConfirmation Confirm(Enrollment.EnrollmentView view, long now, string origin = Origin)
    {
        var value = new Enrollment.EnrollmentConfirmation(2, origin, view.InvitationId, Id,
            Enrollment.EnrollmentProtocol.Digest(Convert.FromBase64String(view.Claim!.PeerSPKIBase64)),
            view.Claim.ClaimHash, now, view.ExpiresAtUnixSeconds, "");
        return value with { SignatureBase64 = SignText(value.Transcript()) };
    }
    public string SignText(string text) => Convert.ToBase64String(Key.SignData(Encoding.UTF8.GetBytes(text),
        HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
}

internal sealed class TestClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 1, 31, 12, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => Now;
}
