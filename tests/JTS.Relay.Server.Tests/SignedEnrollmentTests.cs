using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using JTS.Relay.Server.Enrollment;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class SignedEnrollmentTests
{
    [Fact]
    public void ConfirmationMustMatchSignerClaimAudienceAndExpiryAndPersistsExactly()
    {
        using var f = new EnrollmentFixture(); var invite = f.Create();
        var claimed = f.Public(EnrollmentFixture.Claim(invite.View, invite.Token, f.Companion), true);
        var valid = f.Controller.Confirm(claimed, f.Clock.Now.ToUnixTimeSeconds());
        object Payload(EnrollmentConfirmation confirmation) => new { action = "confirm", invitationId = claimed.InvitationId,
            claimHash = claimed.Claim!.ClaimHash, confirmation };
        foreach (var invalid in new[] {
            valid with { SignatureBase64 = f.OtherController.SignText(valid.Transcript()) },
            valid with { RelayOrigin = "https://another.example" },
            valid with { ClaimHash = new string('a',64) }, valid with { PeerDeviceId = f.OtherController.Id },
            valid with { ExpiresAtUnixSeconds = valid.ExpiresAtUnixSeconds + 1 },
            valid with { ConfirmedAtUnixSeconds = valid.ExpiresAtUnixSeconds } })
            Assert.Throws<RelayFailure>(() => f.Execute(Payload(invalid)));
        Assert.False(f.Registry.TryGet(f.Companion.Id, out _));
        var bound = (EnrollmentView)f.Execute(Payload(valid));
        Assert.Equal(valid, bound.Confirmation);
        f.Clock.Now = f.Clock.Now.AddDays(3); f.Reopen();
        Assert.Equal(bound, f.Execute(Payload(valid)));
        Assert.Equal(valid, f.Public(new { invitationId = invite.View.InvitationId, claimTokenBase64 = invite.Token }).Confirmation);
        var alteredSignature = valid with { SignatureBase64 = f.Controller.SignText(valid.Transcript()) };
        if (alteredSignature != valid) Assert.Equal(409, Assert.Throws<RelayFailure>(() => f.Execute(Payload(alteredSignature))).Status);
    }

    [Fact]
    public void IndependentSecurityVectorsMatchAllTranscriptsAndSignatures()
    {
        using var auth = Fixture("auth-v2.json"); var a = auth.RootElement;
        string A(string name) => a.GetProperty(name).GetString()!;
        var transcript = string.Join('\n', "JTS-RELAY-AUTH-V2", A("relayOrigin"), A("deviceId"), A("operation"),
            A("challengeId"), A("nonceBase64"), EnrollmentProtocol.Digest(Convert.FromBase64String(A("payloadBase64"))));
        Assert.Equal(Convert.FromBase64String(A("transcriptBase64")), Encoding.UTF8.GetBytes(transcript));
        Verify(A("controllerSPKIBase64"), transcript, A("signatureBase64"));
        using var confirmation = Fixture("confirmation-v2.json"); var c = confirmation.RootElement;
        var signed = EnrollmentConfirmation.Parse(c.GetProperty("confirmation"));
        Assert.Equal(Convert.FromBase64String(c.GetProperty("transcriptBase64").GetString()!), Encoding.UTF8.GetBytes(signed.Transcript()));
        Verify(c.GetProperty("controllerSPKIBase64").GetString()!, signed.Transcript(), signed.SignatureBase64);
        using var revocation = Fixture("revocation-v2.json"); var r = revocation.RootElement;
        var request = RevocationRequest.Parse(r.GetProperty("revocation")); var receipt = RevocationReceipt.Parse(r.GetProperty("receipt"));
        Assert.Equal(r.GetProperty("requestHash").GetString(), request.RequestHash);
        Assert.Equal(Convert.FromBase64String(r.GetProperty("requestTranscriptBase64").GetString()!), Encoding.UTF8.GetBytes(request.Transcript()));
        Assert.Equal(Convert.FromBase64String(r.GetProperty("receiptTranscriptBase64").GetString()!), Encoding.UTF8.GetBytes(receipt.Transcript()));
        Verify(r.GetProperty("controllerSPKIBase64").GetString()!, request.Transcript(), request.SignatureBase64);
        Verify(r.GetProperty("peerSPKIBase64").GetString()!, receipt.Transcript(), receipt.SignatureBase64);
    }
    private static JsonDocument Fixture(string name) => JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", name)));
    private static void Verify(string spki, string text, string signature)
    {
        using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(spki), out _);
        Assert.True(key.VerifyData(Encoding.UTF8.GetBytes(text), Convert.FromBase64String(signature), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
}
