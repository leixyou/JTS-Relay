using System.Security.Cryptography;
using System.Text.Json;
using JTS.Relay.Server.Enrollment;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;
using JTS.Relay.Server.Storage;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class EnrollmentTests
{
    [Fact]
    public void ClaimIsImmutableAndDoesNotAdmitUntilExactControllerConfirmation()
    {
        using var f = new EnrollmentFixture(); var invitation = f.Create();
        var body = EnrollmentFixture.Claim(invitation.View, invitation.Token, f.Companion);
        var claim = f.Public(body, true);
        Assert.Equal("claimed", claim.State); Assert.False(f.Registry.TryGet(f.Companion.Id, out _));
        Assert.Equal(claim, f.Public(body, true));
        Assert.Throws<RelayFailure>(() => f.Public(EnrollmentFixture.Claim(invitation.View, invitation.Token, f.Companion), true));
        Assert.Throws<RelayFailure>(() => f.Execute(new { action = "confirm", invitationId = claim.InvitationId, claimHash = new string('0', 64) }));
        Assert.Throws<RelayFailure>(() => f.Execute(new { action = "confirm", invitationId = claim.InvitationId, claimHash = claim.Claim!.ClaimHash }, f.OtherController));
        Assert.False(f.Registry.TryGet(f.Companion.Id, out _));
        var confirmed = (EnrollmentView)f.Execute(f.ConfirmationRequest(claim));
        Assert.Equal("bound", confirmed.State); Assert.True(f.Registry.AuthorizesPair(f.Controller.Id, f.Companion.Id));
        Assert.Equal(confirmed, f.Public(body, true));
        var input = EnrollmentFixture.Json(body);
        var transcript = string.Join('\n', "JTS-PAIR-1", claim.InvitationId, f.Controller.Id,
            Convert.ToHexStringLower(SHA256.HashData(Convert.FromBase64String(claim.OfferBase64))),
            Convert.ToHexStringLower(SHA256.HashData(Convert.FromBase64String(input.GetProperty("responseBase64").GetString()!))), f.Companion.Id);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(transcript))), claim.Claim!.ClaimHash);
    }
    [Fact]
    public async Task CompetingClaimsAndRepeatedConfirmAreAtomic()
    {
        using var f = new EnrollmentFixture(); using var otherPeer = new TestIdentity(); var invitation = f.Create();
        var claims = new[] { EnrollmentFixture.Claim(invitation.View, invitation.Token, f.Companion), EnrollmentFixture.Claim(invitation.View, invitation.Token, otherPeer) };
        var results = await Task.WhenAll(claims.Select(body => Task.Run(() =>
        {
            try { return f.Public(body, true); } catch (RelayFailure failure) { Assert.Equal(409, failure.Status); return null; }
        })));
        var accepted = Assert.Single(results, value => value is not null)!;
        var confirmationRequest = f.ConfirmationRequest(accepted);
        var confirmed = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() => (EnrollmentView)f.Execute(
            confirmationRequest))));
        Assert.All(confirmed, value => Assert.Equal("bound", value.State));
        Assert.Single(f.Registry.Get(f.Controller.Id).Peers);
        Assert.Equal(accepted.Claim, f.Public(new { invitationId = invitation.View.InvitationId, claimTokenBase64 = invitation.Token }).Claim);
    }
    [Fact]
    public void LostConfirmResponseAndRestartRecoverBoundReceiptWithoutRdpOrRebinding()
    {
        using var f = new EnrollmentFixture(); var invitation = f.Create(); var bound = f.Bind(invitation);
        // No RDP session, endpoint connection or connectivity check has occurred.
        f.Clock.Now = f.Clock.Now.AddDays(2); f.Reopen();
        var receipt = new { invitationId = bound.InvitationId, claimTokenBase64 = invitation.Token };
        Assert.Equal(bound, f.Public(receipt));
        Assert.Equal(bound, f.Execute(f.ConfirmationRequest(bound)));
        Assert.Equal(bound, f.Execute(invitation.Request));
        Assert.Throws<RelayFailure>(() => f.Execute(new { action = "cancel", invitationId = bound.InvitationId }));
        f.Execute(new { action = "revoke", peerDeviceId = f.Companion.Id });
        Assert.Equal("cancelled", f.Public(receipt).State);
        f.Reopen(); Assert.False(f.Registry.AuthorizesPair(f.Controller.Id, f.Companion.Id));
        Assert.Equal("cancelled", f.Public(receipt).State);
        Assert.Throws<RelayFailure>(() => f.Execute(new { action = "confirm", invitationId = bound.InvitationId, claimHash = bound.Claim!.ClaimHash }));
    }
    [Fact]
    public void ExpiryCancelIdentityProofAndControllerScopeFailClosed()
    {
        using var f = new EnrollmentFixture(); var invitation = f.Create();
        Assert.Throws<RelayFailure>(() => f.Public(EnrollmentFixture.Claim(invitation.View, invitation.Token, f.Companion, signer: f.OtherController), true));
        Assert.Throws<RelayFailure>(() => f.Public(new { invitationId = invitation.View.InvitationId, claimTokenBase64 = Convert.ToBase64String(new byte[32]) }));
        foreach (var action in new[] { "status", "cancel" })
            Assert.Throws<RelayFailure>(() => f.Execute(new { action, invitationId = invitation.View.InvitationId }, f.OtherController));
        var claimed = f.Public(EnrollmentFixture.Claim(invitation.View, invitation.Token, f.Companion), true);
        f.Clock.Now = f.Clock.Now.AddMinutes(10);
        Assert.Equal("expired", ((EnrollmentView)f.Execute(new { action = "status", invitationId = claimed.InvitationId })).State);
        Assert.Throws<RelayFailure>(() => f.Execute(new { action = "confirm", invitationId = claimed.InvitationId, claimHash = claimed.Claim!.ClaimHash }));
        var pending = f.Create();
        Assert.Equal("cancelled", ((EnrollmentView)f.Execute(new { action = "cancel", invitationId = pending.View.InvitationId })).State);
        Assert.Throws<RelayFailure>(() => f.Public(EnrollmentFixture.Claim(pending.View, pending.Token, f.Companion), true));
    }
    [Fact]
    public void RevokeStopsOnlyOwnTicketsAndActiveSessionsAndDoesNotReseedLegacyEdges()
    {
        using var f = new EnrollmentFixture(); f.Bind(f.Create()); f.Bind(f.Create(f.OtherController), f.OtherController);
        var active = f.Sessions.Create(f.Registry.Get(f.Controller.Id), new(f.Companion.Id, "rdp"));
        var claimed = f.Sessions.Claim(active.Ticket).Session;
        var pending = f.Sessions.Create(f.Registry.Get(f.Controller.Id), new(f.Companion.Id, "file"));
        var other = f.Sessions.Create(f.Registry.Get(f.OtherController.Id), new(f.Companion.Id, "control"));
        var staleController = f.Registry.Get(f.Controller.Id);
        f.Execute(new { action = "revoke", peerDeviceId = f.Companion.Id });
        Assert.True(claimed.IsComplete);
        Assert.Throws<RelayFailure>(() => f.Sessions.Claim(pending.Ticket));
        Assert.Throws<RelayFailure>(() => f.Sessions.Create(staleController, new(f.Companion.Id, "control")));
        Assert.Equal(other.SessionId, f.Sessions.Claim(other.Ticket).Session.Id);
        // Even a stale config containing that pair cannot restore it on restart.
        f.Options.Devices = [f.Controller.Options("controller", f.Companion.Id), f.Companion.Options("companion", f.Controller.Id)];
        f.Reopen();
        Assert.False(f.Registry.AuthorizesPair(f.Controller.Id, f.Companion.Id));
        Assert.True(f.Registry.AuthorizesPair(f.OtherController.Id, f.Companion.Id));
    }
    [Fact]
    public void OperatorAdmissionAppearsInAlreadyRunningRegistryWithoutRestart()
    {
        using var f = new EnrollmentFixture(); using var extra = new TestIdentity();
        Assert.False(f.Registry.TryGet(extra.Id, out _));
        using (var operatorStore = new AdmissionStore(f.Options, f.Clock)) operatorStore.AddController(extra.Options("controller").PublicKeySpkiBase64);
        Assert.Equal("controller", f.Registry.Get(extra.Id).Role);
        Assert.Equal("pending", f.Create(extra).View.State);
    }
    [Fact]
    public void InvitationCapacityExpiryRangeAndPublicRateAreBounded()
    {
        using var f = new EnrollmentFixture(options => { options.MaxEnrollmentInvitations = 1; options.MaxEnrollmentInvitationsPerController = 1; options.MaxStoredEnrollments = 2; });
        f.Create(); Assert.Equal(429, Assert.Throws<RelayFailure>(() => f.Create()).Status);
        f.Clock.Now = f.Clock.Now.AddMinutes(11); f.Create();
        f.Clock.Now = f.Clock.Now.AddMinutes(11); Assert.Equal(429, Assert.Throws<RelayFailure>(() => f.Create()).Status);
        var options = f.Options; options.MaxRequestsPerMinute = 2; options.MaxPublicEnrollmentRequestsPerMinute = 3;
        var limiter = new EnrollmentRateLimiter(options, f.Clock);
        limiter.Check("one"); limiter.Check("one");
        for (var i = 0; i < 500; i++) Assert.Equal(429, Assert.Throws<RelayFailure>(() => limiter.Check("one")).Status);
        limiter.Check("two");
        Assert.Equal(429, Assert.Throws<RelayFailure>(() => limiter.Check("three")).Status);
        f.Clock.Now = f.Clock.Now.AddMinutes(1); limiter.Check("one");
    }
    [Theory]
    [InlineData("{\"action\":\"status\",\"action\":\"status\",\"invitationId\":\"e3eea5a8-de29-4729-96ba-1f074c73db18\"}")]
    [InlineData("{\"action\":\"status\",\"invitationId\":\"E3EEA5A8-DE29-4729-96BA-1F074C73DB18\"}")]
    [InlineData("{\"action\":\"status\",\"invitationId\":null}")]
    [InlineData("{\"action\":\"revoke\",\"peerDeviceId\":\"x\",\"controllerDeviceId\":\"another\"}")]
    public void AmbiguousOrNoncanonicalFieldsAreRejected(string input)
    {
        using var json = JsonDocument.Parse(input); Assert.Throws<RelayFailure>(() => EnrollmentProtocol.Parse(json.RootElement));
    }
    [Fact]
    public void MaximumReplyRemainsBoundedAndOversizedCipherOrTokenIsRejected()
    {
        using var f = new EnrollmentFixture(); var invitation = f.Create(offer: RandomNumberGenerator.GetBytes(8192));
        var claim = f.Public(EnrollmentFixture.Claim(invitation.View, invitation.Token, f.Companion, new byte[8192]), true);
        Assert.True(JsonSerializer.SerializeToUtf8Bytes(claim).Length < 24576);
        var oversized = EnrollmentFixture.Claim(invitation.View, invitation.Token, f.Companion, new byte[8193]);
        Assert.Throws<RelayFailure>(() => f.Public(oversized, true));
        Assert.Throws<RelayFailure>(() => f.Public(new { invitationId = invitation.View.InvitationId, claimTokenBase64 = invitation.Token + "\n" }));
        Assert.DoesNotContain("claimToken", JsonSerializer.Serialize(claim), StringComparison.OrdinalIgnoreCase);
    }
    [Fact]
    public void IndependentCrossLanguageVectorVerifiesWithoutDoubleHashing()
    {
        using var json = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "enrollment.json")));
        var value = json.RootElement;
        string Text(string name) => value.GetProperty(name).GetString()!;
        var controller = EnrollmentProtocol.Digest(Convert.FromBase64String(Text("controllerSPKIBase64")));
        var view = new EnrollmentView(Text("invitationId"), controller, "pending", 0, Text("offerBase64"), null);
        var verified = EnrollmentProtocol.VerifyClaim(view, new(Text("peerSPKIBase64"), Text("responseBase64"), Text("signatureBase64"), ""));
        Assert.Equal(Text("claimHash"), verified.Claim.ClaimHash);
        Assert.Equal(Convert.FromBase64String(Text("transcriptBase64")), System.Text.Encoding.UTF8.GetBytes(
            EnrollmentProtocol.Transcript(view.InvitationId, controller, view.OfferBase64, Text("responseBase64"), Text("peerSPKIBase64"))));
        Assert.Equal(Text("claimTokenHash"), EnrollmentProtocol.Digest(Convert.FromBase64String(Text("claimTokenBase64"))));
    }
}
