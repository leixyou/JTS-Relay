using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class SecurityTests
{
    [Fact]
    public void ProofIsSingleUseAndBoundToOperation()
    {
        using var identity = new TestIdentity();
        var options = new RelayOptions { PublicOrigin = TestIdentity.Origin, Devices = [identity.Options("controller")] };
        var auth = new ChallengeAuthenticator(options, new(options), new TestClock());
        var challenge = auth.Issue(new(identity.Id, "presence"));
        var proof = identity.Sign("presence", challenge, new { });
        var verified = auth.Authenticate("presence", proof);
        verified.Payload.Dispose();
        Assert.Equal(identity.Id, verified.Device.Id);
        Assert.Equal("authentication_failed", Assert.Throws<RelayFailure>(() => auth.Authenticate("presence", proof)).Code);
        var other = auth.Issue(new(identity.Id, "presence"));
        var invalid = identity.Sign("presence", other, new { });
        Assert.Throws<RelayFailure>(() => auth.Authenticate("devices", invalid));
        auth.Authenticate("presence", invalid).Payload.Dispose();
    }
    [Fact]
    public void InvalidSignatureCannotBurnAnotherClientsChallengeAndExpiredProofFails()
    {
        using var identity = new TestIdentity();
        var options = new RelayOptions { PublicOrigin = TestIdentity.Origin, Devices = [identity.Options("controller")] };
        var clock = new TestClock();
        var auth = new ChallengeAuthenticator(options, new(options), clock);
        var challenge = auth.Issue(new(identity.Id, "presence"));
        var proof = identity.Sign("presence", challenge, new { });
        Assert.Throws<RelayFailure>(() => auth.Authenticate("presence", proof with { SignatureBase64 = Convert.ToBase64String(new byte[64]) }));
        auth.Authenticate("presence", proof).Payload.Dispose();
        challenge = auth.Issue(new(identity.Id, "presence"));
        clock.Now = clock.Now.AddSeconds(61);
        Assert.Throws<RelayFailure>(() => auth.Authenticate("presence", identity.Sign("presence", challenge, new { })));
    }
    [Fact]
    public void RegistryRejectsWrongIdentityAndNonReciprocalPeers()
    {
        using var controller = new TestIdentity();
        using var companion = new TestIdentity();
        var bad = controller.Options("controller");
        bad.DeviceId = new('0', 64);
        Assert.Throws<InvalidOperationException>(() => new DeviceRegistry(new() { Devices = [bad] }));
        Assert.Throws<InvalidOperationException>(() => new DeviceRegistry(new()
        {
            Devices = [controller.Options("controller", companion.Id), companion.Options("companion")]
        }));
    }
    [Fact]
    public void AnonymousIssuanceCannotReserveVictimCapacityOrPoisonAuthenticatedRate()
    {
        using var identity = new TestIdentity();
        var options = new RelayOptions { PublicOrigin = TestIdentity.Origin, MaxChallenges = 1, MaxRequestsPerMinute = 2, Devices = [identity.Options("controller")] };
        var clock = new TestClock();
        var auth = new ChallengeAuthenticator(options, new(options), clock);
        var victim = auth.Issue(new(identity.Id, "presence"), "owner");
        for (var i = 0; i < 100; i++)
        {
            try { auth.Issue(new(identity.Id, "presence"), "attacker"); } catch (RelayFailure e) { Assert.Equal(429, e.Status); }
            try { auth.Authenticate("presence", identity.Sign("presence", victim, new { }) with { SignatureBase64 = Convert.ToBase64String(new byte[64]) }, "attacker"); }
            catch (RelayFailure e) { Assert.Contains(e.Status, new[] { 401, 429 }); }
        }
        auth.Authenticate("presence", identity.Sign("presence", victim, new { }), "owner").Payload.Dispose();
        var another = auth.Issue(new(identity.Id, "presence"), "owner");
        Assert.Equal("capacity_exhausted", Assert.Throws<RelayFailure>(() => auth.Authenticate("presence", identity.Sign("presence", another, new { }), "owner")).Code);
        clock.Now = clock.Now.AddSeconds(61);
        var fresh = auth.Issue(new(identity.Id, "presence"), "owner");
        auth.Authenticate("presence", identity.Sign("presence", fresh, new { }), "owner").Payload.Dispose();
    }

    [Fact]
    public async Task AudienceTamperingRestartAndConcurrentReplayFailClosed()
    {
        using var identity = new TestIdentity();
        var options = new RelayOptions { PublicOrigin = TestIdentity.Origin, Devices = [identity.Options("controller")] };
        var clock = new TestClock(); var registry = new DeviceRegistry(options);
        var auth = new ChallengeAuthenticator(options, registry, clock);
        var challenge = auth.Issue(new(identity.Id, "presence"));
        var wrongAudience = identity.Sign("presence", challenge, new { }, "https://attacker.example");
        Assert.Throws<RelayFailure>(() => auth.Authenticate("presence", wrongAudience));
        var proof = identity.Sign("presence", challenge, new { });
        var legacy = string.Join('\n', "JTS-RELAY-AUTH-V1", identity.Id, "presence", challenge.ChallengeId,
            challenge.NonceBase64, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Convert.FromBase64String(proof.PayloadBase64))));
        Assert.Throws<RelayFailure>(() => auth.Authenticate("presence", proof with { SignatureBase64 = identity.SignText(legacy) }));
        var restarted = new ChallengeAuthenticator(options, registry, clock);
        Assert.Throws<RelayFailure>(() => restarted.Authenticate("presence", proof));
        var successes = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => Task.Run(() =>
        {
            try { auth.Authenticate("presence", proof).Payload.Dispose(); return true; }
            catch (RelayFailure e) { Assert.Equal(401, e.Status); return false; }
        })));
        Assert.Single(successes, value => value);
    }
}
