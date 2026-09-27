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
        var options = new RelayOptions { Devices = [identity.Options("controller")] };
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
        Assert.Throws<RelayFailure>(() => auth.Authenticate("presence", invalid));
    }
    [Fact]
    public void InvalidSignatureBurnsChallengeAndExpiredProofFails()
    {
        using var identity = new TestIdentity();
        var options = new RelayOptions { Devices = [identity.Options("controller")] };
        var clock = new TestClock();
        var auth = new ChallengeAuthenticator(options, new(options), clock);
        var challenge = auth.Issue(new(identity.Id, "presence"));
        var proof = identity.Sign("presence", challenge, new { });
        Assert.Throws<RelayFailure>(() => auth.Authenticate("presence", proof with { SignatureBase64 = Convert.ToBase64String(new byte[64]) }));
        Assert.Throws<RelayFailure>(() => auth.Authenticate("presence", proof));
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
    public void ChallengeCapacityIsBoundedAndCleaned()
    {
        using var identity = new TestIdentity();
        var options = new RelayOptions { MaxChallengesPerDevice = 1, Devices = [identity.Options("controller")] };
        var clock = new TestClock();
        var auth = new ChallengeAuthenticator(options, new(options), clock);
        auth.Issue(new(identity.Id, "presence"));
        Assert.Equal(429, Assert.Throws<RelayFailure>(() => auth.Issue(new(identity.Id, "presence"))).Status);
        clock.Now = clock.Now.AddSeconds(61);
        Assert.NotNull(auth.Issue(new(identity.Id, "presence")));
    }
}
