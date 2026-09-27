using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Security;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class ConfigurationTests
{
    [Theory]
    [InlineData("https://RELAY.example:443/", false, "https://relay.example")]
    [InlineData("https://relay.example:8443", false, "https://relay.example:8443")]
    [InlineData("http://127.0.0.1:8044/", true, "http://127.0.0.1:8044")]
    public void AudienceHasOneCanonicalOrigin(string input, bool development, string expected) =>
        Assert.Equal(expected, RelayOrigin.Canonicalize(input, development));

    [Theory]
    [InlineData("")]
    [InlineData("http://relay.example")]
    [InlineData("https://user@relay.example")]
    [InlineData("https://relay.example/path")]
    [InlineData("https://relay.example?query")]
    [InlineData("https://relay.example#fragment")]
    [InlineData("https://relay.example:0")]
    public void InvalidProductionAudienceFailsClosed(string value) =>
        Assert.Throws<InvalidOperationException>(() => RelayOrigin.Canonicalize(value));

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(33)]
    public void RejectsPerDeviceSessionLimitOutsideProtocolBound(int count)
    {
        using var device = new TestIdentity();
        var options = new RelayOptions { PublicOrigin = TestIdentity.Origin, DatabasePath = Path.GetFullPath("relay.sqlite"), MaxSessionsPerDevice = count, Devices = [device.Options("controller")] };
        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void AcceptsMaximumProtocolBoundAndRejectsOversizedPeerList()
    {
        using var device = new TestIdentity();
        var options = new RelayOptions { PublicOrigin = TestIdentity.Origin, DatabasePath = Path.GetFullPath("relay.sqlite"), MaxDevices = 256, MaxSessionsPerDevice = 32, Devices = [device.Options("controller")] };
        options.Validate();
        options.Devices[0].Peers = Enumerable.Repeat(new string('0', 64), 129).ToList();
        Assert.Throws<InvalidOperationException>(() => new DeviceRegistry(options));
    }

    [Fact]
    public void RejectsGlobalCapacityWithoutAReservedControlSlot()
    {
        using var device = new TestIdentity();
        var options = new RelayOptions { PublicOrigin = TestIdentity.Origin, DatabasePath = Path.GetFullPath("relay.sqlite"), MaxSessions = 1, MaxRdpSessions = 1, Devices = [device.Options("controller")] };
        Assert.Throws<InvalidOperationException>(options.Validate);
    }
}
