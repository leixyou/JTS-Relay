using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Security;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class ConfigurationTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(33)]
    public void RejectsPerDeviceSessionLimitOutsideProtocolBound(int count)
    {
        using var device = new TestIdentity();
        var options = new RelayOptions { DatabasePath = Path.GetFullPath("relay.sqlite"), MaxSessionsPerDevice = count, Devices = [device.Options("controller")] };
        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void AcceptsMaximumProtocolBoundAndRejectsOversizedPeerList()
    {
        using var device = new TestIdentity();
        var options = new RelayOptions { DatabasePath = Path.GetFullPath("relay.sqlite"), MaxDevices = 256, MaxSessionsPerDevice = 32, Devices = [device.Options("controller")] };
        options.Validate();
        options.Devices[0].Peers = Enumerable.Repeat(new string('0', 64), 129).ToList();
        Assert.Throws<InvalidOperationException>(() => new DeviceRegistry(options));
    }

    [Fact]
    public void RejectsGlobalCapacityWithoutAReservedControlSlot()
    {
        using var device = new TestIdentity();
        var options = new RelayOptions { DatabasePath = Path.GetFullPath("relay.sqlite"), MaxSessions = 1, MaxRdpSessions = 1, Devices = [device.Options("controller")] };
        Assert.Throws<InvalidOperationException>(options.Validate);
    }
}
