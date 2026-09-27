using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Forwarding;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;
using JTS.Relay.Server.Storage;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class StateTests
{
    [Fact]
    public void QuotaPersistsAndControlReserveSurvivesCurrentMonthCleanup()
    {
        var directory = Directory.CreateTempSubdirectory("jts-relay-store-test-").FullName;
        try
        {
            var clock = new TestClock();
            var options = new RelayOptions { PublicOrigin = TestIdentity.Origin, DatabasePath = Path.Combine(directory, "relay.sqlite"), MonthlyOutboundBytes = 100, ControlReserveBytes = 20, UsageRetentionDays = 1 };
            using (var store = new RelayStore(options, clock))
            {
                Assert.True(store.TryReserveOutbound(80, "file"));
                Assert.False(store.TryReserveOutbound(1, "rdp"));
                store.Cleanup();
            }
            using (var reopened = new RelayStore(options, clock))
            {
                Assert.False(reopened.TryReserveOutbound(1, "file"));
                Assert.True(reopened.TryReserveOutbound(20, "control"));
                Assert.False(reopened.TryReserveOutbound(1, "control"));
                clock.Now = clock.Now.AddDays(1);
                Assert.True(reopened.TryReserveOutbound(80, "file"));
            }
        }
        finally { Directory.Delete(directory, true); }
    }
    [Fact]
    public void TicketIsRoleSpecificSingleUseAndWaitingSessionsExpire()
    {
        using var controller = new TestIdentity();
        using var companion = new TestIdentity();
        var options = new RelayOptions { PublicOrigin = TestIdentity.Origin, Devices = [controller.Options("controller", companion.Id), companion.Options("companion", controller.Id)] };
        var registry = new DeviceRegistry(options);
        var clock = new TestClock();
        using var sessions = new SessionCoordinator(options, registry, clock);
        var created = sessions.Create(registry.Get(controller.Id), new(companion.Id, "file"));
        var offer = Assert.Single(sessions.Poll(registry.Get(companion.Id)));
        Assert.NotEqual(created.Ticket, offer.Ticket);
        var claim = sessions.Claim(created.Ticket);
        Assert.True(claim.Controller);
        Assert.Throws<RelayFailure>(() => sessions.Claim(created.Ticket));
        Assert.False(sessions.Claim(offer.Ticket).Controller);
        Assert.Empty(sessions.Poll(registry.Get(companion.Id)));
        clock.Now = clock.Now.AddSeconds(61);
        sessions.Cleanup();
        Assert.True(claim.Session.IsComplete);
        Assert.Throws<RelayFailure>(() => sessions.Claim(offer.Ticket));
    }
    [Fact]
    public void WrongPeerAndUnsupportedLaneAreRejected()
    {
        using var controller = new TestIdentity();
        using var companion = new TestIdentity();
        using var outsider = new TestIdentity();
        var options = new RelayOptions { PublicOrigin = TestIdentity.Origin, Devices = [controller.Options("controller", companion.Id), companion.Options("companion", controller.Id), outsider.Options("companion")] };
        var registry = new DeviceRegistry(options);
        using var sessions = new SessionCoordinator(options, registry, new TestClock());
        Assert.Equal(403, Assert.Throws<RelayFailure>(() => sessions.Create(registry.Get(controller.Id), new(outsider.Id, "rdp"))).Status);
        Assert.Throws<RelayFailure>(() => sessions.Create(registry.Get(controller.Id), new(companion.Id, "proxy")));
        Assert.Throws<RelayFailure>(() => sessions.Create(registry.Get(companion.Id), new(controller.Id, "control")));
    }
}
