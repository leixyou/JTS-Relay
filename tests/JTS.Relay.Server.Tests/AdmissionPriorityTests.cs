using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Forwarding;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class AdmissionPriorityTests
{
    [Theory]
    [InlineData(4, 8, 3)] // Global reserve of one controls admission.
    [InlineData(8, 2, 1)] // Per-device reserve of one controls admission.
    public void BulkCannotConsumeReservedControlAdmission(int globalLimit, int deviceLimit, int bulkCapacity)
    {
        using var controller = new TestIdentity();
        using var companion = new TestIdentity();
        var options = new RelayOptions
        {
            MaxSessions = globalLimit, MaxSessionsPerDevice = deviceLimit,
            Devices = [controller.Options("controller", companion.Id), companion.Options("companion", controller.Id)]
        };
        var registry = new DeviceRegistry(options);
        using var coordinator = new SessionCoordinator(options, registry, new TestClock());
        var controllerDevice = registry.Get(controller.Id);
        for (var count = 0; count < bulkCapacity; count++)
            coordinator.Create(controllerDevice, new(companion.Id, "file"));
        Assert.Equal(429, Assert.Throws<RelayFailure>(() => coordinator.Create(controllerDevice, new(companion.Id, "file"))).Status);
        var control = coordinator.Create(controllerDevice, new(companion.Id, "control"));
        Assert.NotNull(control);
        Assert.Equal(bulkCapacity + 1, coordinator.Poll(registry.Get(companion.Id)).Length);
        Assert.Equal(429, Assert.Throws<RelayFailure>(() => coordinator.Create(controllerDevice, new(companion.Id, "control"))).Status);
    }

    [Fact]
    public void ExistingControlDoesNotAllowBulkToConsumeLastFreeControlSlot()
    {
        using var controller = new TestIdentity();
        using var companion = new TestIdentity();
        var options = new RelayOptions
        {
            MaxSessions = 4, MaxSessionsPerDevice = 4,
            Devices = [controller.Options("controller", companion.Id), companion.Options("companion", controller.Id)]
        };
        var registry = new DeviceRegistry(options);
        using var coordinator = new SessionCoordinator(options, registry, new TestClock());
        var controllerDevice = registry.Get(controller.Id);
        coordinator.Create(controllerDevice, new(companion.Id, "control"));
        coordinator.Create(controllerDevice, new(companion.Id, "file"));
        coordinator.Create(controllerDevice, new(companion.Id, "rdp"));
        Assert.Throws<RelayFailure>(() => coordinator.Create(controllerDevice, new(companion.Id, "file")));
        Assert.NotNull(coordinator.Create(controllerDevice, new(companion.Id, "control")));
    }
}
