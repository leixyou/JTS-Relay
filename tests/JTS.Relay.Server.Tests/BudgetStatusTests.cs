using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Storage;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class BudgetStatusTests
{
    [Fact]
    public void ThresholdWarningsAndReadOnlyStatusPersistAcrossRestart()
    {
        var directory = Directory.CreateTempSubdirectory("jts-relay-budget-test-").FullName;
        try
        {
            var options = new RelayOptions { DatabasePath = Path.Combine(directory, "relay.sqlite"), MonthlyOutboundBytes = 100, ControlReserveBytes = 10 };
            var clock = new TestClock();
            var warnings = new List<string>();
            using (var store = new RelayStore(options, clock, warnings.Add))
            {
                Assert.True(store.TryReserveOutbound(79, "control"));
                Assert.Empty(warnings);
                Assert.Equal("normal", BudgetStatusReader.Read(options, clock).Threshold);
                Assert.True(store.TryReserveOutbound(1, "control"));
                Assert.Equal(["relay_budget_80_percent"], warnings);
                var eighty = BudgetStatusReader.Read(options, clock);
                Assert.Equal("warning_80", eighty.Threshold);
                Assert.Equal(80, eighty.OutboundBytes);
                Assert.Equal(10, eighty.BulkAvailableBytes);
                Assert.Equal(20, eighty.ControlAvailableBytes);
            }
            using (var reopened = new RelayStore(options, clock, warnings.Add))
            {
                Assert.True(reopened.TryReserveOutbound(1, "control"));
                Assert.Single(warnings); // Restart does not reset the persistent alert marker.
                Assert.True(reopened.TryReserveOutbound(14, "control"));
                Assert.Equal("warning_95", BudgetStatusReader.Read(options, clock).Threshold);
                Assert.True(reopened.TryReserveOutbound(5, "control"));
                Assert.False(reopened.TryReserveOutbound(1, "control"));
                var exhausted = BudgetStatusReader.Read(options, clock);
                Assert.Equal("exhausted", exhausted.Threshold);
                Assert.Equal(0, exhausted.BulkAvailableBytes);
                Assert.Equal(0, exhausted.ControlAvailableBytes);
                Assert.Equal(["relay_budget_80_percent", "relay_budget_95_percent", "relay_budget_exhausted"], warnings);
                reopened.Cleanup();
                Assert.Equal("exhausted", BudgetStatusReader.Read(options, clock).Threshold);
                clock.Now = clock.Now.AddDays(1);
                Assert.Equal("normal", BudgetStatusReader.Read(options, clock).Threshold);
                Assert.True(reopened.TryReserveOutbound(80, "control"));
                Assert.Equal(4, warnings.Count);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void StatusDoesNotCreateMissingDatabase()
    {
        var directory = Directory.CreateTempSubdirectory("jts-relay-status-test-").FullName;
        try
        {
            var options = new RelayOptions { DatabasePath = Path.Combine(directory, "missing.sqlite") };
            Assert.Throws<Microsoft.Data.Sqlite.SqliteException>(() => BudgetStatusReader.Read(options, new TestClock()));
            Assert.False(File.Exists(options.DatabasePath));
        }
        finally { Directory.Delete(directory, true); }
    }
}
