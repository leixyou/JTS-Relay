using JTS.Relay.Server.Configuration;

namespace JTS.Relay.Server.Storage;

public sealed record BudgetStatus(string Month, long OutboundBytes, long MonthlyLimitBytes,
    long ControlReserveBytes, long BulkAvailableBytes, long ControlAvailableBytes, string Threshold)
{
    internal static BudgetStatus Create(string month, long bytes, RelayOptions options)
    {
        var level = Level(bytes, options.MonthlyOutboundBytes);
        return new(month, bytes, options.MonthlyOutboundBytes, options.ControlReserveBytes,
            Math.Max(0, options.MonthlyOutboundBytes - options.ControlReserveBytes - bytes),
            Math.Max(0, options.MonthlyOutboundBytes - bytes), level switch
            {
                100 => "exhausted", 95 => "warning_95", 80 => "warning_80", _ => "normal"
            });
    }
    internal static int Level(long bytes, long limit) => bytes >= limit ? 100 :
        (decimal)bytes / limit >= .95m ? 95 : (decimal)bytes / limit >= .80m ? 80 : 0;
    internal static string? Warning(int level) => level switch
    {
        100 => "relay_budget_exhausted", 95 => "relay_budget_95_percent", 80 => "relay_budget_80_percent", _ => null
    };
}
