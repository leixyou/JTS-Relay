using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Protocol;

namespace JTS.Relay.Server.Security;

public sealed class EnrollmentRateLimiter(RelayOptions options, TimeProvider clock)
{
    private readonly object gate = new();
    private readonly Dictionary<string, int> clients = new(StringComparer.Ordinal);
    private long minute = -1;
    private int count;
    public void Check(string address)
    {
        lock (gate)
        {
            var now = clock.GetUtcNow().ToUnixTimeSeconds() / 60;
            if (now != minute) { minute = now; count = 0; clients.Clear(); }
            var previous = clients.GetValueOrDefault(address);
            if (count >= options.MaxPublicEnrollmentRequestsPerMinute || previous >= options.MaxRequestsPerMinute ||
                previous == 0 && clients.Count >= 1024) throw new RelayFailure("rate_limited", 429);
            count++;
            clients[address] = previous + 1;
        }
    }
}
