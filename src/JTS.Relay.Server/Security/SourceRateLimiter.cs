using JTS.Relay.Server.Protocol;

namespace JTS.Relay.Server.Security;

// Anonymous traffic never consumes a claimed device's authenticated quota.
internal sealed class SourceRateLimiter(TimeProvider clock, int limit)
{
    private readonly object gate = new();
    private readonly Dictionary<string, int> sources = new(StringComparer.Ordinal);
    private long minute = -1;
    public void Check(string source)
    {
        lock (gate)
        {
            var now = clock.GetUtcNow().ToUnixTimeSeconds() / 60;
            if (minute != now) { minute = now; sources.Clear(); }
            var count = sources.GetValueOrDefault(source);
            if (count >= limit || count == 0 && sources.Count >= 1024) throw new RelayFailure("rate_limited", 429);
            sources[source] = count + 1;
        }
    }
}
