using System.Diagnostics;

namespace JTS.Relay.Server.Forwarding;

public sealed class BytePacer(long bytesPerSecond)
{
    private readonly object gate = new();
    private long next;
    public async ValueTask WaitAsync(int bytes, CancellationToken cancellationToken)
    {
        long delay;
        lock (gate)
        {
            var now = Stopwatch.GetTimestamp();
            var start = Math.Max(now, next);
            next = start + (long)Math.Ceiling((double)bytes * Stopwatch.Frequency / bytesPerSecond);
            delay = next - now;
        }
        if (delay > 0)
            await Task.Delay(TimeSpan.FromSeconds((double)delay / Stopwatch.Frequency), cancellationToken);
    }
}
