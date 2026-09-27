using JTS.Relay.Server.Forwarding;
using JTS.Relay.Server.Security;
using JTS.Relay.Server.Storage;

namespace JTS.Relay.Server.Hosting;

public sealed class ExpiryService(ChallengeAuthenticator auth, SessionCoordinator sessions, RelayStore store) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        var ticks = 0;
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                auth.Cleanup();
                sessions.Cleanup();
                if (++ticks % 60 == 0) store.Cleanup();
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        sessions.Dispose();
        await base.StopAsync(cancellationToken);
    }
}
