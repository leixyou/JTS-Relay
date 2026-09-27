using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text.Json;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Storage;

namespace JTS.Relay.Server.Forwarding;

public sealed class RelaySession : IDisposable
{
    private readonly object gate = new();
    private readonly CancellationTokenSource cancellation = new();
    private readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private WebSocket? controllerSocket;
    private WebSocket? companionSocket;
    private bool controllerClaimed;
    private bool companionClaimed;
    private bool started;
    private bool disposed;
    private long lastActivityTicks;
    public string Id { get; } = Guid.NewGuid().ToString("D");
    public string ControllerId { get; }
    public string CompanionId { get; }
    public string Lane { get; }
    public string ControllerTicket { get; } = Ticket();
    public string CompanionTicket { get; } = Ticket();
    public DateTimeOffset Created { get; }
    public DateTimeOffset Expires => Created.AddSeconds(60);
    public bool IsComplete => completion.Task.IsCompleted;
    public Task Completion => completion.Task;

    public RelaySession(string controllerId, string companionId, string lane, DateTimeOffset now)
    {
        ControllerId = controllerId;
        CompanionId = companionId;
        Lane = lane;
        Created = now;
        lastActivityTicks = now.UtcTicks;
    }
    private static string Ticket() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public bool HasDevice(string id) => ControllerId == id || CompanionId == id;
    public bool IsOfferedTo(string id) { lock (gate) return !disposed && !companionClaimed && CompanionId == id; }
    public bool TryClaim(string ticket, DateTimeOffset now, out bool controller)
    {
        lock (gate)
        {
            controller = false;
            if (disposed || now >= Expires) return false;
            if (!controllerClaimed && ticket == ControllerTicket) { controllerClaimed = true; controller = true; return true; }
            if (!companionClaimed && ticket == CompanionTicket) { companionClaimed = true; return true; }
            return false;
        }
    }
    public void Attach(bool controller, WebSocket socket, RelayOptions options, RelayStore store,
        BytePacer bulk, BytePacer control, TimeProvider clock)
    {
        lock (gate)
        {
            if (disposed) { socket.Abort(); return; }
            if (controller) controllerSocket = socket; else companionSocket = socket;
            if (controllerSocket is null || companionSocket is null || started) return;
            started = true;
            _ = RunAsync(options, store, bulk, control, clock);
        }
    }
    public bool ShouldExpire(DateTimeOffset now, RelayOptions options)
    {
        lock (gate) return disposed || (!started && now >= Expires) ||
            now >= Created.AddSeconds(options.MaxSessionSeconds) ||
            (started && now.UtcTicks - Interlocked.Read(ref lastActivityTicks) >= TimeSpan.FromSeconds(options.IdleTimeoutSeconds).Ticks);
    }
    private async Task RunAsync(RelayOptions options, RelayStore store, BytePacer bulk, BytePacer control, TimeProvider clock)
    {
        try
        {
            var ready = JsonSerializer.SerializeToUtf8Bytes(new { ready = true, sessionId = Id, lane = Lane });
            await controllerSocket!.SendAsync(ready, WebSocketMessageType.Text, true, cancellation.Token);
            await companionSocket!.SendAsync(ready, WebSocketMessageType.Text, true, cancellation.Token);
            var pacer = new BytePacer(options.SessionBytesPerSecond);
            var aggregate = Lane == "control" ? control : bulk;
            var outbound = PumpAsync(controllerSocket, companionSocket, store, aggregate, pacer, clock);
            var inbound = PumpAsync(companionSocket, controllerSocket, store, aggregate, pacer, clock);
            await Task.WhenAny(outbound, inbound);
            cancellation.Cancel();
            controllerSocket.Abort();
            companionSocket.Abort();
            await Task.WhenAll(outbound, inbound);
        }
        // Both pump tasks are joined above. Any transport/storage fault closes the lane;
        // never expose exception text or leave an unobserved background task.
        catch (Exception) { }
        finally { Stop(); }
    }
    private async Task PumpAsync(WebSocket source, WebSocket destination, RelayStore store, BytePacer aggregate, BytePacer session, TimeProvider clock)
    {
        var buffer = new byte[16 * 1024];
        var emptyFrames = 0;
        while (!cancellation.IsCancellationRequested)
        {
            var read = await source.ReceiveAsync(buffer.AsMemory(), cancellation.Token);
            if (read.MessageType != WebSocketMessageType.Binary) return;
            if (read.Count == 0)
            {
                if (++emptyFrames >= 8) return;
                continue; // No SQLite writes, outbound traffic or idle extension for empty frames.
            }
            emptyFrames = 0;
            // Tiny frames still consume scheduler/storage work. Charge a minimum
            // pacing unit without inflating persisted payload-byte accounting.
            var pacedBytes = Math.Max(1024, read.Count);
            await session.WaitAsync(pacedBytes, cancellation.Token);
            await aggregate.WaitAsync(pacedBytes, cancellation.Token);
            if (!store.TryReserveOutbound(read.Count, Lane)) return;
            await destination.SendAsync(buffer.AsMemory(0, read.Count), WebSocketMessageType.Binary,
                read.EndOfMessage, cancellation.Token);
            Interlocked.Exchange(ref lastActivityTicks, clock.GetUtcNow().UtcTicks);
        }
    }
    public void Stop()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            cancellation.Cancel();
            controllerSocket?.Abort();
            companionSocket?.Abort();
            completion.TrySetResult();
        }
    }
    public void Dispose() => Stop();
}
