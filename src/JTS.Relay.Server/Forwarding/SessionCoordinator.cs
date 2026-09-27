using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;

namespace JTS.Relay.Server.Forwarding;

public sealed class SessionCoordinator(RelayOptions options, DeviceRegistry registry, TimeProvider clock) : IDisposable
{
    private readonly object gate = new();
    private readonly Dictionary<string, RelaySession> sessions = new(StringComparer.Ordinal);
    public BytePacer BulkPacer { get; } = new(options.BulkBytesPerSecond);
    public BytePacer ControlPacer { get; } = new(options.ControlBytesPerSecond);
    private int GlobalControlReservation => Math.Max(1, options.MaxSessions / 4);
    private const int DeviceControlReservation = 1;

    public SessionResponse Create(AdmittedDevice controller, SessionRequest request)
    {
        lock (gate)
        {
            CleanupLocked();
            if (controller.Role != "controller" || !registry.TryGet(request.PeerDeviceId, out var peer) ||
                peer.Role != "companion" || !controller.Peers.Contains(peer.Id) || !peer.Peers.Contains(controller.Id))
                throw new RelayFailure("peer_not_authorized", 403);
            if (request.Lane is not ("control" or "file" or "rdp")) throw new RelayFailure("unsupported_lane");
            var controllerSessions = sessions.Values.Count(s => s.HasDevice(controller.Id));
            var companionSessions = sessions.Values.Count(s => s.HasDevice(peer.Id));
            if (sessions.Count >= options.MaxSessions ||
                controllerSessions >= options.MaxSessionsPerDevice || companionSessions >= options.MaxSessionsPerDevice ||
                (request.Lane == "rdp" && sessions.Values.Count(s => s.Lane == "rdp") >= options.MaxRdpSessions))
                throw new RelayFailure("capacity_exhausted", 429);
            // Preserve admission capacity as well as bandwidth for a new cancel/control lane.
            // Existing sockets are never evicted, and control may consume the full hard limit.
            if (request.Lane != "control" &&
                (sessions.Count >= options.MaxSessions - GlobalControlReservation ||
                 controllerSessions >= options.MaxSessionsPerDevice - DeviceControlReservation ||
                 companionSessions >= options.MaxSessionsPerDevice - DeviceControlReservation))
                throw new RelayFailure("capacity_exhausted", 429);
            var session = new RelaySession(controller.Id, peer.Id, request.Lane, clock.GetUtcNow());
            sessions.Add(session.Id, session);
            return new(session.Id, session.ControllerTicket, session.Expires.ToUnixTimeSeconds());
        }
    }
    public SessionOffer[] Poll(AdmittedDevice companion)
    {
        if (companion.Role != "companion") throw new RelayFailure("role_not_authorized", 403);
        lock (gate)
        {
            CleanupLocked();
            return sessions.Values.Where(s => s.IsOfferedTo(companion.Id)).Select(s =>
                new SessionOffer(s.Id, s.Lane, s.ControllerId, s.CompanionTicket, s.Expires.ToUnixTimeSeconds())).ToArray();
        }
    }
    public (RelaySession Session, bool Controller) Claim(string ticket)
    {
        lock (gate)
        {
            CleanupLocked();
            foreach (var session in sessions.Values)
                if (session.TryClaim(ticket, clock.GetUtcNow(), out var controller)) return (session, controller);
            throw new RelayFailure("invalid_ticket", 401);
        }
    }
    public void Cleanup() { lock (gate) CleanupLocked(); }
    private void CleanupLocked()
    {
        foreach (var pair in sessions.Where(s => s.Value.ShouldExpire(clock.GetUtcNow(), options)).ToArray())
        {
            pair.Value.Stop();
            sessions.Remove(pair.Key);
        }
    }
    public void Dispose()
    {
        lock (gate) { foreach (var session in sessions.Values) session.Stop(); sessions.Clear(); }
    }
}
