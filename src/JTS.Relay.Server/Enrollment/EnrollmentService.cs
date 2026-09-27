using System.Text.Json;
using JTS.Relay.Server.Forwarding;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;
using JTS.Relay.Server.Storage;

namespace JTS.Relay.Server.Enrollment;

public sealed class EnrollmentService(AdmissionStore store, DeviceRegistry registry, SessionCoordinator sessions)
{
    public object Execute(string controller, JsonElement payload)
    {
        var request = EnrollmentProtocol.Parse(payload);
        lock (registry.SyncRoot)
        {
            if (!registry.TryGet(controller, out var identity) || identity.Role != "controller")
                throw new RelayFailure("role_not_authorized", 403);
            switch (request.Action)
            {
                case "create": return store.Create(controller, request);
                case "status": case "confirm": case "cancel":
                    return store.Owned(controller, request.InvitationId!, request.Action, request.ClaimHash);
                case "revoke":
                    // Persist removal first, then close every affected ticket/socket before reporting completion.
                    // The shared lock excludes concurrent session creation and ticket claims.
                    store.Revoke(controller, request.PeerDeviceId!);
                    sessions.RevokePair(controller, request.PeerDeviceId!);
                    return new { peerDeviceId = request.PeerDeviceId, state = "revoked" };
                default: throw new RelayFailure("invalid_enrollment_request");
            }
        }
    }
    public EnrollmentView Public(JsonElement payload, bool claim) => store.Public(EnrollmentProtocol.ParsePublic(payload, claim));
}
