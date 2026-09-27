using System.Text.Json;
using JTS.Relay.Server.Forwarding;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;
using JTS.Relay.Server.Storage;

namespace JTS.Relay.Server.Enrollment;

public sealed class RevocationService(AdmissionStore store, DeviceRegistry registry, SessionCoordinator sessions)
{
    public object Execute(string identity, JsonElement payload)
    {
        lock (registry.SyncRoot)
        {
            if (!registry.TryGet(identity, out var device)) throw new RelayFailure("authentication_failed", 401);
            switch (EnrollmentProtocol.Text(payload, "action"))
            {
                case "submit":
                    EnrollmentProtocol.Fields(payload, "action", "revocation");
                    var request = RevocationRequest.Parse(payload.GetProperty("revocation"));
                    var (view, created) = store.SubmitRevocation(device, request);
                    if (created) sessions.RevokePair(identity, request.PeerDeviceId);
                    return view;
                case "status":
                    EnrollmentProtocol.Fields(payload, "action", "revocationId");
                    return store.RevocationStatus(identity, EnrollmentProtocol.Id(payload, "revocationId"));
                case "poll":
                    EnrollmentProtocol.Fields(payload, "action"); return new { revocations = store.PollRevocations(device) };
                case "complete":
                    EnrollmentProtocol.Fields(payload, "action", "receipt");
                    return store.CompleteRevocation(device, RevocationReceipt.Parse(payload.GetProperty("receipt")));
                default: throw new RelayFailure("invalid_revocation_request");
            }
        }
    }
}
