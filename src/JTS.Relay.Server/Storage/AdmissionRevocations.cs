using System.Text.Json;
using JTS.Relay.Server.Enrollment;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;

namespace JTS.Relay.Server.Storage;

public sealed partial class AdmissionStore
{
    public (RevocationView View, bool Created) SubmitRevocation(AdmittedDevice controller, RevocationRequest request)
    {
        lock (SyncRoot)
        {
            if (controller.Role != "controller" || request.ControllerDeviceId != controller.Id ||
                request.Version != 2 || request.RelayOrigin != options.PublicOrigin || request.RequestedAtUnixSeconds <= 0 ||
                !TryGet(request.PeerDeviceId, out var peer) || peer.Role != "companion")
                throw new RelayFailure("revocation_not_authorized", 403);
            EnrollmentConfirmation.VerifySignature(controller.Spki, request.Transcript(), request.SignatureBase64);
            var existing = ReadRevocation(request.RevocationId);
            if (existing is not null)
            {
                if (existing.Revocation != request) throw new RelayFailure("revocation_conflict", 409);
                return (existing, false);
            }
            using var transaction = connection.BeginTransaction();
            if (!controller.Peers.Contains(peer.Id) && Scalar(transaction,
                "SELECT 1 FROM admission_invitations WHERE controller=$controller AND peer_id=$peer LIMIT 1",
                ("$controller", controller.Id), ("$peer", peer.Id)) is null) throw new RelayFailure("revocation_not_authorized", 403);
            if ((long)Scalar(transaction, "SELECT count(*) FROM admission_revocations")! >= options.MaxStoredEnrollments ||
                (long)Scalar(transaction, "SELECT count(*) FROM admission_revocations WHERE peer=$peer AND receipt IS NULL", ("$peer", peer.Id))! >= 128)
                throw new RelayFailure("capacity_exhausted", 429);
            Execute(transaction, "INSERT INTO admission_revocations(id,controller,peer,request,controller_spki) VALUES($id,$controller,$peer,$request,$spki)",
                ("$id", request.RevocationId), ("$controller", controller.Id), ("$peer", peer.Id),
                ("$request", JsonSerializer.Serialize(request)), ("$spki", Convert.ToBase64String(controller.Spki)));
            Execute(transaction, "DELETE FROM admission_peers WHERE controller=$controller AND companion=$peer", ("$controller", controller.Id), ("$peer", peer.Id));
            Execute(transaction, "UPDATE admission_invitations SET state='cancelled',updated=$now WHERE controller=$controller AND peer_id=$peer AND state IN ('claimed','bound')",
                ("$now", Now), ("$controller", controller.Id), ("$peer", peer.Id));
            transaction.Commit();
            return (ReadRevocation(request.RevocationId)!, true);
        }
    }
    public RevocationView RevocationStatus(string identity, string id)
    {
        lock (SyncRoot)
        {
            var view = ReadRevocation(id);
            if (view is null || identity != view.Revocation.ControllerDeviceId && identity != view.Revocation.PeerDeviceId)
                throw new RelayFailure("revocation_not_found", 404);
            return view;
        }
    }
    public RevocationView[] PollRevocations(AdmittedDevice peer)
    {
        lock (SyncRoot)
        {
            if (peer.Role != "companion") throw new RelayFailure("role_not_authorized", 403);
            using var command = Command(null, "SELECT id FROM admission_revocations WHERE peer=$peer AND receipt IS NULL ORDER BY rowid LIMIT 32", ("$peer", peer.Id));
            var ids = new List<string>();
            using (var reader = command.ExecuteReader()) while (reader.Read()) ids.Add(reader.GetString(0));
            var result = new List<RevocationView>(); var bytes = 32;
            foreach (var id in ids)
            {
                var view = ReadRevocation(id)!;
                bytes += JsonSerializer.SerializeToUtf8Bytes(view, new JsonSerializerOptions(JsonSerializerDefaults.Web)).Length + 1;
                if (bytes > 65536) break;
                result.Add(view);
            }
            return result.ToArray();
        }
    }
    public RevocationView CompleteRevocation(AdmittedDevice peer, RevocationReceipt receipt)
    {
        lock (SyncRoot)
        {
            var view = RevocationStatus(peer.Id, receipt.RevocationId);
            if (peer.Role != "companion" || peer.Id != view.Revocation.PeerDeviceId || receipt.PeerDeviceId != peer.Id ||
                receipt.ControllerDeviceId != view.Revocation.ControllerDeviceId || receipt.RequestHash != view.RequestHash ||
                receipt.Version != 2 || receipt.RevokedAtUnixSeconds <= 0)
                throw new RelayFailure("revocation_not_authorized", 403);
            EnrollmentConfirmation.VerifySignature(peer.Spki, receipt.Transcript(), receipt.SignatureBase64);
            if (view.Receipt is not null)
            {
                if (view.Receipt != receipt) throw new RelayFailure("revocation_conflict", 409);
                return view;
            }
            Execute(null, "UPDATE admission_revocations SET receipt=$receipt WHERE id=$id", ("$receipt", JsonSerializer.Serialize(receipt)), ("$id", receipt.RevocationId));
            return ReadRevocation(receipt.RevocationId)!;
        }
    }
    private RevocationView? ReadRevocation(string id)
    {
        using var command = Command(null, "SELECT request,controller_spki,receipt FROM admission_revocations WHERE id=$id", ("$id", id));
        using var reader = command.ExecuteReader(); if (!reader.Read()) return null;
        var request = JsonSerializer.Deserialize<RevocationRequest>(reader.GetString(0))!;
        var receipt = reader.IsDBNull(2) ? null : JsonSerializer.Deserialize<RevocationReceipt>(reader.GetString(2));
        return new(id, request.RequestHash, receipt is null ? "pending" : "complete", request, reader.GetString(1), receipt);
    }
}
