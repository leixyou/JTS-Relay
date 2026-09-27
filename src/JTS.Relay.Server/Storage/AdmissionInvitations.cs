using System.Security.Cryptography;
using System.Text.Json;
using JTS.Relay.Server.Enrollment;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;
using Microsoft.Data.Sqlite;

namespace JTS.Relay.Server.Storage;

public sealed partial class AdmissionStore
{
    private long Now => clock.GetUtcNow().ToUnixTimeSeconds();
    public EnrollmentView Create(string controller, EnrollmentRequest request)
    {
        lock (SyncRoot)
        {
            using var transaction = connection.BeginTransaction(); Expire(transaction);
            var previous = Read(transaction, request.InvitationId!);
            if (previous is not null)
            {
                if (previous.View.ControllerDeviceId != controller || previous.TokenHash != request.ClaimTokenHash ||
                    previous.View.OfferBase64 != request.OfferBase64 || previous.View.ExpiresAtUnixSeconds != request.ExpiresAtUnixSeconds)
                    throw new RelayFailure("invitation_conflict", 409);
                transaction.Commit(); return previous.View;
            }
            if (request.ExpiresAtUnixSeconds < Now + 300 || request.ExpiresAtUnixSeconds > Now + 1800)
                throw new RelayFailure("invalid_invitation_expiry");
            // Bound rows stay available for recovery until explicit revoke; never evict them for a new invitation.
            Execute(transaction, "DELETE FROM admission_invitations WHERE state IN ('cancelled','expired') AND updated < $cutoff",
                ("$cutoff", Now - options.SecurityRetentionDays * 86400L));
            var active = (long)Scalar(transaction, "SELECT count(*) FROM admission_invitations WHERE state IN ('pending','claimed')")!;
            var ownerActive = (long)Scalar(transaction, "SELECT count(*) FROM admission_invitations WHERE controller=$controller AND state IN ('pending','claimed')", ("$controller", controller))!;
            var total = (long)Scalar(transaction, "SELECT count(*) FROM admission_invitations")!;
            if (active >= options.MaxEnrollmentInvitations || ownerActive >= options.MaxEnrollmentInvitationsPerController || total >= options.MaxStoredEnrollments)
                throw new RelayFailure("capacity_exhausted", 429);
            Execute(transaction, "INSERT INTO admission_invitations(id,controller,token_hash,state,expires,offer,updated) VALUES($id,$controller,$token,'pending',$expiry,$offer,$now)",
                ("$id", request.InvitationId!), ("$controller", controller), ("$token", request.ClaimTokenHash!),
                ("$expiry", request.ExpiresAtUnixSeconds), ("$offer", request.OfferBase64!), ("$now", Now));
            var result = Read(transaction, request.InvitationId!)!.View; transaction.Commit(); return result;
        }
    }
    public EnrollmentView Owned(string controller, string id, string action, string? hash = null, EnrollmentConfirmation? confirmation = null)
    {
        lock (SyncRoot)
        {
            if (!TryGet(controller, out var identity)) throw new RelayFailure("authentication_failed", 401);
            using var transaction = connection.BeginTransaction(); Expire(transaction);
            var item = Read(transaction, id);
            if (item is null || item.View.ControllerDeviceId != controller) throw new RelayFailure("invitation_not_found", 404);
            var view = item.View;
            if (action == "confirm")
            {
                if (view.Claim is null || view.Claim.ClaimHash != hash || view.State is not ("claimed" or "bound"))
                    throw new RelayFailure("invitation_not_confirmable", 409);
                if (confirmation is null) throw new RelayFailure("invalid_signed_confirmation", 401);
                confirmation.Verify(view, identity, options.PublicOrigin, Now);
                if (view.State == "bound" && view.Confirmation != confirmation) throw new RelayFailure("confirmation_conflict", 409);
                if (view.State == "claimed")
                {
                    var verified = EnrollmentProtocol.VerifyClaim(view, view.Claim);
                    AddPair(transaction, controller, verified.Peer);
                    Execute(transaction, "INSERT INTO admission_confirmations VALUES($id,$document)",
                        ("$id", id), ("$document", JsonSerializer.Serialize(confirmation)));
                    Execute(transaction, "UPDATE admission_invitations SET state='bound',updated=$now WHERE id=$id", ("$now", Now), ("$id", id));
                }
            }
            else if (action == "cancel")
            {
                if (view.State == "bound") throw new RelayFailure("bound_invitation_requires_revoke", 409);
                if (view.State is "pending" or "claimed")
                    Execute(transaction, "UPDATE admission_invitations SET state='cancelled',updated=$now WHERE id=$id", ("$now", Now), ("$id", id));
            }
            var result = Read(transaction, id)!.View; transaction.Commit(); return result;
        }
    }
    public EnrollmentView Public(PublicEnrollmentRequest request)
    {
        lock (SyncRoot)
        {
            using var transaction = connection.BeginTransaction(); Expire(transaction);
            var item = Read(transaction, request.InvitationId);
            var tokenHash = SHA256.HashData(Convert.FromBase64String(request.ClaimTokenBase64));
            if (item is null || !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(item.TokenHash), tokenHash))
                throw new RelayFailure("invitation_not_found", 404);
            var view = item.View;
            if (request.Claim is not null)
            {
                if (view.State is not ("pending" or "claimed" or "bound")) throw new RelayFailure("invitation_not_claimable", 409);
                (EnrollmentClaim Claim, AdmittedDevice Peer) verified;
                try { verified = EnrollmentProtocol.VerifyClaim(view, request.Claim); }
                catch (InvalidOperationException) { throw new RelayFailure("invalid_claim_proof", 401); }
                if (view.Claim is not null)
                {
                    // Compare the entire original proof, not just the peer or transcript hash.
                    if (view.Claim != verified.Claim) throw new RelayFailure("invitation_already_claimed", 409);
                }
                else
                {
                    if (verified.Peer.Id == view.ControllerDeviceId) throw new RelayFailure("invalid_claim_proof", 401);
                    Execute(transaction, "UPDATE admission_invitations SET state='claimed',peer_spki=$spki,response=$response,signature=$signature,claim_hash=$hash,peer_id=$peer,updated=$now WHERE id=$id",
                        ("$spki", verified.Claim.PeerSPKIBase64), ("$response", verified.Claim.ResponseBase64),
                        ("$signature", verified.Claim.SignatureBase64), ("$hash", verified.Claim.ClaimHash),
                        ("$peer", verified.Peer.Id), ("$now", Now), ("$id", request.InvitationId));
                }
            }
            var result = Read(transaction, request.InvitationId)!.View; transaction.Commit(); return result;
        }
    }
    public void Revoke(string controller, string peer)
    {
        lock (SyncRoot)
        {
            using var transaction = connection.BeginTransaction();
            Execute(transaction, "DELETE FROM admission_peers WHERE controller=$controller AND companion=$peer", ("$controller", controller), ("$peer", peer));
            Execute(transaction, "UPDATE admission_invitations SET state='cancelled',updated=$now WHERE controller=$controller AND peer_id=$peer AND state IN ('claimed','bound')",
                ("$now", Now), ("$controller", controller), ("$peer", peer));
            transaction.Commit();
        }
    }
    private void Expire(SqliteTransaction transaction) => Execute(transaction,
        "UPDATE admission_invitations SET state='expired',updated=$now WHERE state IN ('pending','claimed') AND expires <= $now", ("$now", Now));
    private sealed record StoredInvitation(string TokenHash, EnrollmentView View);
    private StoredInvitation? Read(SqliteTransaction transaction, string id)
    {
        using var command = Command(transaction, "SELECT controller,token_hash,state,expires,offer,peer_spki,response,signature,claim_hash FROM admission_invitations WHERE id=$id", ("$id", id));
        using var reader = command.ExecuteReader(); if (!reader.Read()) return null;
        var claim = reader.IsDBNull(5) ? null : new EnrollmentClaim(reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.GetString(8));
        var result = new StoredInvitation(reader.GetString(1), new(id, reader.GetString(0), reader.GetString(2), reader.GetInt64(3), reader.GetString(4), claim));
        reader.Close();
        var confirmation = Scalar(transaction, "SELECT document FROM admission_confirmations WHERE invitation=$id", ("$id", id)) as string;
        return result with { View = result.View with { Confirmation = confirmation is null ? null : JsonSerializer.Deserialize<EnrollmentConfirmation>(confirmation) } };
    }
}
