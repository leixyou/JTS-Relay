using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;

namespace JTS.Relay.Server.Enrollment;

public sealed record EnrollmentClaim(string PeerSPKIBase64, string ResponseBase64, string SignatureBase64, string ClaimHash);
public sealed record EnrollmentView(string InvitationId, string ControllerDeviceId, string State,
    long ExpiresAtUnixSeconds, string OfferBase64,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] EnrollmentClaim? Claim,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] EnrollmentConfirmation? Confirmation = null);
public sealed record EnrollmentRequest(string Action, string? InvitationId = null, string? ClaimTokenHash = null,
    string? OfferBase64 = null, long ExpiresAtUnixSeconds = 0, string? ClaimHash = null, string? PeerDeviceId = null,
    EnrollmentConfirmation? Confirmation = null);
public sealed record PublicEnrollmentRequest(string InvitationId, string ClaimTokenBase64, EnrollmentClaim? Claim);

public static class EnrollmentProtocol
{
    public const int MaximumCipherBytes = 8192;
    public static EnrollmentRequest Parse(JsonElement root)
    {
        var action = Text(root, "action");
        switch (action)
        {
            case "create":
                Fields(root, "action", "invitationId", "claimTokenHash", "offerBase64", "expiresAtUnixSeconds");
                var expiry = root.GetProperty("expiresAtUnixSeconds");
                if (expiry.ValueKind != JsonValueKind.Number || !expiry.TryGetInt64(out var seconds)) throw Invalid();
                return new(action, Id(root), Hash(root, "claimTokenHash"), Base64(root, "offerBase64", 1, MaximumCipherBytes), seconds);
            case "status": case "cancel":
                Fields(root, "action", "invitationId"); return new(action, Id(root));
            case "confirm":
                Fields(root, "action", "invitationId", "claimHash", "confirmation");
                return new(action, Id(root), ClaimHash: Hash(root, "claimHash"), Confirmation: EnrollmentConfirmation.Parse(root.GetProperty("confirmation")));
            case "revoke":
                Fields(root, "action", "peerDeviceId"); return new(action, PeerDeviceId: Hash(root, "peerDeviceId"));
            default: throw Invalid();
        }
    }
    public static PublicEnrollmentRequest ParsePublic(JsonElement root, bool claim)
    {
        if (claim) Fields(root, "invitationId", "claimTokenBase64", "peerSPKIBase64", "responseBase64", "signatureBase64");
        else Fields(root, "invitationId", "claimTokenBase64");
        return new(Id(root), Base64(root, "claimTokenBase64", 32, 32), claim ? new(
            Base64(root, "peerSPKIBase64", 91, 91), Base64(root, "responseBase64", 1, MaximumCipherBytes),
            Base64(root, "signatureBase64", 64, 64), "") : null);
    }
    public static (EnrollmentClaim Claim, AdmittedDevice Peer) VerifyClaim(EnrollmentView invitation, EnrollmentClaim supplied)
    {
        var spki = Convert.FromBase64String(supplied.PeerSPKIBase64);
        var id = Digest(spki);
        var peer = PublicDeviceIdentity.Parse(id, supplied.PeerSPKIBase64, "companion", []);
        var transcript = Transcript(invitation.InvitationId, invitation.ControllerDeviceId, invitation.OfferBase64,
            supplied.ResponseBase64, supplied.PeerSPKIBase64);
        using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(spki, out _);
        if (!key.VerifyData(Encoding.UTF8.GetBytes(transcript), Convert.FromBase64String(supplied.SignatureBase64),
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            throw new RelayFailure("invalid_claim_proof", 401);
        return (supplied with { ClaimHash = Digest(Encoding.UTF8.GetBytes(transcript)) }, peer);
    }
    public static string Transcript(string invitation, string controller, string offer, string response, string spki) =>
        string.Join('\n', "JTS-PAIR-1", invitation, controller, Digest(Convert.FromBase64String(offer)),
            Digest(Convert.FromBase64String(response)), Digest(Convert.FromBase64String(spki)));
    public static string Digest(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    internal static string Id(JsonElement root, string name = "invitationId")
    {
        var value = Text(root, name);
        if (!Guid.TryParseExact(value, "D", out var id) || id == Guid.Empty || id.ToString("D") != value) throw Invalid();
        return value;
    }
    internal static string Hash(JsonElement root, string name)
    {
        var value = Text(root, name);
        if (value.Length != 64 || value.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))) throw Invalid();
        return value;
    }
    internal static string Base64(JsonElement root, string name, int min, int max)
    {
        var value = Text(root, name);
        if (value.Length > ((max + 2) / 3) * 4) throw Invalid();
        try
        {
            var bytes = Convert.FromBase64String(value);
            if (bytes.Length < min || bytes.Length > max || Convert.ToBase64String(bytes) != value) throw Invalid();
            return value;
        }
        catch (FormatException) { throw Invalid(); }
    }
    internal static string Text(JsonElement root, string name) => root.ValueKind == JsonValueKind.Object &&
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString()! : throw Invalid();
    internal static void Fields(JsonElement root, params string[] expected)
    {
        if (root.ValueKind != JsonValueKind.Object) throw Invalid();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
            if (!expected.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name)) throw Invalid();
        if (seen.Count != expected.Length) throw Invalid();
    }
    private static RelayFailure Invalid() => new("invalid_enrollment_request");
}
