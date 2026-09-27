using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;

namespace JTS.Relay.Server.Enrollment;

public sealed record EnrollmentConfirmation(int Version, string RelayOrigin, string InvitationId,
    string ControllerDeviceId, string PeerDeviceId, string ClaimHash, long ConfirmedAtUnixSeconds,
    long ExpiresAtUnixSeconds, string SignatureBase64)
{
    public static EnrollmentConfirmation Parse(JsonElement value)
    {
        EnrollmentProtocol.Fields(value, "version", "relayOrigin", "invitationId", "controllerDeviceId", "peerDeviceId",
            "claimHash", "confirmedAtUnixSeconds", "expiresAtUnixSeconds", "signatureBase64");
        if (value.GetProperty("version").ValueKind != JsonValueKind.Number ||
            !value.GetProperty("version").TryGetInt32(out var version) || version != 2) throw Invalid();
        return new(2, EnrollmentProtocol.Text(value, "relayOrigin"), EnrollmentProtocol.Id(value),
            EnrollmentProtocol.Hash(value, "controllerDeviceId"), EnrollmentProtocol.Hash(value, "peerDeviceId"),
            EnrollmentProtocol.Hash(value, "claimHash"), Seconds(value, "confirmedAtUnixSeconds"),
            Seconds(value, "expiresAtUnixSeconds"), EnrollmentProtocol.Base64(value, "signatureBase64", 64, 64));
    }
    public string Transcript() => string.Join('\n', "JTS-PAIR-CONFIRM-2", RelayOrigin, InvitationId,
        ControllerDeviceId, PeerDeviceId, ClaimHash, ConfirmedAtUnixSeconds.ToString(CultureInfo.InvariantCulture),
        ExpiresAtUnixSeconds.ToString(CultureInfo.InvariantCulture));
    public void Verify(EnrollmentView view, AdmittedDevice controller, string origin, long now)
    {
        if (Version != 2 || RelayOrigin != origin || InvitationId != view.InvitationId ||
            ControllerDeviceId != controller.Id || ControllerDeviceId != view.ControllerDeviceId || view.Claim is null ||
            PeerDeviceId != EnrollmentProtocol.Digest(Convert.FromBase64String(view.Claim.PeerSPKIBase64)) ||
            ClaimHash != view.Claim.ClaimHash || ExpiresAtUnixSeconds != view.ExpiresAtUnixSeconds ||
            ConfirmedAtUnixSeconds <= 0 || ConfirmedAtUnixSeconds >= ExpiresAtUnixSeconds || ConfirmedAtUnixSeconds > now + 30)
            throw Invalid();
        VerifySignature(controller.Spki, Transcript(), SignatureBase64);
    }
    internal static long Seconds(JsonElement value, string name) => value.GetProperty(name).ValueKind == JsonValueKind.Number &&
        value.GetProperty(name).TryGetInt64(out var result) && result > 0 ? result : throw Invalid();
    internal static void VerifySignature(byte[] spki, string transcript, string signature)
    {
        try
        {
            using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(spki, out _);
            if (!key.VerifyData(Encoding.UTF8.GetBytes(transcript), Convert.FromBase64String(signature),
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw Invalid();
        }
        catch (Exception e) when (e is FormatException or CryptographicException) { throw Invalid(); }
    }
    private static RelayFailure Invalid() => new("invalid_signed_confirmation", 401);
}
