using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using JTS.Relay.Server.Protocol;

namespace JTS.Relay.Server.Enrollment;

public sealed record RevocationRequest(int Version, string RevocationId, string RelayOrigin, string ControllerDeviceId,
    string PeerDeviceId, string PairingId, string GrantId, string FileGrantId, string RdpGrantId,
    long RequestedAtUnixSeconds, string SignatureBase64)
{
    public string Transcript() => string.Join('\n', "JTS-PAIR-REVOKE-2", RevocationId, RelayOrigin, ControllerDeviceId,
        PeerDeviceId, PairingId, GrantId, FileGrantId, RdpGrantId, RequestedAtUnixSeconds.ToString(CultureInfo.InvariantCulture));
    [JsonIgnore] public string RequestHash => EnrollmentProtocol.Digest([.. Encoding.UTF8.GetBytes(Transcript()), .. Convert.FromBase64String(SignatureBase64)]);
    public static RevocationRequest Parse(JsonElement value)
    {
        EnrollmentProtocol.Fields(value, "version", "revocationId", "relayOrigin", "controllerDeviceId", "peerDeviceId",
            "pairingId", "grantId", "fileGrantId", "rdpGrantId", "requestedAtUnixSeconds", "signatureBase64");
        RevocationProtocol.Version(value);
        return new(2, EnrollmentProtocol.Id(value, "revocationId"), EnrollmentProtocol.Text(value, "relayOrigin"),
            EnrollmentProtocol.Hash(value, "controllerDeviceId"), EnrollmentProtocol.Hash(value, "peerDeviceId"),
            EnrollmentProtocol.Id(value, "pairingId"), EnrollmentProtocol.Id(value, "grantId"),
            EnrollmentProtocol.Id(value, "fileGrantId"), EnrollmentProtocol.Id(value, "rdpGrantId"),
            EnrollmentConfirmation.Seconds(value, "requestedAtUnixSeconds"), EnrollmentProtocol.Base64(value, "signatureBase64", 64, 64));
    }
}
public sealed record RevocationReceipt(int Version, string RevocationId, string RequestHash, string ControllerDeviceId,
    string PeerDeviceId, long RevokedAtUnixSeconds, string SignatureBase64)
{
    public string Transcript() => string.Join('\n', "JTS-PAIR-REVOKED-2", RevocationId, RequestHash,
        ControllerDeviceId, PeerDeviceId, RevokedAtUnixSeconds.ToString(CultureInfo.InvariantCulture));
    public static RevocationReceipt Parse(JsonElement value)
    {
        EnrollmentProtocol.Fields(value, "version", "revocationId", "requestHash", "controllerDeviceId", "peerDeviceId",
            "revokedAtUnixSeconds", "signatureBase64");
        RevocationProtocol.Version(value);
        return new(2, EnrollmentProtocol.Id(value, "revocationId"), EnrollmentProtocol.Hash(value, "requestHash"),
            EnrollmentProtocol.Hash(value, "controllerDeviceId"), EnrollmentProtocol.Hash(value, "peerDeviceId"),
            EnrollmentConfirmation.Seconds(value, "revokedAtUnixSeconds"), EnrollmentProtocol.Base64(value, "signatureBase64", 64, 64));
    }
}
public sealed record RevocationView(string RevocationId, string RequestHash, string State, RevocationRequest Revocation,
    string ControllerSPKIBase64, [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] RevocationReceipt? Receipt = null);
public static class RevocationProtocol
{
    internal static void Version(JsonElement value)
    {
        var version = value.GetProperty("version");
        if (version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out var number) || number != 2)
            throw new RelayFailure("invalid_revocation_request");
    }
}
