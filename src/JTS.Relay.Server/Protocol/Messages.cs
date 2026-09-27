namespace JTS.Relay.Server.Protocol;

public sealed record ChallengeRequest(string DeviceId, string Operation);
public sealed record ChallengeResponse(string ChallengeId, string NonceBase64, long ExpiresAtUnixSeconds);
public sealed record AuthEnvelope(string DeviceId, string ChallengeId, string PayloadBase64, string SignatureBase64);
public sealed record SessionRequest(string PeerDeviceId, string Lane);
public sealed record SessionOffer(string SessionId, string Lane, string ControllerDeviceId,
    string Ticket, long ExpiresAtUnixSeconds, string ChannelPath = "/v1/channel");
public sealed record SessionResponse(string SessionId, string Ticket, long ExpiresAtUnixSeconds,
    string ChannelPath = "/v1/channel");
public sealed record DevicePresence(string DeviceId, long? LastSeenAtUnixSeconds);

public sealed class RelayFailure(string code, int status = 400) : Exception(code)
{
    public string Code { get; } = code;
    public int Status { get; } = status;
}
