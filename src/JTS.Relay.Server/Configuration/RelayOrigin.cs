using System.Net;

namespace JTS.Relay.Server.Configuration;

public static class RelayOrigin
{
    public static string Canonicalize(string value, bool allowLoopbackHttp = false)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.UserInfo.Length != 0 ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.AbsolutePath != "/" ||
            uri.Port is < 1 or > 65535 || uri.Host.Length == 0 ||
            uri.Scheme != "https" && !(allowLoopbackHttp && uri.Scheme == "http" &&
                IPAddress.TryParse(uri.Host.Trim('[', ']'), out var address) && IPAddress.IsLoopback(address)))
            throw new InvalidOperationException("invalid_relay_origin");
        return uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
    }
}
