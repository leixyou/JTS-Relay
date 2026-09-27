using System.Security.Cryptography;

namespace JTS.Relay.Server.Security;

public static class PublicDeviceIdentity
{
    public static AdmittedDevice Parse(string id, string encoded, string role, IEnumerable<string> peers)
    {
        try
        {
            if (role is not ("controller" or "companion") || encoded.Length != 124) throw new FormatException();
            var bytes = Convert.FromBase64String(encoded);
            using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(bytes, out var read);
            if (read != bytes.Length || bytes.Length != 91 || Convert.ToBase64String(bytes) != encoded ||
                !key.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(bytes) ||
                key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7" ||
                id != Convert.ToHexStringLower(SHA256.HashData(bytes))) throw new FormatException();
            return new(id, bytes, role, new(peers, StringComparer.Ordinal));
        }
        catch (Exception e) when (e is FormatException or CryptographicException or ArgumentException)
        { throw new InvalidOperationException("invalid_device_registry"); }
    }
}
