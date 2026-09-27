using System.Security.Cryptography;
using JTS.Relay.Server.Configuration;

namespace JTS.Relay.Server.Security;

public sealed record AdmittedDevice(string Id, byte[] Spki, string Role, HashSet<string> Peers);

public sealed class DeviceRegistry
{
    private readonly Dictionary<string, AdmittedDevice> devices = new(StringComparer.Ordinal);
    public DeviceRegistry(RelayOptions options)
    {
        try
        {
            foreach (var item in options.Devices)
            {
                if (item.Role is not ("controller" or "companion") || item.Peers.Count > Math.Min(128, options.MaxDevices))
                    throw new InvalidOperationException();
                var bytes = Convert.FromBase64String(item.PublicKeySpkiBase64);
                using var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(bytes, out var read);
                var parameters = key.ExportParameters(false);
                if (read != bytes.Length || parameters.Curve.Oid.Value != "1.2.840.10045.3.1.7" ||
                    item.DeviceId != Convert.ToHexStringLower(SHA256.HashData(bytes)))
                    throw new InvalidOperationException();
                devices.Add(item.DeviceId, new(item.DeviceId, bytes, item.Role,
                    new(item.Peers, StringComparer.Ordinal)));
            }
            foreach (var device in devices.Values)
            foreach (var peerId in device.Peers)
                if (!devices.TryGetValue(peerId, out var peer) || peer.Role == device.Role ||
                    !peer.Peers.Contains(device.Id)) throw new InvalidOperationException();
        }
        catch (Exception e) when (e is ArgumentException or CryptographicException or FormatException or InvalidOperationException)
        {
            throw new InvalidOperationException("invalid_device_registry");
        }
    }

    public bool TryGet(string? id, out AdmittedDevice device) => devices.TryGetValue(id ?? "", out device!);
    public AdmittedDevice Get(string id) => devices[id];
}
