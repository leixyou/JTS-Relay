using System.Security.Cryptography;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Storage;

namespace JTS.Relay.Server.Security;

public sealed record AdmittedDevice(string Id, byte[] Spki, string Role, HashSet<string> Peers);

public sealed class DeviceRegistry
{
    private readonly Dictionary<string, AdmittedDevice> devices = new(StringComparer.Ordinal);
    private readonly AdmissionStore? store;
    public object SyncRoot { get; }
    internal AdmittedDevice[] All => devices.Values.ToArray();
    public DeviceRegistry(RelayOptions options, AdmissionStore? store = null)
    {
        this.store = store; SyncRoot = store?.SyncRoot ?? new object();
        try
        {
            foreach (var item in options.Devices)
            {
                if (item.Role is not ("controller" or "companion") || item.Peers.Count > Math.Min(128, options.MaxDevices))
                    throw new InvalidOperationException();
                devices.Add(item.DeviceId, PublicDeviceIdentity.Parse(item.DeviceId, item.PublicKeySpkiBase64, item.Role, item.Peers));
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

    public bool TryGet(string? id, out AdmittedDevice device)
    {
        lock (SyncRoot) return store is null ? devices.TryGetValue(id ?? "", out device!) : store.TryGet(id ?? "", out device!);
    }
    public AdmittedDevice Get(string id) => TryGet(id, out var device) ? device : throw new KeyNotFoundException();
    public bool AuthorizesPair(string controller, string companion) =>
        TryGet(controller, out var a) && a.Role == "controller" && TryGet(companion, out var b) &&
        b.Role == "companion" && a.Peers.Contains(b.Id) && b.Peers.Contains(a.Id);
}
