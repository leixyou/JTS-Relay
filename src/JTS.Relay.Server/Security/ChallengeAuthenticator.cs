using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Protocol;

namespace JTS.Relay.Server.Security;

public sealed class ChallengeAuthenticator(RelayOptions options, DeviceRegistry registry, TimeProvider clock)
{
    private sealed record Challenge(string DeviceId, string Operation, string Nonce, DateTimeOffset Expires);
    private readonly object gate = new();
    private readonly Dictionary<string, Challenge> challenges = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (long Minute, int Count)> rates = new(StringComparer.Ordinal);
    private static readonly HashSet<string> Operations = ["presence", "devices", "sessions", "poll"];

    public ChallengeResponse Issue(ChallengeRequest request)
    {
        lock (gate)
        {
            if (!registry.TryGet(request.DeviceId, out _) || !Operations.Contains(request.Operation ?? ""))
                throw new RelayFailure("authentication_failed", 401);
            CheckRate(request.DeviceId);
            CleanupLocked();
            if (challenges.Count >= options.MaxChallenges ||
                challenges.Values.Count(c => c.DeviceId == request.DeviceId) >= options.MaxChallengesPerDevice)
                throw new RelayFailure("capacity_exhausted", 429);
            var id = Guid.NewGuid().ToString("D");
            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var expiry = clock.GetUtcNow().AddSeconds(60);
            challenges.Add(id, new(request.DeviceId, request.Operation!, nonce, expiry));
            return new(id, nonce, expiry.ToUnixTimeSeconds());
        }
    }

    public (AdmittedDevice Device, JsonDocument Payload) Authenticate(string operation, AuthEnvelope envelope)
    {
        Challenge challenge;
        AdmittedDevice device;
        lock (gate)
        {
            // Even malformed or wrong-identity proofs burn an existing challenge.
            if (!challenges.Remove(envelope.ChallengeId ?? "", out challenge!) ||
                challenge.Expires <= clock.GetUtcNow() || challenge.Operation != operation ||
                challenge.DeviceId != envelope.DeviceId || !registry.TryGet(envelope.DeviceId, out device!))
                throw new RelayFailure("authentication_failed", 401);
            CheckRate(device.Id);
        }
        try
        {
            if (envelope.PayloadBase64 is null || envelope.PayloadBase64.Length > 21848 ||
                envelope.SignatureBase64 is null || envelope.SignatureBase64.Length > 88)
                throw new FormatException();
            var payload = Convert.FromBase64String(envelope.PayloadBase64);
            var signature = Convert.FromBase64String(envelope.SignatureBase64);
            if (payload.Length > 16384 || signature.Length != 64) throw new FormatException();
            var input = string.Join('\n', "JTS-RELAY-AUTH-V1", device.Id, operation,
                envelope.ChallengeId, challenge.Nonce, Convert.ToHexStringLower(SHA256.HashData(payload)));
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(device.Spki, out _);
            if (!key.VerifyData(Encoding.UTF8.GetBytes(input), signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new FormatException();
            var document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 8 });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                document.Dispose();
                throw new FormatException();
            }
            return (device, document);
        }
        catch (Exception e) when (e is FormatException or CryptographicException or JsonException)
        {
            throw new RelayFailure("authentication_failed", 401);
        }
    }

    public void Cleanup() { lock (gate) CleanupLocked(); }
    private void CleanupLocked()
    {
        var now = clock.GetUtcNow();
        foreach (var pair in challenges.Where(c => c.Value.Expires <= now).ToArray()) challenges.Remove(pair.Key);
        var minute = now.ToUnixTimeSeconds() / 60;
        foreach (var pair in rates.Where(r => r.Value.Minute < minute).ToArray()) rates.Remove(pair.Key);
    }
    private void CheckRate(string deviceId)
    {
        var minute = clock.GetUtcNow().ToUnixTimeSeconds() / 60;
        var count = rates.TryGetValue(deviceId, out var previous) && previous.Minute == minute ? previous.Count : 0;
        if (count >= options.MaxRequestsPerMinute) throw new RelayFailure("rate_limited", 429);
        rates[deviceId] = (minute, count + 1);
    }
}
