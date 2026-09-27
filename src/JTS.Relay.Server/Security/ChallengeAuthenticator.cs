using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Protocol;

namespace JTS.Relay.Server.Security;

public sealed class ChallengeAuthenticator(RelayOptions options, DeviceRegistry registry, TimeProvider clock)
{
    private readonly object gate = new();
    private readonly byte[] challengeKey = RandomNumberGenerator.GetBytes(32);
    private readonly string origin = RelayOrigin.Canonicalize(options.PublicOrigin, options.AllowLoopbackHttp);
    private readonly Dictionary<string, long> used = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (long Minute, int Count)> rates = new(StringComparer.Ordinal);
    private readonly SourceRateLimiter issuance = new(clock, options.MaxRequestsPerMinute);
    private readonly SourceRateLimiter attempts = new(clock, options.MaxRequestsPerMinute * 2);
    private static readonly HashSet<string> Operations = ["presence", "devices", "sessions", "poll", "enrollment", "revocations"];

    public ChallengeResponse Issue(ChallengeRequest request, string source = "local")
    {
        issuance.Check(source);
        if (!registry.TryGet(request.DeviceId, out _) || !Operations.Contains(request.Operation ?? "")) throw Failed();
        var expiry = clock.GetUtcNow().ToUnixTimeSeconds() + 60;
        // Opaque UUID: expiry plus 88 random bits; the nonce authenticates all fields.
        // Anonymous issuance allocates no pending challenge or per-device state.
        var random = Guid.NewGuid().ToString("D");
        var id = ((uint)expiry).ToString("x8", CultureInfo.InvariantCulture) + random[8..];
        return new(id, Nonce(request.DeviceId, request.Operation!, id), expiry);
    }

    public (AdmittedDevice Device, JsonDocument Payload) Authenticate(string operation, AuthEnvelope envelope, string source = "local")
    {
        attempts.Check(source);
        if (!Operations.Contains(operation) || !Guid.TryParseExact(envelope.ChallengeId, "D", out var parsed) ||
            parsed.ToString("D") != envelope.ChallengeId ||
            !uint.TryParse(envelope.ChallengeId.AsSpan(0, 8), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var expiry) ||
            expiry <= clock.GetUtcNow().ToUnixTimeSeconds() || expiry > clock.GetUtcNow().ToUnixTimeSeconds() + 60 ||
            !registry.TryGet(envelope.DeviceId, out var device)) throw Failed();
        try
        {
            if (envelope.PayloadBase64 is null || envelope.PayloadBase64.Length > 21848 ||
                envelope.SignatureBase64 is null || envelope.SignatureBase64.Length > 88) throw new FormatException();
            var payload = Convert.FromBase64String(envelope.PayloadBase64);
            var signature = Convert.FromBase64String(envelope.SignatureBase64);
            if (payload.Length > 16384 || signature.Length != 64) throw new FormatException();
            var input = string.Join('\n', "JTS-RELAY-AUTH-V2", origin, device.Id, operation,
                envelope.ChallengeId, Nonce(device.Id, operation, envelope.ChallengeId), Convert.ToHexStringLower(SHA256.HashData(payload)));
            using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(device.Spki, out _);
            if (!key.VerifyData(Encoding.UTF8.GetBytes(input), signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new FormatException();
            var document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 8 });
            try
            {
                if (document.RootElement.ValueKind != JsonValueKind.Object) throw new FormatException();
                lock (gate)
                {
                    CleanupLocked();
                    if (used.ContainsKey(envelope.ChallengeId)) throw Failed();
                    if (used.Count >= options.MaxChallenges) throw new RelayFailure("capacity_exhausted", 429);
                    if (!registry.TryGet(device.Id, out var current) || !current.Spki.AsSpan().SequenceEqual(device.Spki)) throw Failed();
                    CheckRate(device.Id);
                    used.Add(envelope.ChallengeId, expiry);
                    return (current, document);
                }
            }
            catch { document.Dispose(); throw; }
        }
        catch (Exception e) when (e is FormatException or CryptographicException or JsonException) { throw Failed(); }
    }
    private string Nonce(string device, string operation, string id) => Convert.ToBase64String(
        HMACSHA256.HashData(challengeKey, Encoding.UTF8.GetBytes(string.Join('\n', "JTS-RELAY-CHALLENGE-2", origin, device, operation, id))));
    public void Cleanup() { lock (gate) CleanupLocked(); }
    private void CleanupLocked()
    {
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        foreach (var pair in used.Where(c => c.Value <= now).ToArray()) used.Remove(pair.Key);
        foreach (var pair in rates.Where(r => r.Value.Minute < now / 60).ToArray()) rates.Remove(pair.Key);
    }
    private void CheckRate(string device)
    {
        var minute = clock.GetUtcNow().ToUnixTimeSeconds() / 60;
        var count = rates.TryGetValue(device, out var previous) && previous.Minute == minute ? previous.Count : 0;
        if (count >= options.MaxRequestsPerMinute) throw new RelayFailure("rate_limited", 429);
        rates[device] = (minute, count + 1);
    }
    private static RelayFailure Failed() => new("authentication_failed", 401);
}
