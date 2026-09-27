using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using JTS.Relay.Server.Enrollment;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class RevocationHttpTests
{
    [Fact]
    public async Task SignedMailboxWireOmitsAbsentReceiptAndOnlyPeerCanComplete()
    {
        await using var f = new RelayFixture(); await f.StartAsync();
        var request = new RevocationRequest(2, Guid.NewGuid().ToString("D"), f.Origin, f.Controller.Id, f.Companion.Id,
            Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"), DateTimeOffset.UtcNow.ToUnixTimeSeconds(), "");
        request = request with { SignatureBase64 = f.Controller.SignText(request.Transcript()) };
        using var submitted = await f.AuthorizedAsync(f.Controller, "revocations", new { action = "submit", revocation = request });
        submitted.EnsureSuccessStatusCode();
        using var pending = JsonDocument.Parse(await submitted.Content.ReadAsStringAsync());
        Assert.False(pending.RootElement.TryGetProperty("receipt", out _));
        Assert.Equal(5, pending.RootElement.EnumerateObject().Count());
        Assert.Equal(11, pending.RootElement.GetProperty("revocation").EnumerateObject().Count());
        using var polled = await f.AuthorizedAsync(f.Companion, "revocations", new { action = "poll" });
        polled.EnsureSuccessStatusCode();
        using var items = JsonDocument.Parse(await polled.Content.ReadAsStringAsync());
        Assert.Equal(1, items.RootElement.GetProperty("revocations").GetArrayLength());
        var receipt = new RevocationReceipt(2, request.RevocationId, request.RequestHash, f.Controller.Id,
            f.Companion.Id, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), "");
        receipt = receipt with { SignatureBase64 = f.Companion.SignText(receipt.Transcript()) };
        using var denied = await f.AuthorizedAsync(f.Controller, "revocations", new { action = "complete", receipt });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        using var complete = await f.AuthorizedAsync(f.Companion, "revocations", new { action = "complete", receipt });
        complete.EnsureSuccessStatusCode();
        var value = (await complete.Content.ReadFromJsonAsync<RevocationView>())!;
        Assert.Equal("complete", value.State); Assert.Equal(receipt, value.Receipt);
        using var status = await f.AuthorizedAsync(f.Controller, "revocations", new { action = "status", revocationId = request.RevocationId });
        Assert.Equal(value, await status.Content.ReadFromJsonAsync<RevocationView>());
    }
}
