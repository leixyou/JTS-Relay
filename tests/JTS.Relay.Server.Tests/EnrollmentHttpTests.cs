using System.Net;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text.Json;
using JTS.Relay.Server.Enrollment;
using JTS.Relay.Server.Protocol;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class EnrollmentHttpTests
{
    [Fact]
    public async Task PublicClaimNeedsSignedControllerConfirmationAndReceiptSurvivesSocketFailure()
    {
        await using var f = new RelayFixture(); using var windows = new TestIdentity(); await f.StartAsync();
        var id = Guid.NewGuid().ToString("D"); var token = RandomNumberGenerator.GetBytes(32);
        var create = new { action = "create", invitationId = id, claimTokenHash = EnrollmentProtocol.Digest(token),
            offerBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(128)), expiresAtUnixSeconds = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds() };
        using var created = await f.AuthorizedAsync(f.Controller, "enrollment", create); created.EnsureSuccessStatusCode();
        Assert.Equal("no-store", created.Headers.CacheControl!.ToString());
        var invitation = (await created.Content.ReadFromJsonAsync<EnrollmentView>())!;
        Assert.Equal("pending", invitation.State);
        Assert.DoesNotContain("\"claim\"", await created.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        var tokenBody = new { invitationId = id, claimTokenBase64 = Convert.ToBase64String(token) };
        using var offered = await f.Http.PostAsJsonAsync("/v1/enrollment/offer", tokenBody); offered.EnsureSuccessStatusCode();
        using var claimResponse = await f.Http.PostAsJsonAsync("/v1/enrollment/claim", EnrollmentFixture.Claim(invitation, tokenBody.claimTokenBase64, windows));
        claimResponse.EnsureSuccessStatusCode(); var claimed = (await claimResponse.Content.ReadFromJsonAsync<EnrollmentView>())!;
        using var before = await f.Http.PostAsJsonAsync("/v1/challenges", new ChallengeRequest(windows.Id, "presence"));
        Assert.Equal(HttpStatusCode.Unauthorized, before.StatusCode);
        using var confirm = await f.AuthorizedAsync(f.Controller, "enrollment", new { action = "confirm", invitationId = id,
            claimHash = claimed.Claim!.ClaimHash, confirmation = f.Controller.Confirm(claimed, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), f.Origin) });
        confirm.EnsureSuccessStatusCode();
        using var admitted = await f.AuthorizedAsync(windows, "presence", new { }); admitted.EnsureSuccessStatusCode();
        // Simulate connection loss after creating a lane. Enrollment is not a connectivity probe.
        using var sessionResponse = await f.AuthorizedAsync(f.Controller, "sessions", new SessionRequest(windows.Id, "rdp"));
        var session = (await sessionResponse.Content.ReadFromJsonAsync<SessionResponse>())!;
        using (var socket = await f.SocketAsync(session.Ticket)) socket.Abort();
        using var receipt = await f.Http.PostAsJsonAsync("/v1/enrollment/receipt", tokenBody); receipt.EnsureSuccessStatusCode();
        Assert.Equal("bound", (await receipt.Content.ReadFromJsonAsync<EnrollmentView>())!.State);
    }

    [Theory]
    [InlineData("control")]
    [InlineData("file")]
    [InlineData("rdp")]
    public async Task RevokeClosesActiveSocketsAndInvalidatesUnclaimedTickets(string lane)
    {
        await using var f = new RelayFixture(); await f.StartAsync();
        var active = await f.SessionAsync(lane);
        using var mac = await f.SocketAsync(active.Created.Ticket); using var windows = await f.SocketAsync(active.Offer.Ticket);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await mac.ReceiveAsync(new byte[1024], deadline.Token); await windows.ReceiveAsync(new byte[1024], deadline.Token);
        var pending = await f.SessionAsync("control");
        using var revoked = await f.AuthorizedAsync(f.Controller, "enrollment", new { action = "revoke", peerDeviceId = f.Companion.Id });
        revoked.EnsureSuccessStatusCode();
        await Assert.ThrowsAsync<WebSocketException>(async () => await windows.ReceiveAsync(new byte[1024], deadline.Token));
        await Assert.ThrowsAsync<WebSocketException>(() => f.SocketAsync(pending.Created.Ticket));
        using var denied = await f.AuthorizedAsync(f.Controller, "sessions", new SessionRequest(f.Companion.Id, lane));
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
    }

    [Fact]
    public async Task EnrollmentUsesExistingSignedAuthenticationAndCompanionCannotIssueInvitations()
    {
        await using var f = new RelayFixture(); await f.StartAsync();
        using var unsigned = await f.Http.PostAsJsonAsync("/v1/enrollment", new { action = "status", invitationId = Guid.NewGuid().ToString("D") });
        Assert.Equal(HttpStatusCode.BadRequest, unsigned.StatusCode);
        using var denied = await f.AuthorizedAsync(f.Companion, "enrollment", new { action = "status", invitationId = Guid.NewGuid().ToString("D") });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        using var challengeResponse = await f.Http.PostAsJsonAsync("/v1/challenges", new ChallengeRequest(f.Controller.Id, "enrollment"));
        var challenge = (await challengeResponse.Content.ReadFromJsonAsync<ChallengeResponse>())!;
        var proof = f.Companion.Sign("enrollment", challenge, new { action = "status", invitationId = Guid.NewGuid().ToString("D") });
        using var wrong = await f.Http.PostAsJsonAsync("/v1/enrollment", proof);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
    }
}
