using System.Net;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.Relay.Server.Protocol;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class WebSocketTests
{
    [Theory]
    [InlineData("control")]
    [InlineData("file")]
    [InlineData("rdp")]
    public async Task RealKestrelForwardsBinaryBothWaysAndRejectsTicketReplay(string lane)
    {
        await using var fixture = new RelayFixture();
        await fixture.StartAsync();
        var (session, offer) = await fixture.SessionAsync(lane);
        using var controller = await fixture.SocketAsync(session.Ticket);
        using var companion = await fixture.SocketAsync(offer.Ticket);
        await Ready(controller, session.SessionId, lane);
        await Ready(companion, session.SessionId, lane);
        await Assert.ThrowsAsync<WebSocketException>(() => fixture.SocketAsync(session.Ticket));
        var bytes = RandomNumberGenerator.GetBytes(65536);
        await RoundTrip(controller, companion, bytes);
        await RoundTrip(companion, controller, bytes);
    }

    [Fact]
    public async Task TextPayloadClosesBothEnds()
    {
        await using var fixture = new RelayFixture();
        await fixture.StartAsync();
        var (session, offer) = await fixture.SessionAsync("control");
        using var controller = await fixture.SocketAsync(session.Ticket);
        using var companion = await fixture.SocketAsync(offer.Ticket);
        await Ready(controller, session.SessionId, "control");
        await Ready(companion, session.SessionId, "control");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await controller.SendAsync("no plaintext"u8.ToArray(), WebSocketMessageType.Text, true, deadline.Token);
        await Assert.ThrowsAsync<WebSocketException>(async () => await companion.ReceiveAsync(new byte[1024], deadline.Token));
    }

    [Fact]
    public async Task EmptyFrameFloodClosesWithoutProgress()
    {
        await using var fixture = new RelayFixture();
        await fixture.StartAsync();
        var (session, offer) = await fixture.SessionAsync("control");
        using var controller = await fixture.SocketAsync(session.Ticket);
        using var companion = await fixture.SocketAsync(offer.Ticket);
        await Ready(controller, session.SessionId, "control");
        await Ready(companion, session.SessionId, "control");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        for (var count = 0; count < 8; count++)
            await controller.SendAsync(Array.Empty<byte>(), WebSocketMessageType.Binary, true, deadline.Token);
        await Assert.ThrowsAsync<WebSocketException>(async () => await companion.ReceiveAsync(new byte[1024], deadline.Token));
    }

    [Fact]
    public async Task PlainHttpIsDeniedUnlessExplicitLoopbackDevelopment()
    {
        await using var fixture = new RelayFixture();
        await fixture.StartAsync(options => options.AllowLoopbackHttp = false);
        using var response = await fixture.Http.GetAsync("/healthz");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("https_required", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"deviceId\":\"x\",\"deviceId\":\"x\",\"operation\":\"presence\"}")]
    [InlineData("{\"deviceId\":\"x\",\"operation\":\"presence\",\"extra\":true}")]
    [InlineData("{\"deviceId\":null,\"operation\":\"presence\"}")]
    public async Task RequestParsingRejectsAmbiguousOrUnknownFields(string json)
    {
        await using var fixture = new RelayFixture();
        await fixture.StartAsync();
        using var response = await fixture.Http.PostAsync("/v1/challenges", new StringContent(json, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task BulkQuotaClosesStreamWithoutLeakingBytesAndControlStillWorks()
    {
        await using var fixture = new RelayFixture();
        await fixture.StartAsync(options => { options.MonthlyOutboundBytes = 1024; options.ControlReserveBytes = 512; });
        var (session, offer) = await fixture.SessionAsync("file");
        using (var controller = await fixture.SocketAsync(session.Ticket))
        using (var companion = await fixture.SocketAsync(offer.Ticket))
        {
            await Ready(controller, session.SessionId, "file");
            await Ready(companion, session.SessionId, "file");
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await controller.SendAsync(new byte[513], WebSocketMessageType.Binary, true, deadline.Token);
            await Assert.ThrowsAsync<WebSocketException>(async () => await companion.ReceiveAsync(new byte[1024], deadline.Token));
        }
        var control = await fixture.SessionAsync("control");
        using var mac = await fixture.SocketAsync(control.Created.Ticket);
        using var windows = await fixture.SocketAsync(control.Offer.Ticket);
        await Ready(mac, control.Created.SessionId, "control");
        await Ready(windows, control.Created.SessionId, "control");
        await RoundTrip(mac, windows, new byte[800]);
    }

    [Fact]
    public async Task HttpAuthIsRequiredAndPresenceIsPeerScoped()
    {
        await using var fixture = new RelayFixture();
        await fixture.StartAsync();
        using var unknown = await fixture.Http.PostAsJsonAsync("/v1/challenges", new ChallengeRequest(new('f', 64), "presence"));
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        using var touched = await fixture.AuthorizedAsync(fixture.Companion, "presence", new { });
        Assert.True(touched.IsSuccessStatusCode);
        using var devices = await fixture.AuthorizedAsync(fixture.Controller, "devices", new { });
        using var list = JsonDocument.Parse(await devices.Content.ReadAsStringAsync());
        var device = Assert.Single(list.RootElement.GetProperty("devices").EnumerateArray());
        Assert.Equal(fixture.Companion.Id, device.GetProperty("deviceId").GetString());
        Assert.Equal(JsonValueKind.Number, device.GetProperty("lastSeenAtUnixSeconds").ValueKind);
        using var invalidPayload = await fixture.AuthorizedAsync(fixture.Controller, "presence", new { arbitrary = "field" });
        Assert.Equal(HttpStatusCode.BadRequest, invalidPayload.StatusCode);
    }
    private static async Task Ready(ClientWebSocket socket, string id, string lane)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var buffer = new byte[1024];
        var received = await socket.ReceiveAsync(buffer, deadline.Token);
        Assert.Equal(WebSocketMessageType.Text, received.MessageType);
        using var json = JsonDocument.Parse(buffer.AsMemory(0, received.Count));
        Assert.True(json.RootElement.GetProperty("ready").GetBoolean());
        Assert.Equal(id, json.RootElement.GetProperty("sessionId").GetString());
        Assert.Equal(lane, json.RootElement.GetProperty("lane").GetString());
    }
    private static async Task RoundTrip(ClientWebSocket source, ClientWebSocket target, byte[] payload)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var sending = source.SendAsync(payload, WebSocketMessageType.Binary, true, deadline.Token);
        var output = new byte[payload.Length];
        var offset = 0;
        while (offset < output.Length)
        {
            var part = await target.ReceiveAsync(output.AsMemory(offset), deadline.Token);
            Assert.Equal(WebSocketMessageType.Binary, part.MessageType);
            offset += part.Count;
        }
        await sending;
        Assert.Equal(payload, output);
    }
}
