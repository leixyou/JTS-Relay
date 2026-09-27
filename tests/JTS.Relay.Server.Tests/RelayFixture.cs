using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text.Json;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Hosting;
using JTS.Relay.Server.Protocol;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace JTS.Relay.Server.Tests;

internal sealed class RelayFixture : IAsyncDisposable
{
    private readonly string directory = Directory.CreateTempSubdirectory("jts-relay-http-test-").FullName;
    private WebApplication? app;
    public TestIdentity Controller { get; } = new();
    public TestIdentity Companion { get; } = new();
    public HttpClient Http { get; private set; } = null!;
    public async Task StartAsync(Action<RelayOptions>? configure = null)
    {
        var options = new RelayOptions
        {
            DatabasePath = Path.Combine(directory, "relay.sqlite"), AllowLoopbackHttp = true,
            Devices = [Controller.Options("controller", Companion.Id), Companion.Options("companion", Controller.Id)]
        };
        configure?.Invoke(options);
        app = RelayApplication.Build([], builder =>
        {
            builder.Configuration.AddJsonStream(new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(new { Relay = options })));
            builder.WebHost.UseSetting("urls", "http://127.0.0.1:0");
        });
        await app.StartAsync();
        Http = new() { BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(10) };
    }
    public async Task<HttpResponseMessage> AuthorizedAsync(TestIdentity device, string operation, object payload)
    {
        var challengeResponse = await Http.PostAsJsonAsync("/v1/challenges", new ChallengeRequest(device.Id, operation));
        challengeResponse.EnsureSuccessStatusCode();
        var challenge = (await challengeResponse.Content.ReadFromJsonAsync<ChallengeResponse>())!;
        return await Http.PostAsJsonAsync("/v1/" + operation, device.Sign(operation, challenge, payload));
    }
    public async Task<(SessionResponse Created, SessionOffer Offer)> SessionAsync(string lane)
    {
        using var createdResponse = await AuthorizedAsync(Controller, "sessions", new SessionRequest(Companion.Id, lane));
        createdResponse.EnsureSuccessStatusCode();
        var created = (await createdResponse.Content.ReadFromJsonAsync<SessionResponse>())!;
        using var poll = await AuthorizedAsync(Companion, "poll", new { });
        poll.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await poll.Content.ReadAsStringAsync());
        var offer = json.RootElement.GetProperty("offers")[0].Deserialize<SessionOffer>(new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        return (created, offer);
    }
    public async Task<ClientWebSocket> SocketAsync(string ticket)
    {
        var socket = new ClientWebSocket();
        socket.Options.SetRequestHeader("Authorization", "Bearer " + ticket);
        var uri = new UriBuilder(Http.BaseAddress!) { Scheme = "ws", Path = "/v1/channel" }.Uri;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await socket.ConnectAsync(uri, timeout.Token);
            return socket;
        }
        catch { socket.Dispose(); throw; }
    }
    public async ValueTask DisposeAsync()
    {
        Http?.Dispose();
        if (app is not null) { await app.StopAsync(); await app.DisposeAsync(); }
        Controller.Dispose();
        Companion.Dispose();
        Directory.Delete(directory, true);
    }
}
