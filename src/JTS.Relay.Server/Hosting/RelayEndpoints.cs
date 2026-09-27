using System.Net;
using System.Text.Json;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Forwarding;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;
using JTS.Relay.Server.Storage;

namespace JTS.Relay.Server.Hosting;

public static class RelayEndpoints
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { MaxDepth = 8 };

    public static void MapRelay(this WebApplication app, RelayOptions options)
    {
        app.Use(async (context, next) =>
        {
            try
            {
                if (!context.Request.IsHttps && !(options.AllowLoopbackHttp &&
                    context.Connection.RemoteIpAddress is { } ip && IPAddress.IsLoopback(ip)))
                    throw new RelayFailure("https_required", 400);
                await next(context);
            }
            catch (Exception e) when (!context.Response.HasStarted)
            {
                context.Response.StatusCode = e switch
                {
                    RelayFailure failure => failure.Status,
                    BadHttpRequestException bad => bad.StatusCode,
                    JsonException => 400,
                    _ => 500
                };
                await context.Response.WriteAsJsonAsync(new { code = e is RelayFailure relayFailure ? relayFailure.Code :
                    context.Response.StatusCode < 500 ? "invalid_request" : "internal_error" }, context.RequestAborted);
            }
        });
        app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(30) });
        app.MapGet("/healthz", () => Results.Json(new { status = "ok" }));
        app.MapGet("/v1/info", () => Results.Json(new { protocolVersion = 1, lanes = new[] { "control", "file", "rdp" } }));
        app.MapPost("/v1/challenges", async (HttpContext context, ChallengeAuthenticator auth) =>
            Results.Json(auth.Issue(await Read<ChallengeRequest>(context))));
        foreach (var operation in new[] { "presence", "devices", "sessions", "poll" })
            app.MapPost("/v1/" + operation, async (HttpContext context, ChallengeAuthenticator auth,
                SessionCoordinator sessions, RelayStore store) =>
            {
                var (device, document) = auth.Authenticate(operation, await Read<AuthEnvelope>(context));
                using (document)
                {
                    if (operation != "sessions" && document.RootElement.EnumerateObject().Any())
                        throw new RelayFailure("invalid_payload");
                    return operation switch
                    {
                        "presence" => Presence(device, store),
                        "devices" => Results.Json(new { devices = store.Presence(device.Peers) }),
                        "sessions" => Results.Json(sessions.Create(device, ParseSession(document))),
                        "poll" => Results.Json(new { offers = sessions.Poll(device) }),
                        _ => throw new RelayFailure("invalid_operation")
                    };
                }
            });
        app.MapGet("/v1/channel", Channel);
    }
    private static IResult Presence(AdmittedDevice device, RelayStore store)
    {
        store.Touch(device.Id);
        return Results.Json(new { deviceId = device.Id });
    }
    private static SessionRequest ParseSession(JsonDocument payload)
    {
        if (payload.RootElement.EnumerateObject().Count() != 2 ||
            !payload.RootElement.TryGetProperty("peerDeviceId", out var peer) || peer.ValueKind != JsonValueKind.String ||
            !payload.RootElement.TryGetProperty("lane", out var lane) || lane.ValueKind != JsonValueKind.String)
            throw new RelayFailure("invalid_payload");
        return new(peer.GetString()!, lane.GetString()!);
    }
    private static async Task<T> Read<T>(HttpContext context)
    {
        if (!context.Request.HasJsonContentType()) throw new RelayFailure("json_required", 415);
        using var document = await JsonDocument.ParseAsync(context.Request.Body,
            new JsonDocumentOptions { MaxDepth = 8 }, context.RequestAborted);
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new RelayFailure("invalid_request");
        string[] expected = typeof(T) == typeof(ChallengeRequest) ? ["deviceId", "operation"] :
            ["deviceId", "challengeId", "payloadBase64", "signatureBase64"];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
            if (!expected.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name) ||
                property.Value.ValueKind != JsonValueKind.String) throw new RelayFailure("invalid_request");
        if (seen.Count != expected.Length) throw new RelayFailure("invalid_request");
        return document.RootElement.Deserialize<T>(Json) ?? throw new RelayFailure("invalid_request");
    }
    private static async Task Channel(HttpContext context, SessionCoordinator coordinator,
        RelayOptions options, RelayStore store, TimeProvider clock)
    {
        if (!context.WebSockets.IsWebSocketRequest || context.Request.QueryString.HasValue ||
            context.Request.Headers.Authorization.Count != 1)
            throw new RelayFailure("invalid_channel_request");
        var header = context.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.Ordinal) || header.Length != 50)
            throw new RelayFailure("invalid_ticket", 401);
        var claim = coordinator.Claim(header[7..]);
        try
        {
            using var socket = await context.WebSockets.AcceptWebSocketAsync(new WebSocketAcceptContext { DangerousEnableCompression = false });
            using var registration = context.RequestAborted.Register(claim.Session.Stop);
            claim.Session.Attach(claim.Controller, socket, options, store, coordinator.BulkPacer, coordinator.ControlPacer, clock);
            await claim.Session.Completion;
        }
        finally { claim.Session.Stop(); }
    }
}
