using System.Text.Json;
using JTS.Relay.Server.Enrollment;
using JTS.Relay.Server.Protocol;
using JTS.Relay.Server.Security;

namespace JTS.Relay.Server.Hosting;

public static class EnrollmentEndpoints
{
    public static void MapEnrollment(this WebApplication app)
    {
        foreach (var action in new[] { "offer", "claim", "receipt" })
            app.MapPost("/v1/enrollment/" + action, async (HttpContext context, EnrollmentService service, EnrollmentRateLimiter limiter) =>
            {
                context.Response.Headers.CacheControl = "no-store";
                limiter.Check(context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
                if (context.Request.QueryString.HasValue) throw new RelayFailure("invalid_enrollment_request");
                if (!context.Request.HasJsonContentType()) throw new RelayFailure("json_required", 415);
                using var document = await JsonDocument.ParseAsync(context.Request.Body,
                    new JsonDocumentOptions { MaxDepth = 3 }, context.RequestAborted);
                return Results.Json(service.Public(document.RootElement, action == "claim"));
            });
    }
}
