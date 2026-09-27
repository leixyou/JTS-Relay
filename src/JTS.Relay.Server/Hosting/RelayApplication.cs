using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Forwarding;
using JTS.Relay.Server.Security;
using JTS.Relay.Server.Storage;
using JTS.Relay.Server.Enrollment;

namespace JTS.Relay.Server.Hosting;

public static class RelayApplication
{
    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        var builder = WebApplication.CreateSlimBuilder(args);
        // SlimBuilder only registers Kestrel core. PEM/HTTPS endpoints loaded from
        // deployment configuration require explicit HTTPS services.
        builder.WebHost.UseKestrelHttpsConfiguration();
        // No request/access logging: bearer values and endpoint traffic must never enter diagnostics.
        builder.Logging.ClearProviders();
        ExternalConfiguration.AddTo(builder.Configuration, args);
        configure?.Invoke(builder);
        var options = ExternalConfiguration.ReadOptions(builder.Configuration);
        _ = new DeviceRegistry(options); // Fail before binding listeners for invalid legacy seed configuration.
        builder.WebHost.ConfigureKestrel(server =>
        {
            server.AddServerHeader = false;
            server.Limits.MaxRequestBodySize = 32768;
            server.Limits.MaxRequestHeadersTotalSize = 8192;
            server.Limits.MaxRequestLineSize = 2048;
            server.Limits.MaxConcurrentConnections = options.MaxSessions * 2L + options.MaxDevices + 32;
            server.Limits.MaxConcurrentUpgradedConnections = options.MaxSessions * 2L;
            server.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
        });
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<AdmissionStore>();
        builder.Services.AddSingleton<DeviceRegistry>();
        builder.Services.AddSingleton<EnrollmentService>();
        builder.Services.AddSingleton<EnrollmentRateLimiter>();
        builder.Services.AddSingleton<ChallengeAuthenticator>();
        builder.Services.AddSingleton<RelayStore>();
        builder.Services.AddSingleton<SessionCoordinator>();
        builder.Services.AddHostedService<ExpiryService>();
        var app = builder.Build();
        app.MapRelay(options);
        // Load/migrate the durable registry before the listener starts.
        _ = app.Services.GetRequiredService<AdmissionStore>();
        return app;
    }
}
