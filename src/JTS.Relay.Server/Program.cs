using JTS.Relay.Server.Hosting;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Storage;
using System.Text.Json;
using System.Reflection;

try
{
    if (args.Contains("--version", StringComparer.Ordinal))
    {
        var version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
        Console.WriteLine("JTS Relay " + version);
    }
    else if (args.Contains("--help", StringComparer.Ordinal))
    {
        Console.WriteLine("JTS Relay - authenticated opaque control/file/RDP relay");
        Console.WriteLine("Usage: JTS.Relay.Server --config /absolute/relay.json");
        Console.WriteLine("       JTS.Relay.Server --status --config /absolute/relay.json");
        Console.WriteLine("       JTS.Relay.Server --version | --help");
        Console.WriteLine("JTS_RELAY_CONFIG may supply the absolute configuration path.");
        Console.WriteLine("--status reads only local budget counters; no listener is started.");
    }
    else if (args.Contains("--status", StringComparer.Ordinal))
    {
        var configuration = new ConfigurationBuilder();
        ExternalConfiguration.AddTo(configuration, args, required: true);
        var options = ExternalConfiguration.ReadOptions(configuration.Build());
        var status = BudgetStatusReader.Read(options, TimeProvider.System);
        Console.WriteLine(JsonSerializer.Serialize(status, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    }
    else
    {
        var app = RelayApplication.Build(args);
        await app.RunAsync();
    }
}
catch (Exception)
{
    // Configuration errors can contain paths or supplied values. Never dump them.
    Console.Error.WriteLine(args.Contains("--status", StringComparer.Ordinal) ? "relay_status_failed" : "relay_startup_failed");
    Environment.ExitCode = 1;
}
