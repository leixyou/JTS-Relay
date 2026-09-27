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
        Console.WriteLine("       JTS.Relay.Server --admit-controller-spki /absolute/controller.spki --config /absolute/relay.json");
        Console.WriteLine("       JTS.Relay.Server --version | --help");
        Console.WriteLine("JTS_RELAY_CONFIG may supply the absolute configuration path.");
        Console.WriteLine("--status reads only local budget counters; no listener is started.");
        Console.WriteLine("--admit-controller-spki admits one canonical public P-256 key to this node's durable registry; no restart is needed.");
    }
    else if (args.Contains("--admit-controller-spki", StringComparer.Ordinal))
    {
        var index = Array.IndexOf(args, "--admit-controller-spki");
        if (index + 1 >= args.Length || !Path.IsPathFullyQualified(args[index + 1])) throw new InvalidOperationException();
        var path = args[index + 1];
        if (new FileInfo(path).Length is < 1 or > 1024) throw new InvalidOperationException();
        var bytes = File.ReadAllBytes(path);
        var encoded = bytes.Length == 91 ? Convert.ToBase64String(bytes) : System.Text.Encoding.UTF8.GetString(bytes).Trim();
        var configuration = new ConfigurationBuilder();
        ExternalConfiguration.AddTo(configuration, args, required: true);
        using var store = new AdmissionStore(ExternalConfiguration.ReadOptions(configuration.Build()), TimeProvider.System);
        store.AddController(encoded);
        Console.WriteLine("{\"state\":\"controllerAdmitted\"}");
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
    Console.Error.WriteLine(args.Contains("--status", StringComparer.Ordinal) ? "relay_status_failed" :
        args.Contains("--admit-controller-spki", StringComparer.Ordinal) ? "relay_admission_failed" : "relay_startup_failed");
    Environment.ExitCode = 1;
}
