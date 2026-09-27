namespace JTS.Relay.Server.Configuration;

public static class ExternalConfiguration
{
    public static void AddTo(IConfigurationBuilder builder, string[] args, bool required = false)
    {
        var configIndex = Array.IndexOf(args, "--config");
        var config = configIndex >= 0 && configIndex + 1 < args.Length ? args[configIndex + 1] :
            Environment.GetEnvironmentVariable("JTS_RELAY_CONFIG");
        if (config is null)
        {
            if (required || configIndex >= 0) throw new InvalidOperationException("config_required");
            return;
        }
        if (!Path.IsPathFullyQualified(config)) throw new InvalidOperationException("absolute_config_path_required");
        builder.AddJsonFile(config, optional: false, reloadOnChange: false);
    }

    public static RelayOptions ReadOptions(IConfiguration configuration)
    {
        var options = configuration.GetSection("Relay").Get<RelayOptions>() ?? new();
        options.Validate();
        return options;
    }
}
