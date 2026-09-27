namespace JTS.Relay.Server.Configuration;

public sealed class RelayOptions
{
    public string DatabasePath { get; set; } = "";
    public bool AllowLoopbackHttp { get; set; }
    public int MaxDevices { get; set; } = 64;
    public int MaxCompanionDevices { get; set; } = 10;
    public int MaxChallenges { get; set; } = 1024;
    public int MaxChallengesPerDevice { get; set; } = 8;
    public int MaxSessions { get; set; } = 64;
    public int MaxSessionsPerDevice { get; set; } = 8;
    public int MaxRdpSessions { get; set; } = 3;
    public int MaxRequestsPerMinute { get; set; } = 120;
    public long BulkBytesPerSecond { get; set; } = 2_621_440;
    public long ControlBytesPerSecond { get; set; } = 262_144;
    public long SessionBytesPerSecond { get; set; } = 1_048_576;
    public long MonthlyOutboundBytes { get; set; } = 107_374_182_400;
    public long ControlReserveBytes { get; set; } = 104_857_600;
    public int MaxSessionSeconds { get; set; } = 86_400;
    public int IdleTimeoutSeconds { get; set; } = 120;
    public int SecurityRetentionDays { get; set; } = 7;
    public int UsageRetentionDays { get; set; } = 30;
    public List<DeviceOptions> Devices { get; set; } = [];

    public void Validate()
    {
        if (!Path.IsPathFullyQualified(DatabasePath) || Devices.Count == 0 ||
            MaxDevices is < 2 or > 10000 || MaxCompanionDevices < 1 ||
            MaxCompanionDevices > MaxDevices || Devices.Count > MaxDevices ||
            Devices.Count(d => d.Role == "companion") > MaxCompanionDevices ||
            MaxChallenges is < 1 or > 100000 || MaxChallengesPerDevice is < 1 or > 1000 ||
            MaxSessions is < 2 or > 10000 || MaxSessionsPerDevice is < 2 or > 32 ||
            MaxRdpSessions < 1 || MaxRdpSessions > MaxSessions ||
            MaxRequestsPerMinute is < 1 or > 10000 ||
            BulkBytesPerSecond is < 16384 or > 1_073_741_824 ||
            ControlBytesPerSecond is < 16384 or > 1_073_741_824 ||
            SessionBytesPerSecond is < 16384 or > 1_073_741_824 ||
            MonthlyOutboundBytes < 1 || ControlReserveBytes < 0 ||
            ControlReserveBytes >= MonthlyOutboundBytes ||
            MaxSessionSeconds is < 1 or > 86400 || IdleTimeoutSeconds is < 1 or > 3600 ||
            SecurityRetentionDays is < 1 or > 365 || UsageRetentionDays is < 1 or > 365)
            throw new InvalidOperationException("invalid_relay_configuration");
    }
}

public sealed class DeviceOptions
{
    public string DeviceId { get; set; } = "";
    public string PublicKeySpkiBase64 { get; set; } = "";
    public string Role { get; set; } = "";
    public List<string> Peers { get; set; } = [];
}
