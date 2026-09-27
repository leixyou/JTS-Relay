using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using JTS.Relay.Server.Configuration;
using JTS.Relay.Server.Storage;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class StatusCommandTests
{
    [Theory]
    [InlineData("--version", "JTS Relay 1.0.0-alpha.1")]
    [InlineData("--help", "--status")]
    public async Task InformationalCommandsNeedNoConfiguration(string argument, string expected)
    {
        var start = StartInfo();
        start.Environment["JTS_RELAY_CONFIG"] = "/nonexistent-jts-relay-config-for-command-test.json";
        start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var output = await process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errors = await process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
            Assert.Equal(0, process.ExitCode);
            Assert.Empty(errors);
            Assert.Contains(expected, output, StringComparison.Ordinal);
            Assert.DoesNotContain("nonexistent-jts-relay", output, StringComparison.Ordinal);
        }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
    }

    [Fact]
    public async Task LocalStatusCommandReturnsOnlyBudgetFieldsAndExits()
    {
        var directory = Directory.CreateTempSubdirectory("jts-relay-status-command-").FullName;
        try
        {
            using var identity = new TestIdentity();
            var options = new RelayOptions
            {
                DatabasePath = Path.Combine(directory, "relay.sqlite"),
                MonthlyOutboundBytes = 100, ControlReserveBytes = 10,
                Devices = [identity.Options("controller")]
            };
            using (var store = new RelayStore(options, TimeProvider.System, _ => { }))
            {
                store.Touch(identity.Id);
                Assert.True(store.TryReserveOutbound(80, "control"));
            }
            var configPath = Path.Combine(directory, "relay.json");
            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new { Relay = options }));
            var start = StartInfo();
            start.ArgumentList.Add("--status");
            start.ArgumentList.Add("--config");
            start.ArgumentList.Add(configPath);
            using var process = Process.Start(start)!;
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var output = await process.StandardOutput.ReadToEndAsync(timeout.Token);
                var errors = await process.StandardError.ReadToEndAsync(timeout.Token);
                await process.WaitForExitAsync(timeout.Token);
                Assert.Equal(0, process.ExitCode);
                Assert.Empty(errors);
                Assert.DoesNotContain(identity.Id, output, StringComparison.Ordinal);
                Assert.DoesNotContain(options.DatabasePath, output, StringComparison.Ordinal);
                using var json = JsonDocument.Parse(output);
                Assert.Equal(7, json.RootElement.EnumerateObject().Count());
                Assert.Equal(80, json.RootElement.GetProperty("outboundBytes").GetInt64());
                Assert.Equal("warning_80", json.RootElement.GetProperty("threshold").GetString());
            }
            finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        }
        finally { Directory.Delete(directory, true); }
    }

    private static ProcessStartInfo StartInfo()
    {
        var dotnet = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? Path.GetFullPath(
            Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "../../..", OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet"));
        var start = new ProcessStartInfo(dotnet) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        start.ArgumentList.Add(typeof(RelayStore).Assembly.Location);
        return start;
    }
}
