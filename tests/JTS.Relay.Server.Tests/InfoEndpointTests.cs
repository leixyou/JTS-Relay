using System.Text.Json;
using Xunit;

namespace JTS.Relay.Server.Tests;

public sealed class InfoEndpointTests
{
    [Fact]
    public async Task PublicInfoAdvertisesOnlySupportedVersionAndLanes()
    {
        await using var fixture = new RelayFixture();
        await fixture.StartAsync();
        using var response = await fixture.Http.GetAsync("/v1/info");
        response.EnsureSuccessStatusCode();
        using var info = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(["lanes", "protocolVersion"], info.RootElement.EnumerateObject().Select(p => p.Name).Order());
        Assert.Equal(1, info.RootElement.GetProperty("protocolVersion").GetInt32());
        Assert.Equal(["control", "file", "rdp"], info.RootElement.GetProperty("lanes").EnumerateArray().Select(l => l.GetString()));
    }
}
