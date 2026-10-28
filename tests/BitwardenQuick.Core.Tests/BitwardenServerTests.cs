using BitwardenQuick.Core.Api;

namespace BitwardenQuick.Core.Tests;

public sealed class BitwardenServerTests
{
    [Theory]
    [InlineData("bitwarden.com")]
    [InlineData("vault.bitwarden.com")]
    [InlineData(" https://vault.bitwarden.com/ ")]
    [InlineData("BITWARDEN.COM")]
    public void Recognizes_the_US_cloud(string value) =>
        Assert.Same(BitwardenServer.UnitedStates, BitwardenServer.Parse(value));

    [Theory]
    [InlineData("bitwarden.eu")]
    [InlineData("vault.bitwarden.eu")]
    [InlineData("https://vault.bitwarden.eu")]
    public void Recognizes_the_EU_cloud(string value) =>
        Assert.Same(BitwardenServer.Europe, BitwardenServer.Parse(value));

    [Fact]
    public void The_EU_cloud_has_its_own_addresses()
    {
        var eu = BitwardenServer.Europe;
        Assert.Equal("https://identity.bitwarden.eu/", eu.Identity.AbsoluteUri);
        Assert.Equal("https://api.bitwarden.eu/", eu.Api.AbsoluteUri);
        Assert.Equal("https://icons.bitwarden.eu/", eu.Icons.AbsoluteUri);
        Assert.Equal("https://vault.bitwarden.eu/", eu.WebVault.AbsoluteUri);
        Assert.True(eu.IsCloud);
        Assert.Equal("bitwarden.eu", new BitwardenApi(eu).Name);
        Assert.Equal("https://identity.bitwarden.eu/", new BitwardenApi(eu).Server);
    }

    [Fact]
    public void A_self_hosted_server_serves_everything_under_its_base_url()
    {
        var server = BitwardenServer.Parse("https://vault.example.com/bitwarden/");
        Assert.Equal("https://vault.example.com/bitwarden/identity/", server.Identity.AbsoluteUri);
        Assert.Equal("https://vault.example.com/bitwarden/api/", server.Api.AbsoluteUri);
        Assert.Equal("https://vault.example.com/bitwarden/icons/", server.Icons.AbsoluteUri);
        Assert.Equal("https://vault.example.com/bitwarden/", server.WebVault.AbsoluteUri);
        Assert.Equal("vault.example.com", server.Name);
        Assert.False(server.IsCloud);
    }

    [Theory]
    [InlineData("http://vault.bitwarden.eu")]
    [InlineData("http://vault.example.com")]
    [InlineData("vault.example.com")]
    [InlineData("not a server")]
    public void Rejects_anything_else(string value) =>
        Assert.Throws<ArgumentException>(() => BitwardenServer.Parse(value));
}
