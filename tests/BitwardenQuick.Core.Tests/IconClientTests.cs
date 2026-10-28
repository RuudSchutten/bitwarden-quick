using System.Net;
using System.Net.Http.Headers;
using BitwardenQuick.Core.Api;

namespace BitwardenQuick.Core.Tests;

public sealed class IconClientTests
{
    private sealed class FakeIcons(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);
            return Task.FromResult(respond(request));
        }
    }

    private sealed class UnknownLength(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
    }

    private static HttpResponseMessage Image(byte[] bytes, string type = "image/png")
    {
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new MediaTypeHeaderValue(type);
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
    }

    [Theory]
    [InlineData("https://login.example.com/common/oauth2", "login.example.com")]
    [InlineData("example.org", "example.org")]
    [InlineData("  HTTP://WWW.GitHub.com:8443/path  ", "www.github.com")]
    [InlineData("https://bücher.de", "xn--bcher-kva.de")]
    [InlineData("https://example.com./", "example.com")]
    public void HostFor_returns_the_ascii_host_of_a_website(string uri, string expected) =>
        Assert.Equal(expected, IconClient.HostFor(uri));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("androidapp://com.microsoft.teams")]
    [InlineData("ftp://files.example.com")]
    [InlineData("https://192.168.1.10/admin")]
    [InlineData("https://[::1]/")]
    [InlineData("http://nas:5000")]
    [InlineData("https://localhost")]
    [InlineData("https://printer.local")]
    [InlineData("https://router.home.arpa")]
    [InlineData("https://wiki.corp")]
    [InlineData("not a url at all")]
    public void HostFor_skips_uris_without_a_public_website(string? uri) =>
        Assert.Null(IconClient.HostFor(uri));

    [Fact]
    public async Task Fetches_the_icon_from_the_icon_service()
    {
        var handler = new FakeIcons(_ => Image([1, 2, 3]));
        using var client = new IconClient(handler: handler);

        Assert.Equal([1, 2, 3], await client.GetAsync("login.example.com"));
        Assert.Equal(new Uri("https://icons.bitwarden.net/login.example.com/icon.png"), Assert.Single(handler.Requests));
    }

    [Fact]
    public async Task Uses_a_self_hosted_icon_server()
    {
        var handler = new FakeIcons(_ => Image([1]));
        using var client = new IconClient(new Uri("https://vault.example.com/icons"), handler);

        await client.GetAsync("github.com");
        Assert.Equal(new Uri("https://vault.example.com/icons/github.com/icon.png"), Assert.Single(handler.Requests));
    }

    [Fact]
    public void Rejects_an_http_icon_server() =>
        Assert.Throws<ArgumentException>(() => new IconClient(new Uri("http://icons.example.com/")));

    [Fact]
    public async Task Rejects_hosts_that_are_not_websites()
    {
        var handler = new FakeIcons(_ => Image([1]));
        using var client = new IconClient(handler: handler);

        await Assert.ThrowsAsync<ArgumentException>(() => client.GetAsync("../evil.com"));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetAsync("nas"));
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData("image/svg+xml")]
    [InlineData("text/html")]
    public async Task Returns_null_for_content_that_is_not_a_bitmap(string type)
    {
        using var client = new IconClient(handler: new FakeIcons(_ => Image([1, 2, 3], type)));
        Assert.Null(await client.GetAsync("example.com"));
    }

    [Fact]
    public async Task Returns_null_when_the_site_has_no_icon()
    {
        using var client = new IconClient(handler: new FakeIcons(_ => new HttpResponseMessage(HttpStatusCode.NotFound)));
        Assert.Null(await client.GetAsync("example.com"));
    }

    [Fact]
    public async Task Returns_null_for_an_icon_that_is_too_large()
    {
        using var client = new IconClient(handler: new FakeIcons(_ => Image(new byte[IconClient.MaxBytes + 1])));
        Assert.Null(await client.GetAsync("example.com"));
    }

    [Fact]
    public async Task Returns_null_for_a_too_large_icon_without_content_length()
    {
        using var client = new IconClient(handler: new FakeIcons(_ =>
        {
            var content = new StreamContent(new UnknownLength(new byte[IconClient.MaxBytes + 10]));
            content.Headers.ContentType = new MediaTypeHeaderValue("image/png");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        }));
        Assert.Null(await client.GetAsync("example.com"));
    }

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task Throws_when_the_icon_service_is_unavailable(HttpStatusCode status)
    {
        using var client = new IconClient(handler: new FakeIcons(_ => new HttpResponseMessage(status)));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync("example.com"));
    }
}
