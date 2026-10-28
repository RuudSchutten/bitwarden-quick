using BitwardenQuick.Core.Crypto;
using BitwardenQuick.Core.Items;

namespace BitwardenQuick.Core.Tests;

public sealed class SearchTests : IDisposable
{
    private readonly SymmetricKey _key = SymmetricKey.Generate();
    private readonly List<VaultEntry> _entries;

    public SearchTests()
    {
        _entries =
        [
            Entry("1", "Zoom - Personal", "ruud@example.com", "https://zoom.example"),
            Entry("2", "Google", "ruud@mail.example", "https://accounts.google.com"),
            Entry("3", "My Zoo Tickets", "ruud", "https://tickets.example"),
            Entry("4", "Azure DevOps", "ruud@contoso.example", "https://dev.azure.com", favorite: true),
            Entry("5", "GitHub", "ruud", "https://github.com"),
        ];
    }

    private VaultEntry Entry(string id, string name, string user, string uri, bool favorite = false)
    {
        var host = VaultEntry.HostOf(uri);
        return new VaultEntry
        {
            Id = id, Name = name, Username = user, Uri = uri, Host = host, Favorite = favorite, Key = _key,
            NameLower = name.ToLowerInvariant(), UsernameLower = user.ToLowerInvariant(),
            HostLower = host?.ToLowerInvariant() ?? "", UriLower = uri.ToLowerInvariant(),
        };
    }

    [Fact]
    public void Name_prefix_beats_word_start_and_substring()
    {
        var result = VaultSearch.Search(_entries, "zoo", []);
        Assert.Equal(["1", "3"], result.Select(e => e.Id));
    }

    [Fact]
    public void All_tokens_must_match()
    {
        Assert.Equal(["4"], VaultSearch.Search(_entries, "azure contoso", []).Select(e => e.Id));
        Assert.Empty(VaultSearch.Search(_entries, "zoom github", []));
    }

    [Fact]
    public void Matches_host_and_username()
    {
        Assert.Equal("2", VaultSearch.Search(_entries, "accounts.google", [])[0].Id);
        Assert.Contains(VaultSearch.Search(_entries, "mail.example", []), e => e.Id == "2");
    }

    [Fact]
    public void Empty_query_lists_recent_then_favorites()
    {
        var result = VaultSearch.Search(_entries, "  ", ["5", "1"]);
        Assert.Equal(["5", "1", "4"], result.Take(3).Select(e => e.Id));
        Assert.Equal(5, result.Count);
    }

    [Fact]
    public void Recent_use_breaks_ties()
    {
        var result = VaultSearch.Search(_entries, "ruud", ["5"]);
        Assert.Equal("5", result[0].Id);
    }

    [Theory]
    [InlineData("https://www.github.com/login", "github.com")]
    [InlineData("zoom.example", "zoom.example")]
    [InlineData("androidapp://com.foo", "com.foo")]
    [InlineData("", null)]
    public void Host_extraction(string uri, string? expected) => Assert.Equal(expected, VaultEntry.HostOf(uri));

    public void Dispose() => _key.Dispose();
}
