using BitwardenQuick.Core.Storage;

namespace BitwardenQuick.Core.Tests;

public sealed class IconCacheFileTests
{
    private static readonly DateTimeOffset Fetched = DateTimeOffset.FromUnixTimeSeconds(1_780_000_000);

    [Fact]
    public void Round_trips_icons_and_missing_icons()
    {
        var icons = new Dictionary<string, CachedIcon>
        {
            ["github.com"] = new([1, 2, 3], Fetched),
            ["example.org"] = new(null, Fetched.AddDays(1)),
        };

        var read = IconCacheFile.Read(IconCacheFile.Write(icons));

        Assert.Equal(2, read.Count);
        Assert.Equal([1, 2, 3], read["github.com"].Png);
        Assert.Equal(Fetched, read["github.com"].Fetched);
        Assert.Null(read["example.org"].Png);
        Assert.Equal(Fetched.AddDays(1), read["example.org"].Fetched);
    }

    [Fact]
    public void Reads_nothing_from_missing_or_damaged_data()
    {
        var data = IconCacheFile.Write(new Dictionary<string, CachedIcon> { ["github.com"] = new(new byte[100], Fetched) });

        Assert.Empty(IconCacheFile.Read(null));
        Assert.Empty(IconCacheFile.Read([]));
        Assert.Empty(IconCacheFile.Read(data[..^10]));
        Assert.Empty(IconCacheFile.Read([9, 0, 0, 0, 0, 0, 0, 0]));
    }

    [Fact]
    public void Drops_hosts_that_are_not_websites()
    {
        var data = IconCacheFile.Write(new Dictionary<string, CachedIcon>
        {
            ["nas"] = new([1], Fetched),
            ["../x"] = new([1], Fetched),
            ["github.com"] = new([1], Fetched),
        });

        Assert.Equal(["github.com"], IconCacheFile.Read(data).Keys);
    }
}
