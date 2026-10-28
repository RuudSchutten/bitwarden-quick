using System.Text;
using BitwardenQuick.Core.Api;

namespace BitwardenQuick.Core.Storage;

/// <summary>A cached icon. <see cref="Png"/> is null when the site has no icon.</summary>
public readonly record struct CachedIcon(byte[]? Png, DateTimeOffset Fetched);

/// <summary>The plaintext layout of the icon cache: host, fetch time and PNG for each website.</summary>
public static class IconCacheFile
{
    private const int Format = 1;
    private const int MaxEntries = 20_000;

    public static byte[] Write(IReadOnlyDictionary<string, CachedIcon> icons)
    {
        using var stream = new MemoryStream();
        using (var w = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            w.Write(Format);
            w.Write(icons.Count);
            foreach (var (host, icon) in icons)
            {
                w.Write(host);
                w.Write(icon.Fetched.ToUnixTimeSeconds());
                w.Write(icon.Png?.Length ?? 0);
                if (icon.Png is { } png) w.Write(png);
            }
        }
        return stream.ToArray();
    }

    /// <summary>Returns the icons in <paramref name="data"/>, or none when it is from another version or damaged.</summary>
    public static Dictionary<string, CachedIcon> Read(byte[]? data)
    {
        var icons = Empty();
        if (data is null) return icons;
        try
        {
            using var r = new BinaryReader(new MemoryStream(data, writable: false), Encoding.UTF8);
            if (r.ReadInt32() != Format) return icons;
            var count = r.ReadInt32();
            if (count is < 0 or > MaxEntries) return icons;
            for (var i = 0; i < count; i++)
            {
                var host = r.ReadString();
                var fetched = DateTimeOffset.FromUnixTimeSeconds(r.ReadInt64());
                var length = r.ReadInt32();
                if (length is < 0 or > IconClient.MaxBytes) return Empty();
                var png = length == 0 ? null : r.ReadBytes(length);
                if (png is not null && png.Length != length) return Empty();
                if (IconClient.HostFor(host) == host) icons[host] = new CachedIcon(png, fetched);
            }
            return icons;
        }
        catch (Exception e) when (e is EndOfStreamException or IOException or ArgumentOutOfRangeException or FormatException)
        {
            return Empty();
        }
    }

    private static Dictionary<string, CachedIcon> Empty() => new(StringComparer.Ordinal);
}
