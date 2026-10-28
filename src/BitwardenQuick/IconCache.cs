using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using BitwardenQuick.Core;
using BitwardenQuick.Core.Api;
using BitwardenQuick.Core.Storage;

namespace BitwardenQuick;

/// <summary>
/// Website icons for the hosts in the vault. They are stored as small PNGs in a file encrypted with the user key,
/// read once per unlock and forgotten on lock. Must be used from the UI thread.
/// </summary>
internal sealed class IconCache : IDisposable
{
    private const int PixelSize = 48;
    private const long MaxPixels = 1024 * 1024;
    private static readonly TimeSpan IconLifetime = TimeSpan.FromDays(30);
    private static readonly TimeSpan MissingLifetime = TimeSpan.FromDays(7);

    private sealed class Entry
    {
        public byte[]? Png;
        public DateTimeOffset Fetched;
        public ImageSource? Image;
        public Task<ImageSource?>? Pending;

        public bool IsStale => DateTimeOffset.UtcNow - Fetched > (Png is null ? MissingLifetime : IconLifetime);
    }

    private readonly IconClient _client;
    private readonly VaultService _service;
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly DispatcherTimer _saveTimer;
    private CancellationTokenSource _cts = new();
    private bool _loaded;
    private bool _dirty;

    public IconCache(IconClient client, VaultService service)
    {
        _client = client;
        _service = service;
        _saveTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _saveTimer.Tick += (_, _) => Save();
    }

    public bool Enabled { get; set; } = true;

    /// <summary>The icon for a vault item's website, or null when there is nothing to fetch. The task does not fault.</summary>
    public Task<ImageSource?>? Get(string? uri)
    {
        if (!Enabled || !_service.IsUnlocked || IconClient.HostFor(uri) is not { } host) return null;
        EnsureLoaded();

        if (!_entries.TryGetValue(host, out var entry))
        {
            entry = new Entry();
            _entries[host] = entry;
        }

        if (entry.Png is not null)
        {
            entry.Image ??= Decode(entry.Png);
            if (entry.IsStale && entry.Pending is null) entry.Pending = FetchAsync(host, entry, _cts.Token);
            return Task.FromResult(entry.Image);
        }
        if (entry.Pending is { } pending) return pending;
        if (!entry.IsStale) return Task.FromResult<ImageSource?>(null);
        return entry.Pending = FetchAsync(host, entry, _cts.Token);
    }

    /// <summary>Writes pending changes, then forgets every icon so no list of the vault's websites stays in memory.</summary>
    public void Lock()
    {
        Save();
        Clear();
    }

    /// <summary>Forgets every icon without saving, for when the stored data is being deleted.</summary>
    public void Clear()
    {
        _saveTimer.Stop();
        _cts.Cancel();
        _cts.Dispose();
        _cts = new CancellationTokenSource();
        _entries.Clear();
        _loaded = false;
        _dirty = false;
    }

    private void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;
        foreach (var (host, icon) in IconCacheFile.Read(_service.LoadIconCache()))
            _entries[host] = new Entry { Png = icon.Png, Fetched = icon.Fetched };
    }

    private async Task<ImageSource?> FetchAsync(string host, Entry entry, CancellationToken ct)
    {
        // Get stores the task in entry.Pending, which must happen before the finally below clears it.
        await Task.Yield();
        try
        {
            var bytes = await _client.GetAsync(host, ct);
            var (image, png) = bytes is null ? (null, null) : await Task.Run(() => DecodeAndEncode(bytes), ct);
            if (ct.IsCancellationRequested) return null;
            entry.Image = image;
            entry.Png = png;
            entry.Fetched = DateTimeOffset.UtcNow;
            MarkDirty();
            return image;
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException or ObjectDisposedException)
        {
            return entry.Image;
        }
        finally
        {
            entry.Pending = null;
        }
    }

    private void MarkDirty()
    {
        _dirty = true;
        _saveTimer.Stop();
        _saveTimer.Start();
    }

    /// <summary>Saves the icons of the websites that are still in the vault.</summary>
    public void Save()
    {
        _saveTimer.Stop();
        if (!_dirty || !_loaded || !_service.IsUnlocked) return;

        var live = _service.Current?.Entries.Select(e => IconClient.HostFor(e.Uri)).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var icons = new Dictionary<string, CachedIcon>(StringComparer.Ordinal);
        foreach (var (host, entry) in _entries)
            if (entry.Fetched != default && (live is null || live.Contains(host)))
                icons[host] = new CachedIcon(entry.Png, entry.Fetched);

        try
        {
            _service.SaveIconCache(IconCacheFile.Write(icons));
            _dirty = false;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or CryptographicException or ObjectDisposedException)
        {
        }
    }

    private static (ImageSource? Image, byte[]? Png) DecodeAndEncode(byte[] bytes)
    {
        if (Decode(bytes) is not { } image) return (null, null);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(image));
        using var stream = new MemoryStream();
        encoder.Save(stream);
        return (image, stream.ToArray());
    }

    private static BitmapSource? Decode(byte[] bytes)
    {
        try
        {
            using var stream = new MemoryStream(bytes, writable: false);
            var decoder = BitmapDecoder.Create(stream,
                BitmapCreateOptions.IgnoreColorProfile | BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.None);

            BitmapSource? best = null;
            foreach (var frame in decoder.Frames)
            {
                var size = Math.Max(frame.PixelWidth, frame.PixelHeight);
                if (size == 0 || (long)frame.PixelWidth * frame.PixelHeight > MaxPixels) continue;
                if (best is null) best = frame;
                else
                {
                    var bestSize = Math.Max(best.PixelWidth, best.PixelHeight);
                    // The smallest frame that is still sharp at PixelSize, else the largest there is.
                    if (bestSize < PixelSize ? size > bestSize : size >= PixelSize && size < bestSize) best = frame;
                }
            }
            if (best is null) return null;

            BitmapSource source = best;
            var largest = Math.Max(best.PixelWidth, best.PixelHeight);
            if (largest > PixelSize)
            {
                var scale = (double)PixelSize / largest;
                source = new TransformedBitmap(source, new ScaleTransform(scale, scale));
            }
            var bitmap = new WriteableBitmap(new FormatConvertedBitmap(source, PixelFormats.Pbgra32, null, 0));
            bitmap.Freeze();
            return bitmap;
        }
        catch (Exception e) when (e is NotSupportedException or FileFormatException or ArgumentException
                                      or InvalidOperationException or IOException or OverflowException
                                      or System.Runtime.InteropServices.ExternalException)
        {
            return null;
        }
    }

    public void Dispose()
    {
        Save();
        _saveTimer.Stop();
        _cts.Cancel();
        _cts.Dispose();
        _client.Dispose();
    }
}
