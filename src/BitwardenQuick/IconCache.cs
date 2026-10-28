using System.IO;
using System.Net.Http;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using BitwardenQuick.Core.Api;

namespace BitwardenQuick;

/// <summary>
/// Website icons for the hosts in the vault, kept in memory only. Must be used from the UI thread.
/// </summary>
internal sealed class IconCache : IDisposable
{
    private const int PixelSize = 64;
    private const long MaxPixels = 1024 * 1024;

    private readonly IconClient _client;
    private readonly Dictionary<string, Task<ImageSource?>> _icons = new(StringComparer.Ordinal);
    private CancellationTokenSource _cts = new();

    public IconCache(IconClient client) => _client = client;

    public bool Enabled { get; set; } = true;

    /// <summary>The icon for a vault item's website, or null when there is nothing to fetch. The task does not fault.</summary>
    public Task<ImageSource?>? Get(string? uri)
    {
        if (!Enabled || IconClient.HostFor(uri) is not { } host) return null;
        if (!_icons.TryGetValue(host, out var task))
        {
            task = LoadAsync(host, _cts.Token);
            _icons[host] = task;
        }
        return task;
    }

    /// <summary>Forgets every icon, so no list of the vault's websites stays in memory while it is locked.</summary>
    public void Clear()
    {
        _cts.Cancel();
        _cts.Dispose();
        _cts = new CancellationTokenSource();
        _icons.Clear();
    }

    private async Task<ImageSource?> LoadAsync(string host, CancellationToken ct)
    {
        try
        {
            var bytes = await _client.GetAsync(host, ct);
            return bytes is null ? null : await Task.Run(() => Decode(bytes), ct);
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException or ObjectDisposedException)
        {
            // A failure can complete synchronously, before Get has stored the task.
            await Task.Yield();
            if (!ct.IsCancellationRequested) _icons.Remove(host);
            return null;
        }
    }

    private static ImageSource? Decode(byte[] bytes)
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
        _cts.Cancel();
        _cts.Dispose();
        _client.Dispose();
    }
}
