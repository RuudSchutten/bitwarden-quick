using System.Globalization;
using System.Net;
using System.Net.Http.Headers;

namespace BitwardenQuick.Core.Api;

/// <summary>Fetches website icons from Bitwarden's icon service, like Bitwarden's own apps do.</summary>
public sealed class IconClient : IDisposable
{
    public const int MaxBytes = 256 * 1024;

    // Names that only resolve on a local network have no public icon, and sending them out would leak them.
    private static readonly string[] PrivateSuffixes = ["localhost", "local", "lan", "internal", "intranet", "corp", "home.arpa"];

    private static readonly IdnMapping Idn = new() { UseStd3AsciiRules = true };

    private readonly HttpClient _http;
    private readonly Uri _base;

    public IconClient(Uri? iconsBase = null, HttpMessageHandler? handler = null)
    {
        _base = iconsBase ?? new Uri("https://icons.bitwarden.net/");
        if (_base.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("The icon server URL must use https.");
        if (!_base.AbsolutePath.EndsWith('/')) _base = new Uri(_base.AbsoluteUri + "/");
        _http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            MaxConnectionsPerServer = 4,
            MaxAutomaticRedirections = 3,
            UseCookies = false,
        })
        {
            Timeout = TimeSpan.FromSeconds(15),
        };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("BitwardenQuick", "1.0"));
    }

    /// <summary>The ASCII host to fetch an icon for, or null when the URI is not a public website.</summary>
    public static string? HostFor(string? uri)
    {
        if (string.IsNullOrWhiteSpace(uri)) return null;
        uri = uri.Trim();
        var candidate = uri.Contains("://", StringComparison.Ordinal) ? uri : "https://" + uri;
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var parsed)) return null;
        if (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp) return null;
        if (parsed.HostNameType != UriHostNameType.Dns) return null;

        string host;
        try
        {
            host = Idn.GetAscii(parsed.IdnHost.TrimEnd('.')).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return null;
        }

        if (host.Length > 253 || !host.Contains('.')) return null;
        foreach (var suffix in PrivateSuffixes)
            if (host == suffix || host.EndsWith("." + suffix, StringComparison.Ordinal)) return null;
        return host;
    }

    /// <summary>
    /// Returns the icon image, or null when the site has none. Throws <see cref="HttpRequestException"/>
    /// when the icon service could not be reached, so the caller can try again later.
    /// </summary>
    public async Task<byte[]?> GetAsync(string host, CancellationToken ct = default)
    {
        if (HostFor(host) != host) throw new ArgumentException("Not a valid icon host.", nameof(host));

        using var response = await _http.GetAsync(new Uri(_base, host + "/icon.png"), HttpCompletionOption.ResponseHeadersRead, ct)
            .ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.TooManyRequests || (int)response.StatusCode >= 500)
            throw new HttpRequestException($"Icon service returned {(int)response.StatusCode}.", null, response.StatusCode);
        if (!response.IsSuccessStatusCode) return null;

        var content = response.Content;
        if (content.Headers.ContentType?.MediaType is not { } type
            || !type.StartsWith("image/", StringComparison.OrdinalIgnoreCase)
            || type.Contains("svg", StringComparison.OrdinalIgnoreCase))
            return null;
        if (content.Headers.ContentLength > MaxBytes) return null;

        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = new byte[MaxBytes + 1];
        var length = 0;
        int read;
        while (length < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(length), ct).ConfigureAwait(false)) > 0)
            length += read;
        return length is 0 or > MaxBytes ? null : buffer[..length];
    }

    public void Dispose() => _http.Dispose();
}
