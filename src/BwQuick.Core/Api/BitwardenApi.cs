using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace BwQuick.Core.Api;

public sealed class BitwardenAuthException(string message) : Exception(message);

public sealed record ApiCredentials(string ClientId, string ClientSecret, Guid DeviceId);

public sealed class BitwardenApi : IDisposable
{
    // WindowsCLI: the device type Bitwarden associates with personal API key logins.
    private const string DeviceType = "23";

    // The server rejects requests without a client version, and uses it to decide which
    // encryption features (such as per-item cipher keys) a client understands.
    private const string ClientName = "cli";
    private const string ClientVersion = "2026.9.0";

    private readonly HttpClient _http;
    private readonly Uri _identity;
    private readonly Uri _api;

    public BitwardenApi(Uri? identity = null, Uri? api = null, HttpMessageHandler? handler = null)
    {
        _identity = identity ?? new Uri("https://identity.bitwarden.com/");
        _api = api ?? new Uri("https://api.bitwarden.com/");
        if (_identity.Scheme != Uri.UriSchemeHttps || _api.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("Bitwarden server URLs must use https.");
        _http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
        })
        {
            Timeout = TimeSpan.FromSeconds(30),
        };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("BwQuick", "1.0"));
        _http.DefaultRequestHeaders.Add("Device-Type", DeviceType);
        _http.DefaultRequestHeaders.Add("Bitwarden-Client-Name", ClientName);
        _http.DefaultRequestHeaders.Add("Bitwarden-Client-Version", ClientVersion);
    }

    public string Server => _identity.AbsoluteUri;

    public async Task<TokenResponse> LoginAsync(ApiCredentials credentials, CancellationToken ct = default)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["scope"] = "api",
            ["client_id"] = credentials.ClientId.Trim(),
            ["client_secret"] = credentials.ClientSecret.Trim(),
            ["deviceType"] = DeviceType,
            ["deviceIdentifier"] = credentials.DeviceId.ToString(),
            ["deviceName"] = "BwQuick",
        });

        using var response = await _http.PostAsync(new Uri(_identity, "connect/token"), form, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            string? detail = null;
            try { detail = JsonSerializer.Deserialize(body, ApiJsonContext.Default.TokenError)?.ErrorDescription; }
            catch (JsonException) { }
            if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized)
                throw new BitwardenAuthException(detail ?? "API key was rejected.");
            throw new HttpRequestException($"Sign-in failed ({(int)response.StatusCode}).", null, response.StatusCode);
        }

        return JsonSerializer.Deserialize(body, ApiJsonContext.Default.TokenResponse)
            ?? throw new HttpRequestException("Empty response from the server.");
    }

    public async Task<long> GetRevisionDateAsync(string accessToken, CancellationToken ct = default)
    {
        using var request = Authorized(HttpMethod.Get, "accounts/revision-date", accessToken);
        using var response = await SendAsync(request, ct).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return long.TryParse(text.Trim(), out var value) ? value : 0;
    }

    /// <summary>Returns the raw sync JSON. All vault fields in it are still encrypted.</summary>
    public async Task<byte[]> SyncAsync(string accessToken, CancellationToken ct = default)
    {
        using var request = Authorized(HttpMethod.Get, "sync?excludeDomains=true", accessToken);
        using var response = await SendAsync(request, ct).ConfigureAwait(false);
        return await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
    }

    public static SyncResponse ParseSync(ReadOnlySpan<byte> json) =>
        JsonSerializer.Deserialize(json, ApiJsonContext.Default.SyncResponse)
        ?? throw new JsonException("Empty sync response.");

    private HttpRequestMessage Authorized(HttpMethod method, string path, string accessToken)
    {
        var request = new HttpRequestMessage(method, new Uri(_api, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return request;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            response.Dispose();
            throw new UnauthorizedAccessException("Access token rejected.");
        }
        if (!response.IsSuccessStatusCode)
        {
            var status = response.StatusCode;
            response.Dispose();
            throw new HttpRequestException($"Bitwarden returned {(int)status}.", null, status);
        }
        return response;
    }

    public void Dispose() => _http.Dispose();
}
