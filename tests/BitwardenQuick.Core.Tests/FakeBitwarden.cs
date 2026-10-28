using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BitwardenQuick.Core.Crypto;

namespace BitwardenQuick.Core.Tests;

/// <summary>Builds a vault encrypted the way Bitwarden clients do and serves it over a fake HTTP handler.</summary>
internal sealed class FakeBitwarden : HttpMessageHandler
{
    public const string ClientId = "user.11111111-2222-3333-4444-555555555555";
    public const string ClientSecret = "s3cr3t";
    public const string Email = "Test@Example.com";
    public const string OrgId = "aaaaaaaa-0000-0000-0000-000000000001";

    public int TokenCalls;
    public int SyncCalls;
    public long Revision = 1_700_000_000_000;
    public bool Offline;

    private KdfConfig _kdf;
    private string _protectedUserKey;
    private readonly List<object> _ciphers = [];
    private readonly string _encPrivateKey;
    private readonly string _encOrgKey;

    public SymmetricKey UserKey { get; }
    public SymmetricKey OrgKey { get; }

    public FakeBitwarden(string masterPassword, KdfConfig kdf)
    {
        _kdf = kdf;
        UserKey = SymmetricKey.Generate();
        _protectedUserKey = Wrap(UserKey, masterPassword, kdf);

        using var rsa = RSA.Create(2048);
        _encPrivateKey = UserKey.Encrypt(rsa.ExportPkcs8PrivateKey()).ToString();
        OrgKey = SymmetricKey.Generate();
        using (var raw = OrgKey.Export())
            _encOrgKey = "4." + Convert.ToBase64String(rsa.Encrypt(raw.Span.ToArray(), RSAEncryptionPadding.OaepSHA1));
    }

    /// <summary>Re-wraps a user key the way a master password or KDF change does.</summary>
    public void Rewrap(SymmetricKey userKey, string masterPassword, KdfConfig kdf)
    {
        _kdf = kdf;
        _protectedUserKey = Wrap(userKey, masterPassword, kdf);
    }

    private static string Wrap(SymmetricKey userKey, string masterPassword, KdfConfig kdf)
    {
        using var masterKey = Kdf.DeriveMasterKey(Encoding.UTF8.GetBytes(masterPassword), Email, kdf);
        using var stretched = Kdf.StretchMasterKey(masterKey.Span);
        using var raw = userKey.Export();
        return stretched.Encrypt(raw.Span).ToString();
    }

    public void AddLogin(string id, SymmetricKey key, string name, string? username, string? password, string? uri,
        string? orgId = null, string? cipherKey = null, int type = 1, DateTime? deletedDate = null, bool favorite = false, int reprompt = 0, string? totp = null)
    {
        string? E(string? v) => v is null ? null : key.Encrypt(Encoding.UTF8.GetBytes(v)).ToString();
        _ciphers.Add(new
        {
            id,
            organizationId = orgId,
            type,
            name = E(name),
            key = cipherKey,
            favorite,
            reprompt,
            deletedDate,
            login = new { username = E(username), password = E(password), totp = E(totp), uris = uri is null ? null : new[] { new { uri = E(uri), match = (int?)null } } },
        });
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (Offline) throw new HttpRequestException("offline");
        var path = request.RequestUri!.AbsolutePath;

        if (!request.Headers.Contains("Bitwarden-Client-Version"))
            return Json(HttpStatusCode.BadRequest, new { error = "invalid_client_version", error_description = "No client version header found." });

        if (request.RequestUri.Host == "identity.test" && path == "/connect/token")
        {
            TokenCalls++;
            var form = request.Content!.ReadAsStringAsync(cancellationToken).Result;
            if (!form.Contains("client_secret=" + ClientSecret, StringComparison.Ordinal)
                || !form.Contains("grant_type=client_credentials", StringComparison.Ordinal))
                return Json(HttpStatusCode.BadRequest, new { error = "invalid_client", error_description = "invalid_client" });

            return Json(HttpStatusCode.OK, new Dictionary<string, object?>
            {
                ["access_token"] = "token-" + TokenCalls,
                ["expires_in"] = 3600,
                ["token_type"] = "Bearer",
                ["Key"] = _protectedUserKey,
                ["PrivateKey"] = _encPrivateKey,
                ["Kdf"] = (int)_kdf.Type,
                ["KdfIterations"] = _kdf.Iterations,
                ["KdfMemory"] = _kdf.MemoryMiB,
                ["KdfParallelism"] = _kdf.Parallelism,
            });
        }

        if (request.Headers.Authorization?.Parameter?.StartsWith("token-", StringComparison.Ordinal) != true)
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));

        if (path == "/accounts/revision-date")
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Revision.ToString()) });

        if (path == "/sync")
        {
            SyncCalls++;
            return Json(HttpStatusCode.OK, new
            {
                @object = "sync",
                profile = new
                {
                    id = "user-1",
                    email = Email,
                    key = _protectedUserKey,
                    privateKey = _encPrivateKey,
                    organizations = new[] { new { id = OrgId, name = "Contoso", key = _encOrgKey } },
                },
                folders = Array.Empty<object>(),
                ciphers = _ciphers,
            });
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }

    private static Task<HttpResponseMessage> Json(HttpStatusCode status, object body) =>
        Task.FromResult(new HttpResponseMessage(status)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        });
}
