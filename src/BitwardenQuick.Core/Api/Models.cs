using System.Text.Json.Serialization;

namespace BitwardenQuick.Core.Api;

public sealed class TokenResponse
{
    [JsonPropertyName("access_token")] public string AccessToken { get; set; } = "";
    [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    public string? Key { get; set; }
    public string? PrivateKey { get; set; }
    public int Kdf { get; set; }
    public int KdfIterations { get; set; }
    public int? KdfMemory { get; set; }
    public int? KdfParallelism { get; set; }
    public bool ApiUseKeyConnector { get; set; }
}

public sealed class TokenError
{
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("error_description")] public string? ErrorDescription { get; set; }
}

public sealed class SyncResponse
{
    public ProfileModel? Profile { get; set; }
    public List<CipherModel>? Ciphers { get; set; }
}

public sealed class ProfileModel
{
    public string? Id { get; set; }
    public string? Email { get; set; }
    public string? Key { get; set; }
    public string? PrivateKey { get; set; }
    public List<OrganizationModel>? Organizations { get; set; }
}

public sealed class OrganizationModel
{
    public string? Id { get; set; }
    public string? Name { get; set; }
    public string? Key { get; set; }
}

public sealed class CipherModel
{
    public string? Id { get; set; }
    public string? OrganizationId { get; set; }
    public int Type { get; set; }
    public string? Name { get; set; }
    public string? Key { get; set; }
    public LoginModel? Login { get; set; }
    public bool Favorite { get; set; }
    public int Reprompt { get; set; }
    public DateTime? DeletedDate { get; set; }
}

public sealed class LoginModel
{
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? Totp { get; set; }
    public string? Uri { get; set; }
    public List<LoginUriModel>? Uris { get; set; }
}

public sealed class LoginUriModel
{
    public string? Uri { get; set; }
}

[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(TokenError))]
[JsonSerializable(typeof(SyncResponse))]
internal sealed partial class ApiJsonContext : JsonSerializerContext;
