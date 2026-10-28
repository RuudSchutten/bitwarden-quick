using BitwardenQuick.Core.Crypto;

namespace BitwardenQuick.Core.Items;

public sealed class VaultEntry
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string? Username { get; init; }
    public string? Uri { get; init; }
    public string? Host { get; init; }
    public string? OrganizationName { get; init; }
    public bool Favorite { get; init; }
    public bool Reprompt { get; init; }

    internal EncString? Password { get; init; }
    internal EncString? Totp { get; init; }
    internal SymmetricKey Key { get; init; } = null!;

    internal string NameLower { get; init; } = "";
    internal string UsernameLower { get; init; } = "";
    internal string HostLower { get; init; } = "";
    internal string UriLower { get; init; } = "";

    public bool HasPassword => Password is not null;
    public bool HasTotp => Totp is not null;

    public string Subtitle => (Username, Host) switch
    {
        ({ Length: > 0 } u, { Length: > 0 } h) => $"{u} · {h}",
        ({ Length: > 0 } u, _) => u,
        (_, { Length: > 0 } h) => h,
        _ => "",
    };

    public string Initial => Name.Length > 0 ? char.ToUpperInvariant(Name.TrimStart()[0]).ToString() : "?";

    internal static string? HostOf(string? uri)
    {
        if (string.IsNullOrWhiteSpace(uri)) return null;
        var candidate = uri.Contains("://", StringComparison.Ordinal) ? uri : "https://" + uri;
        if (!System.Uri.TryCreate(candidate, UriKind.Absolute, out var parsed) || string.IsNullOrEmpty(parsed.Host))
            return null;
        var host = parsed.Host;
        return host.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? host[4..] : host;
    }
}
