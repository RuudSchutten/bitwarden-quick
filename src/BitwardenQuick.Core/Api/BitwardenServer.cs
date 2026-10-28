namespace BitwardenQuick.Core.Api;

/// <summary>The addresses of a Bitwarden server: one of the two cloud regions, or a self-hosted server.</summary>
public sealed record BitwardenServer(string Name, Uri Identity, Uri Api, Uri Icons, Uri WebVault)
{
    public static readonly BitwardenServer UnitedStates = new("bitwarden.com",
        new Uri("https://identity.bitwarden.com/"), new Uri("https://api.bitwarden.com/"),
        new Uri("https://icons.bitwarden.net/"), new Uri("https://vault.bitwarden.com/"));

    public static readonly BitwardenServer Europe = new("bitwarden.eu",
        new Uri("https://identity.bitwarden.eu/"), new Uri("https://api.bitwarden.eu/"),
        new Uri("https://icons.bitwarden.eu/"), new Uri("https://vault.bitwarden.eu/"));

    public bool IsCloud => this == UnitedStates || this == Europe;

    /// <summary>
    /// Accepts bitwarden.com or bitwarden.eu (also as their web vault address), or the https base URL of a
    /// self-hosted server, which serves identity, api and icons under that URL.
    /// </summary>
    public static BitwardenServer Parse(string value)
    {
        var trimmed = value.Trim().TrimEnd('/');
        var host = trimmed.Contains("://", StringComparison.Ordinal) ? trimmed[(trimmed.IndexOf("://", StringComparison.Ordinal) + 3)..] : trimmed;
        if (trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || !trimmed.Contains("://", StringComparison.Ordinal))
        {
            switch (host.ToLowerInvariant())
            {
                case "bitwarden.com" or "vault.bitwarden.com":
                    return UnitedStates;
                case "bitwarden.eu" or "vault.bitwarden.eu":
                    return Europe;
            }
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var root) || root.Scheme != Uri.UriSchemeHttps || root.Host.Length == 0)
            throw new ArgumentException($"\"{value}\" is not bitwarden.com, bitwarden.eu or an https URL.");
        var baseUrl = root.AbsoluteUri.TrimEnd('/');
        return new BitwardenServer(root.Host,
            new Uri(baseUrl + "/identity/"), new Uri(baseUrl + "/api/"), new Uri(baseUrl + "/icons/"), new Uri(baseUrl + "/"));
    }
}
