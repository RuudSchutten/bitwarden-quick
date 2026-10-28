using BitwardenQuick.Core.Api;
using BitwardenQuick.Core.Crypto;

namespace BitwardenQuick.Core.Items;

/// <summary>
/// The searchable view of a synced vault. Names, usernames and URIs are decrypted up
/// front for searching; passwords stay encrypted until <see cref="DecryptPassword"/>.
/// </summary>
public sealed class Vault : IDisposable
{
    private const int LoginType = 1;

    private readonly List<SymmetricKey> _ownedKeys;

    public IReadOnlyList<VaultEntry> Entries { get; }
    public int SkippedItems { get; }

    private Vault(List<VaultEntry> entries, List<SymmetricKey> ownedKeys, int skipped)
    {
        Entries = entries;
        _ownedKeys = ownedKeys;
        SkippedItems = skipped;
    }

    public static Vault Load(SyncResponse sync, SymmetricKey userKey)
    {
        var owned = new List<SymmetricKey>();
        var entries = new List<VaultEntry>();
        var skipped = 0;
        var orgKeys = new Dictionary<string, (SymmetricKey Key, string? Name)>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var profile = sync.Profile ?? throw new InvalidDataException("Sync response has no profile.");
            if (profile.Organizations is { Count: > 0 } orgs && EncString.ParseOrNull(profile.PrivateKey) is { } encPrivate)
            {
                using var der = userKey.Decrypt(encPrivate);
                using var privateKey = PrivateKey.ImportPkcs8(der.Span);
                foreach (var org in orgs)
                {
                    if (org.Id is null || EncString.ParseOrNull(org.Key) is not { } encOrgKey) continue;
                    try
                    {
                        var key = privateKey.DecryptKey(encOrgKey);
                        owned.Add(key);
                        orgKeys[org.Id] = (key, org.Name);
                    }
                    catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or NotSupportedException)
                    {
                    }
                }
            }

            foreach (var cipher in sync.Ciphers ?? [])
            {
                if (cipher.Type != LoginType || cipher.DeletedDate is not null || cipher.Id is null) continue;
                try
                {
                    var entry = BuildEntry(cipher, userKey, orgKeys, owned);
                    if (entry is null) skipped++;
                    else entries.Add(entry);
                }
                catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or NotSupportedException)
                {
                    skipped++;
                }
            }

            entries.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase));
            return new Vault(entries, owned, skipped);
        }
        catch
        {
            foreach (var key in owned) key.Dispose();
            throw;
        }
    }

    private static VaultEntry? BuildEntry(
        CipherModel cipher,
        SymmetricKey userKey,
        Dictionary<string, (SymmetricKey Key, string? Name)> orgKeys,
        List<SymmetricKey> owned)
    {
        SymmetricKey containerKey = userKey;
        string? orgName = null;
        if (cipher.OrganizationId is { } orgId)
        {
            if (!orgKeys.TryGetValue(orgId, out var org)) return null;
            containerKey = org.Key;
            orgName = org.Name;
        }

        var key = containerKey;
        if (EncString.ParseOrNull(cipher.Key) is { } encCipherKey)
        {
            key = containerKey.DecryptKey(encCipherKey);
            owned.Add(key);
        }

        string? Dec(string? value) => EncString.ParseOrNull(value) is { } enc ? key.DecryptString(enc) : null;

        var name = Dec(cipher.Name) ?? "";
        var username = Dec(cipher.Login?.Username);
        var uri = Dec(cipher.Login?.Uris?.FirstOrDefault(u => !string.IsNullOrEmpty(u.Uri))?.Uri ?? cipher.Login?.Uri);
        var host = VaultEntry.HostOf(uri);

        return new VaultEntry
        {
            Id = cipher.Id!,
            Name = name,
            Username = username,
            Uri = uri,
            Host = host,
            OrganizationName = orgName,
            Favorite = cipher.Favorite,
            Reprompt = cipher.Reprompt != 0,
            Password = EncString.ParseOrNull(cipher.Login?.Password),
            Key = key,
            NameLower = name.ToLowerInvariant(),
            UsernameLower = username?.ToLowerInvariant() ?? "",
            HostLower = host?.ToLowerInvariant() ?? "",
            UriLower = uri?.ToLowerInvariant() ?? "",
        };
    }

    public VaultEntry? Find(string id)
    {
        foreach (var entry in Entries)
            if (entry.Id == id) return entry;
        return null;
    }

    public static Secret? DecryptPassword(VaultEntry entry) =>
        entry.Password is { } enc ? entry.Key.Decrypt(enc) : null;

    public void Dispose()
    {
        foreach (var key in _ownedKeys) key.Dispose();
        _ownedKeys.Clear();
    }
}
