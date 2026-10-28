using System.Security.Cryptography;
using System.Text;
using BitwardenQuick.Core.Api;
using BitwardenQuick.Core.Crypto;
using BitwardenQuick.Core.Items;
using BitwardenQuick.Core.Storage;

namespace BitwardenQuick.Core;

public sealed class SetupException(string message, Exception? inner = null) : Exception(message, inner);

public sealed class VaultService : IDisposable
{
    private static readonly byte[] HelloKeyInfo = "BitwardenQuick Windows Hello"u8.ToArray();

    private readonly SecureStore _store;
    private BitwardenApi _api;
    private readonly SemaphoreSlim _syncLock = new(1, 1);
    private readonly Lock _gate = new();

    private AccountInfo? _account;
    private SymmetricKey? _userKey;
    private Vault? _vault;
    private long _revision;
    private string? _accessToken;
    private DateTimeOffset _accessTokenExpiry;

    public VaultService(SecureStore store, BitwardenApi api)
    {
        _store = store;
        _api = api;
    }

    public event Action? Changed;

    public bool HasStoredAccount => _store.HasAccount;
    public bool IsConfigured => _account is not null;
    public bool IsUnlocked => _userKey is not null;
    public bool NeedsSetup { get; private set; }
    public Vault? Current => _vault;
    public DateTimeOffset? LastSync { get; private set; }
    public string? LastError { get; private set; }
    public string? Email => _account?.Email;
    public string ServerName => _api.Name;

    /// <summary>
    /// Signs in to another server from now on, for a setup that is about to start. Forgets the account in memory;
    /// the stored one is replaced when that setup completes, and is still used after a restart if it does not.
    /// </summary>
    public void UseServer(BitwardenApi api)
    {
        BitwardenApi old;
        lock (_gate)
        {
            if (api.Server == _api.Server)
            {
                api.Dispose();
                return;
            }
            SwapVault(null, 0);
            ReplaceUserKey(null);
            _account = null;
            _accessToken = null;
            NeedsSetup = false;
            LastSync = null;
            LastError = null;
            old = _api;
            _api = api;
        }
        old.Dispose();
        Changed?.Invoke();
    }

    /// <summary>The challenge to sign with the Windows Hello key, or null when Hello unlock is not set up.</summary>
    public byte[]? HelloChallenge => _account?.HelloChallenge;

    /// <summary>Reads the stored account. The vault stays locked until one of the unlock methods succeeds.</summary>
    public void LoadAccount()
    {
        AccountInfo account;
        try
        {
            account = _store.LoadAccount();
        }
        catch (LegacyAccountException)
        {
            _store.Wipe();
            throw new SetupException("BitwardenQuick now locks your vault. Connect your vault again.");
        }
        if (account.Server != _api.Server)
            throw new SetupException($"BitwardenQuick was set up for {account.Server}. Connect your vault again.");

        lock (_gate)
        {
            SwapVault(null, 0);
            ReplaceUserKey(null);
            _accessToken = null;
            _account = account;
        }
    }

    public bool UnlockWithHello(ReadOnlySpan<byte> signature)
    {
        if (_account is not { HelloChallenge: { } challenge, HelloProtectedUserKey: { } wrapped }) return false;
        try
        {
            using var wrappingKey = HelloWrappingKey(signature, challenge);
            return TryUnlock(wrappingKey.DecryptKey(EncString.Parse(wrapped)));
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException)
        {
            return false;
        }
    }

    public bool UnlockWithMasterPassword(Secret password)
    {
        if (_account is not { } account) return false;
        try
        {
            using var masterKey = Kdf.DeriveMasterKey(password.Span, account.Email, account.Kdf);
            return TryUnlock(Kdf.DecryptUserKey(masterKey.Span, EncString.Parse(account.ProtectedUserKey)));
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException)
        {
            return false;
        }
    }

    private bool TryUnlock(SymmetricKey key)
    {
        var account = _account;
        if (account is null)
        {
            key.Dispose();
            return false;
        }
        try
        {
            // The client secret is authenticated with the user key, so this rejects a wrong key.
            using (key.Decrypt(EncString.Parse(account.ProtectedClientSecret))) { }
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException)
        {
            key.Dispose();
            return false;
        }

        Vault? vault = null;
        long revision = 0;
        if (_store.LoadVault() is { } cached)
        {
            try
            {
                vault = Vault.Load(BitwardenApi.ParseSync(cached.SyncJson), key);
                revision = cached.Revision;
            }
            catch (Exception e) when (e is CryptographicException or System.Text.Json.JsonException or InvalidDataException)
            {
            }
        }

        lock (_gate)
        {
            if (!ReferenceEquals(_account, account))
            {
                vault?.Dispose();
                key.Dispose();
                return false;
            }
            ReplaceUserKey(key);
            SwapVault(vault, revision);
        }
        Changed?.Invoke();
        return true;
    }

    /// <summary>Forgets the user key, the decrypted vault and the access token until the next unlock.</summary>
    public void Lock()
    {
        lock (_gate)
        {
            if (_userKey is null) return;
            SwapVault(null, 0);
            ReplaceUserKey(null);
            _accessToken = null;
        }
        Changed?.Invoke();
    }

    public static byte[] NewHelloChallenge() => RandomNumberGenerator.GetBytes(32);

    /// <summary>
    /// Wraps the user key with a key derived from a Windows Hello signature over <paramref name="challenge"/>.
    /// Hello keys sign with RSA PKCS#1 v1.5, which is deterministic, so the same signature unlocks later.
    /// </summary>
    public void EnableHello(byte[] challenge, ReadOnlySpan<byte> signature)
    {
        lock (_gate)
        {
            if (_account is null || _userKey is null) throw new InvalidOperationException("The vault is locked.");
            using var wrappingKey = HelloWrappingKey(signature, challenge);
            using var raw = _userKey.Export();
            _account = _account with
            {
                HelloChallenge = challenge,
                HelloProtectedUserKey = wrappingKey.Encrypt(raw.Span).ToString(),
            };
            _store.SaveAccount(_account);
        }
    }

    private static SymmetricKey HelloWrappingKey(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> challenge)
    {
        Span<byte> key = stackalloc byte[64];
        try
        {
            HKDF.DeriveKey(HashAlgorithmName.SHA256, signature, key, challenge, HelloKeyInfo);
            return new SymmetricKey(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public async Task SetupAsync(
        string clientId,
        string clientSecret,
        Secret masterPassword,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        var credentials = new ApiCredentials(clientId.Trim(), clientSecret.Trim(), Guid.NewGuid());

        progress?.Report($"Signing in to {_api.Name}…");
        TokenResponse token;
        try
        {
            token = await _api.LoginAsync(credentials, ct).ConfigureAwait(false);
        }
        catch (BitwardenAuthException e)
        {
            throw new SetupException($"Client ID or client secret is incorrect ({e.Message}).", e);
        }
        catch (HttpRequestException e)
        {
            throw new SetupException($"Cannot reach {_api.Name}. Check your internet connection.", e);
        }

        if (token.ApiUseKeyConnector)
            throw new SetupException("This account uses Key Connector instead of a master password, which is not supported.");

        progress?.Report("Fetching vault…");
        var revision = await _api.GetRevisionDateAsync(token.AccessToken, ct).ConfigureAwait(false);
        var json = await _api.SyncAsync(token.AccessToken, ct).ConfigureAwait(false);
        var sync = BitwardenApi.ParseSync(json);

        var email = sync.Profile?.Email ?? throw new SetupException("The profile has no email address.");
        var protectedUserKey = token.Key ?? sync.Profile?.Key ?? throw new SetupException("No vault key received.");
        var kdf = KdfOf(token);

        try
        {
            kdf.Validate();
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException)
        {
            throw new SetupException($"Unsafe or unknown KDF settings from the server: {e.Message}", e);
        }

        progress?.Report("Checking master password…");
        SymmetricKey userKey;
        try
        {
            userKey = await Task.Run(() =>
            {
                using var masterKey = Kdf.DeriveMasterKey(masterPassword.Span, email, kdf);
                return Kdf.DecryptUserKey(masterKey.Span, EncString.Parse(protectedUserKey));
            }, ct).ConfigureAwait(false);
        }
        catch (CryptographicException e)
        {
            throw new SetupException("Incorrect master password.", e);
        }
        catch (NotSupportedException e)
        {
            throw new SetupException($"This account uses an encryption type that is not supported yet: {e.Message}", e);
        }

        Vault vault;
        AccountInfo account;
        try
        {
            vault = Vault.Load(sync, userKey);
            var protectedSecret = userKey.Encrypt(Encoding.UTF8.GetBytes(credentials.ClientSecret)).ToString();
            account = new AccountInfo(_api.Server, credentials.ClientId, protectedSecret, credentials.DeviceId, email, kdf, protectedUserKey);
        }
        catch
        {
            userKey.Dispose();
            throw;
        }

        lock (_gate)
        {
            _store.SaveAccount(account);
            _store.SaveVault(revision, json);
            _account = account;
            _accessToken = token.AccessToken;
            _accessTokenExpiry = ExpiryOf(token);
            NeedsSetup = false;
            ReplaceUserKey(userKey);
            SwapVault(vault, revision);
        }
        LastSync = DateTimeOffset.Now;
        LastError = null;
        Changed?.Invoke();
    }

    /// <summary>Checks the account revision and only downloads the vault when something changed.</summary>
    public async Task SyncAsync(bool force = false, CancellationToken ct = default)
    {
        var account = _account;
        var userKey = _userKey;
        if (account is null || userKey is null) return;
        if (!await _syncLock.WaitAsync(0, ct).ConfigureAwait(false)) return;
        try
        {
            var token = await GetAccessTokenAsync(account, userKey, ct).ConfigureAwait(false);
            long revision;
            try
            {
                revision = await _api.GetRevisionDateAsync(token, ct).ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException)
            {
                _accessToken = null;
                token = await GetAccessTokenAsync(account, userKey, ct).ConfigureAwait(false);
                revision = await _api.GetRevisionDateAsync(token, ct).ConfigureAwait(false);
            }

            if (force || revision != _revision || _vault is null)
            {
                var json = await _api.SyncAsync(token, ct).ConfigureAwait(false);
                var sync = BitwardenApi.ParseSync(json);
                Vault vault;
                try
                {
                    vault = Vault.Load(sync, userKey);
                }
                catch (CryptographicException) when (ReferenceEquals(_userKey, userKey))
                {
                    NeedsSetup = true;
                    throw new SetupException("Your vault key has changed. Set up BitwardenQuick again.");
                }

                try
                {
                    await RefreshAccountAsync(account, userKey, sync, ct).ConfigureAwait(false);
                }
                catch
                {
                    vault.Dispose();
                    throw;
                }

                lock (_gate)
                {
                    if (!ReferenceEquals(_userKey, userKey))
                    {
                        vault.Dispose();
                        return;
                    }
                    _store.SaveVault(revision, json);
                    SwapVault(vault, revision);
                }
            }

            LastSync = DateTimeOffset.Now;
            LastError = null;
        }
        catch (BitwardenAuthException)
        {
            NeedsSetup = true;
            LastError = "The API key was revoked or changed. Set up BitwardenQuick again.";
        }
        catch (SetupException e)
        {
            LastError = e.Message;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            LastError = "Offline – showing the last synced vault";
        }
        catch (Exception e) when (e is ObjectDisposedException or CryptographicException && !ReferenceEquals(_userKey, userKey))
        {
        }
        finally
        {
            _syncLock.Release();
            Changed?.Invoke();
        }
    }

    /// <summary>
    /// A master password, KDF or email change re-wraps the same user key. The KDF settings come from a fresh
    /// login so they always match the wrapped key that is stored with them.
    /// </summary>
    private async Task RefreshAccountAsync(AccountInfo account, SymmetricKey userKey, SyncResponse sync, CancellationToken ct)
    {
        var wrapped = sync.Profile?.Key ?? account.ProtectedUserKey;
        var email = sync.Profile?.Email ?? account.Email;
        if (wrapped == account.ProtectedUserKey && email == account.Email) return;

        var token = await LoginAsync(account, userKey, ct).ConfigureAwait(false);
        var kdf = KdfOf(token);
        try
        {
            kdf.Validate();
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException)
        {
            return;
        }

        lock (_gate)
        {
            if (!ReferenceEquals(_account, account) || !ReferenceEquals(_userKey, userKey)) return;
            _account = account with { ProtectedUserKey = token.Key ?? wrapped, Email = email, Kdf = kdf };
            _store.SaveAccount(_account);
        }
    }

    private async Task<string> GetAccessTokenAsync(AccountInfo account, SymmetricKey userKey, CancellationToken ct)
    {
        if (_accessToken is { } cached && DateTimeOffset.UtcNow < _accessTokenExpiry) return cached;
        var token = await LoginAsync(account, userKey, ct).ConfigureAwait(false);
        return token.AccessToken;
    }

    private async Task<TokenResponse> LoginAsync(AccountInfo account, SymmetricKey userKey, CancellationToken ct)
    {
        var clientSecret = userKey.DecryptString(EncString.Parse(account.ProtectedClientSecret));
        var token = await _api.LoginAsync(new ApiCredentials(account.ClientId, clientSecret, account.DeviceId), ct)
            .ConfigureAwait(false);
        lock (_gate)
        {
            if (ReferenceEquals(_userKey, userKey))
            {
                _accessToken = token.AccessToken;
                _accessTokenExpiry = ExpiryOf(token);
            }
        }
        return token;
    }

    private static KdfConfig KdfOf(TokenResponse token) =>
        new((KdfType)token.Kdf, token.KdfIterations, token.KdfMemory, token.KdfParallelism);

    private static DateTimeOffset ExpiryOf(TokenResponse token) =>
        DateTimeOffset.UtcNow.AddSeconds(Math.Max(60, token.ExpiresIn - 60));

    public (string Code, int SecondsLeft)? GenerateTotp(string id, DateTimeOffset now)
    {
        var entry = _vault?.Find(id);
        return entry is null ? null : Vault.GenerateTotp(entry, now);
    }

    /// <summary>Reads the icon cache. It is encrypted with the user key, so like the vault it is unreadable while locked.</summary>
    public byte[]? LoadIconCache()
    {
        lock (_gate)
        {
            if (_userKey is not { } key || _store.LoadIcons() is not { } encrypted) return null;
            try
            {
                using var plain = key.Decrypt(encrypted);
                return plain.Span.ToArray();
            }
            catch (CryptographicException)
            {
                return null;
            }
        }
    }

    public void SaveIconCache(ReadOnlySpan<byte> data)
    {
        lock (_gate)
        {
            if (_userKey is { } key) _store.SaveIcons(key.Encrypt(data));
        }
    }

    public Secret? DecryptPassword(string id)
    {
        var entry = _vault?.Find(id);
        return entry is null ? null : Vault.DecryptPassword(entry);
    }

    /// <summary>Re-derives the master key and checks it unwraps to the user key this vault is unlocked with.</summary>
    public bool VerifyMasterPassword(Secret password)
    {
        var account = _account;
        var userKey = _userKey;
        if (account is null || userKey is null) return false;
        try
        {
            using var masterKey = Kdf.DeriveMasterKey(password.Span, account.Email, account.Kdf);
            using var candidate = Kdf.DecryptUserKey(masterKey.Span, EncString.Parse(account.ProtectedUserKey));
            using var a = candidate.Export();
            using var b = userKey.Export();
            return CryptographicOperations.FixedTimeEquals(a.Span, b.Span);
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException or ObjectDisposedException)
        {
            return false;
        }
    }

    public void SignOut()
    {
        lock (_gate)
        {
            _store.Wipe();
            SwapVault(null, 0);
            ReplaceUserKey(null);
            _account = null;
            _accessToken = null;
            LastSync = null;
        }
        Changed?.Invoke();
    }

    private void ReplaceUserKey(SymmetricKey? key)
    {
        var old = _userKey;
        _userKey = key;
        if (!ReferenceEquals(old, key)) old?.Dispose();
    }

    private void SwapVault(Vault? vault, long revision)
    {
        var old = Interlocked.Exchange(ref _vault, vault);
        _revision = revision;
        old?.Dispose();
    }

    public void Dispose()
    {
        _vault?.Dispose();
        _userKey?.Dispose();
        _syncLock.Dispose();
    }
}
