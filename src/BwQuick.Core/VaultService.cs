using System.Security.Cryptography;
using BwQuick.Core.Api;
using BwQuick.Core.Crypto;
using BwQuick.Core.Items;
using BwQuick.Core.Storage;

namespace BwQuick.Core;

public sealed class SetupException(string message, Exception? inner = null) : Exception(message, inner);

public sealed class VaultService : IDisposable
{
    private readonly SecureStore _store;
    private readonly BitwardenApi _api;
    private readonly SemaphoreSlim _syncLock = new(1, 1);

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

    public bool IsConfigured => _store.HasAccount;
    public bool IsUnlocked => _vault is not null;
    public bool NeedsSetup { get; private set; }
    public Vault? Current => _vault;
    public DateTimeOffset? LastSync { get; private set; }
    public string? LastError { get; private set; }

    /// <summary>Unlocks using the DPAPI-protected user key and the cached vault. No network needed.</summary>
    public void UnlockFromDisk()
    {
        var (info, key) = _store.LoadAccount();
        _account = info;
        ReplaceUserKey(key);

        if (_store.LoadVault() is { } cached)
        {
            try
            {
                SwapVault(Vault.Load(BitwardenApi.ParseSync(cached.SyncJson), key), cached.Revision);
            }
            catch (Exception e) when (e is CryptographicException or System.Text.Json.JsonException or InvalidDataException)
            {
                _revision = 0;
            }
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

        progress?.Report("Signing in to bitwarden.com…");
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
            throw new SetupException("Cannot reach bitwarden.com. Check your internet connection.", e);
        }

        if (token.ApiUseKeyConnector)
            throw new SetupException("This account uses Key Connector instead of a master password, which is not supported.");

        progress?.Report("Fetching vault…");
        var revision = await _api.GetRevisionDateAsync(token.AccessToken, ct).ConfigureAwait(false);
        var json = await _api.SyncAsync(token.AccessToken, ct).ConfigureAwait(false);
        var sync = BitwardenApi.ParseSync(json);

        var email = sync.Profile?.Email ?? throw new SetupException("The profile has no email address.");
        var protectedUserKey = token.Key ?? sync.Profile?.Key ?? throw new SetupException("No vault key received.");
        var kdf = new KdfConfig((KdfType)token.Kdf, token.KdfIterations, token.KdfMemory, token.KdfParallelism);

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
        try
        {
            vault = Vault.Load(sync, userKey);
        }
        catch
        {
            userKey.Dispose();
            throw;
        }

        var account = new AccountInfo(credentials.ClientId, credentials.ClientSecret, credentials.DeviceId, email, kdf, protectedUserKey);
        _store.SaveAccount(account, userKey);
        _store.SaveVault(revision, json);

        _account = account;
        _accessToken = token.AccessToken;
        _accessTokenExpiry = DateTimeOffset.UtcNow.AddSeconds(token.ExpiresIn - 60);
        NeedsSetup = false;
        ReplaceUserKey(userKey);
        SwapVault(vault, revision);
        LastSync = DateTimeOffset.Now;
        LastError = null;
        Changed?.Invoke();
    }

    /// <summary>Checks the account revision and only downloads the vault when something changed.</summary>
    public async Task SyncAsync(bool force = false, CancellationToken ct = default)
    {
        if (_account is null || _userKey is null) return;
        if (!await _syncLock.WaitAsync(0, ct).ConfigureAwait(false)) return;
        try
        {
            var token = await GetAccessTokenAsync(ct).ConfigureAwait(false);
            long revision;
            try
            {
                revision = await _api.GetRevisionDateAsync(token, ct).ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException)
            {
                _accessToken = null;
                token = await GetAccessTokenAsync(ct).ConfigureAwait(false);
                revision = await _api.GetRevisionDateAsync(token, ct).ConfigureAwait(false);
            }

            if (force || revision != _revision || _vault is null)
            {
                var json = await _api.SyncAsync(token, ct).ConfigureAwait(false);
                var sync = BitwardenApi.ParseSync(json);
                Vault vault;
                try
                {
                    vault = Vault.Load(sync, _userKey);
                }
                catch (CryptographicException)
                {
                    NeedsSetup = true;
                    throw new SetupException("Your vault key has changed. Set up BwQuick again.");
                }
                // A master password change re-wraps the same user key; keep the new wrap for reprompt checks.
                if (sync.Profile?.Key is { } wrapped && wrapped != _account.ProtectedUserKey)
                {
                    _account = _account with { ProtectedUserKey = wrapped };
                    _store.SaveAccount(_account, _userKey);
                }
                _store.SaveVault(revision, json);
                SwapVault(vault, revision);
            }

            LastSync = DateTimeOffset.Now;
            LastError = null;
        }
        catch (BitwardenAuthException)
        {
            NeedsSetup = true;
            LastError = "The API key was revoked or changed. Set up BwQuick again.";
        }
        catch (SetupException e)
        {
            LastError = e.Message;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            LastError = "Offline – showing the last synced vault";
        }
        finally
        {
            _syncLock.Release();
            Changed?.Invoke();
        }
    }

    private async Task<string> GetAccessTokenAsync(CancellationToken ct)
    {
        if (_accessToken is not null && DateTimeOffset.UtcNow < _accessTokenExpiry) return _accessToken;
        var account = _account!;
        var token = await _api.LoginAsync(new ApiCredentials(account.ClientId, account.ClientSecret, account.DeviceId), ct)
            .ConfigureAwait(false);
        _accessToken = token.AccessToken;
        _accessTokenExpiry = DateTimeOffset.UtcNow.AddSeconds(Math.Max(60, token.ExpiresIn - 60));
        return _accessToken;
    }

    public Secret? DecryptPassword(string id)
    {
        var entry = _vault?.Find(id);
        return entry is null ? null : Vault.DecryptPassword(entry);
    }

    /// <summary>Re-derives the master key and checks it unwraps the stored user key.</summary>
    public bool VerifyMasterPassword(Secret password)
    {
        if (_account is null) return false;
        try
        {
            using var masterKey = Kdf.DeriveMasterKey(password.Span, _account.Email, _account.Kdf);
            using var key = Kdf.DecryptUserKey(masterKey.Span, EncString.Parse(_account.ProtectedUserKey));
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public void SignOut()
    {
        _store.Wipe();
        _vault?.Dispose();
        _vault = null;
        _userKey?.Dispose();
        _userKey = null;
        _account = null;
        _accessToken = null;
        _revision = 0;
        LastSync = null;
        Changed?.Invoke();
    }

    private void ReplaceUserKey(SymmetricKey key)
    {
        var old = _userKey;
        _userKey = key;
        if (!ReferenceEquals(old, key)) old?.Dispose();
    }

    private void SwapVault(Vault vault, long revision)
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
