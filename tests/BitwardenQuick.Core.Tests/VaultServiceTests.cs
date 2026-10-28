using System.Security.Cryptography;
using System.Text;
using BitwardenQuick.Core.Api;
using BitwardenQuick.Core.Crypto;
using BitwardenQuick.Core.Items;
using BitwardenQuick.Core.Storage;

namespace BitwardenQuick.Core.Tests;

public sealed class VaultServiceTests : IDisposable
{
    private const string MasterPassword = "Correct Horse Battery 1!";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "bitwardenquick-tests-" + Guid.NewGuid().ToString("N"));
    private readonly FakeBitwarden _server;

    public VaultServiceTests()
    {
        _server = new FakeBitwarden(MasterPassword, new KdfConfig(KdfType.Pbkdf2, 5000));

        using var cipherKey = SymmetricKey.Generate();
        string wrappedCipherKey;
        using (var raw = cipherKey.Export()) wrappedCipherKey = _server.UserKey.Encrypt(raw.Span).ToString();

        _server.AddLogin("c1", _server.UserKey, "GitHub", "ruud", "gh-pass", "https://www.github.com/login", favorite: true);
        _server.AddLogin("c2", cipherKey, "Zoom - Personal", "ruud@example.com", "zoom-pass", "zoom.example", cipherKey: wrappedCipherKey);
        _server.AddLogin("c3", _server.OrgKey, "Azure Portal", "ruud@contoso.example", "az-pass", "https://portal.azure.com", orgId: FakeBitwarden.OrgId, reprompt: 1);
        _server.AddLogin("c4", _server.UserKey, "Deleted", "x", "x", null, deletedDate: DateTime.UtcNow);
        _server.AddLogin("c5", _server.UserKey, "A note", null, null, null, type: 2);
        using (var stranger = SymmetricKey.Generate())
            _server.AddLogin("c6", stranger, "Corrupt", "x", "x", null);
    }

    private VaultService NewService(string identity = "https://identity.test/") =>
        new(new SecureStore(_dir), new BitwardenApi(new Uri(identity), new Uri("https://api.test/"), _server));

    private async Task<VaultService> SetUpService()
    {
        var service = NewService();
        using var pw = Secret.FromChars(MasterPassword.AsSpan());
        await service.SetupAsync(FakeBitwarden.ClientId, FakeBitwarden.ClientSecret, pw);
        return service;
    }

    private static bool Unlock(VaultService service, string password)
    {
        using var pw = Secret.FromChars(password.AsSpan());
        return service.UnlockWithMasterPassword(pw);
    }

    private static bool Verify(VaultService service, string password)
    {
        using var pw = Secret.FromChars(password.AsSpan());
        return service.VerifyMasterPassword(pw);
    }

    private static string Password(VaultService service, string id)
    {
        using var secret = service.DecryptPassword(id)!;
        return secret.ToUnprotectedString();
    }

    [Fact]
    public async Task Switching_server_forgets_the_account_in_memory_but_keeps_the_stored_one()
    {
        using (var service = await SetUpService())
        {
            service.UseServer(new BitwardenApi(BitwardenServer.Europe, _server));
            Assert.False(service.IsConfigured);
            Assert.False(service.IsUnlocked);
            Assert.Null(service.Current);
            Assert.Equal("bitwarden.eu", service.ServerName);

            var e = Assert.Throws<SetupException>(service.LoadAccount);
            Assert.Contains("identity.test", e.Message);
        }

        using var restarted = NewService();
        restarted.LoadAccount();
        Assert.True(Unlock(restarted, MasterPassword));
    }

    [Fact]
    public async Task Generates_one_time_passwords_from_the_items_authenticator_key()
    {
        _server.AddLogin("t1", _server.UserKey, "With TOTP", "me", "pw", "https://totp.test",
            totp: "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8");
        _server.AddLogin("t2", _server.UserKey, "Broken TOTP", "me", "pw", null, totp: "not a key!");
        using var service = await SetUpService();

        Assert.True(service.Current!.Find("t1")!.HasTotp);
        Assert.False(service.Current!.Find("c1")!.HasTotp);
        Assert.Equal(("94287082", 1), service.GenerateTotp("t1", DateTimeOffset.FromUnixTimeSeconds(59)));
        Assert.Null(service.GenerateTotp("t2", DateTimeOffset.UtcNow));
        Assert.Null(service.GenerateTotp("c1", DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task Icon_cache_is_encrypted_with_the_user_key_and_only_readable_while_unlocked()
    {
        var data = Encoding.UTF8.GetBytes("github.com icon bytes");
        using (var service = await SetUpService())
        {
            service.SaveIconCache(data);
            Assert.Equal(data, service.LoadIconCache());
            service.Lock();
            Assert.Null(service.LoadIconCache());
            service.SaveIconCache([1, 2, 3]);
        }

        var stored = ProtectedData.Unprotect(File.ReadAllBytes(Path.Combine(_dir, "icons.dat")), SecureStore.Entropy, DataProtectionScope.CurrentUser);
        Assert.DoesNotContain("github.com", Encoding.UTF8.GetString(stored));

        using var restarted = NewService();
        restarted.LoadAccount();
        Assert.True(Unlock(restarted, MasterPassword));
        Assert.Equal(data, restarted.LoadIconCache());

        restarted.SignOut();
        Assert.False(File.Exists(Path.Combine(_dir, "icons.dat")));
    }

    [Fact]
    public async Task Setup_rejects_wrong_master_password_and_stores_nothing()
    {
        using var service = NewService();
        using var wrong = Secret.FromChars("nope".AsSpan());
        var e = await Assert.ThrowsAsync<SetupException>(() => service.SetupAsync(FakeBitwarden.ClientId, FakeBitwarden.ClientSecret, wrong));
        Assert.Contains("master password", e.Message);
        Assert.False(service.IsConfigured);
    }

    [Fact]
    public async Task Setup_rejects_bad_api_key()
    {
        using var service = NewService();
        using var pw = Secret.FromChars(MasterPassword.AsSpan());
        await Assert.ThrowsAsync<SetupException>(() => service.SetupAsync(FakeBitwarden.ClientId, "wrong", pw));
    }

    [Fact]
    public async Task Setup_decrypts_personal_cipher_key_and_org_items()
    {
        using var service = NewService();
        using var pw = Secret.FromChars(MasterPassword.AsSpan());
        await service.SetupAsync(FakeBitwarden.ClientId, FakeBitwarden.ClientSecret, pw);

        var vault = service.Current!;
        Assert.Equal(["Azure Portal", "GitHub", "Zoom - Personal"], vault.Entries.Select(e => e.Name));
        Assert.Equal(1, vault.SkippedItems);

        var github = vault.Find("c1")!;
        Assert.Equal("github.com", github.Host);
        Assert.Equal("ruud", github.Username);
        Assert.Equal("gh-pass", Password(service, "c1"));
        Assert.Equal("zoom-pass", Password(service, "c2"));

        var azure = vault.Find("c3")!;
        Assert.Equal("Contoso", azure.OrganizationName);
        Assert.True(azure.Reprompt);
        Assert.Equal("az-pass", Password(service, "c3"));

        Assert.True(service.VerifyMasterPassword(pw));
        using var wrong = Secret.FromChars("nope".AsSpan());
        Assert.False(service.VerifyMasterPassword(wrong));
    }

    [Fact]
    public async Task Restart_stays_locked_until_the_master_password_unlocks_it_offline()
    {
        (await SetUpService()).Dispose();

        _server.Offline = true;
        using var second = NewService();
        Assert.True(second.HasStoredAccount);
        second.LoadAccount();
        Assert.True(second.IsConfigured);
        Assert.False(second.IsUnlocked);
        Assert.Null(second.Current);
        Assert.Null(second.DecryptPassword("c1"));

        Assert.False(Unlock(second, "nope"));
        Assert.False(second.IsUnlocked);
        Assert.True(Unlock(second, MasterPassword));
        Assert.Equal(3, second.Current!.Entries.Count);
        Assert.Equal("gh-pass", Password(second, "c1"));

        await second.SyncAsync();
        Assert.NotNull(second.LastError);
        Assert.Equal(3, second.Current!.Entries.Count);
    }

    [Fact]
    public async Task Windows_Hello_signature_unlocks_and_a_different_one_does_not()
    {
        var signature = RandomNumberGenerator.GetBytes(256);
        using (var first = await SetUpService())
        {
            Assert.Null(first.HelloChallenge);
            first.EnableHello(VaultService.NewHelloChallenge(), signature);
        }

        using var second = NewService();
        second.LoadAccount();
        Assert.NotNull(second.HelloChallenge);
        Assert.False(second.UnlockWithHello(RandomNumberGenerator.GetBytes(256)));
        Assert.False(second.IsUnlocked);
        Assert.True(second.UnlockWithHello(signature));
        Assert.Equal("gh-pass", Password(second, "c1"));
    }

    [Fact]
    public async Task Lock_forgets_the_vault_and_stops_syncing()
    {
        using var service = await SetUpService();
        service.Lock();

        Assert.False(service.IsUnlocked);
        Assert.Null(service.Current);
        Assert.Null(service.DecryptPassword("c1"));
        Assert.False(Verify(service, MasterPassword));

        var tokenCalls = _server.TokenCalls;
        _server.Revision++;
        await service.SyncAsync(force: true);
        Assert.Equal(tokenCalls, _server.TokenCalls);
        Assert.Equal(1, _server.SyncCalls);

        Assert.True(Unlock(service, MasterPassword));
        Assert.Equal("gh-pass", Password(service, "c1"));
    }

    [Fact]
    public async Task Reprompt_rejects_a_password_for_a_key_the_server_swapped_in()
    {
        using var service = await SetUpService();
        using var forged = SymmetricKey.Generate();
        _server.Rewrap(forged, "attacker", new KdfConfig(KdfType.Pbkdf2, 5000));
        _server.Revision++;
        await service.SyncAsync();

        Assert.Null(service.LastError);
        Assert.False(Verify(service, "attacker"));
    }

    [Fact]
    public async Task Master_password_and_kdf_changes_are_picked_up_on_sync()
    {
        using (var service = await SetUpService())
        {
            _server.Rewrap(_server.UserKey, "New password 2!", new KdfConfig(KdfType.Argon2id, 3, 16, 2));
            _server.Revision++;
            await service.SyncAsync();

            Assert.Null(service.LastError);
            Assert.True(Verify(service, "New password 2!"));
            Assert.False(Verify(service, MasterPassword));
        }

        using var restarted = NewService();
        restarted.LoadAccount();
        Assert.True(Unlock(restarted, "New password 2!"));
    }

    [Fact]
    public async Task Account_from_another_server_is_not_used()
    {
        (await SetUpService()).Dispose();
        using var other = NewService("https://evil.test/");
        await Assert.ThrowsAsync<SetupException>(() => Task.Run(other.LoadAccount));
    }

    [Fact]
    public void Old_account_file_with_a_raw_key_is_deleted()
    {
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, "account.dat");
        File.WriteAllBytes(path, ProtectedData.Protect(BitConverter.GetBytes(1), SecureStore.Entropy, DataProtectionScope.CurrentUser));

        using var service = NewService();
        Assert.Throws<SetupException>(service.LoadAccount);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void Plain_http_servers_are_refused()
    {
        Assert.Throws<ArgumentException>(() => new BitwardenApi(new Uri("http://identity.test/"), new Uri("https://api.test/")));
    }

    [Fact]
    public async Task Sync_only_downloads_when_revision_changes()
    {
        using var service = NewService();
        using (var pw = Secret.FromChars(MasterPassword.AsSpan()))
            await service.SetupAsync(FakeBitwarden.ClientId, FakeBitwarden.ClientSecret, pw);
        Assert.Equal(1, _server.SyncCalls);

        await service.SyncAsync();
        Assert.Equal(1, _server.SyncCalls);
        Assert.Null(service.LastError);

        _server.AddLogin("c7", _server.UserKey, "New item", "n", "new-pass", null);
        _server.Revision++;
        await service.SyncAsync();
        Assert.Equal(2, _server.SyncCalls);
        Assert.Equal("new-pass", Password(service, "c7"));
    }

    [Fact]
    public async Task Stored_files_contain_no_plaintext()
    {
        using var service = NewService();
        using (var pw = Secret.FromChars(MasterPassword.AsSpan()))
            await service.SetupAsync(FakeBitwarden.ClientId, FakeBitwarden.ClientSecret, pw);

        foreach (var file in Directory.GetFiles(_dir))
        {
            var text = Encoding.Latin1.GetString(File.ReadAllBytes(file));
            foreach (var needle in new[] { "gh-pass", "GitHub", FakeBitwarden.ClientSecret, MasterPassword, "Example.com", "sync" })
                Assert.DoesNotContain(needle, text, StringComparison.OrdinalIgnoreCase);
        }

        var account = Encoding.Latin1.GetString(ProtectedData.Unprotect(
            File.ReadAllBytes(Path.Combine(_dir, "account.dat")), SecureStore.Entropy, DataProtectionScope.CurrentUser));
        Assert.DoesNotContain(FakeBitwarden.ClientSecret, account);
        Assert.DoesNotContain(MasterPassword, account);

        service.SignOut();
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public async Task Argon2id_accounts_work()
    {
        var server = new FakeBitwarden(MasterPassword, new KdfConfig(KdfType.Argon2id, 3, 16, 2));
        server.AddLogin("a1", server.UserKey, "Argon item", "u", "argon-pass", null);
        using var service = new VaultService(new SecureStore(_dir),
            new BitwardenApi(new Uri("https://identity.test/"), new Uri("https://api.test/"), server));
        using var pw = Secret.FromChars(MasterPassword.AsSpan());
        await service.SetupAsync(FakeBitwarden.ClientId, FakeBitwarden.ClientSecret, pw);
        Assert.Equal("argon-pass", Password(service, "a1"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }
}
