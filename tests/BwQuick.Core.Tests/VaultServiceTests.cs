using System.Text;
using BwQuick.Core.Api;
using BwQuick.Core.Crypto;
using BwQuick.Core.Items;
using BwQuick.Core.Storage;

namespace BwQuick.Core.Tests;

public sealed class VaultServiceTests : IDisposable
{
    private const string MasterPassword = "Correct Horse Battery 1!";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "bwquick-tests-" + Guid.NewGuid().ToString("N"));
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

    private VaultService NewService() =>
        new(new SecureStore(_dir), new BitwardenApi(new Uri("https://identity.test/"), new Uri("https://api.test/"), _server));

    private static string Password(VaultService service, string id)
    {
        using var secret = service.DecryptPassword(id)!;
        return secret.ToUnprotectedString();
    }

    [Fact]
    public async Task Setup_rejects_wrong_master_password_and_stores_nothing()
    {
        using var service = NewService();
        using var wrong = Secret.FromChars("nope".AsSpan());
        var e = await Assert.ThrowsAsync<SetupException>(() => service.SetupAsync(FakeBitwarden.ClientId, FakeBitwarden.ClientSecret, wrong));
        Assert.Contains("hoofdwachtwoord", e.Message);
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
    public async Task Restart_unlocks_from_disk_without_network_or_master_password()
    {
        using (var first = NewService())
        using (var pw = Secret.FromChars(MasterPassword.AsSpan()))
            await first.SetupAsync(FakeBitwarden.ClientId, FakeBitwarden.ClientSecret, pw);

        _server.Offline = true;
        using var second = NewService();
        Assert.True(second.IsConfigured);
        second.UnlockFromDisk();
        Assert.Equal(3, second.Current!.Entries.Count);
        Assert.Equal("gh-pass", Password(second, "c1"));

        await second.SyncAsync();
        Assert.NotNull(second.LastError);
        Assert.Equal(3, second.Current!.Entries.Count);
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
