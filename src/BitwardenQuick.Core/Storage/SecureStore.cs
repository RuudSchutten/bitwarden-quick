using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using BitwardenQuick.Core.Crypto;

namespace BitwardenQuick.Core.Storage;

/// <summary>
/// Everything needed to unlock and sync. The secrets in it are encrypted: the user key with the master key
/// (as Bitwarden stores it) and optionally with a Windows Hello key, the client secret with the user key.
/// </summary>
public sealed record AccountInfo(
    string Server,
    string ClientId,
    string ProtectedClientSecret,
    Guid DeviceId,
    string Email,
    KdfConfig Kdf,
    string ProtectedUserKey,
    byte[]? HelloChallenge = null,
    string? HelloProtectedUserKey = null);

public sealed class LegacyAccountException() : Exception("Account file from an older BitwardenQuick version.");

/// <summary>
/// Persists the account, the encrypted vault cache and the encrypted icon cache under %LOCALAPPDATA%, wrapped with DPAPI
/// so only the current Windows user on this machine can read them.
/// </summary>
public sealed class SecureStore
{
    private const int LegacyAccountFormat = 1;
    private const int AccountFormat = 2;
    private const int VaultFormat = 1;
    internal static readonly byte[] Entropy = "BitwardenQuick.v1.7f3c2e9a-3d4b-4a8e-9c1f-2b6d8e0a5c47"u8.ToArray();

    public string Directory { get; }
    private string AccountPath => Path.Combine(Directory, "account.dat");
    private string VaultPath => Path.Combine(Directory, "vault.dat");
    private string IconsPath => Path.Combine(Directory, "icons.dat");

    public SecureStore(string? directory = null)
    {
        Directory = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BitwardenQuick");
        RestrictToCurrentUser(Directory);
    }

    /// <summary>
    /// The folder may be moved anywhere with BITWARDENQUICK_DATA_DIR, where other Windows users could otherwise write
    /// settings.json or replace the data files. Refuses a folder someone else owns, and limits access to this user and SYSTEM.
    /// </summary>
    private static void RestrictToCurrentUser(string path)
    {
        var folder = new DirectoryInfo(path);
        if (!folder.Exists) folder.Create();
        folder.Refresh();
        if (folder.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new UnauthorizedAccessException($"The data folder {path} is a link to another location.");

        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new UnauthorizedAccessException("The current Windows user has no SID.");
        // An elevated administrator creates folders owned by the Administrators group, which is then the token's owner.
        var owner = folder.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier));
        if (owner != user && owner != identity.Owner)
            throw new UnauthorizedAccessException($"The data folder {path} belongs to another user.");

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { user, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }
        folder.SetAccessControl(security);
    }

    public bool HasAccount => File.Exists(AccountPath);

    public void SaveAccount(AccountInfo info)
    {
        using var stream = new MemoryStream();
        using (var w = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            w.Write(AccountFormat);
            w.Write(info.Server);
            w.Write(info.ClientId);
            w.Write(info.ProtectedClientSecret);
            w.Write(info.DeviceId.ToByteArray());
            w.Write(info.Email);
            w.Write((int)info.Kdf.Type);
            w.Write(info.Kdf.Iterations);
            w.Write(info.Kdf.MemoryMiB ?? 0);
            w.Write(info.Kdf.Parallelism ?? 0);
            w.Write(info.ProtectedUserKey);
            var hello = info is { HelloChallenge: not null, HelloProtectedUserKey: not null };
            w.Write(hello);
            if (hello)
            {
                w.Write(info.HelloChallenge!.Length);
                w.Write(info.HelloChallenge);
                w.Write(info.HelloProtectedUserKey!);
            }
        }
        WriteProtected(AccountPath, stream.ToArray());
    }

    public AccountInfo LoadAccount()
    {
        var plain = ProtectedData.Unprotect(File.ReadAllBytes(AccountPath), Entropy, DataProtectionScope.CurrentUser);
        try
        {
            using var r = new BinaryReader(new MemoryStream(plain), Encoding.UTF8);
            var format = r.ReadInt32();
            if (format == LegacyAccountFormat) throw new LegacyAccountException();
            if (format != AccountFormat) throw new InvalidDataException("Unknown account file format.");
            var server = r.ReadString();
            var clientId = r.ReadString();
            var protectedClientSecret = r.ReadString();
            var deviceId = new Guid(r.ReadBytes(16));
            var email = r.ReadString();
            var kdfType = (KdfType)r.ReadInt32();
            var iterations = r.ReadInt32();
            var memory = r.ReadInt32();
            var parallelism = r.ReadInt32();
            var protectedUserKey = r.ReadString();
            byte[]? helloChallenge = null;
            string? helloProtectedUserKey = null;
            if (r.ReadBoolean())
            {
                var length = r.ReadInt32();
                if (length is < 16 or > 256) throw new InvalidDataException("Corrupt account file.");
                helloChallenge = r.ReadBytes(length);
                helloProtectedUserKey = r.ReadString();
            }

            var kdf = new KdfConfig(kdfType, iterations, memory == 0 ? null : memory, parallelism == 0 ? null : parallelism);
            return new AccountInfo(server, clientId, protectedClientSecret, deviceId, email, kdf, protectedUserKey,
                helloChallenge, helloProtectedUserKey);
        }
        catch (EndOfStreamException e)
        {
            throw new InvalidDataException("Corrupt account file.", e);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>Caches the raw sync JSON. Its vault fields are already end-to-end encrypted.</summary>
    public void SaveVault(long revision, ReadOnlySpan<byte> syncJson)
    {
        var buffer = new byte[12 + syncJson.Length];
        BitConverter.TryWriteBytes(buffer.AsSpan(0, 4), VaultFormat);
        BitConverter.TryWriteBytes(buffer.AsSpan(4, 8), revision);
        syncJson.CopyTo(buffer.AsSpan(12));
        WriteProtected(VaultPath, buffer);
    }

    public (long Revision, byte[] SyncJson)? LoadVault()
    {
        if (!File.Exists(VaultPath)) return null;
        try
        {
            var plain = ProtectedData.Unprotect(File.ReadAllBytes(VaultPath), Entropy, DataProtectionScope.CurrentUser);
            if (plain.Length < 12 || BitConverter.ToInt32(plain, 0) != VaultFormat) return null;
            return (BitConverter.ToInt64(plain, 4), plain[12..]);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>Stores the icon cache, already encrypted with the user key, as iv | mac | ciphertext.</summary>
    public void SaveIcons(EncString encrypted)
    {
        var buffer = new byte[16 + 32 + encrypted.Data.Length];
        encrypted.Iv.CopyTo(buffer, 0);
        encrypted.Mac.CopyTo(buffer, 16);
        encrypted.Data.CopyTo(buffer, 48);
        WriteProtected(IconsPath, buffer);
    }

    public EncString? LoadIcons()
    {
        if (!File.Exists(IconsPath)) return null;
        try
        {
            var plain = ProtectedData.Unprotect(File.ReadAllBytes(IconsPath), Entropy, DataProtectionScope.CurrentUser);
            if (plain.Length < 48 + 16) return null;
            return EncString.Authenticated(plain[..16], plain[48..], plain[16..48]);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    public void Wipe()
    {
        foreach (var path in new[] { AccountPath, VaultPath, IconsPath, AccountPath + ".tmp", VaultPath + ".tmp", IconsPath + ".tmp" })
        {
            if (!File.Exists(path)) continue;
            var length = new FileInfo(path).Length;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
                fs.Write(new byte[length]);
            File.Delete(path);
        }
    }

    private static void WriteProtected(string path, byte[] plain)
    {
        var sealedBytes = ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
        var temp = path + ".tmp";
        File.WriteAllBytes(temp, sealedBytes);
        File.Move(temp, path, overwrite: true);
    }
}
