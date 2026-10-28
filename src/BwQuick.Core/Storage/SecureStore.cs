using System.Security.Cryptography;
using System.Text;
using BwQuick.Core.Crypto;

namespace BwQuick.Core.Storage;

public sealed record AccountInfo(
    string ClientId,
    string ClientSecret,
    Guid DeviceId,
    string Email,
    KdfConfig Kdf,
    string ProtectedUserKey);

/// <summary>
/// Persists account secrets and the encrypted vault cache under %LOCALAPPDATA%,
/// wrapped with DPAPI so only the current Windows user on this machine can read them.
/// </summary>
public sealed class SecureStore
{
    private const int AccountFormat = 1;
    private const int VaultFormat = 1;
    private static readonly byte[] Entropy = "BwQuick.v1.7f3c2e9a-3d4b-4a8e-9c1f-2b6d8e0a5c47"u8.ToArray();

    public string Directory { get; }
    private string AccountPath => Path.Combine(Directory, "account.dat");
    private string VaultPath => Path.Combine(Directory, "vault.dat");

    public SecureStore(string? directory = null)
    {
        Directory = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BwQuick");
        System.IO.Directory.CreateDirectory(Directory);
    }

    public bool HasAccount => File.Exists(AccountPath);

    public void SaveAccount(AccountInfo info, SymmetricKey userKey)
    {
        // Pre-sized so the buffer never regrows and leaves an unzeroed copy behind.
        using var stream = new MemoryStream(8192);
        using (var w = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            w.Write(AccountFormat);
            w.Write(info.ClientId);
            w.Write(info.ClientSecret);
            w.Write(info.DeviceId.ToByteArray());
            w.Write(info.Email);
            w.Write((int)info.Kdf.Type);
            w.Write(info.Kdf.Iterations);
            w.Write(info.Kdf.MemoryMiB ?? 0);
            w.Write(info.Kdf.Parallelism ?? 0);
            w.Write(info.ProtectedUserKey);
            using var raw = userKey.Export();
            w.Write(raw.Length);
            w.Write(raw.Span);
        }

        var buffer = stream.GetBuffer();
        try
        {
            WriteProtected(AccountPath, buffer.AsSpan(0, (int)stream.Length));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public (AccountInfo Info, SymmetricKey UserKey) LoadAccount()
    {
        var plain = ProtectedData.Unprotect(File.ReadAllBytes(AccountPath), Entropy, DataProtectionScope.CurrentUser);
        try
        {
            using var r = new BinaryReader(new MemoryStream(plain), Encoding.UTF8);
            if (r.ReadInt32() != AccountFormat) throw new InvalidDataException("Unknown account file format.");
            var clientId = r.ReadString();
            var clientSecret = r.ReadString();
            var deviceId = new Guid(r.ReadBytes(16));
            var email = r.ReadString();
            var kdfType = (KdfType)r.ReadInt32();
            var iterations = r.ReadInt32();
            var memory = r.ReadInt32();
            var parallelism = r.ReadInt32();
            var protectedUserKey = r.ReadString();
            var keyLength = r.ReadInt32();
            if (keyLength is not (32 or 64)) throw new InvalidDataException("Corrupt account file.");
            var key = new SymmetricKey(plain.AsSpan((int)r.BaseStream.Position, keyLength));

            var kdf = new KdfConfig(kdfType, iterations, memory == 0 ? null : memory, parallelism == 0 ? null : parallelism);
            return (new AccountInfo(clientId, clientSecret, deviceId, email, kdf, protectedUserKey), key);
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

    public void Wipe()
    {
        foreach (var path in new[] { AccountPath, VaultPath })
        {
            if (!File.Exists(path)) continue;
            var length = new FileInfo(path).Length;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
                fs.Write(new byte[length]);
            File.Delete(path);
        }
    }

    private static void WriteProtected(string path, ReadOnlySpan<byte> plain)
    {
        var copy = plain.ToArray();
        byte[] sealedBytes;
        try
        {
            sealedBytes = ProtectedData.Protect(copy, Entropy, DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }

        var temp = path + ".tmp";
        File.WriteAllBytes(temp, sealedBytes);
        File.Move(temp, path, overwrite: true);
    }
}
