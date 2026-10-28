using System.Security.Cryptography;

namespace BitwardenQuick.Core.Crypto;

/// <summary>
/// A Bitwarden symmetric key: either a legacy 32-byte AES key, or 64 bytes of
/// AES-256 encryption key followed by an HMAC-SHA256 key. Kept sealed with
/// CryptProtectMemory and only unsealed for the duration of a single operation.
/// </summary>
public sealed class SymmetricKey : IDisposable
{
    private readonly byte[] _sealed;
    private bool _disposed;

    public int Length { get; }

    public SymmetricKey(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (32 or 64))
            throw new CryptographicException($"Invalid symmetric key length {key.Length}.");
        Length = key.Length;
        _sealed = GC.AllocateArray<byte>(key.Length, pinned: true);
        key.CopyTo(_sealed);
        MemoryProtection.Protect(_sealed);
    }

    public static SymmetricKey Generate()
    {
        Span<byte> bytes = stackalloc byte[64];
        RandomNumberGenerator.Fill(bytes);
        try { return new SymmetricKey(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private Secret Unseal()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var raw = new Secret(Length);
        _sealed.CopyTo(raw.Buffer, 0);
        MemoryProtection.Unprotect(raw.Buffer);
        return raw;
    }

    internal Secret Export() => Unseal();

    public Secret Decrypt(EncString enc)
    {
        using var raw = Unseal();
        var key = raw.Span;

        switch (enc.Type)
        {
            case EncType.AesCbc256_B64:
                if (Length != 32)
                    throw new CryptographicException("Unauthenticated ciphertext is only accepted with a legacy key.");
                return AesDecrypt(key, enc);

            case EncType.AesCbc256_HmacSha256_B64:
                if (Length != 64)
                    throw new CryptographicException("Authenticated ciphertext requires a key with a MAC key.");
                Span<byte> mac = stackalloc byte[32];
                using (var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key[32..]))
                {
                    hmac.AppendData(enc.Iv);
                    hmac.AppendData(enc.Data);
                    hmac.GetHashAndReset(mac);
                }
                if (!CryptographicOperations.FixedTimeEquals(mac, enc.Mac))
                    throw new CryptographicException("MAC verification failed.");
                return AesDecrypt(key[..32], enc);

            default:
                throw new CryptographicException($"Encryption type {(int)enc.Type} is not symmetric.");
        }
    }

    private static Secret AesDecrypt(ReadOnlySpan<byte> encKey, EncString enc)
    {
        if (enc.Iv.Length != 16 || enc.Data.Length == 0 || enc.Data.Length % 16 != 0)
            throw new CryptographicException("Malformed AES-CBC ciphertext.");

        var keyCopy = GC.AllocateArray<byte>(32, pinned: true);
        try
        {
            encKey.CopyTo(keyCopy);
            using var aes = Aes.Create();
            aes.Key = keyCopy;
            var output = new Secret(enc.Data.Length);
            try
            {
                var written = aes.DecryptCbc(enc.Data, enc.Iv, output.Buffer, PaddingMode.PKCS7);
                return output.Truncate(written);
            }
            catch
            {
                output.Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyCopy);
        }
    }

    public EncString Encrypt(ReadOnlySpan<byte> plaintext)
    {
        if (Length != 64) throw new CryptographicException("Encryption requires a key with a MAC key.");
        using var raw = Unseal();
        var key = raw.Span;

        var iv = RandomNumberGenerator.GetBytes(16);
        var keyCopy = GC.AllocateArray<byte>(32, pinned: true);
        try
        {
            key[..32].CopyTo(keyCopy);
            using var aes = Aes.Create();
            aes.Key = keyCopy;
            var data = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key[32..]);
            hmac.AppendData(iv);
            hmac.AppendData(data);
            var mac = hmac.GetHashAndReset();
            return EncString.Parse($"2.{Convert.ToBase64String(iv)}|{Convert.ToBase64String(data)}|{Convert.ToBase64String(mac)}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyCopy);
        }
    }

    /// <summary>Unwraps a user, organization or item key; only 64-byte keys are valid there.</summary>
    public SymmetricKey DecryptKey(EncString enc)
    {
        using var plain = Decrypt(enc);
        if (plain.Length != 64) throw new CryptographicException("Decrypted key has an unexpected length.");
        return new SymmetricKey(plain.Span);
    }

    public string DecryptString(EncString enc)
    {
        using var plain = Decrypt(enc);
        return plain.ToUnprotectedString();
    }

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_sealed);
        _disposed = true;
    }
}
