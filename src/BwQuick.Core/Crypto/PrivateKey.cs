using System.Security.Cryptography;

namespace BwQuick.Core.Crypto;

/// <summary>The account's RSA private key, used to unwrap organization keys.</summary>
public sealed class PrivateKey : IDisposable
{
    private readonly RSA _rsa;

    private PrivateKey(RSA rsa) => _rsa = rsa;

    public static PrivateKey ImportPkcs8(ReadOnlySpan<byte> der)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportPkcs8PrivateKey(der, out _);
            return new PrivateKey(rsa);
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    public Secret Decrypt(EncString enc)
    {
        var padding = enc.Type switch
        {
            EncType.Rsa2048_OaepSha256_B64 or EncType.Rsa2048_OaepSha256_HmacSha256_B64 => RSAEncryptionPadding.OaepSHA256,
            EncType.Rsa2048_OaepSha1_B64 or EncType.Rsa2048_OaepSha1_HmacSha256_B64 => RSAEncryptionPadding.OaepSHA1,
            _ => throw new CryptographicException($"Encryption type {(int)enc.Type} is not asymmetric."),
        };

        var output = new Secret(_rsa.KeySize / 8);
        try
        {
            if (!_rsa.TryDecrypt(enc.Data, output.Buffer, padding, out var written))
                throw new CryptographicException("RSA decryption failed.");
            return output.Truncate(written);
        }
        catch
        {
            output.Dispose();
            throw;
        }
    }

    public SymmetricKey DecryptKey(EncString enc)
    {
        using var plain = Decrypt(enc);
        if (plain.Length != 64) throw new CryptographicException("Decrypted key has an unexpected length.");
        return new SymmetricKey(plain.Span);
    }

    public void Dispose() => _rsa.Dispose();
}
