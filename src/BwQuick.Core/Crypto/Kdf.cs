using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace BwQuick.Core.Crypto;

public enum KdfType
{
    Pbkdf2 = 0,
    Argon2id = 1,
}

public sealed record KdfConfig(KdfType Type, int Iterations, int? MemoryMiB = null, int? Parallelism = null)
{
    /// <summary>
    /// Rejects parameters a compromised server could use to weaken the derivation, and
    /// absurd ones that would hang the machine. Minimums match Bitwarden's own clients.
    /// </summary>
    public void Validate()
    {
        switch (Type)
        {
            case KdfType.Pbkdf2:
                if (Iterations is < 5_000 or > 10_000_000)
                    throw new CryptographicException($"PBKDF2 iteration count {Iterations} is out of range.");
                break;
            case KdfType.Argon2id:
                if (Iterations is < 2 or > 100
                    || MemoryMiB is not (>= 16 and <= 1024)
                    || Parallelism is not (>= 1 and <= 16))
                    throw new CryptographicException("Argon2id parameters are out of range.");
                break;
            default:
                throw new NotSupportedException($"KDF type {(int)Type} is not supported.");
        }
    }
}

public static class Kdf
{
    public static string NormalizeSalt(string email) => email.Trim().ToLowerInvariant();

    public static Secret DeriveMasterKey(ReadOnlySpan<byte> password, string salt, KdfConfig config)
    {
        config.Validate();
        var saltBytes = Encoding.UTF8.GetBytes(NormalizeSalt(salt));
        var output = new Secret(32);

        if (config.Type == KdfType.Pbkdf2)
        {
            Rfc2898DeriveBytes.Pbkdf2(password, saltBytes, output.Buffer, config.Iterations, HashAlgorithmName.SHA256);
            return output;
        }

        var passwordCopy = Secret.Copy(password);
        try
        {
            var argon = new Argon2id(passwordCopy.Buffer)
            {
                Salt = SHA256.HashData(saltBytes),
                Iterations = config.Iterations,
                MemorySize = config.MemoryMiB!.Value * 1024,
                DegreeOfParallelism = config.Parallelism!.Value,
            };
            var hash = argon.GetBytes(32);
            hash.CopyTo(output.Buffer, 0);
            CryptographicOperations.ZeroMemory(hash);
            return output;
        }
        catch
        {
            output.Dispose();
            throw;
        }
        finally
        {
            passwordCopy.Dispose();
        }
    }

    public static SymmetricKey StretchMasterKey(ReadOnlySpan<byte> masterKey)
    {
        using var stretched = new Secret(64);
        HKDF.Expand(HashAlgorithmName.SHA256, masterKey, stretched.Buffer.AsSpan(0, 32), "enc"u8);
        HKDF.Expand(HashAlgorithmName.SHA256, masterKey, stretched.Buffer.AsSpan(32, 32), "mac"u8);
        return new SymmetricKey(stretched.Span);
    }

    public static SymmetricKey DecryptUserKey(ReadOnlySpan<byte> masterKey, EncString protectedUserKey)
    {
        using var wrappingKey = protectedUserKey.Type == EncType.AesCbc256_B64
            ? new SymmetricKey(masterKey)
            : StretchMasterKey(masterKey);
        var userKey = wrappingKey.DecryptKey(protectedUserKey);
        if (userKey.Length != 64)
        {
            userKey.Dispose();
            throw new CryptographicException("Decrypted user key has an unexpected length.");
        }
        return userKey;
    }
}
