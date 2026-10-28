using System.Security.Cryptography;
using System.Text;
using BitwardenQuick.Core.Crypto;

namespace BitwardenQuick.Core.Tests;

/// <summary>Vectors copied from bitwarden/sdk-internal crates/bitwarden-crypto tests.</summary>
public class CryptoVectorTests
{
    private static readonly byte[] Pbkdf2MasterKey =
    [
        31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167,
        69, 167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
    ];

    [Fact]
    public void Pbkdf2_matches_sdk_vector()
    {
        using var key = Kdf.DeriveMasterKey("67t9b5g67$%Dh89n"u8, "test_key", new KdfConfig(KdfType.Pbkdf2, 10000));
        Assert.Equal(Pbkdf2MasterKey, key.Span.ToArray());
    }

    [Fact]
    public void Argon2id_matches_sdk_vector()
    {
        using var key = Kdf.DeriveMasterKey("67t9b5g67$%Dh89n"u8, "test_key", new KdfConfig(KdfType.Argon2id, 4, 32, 2));
        byte[] expected =
        [
            207, 240, 225, 177, 162, 19, 163, 76, 98, 106, 179, 175, 224, 9, 17, 240, 20, 147,
            237, 47, 246, 150, 141, 184, 62, 225, 131, 242, 51, 53, 225, 242,
        ];
        Assert.Equal(expected, key.Span.ToArray());
    }

    [Fact]
    public void Stretch_matches_sdk_vector()
    {
        using var stretched = Kdf.StretchMasterKey(Pbkdf2MasterKey);
        using var raw = stretched.Export();
        byte[] enc =
        [
            111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135, 173, 195, 23, 142,
            134, 120, 249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96,
        ];
        byte[] mac =
        [
            221, 127, 206, 234, 101, 27, 202, 38, 86, 52, 34, 28, 78, 28, 185, 16, 48, 61, 127,
            166, 209, 247, 194, 87, 232, 26, 48, 85, 193, 249, 179, 155,
        ];
        Assert.Equal(enc, raw.Span[..32].ToArray());
        Assert.Equal(mac, raw.Span[32..].ToArray());
    }

    [Fact]
    public void Legacy_type0_user_key_decrypts_with_raw_master_key()
    {
        var masterKey = Convert.FromBase64String("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe08=");
        var enc = EncString.Parse("0.tn/heK4HLbbEe+yEkC+kvw==|8QM94f7aVTtjm/bmvRdVxOxiLiiZtHYYO7+oBdjFCkilncesx0iVrXPl+tMKqW+Jo7+FtZdPNsTrL6RdoG7i5QbCRVwK+9010+xm7MTQY8s=");

        using var userKey = Kdf.DecryptUserKey(masterKey, enc);
        using var raw = userKey.Export();
        byte[] expectedEnc = [116, 170, 187, 43, 80, 212, 193, 202, 234, 181, 57, 66, 151, 249, 59, 47, 70, 16, 57, 4, 170, 78, 85, 241, 152, 232, 91, 57, 9, 87, 209, 245];
        byte[] expectedMac = [40, 245, 106, 140, 2, 225, 138, 213, 98, 223, 92, 168, 135, 208, 22, 194, 31, 21, 178, 252, 203, 198, 35, 174, 53, 218, 254, 151, 235, 57, 7, 98];
        Assert.Equal(expectedEnc, raw.Span[..32].ToArray());
        Assert.Equal(expectedMac, raw.Span[32..].ToArray());
    }

    [Fact]
    public void Legacy_account_full_password_to_user_key()
    {
        using var masterKey = Kdf.DeriveMasterKey("asdfasdfasdf"u8, "legacy@bitwarden.com", new KdfConfig(KdfType.Pbkdf2, 600000));
        var enc = EncString.Parse("0.8UClLa8IPE1iZT7chy5wzQ==|6PVfHnVk5S3XqEtQemnM5yb4JodxmPkkWzmDRdfyHtjORmvxqlLX40tBJZ+CKxQWmS8tpEB5w39rbgHg/gqs0haGdZG4cPbywsgGzxZ7uNI=");

        using var userKey = Kdf.DecryptUserKey(masterKey.Span, enc);
        using var raw = userKey.Export();
        byte[] expectedEnc = [12, 95, 151, 203, 37, 4, 236, 67, 137, 97, 90, 58, 6, 127, 242, 28, 209, 168, 125, 29, 118, 24, 213, 44, 117, 202, 2, 115, 132, 165, 125, 148];
        byte[] expectedMac = [186, 215, 234, 137, 24, 169, 227, 29, 218, 57, 180, 237, 73, 91, 189, 51, 253, 26, 17, 52, 226, 4, 134, 75, 194, 208, 178, 133, 128, 224, 140, 167];
        Assert.Equal(expectedEnc, raw.Span[..32].ToArray());
        Assert.Equal(expectedMac, raw.Span[32..].ToArray());
    }

    [Fact]
    public void Salt_is_trimmed_and_lowercased()
    {
        var cfg = new KdfConfig(KdfType.Pbkdf2, 5000);
        using var a = Kdf.DeriveMasterKey("asdfasdf"u8, "test@bitwarden.com", cfg);
        using var b = Kdf.DeriveMasterKey("asdfasdf"u8, " TEST@bitwarden.com ", cfg);
        Assert.Equal(a.Span.ToArray(), b.Span.ToArray());
    }

    [Fact]
    public void Rsa_oaep_sha1_org_key_decrypts_to_64_byte_key()
    {
        using var privateKey = PrivateKey.ImportPkcs8(TestKeys.SdkRsaPrivateKeyDer);
        var enc = EncString.Parse(TestKeys.SdkRsaEncString);
        using var key = privateKey.DecryptKey(enc);
        Assert.Equal(64, key.Length);
    }

    [Fact]
    public void Type2_round_trip_and_tamper_detection()
    {
        using var key = SymmetricKey.Generate();
        var enc = key.Encrypt("hunter2"u8);
        Assert.Equal(EncType.AesCbc256_HmacSha256_B64, enc.Type);
        Assert.Equal("hunter2", key.DecryptString(EncString.Parse(enc.ToString())));

        var tampered = enc.ToString().ToCharArray();
        var dataStart = tampered.AsSpan().IndexOf('|') + 2;
        tampered[dataStart] = tampered[dataStart] == 'A' ? 'B' : 'A';
        Assert.Throws<CryptographicException>(() => key.DecryptString(EncString.Parse(new string(tampered))));

        using var other = SymmetricKey.Generate();
        Assert.Throws<CryptographicException>(() => other.DecryptString(enc));
    }

    [Fact]
    public void Unauthenticated_ciphertext_is_rejected_by_mac_key()
    {
        using var key = SymmetricKey.Generate();
        var enc = EncString.Parse("0.tn/heK4HLbbEe+yEkC+kvw==|8QM94f7aVTtjm/bmvRdVxOxiLiiZtHYYO7+oBdjFCkilncesx0iVrXPl+tMKqW+Jo7+FtZdPNsTrL6RdoG7i5QbCRVwK+9010+xm7MTQY8s=");
        Assert.Throws<CryptographicException>(() => key.Decrypt(enc));
    }

    [Theory]
    [InlineData(KdfType.Pbkdf2, 1000, null, null)]
    [InlineData(KdfType.Argon2id, 1, 64, 4)]
    [InlineData(KdfType.Argon2id, 3, 8, 4)]
    [InlineData(KdfType.Argon2id, 3, 64, 0)]
    public void Weak_kdf_parameters_are_rejected(KdfType type, int iterations, int? memory, int? parallelism)
    {
        Assert.Throws<CryptographicException>(() => new KdfConfig(type, iterations, memory, parallelism).Validate());
    }

    [Fact]
    public void Unsupported_types_fail_loudly()
    {
        Assert.Throws<NotSupportedException>(() => EncString.Parse("7.AAAA"));
        Assert.Throws<CryptographicException>(() => EncString.Parse("2.notbase64|x|y"));
    }

    [Fact]
    public void Unwrapped_keys_must_be_64_bytes()
    {
        using var key = SymmetricKey.Generate();
        var wrapped = key.Encrypt(new byte[32]);
        Assert.Throws<CryptographicException>(() => key.DecryptKey(wrapped));
    }

    [Fact]
    public void Secret_zeroes_on_dispose()
    {
        var secret = Secret.FromChars("secret".AsSpan());
        var buffer = secret.Buffer;
        Assert.Equal("secret", Encoding.UTF8.GetString(secret.Span));
        secret.Dispose();
        Assert.All(buffer, b => Assert.Equal(0, b));
    }
}
