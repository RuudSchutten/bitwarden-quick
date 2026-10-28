using System.Security.Cryptography;

namespace BitwardenQuick.Core.Crypto;

public enum EncType
{
    AesCbc256_B64 = 0,
    AesCbc128_HmacSha256_B64 = 1,
    AesCbc256_HmacSha256_B64 = 2,
    Rsa2048_OaepSha256_B64 = 3,
    Rsa2048_OaepSha1_B64 = 4,
    Rsa2048_OaepSha256_HmacSha256_B64 = 5,
    Rsa2048_OaepSha1_HmacSha256_B64 = 6,
    Cose_Encrypt0_B64 = 7,
}

public sealed class EncString
{
    public EncType Type { get; }
    public byte[] Iv { get; }
    public byte[] Data { get; }
    public byte[] Mac { get; }

    private EncString(EncType type, byte[] iv, byte[] data, byte[] mac)
    {
        Type = type;
        Iv = iv;
        Data = data;
        Mac = mac;
    }

    public bool IsSymmetric => Type is EncType.AesCbc256_B64 or EncType.AesCbc256_HmacSha256_B64;

    public static EncString? ParseOrNull(string? value) =>
        string.IsNullOrEmpty(value) ? null : Parse(value);

    public static EncString Parse(string value)
    {
        EncType type;
        string body;
        var dot = value.IndexOf('.');
        if (dot > 0 && int.TryParse(value.AsSpan(0, dot), out var t))
        {
            type = (EncType)t;
            body = value[(dot + 1)..];
        }
        else
        {
            body = value;
            type = value.Split('|').Length == 3 ? EncType.AesCbc128_HmacSha256_B64 : EncType.AesCbc256_B64;
        }

        var parts = body.Split('|');
        try
        {
            return type switch
            {
                EncType.AesCbc256_B64 when parts.Length == 2 =>
                    new EncString(type, Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]), []),
                EncType.AesCbc256_HmacSha256_B64 when parts.Length == 3 =>
                    new EncString(type, Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]), Convert.FromBase64String(parts[2])),
                EncType.Rsa2048_OaepSha256_B64 or EncType.Rsa2048_OaepSha1_B64 when parts.Length == 1 =>
                    new EncString(type, [], Convert.FromBase64String(parts[0]), []),
                EncType.Rsa2048_OaepSha256_HmacSha256_B64 or EncType.Rsa2048_OaepSha1_HmacSha256_B64 when parts.Length == 2 =>
                    new EncString(type, [], Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1])),
                EncType.AesCbc128_HmacSha256_B64 or EncType.Cose_Encrypt0_B64 =>
                    throw new NotSupportedException($"Encryption type {(int)type} is not supported."),
                _ => throw new CryptographicException($"Malformed encrypted string (type {(int)type})."),
            };
        }
        catch (FormatException e)
        {
            throw new CryptographicException("Malformed encrypted string.", e);
        }
    }

    public override string ToString() => Type switch
    {
        EncType.AesCbc256_B64 => $"0.{Convert.ToBase64String(Iv)}|{Convert.ToBase64String(Data)}",
        EncType.AesCbc256_HmacSha256_B64 => $"2.{Convert.ToBase64String(Iv)}|{Convert.ToBase64String(Data)}|{Convert.ToBase64String(Mac)}",
        _ when Mac.Length > 0 => $"{(int)Type}.{Convert.ToBase64String(Data)}|{Convert.ToBase64String(Mac)}",
        _ => $"{(int)Type}.{Convert.ToBase64String(Data)}",
    };
}
