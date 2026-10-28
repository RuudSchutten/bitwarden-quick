using System.Security.Cryptography;

namespace BitwardenQuick.Core.Crypto;

/// <summary>
/// One-time passwords (RFC 6238) from the formats Bitwarden accepts for a login's authenticator key:
/// a base32 secret, an otpauth:// URI, or steam://.
/// </summary>
public static class Totp
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private const string SteamAlphabet = "23456789BCDFGHJKMNPQRTVWXY";

    /// <summary>The code for <paramref name="now"/> and the seconds it stays valid, or null when the key is not valid.</summary>
    public static (string Code, int SecondsLeft)? Generate(ReadOnlySpan<char> authenticatorKey, DateTimeOffset now)
    {
        var digits = 6;
        var period = 30;
        var algorithm = HashAlgorithmName.SHA1;
        var steam = false;
        ReadOnlySpan<char> secret;

        var value = authenticatorKey.Trim();
        if (value.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
        {
            var query = value.IndexOf('?');
            if (query < 0) return null;
            secret = default;
            foreach (var range in value[(query + 1)..].Split('&'))
            {
                var pair = value[(query + 1)..][range];
                var eq = pair.IndexOf('=');
                if (eq <= 0) continue;
                var name = pair[..eq];
                var arg = pair[(eq + 1)..];
                if (name.Equals("secret", StringComparison.OrdinalIgnoreCase)) secret = arg;
                else if (name.Equals("digits", StringComparison.OrdinalIgnoreCase) && int.TryParse(arg, out var d) && d is > 0 and <= 10) digits = d;
                else if (name.Equals("period", StringComparison.OrdinalIgnoreCase) && int.TryParse(arg, out var p) && p > 0) period = p;
                else if (name.Equals("algorithm", StringComparison.OrdinalIgnoreCase))
                {
                    if (arg.Equals("sha256", StringComparison.OrdinalIgnoreCase)) algorithm = HashAlgorithmName.SHA256;
                    else if (arg.Equals("sha512", StringComparison.OrdinalIgnoreCase)) algorithm = HashAlgorithmName.SHA512;
                }
                else if (name.Equals("encoder", StringComparison.OrdinalIgnoreCase) && arg.Equals("steam", StringComparison.OrdinalIgnoreCase)) steam = true;
            }
        }
        else if (value.StartsWith("steam://", StringComparison.OrdinalIgnoreCase))
        {
            secret = value["steam://".Length..];
            steam = true;
        }
        else
        {
            secret = value;
        }

        char[]? unescaped = null;
        if (secret.Contains('%'))
        {
            unescaped = new char[secret.Length];
            secret = unescaped.AsSpan(0, PercentDecode(secret, unescaped));
        }

        var key = new byte[secret.Length * 5 / 8 + 1];
        try
        {
            if (DecodeBase32(secret, key) is not { } length || length == 0) return null;

            var unix = now.ToUnixTimeSeconds();
            Span<byte> counter = stackalloc byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, unix / period);
            Span<byte> hash = stackalloc byte[64];
            var secretKey = key.AsSpan(0, length);
            var written = algorithm == HashAlgorithmName.SHA512 ? HMACSHA512.HashData(secretKey, counter, hash)
                : algorithm == HashAlgorithmName.SHA256 ? HMACSHA256.HashData(secretKey, counter, hash)
                : HMACSHA1.HashData(secretKey, counter, hash);
            hash = hash[..written];

            var offset = hash[^1] & 0x0F;
            var binary = (hash[offset] & 0x7F) << 24 | hash[offset + 1] << 16 | hash[offset + 2] << 8 | hash[offset + 3];
            CryptographicOperations.ZeroMemory(hash);

            string code;
            if (steam)
            {
                var chars = new char[5];
                for (var i = 0; i < chars.Length; i++)
                {
                    chars[i] = SteamAlphabet[binary % SteamAlphabet.Length];
                    binary /= SteamAlphabet.Length;
                }
                code = new string(chars);
            }
            else
            {
                code = ((long)binary % (long)Math.Pow(10, digits)).ToString().PadLeft(digits, '0');
            }
            return (code, period - (int)(unix % period));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (unescaped is not null) Array.Clear(unescaped);
        }
    }

    private static int PercentDecode(ReadOnlySpan<char> text, Span<char> output)
    {
        var length = 0;
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '%' && i + 2 < text.Length
                && byte.TryParse(text.Slice(i + 1, 2), System.Globalization.NumberStyles.HexNumber, null, out var b))
            {
                output[length++] = (char)b;
                i += 2;
            }
            else
            {
                output[length++] = text[i];
            }
        }
        return length;
    }

    /// <summary>Decodes base32, ignoring spaces, dashes, padding and case. Returns null on any other character.</summary>
    private static int? DecodeBase32(ReadOnlySpan<char> text, Span<byte> output)
    {
        var buffer = 0;
        var bits = 0;
        var length = 0;
        foreach (var ch in text)
        {
            if (ch is ' ' or '-' or '=' || char.IsWhiteSpace(ch)) continue;
            var index = Base32Alphabet.IndexOf(char.ToUpperInvariant(ch));
            if (index < 0) return null;
            buffer = buffer << 5 | index;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                output[length++] = (byte)(buffer >> bits);
                buffer &= (1 << bits) - 1;
            }
        }
        return length;
    }
}
