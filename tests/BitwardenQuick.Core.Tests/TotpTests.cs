using System.Text;
using BitwardenQuick.Core.Crypto;

namespace BitwardenQuick.Core.Tests;

public sealed class TotpTests
{
    private const string Sha1Key = "12345678901234567890";
    private const string Sha256Key = "12345678901234567890123456789012";
    private const string Sha512Key = "1234567890123456789012345678901234567890123456789012345678901234";

    private static string Base32(string ascii)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = string.Concat(Encoding.ASCII.GetBytes(ascii).Select(b => Convert.ToString(b, 2).PadLeft(8, '0')));
        bits = bits.PadRight((bits.Length + 4) / 5 * 5, '0');
        return string.Concat(Enumerable.Range(0, bits.Length / 5).Select(i => alphabet[Convert.ToInt32(bits.Substring(i * 5, 5), 2)]));
    }

    private static string? Code(string key, long unix) =>
        Totp.Generate(key, DateTimeOffset.FromUnixTimeSeconds(unix))?.Code;

    [Theory]
    [InlineData(59, "SHA1", "94287082")]
    [InlineData(59, "SHA256", "46119246")]
    [InlineData(59, "SHA512", "90693936")]
    [InlineData(1111111109, "SHA1", "07081804")]
    [InlineData(1111111109, "SHA256", "68084774")]
    [InlineData(1111111109, "SHA512", "25091201")]
    [InlineData(2000000000, "SHA1", "69279037")]
    [InlineData(2000000000, "SHA256", "90698825")]
    [InlineData(2000000000, "SHA512", "38618901")]
    public void Matches_the_RFC_6238_test_vectors(long unix, string algorithm, string expected)
    {
        var key = algorithm switch { "SHA1" => Sha1Key, "SHA256" => Sha256Key, _ => Sha512Key };
        var uri = $"otpauth://totp/Example:alice@example.com?secret={Base32(key)}&issuer=Example&algorithm={algorithm}&digits=8&period=30";
        Assert.Equal(expected, Code(uri, unix));
    }

    [Fact]
    public void A_plain_secret_gives_six_digits_every_thirty_seconds()
    {
        var secret = Base32(Sha1Key);
        Assert.Equal("287082", Code(secret, 59));
        Assert.Equal("287082", Code(secret.ToLowerInvariant(), 59));
        Assert.Equal("287082", Code(" " + string.Join(' ', secret.Chunk(4).Select(c => new string(c))) + " ", 59));
    }

    [Fact]
    public void Reports_the_seconds_the_code_stays_valid()
    {
        Assert.Equal(1, Totp.Generate(Base32(Sha1Key), DateTimeOffset.FromUnixTimeSeconds(59))!.Value.SecondsLeft);
        Assert.Equal(30, Totp.Generate(Base32(Sha1Key), DateTimeOffset.FromUnixTimeSeconds(60))!.Value.SecondsLeft);
        Assert.Equal(55, Totp.Generate($"otpauth://totp/x?secret={Base32(Sha1Key)}&period=60", DateTimeOffset.FromUnixTimeSeconds(65))!.Value.SecondsLeft);
    }

    [Fact]
    public void Reads_a_percent_encoded_secret()
    {
        var secret = Base32(Sha1Key);
        Assert.Equal("287082", Code($"otpauth://totp/x?secret={secret}%3D%3D", 59));
    }

    [Fact]
    public void Steam_codes_use_five_steam_characters()
    {
        var secret = Base32(Sha1Key);
        var code = Code("steam://" + secret, 59);
        Assert.NotNull(code);
        Assert.Equal(5, code.Length);
        Assert.All(code, c => Assert.Contains(c, "23456789BCDFGHJKMNPQRTVWXY"));
        Assert.Equal(code, Code($"otpauth://totp/Steam:me?secret={secret}&encoder=steam", 59));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not base32!")]
    [InlineData("otpauth://totp/x?issuer=nosecret")]
    [InlineData("otpauth://totp/x")]
    public void Returns_null_for_a_key_that_is_not_valid(string key) =>
        Assert.Null(Code(key, 59));
}
