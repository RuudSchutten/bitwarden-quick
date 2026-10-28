using System.Security.Cryptography;

namespace BitwardenQuick.Core.Crypto;

/// <summary>Plaintext bytes in a pinned buffer that is zeroed on dispose.</summary>
public sealed class Secret : IDisposable
{
    private readonly byte[] _buffer;
    private bool _disposed;

    public int Length { get; }

    internal Secret(int capacity)
    {
        _buffer = GC.AllocateArray<byte>(Math.Max(capacity, 1), pinned: true);
        Length = capacity;
    }

    private Secret(byte[] buffer, int length)
    {
        _buffer = buffer;
        Length = length;
    }

    internal byte[] Buffer => _disposed ? throw new ObjectDisposedException(nameof(Secret)) : _buffer;

    public ReadOnlySpan<byte> Span => Buffer.AsSpan(0, Length);

    internal Secret Truncate(int length)
    {
        if (length > Length) throw new ArgumentOutOfRangeException(nameof(length));
        var result = new Secret(_buffer, length);
        _disposed = true;
        return result;
    }

    public static Secret FromChars(ReadOnlySpan<char> chars)
    {
        var secret = new Secret(System.Text.Encoding.UTF8.GetMaxByteCount(chars.Length));
        var written = System.Text.Encoding.UTF8.GetBytes(chars, secret._buffer);
        return secret.Truncate(written);
    }

    public static Secret Copy(ReadOnlySpan<byte> bytes)
    {
        var secret = new Secret(bytes.Length);
        bytes.CopyTo(secret._buffer);
        return secret;
    }

    /// <summary>Decodes UTF-8 into a pinned char buffer; the caller must zero it after use.</summary>
    public char[] ToChars()
    {
        var chars = GC.AllocateArray<char>(System.Text.Encoding.UTF8.GetCharCount(Span), pinned: true);
        System.Text.Encoding.UTF8.GetChars(Span, chars);
        return chars;
    }

    public string ToUnprotectedString() => System.Text.Encoding.UTF8.GetString(Span);

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_buffer);
        _disposed = true;
    }
}
