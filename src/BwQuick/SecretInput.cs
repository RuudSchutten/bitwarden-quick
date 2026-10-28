using System.Runtime.InteropServices;
using System.Security;
using BwQuick.Core.Crypto;

namespace BwQuick;

internal static class SecretInput
{
    /// <summary>Converts a PasswordBox's SecureString to UTF-8 without creating a managed string.</summary>
    public static unsafe Secret FromSecureString(SecureString value)
    {
        var ptr = Marshal.SecureStringToGlobalAllocUnicode(value);
        try
        {
            return Secret.FromChars(new ReadOnlySpan<char>((char*)ptr, value.Length));
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(ptr);
        }
    }
}
