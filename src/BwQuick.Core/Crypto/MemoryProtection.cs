using System.ComponentModel;
using System.Runtime.InteropServices;

namespace BwQuick.Core.Crypto;

/// <summary>
/// Wraps CryptProtectMemory so key material at rest in the heap is encrypted with a
/// per-boot, per-process key and does not show up in plaintext in memory dumps.
/// </summary>
internal static partial class MemoryProtection
{
    public const int BlockSize = 16;
    private const uint SameProcess = 0;

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptProtectMemory(byte[] data, uint size, uint flags);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptUnprotectMemory(byte[] data, uint size, uint flags);

    public static void Protect(byte[] buffer)
    {
        if (!CryptProtectMemory(buffer, (uint)buffer.Length, SameProcess))
            throw new Win32Exception(Marshal.GetLastPInvokeError());
    }

    public static void Unprotect(byte[] buffer)
    {
        if (!CryptUnprotectMemory(buffer, (uint)buffer.Length, SameProcess))
            throw new Win32Exception(Marshal.GetLastPInvokeError());
    }
}
