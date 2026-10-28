using System.ComponentModel;
using System.Runtime.InteropServices;

namespace BwQuick.Native;

/// <summary>
/// Writes to the clipboard through Win32 directly so secrets never become managed strings,
/// and tags sensitive data so Windows keeps it out of clipboard history and cloud sync.
/// </summary>
internal static class SecureClipboard
{
    private static readonly uint ExcludeFromMonitoring = Win32.RegisterClipboardFormat("ExcludeClipboardContentFromMonitorProcessing");
    private static readonly uint CanIncludeInHistory = Win32.RegisterClipboardFormat("CanIncludeInClipboardHistory");
    private static readonly uint CanUploadToCloud = Win32.RegisterClipboardFormat("CanUploadToCloudClipboard");
    private static readonly uint[] TextFormats = [Win32.CF_UNICODETEXT, Win32.CF_TEXT, Win32.CF_OEMTEXT];

    /// <returns>The clipboard sequence number after the write, to detect later changes by others.</returns>
    public static uint SetText(nint owner, ReadOnlySpan<char> text, bool sensitive)
    {
        Open(owner);
        try
        {
            if (!Win32.EmptyClipboard()) throw new Win32Exception();

            if (sensitive)
            {
                SetDword(ExcludeFromMonitoring, 0);
                SetDword(CanIncludeInHistory, 0);
                SetDword(CanUploadToCloud, 0);
            }

            var bytes = (nuint)((text.Length + 1) * sizeof(char));
            var handle = Win32.GlobalAlloc(Win32.GMEM_MOVEABLE, bytes);
            if (handle == 0) throw new Win32Exception();
            try
            {
                unsafe
                {
                    var target = new Span<char>((void*)Win32.GlobalLock(handle), text.Length + 1);
                    text.CopyTo(target);
                    target[text.Length] = '\0';
                    Win32.GlobalUnlock(handle);
                }
                if (Win32.SetClipboardData(Win32.CF_UNICODETEXT, handle) == 0) throw new Win32Exception();
            }
            catch
            {
                Win32.GlobalFree(handle);
                throw;
            }
        }
        finally
        {
            Win32.CloseClipboard();
        }
        return Win32.GetClipboardSequenceNumber();
    }

    /// <summary>Wipes and empties the clipboard, but only if nobody copied something else since.</summary>
    public static void ClearIfUnchanged(nint owner, uint sequence)
    {
        if (Win32.GetClipboardSequenceNumber() != sequence) return;
        try { Open(owner); }
        catch (Win32Exception) { return; }
        try
        {
            // Opening can wait for another program that is writing; only clear what is still ours.
            if (Win32.GetClipboardSequenceNumber() != sequence) return;
            // Windows converts CF_UNICODETEXT to CF_TEXT and CF_OEMTEXT for programs that ask, and keeps
            // those copies until the clipboard is emptied, so they are zeroed too.
            foreach (var format in TextFormats)
            {
                var handle = Win32.GetClipboardData(format);
                if (handle == 0) continue;
                var ptr = Win32.GlobalLock(handle);
                if (ptr == 0) continue;
                unsafe { new Span<byte>((void*)ptr, (int)Win32.GlobalSize(handle)).Clear(); }
                Win32.GlobalUnlock(handle);
            }
            Win32.EmptyClipboard();
        }
        finally
        {
            Win32.CloseClipboard();
        }
    }

    private static void Open(nint owner)
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            if (Win32.OpenClipboard(owner)) return;
            Thread.Sleep(15);
        }
        throw new Win32Exception(Marshal.GetLastPInvokeError(), "The clipboard is in use by another program.");
    }

    private static void SetDword(uint format, int value)
    {
        var handle = Win32.GlobalAlloc(Win32.GMEM_MOVEABLE, sizeof(int));
        if (handle == 0) return;
        Marshal.WriteInt32(Win32.GlobalLock(handle), value);
        Win32.GlobalUnlock(handle);
        if (Win32.SetClipboardData(format, handle) == 0) Win32.GlobalFree(handle);
    }
}
