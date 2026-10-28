using System.Runtime.InteropServices;

namespace BitwardenQuick.Native;

/// <summary>Types a username and password into another window, as username, Tab, password, Enter.</summary>
internal static class AutoType
{
    private static readonly ushort[] HeldKeys =
        [Win32.VK_SHIFT, Win32.VK_CONTROL, Win32.VK_MENU, Win32.VK_LWIN, Win32.VK_RWIN, Win32.VK_RETURN];

    /// <summary>The window that was in front before BitwardenQuick opened, or 0 when that was BitwardenQuick itself.</summary>
    public static nint ForegroundWindowOfOtherProcess()
    {
        var window = Win32.GetForegroundWindow();
        if (window == 0) return 0;
        Win32.GetWindowThreadProcessId(window, out var pid);
        return pid == Environment.ProcessId ? 0 : window;
    }

    /// <summary>Returns null when the keys were sent, otherwise why nothing was typed.</summary>
    public static async Task<string?> TypeAsync(nint target, string? username, char[]? password)
    {
        if (target == 0 || !Win32.IsWindow(target)) return "The window to type into was closed.";

        // A Shift still held from Shift+Enter would turn Tab into Shift+Tab.
        var deadline = Environment.TickCount64 + 3000;
        while (HeldKeys.Any(vk => Win32.GetAsyncKeyState(vk) < 0))
        {
            if (Environment.TickCount64 > deadline) return "Release the keyboard to Auto-Type.";
            await Task.Delay(20);
        }

        Win32.SetForegroundWindow(target);
        deadline = Environment.TickCount64 + 1500;
        while (Win32.GetForegroundWindow() != target)
        {
            if (Environment.TickCount64 > deadline) return "Could not switch to the window to type into.";
            await Task.Delay(20);
        }
        await Task.Delay(80);
        if (Win32.GetForegroundWindow() != target) return "The window to type into lost focus.";

        var hasUser = !string.IsNullOrEmpty(username);
        var hasPassword = password is { Length: > 0 };
        var count = 2 + (hasUser ? Typed(username) : 0) + (hasPassword ? Typed(password) : 0) + (hasUser && hasPassword ? 2 : 0);
        var buffer = new Win32.INPUT[count];
        var index = 0;
        try
        {
            if (hasUser)
            {
                AddText(buffer, ref index, username);
                if (hasPassword) AddKey(buffer, ref index, Win32.VK_TAB);
            }
            if (hasPassword) AddText(buffer, ref index, password);
            AddKey(buffer, ref index, Win32.VK_RETURN);

            unsafe
            {
                fixed (Win32.INPUT* p = buffer)
                {
                    var sent = Win32.SendInput((uint)index, p, Marshal.SizeOf<Win32.INPUT>());
                    return sent == index ? null : "Windows blocked the typed input.";
                }
            }
        }
        finally
        {
            Array.Clear(buffer);
        }
    }

    private static int Typed(ReadOnlySpan<char> text)
    {
        var count = 0;
        foreach (var ch in text)
            if (!char.IsControl(ch)) count += 2;
        return count;
    }

    private static void AddText(Win32.INPUT[] buffer, ref int index, ReadOnlySpan<char> text)
    {
        foreach (var ch in text)
        {
            if (char.IsControl(ch)) continue;
            buffer[index++] = Key(0, ch, Win32.KEYEVENTF_UNICODE);
            buffer[index++] = Key(0, ch, Win32.KEYEVENTF_UNICODE | Win32.KEYEVENTF_KEYUP);
        }
    }

    private static void AddKey(Win32.INPUT[] buffer, ref int index, ushort vk)
    {
        buffer[index++] = Key(vk, 0, 0);
        buffer[index++] = Key(vk, 0, Win32.KEYEVENTF_KEYUP);
    }

    private static Win32.INPUT Key(ushort vk, ushort scan, uint flags) => new()
    {
        type = Win32.INPUT_KEYBOARD,
        u = new Win32.INPUTUNION { ki = new Win32.KEYBDINPUT { wVk = vk, wScan = scan, dwFlags = flags } },
    };
}
