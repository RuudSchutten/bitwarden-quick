using System.Windows.Input;
using System.Windows.Interop;

namespace BwQuick.Native;

/// <summary>A global hotkey bound to a hidden message-only window, which also owns the clipboard.</summary>
internal sealed class HotKey : IDisposable
{
    private const int Id = 0xB00C;
    private static readonly nint HwndMessage = -3;

    private readonly HwndSource _source;
    private bool _registered;

    public event Action? Pressed;

    public nint Handle => _source.Handle;

    public HotKey()
    {
        _source = new HwndSource(new HwndSourceParameters("BwQuick.Messages") { ParentWindow = HwndMessage, WindowStyle = 0 });
        _source.AddHook(WndProc);
    }

    public bool Register(string gesture, out string error)
    {
        error = "";
        if (_registered) Win32.UnregisterHotKey(Handle, Id);
        _registered = false;

        if (!TryParse(gesture, out var modifiers, out var vk))
        {
            error = $"Sneltoets \"{gesture}\" wordt niet herkend.";
            return false;
        }
        if (!Win32.RegisterHotKey(Handle, Id, modifiers | Win32.MOD_NOREPEAT, vk))
        {
            error = $"Sneltoets {gesture} is al in gebruik door een ander programma.";
            return false;
        }
        _registered = true;
        return true;
    }

    private static bool TryParse(string gesture, out uint modifiers, out uint vk)
    {
        modifiers = 0;
        vk = 0;
        foreach (var part in gesture.Split('+', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            switch (part.ToLowerInvariant())
            {
                case "ctrl" or "control": modifiers |= Win32.MOD_CONTROL; break;
                case "shift": modifiers |= Win32.MOD_SHIFT; break;
                case "alt": modifiers |= Win32.MOD_ALT; break;
                case "win": modifiers |= Win32.MOD_WIN; break;
                default:
                    if (!Enum.TryParse<Key>(part, ignoreCase: true, out var key)) return false;
                    vk = (uint)KeyInterop.VirtualKeyFromKey(key);
                    break;
            }
        }
        return vk != 0 && modifiers != 0;
    }

    private nint WndProc(nint hwnd, int msg, nint wParam, nint lParam, ref bool handled)
    {
        if (msg == Win32.WM_HOTKEY && wParam == Id)
        {
            handled = true;
            Pressed?.Invoke();
        }
        return 0;
    }

    public void Dispose()
    {
        if (_registered) Win32.UnregisterHotKey(Handle, Id);
        _source.Dispose();
    }
}
