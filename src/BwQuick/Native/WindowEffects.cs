using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace BwQuick.Native;

internal static class WindowEffects
{
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWA_SYSTEMBACKDROP_TYPE = 38;
    private const int DWMWCP_ROUND = 2;
    private const int DWMSBT_TRANSIENTWINDOW = 3;

    public static bool SupportsBackdrop => Environment.OSVersion.Version.Build >= 22621;

    /// <summary>Gives a chromeless window the Windows 11 acrylic backdrop, rounded corners and shadow.</summary>
    public static void ApplyFluent(Window window, bool dark, bool acrylic)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == 0) return;

        var value = dark ? 1 : 0;
        Win32.DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref value, sizeof(int));
        value = DWMWCP_ROUND;
        Win32.DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref value, sizeof(int));

        if (acrylic && SupportsBackdrop)
        {
            if (HwndSource.FromHwnd(hwnd) is { CompositionTarget: { } target })
                target.BackgroundColor = Colors.Transparent;
            var margins = new Win32.MARGINS { Left = -1, Right = -1, Top = -1, Bottom = -1 };
            Win32.DwmExtendFrameIntoClientArea(hwnd, ref margins);
            value = DWMSBT_TRANSIENTWINDOW;
            Win32.DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, ref value, sizeof(int));
        }
    }

    public static void HideFromAltTab(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        var exStyle = Win32.GetWindowLongPtr(hwnd, Win32.GWL_EXSTYLE);
        Win32.SetWindowLongPtr(hwnd, Win32.GWL_EXSTYLE, (exStyle | Win32.WS_EX_TOOLWINDOW) & ~Win32.WS_EX_APPWINDOW);
        // Without this DWM still paints the caption buttons under the extended glass frame.
        var style = Win32.GetWindowLongPtr(hwnd, Win32.GWL_STYLE);
        Win32.SetWindowLongPtr(hwnd, Win32.GWL_STYLE, style & ~Win32.WS_SYSMENU);
    }

    public static void ExcludeFromCapture(Window window, bool exclude)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        Win32.SetWindowDisplayAffinity(hwnd, exclude ? Win32.WDA_EXCLUDEFROMCAPTURE : Win32.WDA_NONE);
    }

    /// <summary>Centers the window horizontally on the monitor under the cursor, in the upper part of the screen.</summary>
    public static void PlaceOnCursorMonitor(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        Win32.GetCursorPos(out var cursor);
        var monitor = Win32.MonitorFromPoint(cursor, Win32.MONITOR_DEFAULTTONEAREST);
        var info = new Win32.MONITORINFO { cbSize = System.Runtime.InteropServices.Marshal.SizeOf<Win32.MONITORINFO>() };
        if (!Win32.GetMonitorInfo(monitor, ref info)) return;

        Win32.GetWindowRect(hwnd, out var rect);
        var width = (double)(rect.Right - rect.Left);
        var currentDpi = Win32.GetDpiForWindow(hwnd);
        if (Win32.GetDpiForMonitor(monitor, 0, out var targetDpi, out _) == 0 && currentDpi > 0)
            width = width * targetDpi / currentDpi;

        var work = info.rcWork;
        var x = work.Left + (int)((work.Right - work.Left - width) / 2);
        var y = work.Top + (int)((work.Bottom - work.Top) * 0.2);
        Win32.SetWindowPos(hwnd, 0, x, y, 0, 0, Win32.SWP_NOSIZE | Win32.SWP_NOZORDER | Win32.SWP_NOACTIVATE);
    }
}
