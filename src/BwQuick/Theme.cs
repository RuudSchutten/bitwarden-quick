using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace BwQuick;

internal static class Theme
{
    public static bool IsDark
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
        }
    }

    public static void Apply(ResourceDictionary resources, bool acrylic)
    {
        var dark = IsDark;
        Set(resources, "SurfaceBrush", dark
            ? (acrylic ? "#B81C1C1C" : "#FF202020")
            : (acrylic ? "#C8F7F7F7" : "#FFF7F7F7"));
        Set(resources, "WindowBrush", dark ? "#FF202020" : "#FFF7F7F7");
        Set(resources, "InputBrush", dark ? "#FF2C2C2C" : "#FFFFFFFF");
        Set(resources, "TextBrush", dark ? "#FFF3F3F3" : "#FF1B1B1B");
        Set(resources, "MutedBrush", dark ? "#FFA8A8A8" : "#FF5F5F5F");
        Set(resources, "AccentBrush", dark ? "#FF4C8DF6" : "#FF175DDC");
        Set(resources, "SelectionBrush", dark ? "#FF2F6FE4" : "#FF175DDC");
        Set(resources, "HoverBrush", dark ? "#14FFFFFF" : "#0D000000");
        Set(resources, "DividerBrush", dark ? "#1FFFFFFF" : "#1A000000");
        Set(resources, "FooterBrush", dark ? "#0DFFFFFF" : "#08000000");
        Set(resources, "KeyBrush", dark ? "#1FFFFFFF" : "#FFFFFFFF");
        Set(resources, "KeyBorderBrush", dark ? "#33FFFFFF" : "#26000000");
        Set(resources, "ErrorBrush", dark ? "#FFFF8A80" : "#FFC42B1C");
    }

    private static void Set(ResourceDictionary resources, string key, string color)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
        brush.Freeze();
        resources[key] = brush;
    }

    private static readonly Color[] AvatarColors =
    [
        Color.FromRgb(0x17, 0x5D, 0xDC), Color.FromRgb(0x0E, 0x7C, 0x66), Color.FromRgb(0x8E, 0x44, 0xAD),
        Color.FromRgb(0xC0, 0x39, 0x2B), Color.FromRgb(0xD3, 0x54, 0x00), Color.FromRgb(0x27, 0x6E, 0x9E),
        Color.FromRgb(0x6D, 0x4C, 0x41), Color.FromRgb(0x2E, 0x7D, 0x32), Color.FromRgb(0xAD, 0x14, 0x57),
    ];

    private static readonly Brush[] AvatarBrushes = AvatarColors.Select(c =>
    {
        var b = new SolidColorBrush(c);
        b.Freeze();
        return (Brush)b;
    }).ToArray();

    public static Brush AvatarFor(string key)
    {
        var hash = 0u;
        foreach (var ch in key) hash = hash * 31 + ch;
        return AvatarBrushes[hash % (uint)AvatarBrushes.Length];
    }
}
