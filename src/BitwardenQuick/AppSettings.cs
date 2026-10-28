using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace BitwardenQuick;

internal sealed class AppSettings
{
    private const int MaxRecent = 15;

    public string Hotkey { get; set; } = "Ctrl+Shift+Space";
    public int ClipboardClearSeconds { get; set; } = 30;
    public int LockAfterIdleMinutes { get; set; } = 15;
    public bool HideFromScreenCapture { get; set; } = true;
    public bool ShowWebsiteIcons { get; set; } = true;
    public List<string> Recent { get; set; } = [];

    [JsonIgnore] public string? Path { get; private set; }

    public static AppSettings Load(string directory)
    {
        var path = System.IO.Path.Combine(directory, "settings.json");
        AppSettings settings;
        try
        {
            settings = File.Exists(path)
                ? JsonSerializer.Deserialize(File.ReadAllBytes(path), SettingsJsonContext.Default.AppSettings) ?? new()
                : new();
        }
        catch (JsonException)
        {
            settings = new();
        }
        settings.Path = path;
        settings.ClipboardClearSeconds = Math.Clamp(settings.ClipboardClearSeconds, 5, 600);
        settings.LockAfterIdleMinutes = Math.Clamp(settings.LockAfterIdleMinutes, 0, 1440);
        return settings;
    }

    public void Save()
    {
        if (Path is null) return;
        var temp = Path + ".tmp";
        try
        {
            File.WriteAllBytes(temp, JsonSerializer.SerializeToUtf8Bytes(this, SettingsJsonContext.Default.AppSettings));
            File.Move(temp, Path, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }

    public void MarkUsed(string id)
    {
        Recent.Remove(id);
        Recent.Insert(0, id);
        if (Recent.Count > MaxRecent) Recent.RemoveRange(MaxRecent, Recent.Count - MaxRecent);
        Save();
    }

    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValue = "BitwardenQuick";

    public static bool StartWithWindows
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey);
            return key?.GetValue(RunValue) is string;
        }
        set
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKey);
            if (value) key.SetValue(RunValue, $"\"{Environment.ProcessPath}\" --background");
            else key.DeleteValue(RunValue, throwOnMissingValue: false);
        }
    }
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(AppSettings))]
internal sealed partial class SettingsJsonContext : JsonSerializerContext;
