using System.Security.Cryptography;
using System.Windows;
using System.Windows.Threading;
using BwQuick.Core;
using BwQuick.Core.Api;
using BwQuick.Core.Storage;
using BwQuick.Native;
using Microsoft.Win32;

namespace BwQuick;

public partial class App : Application
{
    private const string InstanceName = @"Local\BwQuick.Instance";
    private const string ShowSignalName = @"Local\BwQuick.Show";

    private Mutex? _instance;
    private EventWaitHandle? _showSignal;
    private RegisteredWaitHandle? _showWait;
    private VaultService? _service;
    private AppSettings? _settings;
    private HotKey? _hotKey;
    private TrayIcon? _tray;
    private QuickWindow? _quick;
    private SetupWindow? _setup;
    private ClipboardGuard? _clipboard;
    private DispatcherTimer? _syncTimer;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _instance = new Mutex(true, InstanceName, out var isFirst);
        if (!isFirst)
        {
            try { EventWaitHandle.OpenExisting(ShowSignalName).Set(); }
            catch (WaitHandleCannotBeOpenedException) { }
            Shutdown();
            return;
        }

        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowSignalName);
        _showWait = ThreadPool.RegisterWaitForSingleObject(_showSignal,
            (_, _) => Dispatcher.BeginInvoke(ShowQuick), null, Timeout.Infinite, executeOnlyOnce: false);

        var store = new SecureStore(Environment.GetEnvironmentVariable("BWQUICK_DATA_DIR"));
        _settings = AppSettings.Load(store.Directory);
        _service = new VaultService(store, CreateApi(Environment.GetEnvironmentVariable("BWQUICK_SERVER")));
        _service.Changed += () => Dispatcher.BeginInvoke(OnVaultChanged);

        _hotKey = new HotKey();
        _clipboard = new ClipboardGuard(() => _hotKey.Handle);
        _quick = new QuickWindow(_service, _settings, _clipboard);
        _quick.SetupRequested += () => ShowSetup(null);
        _quick.SyncRequested += () => _ = SyncAsync(force: false);
        _quick.Prewarm();

        _tray = new TrayIcon();
        _tray.SetHotkeyLabel(_settings.Hotkey);
        _tray.OpenRequested += ShowQuick;
        _tray.SyncRequested += () => _ = SyncAsync(force: true);
        _tray.SignOutRequested += SignOut;
        _tray.ExitRequested += () => Shutdown();

        _hotKey.Pressed += ShowQuick;
        if (!_hotKey.Register(_settings.Hotkey, out var hotkeyError))
            _tray.Notify("Hotkey unavailable", hotkeyError + " Change \"Hotkey\" in settings.json.", error: true);

        _syncTimer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(5) };
        _syncTimer.Tick += (_, _) => _ = SyncAsync(force: false);
        _syncTimer.Start();

        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;

        var background = e.Args.Contains("--background", StringComparer.OrdinalIgnoreCase);
        if (!_service.IsConfigured)
        {
            ShowSetup(null);
            return;
        }

        try
        {
            _service.UnlockFromDisk();
        }
        catch (Exception ex) when (ex is CryptographicException or System.IO.IOException or System.IO.InvalidDataException)
        {
            ShowSetup("The saved data could not be opened. Connect your vault again.");
            return;
        }

        OnVaultChanged();
        _ = SyncAsync(force: false);
        if (!background) ShowQuick();
    }

    /// <summary>A self-hosted style base URL serves identity under /identity and the API under /api.</summary>
    private static BitwardenApi CreateApi(string? server)
    {
        if (string.IsNullOrWhiteSpace(server)) return new BitwardenApi();
        var root = server.TrimEnd('/');
        return new BitwardenApi(new Uri(root + "/identity/"), new Uri(root + "/api/"));
    }

    private void ShowQuick()
    {
        if (_setup is not null)
        {
            _setup.Activate();
            return;
        }
        _quick?.ShowQuick();
    }

    private void ShowSetup(string? reason)
    {
        if (_setup is not null)
        {
            _setup.Activate();
            return;
        }
        _quick?.Hide();
        _setup = new SetupWindow(_service!, reason);
        _setup.SourceInitialized += (_, _) => WindowEffects.ApplyFluent(_setup, Theme.IsDark, acrylic: false);
        _setup.Completed += () =>
        {
            _tray?.Notify("BwQuick is ready", $"Press {_settings!.Hotkey} to search your vault.");
            Dispatcher.BeginInvoke(() => _quick?.ShowQuick(), DispatcherPriority.Background);
        };
        _setup.Closed += (_, _) => _setup = null;
        _setup.Show();
        _setup.Activate();
    }

    private async Task SyncAsync(bool force)
    {
        if (_service is not { IsUnlocked: true }) return;
        _quick?.SetSyncing(true);
        try
        {
            await _service.SyncAsync(force);
        }
        finally
        {
            _quick?.SetSyncing(false);
        }
        if (_service.NeedsSetup)
            _tray?.Notify("BwQuick needs to be set up again", _service.LastError ?? "Connect your vault again.", error: true);
    }

    private void OnVaultChanged()
    {
        _quick?.OnVaultChanged();
        var count = _service?.Current?.Entries.Count ?? 0;
        _tray?.SetStatus(_service?.LastError is { } error ? $"BwQuick – {error}" : $"BwQuick – {count} items");
    }

    private void SignOut()
    {
        var answer = MessageBox.Show(
            "Your API key, vault key and the local copy of your vault will be removed from this PC. Your Bitwarden account is not affected.",
            "Sign out", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.OK) return;

        _clipboard?.ClearNow();
        _service?.SignOut();
        _settings!.Recent.Clear();
        _settings.Save();
        ShowSetup(null);
    }

    private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Resume)
            Dispatcher.BeginInvoke(() => _ = SyncAsync(force: false));
    }

    private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (e.Category is UserPreferenceCategory.General or UserPreferenceCategory.Color)
            Dispatcher.BeginInvoke(() => _quick?.ApplyTheme());
    }

    protected override void OnExit(ExitEventArgs e)
    {
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
        _clipboard?.ClearNow();
        _showWait?.Unregister(null);
        _hotKey?.Dispose();
        _tray?.Dispose();
        _service?.Dispose();
        _instance?.Dispose();
        base.OnExit(e);
    }
}
