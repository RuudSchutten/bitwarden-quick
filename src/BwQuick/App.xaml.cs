using System.Security.Cryptography;
using System.Windows;
using System.Windows.Threading;
using BwQuick.Core;
using BwQuick.Core.Api;
using BwQuick.Core.Storage;
using BwQuick.Native;
using Microsoft.Win32;
using Windows.Security.Credentials;

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
    private DispatcherTimer? _idleTimer;
    private bool _unlocking;

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

        BitwardenApi api;
        try
        {
            api = CreateApi(Environment.GetEnvironmentVariable("BWQUICK_SERVER"));
        }
        catch (Exception ex) when (ex is ArgumentException or UriFormatException)
        {
            MessageBox.Show($"BWQUICK_SERVER is not a valid https URL. {ex.Message}", "BwQuick", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown();
            return;
        }

        AppDomain.CurrentDomain.UnhandledException += (_, _) => _clipboard?.ClearAfterCrash();

        var store = new SecureStore(Environment.GetEnvironmentVariable("BWQUICK_DATA_DIR"));
        _settings = AppSettings.Load(store.Directory);
        _service = new VaultService(store, api);
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
        _tray.LockRequested += Lock;
        _tray.SignOutRequested += SignOut;
        _tray.ExitRequested += () => Shutdown();

        _hotKey.Pressed += ShowQuick;
        if (!_hotKey.Register(_settings.Hotkey, out var hotkeyError))
            _tray.Notify("Hotkey unavailable", hotkeyError + " Change \"Hotkey\" in settings.json.", error: true);

        _syncTimer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(5) };
        _syncTimer.Tick += (_, _) => _ = SyncAsync(force: false);
        _syncTimer.Start();

        _idleTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _idleTimer.Tick += (_, _) =>
        {
            if (_settings.LockAfterIdleMinutes > 0 && Win32.IdleTime >= TimeSpan.FromMinutes(_settings.LockAfterIdleMinutes))
                Lock();
        };
        _idleTimer.Start();

        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;

        var background = e.Args.Contains("--background", StringComparer.OrdinalIgnoreCase);
        if (!_service.HasStoredAccount)
        {
            ShowSetup(null);
            return;
        }

        try
        {
            _service.LoadAccount();
        }
        catch (SetupException ex)
        {
            ShowSetup(ex.Message);
            return;
        }
        catch (Exception ex) when (ex is CryptographicException or System.IO.IOException or System.IO.InvalidDataException)
        {
            ShowSetup("The saved data could not be opened. Connect your vault again.");
            return;
        }

        OnVaultChanged();
        if (!background) ShowQuick();
    }

    /// <summary>A self-hosted style base URL serves identity under /identity and the API under /api.</summary>
    private static BitwardenApi CreateApi(string? server)
    {
        if (string.IsNullOrWhiteSpace(server)) return new BitwardenApi();
        var root = server.TrimEnd('/');
        return new BitwardenApi(new Uri(root + "/identity/"), new Uri(root + "/api/"));
    }

    private async void ShowQuick()
    {
        if (_setup is not null)
        {
            _setup.Activate();
            return;
        }
        if (_service is { IsConfigured: true, IsUnlocked: false, NeedsSetup: false } && !await UnlockAsync()) return;
        _quick?.ShowQuick();
    }

    /// <summary>Unlocks with Windows Hello, and with the master password when Hello is unavailable or fails.</summary>
    private async Task<bool> UnlockAsync()
    {
        var service = _service!;
        if (_unlocking) return false;
        _unlocking = true;
        try
        {
            var enroll = service.HelloChallenge is null;
            if (service.HelloChallenge is { } challenge)
            {
                var (status, signature) = await WindowsHello.SignAsync(challenge);
                if (signature is not null && await Task.Run(() => service.UnlockWithHello(signature))) return true;
                if (status == KeyCredentialStatus.UserCanceled) return false;
                enroll = true;
            }

            if (!PasswordPromptWindow.Ask(null, "Unlock BwQuick", "Enter your master password to unlock your vault.",
                    "Unlock", service.UnlockWithMasterPassword))
                return false;
            if (enroll) await EnrollHelloAsync();
            return true;
        }
        finally
        {
            _unlocking = false;
        }
    }

    private async Task EnrollHelloAsync()
    {
        if (!await WindowsHello.IsAvailableAsync()) return;
        var challenge = VaultService.NewHelloChallenge();
        if (await WindowsHello.CreateAndSignAsync(challenge) is not { } signature) return;
        try
        {
            _service!.EnableHello(challenge, signature);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.IO.IOException or UnauthorizedAccessException)
        {
        }
    }

    private void Lock()
    {
        if (_service is not { IsUnlocked: true }) return;
        _clipboard?.ClearNow();
        _quick?.Hide();
        _service.Lock();
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
        _setup.Completed += async () =>
        {
            await EnrollHelloAsync();
            _tray?.Notify("BwQuick is ready", $"Press {_settings!.Hotkey} to search your vault.");
            _ = Dispatcher.BeginInvoke(() => _quick?.ShowQuick(), DispatcherPriority.Background);
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
        _tray?.SetStatus(_service is { IsConfigured: true, IsUnlocked: false } ? "BwQuick – Locked"
            : _service?.LastError is { } error ? $"BwQuick – {error}"
            : $"BwQuick – {count} items");
    }

    private void SignOut()
    {
        var answer = MessageBox.Show(
            "Your API key, vault key and the local copy of your vault will be removed from this PC. Your Bitwarden account is not affected.",
            "Sign out", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.OK) return;

        _clipboard?.ClearNow();
        _service?.SignOut();
        _ = WindowsHello.DeleteAsync();
        _settings!.Recent.Clear();
        _settings.Save();
        ShowSetup(null);
    }

    private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Suspend)
            Dispatcher.Invoke(Lock);
        else if (e.Mode == PowerModes.Resume)
            Dispatcher.BeginInvoke(() => _ = SyncAsync(force: false));
    }

    private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect)
            Dispatcher.Invoke(Lock);
    }

    private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (e.Category is UserPreferenceCategory.General or UserPreferenceCategory.Color)
            Dispatcher.BeginInvoke(() => _quick?.ApplyTheme());
    }

    protected override void OnExit(ExitEventArgs e)
    {
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        SystemEvents.SessionSwitch -= OnSessionSwitch;
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
