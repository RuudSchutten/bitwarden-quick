using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using BwQuick.Core;
using BwQuick.Core.Items;
using BwQuick.Native;

namespace BwQuick;

public sealed class ResultItem
{
    public ResultItem(VaultEntry entry)
    {
        Entry = entry;
        Avatar = Theme.AvatarFor(entry.Host ?? entry.Name);
    }

    public VaultEntry Entry { get; }
    public string Name => Entry.Name;
    public string Subtitle => Entry.Subtitle;
    public string Initial => Entry.Initial;
    public string? Organization => Entry.OrganizationName;
    public Brush Avatar { get; }
    public Visibility SubtitleVisibility => Subtitle.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    public Visibility OrganizationVisibility => Organization is null ? Visibility.Collapsed : Visibility.Visible;
    public Visibility RepromptVisibility => Entry.Reprompt ? Visibility.Visible : Visibility.Collapsed;
}

public partial class QuickWindow : Window
{
    private readonly VaultService _service;
    private readonly AppSettings _settings;
    private readonly ClipboardGuard _clipboard;
    private readonly bool _acrylic = WindowEffects.SupportsBackdrop;
    private bool _modal;
    private bool _syncing;

    internal event Action? SetupRequested;
    internal event Action? SyncRequested;

    internal QuickWindow(VaultService service, AppSettings settings, ClipboardGuard clipboard)
    {
        _service = service;
        _settings = settings;
        _clipboard = clipboard;
        InitializeComponent();

        SourceInitialized += (_, _) =>
        {
            WindowEffects.HideFromAltTab(this);
            WindowEffects.ExcludeFromCapture(this, _settings.HideFromScreenCapture);
            ApplyTheme();
        };
        Deactivated += (_, _) =>
        {
            if (!_modal) Hide();
        };
        DpiChanged += (_, _) =>
        {
            if (IsVisible) WindowEffects.PlaceOnCursorMonitor(this);
        };
        PreviewKeyDown += OnKey;
    }

    internal bool Acrylic => _acrylic;

    internal void ApplyTheme()
    {
        Theme.Apply(Application.Current.Resources, _acrylic);
        if (_acrylic) Background = Brushes.Transparent;
        WindowEffects.ApplyFluent(this, Theme.IsDark, _acrylic);
    }

    /// <summary>Creates the native window and runs first layout off-screen so the first hotkey press is instant.</summary>
    internal void Prewarm()
    {
        ShowActivated = false;
        Left = -32000;
        Top = -32000;
        Show();
        Hide();
        ShowActivated = true;
    }

    internal void ShowQuick()
    {
        if (_service.NeedsSetup || !_service.IsConfigured)
        {
            SetupRequested?.Invoke();
            return;
        }

        RunSearch();
        SearchBox.SelectAll();
        WindowEffects.PlaceOnCursorMonitor(this);
        Show();
        Activate();
        Win32.SetForegroundWindow(new WindowInteropHelper(this).Handle);
        SearchBox.Focus();
        Keyboard.Focus(SearchBox);

        if (_service.LastSync is not { } last || DateTimeOffset.Now - last > TimeSpan.FromMinutes(1))
            SyncRequested?.Invoke();
    }

    internal void SetSyncing(bool syncing)
    {
        _syncing = syncing;
        SyncIcon.Visibility = syncing ? Visibility.Visible : Visibility.Collapsed;
    }

    internal void OnVaultChanged()
    {
        if (IsVisible) RunSearch();
        else UpdateStatus();
    }

    private void OnSearchChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        Placeholder.Visibility = SearchBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        RunSearch();
    }

    private void RunSearch()
    {
        var vault = _service.Current;
        List<ResultItem> items = vault is null
            ? []
            : VaultSearch.Search(vault.Entries, SearchBox.Text, _settings.Recent).Select(e => new ResultItem(e)).ToList();

        Results.ItemsSource = items;
        Results.SelectedIndex = items.Count > 0 ? 0 : -1;
        if (items.Count > 0) Results.ScrollIntoView(items[0]);
        Results.Visibility = items.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        EmptyText.Text = vault is null
            ? "Loading vault…"
            : SearchBox.Text.Trim().Length > 0
                ? $"No results for \"{SearchBox.Text.Trim()}\"."
                : "Your vault has no logins yet.";
        EmptyText.Visibility = items.Count > 0 ? Visibility.Collapsed : Visibility.Visible;
        UpdateStatus();
    }

    private void UpdateStatus()
    {
        if (_service.LastError is { } error)
        {
            StatusText.Text = error;
            StatusText.ToolTip = error;
            StatusText.Foreground = (Brush)Application.Current.Resources["ErrorBrush"];
            return;
        }
        StatusText.Foreground = (Brush)Application.Current.Resources["MutedBrush"];
        StatusText.ToolTip = null;
        var count = _service.Current?.Entries.Count ?? 0;
        StatusText.Text = _syncing ? "Syncing…" : $"{count} items";
    }

    private void SetStatus(string text, bool error = false)
    {
        StatusText.Text = text;
        StatusText.Foreground = (Brush)Application.Current.Resources[error ? "ErrorBrush" : "MutedBrush"];
    }

    private ResultItem? Selected => Results.SelectedItem as ResultItem;

    private void OnKey(object sender, KeyEventArgs e)
    {
        var key = e.Key == Key.System ? e.SystemKey : e.Key;
        var ctrl = Keyboard.Modifiers.HasFlag(ModifierKeys.Control);
        var shift = Keyboard.Modifiers.HasFlag(ModifierKeys.Shift);

        switch (key)
        {
            case Key.Escape:
                Hide();
                break;
            case Key.Down:
                Move(1);
                break;
            case Key.Up:
                Move(-1);
                break;
            case Key.PageDown:
                Move(8);
                break;
            case Key.PageUp:
                Move(-8);
                break;
            case Key.Enter:
                CopyPassword();
                break;
            case Key.C when ctrl && shift:
                CopyPassword();
                break;
            case Key.C when ctrl:
                CopyUsername();
                break;
            case Key.U when ctrl && shift:
                CopyWebsite();
                break;
            default:
                return;
        }
        e.Handled = true;
    }

    private void Move(int delta)
    {
        if (Results.Items.Count == 0) return;
        var index = Math.Clamp(Results.SelectedIndex + delta, 0, Results.Items.Count - 1);
        Results.SelectedIndex = index;
        Results.ScrollIntoView(Results.SelectedItem);
    }

    private void OnResultDoubleClick(object sender, MouseButtonEventArgs e) => CopyPassword();

    private nint ClipboardOwner => new WindowInteropHelper(this).Handle;

    private async void CopyPassword()
    {
        if (Selected is not { } item) return;
        var entry = item.Entry;
        if (!entry.HasPassword)
        {
            SetStatus("This item has no password.", error: true);
            return;
        }

        if (entry.Reprompt)
        {
            _modal = true;
            bool confirmed;
            try
            {
                confirmed = await RepromptGate.ConfirmAsync(this, entry.Name, _service);
            }
            finally
            {
                _modal = false;
            }
            if (!confirmed)
            {
                SetStatus("Not confirmed. Nothing was copied.", error: true);
                Activate();
                return;
            }
        }

        try
        {
            using var secret = _service.DecryptPassword(entry.Id);
            if (secret is null)
            {
                SetStatus("Item no longer exists. Try again.", error: true);
                RunSearch();
                return;
            }
            var chars = secret.ToChars();
            try
            {
                _clipboard.Arm(SecureClipboard.SetText(ClipboardOwner, chars, sensitive: true), _settings.ClipboardClearSeconds);
            }
            finally
            {
                Array.Clear(chars);
            }
            Done(entry);
        }
        catch (Exception ex) when (ex is ObjectDisposedException or System.Security.Cryptography.CryptographicException or Win32Exception)
        {
            SetStatus(ex is Win32Exception ? ex.Message : "Decryption failed.", error: true);
        }
    }

    private void CopyUsername()
    {
        if (Selected?.Entry is not { } entry) return;
        if (string.IsNullOrEmpty(entry.Username))
        {
            SetStatus("This item has no username.", error: true);
            return;
        }
        CopyPlain(entry, entry.Username);
    }

    private void CopyWebsite()
    {
        if (Selected?.Entry is not { } entry) return;
        if (string.IsNullOrEmpty(entry.Uri))
        {
            SetStatus("This item has no website.", error: true);
            return;
        }
        CopyPlain(entry, entry.Uri);
    }

    private void CopyPlain(VaultEntry entry, string value)
    {
        try
        {
            SecureClipboard.SetText(ClipboardOwner, value, sensitive: false);
            Done(entry);
        }
        catch (Win32Exception ex)
        {
            SetStatus(ex.Message, error: true);
        }
    }

    private void Done(VaultEntry entry)
    {
        _settings.MarkUsed(entry.Id);
        Hide();
    }
}
