using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using BitwardenQuick.Core;
using BitwardenQuick.Core.Items;
using BitwardenQuick.Native;

namespace BitwardenQuick;

public sealed class ResultItem : INotifyPropertyChanged
{
    private readonly IconCache? _icons;
    private ImageSource? _icon;
    private bool _iconRequested;

    internal ResultItem(VaultEntry entry, IconCache? icons)
    {
        Entry = entry;
        Avatar = Theme.AvatarFor(entry.Host ?? entry.Name);
        _icons = icons;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public VaultEntry Entry { get; }
    public string Name => Entry.Name;
    public string Initial => Entry.Initial;
    public Brush Avatar { get; }
    public string Details => Join(" – ", "", Entry.Username, Entry.Host);
    public string Summary => Join(" – ", null, Entry.Username, Entry.Uri);
    public string PrimaryAction => Entry.HasPassword ? "Copy password" : "";
    public Visibility RepromptVisibility => Entry.Reprompt ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>Fetched on first read, which happens when a row is shown, so hidden rows cost nothing.</summary>
    public ImageSource? Icon
    {
        get
        {
            if (!_iconRequested)
            {
                _iconRequested = true;
                LoadIcon();
            }
            return _icon;
        }
        private set
        {
            if (ReferenceEquals(_icon, value)) return;
            _icon = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Icon)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IconVisibility)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(InitialVisibility)));
        }
    }

    private async void LoadIcon()
    {
        if (_icons?.Get(Entry.Uri) is { } icon) Icon = await icon;
    }

    public Visibility IconVisibility => _icon is null ? Visibility.Collapsed : Visibility.Visible;
    public Visibility InitialVisibility => _icon is null ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>Joins the non-empty parts; <paramref name="lead"/> non-null puts a separator in front as well.</summary>
    private static string Join(string separator, string? lead, params string?[] parts)
    {
        var text = string.Join(separator, parts.Where(p => !string.IsNullOrEmpty(p)));
        return lead is null || text.Length == 0 ? text : separator + text;
    }
}

public sealed class ActionItem(string label, string shortcut, Action run)
{
    public string Label { get; } = label;
    public string Shortcut { get; } = shortcut;
    public Action Run { get; } = run;
    public bool GroupStart { get; set; }
    public Visibility DividerVisibility => GroupStart ? Visibility.Visible : Visibility.Collapsed;
}

public sealed record ShortcutInfo(string Label, string[] Keys);

public partial class QuickWindow : Window
{
    private enum View { Search, Actions, Shortcuts }

    private readonly VaultService _service;
    private readonly AppSettings _settings;
    private readonly ClipboardGuard _clipboard;
    private readonly IconCache _icons;
    private readonly Uri _webVault;
    private readonly bool _acrylic = WindowEffects.SupportsBackdrop;
    private View _view;
    private ResultItem? _actionsItem;
    private nint _target;
    private bool _modal;
    private bool _syncing;

    internal event Action? SetupRequested;
    internal event Action? SyncRequested;

    internal QuickWindow(VaultService service, AppSettings settings, ClipboardGuard clipboard, IconCache icons, Uri webVault)
    {
        _service = service;
        _settings = settings;
        _clipboard = clipboard;
        _icons = icons;
        _webVault = webVault;
        InitializeComponent();

        var hotkey = settings.Hotkey.Split('+', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        foreach (var key in hotkey)
            HotkeyCaps.Children.Add(new Border
            {
                Style = (Style)FindResource("KeyCap"),
                Child = new TextBlock { Style = (Style)FindResource("KeyText"), Text = key },
            });
        ShortcutList.ItemsSource = new ShortcutInfo[]
        {
            new("Show BitwardenQuick", hotkey),
            new("Copy password", ["Enter"]),
            new("Copy username", ["Ctrl", "C"]),
            new("Copy password", ["Ctrl", "Shift", "C"]),
            new("Copy website", ["Ctrl", "Shift", "U"]),
            new("Open in browser", ["Alt", "Enter"]),
            new("Auto-Type", ["Shift", "Enter"]),
            new("Open in Bitwarden", ["Ctrl", "Shift", "O"]),
            new("More actions", ["→"]),
            new("Back or close", ["Esc"]),
        };

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

    /// <summary>Remembers the window in front, before an unlock prompt takes its place, so Auto-Type can type into it.</summary>
    internal void RememberTarget()
    {
        if (!IsVisible) _target = AutoType.ForegroundWindowOfOtherProcess();
    }

    internal void ShowQuick()
    {
        if (_service.NeedsSetup || !_service.IsConfigured)
        {
            SetupRequested?.Invoke();
            return;
        }

        _view = View.Search;
        SearchBox.Clear();
        RunSearch();
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
        UpdateStatus();
    }

    internal void OnVaultChanged()
    {
        if (IsVisible) RunSearch();
        else UpdateStatus();
    }

    private void OnSearchChanged(object sender, TextChangedEventArgs e)
    {
        Placeholder.Visibility = SearchBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        _view = View.Search;
        RunSearch();
    }

    private void RunSearch()
    {
        var vault = _service.Current;
        var query = SearchBox.Text.Trim();
        List<ResultItem> items = vault is null || query.Length == 0
            ? []
            : VaultSearch.Search(vault.Entries, query, _settings.Recent).Select(e => new ResultItem(e, _icons)).ToList();

        Results.ItemsSource = items;
        Results.SelectedIndex = items.Count > 0 ? 0 : -1;
        if (items.Count > 0) Results.ScrollIntoView(items[0]);
        EmptyText.Text = vault is null ? "Loading vault…" : $"No results for \"{query}\".";
        UpdateView();
        UpdateStatus();
    }

    private void UpdateView()
    {
        static Visibility Show(bool visible) => visible ? Visibility.Visible : Visibility.Collapsed;

        var search = _view == View.Search;
        var results = Results.Items.Count > 0;
        Results.Visibility = Show(search && results);
        EmptyText.Visibility = Show(search && !results && SearchBox.Text.Trim().Length > 0);
        ActionsPanel.Visibility = Show(_view == View.Actions);
        ShortcutsPanel.Visibility = Show(_view == View.Shortcuts);
        IdleHints.Visibility = Show(_view == View.Shortcuts || (search && !results));
        ResultHints.Visibility = Show(search && results);
        LocatedIn.Visibility = Show(_view == View.Actions);
        ClearButton.Visibility = Show(SearchBox.Text.Length > 0);
        if (search && Results.SelectedItem is { } selected) Results.ScrollIntoView(selected);
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
        StatusText.ToolTip = text;
        StatusText.Foreground = (Brush)Application.Current.Resources[error ? "ErrorBrush" : "MutedBrush"];
    }

    /// <summary>The item the actions apply to: the one whose actions are open, else the selected result.</summary>
    private ResultItem? Current => _view == View.Actions ? _actionsItem : Results.SelectedItem as ResultItem;

    private void OnKey(object sender, KeyEventArgs e)
    {
        var key = e.Key == Key.System ? e.SystemKey : e.Key;
        var modifiers = Keyboard.Modifiers;
        var ctrl = modifiers.HasFlag(ModifierKeys.Control);
        var shift = modifiers.HasFlag(ModifierKeys.Shift);
        var alt = modifiers.HasFlag(ModifierKeys.Alt);

        switch (key)
        {
            case Key.Escape when _view != View.Search:
            case Key.Left when _view == View.Actions:
                ShowSearch();
                break;
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
            case Key.Right when _view == View.Search && modifiers == ModifierKeys.None && CaretAtEnd && Current is { } item:
                ShowActions(item);
                break;
            case Key.Enter when alt:
                OpenInBrowser();
                break;
            case Key.Enter when shift:
                AutoTypeCurrent();
                break;
            case Key.Enter when _view == View.Actions:
                (ActionList.SelectedItem as ActionItem)?.Run();
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
            case Key.O when ctrl && shift:
                OpenInBitwarden();
                break;
            case Key.OemQuestion or Key.Divide when ctrl && shift:
            case Key.F1:
                ToggleShortcuts();
                break;
            default:
                return;
        }
        e.Handled = true;
    }

    private bool CaretAtEnd => SearchBox.SelectionLength > 0 || SearchBox.CaretIndex == SearchBox.Text.Length;

    private void Move(int delta)
    {
        var list = _view switch
        {
            View.Search => Results,
            View.Actions => ActionList,
            _ => null,
        };
        if (list is null || list.Items.Count == 0) return;
        list.SelectedIndex = Math.Clamp(list.SelectedIndex + delta, 0, list.Items.Count - 1);
        list.ScrollIntoView(list.SelectedItem);
    }

    private void ShowSearch()
    {
        _view = View.Search;
        UpdateView();
    }

    private void ToggleShortcuts()
    {
        _view = _view == View.Shortcuts ? View.Search : View.Shortcuts;
        UpdateView();
    }

    private void ShowActions(ResultItem item)
    {
        var entry = item.Entry;
        var actions = new List<ActionItem>();
        if (!string.IsNullOrEmpty(entry.Username)) actions.Add(new("Copy username", "Ctrl+C", CopyUsername));
        if (entry.HasPassword) actions.Add(new("Copy password", "Ctrl+Shift+C", CopyPassword));
        if (!string.IsNullOrEmpty(entry.Uri)) actions.Add(new("Copy website", "Ctrl+Shift+U", CopyWebsite));
        var firstOpen = actions.Count;
        if (WebUri(entry.Uri) is not null) actions.Add(new("Open in browser", "Alt+Enter", OpenInBrowser));
        if (entry.HasPassword || !string.IsNullOrEmpty(entry.Username)) actions.Add(new("Auto-Type", "Shift+Enter", AutoTypeCurrent));
        actions.Add(new("Open in Bitwarden", "Ctrl+Shift+O", OpenInBitwarden));
        actions[firstOpen].GroupStart = firstOpen > 0;

        _actionsItem = item;
        ActionsPanel.DataContext = item;
        ActionList.ItemsSource = actions;
        ActionList.SelectedIndex = 0;
        var organization = entry.OrganizationName;
        LocatedInIcon.Text = organization is null ? "" : "";
        LocatedInText.Text = organization ?? _service.Email ?? "My vault";
        _view = View.Actions;
        UpdateView();
    }

    private void OnMoreClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not ResultItem item) return;
        Results.SelectedItem = item;
        ShowActions(item);
    }

    private void OnCloseActionsClick(object sender, RoutedEventArgs e) => ShowSearch();

    private void OnClearClick(object sender, RoutedEventArgs e)
    {
        SearchBox.Clear();
        Keyboard.Focus(SearchBox);
    }

    private void OnActionClick(object sender, MouseButtonEventArgs e)
    {
        if (ItemsControl.ContainerFromElement(ActionList, e.OriginalSource as DependencyObject) is ListBoxItem { DataContext: ActionItem action })
            action.Run();
    }

    private void OnResultDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ItemsControl.ContainerFromElement(Results, e.OriginalSource as DependencyObject) is ListBoxItem) CopyPassword();
    }

    private nint ClipboardOwner => new WindowInteropHelper(this).Handle;

    /// <summary>Looks the item up again, since a sync may have replaced or removed it.</summary>
    private VaultEntry? CurrentEntry(bool needPassword)
    {
        if (Current is not { } item) return null;
        if (_service.Current?.Find(item.Entry.Id) is not { } entry)
        {
            SetStatus("Item no longer exists. Try again.", error: true);
            ShowSearch();
            RunSearch();
            return null;
        }
        if (needPassword && !entry.HasPassword)
        {
            SetStatus("This item has no password.", error: true);
            return null;
        }
        return entry;
    }

    private async Task<bool> ConfirmAsync(VaultEntry entry, string verb)
    {
        if (!entry.Reprompt) return true;
        _modal = true;
        bool confirmed;
        try
        {
            confirmed = await RepromptGate.ConfirmAsync(this, entry.Name, _service, verb);
        }
        finally
        {
            _modal = false;
        }
        if (!confirmed)
        {
            SetStatus("Not confirmed.", error: true);
            Activate();
        }
        return confirmed;
    }

    private async void CopyPassword()
    {
        if (CurrentEntry(needPassword: true) is not { } entry || !await ConfirmAsync(entry, "copy")) return;
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
        if (CurrentEntry(needPassword: false) is not { } entry) return;
        if (string.IsNullOrEmpty(entry.Username))
        {
            SetStatus("This item has no username.", error: true);
            return;
        }
        CopyPlain(entry, entry.Username);
    }

    private void CopyWebsite()
    {
        if (CurrentEntry(needPassword: false) is not { } entry) return;
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

    private void OpenInBrowser()
    {
        if (CurrentEntry(needPassword: false) is not { } entry) return;
        if (WebUri(entry.Uri) is not { } uri)
        {
            SetStatus("This item has no website.", error: true);
            return;
        }
        Launch(uri, entry);
    }

    private void OpenInBitwarden()
    {
        if (CurrentEntry(needPassword: false) is not { } entry) return;
        Launch(new Uri($"{_webVault.AbsoluteUri}#/vault?itemId={Uri.EscapeDataString(entry.Id)}&action=view"), entry);
    }

    private void Launch(Uri uri, VaultEntry entry)
    {
        try
        {
            Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true })?.Dispose();
            Done(entry);
        }
        catch (Win32Exception ex)
        {
            SetStatus(ex.Message, error: true);
        }
    }

    /// <summary>Only http and https, so a vault item cannot make the shell run a file or another protocol handler.</summary>
    private static Uri? WebUri(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        value = value.Trim();
        var candidate = value.Contains("://", StringComparison.Ordinal) ? value : "https://" + value;
        return Uri.TryCreate(candidate, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
            ? uri
            : null;
    }

    private async void AutoTypeCurrent()
    {
        if (CurrentEntry(needPassword: false) is not { } entry) return;
        if (!entry.HasPassword && string.IsNullOrEmpty(entry.Username))
        {
            SetStatus("This item has no username or password.", error: true);
            return;
        }
        var target = _target;
        if (target == 0 || !Win32.IsWindow(target))
        {
            SetStatus("No window to type into.", error: true);
            return;
        }
        if (!await ConfirmAsync(entry, "type")) return;

        char[]? password = null;
        string? error;
        try
        {
            using (var secret = entry.HasPassword ? _service.DecryptPassword(entry.Id) : null)
                password = secret?.ToChars();
            _settings.MarkUsed(entry.Id);
            Hide();
            error = await AutoType.TypeAsync(target, entry.Username, password);
        }
        catch (Exception ex) when (ex is ObjectDisposedException or System.Security.Cryptography.CryptographicException)
        {
            error = "Decryption failed.";
        }
        finally
        {
            if (password is not null) Array.Clear(password);
        }

        if (error is null) return;
        if (!IsVisible)
        {
            WindowEffects.PlaceOnCursorMonitor(this);
            Show();
            Activate();
            Keyboard.Focus(SearchBox);
        }
        SetStatus(error, error: true);
    }

    private void Done(VaultEntry entry)
    {
        _settings.MarkUsed(entry.Id);
        Hide();
    }
}
