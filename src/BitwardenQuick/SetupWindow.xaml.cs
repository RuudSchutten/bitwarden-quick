using System.Net.Http;
using System.Windows;
using System.Windows.Media;
using BitwardenQuick.Core;
using BitwardenQuick.Core.Api;

namespace BitwardenQuick;

public partial class SetupWindow : Window
{
    private readonly VaultService _service;
    private readonly BitwardenServer _fixedServer;
    private readonly bool _canChooseRegion;

    internal event Action? Completed;

    /// <summary>Raised with the region to sign in to, before the sign-in starts.</summary>
    internal event Action<BitwardenServer>? ServerChosen;

    internal SetupWindow(VaultService service, string? reason, BitwardenServer server, bool canChooseRegion)
    {
        _service = service;
        _fixedServer = server;
        _canChooseRegion = canChooseRegion;
        InitializeComponent();
        RegionPanel.Visibility = canChooseRegion ? Visibility.Visible : Visibility.Collapsed;
        RegionEu.IsChecked = server == BitwardenServer.Europe;
        VaultHost.Text = server.WebVault.Host;
        if (reason is not null) ShowStatus(reason, error: true);
        Loaded += (_, _) => ClientId.Focus();
    }

    private void ShowStatus(string text, bool error = false)
    {
        Status.Text = text;
        Status.Foreground = (Brush)Application.Current.Resources[error ? "ErrorBrush" : "MutedBrush"];
    }

    private BitwardenServer Server => !_canChooseRegion ? _fixedServer
        : RegionEu.IsChecked == true ? BitwardenServer.Europe : BitwardenServer.UnitedStates;

    private void OnRegionChanged(object sender, RoutedEventArgs e)
    {
        // Also raised while the XAML loads, before every named element exists.
        if (VaultHost is not null && RegionEu is not null) VaultHost.Text = Server.WebVault.Host;
    }

    private async void OnConnect(object sender, RoutedEventArgs e)
    {
        if (ClientId.Text.Trim().Length == 0 || ClientSecret.SecurePassword.Length == 0 || MasterPassword.SecurePassword.Length == 0)
        {
            ShowStatus("Fill in all three fields.", error: true);
            return;
        }

        var server = Server;
        SetBusy(true);
        try
        {
            ServerChosen?.Invoke(server);
            using var master = SecretInput.FromSecureString(MasterPassword.SecurePassword);
            // Reports are posted, so one can arrive after a quick failure and would hide its message.
            var progress = new Progress<string>(text =>
            {
                if (!Connect.IsEnabled) ShowStatus(text);
            });
            await _service.SetupAsync(ClientId.Text, ClientSecret.Password, master, progress);
            MasterPassword.Clear();
            ClientSecret.Clear();

            try { AppSettings.StartWithWindows = Autostart.IsChecked == true; }
            catch (UnauthorizedAccessException) { }

            Completed?.Invoke();
            Close();
        }
        catch (SetupException ex)
        {
            ShowStatus(ex.Message, error: true);
            MasterPassword.Clear();
            MasterPassword.Focus();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            ShowStatus($"Could not connect to {server.Name}. Try again later.", error: true);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        Connect.IsEnabled = !busy;
        ClientId.IsEnabled = !busy;
        ClientSecret.IsEnabled = !busy;
        MasterPassword.IsEnabled = !busy;
        RegionPanel.IsEnabled = !busy;
    }
}
