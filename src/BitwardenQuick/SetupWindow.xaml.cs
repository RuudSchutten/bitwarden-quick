using System.Net.Http;
using System.Windows;
using System.Windows.Media;
using BitwardenQuick.Core;

namespace BitwardenQuick;

public partial class SetupWindow : Window
{
    private readonly VaultService _service;

    internal event Action? Completed;

    internal SetupWindow(VaultService service, string? reason)
    {
        _service = service;
        InitializeComponent();
        if (reason is not null) ShowStatus(reason, error: true);
        Loaded += (_, _) => ClientId.Focus();
    }

    private void ShowStatus(string text, bool error = false)
    {
        Status.Text = text;
        Status.Foreground = (Brush)Application.Current.Resources[error ? "ErrorBrush" : "MutedBrush"];
    }

    private async void OnConnect(object sender, RoutedEventArgs e)
    {
        if (ClientId.Text.Trim().Length == 0 || ClientSecret.SecurePassword.Length == 0 || MasterPassword.SecurePassword.Length == 0)
        {
            ShowStatus("Fill in all three fields.", error: true);
            return;
        }

        SetBusy(true);
        try
        {
            using var master = SecretInput.FromSecureString(MasterPassword.SecurePassword);
            var progress = new Progress<string>(text => ShowStatus(text));
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
            ShowStatus("Could not connect to bitwarden.com. Try again later.", error: true);
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
    }
}
