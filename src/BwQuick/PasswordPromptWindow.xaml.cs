using System.Windows;
using BwQuick.Core;

namespace BwQuick;

public partial class PasswordPromptWindow : Window
{
    private readonly VaultService _service;

    private PasswordPromptWindow(VaultService service, string itemName)
    {
        _service = service;
        InitializeComponent();
        Message.Text = $"\"{itemName}\" requires your master password. Windows Hello is not set up on this PC.";
        Loaded += (_, _) => Password.Focus();
    }

    internal static bool Ask(Window owner, string itemName, VaultService service)
    {
        var dialog = new PasswordPromptWindow(service, itemName);
        if (owner.IsVisible) dialog.Owner = owner;
        return dialog.ShowDialog() == true;
    }

    private async void OnConfirm(object sender, RoutedEventArgs e)
    {
        Confirm.IsEnabled = false;
        Error.Visibility = Visibility.Collapsed;
        using var secret = SecretInput.FromSecureString(Password.SecurePassword);
        Password.Clear();
        var ok = await Task.Run(() => _service.VerifyMasterPassword(secret));
        Confirm.IsEnabled = true;
        if (ok)
        {
            DialogResult = true;
            return;
        }
        Error.Visibility = Visibility.Visible;
        Password.Focus();
    }
}
