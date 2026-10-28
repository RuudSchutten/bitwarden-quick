using System.Windows;
using BwQuick.Core.Crypto;

namespace BwQuick;

public partial class PasswordPromptWindow : Window
{
    private readonly Func<Secret, bool> _verify;

    private PasswordPromptWindow(string title, string message, string button, Func<Secret, bool> verify)
    {
        _verify = verify;
        InitializeComponent();
        Title = title;
        Message.Text = message;
        Confirm.Content = button;
        Loaded += (_, _) =>
        {
            Activate();
            Password.Focus();
        };
    }

    internal static bool Ask(Window? owner, string title, string message, string button, Func<Secret, bool> verify)
    {
        var dialog = new PasswordPromptWindow(title, message, button, verify);
        if (owner is { IsVisible: true }) dialog.Owner = owner;
        else dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        return dialog.ShowDialog() == true;
    }

    private async void OnConfirm(object sender, RoutedEventArgs e)
    {
        Confirm.IsEnabled = false;
        Error.Visibility = Visibility.Collapsed;
        using var secret = SecretInput.FromSecureString(Password.SecurePassword);
        Password.Clear();
        var ok = await Task.Run(() => _verify(secret));
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
