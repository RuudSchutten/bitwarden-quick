using System.Windows;
using BwQuick.Core.Crypto;
using BwQuick.Native;

namespace BwQuick;

public partial class PasswordPromptWindow : Window
{
    private static int _failures;
    private readonly Func<Secret, bool> _verify;

    private PasswordPromptWindow(string title, string message, string button, Func<Secret, bool> verify)
    {
        _verify = verify;
        InitializeComponent();
        Title = title;
        Message.Text = message;
        Confirm.Content = button;
        SourceInitialized += (_, _) => WindowEffects.ExcludeFromCapture(this, true);
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
        if (ok)
        {
            _failures = 0;
            DialogResult = true;
            return;
        }
        Error.Visibility = Visibility.Visible;
        if (++_failures >= 3) await Task.Delay(TimeSpan.FromSeconds(1 << Math.Min(_failures - 3, 5)));
        Confirm.IsEnabled = true;
        Password.Focus();
    }
}
