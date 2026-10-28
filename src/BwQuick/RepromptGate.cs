using System.Windows;
using System.Windows.Interop;
using BwQuick.Core;
using Windows.Security.Credentials.UI;

namespace BwQuick;

/// <summary>
/// Honors Bitwarden's "master password re-prompt" flag with Windows Hello, falling back
/// to the master password when Hello is not set up.
/// </summary>
internal static class RepromptGate
{
    public static async Task<bool> ConfirmAsync(Window owner, string itemName, VaultService service)
    {
        try
        {
            if (await UserConsentVerifier.CheckAvailabilityAsync() == UserConsentVerifierAvailability.Available)
            {
                var hwnd = new WindowInteropHelper(owner).Handle;
                var result = await UserConsentVerifierInterop.RequestVerificationForWindowAsync(
                    hwnd, $"Bevestig dat je het wachtwoord van \"{itemName}\" wilt kopiëren.");
                return result == UserConsentVerificationResult.Verified;
            }
        }
        catch (Exception e) when (e is System.Runtime.InteropServices.COMException or InvalidOperationException)
        {
        }

        return PasswordPromptWindow.Ask(owner, itemName, service);
    }
}
