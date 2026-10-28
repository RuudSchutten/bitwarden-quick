using System.Windows;
using System.Windows.Interop;
using BitwardenQuick.Core;
using Windows.Security.Credentials.UI;

namespace BitwardenQuick;

/// <summary>
/// Honors Bitwarden's "master password re-prompt" flag with Windows Hello, falling back
/// to the master password when Hello is not set up.
/// </summary>
internal static class RepromptGate
{
    public static async Task<bool> ConfirmAsync(Window owner, string itemName, VaultService service, string verb = "copy")
    {
        try
        {
            if (await UserConsentVerifier.CheckAvailabilityAsync() == UserConsentVerifierAvailability.Available)
            {
                var hwnd = new WindowInteropHelper(owner).Handle;
                var result = await UserConsentVerifierInterop.RequestVerificationForWindowAsync(
                    hwnd, $"Confirm that you want to {verb} the password for \"{itemName}\".");
                return result == UserConsentVerificationResult.Verified;
            }
        }
        catch (Exception e) when (e is System.Runtime.InteropServices.COMException or InvalidOperationException)
        {
        }

        return PasswordPromptWindow.Ask(owner, "Confirm",
            $"\"{itemName}\" requires your master password. Windows Hello is not set up on this PC.",
            "Confirm", service.VerifyMasterPassword);
    }
}
