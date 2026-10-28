using System.IO;
using System.Runtime.InteropServices;
using BitwardenQuick.Native;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;

namespace BitwardenQuick;

/// <summary>
/// A Windows Hello key whose signature over a stored challenge derives the key that wraps the
/// vault's user key on disk, so unlocking needs the user's face, fingerprint or PIN.
/// </summary>
internal static class WindowsHello
{
    private const string KeyName = "BitwardenQuick";
    private const string DialogClass = "Credential Dialog Xaml Host";

    public static async Task<bool> IsAvailableAsync()
    {
        try
        {
            return await KeyCredentialManager.IsSupportedAsync();
        }
        catch (COMException)
        {
            return false;
        }
    }

    public static async Task<(KeyCredentialStatus Status, byte[]? Signature)> SignAsync(byte[] challenge)
    {
        try
        {
            var opened = await KeyCredentialManager.OpenAsync(KeyName);
            if (opened.Status != KeyCredentialStatus.Success) return (opened.Status, null);
            return await SignAsync(opened.Credential, challenge);
        }
        catch (COMException)
        {
            return (KeyCredentialStatus.UnknownError, null);
        }
    }

    /// <summary>Creates a new key, replacing an old one, and signs the challenge with it.</summary>
    public static async Task<byte[]?> CreateAndSignAsync(byte[] challenge)
    {
        try
        {
            var created = await InFront(KeyCredentialManager.RequestCreateAsync(KeyName, KeyCredentialCreationOption.ReplaceExisting).AsTask());
            if (created.Status != KeyCredentialStatus.Success) return null;
            return (await SignAsync(created.Credential, challenge)).Signature;
        }
        catch (COMException)
        {
            return null;
        }
    }

    public static async Task DeleteAsync(string keyName = KeyName)
    {
        try
        {
            await KeyCredentialManager.DeleteAsync(keyName);
        }
        catch (Exception e) when (e is COMException or IOException)
        {
        }
    }

    private static async Task<(KeyCredentialStatus Status, byte[]? Signature)> SignAsync(KeyCredential credential, byte[] challenge)
    {
        var result = await InFront(credential.RequestSignAsync(CryptographicBuffer.CreateFromByteArray(challenge)).AsTask());
        if (result.Status != KeyCredentialStatus.Success) return (result.Status, null);
        CryptographicBuffer.CopyToByteArray(result.Result, out var signature);
        return (result.Status, signature);
    }

    /// <summary>The Hello dialog cannot be parented to a desktop window and often opens behind other windows.</summary>
    private static async Task<T> InFront<T>(Task<T> operation)
    {
        _ = Task.Run(async () =>
        {
            for (var attempt = 0; attempt < 30 && !operation.IsCompleted; attempt++)
            {
                if (Win32.FindWindow(DialogClass, null) is var dialog and not 0)
                {
                    Win32.SetForegroundWindow(dialog);
                    return;
                }
                await Task.Delay(100);
            }
        });
        return await operation;
    }
}
