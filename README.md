# BwQuick

Search your Bitwarden vault from anywhere in Windows, similar to Quick Access in 1Password.

Unofficial; not affiliated with Bitwarden.

## Usage

| Key | Action |
| --- | --- |
| `Ctrl+Shift+Space` | Open the search window |
| `↑` / `↓` | Select an item |
| `Enter` or `Ctrl+Shift+C` | Copy password |
| `Ctrl+C` | Copy username |
| `Ctrl+Shift+U` | Copy website |
| `Esc` | Close |

Run `publish\BwQuick.exe`. On first start BwQuick asks for your personal API key
(vault.bitwarden.com › Settings › Security › Keys › View API key) and your master password.
After that it starts with Windows and runs in the system tray.

Build:

```
dotnet publish src\BwQuick -c Release -r win-x64 --self-contained false -p:PublishReadyToRun=true -o publish
```

## Security

- Talks to bitwarden.com directly; no Bitwarden CLI, local server or open port.
- The master password is never stored. The vault's user key and the API key are stored in
  `%LOCALAPPDATA%\BwQuick`, protected with DPAPI (bound to your Windows account).
- The local vault copy is Bitwarden's encrypted sync data, wrapped once more with DPAPI.
- Vault keys are kept encrypted in memory with `CryptProtectMemory`. Passwords are decrypted only when copied
  and go to the clipboard without passing through a managed string.
- Copied passwords are excluded from clipboard history (Win+V) and cloud clipboard, and are cleared after
  30 seconds if they are still on the clipboard.
- The search window is hidden from screen sharing and screen recordings.
- Items with "Master password re-prompt" require Windows Hello (or the master password) before the password
  is copied.
- The server's KDF settings are checked against Bitwarden's minimums.

### Limitations

- BwQuick does not lock. Anyone who can use your unlocked Windows session can search and copy from your vault.
- At rest, the vault is only as safe as your Windows account: any program running as you can decrypt the stored
  key through DPAPI. Malware on your PC means your vault is exposed.
- Signing out in BwQuick only deletes local data. If your PC may be compromised, rotate your API key on
  vault.bitwarden.com.
- The re-prompt check runs in BwQuick itself; it does not protect against software running as you.

## Settings

`%LOCALAPPDATA%\BwQuick\settings.json`: `Hotkey`, `ClipboardClearSeconds`, `HideFromScreenCapture`.
Sign out and delete all local data from the tray icon menu.
