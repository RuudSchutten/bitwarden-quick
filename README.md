# BitwardenQuick

Search your Bitwarden vault from anywhere in Windows, similar to Quick Access in 1Password.

Unofficial; not affiliated with Bitwarden.

## Usage

| Key | Action |
| --- | --- |
| `Ctrl+Shift+Space` | Open the search window |
| `↑` / `↓` | Select an item |
| `Enter` or `Ctrl+Shift+C` | Copy password |
| `Ctrl+C` | Copy username |
| `Ctrl+Alt+C` | Copy the one-time password (TOTP) |
| `Ctrl+Shift+U` | Copy website |
| `Alt+Enter` | Open the website in your browser |
| `Shift+Enter` | Auto-Type: type username, Tab, password, Enter into the window you came from, then copy the one-time password if the item has one |
| `Ctrl+Shift+O` | Open the item in the Bitwarden web vault |
| `→` | More actions for the selected item (`Esc` or `←` goes back) |
| `Ctrl+Shift+/` or `F1` | Keyboard shortcuts |
| `Esc` | Close |

Run `publish\BitwardenQuick.exe`. On first start BitwardenQuick asks for your personal API key
(vault.bitwarden.com › Settings › Security › Keys › View API key) and your master password.
After that it starts with Windows and runs in the system tray.

Build:

```
dotnet publish src\BitwardenQuick -c Release -r win-x64 --self-contained false -p:PublishReadyToRun=true -p:RestoreLockedMode=true -o publish
```

## Locking

BitwardenQuick starts locked and locks again when Windows locks, when the PC goes to sleep, after 15 minutes without
keyboard or mouse input, or from the tray menu. While locked, the user key, the decrypted vault and the access
token are not in memory, and BitwardenQuick does not sync.

Unlock with Windows Hello (face, fingerprint or PIN). Without Windows Hello, or when it fails, BitwardenQuick asks
for your master password.

## Security

- Talks to bitwarden.com directly; no Bitwarden CLI, local server or open port. Only https is accepted.
- The master password is never stored. On disk the user key exists only encrypted: with your master key, as
  Bitwarden stores it, and with a key derived from a Windows Hello signature. The API client secret is
  encrypted with the user key. All of it is wrapped once more with DPAPI in `%LOCALAPPDATA%\BitwardenQuick`.
- The local vault copy is Bitwarden's encrypted sync data, wrapped once more with DPAPI.
- Vault keys are kept encrypted in memory with `CryptProtectMemory`. Passwords are decrypted only when copied
  and go to the clipboard without passing through a managed string.
- Copied passwords are excluded from clipboard history (Win+V) and cloud clipboard, and are cleared after
  30 seconds if they are still on the clipboard, when BitwardenQuick locks, and when it crashes.
- The search window and the password dialogs are hidden from screen sharing and screen recordings.
- Items with "Master password re-prompt" require Windows Hello (or the master password) before the password
  is copied. A master password is only accepted if it unwraps the key the vault is unlocked with.
- After three wrong master passwords, each further attempt waits longer, up to 32 seconds.
- NuGet dependencies are pinned by content hash in `packages.lock.json`.
- The server's KDF settings are checked against Bitwarden's bounds.
- Website icons come from Bitwarden's icon service (`icons.bitwarden.net`, or `/icons` on a self-hosted server),
  like in Bitwarden's own apps. That service sees the host names of your logins, never other item data. Addresses
  on a local network (IP addresses, `localhost`, `.local`, `.lan`, `.internal`, names without a dot) are not sent.
  Icons are only fetched for results on screen, and are kept as 48-pixel PNGs (a few KB each) in `icons.dat`,
  encrypted with your user key like the vault. They are refreshed after 30 days, missing icons after 7.
- Auto-Type only types into the window that was in front when you pressed the hotkey, and only once that window
  is in front again; never into the taskbar or desktop. Items with "Master password re-prompt" ask for
  confirmation first.
- Open in browser only opens `http` and `https` addresses.
- One-time passwords are computed on this PC from the item's authenticator key, which is decrypted only for that.
  Like passwords they are excluded from clipboard history, cleared after 30 seconds, and need confirmation for
  items with "Master password re-prompt".

### Limitations

- While BitwardenQuick is unlocked, a program running as you can read its memory or the clipboard. Locking limits
  how long that window is open.
- The stored user key is encrypted with your master key, like in Bitwarden's own apps. Someone who obtains
  that file and can decrypt it as you can try to guess your master password offline, so use a strong one.
- Signing out in BitwardenQuick only deletes local data and the Windows Hello key. If your PC may be compromised,
  rotate your API key on vault.bitwarden.com.
- The re-prompt check runs in BitwardenQuick itself; it does not protect against software running as you.

## Settings

`%LOCALAPPDATA%\BitwardenQuick\settings.json`: `Hotkey`, `ClipboardClearSeconds`, `LockAfterIdleMinutes`
(`0` disables the idle lock), `HideFromScreenCapture`, `ShowWebsiteIcons`.
Lock, and sign out and delete all local data, from the tray icon menu.

For a self-hosted server, set `BITWARDENQUICK_SERVER` to its base URL (https only) before setup. An account set up
for one server is not used with another. `BITWARDENQUICK_DATA_DIR` moves the data folder.
