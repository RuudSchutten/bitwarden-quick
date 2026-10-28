# BwQuick

Snelzoeken in je Bitwarden-kluis vanaf elke plek in Windows, zoals Quick Access in 1Password.

## Gebruik

| Toets | Actie |
| --- | --- |
| `Ctrl+Shift+Space` | Zoekvenster openen |
| `↑` / `↓` | Item kiezen |
| `Enter` of `Ctrl+Shift+C` | Wachtwoord kopiëren |
| `Ctrl+C` | Gebruikersnaam kopiëren |
| `Ctrl+Shift+U` | Website kopiëren |
| `Esc` | Sluiten |

Starten: `publish\BwQuick.exe`. De eerste keer vraagt BwQuick om je persoonlijke API-key
(vault.bitwarden.com › Instellingen › Beveiliging › Sleutels › API-sleutel bekijken) en je hoofdwachtwoord.
Daarna start het met Windows mee en draait het in het systeemvak.

Bouwen:

```
dotnet publish src\BwQuick -c Release -r win-x64 --self-contained false -p:PublishReadyToRun=true -o publish
```

## Beveiliging

- Praat rechtstreeks met bitwarden.com; geen Bitwarden CLI, lokale server of open poort.
- Het hoofdwachtwoord wordt nooit opgeslagen. Alleen de afgeleide kluissleutel en de API-key worden met
  DPAPI (gebonden aan je Windows-account) opgeslagen in `%LOCALAPPDATA%\BwQuick`.
- De lokale kluiskopie is de versleutelde sync van Bitwarden, nog eens extra met DPAPI ingepakt.
- Sleutels staan in het geheugen versleuteld met `CryptProtectMemory`. Wachtwoorden worden pas bij het
  kopiëren ontsleuteld en gaan zonder managed string direct naar het klembord.
- Gekopieerde wachtwoorden worden uitgesloten van de klembordgeschiedenis (Win+V) en cloud-sync, en na
  30 seconden gewist als ze dan nog op het klembord staan.
- Het zoekvenster is onzichtbaar bij schermdelen en schermopnames.
- Items met "hoofdwachtwoord opnieuw vragen" vragen om Windows Hello (of het hoofdwachtwoord).
- KDF-instellingen van de server worden gecontroleerd op minimale sterkte.

## Instellingen

`%LOCALAPPDATA%\BwQuick\settings.json`: `Hotkey`, `ClipboardClearSeconds`, `HideFromScreenCapture`.
Uitloggen en alle lokale gegevens wissen kan via het systeemvakicoon.
