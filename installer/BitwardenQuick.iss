; Per-user installer. Build with: iscc /DVersion=1.2.3-beta.1 /DNumericVersion=1.2.3 /DSourceDir=..\publish installer\BitwardenQuick.iss

#ifndef Version
  #define Version "0.0.0"
#endif
#ifndef NumericVersion
  #define NumericVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\publish"
#endif

[Setup]
AppId={{E02DC3D0-E720-43A8-A7BA-A1A9D08D3F5F}
AppName=BitwardenQuick
AppVersion={#Version}
AppVerName=BitwardenQuick {#Version}
AppPublisher=Ruud Schutten
VersionInfoVersion={#NumericVersion}
DefaultDirName={localappdata}\Programs\BitwardenQuick
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
OutputDir=..\dist
OutputBaseFilename=BitwardenQuick-{#Version}-setup
SetupIconFile=..\src\BitwardenQuick\app.ico
UninstallDisplayIcon={app}\BitwardenQuick.exe
UninstallDisplayName=BitwardenQuick
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
#ifdef Sign
SignTool=signtool
#endif

[Files]
Source: "{#SourceDir}\*"; Excludes: "*.pdb"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Files of an older version that this one no longer ships.
Type: filesandordirs; Name: "{app}\*"

[Icons]
Name: "{userprograms}\BitwardenQuick"; Filename: "{app}\BitwardenQuick.exe"

[Run]
Filename: "{app}\BitwardenQuick.exe"; Description: "Start BitwardenQuick"; Flags: nowait postinstall skipifsilent

[Code]
const
  RuntimeUrl = 'https://dotnet.microsoft.com/download/dotnet/10.0';
  RunKey = 'Software\Microsoft\Windows\CurrentVersion\Run';

function HasDesktopRuntime: Boolean;
var
  FindRec: TFindRec;
begin
  Result := FindFirst(ExpandConstant('{commonpf64}\dotnet\shared\Microsoft.WindowsDesktop.App\10.*'), FindRec);
  if Result then
    FindClose(FindRec);
end;

function InitializeSetup: Boolean;
var
  ErrorCode: Integer;
begin
  Result := True;
  if HasDesktopRuntime then
    Exit;
  if WizardSilent then
  begin
    Log('The .NET 10 Desktop Runtime (x64) is not installed.');
    Result := False;
    Exit;
  end;
  if MsgBox('BitwardenQuick needs the .NET 10 Desktop Runtime (x64), which is not installed.' + #13#10#13#10 +
            'Open the download page? Install the ".NET Desktop Runtime" for x64, then run this setup again.',
            mbConfirmation, MB_YESNO) = IDYES then
    ShellExec('open', RuntimeUrl, '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
  Result := False;
end;

function InitializeUninstall: Boolean;
begin
  Result := not CheckForMutexes('BitwardenQuick.Instance');
  if not Result then
    MsgBox('BitwardenQuick is running. Exit it from its tray icon menu, then uninstall again.', mbInformation, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Command: String;
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;
  if RegQueryStringValue(HKEY_CURRENT_USER, RunKey, 'BitwardenQuick', Command) and
     (Pos(Lowercase(ExpandConstant('{app}')), Lowercase(Command)) > 0) then
    RegDeleteValue(HKEY_CURRENT_USER, RunKey, 'BitwardenQuick');
end;
