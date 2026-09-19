#ifndef AppVersion
  #define AppVersion "6.0.0"
#endif
#ifndef NumericVersion
  #define NumericVersion "6.0.0.999"
#endif

[Setup]
AppId={{9B2A0F5E-4C3D-4E1B-8A6F-2D7C9E0B1A5D}
AppName=NetLurker
AppVersion={#AppVersion}
VersionInfoVersion={#NumericVersion}
VersionInfoProductVersion={#NumericVersion}
VersionInfoProductTextVersion={#AppVersion}
VersionInfoTextVersion={#AppVersion}
AppPublisher=NetLurker
AppPublisherURL=https://github.com/thesyntax1/NetLurker
AppSupportURL=https://github.com/thesyntax1/NetLurker/issues
DefaultDirName={userpf}\NetLurker
DefaultGroupName=NetLurker
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputBaseFilename=NetLurker-v{#AppVersion}-setup
OutputDir=..\dist
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\NetLurker.exe
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"

[Files]
Source: "..\build\NetLurker.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\lang\*.ini"; DestDir: "{app}\lang"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\PRIVACY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\NetLurker"; Filename: "{app}\NetLurker.exe"
Name: "{autodesktop}\NetLurker"; Filename: "{app}\NetLurker.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional options:"

[Run]
Filename: "{app}\NetLurker.exe"; Description: "Run NetLurker now"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if (not UninstallSilent) and (MsgBox('Also delete NetLurker caches and settings?' + #13#10 +
              '(geoip_cache.tsv, threat_cache.tsv, cert_cache.tsv, banner_cache.tsv, baseline2.tsv, config.ini)',
              mbConfirmation, MB_YESNO) = IDYES) then
      DelTree(ExpandConstant('{userappdata}\NetLurker'), True, True, True);
  end;
end;
