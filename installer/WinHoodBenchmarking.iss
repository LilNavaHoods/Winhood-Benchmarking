; WinHood Benchmarking — Inno Setup 6 Official Windows x64 Installer Script
; Version synchronized with package.json (4.4.0)

#ifndef MyAppVersion
  #define MyAppVersion "4.4.0"
#endif

#define MyAppName "WinHood Benchmark Analyzer"
#define MyAppPublisher "WinHood Engineering & AppSec"
#define MyAppURL "https://github.com/LilNavaHoods/Winhood-Benchmarking"
#define MyAppExeName "WinHood Benchmark Analyzer.exe"

[Setup]
AppId={{8F4E9A12-5C21-4B89-9E71-3D2C1098AF45}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
VersionInfoVersion={#MyAppVersion}.0
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\WinHoodBenchmarking
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\release-windows\installer
OutputBaseFilename=WinHood-Benchmarking-Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\LICENSE
SetupIconFile=..\public\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Dirs]
Name: "{localappdata}\WinHoodBenchmarking\data"; Permissions: users-modify
Name: "{localappdata}\WinHoodBenchmarking\logs"; Permissions: users-modify
Name: "{localappdata}\WinHoodBenchmarking\keys"; Permissions: users-modify

[Files]
Source: "..\release-windows\win-unpacked\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Desinstalar {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
