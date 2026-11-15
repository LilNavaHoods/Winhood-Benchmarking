; WinHood Benchmarking — Inno Setup 6 Official Windows x64 Installer Script
; Version 4.5.0

#define MyAppName "WinHood Benchmark Analyzer"
#define MyAppVersion "4.5.0"
#define MyAppPublisher "WinHood Engineering & AppSec"
#define MyAppURL "https://github.com/LilNavaHoods/Winhood-Benchmarking"
#define MyAppExeName "WinHood Benchmark Analyzer.exe"

[Setup]
AppId={{8F4E9A12-5C21-4B89-9E71-3D2C1098AF45}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\WinHoodBenchmarking
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\release-installer
OutputBaseFilename=WinHood-Benchmarking-Setup-v{#MyAppVersion}-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

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
Source: "..\release\win-unpacked\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Desinstalar {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
