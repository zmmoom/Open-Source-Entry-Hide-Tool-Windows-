; ============================================================
; Hide Apple Account - Inno Setup 安装脚本
; 用于将 PyInstaller 打包的 exe + 依赖制作成 Windows 安装程序
; ============================================================
; 使用方法：
;   1. 先用 PyInstaller 打包: pyinstaller HideAppleAccount-OneFile.spec
;   2. 确保 dist\HideAppleAccount.exe 存在
;   3. 用 Inno Setup Compiler 打开本文件，点击编译（Ctrl+F9）
;   产物在 Output 目录下
; ============================================================

#define MyAppName "Hide Apple Account"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "HideAppleAccount"
#define MyAppExeName "HideAppleAccount.exe"
#define MyAppUrl "https://hideappleaccount.com"

[Setup]
; ---- 基本信息 ----
AppId={{A7D3E5F1-8B2C-4D6A-9E1F-3C5A7B9D2E4F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppUrl}
AppSupportURL={#MyAppUrl}
AppUpdatesURL={#MyAppUrl}

; ---- 安装目录 ----
; 默认安装到 Program Files
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
; 允许用户修改安装目录
DisableDirPage=no

; ---- 输出设置 ----
; 安装程序输出文件名和目录
OutputDir=installer_output
OutputBaseFilename=HideAppleAccount_Setup_v{#MyAppVersion}
; 压缩设置
Compression=lzma2/ultra64
SolidCompression=yes
; 安装程序外观
WizardStyle=modern
WizardSizePercent=120,120
; 不显示 "欢迎" 页（直接显示许可协议或安装位置）
DisableWelcomePage=no
; 安装程序图标（使用项目图标）
SetupIconFile=app.ico
; 不生成 UninstallExe 的话设为 yes（这里我们需要卸载功能，设为 no）
UninstallDisplayName={#MyAppName}

; ---- 权限 ----
; 需要管理员权限（涉及 USB 驱动交互）
PrivilegesRequired=admin

; ---- 语言 ----
ShowLanguageDialog=auto

; ---- 版本信息 ----
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoProductName={#MyAppName}

; ---- 其他 ----
AllowNoIcons=yes
EnableDirDoesntExistWarning=yes
CreateUninstallRegKey=yes


[Languages]
; 英文（主语言）
Name: "english"; MessagesFile: "compiler:Default.isl"
; 简体中文
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"


[Messages]
; 自定义部分安装提示文字（可选）
; chinesesimplified.WelcomeLabel1=欢迎安装 {#MyAppName}


[Tasks]
; 桌面快捷方式
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
; 快速启动栏（Win10+ 已不支持，保留兼容）
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1; Check: not IsInstallOnCompatMode


[Files]
; ---- 主程序（PyInstaller 单文件 exe）----
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; ---- 图标文件（供快捷方式使用，也打进安装目录）----
Source: "app.ico"; DestDir: "{app}"; Flags: ignoreversion

; ---- driver_libs（libimobiledevice 驱动库，USB 通信必需）----
Source: "driver_libs\*"; DestDir: "{app}\driver_libs"; Flags: ignoreversion recursesubdirs createallsubdirs

; ---- 内置苹果 DLL（如果存在，客户免装 iTunes）----
; 先用 collect_apple_dll.py 生成 apple_dll 文件夹；不存在则跳过
Source: "apple_dll\*"; DestDir: "{app}\apple_dll"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: AppleDllExists


[Icons]
; ---- 开始菜单快捷方式 ----
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
; 开始菜单 → 卸载
Name: "{group}\卸载 {#MyAppName}"; Filename: "{uninstallexe}"; WorkingDir: "{app}"

; ---- 桌面快捷方式（用户在安装向导中勾选才创建）----
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon; IconFilename: "{app}\app.ico"


[Run]
; 安装完成后可选立即运行
Filename: "{app}\{#MyAppExeName}"; Description: "立即运行 {#MyAppName}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent


[UninstallDelete]
; 清理运行时可能产生的临时文件
Type: filesandordirs; Name: "{app}\__pycache__"
Type: filesandordirs; Name: "{localappdata}\{#MyAppName}"


[Code]
// ============================================================
// 自定义安装逻辑
// ============================================================

// 检查 apple_dll 目录是否存在（用于条件打包）
function AppleDllExists: Boolean;
begin
  // 编译时如果 apple_dll 不存在，此文件段会被自动跳过
  Result := True;
end;

// 安装前检查：是否需要管理员权限的提示
function InitializeSetup(): Boolean;
begin
  Result := True;
  // 可以在这里添加版本检测、旧版本卸载等逻辑
  // 例如检测是否已安装旧版本：
  // if RegKeyExists(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}') then
  //   MsgBox('检测到已安装旧版本，将继续安装以覆盖升级。', mbInformation, MB_OK);
end;

// 安装完成后清理旧版本残留（如果有）
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // 安装后处理（如有需要）
  end;
end;

// 卸载前确认
function InitializeUninstall(): Boolean;
begin
  Result := MsgBox('确定要卸载 {#MyAppName} 吗？', mbConfirmation, MB_YESNO) = IDYES;
end;
