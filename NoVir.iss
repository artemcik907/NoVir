#define MyAppName "NoVir - Восстановление системы"
#define MyAppVersion "2.3"
#define MyAppPublisher "NoVir Project"
#define MyAppExeName "NoVir.exe"
#define MyAppURL "https://github.com/artemcik907/NoVir"

[Setup]
; Уникальный идентификатор приложения
AppId={{9B9B8E31-7C52-4C5B-9B20-9D8D0C1A7F42}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
VersionInfoVersion={#MyAppVersion}
VersionInfoProductVersion={#MyAppVersion}

; Директория по умолчанию
DefaultDirName={autopf}\NoVir
DefaultGroupName=NoVir

; Настройки сборки установщика
OutputDir=C:\Users\Ribot\Documents\NoVir\installer
OutputBaseFilename=NoVir_Setup_v2.3
UninstallDisplayIcon={app}\NoVir.exe
UninstallDisplayName={#MyAppName}

; Внешний вид и права
WizardStyle=modern
WizardResizable=yes
DisableWelcomePage=no
DisableProgramGroupPage=yes
DisableReadyMemo=no
DisableFinishedPage=no
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=no
RestartIfNeededByRun=no

; Сжатие
Compression=lzma2/ultra64
SolidCompression=yes

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительные значки:"; Flags: checkedonce
Name: "startmenuicon"; Description: "Добавить ярлык в меню «Пуск»"; GroupDescription: "Дополнительные значки:"; Flags: unchecked

[Files]
Source: "C:\Users\Ribot\Documents\NoVir\dist\NoVir.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\NoVir"; Filename: "{app}\NoVir.exe"; Tasks: startmenuicon
Name: "{autodesktop}\NoVir"; Filename: "{app}\NoVir.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\NoVir.exe"; Description: "Запустить NoVir (Восстановление системы)"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Messages]
SetupAppTitle=Установка — {#MyAppName}
SetupWindowTitle=Установка — {#MyAppName}
WelcomeLabel2=Этот мастер установит {#MyAppName} на ваш компьютер.%n%nNoVir помогает восстановить доступ к системным инструментам Windows после вредоносных атак и сбоев.%n%nДля спокойной установки рекомендуется закрыть открытые приложения и сохранить важные документы.
FinishedHeadingLabel=NoVir установлен
FinishedLabel=Установка завершена.%n%nЗапускайте NoVir только тогда, когда готовы выполнять восстановление системы. Для системных операций могут потребоваться права администратора.
ReadyLabel1=Всё готово к установке NoVir.%n%nПроверьте выбранную папку и дополнительные ярлыки, затем нажмите «Установить».
SelectDirLabel3=Выберите папку для установки NoVir.%n%nРекомендуется оставить предложенное расположение.
SelectTasksLabel2=Выберите удобные ярлыки для запуска NoVir.
ClickNext=Продолжить
ClickInstall=Установить NoVir
