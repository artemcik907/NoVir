; ═══════════════════════════════════════════════════════════════════════════
;  NoVir — установщик Windows (Inno Setup 7)
; ───────────────────────────────────────────────────────────────────────────
;  Сборка:        ISCC.exe NoVir.iss   (или открыть файл в Inno Setup и Compile)
;  Готовый файл:  installer\NoVir_Setup_v<версия>.exe
;
;  Перед релизом обновите MyAppVersion — имя файла, версия в «Установка и
;  удаление программ» и свойства установщика подставятся автоматически.
;  Версию в коде держите синхронной: virus_recovery.py → CURRENT_VERSION.
;
;  Установщик многоязычный (RU/EN/UK/DE/PL/FR). Язык определяется по языку
;  системы автоматически; диалог выбора появится только если язык не распознан.
;  Все тексты мастера лежат в конце этого файла (секции [Messages] и
;  [CustomMessages]) — правятся без пересборки приложения.
;
;  Пути только относительные: скрипт работает с любой машины/папки.
; ═══════════════════════════════════════════════════════════════════════════

#define MyAppName "NoVir - Восстановление системы"
#define MyAppVersion "2.5.5"
#define MyAppPublisher "NoVir Project"
#define MyAppExeName "NoVir.exe"
#define MyAppURL "https://github.com/artemcik907/NoVir"

[Setup]
; Уникальный идентификатор приложения — НЕ МЕНЯТЬ:
; по нему Inno находит и корректно обновляет предыдущие установки.
AppId={{9B9B8E31-7C52-4C5B-9B20-9D8D0C1A7F42}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Сведения для свойств файла установщика (правый клик → Свойства)
VersionInfoVersion={#MyAppVersion}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=NoVir Setup
VersionInfoCopyright=© 2026 {#MyAppPublisher}

; Каталоги. OutputDir=. — результат кладётся рядом со скриптом (installer\)
DefaultDirName={autopf}\NoVir
DefaultGroupName=NoVir
DisableProgramGroupPage=yes
OutputDir=.
OutputBaseFilename=NoVir_Setup_v{#MyAppVersion}

; Иконки: значок установщика, ярлыков и записи в «Установка и удаление программ»
SetupIconFile=..\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}

; Внешний вид (размер и адаптивность мастера в Inno 7 — по умолчанию)
WizardStyle=modern
DisableWelcomePage=no
DisableReadyMemo=no
DisableFinishedPage=no

; Языки: диалог выбора только если язык системы не распознан
ShowLanguageDialog=auto

; Права и архитектура (64-битное приложение, включая ARM64-совместимость)
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Если при обновлении NoVir запущен, установщик предложит закрыть его
; автоматически (Windows Restart Manager, директива CloseApplications=yes
; по умолчанию). Автоматическую перезагрузку не запускаем.
RestartIfNeededByRun=no

; Сжатие
Compression=lzma2/ultra64
SolidCompression=yes

[Languages]
; Языки интерфейса установщика. Файлы сообщений поставляются вместе с Inno Setup
; (compiler:...). Первый в списке — English: используется как запасной вариант,
; если язык системы не совпал ни с одним из списка.
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "uk"; MessagesFile: "compiler:Languages\Ukrainian.isl"
Name: "de"; MessagesFile: "compiler:Languages\German.isl"
Name: "pl"; MessagesFile: "compiler:Languages\Polish.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
; Описания задач — из стандартных сообщений Inno ({cm:...}), см. [CustomMessages]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce
Name: "startmenuicon"; Description: "{cm:CreateStartMenuIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
; Путь относительный: ..\dist\NoVir.exe — собранный PyInstaller-дистрибутив.
; Всё остальное (иконки Windows, ресурсы) уже встроено в exe.
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\NoVir"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: startmenuicon
Name: "{autodesktop}\NoVir"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,NoVir}"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

; ═══════════════════════════════════════════════════════════════════════════
;  ТЕКСТЫ МАСТЕРА ПО ЯЗЫКАМ
;  Префикс сообщения — внутреннее имя языка из секции [Languages].
;  Метки [name] и [name/ver] подставляются автоматически:
;  [name] = название приложения, [name/ver] = название + версия.
;  %n — перенос строки. Без префикса сообщение применилось бы ко всем языкам.
; ═══════════════════════════════════════════════════════════════════════════

[Messages]
; ── Русский ──
ru.WelcomeLabel2=Этот мастер установит [name/ver] на ваш компьютер.%n%nNoVir помогает восстановить доступ к системным инструментам Windows после вредоносных атак и сбоев.%n%nПеред установкой рекомендуется закрыть открытые приложения и сохранить важные документы.
ru.SelectDirLabel3=Выберите папку для установки [name].%n%nРекомендуется оставить предложенное расположение.
ru.SelectTasksLabel2=Выберите удобные ярлыки для запуска NoVir.
ru.ReadyLabel1=Всё готово к установке [name].%n%nПроверьте выбранную папку и дополнительные ярлыки, затем нажмите «Установить».
ru.FinishedHeadingLabel=NoVir установлен
ru.FinishedLabel=Установка завершена.%n%nЗапускайте NoVir только тогда, когда готовы выполнять восстановление системы. Для системных операций могут потребоваться права администратора.
ru.ButtonInstall=&Установить NoVir

; ── English ──
en.WelcomeLabel2=This wizard will install [name/ver] on your computer.%n%nNoVir helps restore access to Windows system tools after malware attacks and failures.%n%nBefore installing, it is recommended to close open applications and save important documents.
en.SelectDirLabel3=Choose the folder where [name] will be installed.%n%nIt is recommended to keep the suggested location.
en.SelectTasksLabel2=Choose the shortcuts you want to create for NoVir.
en.ReadyLabel1=Everything is ready to install [name].%n%nCheck the selected folder and shortcuts, then click “Install”.
en.FinishedHeadingLabel=NoVir has been installed
en.FinishedLabel=Installation complete.%n%nRun NoVir only when you are ready to perform system recovery. System operations may require administrator rights.
en.ButtonInstall=&Install NoVir

; ── Українська ──
uk.WelcomeLabel2=Цей майстер встановить [name/ver] на ваш комп’ютер.%n%nNoVir допомагає відновити доступ до системних інструментів Windows після шкідливих атак і збоїв.%n%nПеред встановленням рекомендується закрити відкриті програми та зберегти важливі документи.
uk.SelectDirLabel3=Виберіть папку для встановлення [name].%n%nРекомендується залишити запропоноване розташування.
uk.SelectTasksLabel2=Виберіть зручні ярлики для запуску NoVir.
uk.ReadyLabel1=Усе готово до встановлення [name].%n%nПеревірте вибрану папку та додаткові ярлики, потім натисніть «Встановити».
uk.FinishedHeadingLabel=NoVir встановлено
uk.FinishedLabel=Встановлення завершено.%n%nЗапускайте NoVir лише тоді, коли готові виконувати відновлення системи. Для системних операцій можуть знадобитися права адміністратора.
uk.ButtonInstall=&Встановити NoVir

; ── Deutsch ──
de.WelcomeLabel2=Dieser Assistent installiert [name/ver] auf Ihrem Computer.%n%nNoVir hilft, den Zugriff auf Windows-Systemtools nach Malware-Angriffen und Fehlern wiederherzustellen.%n%nVor der Installation wird empfohlen, geöffnete Programme zu schließen und wichtige Dokumente zu speichern.
de.SelectDirLabel3=Wählen Sie den Ordner, in dem [name] installiert werden soll.%n%nEs wird empfohlen, den vorgeschlagenen Speicherort beizubehalten.
de.SelectTasksLabel2=Wählen Sie die gewünschten Verknüpfungen für NoVir.
de.ReadyLabel1=Alles ist bereit für die Installation von [name].%n%nPrüfen Sie den Zielordner und die Verknüpfungen und klicken Sie dann auf „Installieren“.
de.FinishedHeadingLabel=NoVir wurde installiert
de.FinishedLabel=Die Installation ist abgeschlossen.%n%nStarten Sie NoVir nur, wenn Sie bereit sind, eine Systemwiederherstellung durchzuführen. Systemoperationen erfordern möglicherweise Administratorrechte.
de.ButtonInstall=NoVir &installieren

; ── Polski ──
pl.WelcomeLabel2=Ten kreator zainstaluje [name/ver] na Twoim komputerze.%n%nNoVir pomaga przywrócić dostęp do narzędzi systemowych Windows po atakach złośliwego oprogramowania i awariach.%n%nPrzed instalacją zaleca się zamknięcie otwartych programów i zapisanie ważnych dokumentów.
pl.SelectDirLabel3=Wybierz folder, w którym zostanie zainstalowany [name].%n%nZaleca się pozostawienie sugerowanej lokalizacji.
pl.SelectTasksLabel2=Wybierz wygodne skróty do uruchamiania NoVir.
pl.ReadyLabel1=Wszystko jest gotowe do instalacji [name].%n%nSprawdź wybrany folder i skróty, a następnie kliknij „Zainstaluj”.
pl.FinishedHeadingLabel=NoVir został zainstalowany
pl.FinishedLabel=Instalacja zakończona.%n%nUruchamiaj NoVir tylko wtedy, gdy jesteś gotowy do przeprowadzenia odzyskiwania systemu. Operacje systemowe mogą wymagać uprawnień administratora.
pl.ButtonInstall=&Zainstaluj NoVir

; ── Français ──
fr.WelcomeLabel2=Cet assistant va installer [name/ver] sur votre ordinateur.%n%nNoVir aide à restaurer l’accès aux outils système de Windows après des attaques de logiciels malveillants et des pannes.%n%nAvant de continuer, il est recommandé de fermer les applications ouvertes et d’enregistrer vos documents importants.
fr.SelectDirLabel3=Choisissez le dossier dans lequel [name] sera installé.%n%nIl est recommandé de conserver l’emplacement proposé.
fr.SelectTasksLabel2=Choisissez les raccourcis souhaités pour NoVir.
fr.ReadyLabel1=Tout est prêt pour installer [name].%n%nVérifiez le dossier et les raccourcis choisis, puis cliquez sur « Installer ».
fr.FinishedHeadingLabel=NoVir a été installé
fr.FinishedLabel=L’installation est terminée.%n%nNe lancez NoVir que lorsque vous êtes prêt à effectuer une restauration du système. Les opérations système peuvent nécessiter des droits d’administrateur.
fr.ButtonInstall=&Installer NoVir

[CustomMessages]
; Дополнительные сообщения. Стандартные (AdditionalIcons, CreateDesktopIcon,
; LaunchProgram) уже переведены в поставляемых файлах Inno — берём их
; через {cm:...} в секциях [Tasks] и [Run]. Здесь — только наши тексты.
ru.CreateStartMenuIcon=Добавить ярлык в меню «Пуск»
en.CreateStartMenuIcon=Add a Start menu shortcut
uk.CreateStartMenuIcon=Додати ярлик у меню «Пуск»
de.CreateStartMenuIcon=Verknüpfung im Startmenü hinzufügen
pl.CreateStartMenuIcon=Dodaj skrót w menu Start
fr.CreateStartMenuIcon=Ajouter un raccourci dans le menu Démarrer
