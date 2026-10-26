import os
import shutil
import string
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, 
                             QPushButton, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QMessageBox, QMenu, QAbstractItemView, QStyle,
                             QFileIconProvider)
from PySide6.QtCore import QFile, QFileInfo, Qt, QSize
from PySide6.QtGui import QIcon

try:
    import novir_native
except ImportError:
    novir_native = None


def tr(text):
    """Read the active NoVir language lazily to avoid an import cycle."""
    try:
        from virus_recovery import language_manager
        return language_manager.translate(text)
    except (ImportError, AttributeError):
        return text



def is_protected_system_folder(path):
    r"""
    Проверяет, является ли путь защищённой системной папкой Windows.
    Защищены: корни дисков (C:\, D:\), папка Windows и её системные компоненты (System32, SysWOW64, WinSxS),
    корневые системные каталоги Program Files, Users, ProgramData, корзина и загрузочные файлы.
    Все остальные файлы и каталоги разрешено удалять.
    """
    if not path or not isinstance(path, str):
        return True
    try:
        norm = os.path.normcase(os.path.abspath(path)).rstrip("\\")
    except Exception:
        return True

    # Корни дисков (C:, D:, E: и т.д.)
    if len(norm) <= 3 and (norm.endswith(":") or norm.endswith(":\\")):
        return True
    if len(norm) == 2 and norm[1] == ":":
        return True

    win_dir = os.environ.get("WINDIR", r"C:\Windows").lower().rstrip("\\")
    sys32 = os.path.join(win_dir, "system32").lower()
    syswow = os.path.join(win_dir, "syswow64").lower()
    winsxs = os.path.join(win_dir, "winsxs").lower()
    prog_files = os.environ.get("ProgramFiles", r"C:\Program Files").lower().rstrip("\\")
    prog_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower().rstrip("\\")
    prog_data = os.environ.get("ProgramData", r"C:\ProgramData").lower().rstrip("\\")
    users_root = os.path.dirname(os.environ.get("USERPROFILE", r"C:\Users\Default")).lower().rstrip("\\")
    cur_profile = os.environ.get("USERPROFILE", "").lower().rstrip("\\")

    strictly_protected = {
        win_dir, sys32, syswow, winsxs,
        prog_files, prog_files_x86, prog_data, users_root, cur_profile,
        r"c:\boot", r"c:\recovery", r"c:\system volume information", r"c:\$recycle.bin"
    }

    if norm in strictly_protected:
        return True

    critical_files = {
        r"c:\bootmgr", r"c:\ntldr", r"c:\pagefile.sys", r"c:\hiberfil.sys", r"c:\swapfile.sys"
    }
    if norm in critical_files:
        return True

    return False


def unlock_and_kill_locking_processes(target_path):
    """
    Находит и завершает процессы, удерживающие дескриптор файла или папки через RestartManager API.
    """
    import ctypes
    from ctypes import wintypes

    rm = ctypes.windll.rstrtmgr

    class RM_UNIQUE_PROCESS(ctypes.Structure):
        _fields_ = [('dwProcessId', wintypes.DWORD), ('ProcessStartTime', wintypes.FILETIME)]

    class RM_PROCESS_INFO(ctypes.Structure):
        _fields_ = [
            ('Process', RM_UNIQUE_PROCESS),
            ('strAppName', wintypes.WCHAR * 256),
            ('strServiceShortName', wintypes.WCHAR * 64),
            ('ApplicationType', wintypes.DWORD),
            ('AppStatus', wintypes.DWORD),
            ('TSSessionId', wintypes.DWORD),
            ('bRestartable', wintypes.BOOL)
        ]

    session_handle = wintypes.DWORD()
    session_key = (wintypes.WCHAR * 33)()
    if rm.RmStartSession(ctypes.byref(session_handle), 0, session_key) != 0:
        return []

    killed_pids = []
    try:
        paths = (wintypes.LPCWSTR * 1)(target_path)
        if rm.RmRegisterResources(session_handle, 1, paths, 0, None, 0, None) == 0:
            n_needed = wintypes.UINT(0)
            n_proc = wintypes.UINT(0)
            reboot_reasons = wintypes.DWORD()
            res = rm.RmGetList(session_handle, ctypes.byref(n_needed), ctypes.byref(n_proc), None, ctypes.byref(reboot_reasons))
            if res in (0, 234) and n_needed.value > 0:
                arr = (RM_PROCESS_INFO * n_needed.value)()
                n_proc = wintypes.UINT(n_needed.value)
                if rm.RmGetList(session_handle, ctypes.byref(n_needed), ctypes.byref(n_proc), arr, ctypes.byref(reboot_reasons)) == 0:
                    for i in range(n_proc.value):
                        p_id = arr[i].Process.dwProcessId
                        if p_id > 4:  # Игнорируем System / Idle
                            try:
                                h_proc = ctypes.windll.kernel32.OpenProcess(1, False, p_id)
                                if h_proc:
                                    ctypes.windll.kernel32.TerminateProcess(h_proc, 1)
                                    ctypes.windll.kernel32.CloseHandle(h_proc)
                                    killed_pids.append(p_id)
                            except Exception:
                                pass
    finally:
        rm.RmEndSession(session_handle)

    # Проверка через psutil для запущенного исполняемого файла
    try:
        import psutil
        norm_target = os.path.normcase(os.path.abspath(target_path))
        for proc in psutil.process_iter(['pid', 'exe']):
            try:
                pid = proc.info['pid']
                exe = proc.info['exe']
                if pid > 4 and exe and os.path.normcase(os.path.abspath(exe)) == norm_target:
                    proc.kill()
                    killed_pids.append(pid)
            except Exception:
                pass
    except Exception:
        pass

    return killed_pids


def force_delete_file_or_dir(target_path):
    """
    Принудительное удаление файла или папки с разблокировкой процессов,
    снятием прав и планированием удаления на перезагрузку при необходимости.
    """
    import os, shutil, ctypes, subprocess, time

    if not os.path.exists(target_path) and not os.path.islink(target_path):
        return True, "Объект уже отсутствует"

    # 1. Снимаем атрибуты Read-Only / System / Hidden
    try:
        ctypes.windll.kernel32.SetFileAttributesW(target_path, 0x80)  # FILE_ATTRIBUTE_NORMAL
    except Exception:
        pass

    # 2. Пытаемся получить права доступа (takeown + icacls)
    try:
        subprocess.run(["takeown", "/f", target_path, "/a"], capture_output=True, creationflags=0x08000000)
        subprocess.run(["icacls", target_path, "/grant", "*S-1-5-32-544:F", "/c", "/q"], capture_output=True, creationflags=0x08000000)
    except Exception:
        pass

    # Функция удаления атрибутов только для чтения для rmtree onerror
    def _handle_remove_readonly(func, path, exc):
        try:
            ctypes.windll.kernel32.SetFileAttributesW(path, 0x80)
            func(path)
        except Exception:
            pass

    # 3. Первая попытка обычного удаления
    try:
        if os.path.isdir(target_path) and not os.path.islink(target_path):
            shutil.rmtree(target_path, onerror=_handle_remove_readonly)
        else:
            os.remove(target_path)
        return True, "Успешно удалено"
    except (PermissionError, OSError):
        pass

    # 4. Файл заблокирован процессом: убиваем удерживающие процессы
    killed = unlock_and_kill_locking_processes(target_path)
    time.sleep(0.2)

    # 5. Вторая попытка после разблокировки процессов
    try:
        if os.path.isdir(target_path) and not os.path.islink(target_path):
            shutil.rmtree(target_path, onerror=_handle_remove_readonly)
        else:
            os.remove(target_path)
        msg = f"Удалено (завершено удерживающих процессов: {len(killed)})" if killed else "Успешно удалено"
        return True, msg
    except Exception:
        pass

    # 6. Если файл всё ещё заблокирован ядром — трюк с переименованием и отложенным удалением
    try:
        temp_dir = os.environ.get("TEMP", os.path.dirname(target_path))
        temp_name = os.path.join(temp_dir, f"del_{os.path.basename(target_path)}_{int(time.time())}.tmp")
        try:
            os.rename(target_path, temp_name)
            target_to_schedule = temp_name
        except Exception:
            target_to_schedule = target_path

        # MOVEFILE_DELAY_UNTIL_REBOOT = 4
        res = ctypes.windll.kernel32.MoveFileExW(target_to_schedule, None, 4)
        if res != 0:
            return True, "Файл заблокирован драйвером ядра: запланировано удаление при перезагрузке"
    except Exception as e:
        return False, f"Ошибка удаления: {e}"

    return False, "Не удалось удалить заблокированный файл"


class ExplorerTab(QWidget):
    ROOT_PATH = "__novir_this_pc__"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_path = self.ROOT_PATH
        self.history = []
        # Icon cache and provider for real Windows shell icons
        self._icon_provider = QFileIconProvider()
        self._icon_cache = {}  # extension -> QIcon
        self._init_icon_cache()
        self.init_ui()
        self.refresh_files()

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Top bar
        top_bar = QWidget()
        top_bar.setStyleSheet("background-color: #000000; border-bottom: 1px solid #000000;")
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(10, 10, 10, 10)
        top_layout.setSpacing(10)

        self.btn_back = QPushButton()
        self.btn_back.setFixedSize(34, 32)
        self.btn_back.setIcon(self.style().standardIcon(QStyle.SP_ArrowBack))
        self.btn_back.setIconSize(QSize(16, 16))
        self.btn_back.setStyleSheet("QPushButton { background-color: transparent; border: 1px solid transparent; } QPushButton:hover, QPushButton:focus { background-color: #111111; border-color: #ffffff; }")
        self.btn_back.setToolTip(tr("Назад"))
        self.btn_back.clicked.connect(self.go_back)
        top_layout.addWidget(self.btn_back)

        self.btn_refresh = QPushButton()
        self.btn_refresh.setFixedSize(34, 32)
        self.btn_refresh.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        self.btn_refresh.setIconSize(QSize(16, 16))
        self.btn_refresh.setStyleSheet("QPushButton { background-color: transparent; border: 1px solid transparent; } QPushButton:hover, QPushButton:focus { background-color: #111111; border-color: #ffffff; }")
        self.btn_refresh.setToolTip(tr("Обновить список"))
        self.btn_refresh.clicked.connect(self.refresh_files)
        top_layout.addWidget(self.btn_refresh)

        self.path_edit = QLineEdit()
        self.path_edit.setFixedHeight(30)
        self.path_edit.setStyleSheet("QLineEdit { background-color: #080808; border: 1px solid #333333; border-radius: 0px; padding: 0 10px; color: #ffffff; } QLineEdit:focus { border-color: #ffffff; }")
        self.path_edit.returnPressed.connect(self.navigate_to_path)
        top_layout.addWidget(self.path_edit)

        self.layout.addWidget(top_bar)

        # Table
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(4)
        self.file_table.setHorizontalHeaderLabels([tr("Имя"), tr("Тип"), tr("Размер"), tr("Атрибуты")])
        self.file_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.file_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        
        self.file_table.verticalHeader().setVisible(False)
        self.file_table.setShowGrid(False)
        self.file_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.file_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.file_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.file_table.setAlternatingRowColors(True)
        self.file_table.verticalHeader().setDefaultSectionSize(30)

        self.file_table.setStyleSheet("""
            QTableWidget {
                background-color: #000000;
                color: #ffffff;
                border: 1px solid #222222;
                alternate-background-color: #090909;
            }
            QHeaderView::section {
                background-color: #000000;
                color: #ffffff;
                padding: 7px 8px;
                border: none;
                font-weight: bold;
                border-bottom: 1px solid #333333;
            }
            QTableWidget::item:selected {
                background-color: #181818;
                color: #ffffff;
            }
        """)

        self.file_table.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.file_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self.show_context_menu)

        
        # Search bar
        search_layout = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(tr("Поиск файлов..."))
        self.search_edit.setStyleSheet("QLineEdit { background-color: #080808; color: #fff; border: 1px solid #333; padding: 7px 9px; } QLineEdit:focus { border-color: #fff; }")
        self.search_edit.textChanged.connect(self.filter_files)
        
        self.btn_hidden = QPushButton(tr("Скрытые"))
        self.btn_hidden.setCheckable(True)
        self.btn_hidden.setFixedSize(80, 28)
        self.btn_hidden.setStyleSheet("QPushButton { background-color: #080808; color: #aaa; border: 1px solid #333; padding: 4px 8px; } QPushButton:hover, QPushButton:focus { color: #fff; border-color: #aaa; } QPushButton:checked { color: #fff; border-color: #fff; background-color: #181818; }")
        self.btn_hidden.clicked.connect(self.refresh_files)
        
        search_layout.addWidget(self.search_edit)
        search_layout.addWidget(self.btn_hidden)
        self.layout.addLayout(search_layout)
        self.layout.addWidget(self.file_table)

    def retranslate_ui(self):
        """Refresh display-only text after an in-app language switch."""
        self.btn_back.setToolTip(tr("Назад"))
        self.btn_refresh.setToolTip(tr("Обновить список"))
        self.file_table.setHorizontalHeaderLabels([tr("Имя"), tr("Тип"), tr("Размер"), tr("Атрибуты")])
        self.refresh_files()

    def get_logical_drives(self):
        drives = []
        try:
            import ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drives.append(f"{letter}:\\")
                bitmask >>= 1
            if drives:
                return drives
        except Exception:
            pass
        return ["C:\\"]

    def _init_icon_cache(self):
        """Pre-populate icon cache for common extensions."""
        common_exts = [
            ".exe", ".dll", ".sys", ".lnk", ".bat", ".cmd", ".reg", ".inf",
            ".ps1", ".vbs", ".scr", ".ani", ".ico", ".bmp", ".jpg", ".jpeg",
            ".png", ".gif", ".tiff", ".webp", ".mp3", ".wav", ".mp4", ".avi",
            ".mkv", ".mov", ".wmv", ".flv", ".pdf", ".doc", ".docx", ".xls",
            ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".tar", ".gz", ".7z",
            ".nfo", ".txt", ".csv", ".html", ".htm", ".json", ".py", ".rb",
            ".java", ".cpp", ".h", ".pas", ".asm",
        ]
        for ext in common_exts:
            # QFileIconProvider returns icon for file type; we use a dummy QFileInfo
            try:
                info = QFileInfo(f"dummy{ext}")
                icon = self._icon_provider.icon(info)
                if icon.isNull():
                    icon = self.style().standardIcon(QStyle.SP_FileIcon)
                self._icon_cache[ext.lower()] = icon
            except Exception:
                self._icon_cache[ext.lower()] = self.style().standardIcon(QStyle.SP_FileIcon)

    def _get_cached_icon(self, ext):
        """Return cached icon for extension, or default file icon."""
        key = ext.lower() if ext else ".file"
        if key in self._icon_cache:
            return self._icon_cache[key]
        # Default fallback
        return self.style().standardIcon(QStyle.SP_FileIcon)

    def refresh_files(self):
        self.file_table.setRowCount(0)
        self.path_edit.setText(tr("Компьютер") if self.current_path == self.ROOT_PATH else self.current_path)

        if self.current_path == self.ROOT_PATH:
            drives = self.get_logical_drives()
            for row, drive in enumerate(drives):
                self.file_table.insertRow(row)
                item = QTableWidgetItem(drive)
                try:
                    drive_icon = self._icon_provider.icon(QFileInfo(drive))
                except Exception:
                    drive_icon = QIcon()
                if drive_icon.isNull():
                    drive_icon = self.style().standardIcon(QStyle.SP_DriveHDIcon)
                item.setIcon(drive_icon)
                self.file_table.setItem(row, 0, item)
                self.file_table.setItem(row, 1, QTableWidgetItem(tr("Локальный диск")))
                self.file_table.setItem(row, 2, QTableWidgetItem(""))
                self.file_table.setItem(row, 3, QTableWidgetItem(""))
            return

        if not os.path.exists(self.current_path):
            self.current_path = self.ROOT_PATH
            self.refresh_files()
            return

        try:
            with os.scandir(self.current_path) as it:
                dirs = []
                files = []
                for entry in it:
                    try:
                        if entry.is_dir():
                            try:
                                import ctypes
                                attrs = ctypes.windll.kernel32.GetFileAttributesW(entry.path)
                                if attrs != -1 and (attrs & 2) and (not getattr(self, "btn_hidden", None) or not self.btn_hidden.isChecked()):
                                    pass  # skip hidden
                                else:
                                    dirs.append(entry.name)
                            except:
                                dirs.append(entry.name)
                        else:
                            try:
                                stat = entry.stat()
                                size = stat.st_size
                            except:
                                size = -1
                            files.append((entry.name, size))
                    except:
                        pass
        except Exception as e:
            QMessageBox.warning(self, tr("Ошибка"), f"{tr('Нет доступа:')}\n{e}")
            self.go_back()
            return

        dirs.sort(key=str.lower)
        files.sort(key=lambda x: str.lower(x[0]))

        row = 0
        for d in dirs:
            self.file_table.insertRow(row)
            item = QTableWidgetItem(d)
            full_dir = os.path.join(self.current_path, d)
            try:
                dir_icon = self._icon_provider.icon(QFileInfo(full_dir))
            except Exception:
                dir_icon = QIcon()
            if dir_icon.isNull():
                dir_icon = self.style().standardIcon(QStyle.SP_DirIcon)
            item.setIcon(dir_icon)
            item.setData(Qt.UserRole, full_dir)
            self.file_table.setItem(row, 0, item)
            self.file_table.setItem(row, 1, QTableWidgetItem(tr("Папка")))
            self.file_table.setItem(row, 2, QTableWidgetItem(""))
            self.file_table.setItem(row, 3, QTableWidgetItem(""))
            row += 1

        for f_tuple in files:
            f, size = f_tuple
            self.file_table.insertRow(row)
            full_path = os.path.join(self.current_path, f)
            ext = os.path.splitext(f)[1].lower()
            try:
                icon = self._icon_provider.icon(QFileInfo(full_path))
            except Exception:
                icon = QIcon()
            if icon.isNull():
                icon = self._get_cached_icon(ext) if ext else self.style().standardIcon(QStyle.SP_FileIcon)
            item = QTableWidgetItem(f)
            item.setIcon(icon)
            item.setData(Qt.UserRole, full_path)
            self.file_table.setItem(row, 0, item)
            
            ext = os.path.splitext(f)[1].upper()
            self.file_table.setItem(row, 1, QTableWidgetItem(f"{tr('Файл')} {ext}" if ext else tr("Файл")))
            
            if size >= 0:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = ""
            self.file_table.setItem(row, 2, QTableWidgetItem(size_str))
            self.file_table.setItem(row, 3, QTableWidgetItem(""))
            row += 1

    def filter_files(self, text=""):
        for row in range(self.file_table.rowCount()):
            item = self.file_table.item(row, 0)
            if item:
                name = item.text().lower()
                self.file_table.setRowHidden(row, bool(text) and text.lower() not in name)

    def go_back(self):
        if self.current_path == self.ROOT_PATH:
            return
        parent_dir = os.path.dirname(self.current_path)
        if parent_dir == self.current_path:
            self.current_path = self.ROOT_PATH
        else:
            self.current_path = parent_dir
        self.refresh_files()

    def navigate_to_path(self):
        new_path = self.path_edit.text().strip()
        root_names = {"", "компьютер", "this pc", "цей комп'ютер"}
        if new_path.lower() in root_names:
            self.current_path = self.ROOT_PATH
        elif os.path.isdir(new_path):
            self.current_path = new_path
        else:
            QMessageBox.warning(self, tr("Ошибка"), tr("Неверный путь"))
            self.path_edit.setText(tr("Компьютер") if self.current_path == self.ROOT_PATH else self.current_path)
            return
        self.refresh_files()

    def on_item_double_clicked(self, item):
        row = item.row()
        name_item = self.file_table.item(row, 0)
        if self.current_path == self.ROOT_PATH:
            self.current_path = name_item.text()
            self.refresh_files()
            return
        
        path = name_item.data(Qt.UserRole)
        if os.path.isdir(path):
            self.current_path = path
            self.refresh_files()
        else:
            try:
                os.startfile(path)
            except Exception as e:
                QMessageBox.warning(self, tr("Ошибка"), str(e))

    def show_context_menu(self, pos):
        item = self.file_table.itemAt(pos)
        if not item: return
        
        row = item.row()
        name_item = self.file_table.item(row, 0)
        
        if self.current_path == self.ROOT_PATH:
            path = name_item.text()
        else:
            path = name_item.data(Qt.UserRole)
            
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #000000; color: white; border: 1px solid #333333; } QMenu::item:selected { background-color: #4a4a5a; }")
        
        action_open = menu.addAction(tr("Открыть"))
        menu.addSeparator()
        
        if self.current_path != self.ROOT_PATH:
            action_rename = menu.addAction(tr("Переименовать"))
            action_copy_file = menu.addAction(tr("Копировать файл"))
            action_move_file = menu.addAction(tr("Переместить файл"))
            action_copy_path = menu.addAction(tr("Копировать путь"))
            menu.addSeparator()
            action_unlock = menu.addAction(tr("Разблокировать (Unlocker)"))
            action_own = menu.addAction(tr("Стать владельцем (Take Ownership)"))
            action_del = menu.addAction(tr("Удалить безвозвратно (Force Delete)"))
            
            action = menu.exec(self.file_table.viewport().mapToGlobal(pos))
            
            if action == action_open:
                self.on_item_double_clicked(name_item)
            elif action == action_copy_file:
                import shutil
                from PySide6.QtWidgets import QInputDialog, QFileDialog
                dest_dir = QFileDialog.getExistingDirectory(self, tr("Выберите папку назначения"))
                if dest_dir:
                    try:
                        shutil.copy2(path, dest_dir)
                        self.refresh_files()
                    except Exception as e:
                        QMessageBox.warning(self, tr("Ошибка"), str(e))
            elif action == action_move_file:
                import shutil
                from PySide6.QtWidgets import QFileDialog
                dest_dir = QFileDialog.getExistingDirectory(self, tr("Выберите папку назначения"))
                if dest_dir:
                    try:
                        shutil.move(path, dest_dir)
                        self.refresh_files()
                    except Exception as e:
                        QMessageBox.warning(self, tr("Ошибка"), str(e))
            elif action == action_rename:
                from PySide6.QtWidgets import QInputDialog
                new_name, ok = QInputDialog.getText(self, tr("Переименование"), tr("Новое имя:"), QLineEdit.Normal, os.path.basename(path))
                if ok and new_name:
                    new_path = os.path.join(os.path.dirname(path), new_name)
                    try:
                        os.rename(path, new_path)
                        self.refresh_files()
                    except Exception as e:
                        QMessageBox.warning(self, tr("Ошибка"), f"{tr('Не удалось переименовать:')} {e}")
            elif action == action_copy_path:
                from PySide6.QtWidgets import QApplication
                QApplication.clipboard().setText(path)
            elif action == action_unlock:
                if novir_native and hasattr(novir_native, 'unlock_file'):
                    res = novir_native.unlock_file(path)
                    QMessageBox.information(self, tr("Разблокировка"), tr("Файл разблокирован!") if res else tr("Не удалось разблокировать или файл не заблокирован."))
                else:
                    QMessageBox.warning(self, tr("Ошибка"), tr("Модуль novir_native недоступен."))
            elif action == action_own:
                if novir_native and hasattr(novir_native, 'take_ownership'):
                    res = novir_native.take_ownership(path)
                    QMessageBox.information(self, tr("Владелец"), tr("Права получены!") if res else tr("Не удалось получить права."))
                else:
                    QMessageBox.warning(self, tr("Ошибка"), tr("Модуль novir_native недоступен."))
            elif action == action_del:
                self.force_delete_selected_path(path)
        else:
            action = menu.exec(self.file_table.viewport().mapToGlobal(pos))
            if action == action_open:
                self.on_item_double_clicked(name_item)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Delete:
            row = self.file_table.currentRow()
            if row >= 0:
                item = self.file_table.item(row, 0)
                if item and self.current_path != self.ROOT_PATH:
                    path = item.data(Qt.UserRole)
                    if path:
                        self.force_delete_selected_path(path)
                        return
        super().keyPressEvent(event)

    def force_delete_selected_path(self, path):
        """Удаляет файл или папку, даже если они заняты процессом (кроме системных папок)"""
        if is_protected_system_folder(path):
            QMessageBox.warning(
                self,
                tr("Защита системы"),
                tr("Данный объект является защищённой системной папкой или критическим файлом Windows. Удаление заблокировано во избежание краха системы.")
            )
            return

        reply = QMessageBox.question(
            self,
            tr("Принудительное удаление"),
            f"{tr('Удалить безвозвратно (включая разблокировку и закрытие удерживающих процессов)?')}\n\n{path}",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        ok, msg = force_delete_file_or_dir(path)
        if ok:
            self.refresh_files()
            QMessageBox.information(self, tr("Готово"), msg)
        else:
            QMessageBox.critical(self, tr("Ошибка"), msg)
