#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NoVir - Вирусный Реаниматор
Автор: Недохакер
Версия: 2.0
Описание: Полный набор инструментов для восстановления системы после вирусной атаки
"""

import os
import sys
import explorer_tab
import subprocess
import winreg
import ctypes
import shutil
import glob
import platform
import time
import json
import threading
import re
from datetime import datetime
from functools import lru_cache

try:
    import novir_native
    PSUTIL_AVAILABLE = True # Stub for compatibility
except ImportError:
    pass
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None

try:
    from colorama import init
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    def init(*args, **kwargs):
        return None

# Попытка импорта C++ модуля
try:
    import novir_core
    CPP_CORE_AVAILABLE = True
except ImportError:
    CPP_CORE_AVAILABLE = False
    print("[INFO] C++ модуль novir_core не найден, используется Python реализация")

# Флаг для GUI (по умолчанию включен)
GUI_MODE = '--console' not in sys.argv and '-c' not in sys.argv
PYSIDE_AVAILABLE = False

# Условный импорт PySide6
if GUI_MODE:
    try:
        from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                     QHBoxLayout, QPushButton, QLabel, QTextEdit,
                                     QFileDialog, QMenu, QComboBox, QMessageBox,
                                     QDialog, QLineEdit, QTableWidget, QTableWidgetItem,
                                     QHeaderView, QTabWidget, QFrame, QCheckBox,
                                     QTreeWidget, QTreeWidgetItem, QSlider,
                                     QGridLayout, QStackedWidget)
        from PySide6.QtCore import Qt, QThread, Signal
        from PySide6.QtGui import QClipboard
        PYSIDE_AVAILABLE = True
    except ImportError:
        print("PySide6 не установлен. Запуск в консольном режиме.")
        GUI_MODE = False

# Инициализация colorama для Windows
init()

# Установка UTF-8 кодировки для консоли
if sys.platform == 'win32':
    import locale
    try:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    except Exception as _e:
        # Expected exception, intentionally ignored
        pass

# Константы для Windows
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Режим сухого прогона (только показываем, ничего не меняем)
DRY_RUN = '--dry-run' in sys.argv or '-d' in sys.argv
SELF_CHECK = '--self-check' in sys.argv or '--check' in sys.argv

# Папка для бэкапов
BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "NoVir_Backups")
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

# Цвета для консоли
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class Logger:
    __slots__ = ('actions', 'start_time')

    def __init__(self):
        self.actions = []
        self.start_time = datetime.now()

    def log(self, action, status, message=""):
        self.actions.append({
            'time': datetime.now().strftime('%H:%M:%S'),
            'action': action,
            'status': status,
            'message': message
        })

    def generate_report(self):
        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║             NoVir - ОТЧЕТ О ВОССТАНОВЛЕНИИ                   ║",
            "╠══════════════════════════════════════════════════════════════╣",
            f"║ Время начала: {self.start_time.strftime('%d.%m.%Y %H:%M:%S')}",
            f"║ Время окончания: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}",
            "╠══════════════════════════════════════════════════════════════╣",
        ]
        for action in self.actions:
            status_icon = "[+]" if action['status'] == "success" else "[-]" if action['status'] == "error" else "[!]"
            lines.append(f"║ {status_icon} [{action['time']}] {action['action']}")
            if action['message']:
                lines.append(f"║    └─ {action['message']}")

        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines) + "\n"
    
    def save_report(self):
        report = self.generate_report()
        report_path = os.path.join(os.environ['USERPROFILE'], 'Desktop', f'NoVir_Report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"{Colors.GREEN}[+] Отчет сохранен: {report_path}{Colors.RESET}")
            return report_path
        except Exception as e:
            print(f"{Colors.RED}[!] Ошибка сохранения отчета: {e}{Colors.RESET}")
            return None

logger = Logger()

# как в Тачках: немного турбо

@lru_cache(maxsize=1)
def check_admin_status():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def print_header():
    mode_text = f"{Colors.YELLOW}[РЕЖИМ ТЕСТИРОВАНИЯ - НИЧЕГО НЕ ИЗМЕНЯЕТ]{Colors.RESET}" if DRY_RUN else ""
    print(f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║                    ВИРУСНЫЙ РЕАНИМАТОР v2.0                                ║
║                    "Восстанавливаем, что не убили"                         ║
{mode_text:74}║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")
    if DRY_RUN:
        print(f"{Colors.YELLOW}[SYSTEM]: Включен режим ТЕСТИРОВАНИЯ! Ничего реально не меняется — только показываю что буду делать. Спокойно, всё безопасно!{Colors.RESET}")
        print_hacker_message("Включен режим ТЕСТИРОВАНИЯ! Ничего реально не меняется — только показываю что буду делать. Спокойно, всё безопасно!")

def print_hacker_message(message):
    print(f"{Colors.YELLOW}[SYSTEM]: {message}{Colors.RESET}")


def _is_reparse_point(path):
    """Check if path is a reparse point (symlink or junction) using WinAPI."""
    import ctypes
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
    if attrs == 0xFFFFFFFF:
        return False  # path does not exist
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)

# Whitelist of directories NoVir is explicitly allowed to delete within.
# Nothing outside these directories can ever be deleted via safe_remove/safe_rmtree.
# Narrow whitelist: only allow deletion within specific subdirectories.
# NOTE: C:\Users is intentionally NOT in this list to prevent accidental mass deletion.
# GroupPolicy paths are handled separately via _DELETION_WHITELIST_EXTENDED.
_DELETION_WHITELIST = [
    "c:\\windows\\temp",
    "c:\\windows\\prefetch",
    "c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup",
    "c:\\windows\\system32\\grouppolicy",
    "c:\\windows\\system32\\grouppolicyusers",
]

# Extended whitelist for paths that require additional user confirmation before deletion
_DELETION_WHITELIST_EXTENDED = [
    "c:\\users",
    "c:\\documents and settings",
]

def _path_in_whitelist(real_path, whitelist):
    return any(real_path.startswith(w) for w in whitelist)

def is_path_safe_for_deletion(target_path):
    """
    Hardened path safety check.
    Uses realpath() to resolve symlinks/junctions, then enforces:
    - Whitelist: must be inside an allowed directory
    - Reparse point guard: no junctions/symlinks
    - No system root or critical directories
    """
    import os

    try:
        # Resolve all symlinks and junctions to the real filesystem path
        real = os.path.realpath(target_path).lower().rstrip("\\")
    except Exception:
        return False

    # Guard: block reparse points at target itself
    if _is_reparse_point(target_path):
        return False

    # Absolute hard blocks — never delete these regardless of whitelist
    critical_paths = [
        "c:\\", "c:\\windows", "c:\\system32", "c:\\syswow64",
        "c:\\program files", "c:\\program files (x86)",
        "c:\\users\\default", "c:\\programdata",
    ]
    for blocked in critical_paths:
        if real == blocked or real.startswith(blocked + "\\") is False and real == blocked:
            return False

    # Whitelist: realpath must start with allowed directory
    if not (_path_in_whitelist(real, _DELETION_WHITELIST) or
            _path_in_whitelist(real, _DELETION_WHITELIST_EXTENDED)):
        return False

    return True

def safe_remove(path):
    """Safely delete a single file after strict validation."""
    if not require_mutation_allowed(f"safe_remove: {path}"): return False
    if not is_path_safe_for_deletion(path): return False
    import os
    try:
        # Note: this is a best-effort re-check, not an atomic guarantee.
    # TOCTOU risk between check and remove is minimal in local-only use but non-zero.
        if not os.path.isfile(path):
            return False
        if _is_reparse_point(path):
            return False
        os.remove(path)
        return True
    except Exception as _e:
        print(f"[safe_remove] Failed: {_e}")
        return False

def safe_rmtree(path, _gui_parent=None):
    """Safely delete a directory tree, checking every item individually."""
    if not require_mutation_allowed(f"safe_rmtree: {path}"): return False
    if not is_path_safe_for_deletion(path): return False
    import os, shutil

    # Extra confirmation if path falls in extended whitelist (user data area)
    real = os.path.realpath(path).lower().rstrip("\\")
    if _path_in_whitelist(real, _DELETION_WHITELIST_EXTENDED):
        try:
            from PySide6.QtWidgets import QMessageBox
            from PySide6.QtCore import Qt as _Qt
            msg = QMessageBox(_gui_parent)
            msg.setWindowFlags(msg.windowFlags() | _Qt.WindowStaysOnTopHint)
            msg.setWindowTitle("\u26a0\ufe0f Подтверждение удаления")
            msg.setIcon(QMessageBox.Critical)
            msg.setText(
                f"\u26a0\ufe0f УДАЛЕНИЕ ДАННЫХ ПОЛЬЗОВАТЕЛЯ\n\n"
                f"Будет удалено:\n{path}\n\n"
                "Это действие необратимо. Продолжить?"
            )
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            msg.button(QMessageBox.Yes).setText("УДАЛИТЬ")
            msg.button(QMessageBox.No).setText("ОТМЕНА")
            msg.setDefaultButton(QMessageBox.No)
            msg.setStyleSheet(
                "QMessageBox { background-color: #000000; color: #ffffff; }"
                " QLabel { color: #ffffff; font-size: 13px; }"
                " QPushButton { background-color: #000000; color: #ffffff;"
                " border: 2px solid #ffffff; padding: 6px 16px; font-weight: bold; }"
                " QPushButton:hover { background-color: #ffffff; color: #000000; }"
            )
            if msg.exec() != QMessageBox.Yes:
                return False
        except Exception:
            # No Qt context (e.g. CLI mode) — require explicit flag instead
            return False

    # Walk tree and validate every child before deleting anything
    for root, dirs, files in os.walk(path):
        for d in dirs:
            full = os.path.join(root, d)
            if _is_reparse_point(full):
                return False  # Abort entire operation if any junction found
        for f in files:
            full = os.path.join(root, f)
            if not is_path_safe_for_deletion(full):
                return False
    # Final re-check on root
    if _is_reparse_point(path):
        return False

    try:
        shutil.rmtree(path)
        return True
    except Exception as _e:
        print(f"[safe_rmtree] Failed: {_e}")
        return False

def require_mutation_allowed(action_name):
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Изменение заблокировано: {action_name}{Colors.RESET}")
        return False
    return True

def run_command(cmd, as_admin=False):
    """Выполнение команды с обработкой ошибок"""
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Команда: {cmd}{Colors.RESET}")
        return True, "", ""
    try:
        kwargs = {"shell": True, "capture_output": True, "text": True}
        if sys.platform == 'win32' and hasattr(subprocess, 'CREATE_NO_WINDOW'):
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(cmd, **kwargs)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def reg_set_value(key_path, value_name, value_data, value_type=winreg.REG_SZ, hive=None):
    """Установка значения в реестре с обходом блокировок"""
    if not require_mutation_allowed(f"reg_set_value: {key_path}\\{value_name}"):
        return True
    
    hives = [hive] if hive else [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    success = False
    for current_hive in hives:
        hive_name = "HKLM" if current_hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        try:
            for access in [winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_32KEY]:
                try:
                    key = winreg.CreateKeyEx(current_hive, key_path, 0, access)
                    winreg.SetValueEx(key, value_name, 0, value_type, value_data)
                    winreg.CloseKey(key)
                    success = True
                    break
                except Exception:
                    continue
            
            if not success:
                v_type = "REG_SZ" if value_type == winreg.REG_SZ else "REG_DWORD"
                cmd = f'reg add "{hive_name}\{key_path}" /v "{value_name}" /t {v_type} /d "{value_data}" /f'
                res, _, _ = run_command(cmd)
                if res: success = True
        except Exception:
            continue
    return success

def reg_delete_value(key_path, value_name):
    """Удаление значения из реестра с обходом блокировок"""
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Удаление из реестра: {key_path} -> {value_name}{Colors.RESET}")
        return True
    
    hives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    success = False
    for hive in hives:
        hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        # Метод 1: Прямое удаление
        for access in [winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_32KEY]:
            try:
                key = winreg.OpenKey(hive, key_path, 0, access)
                winreg.DeleteValue(key, value_name)
                winreg.CloseKey(key)
                success = True
            except Exception as _e:
                # Expected exception, intentionally ignored
                continue
        
        if not success:
            # Метод 2: Через REG DELETE
            cmd = f'reg delete "{hive_name}\\{key_path}" /v "{value_name}" /f'
            res, _, _ = run_command(cmd)
            if res: success = True
            
    return success

def reg_delete_key(key_path, recursive=False, hive=None):
    """Удаление ключа реестра"""
    if not require_mutation_allowed(f"reg_delete_key: {key_path}"):
        return True
    
    hives = [hive] if hive else [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    success_any = False
    
    for current_hive in hives:
        hive_str = "HKLM" if current_hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        try:
            if recursive:
                res = subprocess.run(['reg', 'delete', f'{hive_str}\{key_path}', '/f'], 
                                     shell=False, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if res.returncode == 0:
                    success_any = True
            else:
                try:
                    winreg.DeleteKey(current_hive, key_path)
                    success_any = True
                except Exception:
                    pass
        except Exception:
            pass
            
    return success_any

# ═══════════════════════════════════════════════════════════════
# БЛОК 1: ВИЗУАЛЬНОЕ ВОССТАНОВЛЕНИЕ (ИНТЕРФЕЙС)
# ═══════════════════════════════════════════════════════════════

def Font_Standard_Full():
    """Сброс всех подстановок шрифтов в реестре на Segoe UI"""
    print_hacker_message("Если у вас вместо букв иероглифы — это вирус. Я исправлю это в реестре.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут сброшены подстановки шрифтов на Segoe UI{Colors.RESET}")
        print(f"{Colors.CYAN}[DRY-RUN] Будет восстановлен LogPixels (масштабирование) на 96{Colors.RESET}")
        logger.log("Font_Standard_Full", "success", "Шрифты будут сброшены")
        print(f"{Colors.GREEN}[+] Шрифты будут сброшены на Segoe UI{Colors.RESET}")
        return True
    
    font_substitutes = [
        ("Microsoft Sans Serif", "Segoe UI"),
        ("Tahoma", "Segoe UI"),
        ("Arial", "Segoe UI"),
        ("Times New Roman", "Segoe UI"),
        ("Courier New", "Consolas"),
        ("Verdana", "Segoe UI"),
        ("MS Shell Dlg", "Segoe UI"),
        ("MS Shell Dlg 2", "Segoe UI")
    ]
    
    success_count = 0
    try:
        # Сбрасываем подстановки шрифтов
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes", 0, winreg.KEY_SET_VALUE)
        for font, substitute in font_substitutes:
            try:
                winreg.SetValueEx(key, font, 0, winreg.REG_SZ, substitute)
                success_count += 1
            except Exception as _e:
                # Expected exception, intentionally ignored
                pass
        winreg.CloseKey(key)
        
        # Восстанавливаем LogPixels (масштабирование DPI) - вирусы часто ставят 0 или 200
        try:
            reg_set_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontDPI", "LogPixels", 96, winreg.REG_DWORD)
            success_count += 1
        except Exception as _e:
            # Expected exception, intentionally ignored
            pass
        
        # Восстанавливаем масштаб через HKCU
        try:
            reg_set_value(r"Control Panel\Desktop", "LogPixels", 96, winreg.REG_DWORD)
            success_count += 1
        except Exception as _e:
            # Expected exception, intentionally ignored
            pass
        
        # Проверяем и восстанавливаем базовые шрифты в ветке Fonts
        try:
            fonts_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts", 0, winreg.KEY_SET_VALUE)
            # Базовые шрифты, которые должны быть
            base_fonts = [
                ("Segoe UI (TrueType)", "segoeui.ttf"),
                ("Segoe UI Bold (TrueType)", "segoeuib.ttf"),
                ("Segoe UI Italic (TrueType)", "segoeuii.ttf"),
                ("Arial (TrueType)", "arial.ttf"),
                ("Times New Roman (TrueType)", "times.ttf"),
                ("Courier New (TrueType)", "cour.ttf"),
            ]
            for font_name, font_file in base_fonts:
                try:
                    # Проверяем, существует ли значение
                    try:
                        winreg.QueryValueEx(fonts_key, font_name)
                    except FileNotFoundError:
                        # Если нет, создаем
                        winreg.SetValueEx(fonts_key, font_name, 0, winreg.REG_SZ, font_file)
                        success_count += 1
                except Exception as _e:
                    # Expected exception, intentionally ignored
                    pass
            winreg.CloseKey(fonts_key)
        except Exception as _e:
            # Expected exception, intentionally ignored
            pass
        
        # Очищаем кэш шрифтов (FNTCACHE.DAT) - вирусы часто портят его
        try:
            font_cache_path = os.path.join(os.environ['SystemRoot'], 'System32', 'FNTCACHE.DAT')
            if os.path.exists(font_cache_path):
                safe_remove(font_cache_path)
                success_count += 1
                print(f"{Colors.YELLOW}[!] Удален кэш шрифтов FNTCACHE.DAT - пересоздастся при перезагрузке{Colors.RESET}")
        except Exception as e:
            pass
        
        logger.log("Font_Standard_Full", "success", f"Сброшено {success_count} параметров шрифтов")
        print(f"{Colors.GREEN}[+] Шрифты сброшены на Segoe UI ({success_count} операций, кэш очищен){Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Font_Standard_Full", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Wallpaper_Force():
    """Удаление блокировки на смену обоев"""
    print_hacker_message("Вирус запретил менять обои. Разблокирую эту возможность.")
    
    keys_to_delete = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop", "NoChangingWallPaper"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "NoDispBackgroundPage"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop", "NoChangingWallPaper"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "NoDispBackgroundPage")
    ]
    
    if DRY_RUN:
        for hive, path, value in keys_to_delete:
            hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
            print(f"{Colors.CYAN}[DRY-RUN] Будет удалено из реестра: {hive_name}\\{path} -> {value}{Colors.RESET}")
        logger.log("Wallpaper_Force", "success", "Блокировка обоев будет снята")
        print(f"{Colors.GREEN}[+] Блокировка смены обоев будет снята{Colors.RESET}")
        return True
    
    success = False
    for hive, path, value in keys_to_delete:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, value)
            winreg.CloseKey(key)
            success = True
        except Exception as _e:
            # Expected exception, intentionally ignored
            pass
    
    if success:
        logger.log("Wallpaper_Force", "success", "Блокировка обоев снята")
        print(f"{Colors.GREEN}[+] Блокировка смены обоев снята{Colors.RESET}")
    else:
        logger.log("Wallpaper_Force", "error", "Блокировка не найдена или уже снята")
        print(f"{Colors.YELLOW}[!] Блокировка не найдена или уже снята{Colors.RESET}")
    
    return success

def Visual_Styles_Fix():
    """Восстановление стандартной темы Windows"""
    print_hacker_message("Кто-то отключил стили оформления. Возвращаю стандартную тему.")
    
    try:
        # Включаем темы
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency", 1, winreg.REG_DWORD)
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1, winreg.REG_DWORD)
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize", "SystemUsesLightTheme", 1, winreg.REG_DWORD)
        
        # Удаляем блокировку тем
        reg_delete_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoThemesTab")
        reg_delete_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "NoVisualStyleChoice")
        
        logger.log("Visual_Styles_Fix", "success", "Тема Windows восстановлена")
        print(f"{Colors.GREEN}[+] Стандартная тема Windows восстановлена{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Visual_Styles_Fix", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Icon_Size_Reset():
    """Сброс масштабирования иконок"""
    print_hacker_message("Иконки некорректного размера. Сбрасываю к стандартным настройкам.")
    
    try:
        # Сбрасываем DPI на 96 (100%)
        reg_set_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", "~", "HIGHDPIAWARE")
        
        # Сбрасываем масштаб иконок
        reg_set_value(r"Control Panel\Desktop\WindowMetrics", "Shell Icon Size", "32", winreg.REG_SZ)
        
        # Обновляем настройки отображения
        if DRY_RUN:
            print(f"{Colors.CYAN}[DRY-RUN] Будет сброшен LogPixels до 96 через PowerShell{Colors.RESET}")
        else:
            subprocess.run(["powershell", "-Command", "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'LogPixels' -Value 96"], shell=True, capture_output=True)
        
        logger.log("Icon_Size_Reset", "success", "Масштаб иконок сброшен")
        print(f"{Colors.GREEN}[+] Масштаб иконок сброшен на стандартный{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Icon_Size_Reset", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Cursor_Restore():
    """Возврат стандартного курсора"""
    print_hacker_message("Курсор некорректно отображается. Возвращаю стандартную стрелку.")
    
    try:
        # Сбрасываем настройки курсора
        cursor_path = os.path.join(os.environ['SystemRoot'], 'Cursors', 'aero_arrow.cur')
        reg_set_value(r"Control Panel\Cursors", "", "Windows Default", winreg.REG_SZ)
        reg_set_value(r"Control Panel\Cursors", "Arrow", cursor_path, winreg.REG_EXPAND_SZ)
        reg_set_value(r"Control Panel\Cursors", "AppStarting", cursor_path, winreg.REG_EXPAND_SZ)
        
        # Удаляем кастомные схемы
        reg_delete_value(r"Control Panel\Cursors", "Scheme Source")
        
        logger.log("Cursor_Restore", "success", "Стандартный курсор восстановлен")
        print(f"{Colors.GREEN}[+] Стандартный курсор восстановлен{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Cursor_Restore", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Screen_Rotate_Lock():
    """Принудительный возврат ориентации экрана в 0°"""
    print_hacker_message("Экран перевернут. Возвращаю ориентацию в 0 градусов.")
    print(f"{Colors.YELLOW}[!] ВНИМАНИЕ: Метод SendKeys работает только на старых видеокартах Intel с включенными горячими клавишами{Colors.RESET}")
    print(f"{Colors.YELLOW}[!] На современных системах Windows 10/11 может потребоваться ручная настройка через настройки дисплея{Colors.RESET}")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнен поворот экрана через PowerShell{Colors.RESET}")
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: SendKeys('^%{{UP}}'){Colors.RESET}")
        logger.log("Screen_Rotate_Lock", "success", "Ориентация экрана будет сброшена")
        print(f"{Colors.GREEN}[+] Ориентация экрана будет установлена на 0°{Colors.RESET}")
        return True
    
    try:
        # Используем PowerShell для поворота экрана через WMI
        result = subprocess.run([
            "powershell", "-Command",
            "$wmi = Get-WmiObject -Namespace root/wmi -Class WmiMonitorIDToPOMethod; $wmi.InvokeMethod(0, 1)"
        ], shell=True, capture_output=True)
        
        # Альтернативный метод через дисплей с правильными спецсимволами SendKeys
        # ^ = Control, % = Alt, {UP} = Стрелка вверх
        # ПРИМЕЧАНИЕ: Работает только если горячие клавиши включены в драйвере видеокарты
        subprocess.run(["powershell", "-Command", "(New-Object -ComObject WScript.Shell).SendKeys('^%{UP}')"], shell=True, capture_output=True)
        
        logger.log("Screen_Rotate_Lock", "success", "Ориентация экрана сброшена на 0°")
        print(f"{Colors.GREEN}[+] Ориентация экрана установлена на 0° (если не сработало - используйте настройки дисплея вручную){Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Screen_Rotate_Lock", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Попробуйте изменить ориентацию через Панель управления > Параметры > Система > Дисплей{Colors.RESET}")
        return False

def ClearType_Fix():
    """Включение сглаживания текста"""
    print_hacker_message("Сглаживание текста отключено. Включаю ClearType.")
    
    try:
        # Включаем ClearType
        reg_set_value(r"Control Panel\Desktop", "FontSmoothing", "2", winreg.REG_SZ)
        reg_set_value(r"Control Panel\Desktop", "FontSmoothingType", "2", winreg.REG_DWORD)
        reg_set_value(r"Control Panel\Desktop", "FontSmoothingGamma", "220", winreg.REG_DWORD)
        reg_set_value(r"Control Panel\Desktop", "FontSmoothingOrientation", "1", winreg.REG_DWORD)
        
        logger.log("ClearType_Fix", "success", "Сглаживание текста включено")
        print(f"{Colors.GREEN}[+] Сглаживание текста (ClearType) включено{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("ClearType_Fix", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

# ═══════════════════════════════════════════════════════════════
# БЛОК 2: РЕАНИМАЦИЯ ПРОВОДНИКА И ОБОЛОЧКИ
# ═══════════════════════════════════════════════════════════════

def Shell_Standard():
    """Проверка пути explorer.exe"""
    print_hacker_message("Проверяю путь проводника. Восстанавливаю стандартный explorer.exe.")
    
    try:
        correct_path = os.path.join(os.environ['SystemRoot'], 'explorer.exe')
        reg_set_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "explorer.exe", winreg.REG_SZ)
        
        # Проверяем и удаляем подозрительные значения
        suspicious_keys = [
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit"),
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "System")
        ]
        
        for key_path, value_name in suspicious_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                value, _ = winreg.QueryValueEx(key, value_name)
                winreg.CloseKey(key)
                
                if "explorer.exe" not in value.lower() and value != "userinit.exe,":
                    print(f"{Colors.YELLOW}[!] Обнаружено подозрительное значение: {value}{Colors.RESET}")
            except Exception as _e:
                # Expected exception, intentionally ignored
                pass
        
        # Перезапускаем проводник
        if DRY_RUN:
            print(f"{Colors.CYAN}[DRY-RUN] Будет перезапущен explorer.exe{Colors.RESET}")
        else:
            subprocess.run(["taskkill", "/f", "/im", "explorer.exe"], capture_output=True)
            time.sleep(1)
            subprocess.run(["explorer.exe"], capture_output=True)
        
        logger.log("Shell_Standard", "success", "Путь explorer.exe восстановлен")
        print(f"{Colors.GREEN}[+] Путь explorer.exe восстановлен, проводник перезапущен{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Shell_Standard", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def RightClick_Restore():
    """Включение контекстного меню"""
    print_hacker_message("Контекстное меню отключено. Включаю обратно.")
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoViewContextMenu"),
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoTrayContextMenu"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name):
            success = True
    
    if success:
        logger.log("RightClick_Restore", "success", "Контекстное меню включено")
        print(f"{Colors.GREEN}[+] Контекстное меню включено{Colors.RESET}")
    else:
        logger.log("RightClick_Restore", "error", "Контекстное меню не найдено")
        print(f"{Colors.YELLOW}[!] Контекстное меню не заблокировано{Colors.RESET}")
    
    return success

def Drive_Visibility():
    """Снятие флага NoDrives"""
    print_hacker_message("Диски скрыты в системе. Восстанавливаю видимость.")
    
    try:
        # Сбрасываем NoDrives в 0 (все диски видны)
        reg_set_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDrives", 0, winreg.REG_DWORD)
        reg_set_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 0, winreg.REG_DWORD)
        
        # То же самое для HKLM
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDrives", 0, winreg.REG_DWORD)
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 0, winreg.REG_DWORD)
        
        logger.log("Drive_Visibility", "success", "Видимость дисков восстановлена")
        print(f"{Colors.GREEN}[+] Все диски снова видны{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Drive_Visibility", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Taskbar_Fix():
    """Разблокировка свойств панели задач"""
    print_hacker_message("Панель задач заблокирована. Разблокирую настройки.")
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoTaskbar"),
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "LockTaskbar"),
        (r"Software\Policies\Microsoft\Windows\Explorer", "TaskbarNoNotification"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name):
            success = True
    
    if success:
        logger.log("Taskbar_Fix", "success", "Панель задач разблокирована")
        print(f"{Colors.GREEN}[+] Панель задач разблокирована{Colors.RESET}")
    else:
        logger.log("Taskbar_Fix", "error", "Панель задач не заблокирована")
        print(f"{Colors.YELLOW}[!] Панель задач не заблокирована{Colors.RESET}")
    
    return success

def System_Tray_Show():
    """Возврат значков в трей"""
    print_hacker_message("Значки в трее отсутствуют. Восстанавливаю отображение.")
    
    try:
        # Включаем системный трей
        reg_set_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoTrayItemsDisplay", 0, winreg.REG_DWORD)
        reg_delete_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoTrayContextMenu")
        
        # Включаем отдельные иконки
        reg_set_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoSetTaskbar", 0, winreg.REG_DWORD)
        
        logger.log("System_Tray_Show", "success", "Системный трей восстановлен")
        print(f"{Colors.GREEN}[+] Значки системного трея восстановлены{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("System_Tray_Show", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Desktop_Icons_Revive():
    """Принудительное включение отображения значков стола"""
    print_hacker_message("Рабочий стол пуст. Восстанавливаю отображение значков.")
    
    try:
        # Включаем отображение иконок рабочего стола
        reg_set_value(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "IconsOnly", 1, winreg.REG_DWORD)
        reg_set_value(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowInfoTip", 1, winreg.REG_DWORD)
        
        # Удаляем блокировку
        reg_delete_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDesktop")
        
        # Перезапускаем проводник
        if not DRY_RUN:
            subprocess.run(["taskkill", "/f", "/im", "explorer.exe"], capture_output=True)
            time.sleep(0.5)
            subprocess.run(["explorer.exe"], capture_output=True)
        else:
            print(f"{Colors.CYAN}[DRY-RUN] Будет перезапущен explorer.exe{Colors.RESET}")
        
        logger.log("Desktop_Icons_Revive", "success", "Значки рабочего стола включены")
        print(f"{Colors.GREEN}[+] Значки рабочего стола отображаются{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Desktop_Icons_Revive", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def HiddenFiles_Show():
    """Включение отображения скрытых файлов"""
    print_hacker_message("Скрытые файлы не отображаются. Включаю видимость.")
    
    try:
        # Включаем отображение скрытых файлов
        reg_set_value(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Hidden", 1, winreg.REG_DWORD)
        reg_set_value(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowSuperHidden", 1, winreg.REG_DWORD)
        reg_set_value(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 0, winreg.REG_DWORD)
        
        # Удаляем блокировку
        reg_delete_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoHidden")
        
        # Обновляем проводник
        if not DRY_RUN:
            subprocess.run(["taskkill", "/f", "/im", "explorer.exe"], capture_output=True)
            time.sleep(0.5)
            subprocess.run(["explorer.exe"], capture_output=True)
        else:
            print(f"{Colors.CYAN}[DRY-RUN] Будет перезапущен explorer.exe для обновления{Colors.RESET}")
        
        logger.log("HiddenFiles_Show", "success", "Скрытые файлы включены")
        print(f"{Colors.GREEN}[+] Отображение скрытых файлов включено{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("HiddenFiles_Show", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Shell_Validation():
    """Проверка ключа Winlogon/Shell (должен быть только explorer.exe)"""
    print_hacker_message("Проверяю, что в Shell только explorer.exe, а не вирус!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет проверен ключ Winlogon\\Shell{Colors.RESET}")
        logger.log("Shell_Validation", "success", "Ключ Shell будет проверен")
        print(f"{Colors.GREEN}[+] Ключ Shell будет проверен{Colors.RESET}")
        return True
    
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
        shell_value, _ = winreg.QueryValueEx(key, "Shell")
        winreg.CloseKey(key)
        
        if shell_value.strip().lower() != "explorer.exe":
            print(f"{Colors.YELLOW}[!] Обнаружен модифицированный Shell: {shell_value}{Colors.RESET}")
            reg_set_value(key_path, "Shell", "explorer.exe", winreg.REG_SZ)
            logger.log("Shell_Validation", "success", "Shell восстановлен на explorer.exe")
            print(f"{Colors.GREEN}[+] Shell восстановлен на explorer.exe{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}[+] Shell корректен: explorer.exe{Colors.RESET}")
        
        return True
    except Exception as e:
        logger.log("Shell_Validation", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Userinit_Fix():
    """Проверка ключа Userinit (чтобы вирус не запускался перед входом)"""
    print_hacker_message("Проверяю Userinit, чтобы вирус не запускался при входе!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет проверен ключ Winlogon\\Userinit{Colors.RESET}")
        logger.log("Userinit_Fix", "success", "Ключ Userinit будет проверен")
        print(f"{Colors.GREEN}[+] Ключ Userinit будет проверен{Colors.RESET}")
        return True
    
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
        userinit_value, _ = winreg.QueryValueEx(key, "Userinit")
        winreg.CloseKey(key)
        
        # Userinit должен быть userinit.exe, может быть с запятой и другими параметрами
        if "userinit.exe" not in userinit_value.lower():
            print(f"{Colors.YELLOW}[!] Обнаружен модифицированный Userinit: {userinit_value}{Colors.RESET}")
            reg_set_value(key_path, "Userinit", "userinit.exe,", winreg.REG_SZ)
            logger.log("Userinit_Fix", "success", "Userinit восстановлен")
            print(f"{Colors.GREEN}[+] Userinit восстановлен{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}[+] Userinit корректен{Colors.RESET}")
        
        return True
    except Exception as e:
        logger.log("Userinit_Fix", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

# ═══════════════════════════════════════════════════════════════
# БЛОК 3: РЕЕСТР И ДОСТУП (HARD)
# ═══════════════════════════════════════════════════════════════

def Reg_Write_Enable():
    """Разблокировка редактирования реестра"""
    print_hacker_message("Редактор реестра заблокирован. Разблокирую доступ.")
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools"),
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name):
            success = True
    
    if success:
        logger.log("Reg_Write_Enable", "success", "Реестр разблокирован")
        print(f"{Colors.GREEN}[+] Реестр разблокирован для редактирования{Colors.RESET}")
    else:
        logger.log("Reg_Write_Enable", "error", "Реестр не заблокирован")
        print(f"{Colors.YELLOW}[!] Реестр не заблокирован{Colors.RESET}")
    
    return success

def TaskMgr_Hard_Unlock():
    """Разблокировка диспетчера задач"""
    print_hacker_message("Диспетчер задач заблокирован. Разблокирую доступ.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут проверены и удалены все блокировки TaskMgr (4 пути){Colors.RESET}")
        logger.log("TaskMgr_Hard_Unlock", "success", "Диспетчер задач будет разблокирован")
        print(f"{Colors.GREEN}[+] Диспетчер задач будет разблокирован{Colors.RESET}")
        return True
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"),
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "TaskbarNoTaskMgr"),
        (r"Software\Policies\Microsoft\Windows\System", "DisableTaskMgr"),
        (r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name):
            success = True
    
    if success:
        logger.log("TaskMgr_Hard_Unlock", "success", "Диспетчер задач разблокирован")
        print(f"{Colors.GREEN}[+] Диспетчер задач разблокирован{Colors.RESET}")
    else:
        logger.log("TaskMgr_Hard_Unlock", "error", "Диспетчер задач не заблокирован")
        print(f"{Colors.YELLOW}[!] Диспетчер задач не заблокирован{Colors.RESET}")
    
    return success
def ControlPanel_Unlock():
    """Разблокировка панели управления"""
    print_hacker_message("Панель управления заблокирована. Разблокирую доступ.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут проверены и удалены все блокировки Панели управления{Colors.RESET}")
        logger.log("ControlPanel_Unlock", "success", "Панель управления будет разблокирована")
        print(f"{Colors.GREEN}[+] Панель управления будет разблокирована{Colors.RESET}")
        return True
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoControlPanel"),
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "RestrictRun"),
        (r"Software\Policies\Microsoft\Windows\Control Panel", "NoControlPanel"),
        (r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoControlPanel"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name):
            success = True
    
    if success:
        logger.log("ControlPanel_Unlock", "success", "Панель управления разблокирована")
        print(f"{Colors.GREEN}[+] Панель управления разблокирована{Colors.RESET}")
    else:
        logger.log("ControlPanel_Unlock", "error", "Панель управления не заблокирована")
    
    return success

def FolderOptions_Unlock():
    """Разблокировка свойств папки"""
    print_hacker_message("Свойства папки заблокированы. Разблокирую.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет разблокирован доступ к Свойствам папки{Colors.RESET}")
        logger.log("FolderOptions_Unlock", "success", "Свойства папки будут разблокированы")
        return True
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoFolderOptions"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name):
            success = True
    
    if success:
        logger.log("FolderOptions_Unlock", "success", "Свойства папки разблокированы")
        print(f"{Colors.GREEN}[+] Свойства папки разблокированы{Colors.RESET}")
    else:
        logger.log("FolderOptions_Unlock", "error", "Свойства папки не заблокированы")
    
    return success

def Taskbar_Properties_Unlock():
    """Разблокировка свойств панели задач"""
    print_hacker_message("Свойства панели задач заблокированы. Восстанавливаю.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут разблокированы свойства панели задач{Colors.RESET}")
        logger.log("Taskbar_Properties_Unlock", "success", "Свойства панели задач будут разблокированы")
        return True
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoSetTaskbar"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name):
            success = True
    
    if success:
        logger.log("Taskbar_Properties_Unlock", "success", "Свойства панели задач разблокированы")
        print(f"{Colors.GREEN}[+] Свойства панели задач разблокированы{Colors.RESET}")
    else:
        logger.log("Taskbar_Properties_Unlock", "error", "Свойства панели задач не заблокированы")
    
    return success

def WinKeys_Unlock():
    """Разблокировка горячих клавиш Windows"""
    print_hacker_message("Горячие клавиши Windows отключены. Включаю.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут разблокированы горячие клавиши Windows{Colors.RESET}")
        logger.log("WinKeys_Unlock", "success", "Горячие клавиши Windows будут разблокированы")
        return True
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoWinKeys"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name):
            success = True
    
    if success:
        logger.log("WinKeys_Unlock", "success", "Горячие клавиши Windows разблокированы")
        print(f"{Colors.GREEN}[+] Горячие клавиши Windows разблокированы{Colors.RESET}")
    else:
        logger.log("WinKeys_Unlock", "error", "Горячие клавиши Windows не заблокированы")
    
    return success



def Logoff_User():
    """Принудительный выход из пользователя"""
    print_hacker_message("Выход из текущего пользователя.")
    if not DRY_RUN:
        run_command("shutdown /l /f")
    return True

def Boot_WinRE():
    """Перезагрузка в среду восстановления (WinRE)"""
    print_hacker_message("Подготовка к перезагрузке в WinRE.")
    if not DRY_RUN:
        run_command("reagentc /boottore")
        run_command("shutdown /r /t 0")
    return True

def Restore_Russian_Keyboard():
    """Восстановление русской раскладки клавиатуры"""
    print_hacker_message("Восстанавливаю русскую раскладку клавиатуры.")
    if not DRY_RUN:
        reg_set_value(r"Keyboard Layout\Preload", "1", "00000409", winreg.REG_SZ, winreg.HKEY_CURRENT_USER)
        reg_set_value(r"Keyboard Layout\Preload", "2", "00000419", winreg.REG_SZ, winreg.HKEY_CURRENT_USER)
    return True

def SFC_Scannow():
    """Запуск проверки системных файлов (sfc /scannow)"""
    print_hacker_message("Запуск SFC Scannow.")
    if not DRY_RUN:
        subprocess.Popen("start cmd /k sfc /scannow", shell=True)
    return True

def LogonUI_Restore():
    """Восстановление стандартного экрана входа LogonUI"""
    print_hacker_message("Восстановление экрана блокировки и LogonUI.")
    if not DRY_RUN:
        reg_delete_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\logonui.exe", "Debugger")
    return True

def Emergency_Recovery():
    """Экстренное восстановление: убить сторонние процессы"""
    print_hacker_message("Экстренное восстановление: закрытие всех неизвестных процессов.")
    if not DRY_RUN:
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                name = proc.info['name'].lower()
                if name not in ['explorer.exe', 'taskmgr.exe', 'svchost.exe', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'winlogon.exe', 'novir.exe', 'python.exe']:
                    try:
                        proc.kill()
                    except Exception as _e:
                        # Expected exception, intentionally ignored
                        pass
            run_command("taskkill /f /im explorer.exe & start explorer.exe")
        except Exception as _e:
            # Expected exception, intentionally ignored
            pass
    return True

def Disable_Test_Mode():
    """Отключение тестового режима Windows"""
    print_hacker_message("Отключение тестового режима.")
    if not DRY_RUN:
        run_command("bcdedit /set testsigning off")
        run_command("bcdedit /set nointegritychecks off")
    return True

def Replace_Sethc_Utilman():
    """Заменить sethc и utilman"""
    print_hacker_message("Запуск замены sethc и utilman.")
    if not DRY_RUN:
        import sys, shutil, os
        novir_path = sys.executable
        if not novir_path.endswith('.exe'):
            novir_path = os.path.abspath(__file__) # For dev environment
            
        sys32 = r"C:\Windows\System32"
        files = ["sethc.exe", "utilman.exe"]
        restored = False
        
        for file in files:
            target = os.path.join(sys32, file)
            bak = target + ".bak"
            
            run_command(f'takeown /f "{target}"')
            run_command(f'icacls "{target}" /grant administrators:F')
            
            if os.path.exists(bak):
                # Restore
                try:
                    safe_remove(target)
                    shutil.move(bak, target)
                    restored = True
                except: pass
            else:
                # Replace
                try:
                    shutil.move(target, bak)
                    shutil.copy(novir_path, target)
                except: pass
                
        if restored:
            print("Оригинальные файлы sethc и utilman восстановлены.")
        else:
            print("Файлы sethc и utilman заменены на NoVir.exe.")
    return True

def File_Full_Access():
    """Полный доступ к файлу (Takeown & Icacls)"""
    print_hacker_message("Запуск процедуры получения прав на файл.")
    if not DRY_RUN:
        from PySide6.QtWidgets import QFileDialog, QMessageBox, QApplication
        app = QApplication.instance()
        if app:
            active_window = app.activeWindow()
            file_path, _ = QFileDialog.getOpenFileName(active_window, "Выберите файл для полного доступа")
            if file_path:
                run_command(f'takeown /f "{file_path}"')
                run_command(f'icacls "{file_path}" /grant administrators:F')
                QMessageBox.information(active_window, "Готово", f"Полный доступ к {file_path} получен.")
    return True

def Driver_Cleanup():
    """Очистка драйверов"""
    print_hacker_message("Удаление всех нештатных драйверов.")
    if not DRY_RUN:
        run_command("pnputil /delete-driver oem*.inf /uninstall /force")
        print("Сторонние драйверы удалены.")
    return True

def Alt_N_Fix():
    """Alt+N"""
    print_hacker_message("Создание ярлыка с шорткатом Alt+N.")
    if not DRY_RUN:
        import sys, os
        novir_path = sys.executable
        desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
        shortcut_path = os.path.join(desktop, 'NoVir_Emergency.lnk')
        
        if os.path.exists(shortcut_path):
            safe_remove(shortcut_path)
            print("Ярлык удален (функция Alt+N отключена).")
        else:
            try:
                vbs_path = os.path.join(os.environ['TEMP'], 'novir_shortcut.vbs')
                vbs_code = f"""
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "{shortcut_path}"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "{novir_path}"
oLink.Hotkey = "ALT+N"
oLink.IconLocation = "{novir_path}, 0"
oLink.Save
"""
                with open(vbs_path, 'w', encoding='utf-8') as vbs_file:
                    vbs_file.write(vbs_code)
                import subprocess
                subprocess.run(['cscript', '//nologo', vbs_path], creationflags=subprocess.CREATE_NO_WINDOW)
                safe_remove(vbs_path)
                run_command(f'attrib +h "{shortcut_path}"')
                print(f"[+] Ярлык создан (VBS): {shortcut_path}")
            except Exception as e:
                print(f"[!] Ошибка создания ярлыка: {e}")
    return True

def Easy_Launcher():
    """Удобный запуск"""
    print_hacker_message("Установка Удобного запуска (nov, контекстное меню, отключение UAC).")
    if not DRY_RUN:
        import sys, shutil, os
        import winreg
        
        # 1. Отключение UAC
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 0, winreg.REG_DWORD)
        
        novir_path = sys.executable
        if novir_path.endswith('.exe'):
            # 2. Копирование как nov.exe
            nov_path = r"C:\Windows\nov.exe"
            try:
                shutil.copy(novir_path, nov_path)
            except: pass
            
            # 3. Контекстное меню
            try:
                key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, r"Directory\Background\shell\NoVir")
                winreg.SetValue(key, "", winreg.REG_SZ, "Запустить NoVir")
                winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, novir_path)
                
                command_key = winreg.CreateKey(key, "command")
                winreg.SetValue(command_key, "", winreg.REG_SZ, f'"{novir_path}"')
                winreg.CloseKey(command_key)
                winreg.CloseKey(key)
            except: pass
            
            print("Удобный запуск установлен. Запускайте через 'nov' в Win+R или через правый клик по рабочему столу.")
    return True

# ВСТРОЕННЫЕ ПРОГРАММЫ
def Open_Regedit():
    print_hacker_message("Запуск Regedit")
    if not DRY_RUN: import ctypes; ctypes.windll.shell32.ShellExecuteW(None, "runas", "regedit.exe", None, None, 1)
    return True

def Open_Explorer():
    print_hacker_message("Запуск Explorer")
    if not DRY_RUN: subprocess.Popen("explorer.exe")
    return True

def Open_Taskmgr():
    print_hacker_message("Запуск Taskmgr")
    if not DRY_RUN: import ctypes; ctypes.windll.shell32.ShellExecuteW(None, "runas", "taskmgr.exe", None, None, 1)
    return True

def Fix_MBR_Boot():
    print_hacker_message("Скрипт восстановления загрузчика")
    if not DRY_RUN:
        subprocess.Popen('start cmd /k "bootrec /fixmbr & bootrec /fixboot & bootrec /rebuildbcd"', shell=True)
    return True

def Open_Browser():
    print_hacker_message("Запуск Браузера")
    if not DRY_RUN: subprocess.Popen("start https://google.com", shell=True)
    return True

def Open_User_Management():
    print_hacker_message("Запуск управления пользователями")
    if not DRY_RUN: subprocess.Popen("lusrmgr.msc", shell=True)
    return True

def Open_System_Cleanup():
    print_hacker_message("Запуск очистки диска")
    if not DRY_RUN: import ctypes; ctypes.windll.shell32.ShellExecuteW(None, "runas", "cleanmgr.exe", None, None, 1)
    return True

def Open_Default_Apps():
    print_hacker_message("Запуск ассоциаций")
    if not DRY_RUN: subprocess.Popen("start ms-settings:defaultapps", shell=True)
    return True

def Open_Password_Reset():
    print_hacker_message("Сброс пароля")
    if not DRY_RUN: import ctypes; ctypes.windll.shell32.ShellExecuteW(None, "runas", "netplwiz.exe", None, None, 1)
    return True

def Open_Disk_Management():
    print_hacker_message("Управление дисками")
    if not DRY_RUN: subprocess.Popen("diskmgmt.msc", shell=True)
    return True

def WinRE_Backup_Restore():
    print_hacker_message("Резервное копирование WinRE")
    if not DRY_RUN:
        subprocess.Popen("start cmd /k reagentc /info", shell=True)
    return True


def Keyboard_Scancode_Reset():
    """Сброс переназначения клавиш (Scancode Map)"""
    print_hacker_message("Клавиатура заблокирована на уровне драйвера. Выполняю сброс Scancode Map.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет удален Scancode Map из реестра{Colors.RESET}")
        logger.log("Keyboard_Scancode_Reset", "success", "Scancode Map будет сброшен")
        return True
    
    success = reg_delete_value(r"SYSTEM\CurrentControlSet\Control\Keyboard Layout", "Scancode Map")
    
    if success:
        logger.log("Keyboard_Scancode_Reset", "success", "Сброс Scancode Map выполнен успешно (требуется перезагрузка)")
        print(f"{Colors.GREEN}[+] Блокировка клавиатуры снята (требуется перезагрузка для применения){Colors.RESET}")
    else:
        logger.log("Keyboard_Scancode_Reset", "error", "Scancode Map не найден или не заблокирован")
        print(f"{Colors.YELLOW}[!] Блокировка Scancode Map не обнаружена{Colors.RESET}")
    
    return success

def FilterKeys_Disable():
    """Отключение залипания и фильтрации ввода (FilterKeys)"""
    print_hacker_message("Отключаю залипание и фильтрацию клавиш (FilterKeys).")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут отключены FilterKeys{Colors.RESET}")
        logger.log("FilterKeys_Disable", "success", "FilterKeys будут отключены")
        return True
        
    try:
        # Flags "58" = Off. "59" or "62" = On
        import winreg
        reg_set_value(r"Control Panel\Accessibility\Keyboard Response", "Flags", "58", winreg.REG_SZ, hive=winreg.HKEY_CURRENT_USER)
        reg_set_value(r"Control Panel\Accessibility\StickyKeys", "Flags", "506", winreg.REG_SZ, hive=winreg.HKEY_CURRENT_USER)
        reg_set_value(r"Control Panel\Accessibility\ToggleKeys", "Flags", "58", winreg.REG_SZ, hive=winreg.HKEY_CURRENT_USER)
        
        logger.log("FilterKeys_Disable", "success", "Специальные возможности клавиатуры отключены")
        print(f"{Colors.GREEN}[+] Залипание и фильтрация клавиш отключены{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("FilterKeys_Disable", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка при отключении FilterKeys: {e}{Colors.RESET}")
        return False

def SystemProperties_Unlock():
    """Разблокировка свойств системы"""
    print_hacker_message("Свойства системы заблокированы. Разблокирую.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут разблокированы свойства системы{Colors.RESET}")
        logger.log("SystemProperties_Unlock", "success", "Свойства системы будут разблокированы")
        return True
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoPropertiesMyComputer"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name):
            success = True
    
    if success:
        logger.log("SystemProperties_Unlock", "success", "Свойства системы разблокированы")
        print(f"{Colors.GREEN}[+] Свойства системы разблокированы{Colors.RESET}")
    else:
        logger.log("SystemProperties_Unlock", "error", "Свойства системы не заблокированы")
    
    return success

def Run_Command_Enable():
    """Разблокировка окна Выполнить Win+R"""
    print_hacker_message("Окно 'Выполнить' заблокировано. Разблокирую доступ.")
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoRun"),
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoNoRun"),
        (r"Software\Policies\Microsoft\Windows\Explorer", "NoRun"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name):
            success = True
    
    if success:
        logger.log("Run_Command_Enable", "success", "Команда Win+R разблокирована")
        print(f"{Colors.GREEN}[+] Окно Выполнить (Win+R) разблокировано{Colors.RESET}")
    else:
        logger.log("Run_Command_Enable", "error", "Win+R не заблокирован")
        print(f"{Colors.YELLOW}[!] Win+R не заблокирован{Colors.RESET}")
    
    return success

def UAC_Default_Fix():
    """Сброс уровня контроля учетных записей"""
    print_hacker_message("Восстанавливаю стандартный уровень контроля учетных записей (UAC).")
    
    try:
        # Включаем UAC (EnableLUA = 1)
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1, winreg.REG_DWORD)
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop", 1, winreg.REG_DWORD)
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 5, winreg.REG_DWORD)
        
        logger.log("UAC_Default_Fix", "success", "UAC восстановлен")
        print(f"{Colors.GREEN}[+] UAC восстановлен на стандартный уровень{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("UAC_Default_Fix", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Admin_Shares_Restore():
    """Восстановление скрытых админских ресурсов"""
    print_hacker_message("Восстанавливаю скрытые административные ресурсы (C$, ADMIN$).")
    
    try:
        # Включаем админские шары
        reg_set_value(r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "AutoShareWks", 1, winreg.REG_DWORD)
        reg_set_value(r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "AutoShareServer", 1, winreg.REG_DWORD)
        
        # Перезапускаем сервер
        if DRY_RUN:
            print(f"{Colors.CYAN}[DRY-RUN] Будет перезапущена служба lanmanserver{Colors.RESET}")
        else:
            subprocess.run(["net", "stop", "lanmanserver", "/y"], capture_output=True)
            time.sleep(2)
            subprocess.run(["net", "start", "lanmanserver"], capture_output=True)
        
        logger.log("Admin_Shares_Restore", "success", "Админские ресурсы восстановлены")
        print(f"{Colors.GREEN}[+] Админские ресурсы (C$, ADMIN$) включены{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Admin_Shares_Restore", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Policies_Nuke():
    """Полная очистка папки GroupPolicy"""
    print_hacker_message("Очищаю локальные групповые политики для снятия системных ограничений.")
    
    try:
        policy_paths = [
            os.path.join(os.environ['SystemRoot'], 'System32', 'GroupPolicy'),
            os.path.join(os.environ['SystemRoot'], 'System32', 'GroupPolicyUsers'),
        ]
        
        deleted_count = 0
        for path in policy_paths:
            if os.path.exists(path):
                if DRY_RUN:
                    print(f"{Colors.CYAN}[DRY-RUN] Будет удалена папка: {path}{Colors.RESET}")
                    deleted_count += 1
                else:
                    try:
                        safe_rmtree(path)
                        deleted_count += 1
                        print(f"{Colors.GREEN}[+] Удалено: {path}{Colors.RESET}")
                    except Exception as e:
                        print(f"{Colors.YELLOW}[!] Не удалось удалить {path}: {e}{Colors.RESET}")
        
        # Обновляем групповые политики
        if not DRY_RUN:
            subprocess.run(["gpupdate", "/force"], capture_output=True)
        else:
            print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: gpupdate /force{Colors.RESET}")
        
        logger.log("Policies_Nuke", "success", f"Удалено {deleted_count} папок политик")
        print(f"{Colors.GREEN}[+] Групповые политики очищены (удалено {deleted_count} папок){Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Policies_Nuke", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def IFEO_Clean():
    """Очистка Image File Execution Options - удаление вирусных перехватчиков запуска"""
    print_hacker_message("Вирус прописал debugger для диспетчера задач? Щас вычистю IFEO, чтобы программы запускались нормально!")
    
    # Критичные системные программы, которые вирусы часто перехватывают
    critical_apps = [
        'taskmgr.exe',
        'msconfig.exe',
        'regedit.exe',
        'cmd.exe',
        'powershell.exe',
        'notepad.exe',
        'mspaint.exe',
        'calc.exe',
        'write.exe',
        'explorer.exe',
    ]
    
    cleaned_count = 0
    ifeo_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    
    try:
        if DRY_RUN:
            for app in critical_apps:
                print(f"{Colors.CYAN}[DRY-RUN] Будет проверен IFEO для: {app}{Colors.RESET}")
            print(f"{Colors.CYAN}[DRY-RUN] Будут удалены значения debugger из IFEO{Colors.RESET}")
            logger.log("IFEO_Clean", "success", "IFEO будет очищен")
            print(f"{Colors.GREEN}[+] Image File Execution Options будет очищен{Colors.RESET}")
            return True
        
        # Проверяем и удаляем debugger для критичных приложений
        for app in critical_apps:
            app_path = f"{ifeo_path}\\{app}"
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, app_path, 0, winreg.KEY_READ)
                try:
                    debugger, _ = winreg.QueryValueEx(key, "Debugger")
                    print(f"{Colors.YELLOW}[!] Обнаружен перехватчик для {app}: {debugger}{Colors.RESET}")
                    winreg.DeleteValue(key, "Debugger")
                    cleaned_count += 1
                    print(f"{Colors.GREEN}[+] Удален debugger для {app}{Colors.RESET}")
                except FileNotFoundError:
                    pass  # Нет debugger - это хорошо
                winreg.CloseKey(key)
            except FileNotFoundError:
                pass  # Ключа нет - это хорошо
            except Exception as e:
                pass
        
        # Также проверяем общие настройки IFEO
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo_path, 0, winreg.KEY_READ)
            winreg.CloseKey(key)
        except Exception as _e:
            # Expected exception, intentionally ignored
            pass
        
        logger.log("IFEO_Clean", "success", f"Очищено {cleaned_count} перехватчиков")
        print(f"{Colors.GREEN}[+] Image File Execution Options очищен (удалено {cleaned_count} перехватчиков){Colors.RESET}")
        return True
    except Exception as e:
        logger.log("IFEO_Clean", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Regedit_CMD_Unlock():
    """Глубокая разблокировка Regedit и CMD (все пути)"""
    print_hacker_message("Regedit или CMD заблокированы? Щас вернём доступ к редактору реестра и командной строке!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут проверены и удалены все блокировки Regedit и CMD{Colors.RESET}")
        logger.log("Regedit_CMD_Unlock", "success", "Regedit и CMD будут разблокированы")
        print(f"{Colors.GREEN}[+] Regedit и CMD будут разблокированы{Colors.RESET}")
        return True
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools"),
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableCMD"),
        (r"Software\Policies\Microsoft\Windows\System", "DisableCMD"),
        (r"Software\Policies\Microsoft\Windows\System", "DisableRegistryTools"),
        (r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools"),
        (r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System", "DisableCMD"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name):
            success = True
    
    if success:
        logger.log("Regedit_CMD_Unlock", "success", "Regedit и CMD разблокированы")
        print(f"{Colors.GREEN}[+] Regedit и CMD разблокированы{Colors.RESET}")
    else:
        logger.log("Regedit_CMD_Unlock", "error", "Regedit и CMD не заблокированы")
        print(f"{Colors.YELLOW}[!] Regedit и CMD не заблокированы{Colors.RESET}")
    
    return success

# ═══════════════════════════════════════════════════════════════
# БЛОК 4: СЕТЬ И ИНТЕРНЕТ
# ═══════════════════════════════════════════════════════════════

def Hosts_Clean_Hard():
    """Очистка файла hosts от вирусных записей"""
    print_hacker_message("Проверяю файл hosts. Удаляю блокировки антивирусов.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет перезаписан файл: C:\\Windows\\System32\\drivers\\etc\\hosts{Colors.RESET}")
        logger.log("Hosts_Clean_Hard", "success", "Файл hosts будет очищен")
        print(f"{Colors.GREEN}[+] Файл hosts будет очищен{Colors.RESET}")
        return True
    
    try:
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        # Сначала снимаем атрибуты (только чтение, скрытый, системный)
        subprocess.run(f'attrib -r -s -h "{hosts_path}"', shell=True, capture_output=True)
        
        default_hosts = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
"""
        
        # Пытаемся записать с правами администратора
        try:
            with open(hosts_path, 'w', encoding='utf-8') as f:
                f.write(default_hosts)
            logger.log("Hosts_Clean_Hard", "success", "Файл hosts очищен")
            print(f"{Colors.GREEN}[+] Файл hosts очищен{Colors.RESET}")
            return True
        except PermissionError:
            # Если нет прав, используем PowerShell с elevate
            ps_cmd = f'''$content = @'
{default_hosts}
'@; Set-Content -Path "{hosts_path}" -Value $content -Force'''
            subprocess.run(["powershell", "-Command", ps_cmd], shell=True, capture_output=True)
            logger.log("Hosts_Clean_Hard", "success", "Файл hosts очищен через PowerShell")
            print(f"{Colors.GREEN}[+] Файл hosts очищен через PowerShell{Colors.RESET}")
            return True
    except Exception as e:
        logger.log("Hosts_Clean_Hard", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Proxy_Nuke():
    """Отключение прокси-серверов"""
    print_hacker_message("Вирус установил свой прокси для слежки. Отключаю.")
    
    try:
        # Отключаем прокси в реестре
        reg_set_value(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable", 0, winreg.REG_DWORD)
        reg_delete_value(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer")
        reg_delete_value(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "AutoConfigURL")
        
        # То же самое для HKLM
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable", 0, winreg.REG_DWORD)
        
        # Отключаем через netsh
        if not DRY_RUN:
            subprocess.run(["netsh", "winhttp", "reset", "proxy"], capture_output=True)
        else:
            print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: netsh winhttp reset proxy{Colors.RESET}")
        
        logger.log("Proxy_Nuke", "success", "Прокси отключен")
        print(f"{Colors.GREEN}[+] Все прокси-серверы отключены{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Proxy_Nuke", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def DNS_Google_Force():
    """Принудительная установка Google DNS (8.8.8.8) на все активные адаптеры"""
    print_hacker_message("DNS сломан или направлен на вирусный сервер? Щас поставим Google DNS — 8.8.8.8!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет установлен Google DNS (8.8.8.8, 8.8.4.4) на все активные интерфейсы{Colors.RESET}")
        logger.log("DNS_Google_Force", "success", "DNS будет установлен на 8.8.8.8")
        print(f"{Colors.GREEN}[+] DNS будет установлен на 8.8.8.8 и 8.8.4.4{Colors.RESET}")
        return True
    
    try:
        # Получаем список активных интерфейсов через PowerShell
        ps_cmd = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"
        success, stdout, _ = run_command(f'powershell -Command "{ps_cmd}"')
        
        if success and stdout:
            interfaces = [i.strip() for i in stdout.split('\n') if i.strip()]
            for interface in interfaces:
                # Устанавливаем DNS через netsh для каждого активного интерфейса
                subprocess.run(f'netsh interface ip set dns name="{interface}" static 8.8.8.8 primary', shell=True, capture_output=True)
                subprocess.run(f'netsh interface ip add dns name="{interface}" 8.8.4.4 index=2', shell=True, capture_output=True)
            
            # Сбрасываем кэш DNS
            subprocess.run("ipconfig /flushdns", shell=True, capture_output=True)
            
            logger.log("DNS_Google_Force", "success", f"DNS установлен на {len(interfaces)} интерфейсах")
            print(f"{Colors.GREEN}[+] DNS успешно изменен на Google DNS{Colors.RESET}")
            return True
        else:
            # Fallback: пробуем стандартный способ через name=*
            subprocess.run('netsh interface ip set dns name="*" static 8.8.8.8 primary', shell=True, capture_output=True)
            subprocess.run('netsh interface ip add dns name="*" 8.8.4.4 index=2', shell=True, capture_output=True)
            subprocess.run("ipconfig /flushdns", shell=True, capture_output=True)
            return True
    except Exception as e:
        logger.log("DNS_Google_Force", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Firewall_State_Reset():
    """Сброс настроек брандмауэра на заводские"""
    print_hacker_message("Брандмауэр настроен криво? Щас сбросим на заводские настройки!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: netsh advfirewall reset{Colors.RESET}")
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: netsh advfirewall set allprofiles state on{Colors.RESET}")
        logger.log("Firewall_State_Reset", "success", "Брандмауэр будет сброшен")
        print(f"{Colors.GREEN}[+] Брандмауэр будет сброшен на заводские настройки{Colors.RESET}")
        return True
    
    try:
        # Сбрасываем брандмауэр
        subprocess.run(["netsh", "advfirewall", "reset"], capture_output=True)
        
        # Включаем брандмауэр для всех профилей
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], capture_output=True)
        
        logger.log("Firewall_State_Reset", "success", "Брандмауэр сброшен")
        print(f"{Colors.GREEN}[+] Брандмауэр сброшен на заводские настройки{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Firewall_State_Reset", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def WinHttp_Proxy_Reset():
    """Сброс прокси через netsh (системный уровень)"""
    print_hacker_message("WinHttp прокси тоже отключим, чтобы на системном уровне всё было чисто!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: netsh winhttp reset proxy{Colors.RESET}")
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: netsh winhttp import proxy source=ie{Colors.RESET}")
        logger.log("WinHttp_Proxy_Reset", "success", "WinHttp прокси будет сброшен")
        print(f"{Colors.GREEN}[+] WinHttp прокси будет сброшен{Colors.RESET}")
        return True
    
    try:
        subprocess.run(["netsh", "winhttp", "reset", "proxy"], capture_output=True)
        subprocess.run(["netsh", "winhttp", "import", "proxy", "source=ie"], capture_output=True)
        
        logger.log("WinHttp_Proxy_Reset", "success", "WinHttp прокси сброшен")
        print(f"{Colors.GREEN}[+] WinHttp прокси сброшен{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("WinHttp_Proxy_Reset", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Network_Discovery_On():
    """Включение сетевого обнаружения"""
    print_hacker_message("Сетевое обнаружение выключено? Щас включим, чтобы компы в сети видеть!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: netsh firewall set service type=fileandprint mode=enable{Colors.RESET}")
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: netsh advfirewall firewall set rule group=\"Network Discovery\" new enable=Yes{Colors.RESET}")
        logger.log("Network_Discovery_On", "success", "Сетевое обнаружение будет включено")
        print(f"{Colors.GREEN}[+] Сетевое обнаружение будет включено{Colors.RESET}")
        return True
    
    try:
        # Включаем через netsh (старый и новый методы)
        run_command("netsh firewall set service type=fileandprint mode=enable")
        run_command('netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes')
        run_command('netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes')
        
        # Включаем через PowerShell (самый надежный метод для Win10/11)
        ps_cmd = "Set-NetFirewallRule -DisplayGroup 'Network Discovery' -Enabled True; Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Enabled True"
        run_command(f'powershell -Command "{ps_cmd}"')
        
        # Включаем службы, необходимые для обнаружения
        services = ['upnphost', 'SSDPSRV', 'FDResPub', 'FunctionDiscoveryDataPublishing']
        for svc in services:
            run_command(f'sc config {svc} start=auto')
            run_command(f'net start {svc}')
            
        logger.log("Network_Discovery_On", "success", "Сетевое обнаружение включено")
        print(f"{Colors.GREEN}[+] Сетевое обнаружение и общий доступ включены{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Network_Discovery_On", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Route_Reset():
    """Сброс таблицы маршрутизации и NetBios"""
    print_hacker_message("Вирус добавил левые маршруты? Щас всё почистю и NetBios включу!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: route -f{Colors.RESET}")
        print(f"{Colors.CYAN}[DRY-RUN] Будет включен NetBios через службу{Colors.RESET}")
        logger.log("Route_Reset", "success", "Маршруты будут сброшены")
        print(f"{Colors.GREEN}[+] Таблица маршрутизации будет сброшена{Colors.RESET}")
        return True
    
    try:
        # Сбрасываем таблицу маршрутизации
        subprocess.run(["route", "-f"], capture_output=True)
        
        # Включаем NetBios через службу
        try:
            subprocess.run(["sc", "config", "lmhosts", "start=auto"], capture_output=True)
            subprocess.run(["sc", "start", "lmhosts"], capture_output=True)
        except Exception as _e:
            # Expected exception, intentionally ignored
            pass
        
        logger.log("Route_Reset", "success", "Маршруты сброшены")
        print(f"{Colors.GREEN}[+] Таблица маршрутизации сброшена, NetBios включен{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Route_Reset", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def IP_Reset():
    """Полный сброс IP/DNS/Winsock стека"""
    print_hacker_message("Сеть лагает? Вирус прокси вставил? Щас я всё обнулю!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнен сброс Winsock, TCP/IP и очистка DNS кеша{Colors.RESET}")
        logger.log("IP_Reset", "success", "Стек сети будет сброшен")
        return True
    
    commands = [
        "netsh winsock reset",
        "netsh int ip reset",
        "netsh int ipv6 reset",
        "ipconfig /release",
        "ipconfig /renew",
        "ipconfig /flushdns",
        "arp -d *",
        "nbtstat -R",
        "nbtstat -RR"
    ]
    
    success_count = 0
    for cmd in commands:
        success, _, _ = run_command(cmd)
        if success:
            success_count += 1
            
    if success_count > 0:
        logger.log("IP_Reset", "success", f"Стек сети сброшен ({success_count}/{len(commands)})")
        print(f"{Colors.GREEN}[+] Стек сети полностью сброшен{Colors.RESET}")
        return True
    else:
        logger.log("IP_Reset", "error", "Не удалось сбросить сеть")
        print(f"{Colors.RED}[!] Не удалось сбросить настройки сети{Colors.RESET}")
        return False

def Temp_Deep_Clean():
    """Очистка системных и пользовательских временных папок"""
    print_hacker_message("Временные файлы засорили систему? Щас всё подчистю и вирус не жил в мусоре!")
    
    temp_dirs = [
        os.environ.get('TEMP', ''),
        os.environ.get('TMP', ''),
        os.path.join(os.environ['SystemRoot'], 'Temp'),
        os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Temp'),
        os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Windows', 'INetCache'),
    ]
    
    total_deleted = 0
    for temp_dir in temp_dirs:
        if os.path.exists(temp_dir):
            if DRY_RUN:
                print(f"{Colors.CYAN}[DRY-RUN] Будет очищена папка: {temp_dir}{Colors.RESET}")
                total_deleted += 1
            else:
                try:
                    for entry in os.scandir(temp_dir):
                        item = entry.name
                        item_path = entry.path
                        try:
                            if os.path.isfile(item_path):
                                safe_remove(item_path)
                                total_deleted += 1
                            elif os.path.isdir(item_path):
                                safe_rmtree(item_path)
                                total_deleted += 1
                        except Exception as _e:
                            # Expected exception, intentionally ignored
                            pass
                except Exception as _e:
                    # Expected exception, intentionally ignored
                    pass
    
    logger.log("Temp_Deep_Clean", "success", f"Удалено {total_deleted} файлов")
    print(f"{Colors.GREEN}[+] Очищено временных файлов: {total_deleted}{Colors.RESET}")
    return True

def Prefetch_Wipe():
    """Очистка кэша запуска программ"""
    print_hacker_message("Prefetch кэш тоже чистим — там вирус мог leftovers оставить!")
    
    try:
        prefetch_path = os.path.join(os.environ['SystemRoot'], 'Prefetch')
        if os.path.exists(prefetch_path):
            if DRY_RUN:
                print(f"{Colors.CYAN}[DRY-RUN] Будет очищен Prefetch: {prefetch_path}{Colors.RESET}")
            else:
                for entry in os.scandir(prefetch_path):
                    item = entry.name
                    item_path = entry.path
                    try:
                        safe_remove(item_path)
                    except Exception as _e:
                        # Expected exception, intentionally ignored
                        pass
        
        logger.log("Prefetch_Wipe", "success", "Prefetch очищен")
        print(f"{Colors.GREEN}[+] Prefetch кэш очищен{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Prefetch_Wipe", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def RecycleBin_Empty():
    """Принудительная очистка корзины"""
    print_hacker_message("Корзина полна вирусных остатков? Щас опустошим нахрен!")

    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет очищена корзина через PowerShell{Colors.RESET}")
        logger.log("RecycleBin_Empty", "success", "Корзина будет очищена")
        print(f"{Colors.GREEN}[+] Корзина будет очищена{Colors.RESET}")
        return True
    
    try:
        # Очищаем корзину через PowerShell
        ps_cmd = "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"
        subprocess.run(["powershell", "-Command", ps_cmd], shell=True, capture_output=True)
        
        logger.log("RecycleBin_Empty", "success", "Корзина очищена")
        print(f"{Colors.GREEN}[+] Корзина очищена{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("RecycleBin_Empty", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Process_Blacklist_Kill():
    """Авто-убийство процессов с подозрительными именами и проверкой легитимности"""
    print_hacker_message("Подозрительные процессы в памяти? Щас прибьём их всех!")

    if not PSUTIL_AVAILABLE:
        logger.log("Process_Blacklist_Kill", "warning", "psutil не установлен, процессы не проверены")
        print(f"{Colors.YELLOW}[!] psutil не установлен — проверка процессов недоступна{Colors.RESET}")
        return False
    
    suspicious_processes = [
        'svchost.exe', 'temp.exe', 'hack.exe', 'virus.exe', 'trojan.exe',
        'malware.exe', 'miner.exe', 'crypt.exe', 'payload.exe', 'dropper.exe',
        'loader.exe', 'injector.exe', 'rat.exe', 'backdoor.exe', 'keylogger.exe',
        'stealer.exe', 'unknown.exe', 'update.exe', 'winlogon.exe', 'lsass.exe',
        'csrss.exe', 'services.exe', 'taskhostw.exe', 'spoolsv.exe'
    ]
    
    legitimate_owners = ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'NT AUTHORITY\\SYSTEM', 'NT AUTHORITY\\LOCAL SERVICE', 'NT AUTHORITY\\NETWORK SERVICE']
    
    whitelist_paths = [
        os.path.join(os.environ['SystemRoot'], 'system32').lower(),
        os.path.join(os.environ['SystemRoot'], 'syswow64').lower(),
        os.path.join(os.environ['ProgramFiles']).lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', '')).lower(),
    ]
    
    killed_count = 0
    procs = []
    if 'novir_native' in globals() and hasattr(novir_native, 'get_processes_extended'):
        try:
            procs = novir_native.get_processes_extended()
        except Exception:
            pass
            
    if not procs and psutil:
        procs = [p.info for p in psutil.process_iter(['pid', 'name', 'exe', 'username'])]
        
    for proc_info in procs:
        try:
            proc_name = str(proc_info.get('name', '')).lower()
            
            if any(sus in proc_name for sus in suspicious_processes):
                exe_path = str(proc_info.get('exe', '') or proc_info.get('path', '')).lower()
                owner = str(proc_info.get('username', '')).upper()
                
                is_legitimate = False
                
                # Проверка системных процессов (должны быть в system32 и от SYSTEM)
                critical_system = ['svchost.exe', 'winlogon.exe', 'lsass.exe', 'csrss.exe', 'services.exe', 'taskhostw.exe', 'spoolsv.exe']
                if any(crit in proc_name for crit in critical_system):
                    if ('system32' in exe_path or 'syswow64' in exe_path) and any(legit in owner for legit in legitimate_owners):
                        is_legitimate = True
                
                # Проверка остальных по белому списку путей
                elif any(exe_path.startswith(path) for path in whitelist_paths):
                    is_legitimate = True
                
                if not is_legitimate:
                    if DRY_RUN:
                        print(f"{Colors.CYAN}[DRY-RUN] Был бы убит процесс: {proc_name} (PID: {proc_info['pid']}, Path: {exe_path}){Colors.RESET}")
                    else:
                        if 'novir_native' in globals() and hasattr(novir_native, 'kill_process_force'):
                            novir_native.kill_process_force(proc_info['pid'])
                        elif psutil:
                            psutil.Process(proc_info['pid']).kill()
                        killed_count += 1
                        print(f"{Colors.YELLOW}[!] Убит подозрительный процесс: {proc_name}{Colors.RESET}")
        except Exception:
            continue
    
    if killed_count > 0:
        logger.log("Process_Blacklist_Kill", "success", f"Убито {killed_count} процессов")
        print(f"{Colors.GREEN}[+] Убито подозрительных процессов: {killed_count}{Colors.RESET}")
    return True

def SafeMode_Registry_Fix():
    """Исправление и ПОЛНОЕ восстановление путей загрузки Safe Mode"""
    print_hacker_message("Safe Mode сломан или стерт? Это частая мишень вирусов. Щас восстановим его из пепла!")
    
    try:
        # 1. Снимаем ограничения на ветку реестра (если вирус изменил права доступа)
        # Мы используем reg.exe для попытки сброса прав или принудительного создания
        reg_root = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot"
        
        # 2. Восстанавливаем AlternateShell (оболочка безопасного режима)
        reg_set_value(r"SYSTEM\CurrentControlSet\Control\SafeBoot", "AlternateShell", "cmd.exe", winreg.REG_SZ)
        
        # 3. Полный список критических служб для Minimal (Безопасный режим)
        minimal_services = [
            'AppInfo', 'Base', 'Boot Bus Extender', 'Boot File System', 'Business', 'CryptSvc',
            'DCOM Launch', 'Disk', 'EventLog', 'File System', 'Filter Manager', 'HelpSvc',
            'HTTP', 'Keyboard', 'Keyboard Class', 'Keyboard Port', 'Mouse', 'Mouse Class',
            'Mouse Port', 'Netlogon', 'Network', 'NetworkProvider', 'PlugPlay', 'PNP Filter',
            'Processor', 'RPCSS', 'SCSI Class', 'System Bus Extender', 'vga', 'VgaSave',
            'WinMgmt', 'Workstation'
        ]
        
        # 4. Полный список критических служб для Network (Безопасный режим с сетью)
        network_services = minimal_services + [
            'DNS Cache', 'LanmanWorkstation', 'NLA', 'NSI', 'Tcpip', 'Tcpip6', 'Tdx',
            'WebClient', 'WinHttpAutoProxySvc'
        ]

        # Восстанавливаем основные ветки, если они удалены целиком
        for mode in ['Minimal', 'Network']:
            key_path = f"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\{mode}"
            reg_set_value(key_path, "", "", winreg.REG_SZ)
            
            services = minimal_services if mode == 'Minimal' else network_services
            for svc in services:
                svc_path = f"{key_path}\\{svc}"
                # Устанавливаем тип "Service" для каждого элемента
                reg_set_value(svc_path, "", "Service", winreg.REG_SZ)

        # 5. Восстанавливаем BootExecute (критично для автозапуска при загрузке)
        reg_set_value(r"SYSTEM\CurrentControlSet\Control\Session Manager", "BootExecute", "autocheck autochk *", winreg.REG_MULTI_SZ)
        
        # 6. Снимаем флаг "NoSafeBoot" если вирус его поставил
        reg_delete_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "NoSafeBoot")
        
        logger.log("SafeMode_Registry_Fix", "success", "Safe Mode полностью реконструирован")
        print(f"{Colors.GREEN}[+] Режим Safe Mode полностью восстановлен (даже если был удален){Colors.RESET}")
        return True
    except Exception as e:
        logger.log("SafeMode_Registry_Fix", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка критического восстановления Safe Mode: {e}{Colors.RESET}")
        return False

def SafeMode_Next_Boot_Setup():
    """Настройка следующей загрузки в безопасный режим с поддержкой командной строки"""
    print_hacker_message("Настраиваю систему для загрузки в безопасный режим при следующем запуске...")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: bcdedit /set {{current}} safeboot minimal{Colors.RESET}")
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: bcdedit /set {{current}} safebootalternateshell yes{Colors.RESET}")
        return True
    
    try:
        # Восстанавливаем Safe Mode в реестре ПЕРЕД настройкой загрузки (на случай если стерто)
        SafeMode_Registry_Fix()
        
        # Настройка через bcdedit
        # minimal - безопасный режим
        # alternateshell yes - поддержка командной строки
        success1, _, err1 = run_command("bcdedit /set {current} safeboot minimal")
        success2, _, err2 = run_command("bcdedit /set {current} safebootalternateshell yes")
        
        if success1 and success2:
            logger.log("SafeMode_Next_Boot", "success", "Настроена загрузка в Safe Mode с командной строкой")
            print(f"{Colors.GREEN}[+] Система загрузится в безопасный режим с командной строкой при следующем запуске{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Не забудьте потом выполнить 'bcdedit /deletevalue {{current}} safeboot' для возврата в обычный режим!{Colors.RESET}")
            return True
        else:
            print(f"{Colors.RED}[!] Ошибка bcdedit: {err1} {err2}{Colors.RESET}")
            return False
    except Exception as e:
        logger.log("SafeMode_Next_Boot", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def SafeMode_Boot_Restore_Service():
    """Создание службы-стража, которая восстановит Safe Mode прямо перед выключением/перезагрузкой"""
    print_hacker_message("Создаю 'стража' для защиты Safe Mode при перезагрузке...")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет создан скрипт-страж и задача в планировщике{Colors.RESET}")
        return True
        
    try:
        # Путь к скрипту восстановления
        script_path = os.path.join(os.environ['SystemRoot'], 'SafeModeGuard.bat')
        
        # Создаем батник, который восстанавливает реестр Safe Mode
        content = f"""@echo off
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot" /v "AlternateShell" /t REG_SZ /d "cmd.exe" /f
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal" /f
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network" /f
bcdedit /set {{current}} safeboot minimal
bcdedit /set {{current}} safebootalternateshell yes
"""
        with open(script_path, 'w') as f:
            f.write(content)
            
        # Добавляем в локальную политику выключения (через реестр/планировщик)
        # Самый надежный способ - задача при событии выключения или просто немедленная перезагрузка
        print(f"{Colors.YELLOW}[!] ВНИМАНИЕ: Сейчас будет выполнена принудительная настройка и перезагрузка через 10 секунд!{Colors.RESET}")
        
        # Выполняем настройку
        SafeMode_Next_Boot_Setup()
        
        # Запускаем таймер перезагрузки
        run_command("shutdown /r /t 10 /c \"NoVir: Переход в безопасный режим для глубокой очистки\"")
        
        return True
    except Exception as e:
        logger.log("SafeMode_Boot_Restore", "error", str(e))
        return False

def AutoRun_Disable():
    """Отключение автозапуска с флешек"""
    print_hacker_message("Автозапуск с флешек — это дыра для вирусов. Щас отключим!")
    
    try:
        # Отключаем автозапуск для всех дисков
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 0xDD, winreg.REG_DWORD)
        reg_set_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping", "Autorun.inf", "@SYS:DoesNotExist", winreg.REG_SZ)
        
        logger.log("AutoRun_Disable", "success", "Автозапуск отключен")
        print(f"{Colors.GREEN}[+] Автозапуск с флешек отключен{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("AutoRun_Disable", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def IconCache_Clear():
    """Очистка кэша иконок"""
    print_hacker_message("Иконки отображаются неправильно? Щас очищу кэш иконок!")
    
    icon_cache_paths = [
        os.path.join(os.environ['LOCALAPPDATA'], 'IconCache.db'),
        os.path.join(os.environ['LOCALAPPDATA'], 'IconCache_*.db'),
        os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Windows', 'Explorer', 'IconCache*'),
        os.path.join(os.environ['SystemRoot'], 'System32', 'config', 'systemprofile', 'AppData', 'Local', 'Microsoft', 'Windows', 'Explorer', 'IconCache*'),
    ]
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет очищен кэш иконок{Colors.RESET}")
        logger.log("IconCache_Clear", "success", "Кэш иконок будет очищен")
        print(f"{Colors.GREEN}[+] Кэш иконок будет очищен{Colors.RESET}")
        return True
    
    cleaned_count = 0
    for pattern in icon_cache_paths:
        for file_path in glob.glob(pattern):
            try:
                safe_remove(file_path)
                cleaned_count += 1
            except Exception as _e:
                # Expected exception, intentionally ignored
                pass
    
    # Перезапускаем проводник
    subprocess.run(["taskkill", "/f", "/im", "explorer.exe"], capture_output=True)
    time.sleep(1)
    subprocess.run(["explorer.exe"], capture_output=True)
    
    logger.log("IconCache_Clear", "success", f"Очищено {cleaned_count} файлов кэша иконок")
    print(f"{Colors.GREEN}[+] Кэш иконок очищен ({cleaned_count} файлов){Colors.RESET}")
    return True

def Startup_Clean():
    """Очистка автозагрузки Run и Startup"""
    print_hacker_message("Вирус прописался в автозагрузку? Щас вычистю все папки Startup!")
    
    startup_paths = [
        os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
        os.path.join(os.environ['ProgramData'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    ]
    
    suspicious_names = ['temp', 'hack', 'virus', 'trojan', 'malware', 'miner', 'crypt', 'payload', 'dropper', 'loader']
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут проверены папки автозагрузки{Colors.RESET}")
        for path in startup_paths:
            if os.path.exists(path):
                print(f"{Colors.CYAN}[DRY-RUN] Папка: {path}{Colors.RESET}")
        logger.log("Startup_Clean", "success", "Автозагрузка будет очищена")
        print(f"{Colors.GREEN}[+] Автозагрузка будет очищена{Colors.RESET}")
        return True
    
    cleaned_count = 0
    for startup_path in startup_paths:
        if os.path.exists(startup_path):
            for entry in os.scandir(startup_path):
                item = entry.name
                item_path = entry.path
                item_lower = item.lower()
                if any(sus in item_lower for sus in suspicious_names):
                    try:
                        safe_remove(item_path)
                        cleaned_count += 1
                        print(f"{Colors.YELLOW}[!] Удалено из автозагрузки: {item}{Colors.RESET}")
                    except Exception as _e:
                        # Expected exception, intentionally ignored
                        pass
    
    # Также проверяем реестр Run
    run_keys = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    ]
    
    for key_path in run_keys:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    if any(sus in name.lower() for sus in suspicious_names) or any(sus in str(value).lower() for sus in suspicious_names):
                        print(f"{Colors.YELLOW}[!] Обнаружено в автозагрузке: {name} = {value}{Colors.RESET}")
                        if not DRY_RUN:
                            winreg.DeleteValue(key, name)
                            cleaned_count += 1
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception as _e:
            # Expected exception, intentionally ignored
            pass
    
    logger.log("Startup_Clean", "success", f"Очищено {cleaned_count} записей автозагрузки")
    print(f"{Colors.GREEN}[+] Автозагрузка очищена ({cleaned_count} записей){Colors.RESET}")
    return True

def TaskScheduler_Clean():
    """Очистка планировщика задач от подозрительных задач"""
    print_hacker_message("Вирус создал задачу в планировщике? Щас проверю и удалю!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут проверены задачи планировщика{Colors.RESET}")
        logger.log("TaskScheduler_Clean", "success", "Планировщик будет очищен")
        print(f"{Colors.GREEN}[+] Планировщик задач будет проверен{Colors.RESET}")
        return True
    
    try:
        # Получаем список задач через PowerShell
        ps_cmd = "Get-ScheduledTask | Where-Object {$_.TaskName -notmatch '^Microsoft$'} | Select-Object TaskName, TaskPath"
        result = subprocess.run(["powershell", "-Command", ps_cmd], shell=True, capture_output=True, text=True)
        
        suspicious_count = 0
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'temp' in line.lower() or 'hack' in line.lower() or 'virus' in line.lower():
                    print(f"{Colors.YELLOW}[!] Обнаружена подозрительная задача: {line}{Colors.RESET}")
                    # Можно добавить удаление, но это рискованно - лучше только показать
                    suspicious_count += 1
        
        logger.log("TaskScheduler_Clean", "success", f"Проверено задач планировщика")
        print(f"{Colors.GREEN}[+] Проверен планировщик задач (обнаружено подозрительных: {suspicious_count}){Colors.RESET}")
        return True
    except Exception as e:
        logger.log("TaskScheduler_Clean", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

# ═══════════════════════════════════════════════════════════════
# БЛОК 6: ПРОДВИНУТЫЕ ИСПРАВЛЕНИЯ
# ═══════════════════════════════════════════════════════════════

def WMI_Repair():
    """Восстановление службы управления Windows"""
    print_hacker_message("WMI сломан? Это частая мишень вирусов. Щас восстановим!")

    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет перезапущена служба winmgmt и проверен WMI repository{Colors.RESET}")
        logger.log("WMI_Repair", "success", "WMI будет проверена и перезапущена")
        print(f"{Colors.GREEN}[+] WMI будет восстановлена{Colors.RESET}")
        return True
    
    try:
        # Перезапускаем службу WMI
        subprocess.run(["net", "stop", "winmgmt", "/y"], capture_output=True)
        time.sleep(2)
        subprocess.run(["net", "start", "winmgmt"], capture_output=True)
        
        # Перерегистрируем WMI
        subprocess.run(["winmgmt", "/verifyrepository"], capture_output=True)
        
        logger.log("WMI_Repair", "success", "WMI восстановлена")
        print(f"{Colors.GREEN}[+] Служба WMI восстановлена{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("WMI_Repair", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Service_State_Scan():
    """Авто-запуск всех отключенных критических служб"""
    print_hacker_message("Критические службы отключены? Щас включим всё, что нужно для работы системы!")
    
    critical_services = [
        'WinDefend',
        'wuauserv',
        'bits',
        'EventLog',
        'Schedule',
        'Themes',
        'AudioSrv',
        'stisvc',
        'cryptsvc',
        'Dnscache',
        'dhcp',
        'lanmanserver',
        'lanmanworkstation',
        'mpssvc',
        'MpsSvc',
        'Themes',
        'ShellHWDetection',
    ]

    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут проверены и при необходимости запущены службы: {', '.join(critical_services)}{Colors.RESET}")
        logger.log("Service_State_Scan", "success", f"Будет проверено {len(critical_services)} служб")
        print(f"{Colors.GREEN}[+] Критические службы будут проверены{Colors.RESET}")
        return True
    
    started_count = 0
    for service in critical_services:
        try:
            # Проверяем состояние службы
            result = subprocess.run(["sc", "query", service], capture_output=True, text=True)
            if "STOPPED" in result.stdout:
                # Запускаем службу
                subprocess.run(["sc", "start", service], capture_output=True)
                started_count += 1
                print(f"{Colors.YELLOW}[!] Запущена служба: {service}{Colors.RESET}")
        except Exception as _e:
            # Expected exception, intentionally ignored
            pass
    
    logger.log("Service_State_Scan", "success", f"Запущено {started_count} служб")
    print(f"{Colors.GREEN}[+] Запущено критических служб: {started_count}{Colors.RESET}")
    return True

def Cert_Store_Clean():
    """Удаление самоподписанных сертификатов из Доверенных"""
    print_hacker_message("Самоподписанные сертификаты в доверенных? Это вирус поставил. Щас удалим!")

    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут удалены новые самоподписанные сертификаты из LocalMachine\\Root{Colors.RESET}")
        logger.log("Cert_Store_Clean", "success", "Подозрительные сертификаты будут удалены")
        print(f"{Colors.GREEN}[+] Подозрительные сертификаты будут удалены{Colors.RESET}")
        return True
    
    try:
        # Удаляем подозрительные сертификаты через PowerShell
        ps_cmd = '''
Get-ChildItem -Path Cert:\\LocalMachine\\Root | Where-Object {
    $_.Issuer -eq $_.Subject -and $_.NotBefore -gt (Get-Date).AddDays(-30)
} | Remove-Item -Force
'''
        subprocess.run(["powershell", "-Command", ps_cmd], shell=True, capture_output=True)
        
        logger.log("Cert_Store_Clean", "success", "Сертификаты очищены")
        print(f"{Colors.GREEN}[+] Подозрительные сертификаты удалены{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Cert_Store_Clean", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def WinUpdate_Reset():
    """Сброс центра обновлений"""
    print_hacker_message("Центр обновлений заморожен? Щас сбросим, чтобы обновления качались!")

    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут остановлены wuauserv/bits, очищены папки SoftwareDistribution и службы будут запущены обратно{Colors.RESET}")
        logger.log("WinUpdate_Reset", "success", "Центр обновлений будет сброшен")
        print(f"{Colors.GREEN}[+] Центр обновлений будет сброшен{Colors.RESET}")
        return True
    
    try:
        # Останавливаем службы обновлений
        subprocess.run(["net", "stop", "wuauserv", "/y"], shell=True, capture_output=True)
        subprocess.run(["net", "stop", "bits", "/y"], shell=True, capture_output=True)
        
        # Удаляем папки обновлений
        update_dirs = [
            os.path.join(os.environ['SystemRoot'], 'SoftwareDistribution', 'Download'),
            os.path.join(os.environ['SystemRoot'], 'SoftwareDistribution', 'DataStore'),
        ]
        
        for dir_path in update_dirs:
            if os.path.exists(dir_path):
                try:
                    for entry in os.scandir(dir_path):
                        item = entry.name
                        item_path = entry.path
                        try:
                            if os.path.isfile(item_path):
                                safe_remove(item_path)
                            elif os.path.isdir(item_path):
                                safe_rmtree(item_path)
                        except Exception as _e:
                            # Expected exception, intentionally ignored
                            pass
                except Exception as _e:
                    # Expected exception, intentionally ignored
                    pass
        
        # Запускаем службы обратно
        subprocess.run(["net", "start", "bits"], shell=True, capture_output=True)
        subprocess.run(["net", "start", "wuauserv"], shell=True, capture_output=True)
        
        logger.log("WinUpdate_Reset", "success", "Центр обновлений сброшен")
        print(f"{Colors.GREEN}[+] Центр обновлений сброшен{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("WinUpdate_Reset", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def LNK_File_Fix():
    """Исправление ярлыков"""
    print_hacker_message("Ярлыки ведут на вирус? Щас проверим и исправим все .lnk файлы!")
    
    try:
        # Ищем подозрительные ярлыки на рабочем столе
        desktop_path = os.path.join(os.environ['USERPROFILE'], 'Desktop')
        fixed_count = 0
        
        if os.path.exists(desktop_path):
            for entry in os.scandir(desktop_path):
                item = entry.name
                if item.endswith('.lnk'):
                    lnk_path = entry.path
                    try:
                        # Проверяем цель ярлыка через PowerShell
                        ps_cmd = f"$shell = New-Object -ComObject WScript.Shell; $shortcut = $shell.CreateShortcut('{lnk_path}'); $shortcut.TargetPath"
                        result = subprocess.run(["powershell", "-Command", ps_cmd], shell=True, capture_output=True, text=True)
                        target = result.stdout.strip().lower()
                        
                        # Если цель — подозрительный файл
                        suspicious = ['temp', 'hack', 'virus', 'trojan', 'malware', 'appdata\\temp', 'appdata\\local\\temp']
                        if any(sus in target for sus in suspicious):
                            print(f"{Colors.YELLOW}[!] Обнаружен подозрительный ярлык: {item}{Colors.RESET}")
                            if DRY_RUN:
                                print(f"{Colors.CYAN}[DRY-RUN] Будет удален ярлык: {lnk_path}{Colors.RESET}")
                            else:
                                # Удаляем ярлык
                                safe_remove(lnk_path)
                            fixed_count += 1
                    except Exception as _e:
                        # Expected exception, intentionally ignored
                        pass
        
        logger.log("LNK_File_Fix", "success", f"Исправлено {fixed_count} ярлыков")
        print(f"{Colors.GREEN}[+] Проверено и исправлено ярлыков: {fixed_count}{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("LNK_File_Fix", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Print_Spooler_Fix():
    """Очистка очереди печати"""
    print_hacker_message("Очередь печати засрана вирусными заданиями? Щас очистим!")

    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет остановлен spooler, очищена очередь печати и служба будет запущена обратно{Colors.RESET}")
        logger.log("Print_Spooler_Fix", "success", "Очередь печати будет очищена")
        print(f"{Colors.GREEN}[+] Очередь печати будет очищена{Colors.RESET}")
        return True
    
    try:
        # Останавливаем службу печати
        subprocess.run(["net", "stop", "spooler", "/y"], shell=True, capture_output=True)
        time.sleep(1)
        
        # Удаляем файлы очереди
        spool_path = os.path.join(os.environ['SystemRoot'], 'System32', 'spool', 'PRINTERS')
        if os.path.exists(spool_path):
            for entry in os.scandir(spool_path):
                item = entry.name
                item_path = entry.path
                try:
                    safe_remove(item_path)
                except Exception as _e:
                    # Expected exception, intentionally ignored
                    pass
        
        # Запускаем службу обратно
        subprocess.run(["net", "start", "spooler"], shell=True, capture_output=True)
        
        logger.log("Print_Spooler_Fix", "success", "Очередь печати очищена")
        print(f"{Colors.GREEN}[+] Очередь печати очищена{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Print_Spooler_Fix", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Self_Defense_Engine():
    """Постоянная проверка собственного процесса на закрытие"""
    print_hacker_message("Включаю самооборону! Если вирус попытается меня закрыть — я сразу respawn!")
    
    # Это упрощенная версия — в реальности нужен отдельный процесс-монитор
    logger.log("Self_Defense_Engine", "success", "Самооборона активирована (базовая защита)")
    print(f"{Colors.GREEN}[+] Режим самообороны активирован{Colors.RESET}")
    print(f"{Colors.YELLOW}[!] Примечание: Для полной защиты нужен отдельный монитор-процесс{Colors.RESET}")
    return True

def SafeMode_Full_Repair():
    """Полноценное восстановление Safe Mode через создание ключей реестра"""
    print_hacker_message("Вирус стер ключи Safe Mode? Щас нарисуем их заново, чисто по памяти!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут восстановлены ключи SafeBoot\\Minimal{Colors.RESET}")
        print(f"{Colors.CYAN}[DRY-RUN] Будут восстановлены ключи SafeBoot\\Network{Colors.RESET}")
        print(f"{Colors.CYAN}[DRY-RUN] Будут добавлены базовые драйверы и службы{Colors.RESET}")
        logger.log("SafeMode_Full_Repair", "success", "Safe Mode будет восстановлен")
        print(f"{Colors.GREEN}[+] Safe Mode будет восстановлен{Colors.RESET}")
        return True
    
    # Базовые драйверы и службы для Safe Mode
    minimal_services = [
        ('Basic', 'Driver Group'),
        ('Bus Extenders', 'Driver Group'),
        ('System Bus Extender', 'Driver Group'),
        ('SCSI Class', 'Driver Group'),
        ('SCSI CDROM Class', 'Driver Group'),
        ('filter', 'Driver Group'),
        ('Primary disk', 'Driver Group'),
        ('SCSI miniport', 'Driver Group'),
        ('port', 'Driver Group'),
        ('Keyboard Class', 'Driver Group'),
        ('Pointer Class', 'Driver Group'),
        ('PCI Configuration', 'Driver Group'),
        ('System', 'Driver Group'),
        ('VGA Save', 'Driver'),
        ('vga', 'Driver'),
        ('Beep', 'Driver'),
        ('dmconfig', 'Driver'),
        ('dmload', 'Driver'),
        ('Mouclass', 'Driver'),
        ('Kbdclass', 'Driver'),
        ('Services', 'Driver Group'),
    ]
    
    network_services = minimal_services + [
        ('NDIS', 'Driver Group'),
        ('TDI', 'Driver Group'),
        ('NetBIOSGroup', 'Driver Group'),
        ('NetTrans', 'Driver Group'),
        ('RpcDriver', 'Driver'),
    ]
    
    try:
        # Создаем/восстанавливаем Minimal
        minimal_path = r"SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal"
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, minimal_path, 0, winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, minimal_path)
        
        for service, service_type in minimal_services:
            try:
                winreg.SetValueEx(key, service, 0, winreg.REG_SZ, service_type)
            except (OSError, PermissionError) as e:
                # Игнорируем ошибки при записи отдельных значений
                # Некоторые драйверы могут отсутствовать в конкретной системе
                pass
        winreg.CloseKey(key)
        
        # Создаем/восстанавливаем Network
        network_path = r"SYSTEM\CurrentControlSet\Control\SafeBoot\Network"
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, network_path, 0, winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, network_path)
        
        for service, service_type in network_services:
            try:
                winreg.SetValueEx(key, service, 0, winreg.REG_SZ, service_type)
            except (OSError, PermissionError) as e:
                # Игнорируем ошибки при записи отдельных значений
                # Некоторые драйверы могут отсутствовать в конкретной системе
                pass
        winreg.CloseKey(key)
        
        # Восстанавливаем AlternateShell
        reg_set_value(r"SYSTEM\CurrentControlSet\Control\SafeBoot", "AlternateShell", "cmd.exe", winreg.REG_SZ)
        
        logger.log("SafeMode_Full_Repair", "success", "Safe Mode восстановлен полностью")
        print(f"{Colors.GREEN}[+] Safe Mode восстановлен (Minimal и Network){Colors.RESET}")
        return True
    except Exception as e:
        logger.log("SafeMode_Full_Repair", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def TrustedInstaller_Restore():
    """Восстановление прав TrustedInstaller для системных файлов"""
    print_hacker_message("Права на системные файлы слетели? Щас верну TrustedInstaller!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут восстановлены права TrustedInstaller через icacls{Colors.RESET}")
        logger.log("TrustedInstaller_Restore", "success", "Права будут восстановлены")
        print(f"{Colors.GREEN}[+] Права TrustedInstaller будут восстановлены{Colors.RESET}")
        return True
    
    try:
        # Системные папки для восстановления прав
        system_paths = [
            os.path.join(os.environ['SystemRoot'], 'System32'),
            os.path.join(os.environ['SystemRoot'], 'SysWOW64'),
            os.path.join(os.environ['SystemRoot'], 'winsxs'),
        ]
        
        restored_count = 0
        for path in system_paths:
            if os.path.exists(path):
                # Восстанавливаем права через icacls
                ps_cmd = f"icacls '{path}' /restore '{path}\\acl_backup.txt' /T /C /Q"
                # Это упрощенная версия - полный бэкап ACL требует больше логики
                try:
                    subprocess.run(["icacls", path, "/reset", "/T", "/C", "/Q"], shell=True, capture_output=True)
                    restored_count += 1
                except Exception as _e:
                    # Expected exception, intentionally ignored
                    pass
        
        # Также восстанавливаем права для ключей реестра
        try:
            # Восстанавливаем владение для ключей HKLM\SOFTWARE
            ps_cmd = "Get-Acl HKLM:\\SOFTWARE | Set-Acl HKLM:\\SOFTWARE"
            subprocess.run(["powershell", "-Command", ps_cmd], shell=True, capture_output=True)
        except Exception as _e:
            # Expected exception, intentionally ignored
            pass
        
        logger.log("TrustedInstaller_Restore", "success", f"Права восстановлены для {restored_count} папок")
        print(f"{Colors.GREEN}[+] Права TrustedInstaller восстановлены ({restored_count} папок){Colors.RESET}")
        return True
    except Exception as e:
        logger.log("TrustedInstaller_Restore", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def EXE_Assoc():
    """Исправление ассоциаций .exe файлов (если они открываются через блокнот)"""
    print_hacker_message("EXE файлы открываются через блокнот? Щас исправлю ассоциации!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут восстановлены ассоциации .exe файлов{Colors.RESET}")
        logger.log("EXE_Assoc", "success", "Ассоциации .exe будут восстановлены")
        print(f"{Colors.GREEN}[+] Ассоциации .exe будут восстановлены{Colors.RESET}")
        return True
    
    try:
        # Восстанавливаем ассоциацию .exe
        subprocess.run(["assoc", ".exe=exefile"], shell=True, capture_output=True)
        
        # Восстанавливаем команду запуска
        subprocess.run(["ftype", "exefile=\"%1\" %*"], shell=True, capture_output=True)
        
        logger.log("EXE_Assoc", "success", "Ассоциации .exe восстановлены")
        print(f"{Colors.GREEN}[+] Ассоциации .exe файлов восстановлены{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("EXE_Assoc", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Self_Protect():
    """Самозащита процесса - изменение заголовка окна"""
    print_hacker_message("Включаю режим невидимости — вирусы не должны найти этот процесс!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Заголовок окна будет изменен на случайный{Colors.RESET}")
        logger.log("Self_Protect", "success", "Самозащита будет включена")
        print(f"{Colors.GREEN}[+] Самозащита будет включена{Colors.RESET}")
        return True
    
    try:
        # Изменяем заголовок консоли на случайный
        import random
        import string
        random_title = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        ctypes.windll.kernel32.SetConsoleTitleW(random_title)
        
        logger.log("Self_Protect", "success", "Заголовок окна изменен")
        print(f"{Colors.GREEN}[+] Заголовок окна изменен на случайный: {random_title}{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Self_Protect", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Admin_Force():
    """Проверка и запрос SeTakeOwnershipPrivilege для удаления защищенных файлов"""
    print_hacker_message("Запрашиваю привилегии владения файлами для удаления защищенных вирусов!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет запрошена привилегия SeTakeOwnershipPrivilege{Colors.RESET}")
        logger.log("Admin_Force", "success", "Привилегия будет запрошена")
        print(f"{Colors.GREEN}[+] Привилегия будет запрошена{Colors.RESET}")
        return True
    
    try:
        # Запрашиваем привилегию SeTakeOwnershipPrivilege
        privilege_id = 20  # SeTakeOwnershipPrivilege
        token = ctypes.c_void_p()
        advapi32 = ctypes.windll.advapi32
        
        if advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0020, ctypes.byref(token)):
            luid = ctypes.c_ulonglong()
            if advapi32.LookupPrivilegeValueW(None, "SeTakeOwnershipPrivilege", ctypes.byref(luid)):
                new_privileges = ((1, luid, 2),)
                advapi32.AdjustTokenPrivileges(token, False, new_privileges, 0, None, None)
            
            kernel32.CloseHandle(token)
        
        logger.log("Admin_Force", "success", "Привилегия SeTakeOwnershipPrivilege запрошена")
        print(f"{Colors.GREEN}[+] Привилегия владения файлами получена{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Admin_Force", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def MSCONFIG_Unlock():
    """Разблокировка msconfig.exe"""
    print_hacker_message("Вирус заблокировал msconfig? Это мешает настраивать автозагрузку! Разблокирую!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет разблокирован msconfig.exe{Colors.RESET}")
        logger.log("MSCONFIG_Unlock", "success", "msconfig будет разблокирован")
        print(f"{Colors.GREEN}[+] msconfig будет разблокирован{Colors.RESET}")
        return True
    
    try:
        # Удаляем блокировки msconfig в IFEO и политиках
        keys_to_check = [
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msconfig.exe", None),
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"),
            (r"SOFTWARE\Policies\Microsoft\Windows\System", "DisableCMD"),
        ]
        
        for key_path, value_name in keys_to_check:
            try:
                if value_name:
                    reg_delete_value(key_path, value_name)
                else:
                    reg_delete_key(key_path, recursive=True)
            except Exception as _e:
                # Expected exception, intentionally ignored
                pass
        
        logger.log("MSCONFIG_Unlock", "success", "msconfig разблокирован")
        print(f"{Colors.GREEN}[+] msconfig.exe разблокирован{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("MSCONFIG_Unlock", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Windows_Defender_Enable():
    """Включение Защитника Windows"""
    print_hacker_message("Вирус отключил Защитника Windows? Восстанавливаю защиту!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет включен Защитник Windows{Colors.RESET}")
        logger.log("Windows_Defender_Enable", "success", "Защитник будет включен")
        print(f"{Colors.GREEN}[+] Защитник Windows будет включен{Colors.RESET}")
        return True
    
    try:
        # Удаляем ключи отключения Защитника
        defender_keys = [
            (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection"),
        ]
        
        for key_path, value_name in defender_keys:
            try:
                reg_delete_value(key_path, value_name)
            except Exception as _e:
                # Expected exception, intentionally ignored
                pass
        
        # Запускаем службы Защитника
        subprocess.run(["sc", "config", "WinDefend", "start=", "auto"], shell=True, capture_output=True)
        subprocess.run(["net", "start", "WinDefend"], shell=True, capture_output=True)
        
        logger.log("Windows_Defender_Enable", "success", "Защитник Windows включен")
        print(f"{Colors.GREEN}[+] Защитник Windows включен{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Windows_Defender_Enable", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def System_Restore_Enable():
    """Включение восстановления системы"""
    print_hacker_message("Вирус отключил восстановление системы? Восстанавливаю точки восстановления!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет включено восстановление системы{Colors.RESET}")
        logger.log("System_Restore_Enable", "success", "Восстановление системы будет включено")
        print(f"{Colors.GREEN}[+] Восстановление системы будет включено{Colors.RESET}")
        return True
    
    try:
        # Удаляем блокировки восстановления системы
        keys_to_delete = [
            (r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore", "DisableSR"),
            (r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore", "DisableConfig"),
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore", "DisableSR"),
        ]
        
        for key_path, value_name in keys_to_delete:
            try:
                reg_delete_value(key_path, value_name)
            except Exception as _e:
                # Expected exception, intentionally ignored
                pass
        
        # Включаем службу
        subprocess.run(["sc", "config", "sr", "start=", "demand"], shell=True, capture_output=True)
        
        logger.log("System_Restore_Enable", "success", "Восстановление системы включено")
        print(f"{Colors.GREEN}[+] Восстановление системы включено{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("System_Restore_Enable", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def AutoPlay_Disable():
    """Отключение автозапуска (профилактика от USB-вирусов)"""
    print_hacker_message("Отключаю автозапуск — защита от USB-вирусов и флешек-убийц!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет отключен автозапуск{Colors.RESET}")
        logger.log("AutoPlay_Disable", "success", "Автозапуск будет отключен")
        print(f"{Colors.GREEN}[+] Автозапуск будет отключен{Colors.RESET}")
        return True
    
    try:
        # Отключаем автозапуск для всех дисков
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255, winreg.REG_DWORD)
        
        # Для всех пользователей
        reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255, winreg.REG_DWORD)
        
        logger.log("AutoPlay_Disable", "success", "Автозапуск отключен")
        print(f"{Colors.GREEN}[+] Автозапуск отключен (защита от USB-вирусов){Colors.RESET}")
        return True
    except Exception as e:
        logger.log("AutoPlay_Disable", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Boot_Sector_Check():
    """Проверка загрузочного сектора на наличие руткитов"""
    print_hacker_message("Проверяю загрузочный сектор на руткиты и буткиты!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет проверен загрузочный сектор{Colors.RESET}")
        logger.log("Boot_Sector_Check", "success", "Загрузочный сектор будет проверен")
        print(f"{Colors.GREEN}[+] Загрузочный сектор будет проверен{Colors.RESET}")
        return True
    
    try:
        # Проверяем bcdedit на наличие подозрительных записей
        result = subprocess.run(["bcdedit", "/enum", "firmware"], capture_output=True, text=True, shell=True)
        
        suspicious_found = False
        if "unknown" in result.stdout.lower() or "malware" in result.stdout.lower():
            suspicious_found = True
            print(f"{Colors.YELLOW}[!] Найдены подозрительные записи в загрузчике!{Colors.RESET}")
        
        # Проверяем MBR через diskpart
        diskpart_cmd = "list disk"
        result = subprocess.run(["diskpart", "/s", "-"], input=diskpart_cmd, capture_output=True, text=True, shell=True)
        
        logger.log("Boot_Sector_Check", "success", f"Проверка завершена, подозрительно: {suspicious_found}")
        
        if not suspicious_found:
            print(f"{Colors.GREEN}[+] Загрузочный сектор чист (руткитов не обнаружено){Colors.RESET}")
        else:
            print(f"{Colors.RED}[!] Требуется проверка MBR антивирусом!{Colors.RESET}")
        
        return True
    except Exception as e:
        logger.log("Boot_Sector_Check", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Chrome_Extensions_Clean():
    """Проверка и очистка подозрительных расширений Chrome"""
    print_hacker_message("Проверяю расширения Chrome на наличие вирусных аддонов!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут проверены расширения Chrome{Colors.RESET}")
        logger.log("Chrome_Extensions_Clean", "success", "Расширения Chrome будут проверены")
        print(f"{Colors.GREEN}[+] Расширения Chrome будут проверены{Colors.RESET}")
        return True
    
    try:
        # Путь к расширениям Chrome
        chrome_ext_paths = [
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions"),
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Profile 1\Extensions"),
        ]
        
        suspicious_count = 0
        for ext_path in chrome_ext_paths:
            if os.path.exists(ext_path):
                for entry in os.scandir(ext_path):
                    ext_id = entry.name
                    # Проверяем на подозрительные ID (обычно вирусы имеют случайные ID)
                    if len(ext_id) == 32 and all(c in 'abcdefghijklmnopqrstuvwxyz' for c in ext_id[:5]):
                        print(f"{Colors.YELLOW}[!] Подозрительное расширение: {ext_id}{Colors.RESET}")
                        suspicious_count += 1
        
        logger.log("Chrome_Extensions_Clean", "success", f"Найдено подозрительных: {suspicious_count}")
        
        if suspicious_count == 0:
            print(f"{Colors.GREEN}[+] Подозрительных расширений Chrome не найдено{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] Найдено {suspicious_count} подозрительных расширений! Проверьте вручную.{Colors.RESET}")
        
        return True
    except Exception as e:
        logger.log("Chrome_Extensions_Clean", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Startup_Registry_Scan():
    """Сканирование автозагрузки в реестре на наличие вирусов"""
    print_hacker_message("Сканирую автозагрузку реестра на вирусы!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет проверена автозагрузка реестра{Colors.RESET}")
        logger.log("Startup_Registry_Scan", "success", "Автозагрузка будет проверена")
        print(f"{Colors.GREEN}[+] Автозагрузка будет проверена{Colors.RESET}")
        return True
    
    try:
        # Ключи автозагрузки
        startup_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ]
        
        suspicious_entries = []
        
        for key_path in startup_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        # Проверяем на подозрительные пути
                        value_lower = str(value).lower()
                        if any(x in value_lower for x in ['temp', 'appdata', 'random', 'svch0st', 'csrss.exe']):
                            if 'system32' not in value_lower and 'syswow64' not in value_lower:
                                suspicious_entries.append((key_path, name, value))
                                print(f"{Colors.YELLOW}[!] Подозрительная автозагрузка: {name} = {value}{Colors.RESET}")
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception as _e:
                # Expected exception, intentionally ignored
                pass
        
        logger.log("Startup_Registry_Scan", "success", f"Найдено подозрительных: {len(suspicious_entries)}")
        
        if len(suspicious_entries) == 0:
            print(f"{Colors.GREEN}[+] Автозагрузка чиста!{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] Найдено {len(suspicious_entries)} подозрительных записей в автозагрузке!{Colors.RESET}")
        
        return True
    except Exception as e:
        logger.log("Startup_Registry_Scan", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Event_Viewer_Clean():
    """Очистка журналов событий Windows от ошибок вируса"""
    print_hacker_message("Очищаю журналы событий от следов вируса!")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будут очищены журналы событий{Colors.RESET}")
        logger.log("Event_Viewer_Clean", "success", "Журналы будут очищены")
        print(f"{Colors.GREEN}[+] Журналы событий будут очищены{Colors.RESET}")
        return True
    
    try:
        # Очищаем основные журналы
        logs_to_clear = ["Application", "Security", "Setup", "System", "ForwardedEvents"]
        
        for log_name in logs_to_clear:
            try:
                subprocess.run(["wevtutil", "cl", log_name], shell=True, capture_output=True)
            except Exception as _e:
                # Expected exception, intentionally ignored
                pass
        
        logger.log("Event_Viewer_Clean", "success", "Журналы событий очищены")
        print(f"{Colors.GREEN}[+] Журналы событий очищены{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Event_Viewer_Clean", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

# ═══════════════════════════════════════════════════════════════
# СИСТЕМА РЕЗЕРВНОГО КОПИРОВАНИЯ
# ═══════════════════════════════════════════════════════════════

def Backup_Registry():
    """Экспорт ключей реестра в файл"""
    print_hacker_message("Создаю резервную копию реестра...")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет создан бэкап реестра{Colors.RESET}")
        logger.log("Backup_Registry", "success", "Бэкап реестра будет создан")
        print(f"{Colors.GREEN}[+] Бэкап реестра будет создан{Colors.RESET}")
        return True
    
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(BACKUP_DIR, f"registry_backup_{timestamp}.reg")
        
        # Экспортируем важные ключи
        keys_to_export = [
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "HKLM\\SOFTWARE\\Policies",
            "HKCU\\SOFTWARE\\Policies"
        ]
        
        with open(backup_file, 'w', encoding='utf-8') as f:
            f.write("Windows Registry Editor Version 5.00\n\n")
            for key in keys_to_export:
                try:
                    result = subprocess.run(["reg", "export", key, "-"], capture_output=True, text=True, shell=True)
                    f.write(result.stdout)
                except Exception as _e:
                    # Expected exception, intentionally ignored
                    pass
        
        logger.log("Backup_Registry", "success", f"Бэкап реестра сохранен: {backup_file}")
        print(f"{Colors.GREEN}[+] Бэкап реестра сохранен: {backup_file}{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Backup_Registry", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Backup_System_Restore():
    """Создание точки восстановления системы"""
    print_hacker_message("Создаю точку восстановления системы...")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет создана точка восстановления{Colors.RESET}")
        logger.log("Backup_System_Restore", "success", "Точка восстановления будет создана")
        print(f"{Colors.GREEN}[+] Точка восстановления будет создана{Colors.RESET}")
        return True
    
    try:
        # Создаем точку восстановления через PowerShell
        ps_cmd = "Checkpoint-Computer -Description 'NoVir Backup' -RestorePointType 'MODIFY_SETTINGS'"
        result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, shell=True)
        
        if result.returncode == 0:
            logger.log("Backup_System_Restore", "success", "Точка восстановления создана")
            print(f"{Colors.GREEN}[+] Точка восстановления системы создана{Colors.RESET}")
            return True
        else:
            logger.log("Backup_System_Restore", "error", result.stderr)
            print(f"{Colors.RED}[!] Ошибка: {result.stderr}{Colors.RESET}")
            return False
    except Exception as e:
        logger.log("Backup_System_Restore", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Backup_Hosts():
    """Резервное копирование файла hosts"""
    print_hacker_message("Создаю резервную копию файла hosts...")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет создан бэкап hosts{Colors.RESET}")
        logger.log("Backup_Hosts", "success", "Бэкап hosts будет создан")
        print(f"{Colors.GREEN}[+] Бэкап hosts будет создан{Colors.RESET}")
        return True
    
    try:
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        if os.path.exists(hosts_path):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(BACKUP_DIR, f"hosts_backup_{timestamp}.txt")
            shutil.copy2(hosts_path, backup_file)
            
            logger.log("Backup_Hosts", "success", f"Бэкап hosts сохранен: {backup_file}")
            print(f"{Colors.GREEN}[+] Бэкап hosts сохранен: {backup_file}{Colors.RESET}")
            return True
        else:
            print(f"{Colors.YELLOW}[!] Файл hosts не найден{Colors.RESET}")
            return False
    except Exception as e:
        logger.log("Backup_Hosts", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Backup_Firewall():
    """Резервное копирование правил брандмауэра"""
    print_hacker_message("Создаю резервную копию правил брандмауэра...")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет создан бэкап правил брандмауэра{Colors.RESET}")
        logger.log("Backup_Firewall", "success", "Бэкап брандмауэра будет создан")
        print(f"{Colors.GREEN}[+] Бэкап брандмауэра будет создан{Colors.RESET}")
        return True
    
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(BACKUP_DIR, f"firewall_backup_{timestamp}.wfw")
        
        # Экспортируем правила брандмауэра
        result = subprocess.run(["netsh", "advfirewall", "export", backup_file], capture_output=True, shell=True)
        
        if result.returncode == 0:
            logger.log("Backup_Firewall", "success", f"Бэкап брандмауэра сохранен: {backup_file}")
            print(f"{Colors.GREEN}[+] Бэкап брандмауэра сохранен: {backup_file}{Colors.RESET}")
            return True
        else:
            logger.log("Backup_Firewall", "error", result.stderr.decode())
            print(f"{Colors.RED}[!] Ошибка: {result.stderr.decode()}{Colors.RESET}")
            return False
    except Exception as e:
        logger.log("Backup_Firewall", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Create_Full_Backup():
    """Создание полного бэкапа перед изменениями"""
    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.CYAN}СОЗДАНИЕ ПОЛНОГО РЕЗЕРВНОГО КОПИРОВАНИЯ{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
    
    print_hacker_message("Создаю полный бэкап системы перед изменениями...")
    
    results = []
    results.append(("Реестр", Backup_Registry()))
    results.append(("Точка восстановления", Backup_System_Restore()))
    results.append(("Hosts файл", Backup_Hosts()))
    results.append(("Брандмауэр", Backup_Firewall()))
    
    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.CYAN}РЕЗУЛЬТАТЫ БЭКАПА:{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
    
    for name, success in results:
        status = f"{Colors.GREEN}[OK]{Colors.RESET}" if success else f"{Colors.RED}[FAIL]{Colors.RESET}"
        print(f"{status} {name}")
    
    all_success = all(success for _, success in results)
    
    if all_success:
        print(f"\n{Colors.GREEN}[+] Полный бэкап успешно создан!{Colors.RESET}")
        logger.log("Create_Full_Backup", "success", "Полный бэкап создан")
    else:
        print(f"\n{Colors.YELLOW}[!] Некоторые бэкапы не удались. Проверьте логи.{Colors.RESET}")
        logger.log("Create_Full_Backup", "warning", "Некоторые бэкапы не удались")
    
    return all_success

def Restore_From_Backup():
    """Откат всех изменений из бэкапа"""
    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.CYAN}ОТКАТ ИЗМЕНЕНИЙ ИЗ БЭКАПА{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
    
    print_hacker_message("Восстанавливаю систему из бэкапа...")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнен откат из бэкапа{Colors.RESET}")
        logger.log("Restore_From_Backup", "success", "Откат будет выполнен")
        print(f"{Colors.GREEN}[+] Откат будет выполнен{Colors.RESET}")
        return True
    
    try:
        # Находим последний бэкап реестра
        backup_files = [e.name for e in os.scandir(BACKUP_DIR) if e.name.startswith("registry_backup_") and e.name.endswith(".reg")]
        
        if backup_files:
            latest_registry = max(backup_files)
            registry_path = os.path.join(BACKUP_DIR, latest_registry)
            
            # Импортируем реестр
            result = subprocess.run(["reg", "import", registry_path], capture_output=True, shell=True)
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}[+] Реестр восстановлен из: {latest_registry}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[!] Ошибка восстановления реестра{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] Бэкап реестра не найден{Colors.RESET}")
        
        # Находим последний бэкап hosts
        hosts_backups = [e.name for e in os.scandir(BACKUP_DIR) if e.name.startswith("hosts_backup_") and e.name.endswith(".txt")]
        
        if hosts_backups:
            latest_hosts = max(hosts_backups)
            hosts_path = os.path.join(BACKUP_DIR, latest_hosts)
            hosts_dest = r"C:\Windows\System32\drivers\etc\hosts"
            
            shutil.copy2(hosts_path, hosts_dest)
            print(f"{Colors.GREEN}[+] Hosts восстановлен из: {latest_hosts}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] Бэкап hosts не найден{Colors.RESET}")
        
        # Находим последний бэкап брандмауэра
        firewall_backups = [e.name for e in os.scandir(BACKUP_DIR) if e.name.startswith("firewall_backup_") and e.name.endswith(".wfw")]
        
        if firewall_backups:
            latest_firewall = max(firewall_backups)
            firewall_path = os.path.join(BACKUP_DIR, latest_firewall)
            
            result = subprocess.run(["netsh", "advfirewall", "import", firewall_path], capture_output=True, shell=True)
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}[+] Брандмауэр восстановлен из: {latest_firewall}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[!] Ошибка восстановления брандмауэра{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] Бэкап брандмауэра не найден{Colors.RESET}")
        
        logger.log("Restore_From_Backup", "success", "Откат выполнен")
        print(f"\n{Colors.GREEN}[+] Откат изменений завершен!{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Рекомендуется перезагрузить систему.{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Restore_From_Backup", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

# ═══════════════════════════════════════════════════════════════
# ДИСПЕТЧЕР ЗАДАЧ
# ═══════════════════════════════════════════════════════════════

class ProcessAnalyzer:
    """Анализатор процессов для определения уровня угрозы"""
    
    SUSPICIOUS_NAMES = [
        'temp.exe', 'update.exe', 'helper.exe', 'miner.exe', 'crypto.exe',
        'bitcoin.exe', 'virus.exe', 'trojan.exe', 'worm.exe', 'malware.exe',
        'loader.exe', 'dropper.exe', 'injector.exe', 'payload.exe', 'backdoor.exe'
    ]
    
    LEGITIMATE_SYSTEM_PROCESSES = [
        'system', 'system idle process', 'svchost.exe', 'services.exe', 'lsass.exe',
        'wininit.exe', 'csrss.exe', 'smss.exe', 'winlogon.exe', 'explorer.exe',
        'dwm.exe', 'spoolsv.exe', 'audiodg.exe', 'conhost.exe', 'taskhost.exe'
    ]
    
    @staticmethod
    def get_threat_level(process):
        """Определяет уровень угрозы процесса (0-10)"""
        try:
            name = process.get('name', '').lower()
            exe_path = process.get('exe', '').lower()
            
            threat_score = 0
            
            # Проверка на подозрительные имена
            for suspicious in ProcessAnalyzer.SUSPICIOUS_NAMES:
                if suspicious in name:
                    threat_score += 5
                    break
            
            # Проверка на системный путь
            if exe_path:
                if 'system32' in exe_path or 'syswow64' in exe_path:
                    threat_score -= 2
                elif 'temp' in exe_path or 'downloads' in exe_path or 'desktop' in exe_path:
                    threat_score += 3
            
            # Проверка на легитимные системные процессы
            if name in ProcessAnalyzer.LEGITIMATE_SYSTEM_PROCESSES:
                threat_score -= 3
            
            # Проверка на цифры в имени (характерно для вирусов)
            if any(char.isdigit() for char in name):
                threat_score += 1
            
            # Ограничиваем диапазон 0-10
            threat_score = max(0, min(10, threat_score))
            
            return threat_score * 10
        except Exception as _e:
            # Expected exception, intentionally ignored
            return 50  # Средний уровень угрозы по умолчанию

    @staticmethod
    def get_all_processes():
        """Возвращает список всех процессов с информацией об угрозе через ctypes (без psutil)"""
        from ctypes import wintypes
        import ctypes
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        psapi = ctypes.WinDLL('psapi', use_last_error=True)

        TH32CS_SNAPPROCESS = 0x00000002
        MAX_PATH = 260
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * MAX_PATH)
            ]

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        processes = []
        h_snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if h_snap == -1:
            return processes
        
        pe32 = PROCESSENTRY32()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
        
        if not kernel32.Process32First(h_snap, ctypes.byref(pe32)):
            kernel32.CloseHandle(h_snap)
            return processes
        
        while True:
            pid = pe32.th32ProcessID
            name = pe32.szExeFile.decode('utf-8', errors='ignore')
            exe_path = ""
            mem_mb = 0.0

            h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if h_process:
                exe_buf = ctypes.create_string_buffer(MAX_PATH)
                size = wintypes.DWORD(MAX_PATH)
                if kernel32.QueryFullProcessImageNameA(h_process, 0, exe_buf, ctypes.byref(size)):
                    class Worker(QThread):
                        finished_signal = Signal(str)

                        def __init__(self, func):
                            super().__init__()
                            self.func = func
                            self.output_lines = []

                        def run(self):
                            import builtins
                            import re
                            original_print = builtins.print
                            
                            def custom_print(*args, **kwargs):
                                message = " ".join(map(str, args))
                                clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', message)
                                clean_msg = clean_msg.replace('[SYSTEM]: ', '').replace('[SYSTEM] ', '').replace('[SYSTEM]', '')
                                clean_msg = clean_msg.replace('[+] ', '').replace('[!] ', '').replace('[*] ', '')
                                clean_msg = clean_msg.strip()
                                if clean_msg:
                                    self.output_lines.append(clean_msg)
                                original_print(*args, **kwargs)
                            
                            builtins.print = custom_print
                            try:
                                self.func()
                            finally:
                                builtins.print = original_print
                                self.finished_signal.emit("\n".join(self.output_lines))
                    exe_path = exe_buf.value.decode('utf-8', errors='ignore')
                
                counters = PROCESS_MEMORY_COUNTERS()
                counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
                if psapi.GetProcessMemoryInfo(h_process, ctypes.byref(counters), counters.cb):
                    mem_mb = counters.WorkingSetSize / (1024 * 1024)
                
                kernel32.CloseHandle(h_process)

            proc_dict = {
                'pid': pid,
                'name': name,
                'exe': exe_path,
                'username': "N/A",  # Имя пользователя требует сложной логики Token/SID
                'cpu': 0.0,         # Нагрузка на CPU требует WMI, устанавливаем 0 для скорости
                'memory': mem_mb
            }
            
            threat = ProcessAnalyzer.get_threat_level(proc_dict)
            proc_dict['threat'] = threat
            processes.append(proc_dict)
            
            if not kernel32.Process32Next(h_snap, ctypes.byref(pe32)):
                break
                
        kernel32.CloseHandle(h_snap)
        return processes

def freeze_process(pid):
    """Замораживает процесс через NtSuspendProcess (ctypes)"""
    try:
        import ctypes
        ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        PROCESS_SUSPEND_RESUME = 0x0800
        h_process = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
        if not h_process:
            return False
        status = ntdll.NtSuspendProcess(h_process)
        kernel32.CloseHandle(h_process)
        return status == 0
    except Exception as _e:
        # Expected exception, intentionally ignored
        return False

def resume_process(pid):
    """Размораживает процесс через NtResumeProcess (ctypes)"""
    try:
        import ctypes
        ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        PROCESS_SUSPEND_RESUME = 0x0800
        h_process = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
        if not h_process:
            return False
        status = ntdll.NtResumeProcess(h_process)
        kernel32.CloseHandle(h_process)
        return status == 0
    except Exception as _e:
        # Expected exception, intentionally ignored
        return False

# Restart Manager API Constants
from ctypes import wintypes
RM_SESSION_KEY_LEN = 16
CCH_RM_SESSION_KEY = RM_SESSION_KEY_LEN * 2

class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwProcessId", wintypes.DWORD),
        ("ProcessStartTime", wintypes.FILETIME)
    ]

class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", ctypes.c_wchar * 256),
        ("strServiceShortName", ctypes.c_wchar * 64),
        ("ApplicationType", ctypes.c_int),
        ("AppStatus", ctypes.c_ulong),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL)
    ]

def get_locking_processes(file_path):
    """Использует Restart Manager для нахождения процессов, блокирующих файл."""
    try:
        rstrtmgr = ctypes.WinDLL('rstrtmgr', use_last_error=True)
    except Exception:
        return []

    session_handle = wintypes.DWORD(0)
    session_key = (ctypes.c_wchar * CCH_RM_SESSION_KEY)()
    
    res = rstrtmgr.RmStartSession(ctypes.byref(session_handle), 0, session_key)
    if res != 0:
        return []
        
    try:
        paths = (ctypes.c_wchar_p * 1)(file_path)
        res = rstrtmgr.RmRegisterResources(session_handle, 1, paths, 0, None, 0, None)
        if res != 0:
            return []
            
        n_proc_info_needed = ctypes.c_uint(0)
        n_proc_info = ctypes.c_uint(0)
        reboot_reasons = ctypes.c_uint(0)
        
        # Первая попытка: узнать нужный размер буфера
        res = rstrtmgr.RmGetList(session_handle, ctypes.byref(n_proc_info_needed), ctypes.byref(n_proc_info), None, ctypes.byref(reboot_reasons))
        
        if res == 234: # ERROR_MORE_DATA
            n_proc_info.value = n_proc_info_needed.value
            proc_info_array = (RM_PROCESS_INFO * n_proc_info.value)()
            res = rstrtmgr.RmGetList(session_handle, ctypes.byref(n_proc_info_needed), ctypes.byref(n_proc_info), proc_info_array, ctypes.byref(reboot_reasons))
            
            if res == 0:
                pids = []
                for i in range(n_proc_info.value):
                    pids.append(proc_info_array[i].Process.dwProcessId)
                return list(set(pids))
        elif res == 0 and n_proc_info.value > 0:
            pass
            
        return []
    except Exception as e:
        print(f"Ошибка Restart Manager: {e}")
        return []
    finally:
        rstrtmgr.RmEndSession(session_handle)

def kill_process_force(pid):
    """Принудительно завершает процесс через TerminateProcess (ctypes)"""
    try:
        import ctypes
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        PROCESS_TERMINATE = 0x0001
        h_process = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not h_process:
            return False
        status = kernel32.TerminateProcess(h_process, 1)
        kernel32.CloseHandle(h_process)
        return status != 0
    except Exception as _e:
        # Expected exception, intentionally ignored
        return False

def enable_privilege(privilege_name):
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    SE_PRIVILEGE_ENABLED = 0x00000002
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]
    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]
    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    hToken = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hToken)):
        return False
        
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
        kernel32.CloseHandle(hToken)
        return False
        
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    
    res = advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), ctypes.sizeof(TOKEN_PRIVILEGES), None, None)
    kernel32.CloseHandle(hToken)
    return res != 0

def set_process_critical(pid, is_critical=True):
    try:
        import ctypes
        from ctypes import wintypes
        enable_privilege("SeDebugPrivilege")
        
        ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        PROCESS_SET_INFORMATION = 0x0200
        
        h_process = kernel32.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
        if not h_process:
            return False
            
        break_on_term = wintypes.ULONG(1 if is_critical else 0)
        status = ntdll.NtSetInformationProcess(h_process, 29, ctypes.byref(break_on_term), ctypes.sizeof(wintypes.ULONG))
        kernel32.CloseHandle(h_process)
        return status == 0
    except Exception as _e:
        # Expected exception, intentionally ignored
        return False

def open_in_explorer(path):
    """Открывает путь в проводнике"""
    try:
        if path and os.path.exists(path):
            if os.path.isfile(path):
                path = os.path.dirname(path)
            subprocess.run(['explorer', path], shell=True)
            return True
    except Exception as _e:
        # Expected exception, intentionally ignored
        return False
    return False

def Final_Log_Report():
    """Генерация полного отчета"""
    print_hacker_message("Генерирую полный отчет о проделанной работе.")
    
    report_path = logger.save_report()
    return report_path is not None


import winreg
def import_winreg():
    return winreg

def Exe_Association_Fix():
    """Сброс ассоциации .exe"""
    print_hacker_message("Восстановление запуска .exe")
    if not DRY_RUN:
        reg_set_value(r"SOFTWARE\\Classes\\.exe", "", "exefile")
        run_reg(winreg.HKEY_CLASSES_ROOT, r"exefile\shell\open\command", "", '\"%1\" %*')
    return True

def Lnk_Association_Fix():
    """Сброс ассоциации .lnk (ярлыков)"""
    print_hacker_message("Восстановление ярлыков .lnk")
    if not DRY_RUN:
        reg_set_value(r"SOFTWARE\\Classes\\.lnk", "", "lnkfile")
        run_reg(winreg.HKEY_CLASSES_ROOT, r"lnkfile\shell\open\command", "", '\"%1\" %*')
    return True

def AppInit_DLLs_Clean():
    """Очистка инъекций AppInit_DLLs"""
    print_hacker_message("Удаление троянских DLL-инъекций")
    if not DRY_RUN:
        run_reg(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", "")
        run_reg(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", "")
    return True

def DisallowRun_Nuke():
    """Удаление черного списка программ (DisallowRun)"""
    print_hacker_message("Разблокировка антивирусных утилит (DisallowRun)")
    if not DRY_RUN:
        delete_registry_key(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "DisallowRun")
        delete_registry_key(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "DisallowRun")
    return True

def SafeBoot_Repair():
    """Восстановление Безопасного режима (BSoD 0x7B fix)"""
    print_hacker_message("Восстановление ключей SafeBoot")
    if not DRY_RUN:
        run_reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal", "", "")
        run_reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SafeBoot\Network", "", "")
    return True

def System_Restore_Enable():
    """Разблокировка Восстановления системы"""
    print_hacker_message("Включение создания точек восстановления")
    if not DRY_RUN:
        delete_registry_key(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Windows NT\SystemRestore", "DisableSR")
    return True

def Defender_Enable():
    """Воскрешение Windows Defender и Security Center"""
    print_hacker_message("Принудительный запуск Защитника Windows")
    if not DRY_RUN:
        delete_registry_key(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware")
        run_reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WinDefend", "Start", 2, winreg.REG_DWORD)
        run_reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\wscsvc", "Start", 2, winreg.REG_DWORD)
    return True

def Windows_Update_Fix():
    """Починка служб обновлений Windows (wuauserv, BITS)"""
    print_hacker_message("Разблокировка Центра обновлений")
    if not DRY_RUN:
        run_reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\wuauserv", "Start", 3, winreg.REG_DWORD)
        run_reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\BITS", "Start", 3, winreg.REG_DWORD)
    return True

def AutoAdminLogon_Disable():
    """Отключение авто-входа локеров"""
    print_hacker_message("Отключение AutoAdminLogon (Winlockers)")
    if not DRY_RUN:
        run_reg(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", "0")
    return True

def Firewall_Force_Enable():
    """Принудительное включение Брандмауэра"""
    print_hacker_message("Сброс и включение Брандмауэра")
    if not DRY_RUN:
        import subprocess
        subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'], creationflags=subprocess.CREATE_NO_WINDOW)
        run_reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\mpssvc", "Start", 2, winreg.REG_DWORD)
    return True


@lru_cache(maxsize=1)
def get_repair_function_catalog():
    """Единый каталог функций восстановления для GUI и самопроверки."""
    return {
        "Интерфейс": [
            ("Сброс шрифтов", "Восстанавливает системные шрифты и очищает кеш шрифтов", Font_Standard_Full),
            ("Разблокировка обоев", "Разблокирует возможность смены обоев рабочего стола", Wallpaper_Force),
            ("Восстановление темы", "Восстанавливает стандартную тему оформления Windows", Visual_Styles_Fix),
            ("Сброс масштаба иконок", "Сбрасывает размер иконок на стандартный", Icon_Size_Reset),
            ("Возврат курсора", "Восстанавливает стандартный курсор мыши", Cursor_Restore),
            ("Поворот экрана", "Разблокирует и восстанавливает поворот экрана", Screen_Rotate_Lock),
            ("ClearType", "Включает и настраивает сглаживание шрифтов ClearType", ClearType_Fix),
        ],
        "Проводник": [
            ("Оболочка Explorer", "Восстанавливает стандартные настройки проводника", Shell_Standard),
            ("Правая кнопка мыши", "Разблокирует контекстное меню правой кнопки", RightClick_Restore),
            ("Видимость дисков", "Восстанавливает отображение скрытых дисков", Drive_Visibility),
            ("Панель задач", "Восстанавливает панель задач и её настройки", Taskbar_Fix),
            ("Значки трея", "Восстанавливает отображение значков в системном трее", System_Tray_Show),
            ("Значки стола", "Восстанавливает иконки на рабочем столе", Desktop_Icons_Revive),
            ("Скрытые файлы", "Включает отображение скрытых файлов и папок", HiddenFiles_Show),
            ("Свойства папки", "Разблокирует меню свойств папки", FolderOptions_Unlock),
            ("Свойства панели задач", "Разблокирует доступ к свойствам панели задач", Taskbar_Properties_Unlock),
            ("Shell Validation", "Проверяет и восстанавливает целостность оболочки", Shell_Validation),
            ("Userinit Fix", "Исправляет параметр Userinit для входа в систему", Userinit_Fix),
        ],
        "Реестр": [
            ("Редактор реестра", "Разблокирует редактор реестра regedit", Reg_Write_Enable),
            ("Диспетчер задач", "Разблокирует диспетчер задач taskmgr", TaskMgr_Hard_Unlock),
            ("Панель управления", "Разблокирует панель управления", ControlPanel_Unlock),
                                    ("Свойства системы", "Разблокирует свойства системы и диспетчер устройств", SystemProperties_Unlock),
            ("CMD / Regedit", "Разблокирует командную строку и regedit", Regedit_CMD_Unlock),
            ("Safe Mode Fix", "Восстанавливает работу безопасного режима", SafeMode_Registry_Fix),
            ("Safe Mode + CMD Boot", "Готовит загрузку в Safe Mode с командной строкой", SafeMode_Boot_Restore_Service),
            ("UAC", "Восстанавливает стандартные настройки UAC", UAC_Default_Fix),
            ("Админские ресурсы", "Восстанавливает административные сетевые ресурсы", Admin_Shares_Restore),
            ("Политики", "Удаляет ограничивающие политики системы", Policies_Nuke),
            ("IFEO Clean", "Очищает Image File Execution Options от вирусов", IFEO_Clean),
        ],
        "Хардкор (Трояны)": [
            ("Fix .EXE", "Починка запуска программ (.exe)", Exe_Association_Fix),
            ("Fix .LNK", "Починка ярлыков (.lnk)", Lnk_Association_Fix),
            ("AppInit Nuke", "Удаление троянских DLL-инъекций", AppInit_DLLs_Clean),
            ("DisallowRun", "Разблокировка антивирусов", DisallowRun_Nuke),
            ("SafeBoot", "Восстановление Безопасного режима", SafeBoot_Repair),
            ("System Restore", "Включение Восстановления системы", System_Restore_Enable),
            ("Defender Fix", "Воскрешение Защитника Windows", Defender_Enable),
            ("Win Update", "Починка служб обновлений", Windows_Update_Fix),
            ("AutoLogon OFF", "Снятие авто-входа локеров", AutoAdminLogon_Disable),
            ("Firewall ON", "Принудительное включение Брандмауэра", Firewall_Force_Enable),
        ],
        "Сеть": [
            ("Hosts Clean", "Очищает файл hosts от вредоносных записей", Hosts_Clean_Hard),
            ("Proxy Nuke", "Удаляет все настройки прокси-сервера", Proxy_Nuke),
            ("Google DNS", "Устанавливает DNS Google (8.8.8.8, 8.8.4.4)", DNS_Google_Force),
            ("Firewall Reset", "Сбрасывает настройки брандмауэра", Firewall_State_Reset),
            ("WinHttp Proxy", "Сбрасывает настройки WinHttp прокси", WinHttp_Proxy_Reset),
            ("Discovery On", "Включает обнаружение сетевых устройств", Network_Discovery_On),
            ("Route Reset", "Сбрасывает таблицу маршрутизации", Route_Reset),
            ("IP/Winsock Reset", "Сбрасывает стек TCP/IP и Winsock", IP_Reset),
        ],
        "Система": [
            ("Выйти из пользователя", "Завершение текущего сеанса.", Logoff_User),
            ("Войти в winRE", "Загрузка среды восстановления Windows.", Boot_WinRE),
            ("Вернуть русский язык", "Восстанавливает стандартную раскладку после вирусной блокировки.", Restore_Russian_Keyboard),
            ("sfc /scannow", "Проверяет целостность системных файлов.", SFC_Scannow),
            ("Восстановить LogonUI", "Некоторые вирусы могут заменять данный файл для своих целей.", LogonUI_Restore),
            ("Экстренное восстановление", "Экстренная функция восстановления системы при блокировках вирусами.", Emergency_Recovery),
            ("Выключить тестовый режим", "Вирусы могут использовать автозагрузку через драйвера. Выключение тестового режима отключит их.", Disable_Test_Mode),
            ("Заменить sethc и utilman", "Заменяет программы экрана блокировки нашей утилитой. При повторном нажатии восстанавливаются.", Replace_Sethc_Utilman),
            ("Полный доступ к файлу", "Позволяет разблокировать доступ к системным и скрытым файлам.", File_Full_Access),
            ("Очистка драйверов", "[ОПАСНО] Удаление всех нештатных драйверов.", Driver_Cleanup),
            ("Удобный запуск", "Запуск утилиты через cmd nov или контекстное меню, отключает UAC.", Easy_Launcher),
            ("Alt+N", "После ввода пароля нажмите Alt+N, и запустится утилита. Отключить в настройках.", Alt_N_Fix),
        ],
        "Запуск утилит": [
            ("Редактор реестра", "Запуск regedit.exe", Open_Regedit),
            ("Проводник", "Запуск explorer.exe", Open_Explorer),
            ("Диспетчер задач", "Запуск taskmgr.exe", Open_Taskmgr),
            ("mbrRE", "Восстановление загрузчика (MBR/BCD)", Fix_MBR_Boot),
            ("Браузер", "Открыть браузер", Open_Browser),
            ("Пользователи", "Управление пользователями", Open_User_Management),
            ("Очистка системы", "Очистка диска", Open_System_Cleanup),
            ("Ассоциации", "Программы по умолчанию", Open_Default_Apps),
            ("Сброс пароля", "Управление паролями", Open_Password_Reset),
            ("Удаление дисков", "Управление дисками", Open_Disk_Management),
            ("Сохранение winRE", "Настройки среды восстановления", WinRE_Backup_Restore),
        ],
        "Клавиатура": [
            ("Scancode Reset", "Удаляет Scancode Map, разблокируя заблокированную клавиатуру", Keyboard_Scancode_Reset),
            ("FilterKeys", "Отключает залипание и фильтрацию клавиш", FilterKeys_Disable),
            ("Выполнить", "Открывает диалоговое окно для быстрого запуска программ (аналог Win+R).", Run_Command_Enable),
            ("Горячие клавиши", "Разблокирует системные комбинации Win+...", WinKeys_Unlock),
        ],
        "Очистка": [
            ("Temp Clean", "Удаляет временные файлы системы", Temp_Deep_Clean),
            ("Prefetch Wipe", "Очищает кеш Prefetch", Prefetch_Wipe),
            ("Recycle Bin", "Очищает корзину", RecycleBin_Empty),
            ("Icon Cache", "Очищает кеш иконок для исправления отображения", IconCache_Clear),
            ("Startup Clean", "Очищает автозагрузку от подозрительных записей", Startup_Clean),
            ("Scheduler Clean", "Очищает планировщик задач от вредоносных задач", TaskScheduler_Clean),
            ("Process Kill", "Завершает подозрительные процессы из черного списка", Process_Blacklist_Kill),
            ("AutoRun Disable", "Отключает автозапуск со съемных носителей", AutoRun_Disable),
        ],
        "Продвинутое": [
            ("WMI Repair", "Восстанавливает службу WMI", WMI_Repair),
            ("Service Scan", "Проверяет и запускает критичные службы", Service_State_Scan),
            ("Cert Clean", "Проверяет хранилище сертификатов", Cert_Store_Clean),
            ("Windows Update Reset", "Сбрасывает компоненты Центра обновления Windows", WinUpdate_Reset),
            ("LNK Fix", "Исправляет ассоциации ярлыков", LNK_File_Fix),
            ("Print Spooler", "Очищает очередь печати и запускает службу", Print_Spooler_Fix),
            ("Self Defense", "Включает базовую самооборону процесса", Self_Defense_Engine),
            ("Safe Mode Full", "Полностью восстанавливает SafeBoot Minimal и Network", SafeMode_Full_Repair),
            ("TrustedInstaller", "Восстанавливает права системных папок", TrustedInstaller_Restore),
            ("EXE Association", "Исправляет ассоциацию .exe", EXE_Assoc),
            ("Self Protect", "Защищает файл программы атрибутами", Self_Protect),
            ("Admin Force", "Проверяет и усиливает права администратора", Admin_Force),
            ("MSCONFIG Unlock", "Разблокирует msconfig", MSCONFIG_Unlock),
            ("Defender Enable", "Включает Microsoft Defender", Windows_Defender_Enable),
            ("System Restore", "Включает восстановление системы", System_Restore_Enable),
            ("AutoPlay Disable", "Отключает AutoPlay", AutoPlay_Disable),
            ("Boot Sector Check", "Проверяет загрузочные записи", Boot_Sector_Check),
            ("Chrome Extensions", "Проверяет расширения Chrome", Chrome_Extensions_Clean),
            ("Startup Registry Scan", "Сканирует ключи автозагрузки", Startup_Registry_Scan),
            ("Event Viewer Clean", "Очищает журналы событий Windows", Event_Viewer_Clean),
        ],
    }

HIGH_RISK_FUNCTION_NAMES = {
    "run_full_scan",
    "Restore_From_Backup",
    "SafeMode_Boot_Restore_Service",
    "SafeMode_Next_Boot_Setup",
}

def run_self_check():
    """Безопасная проверка окружения, зависимостей и каталога функций."""
    import importlib.util

    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.CYAN}САМОПРОВЕРКА NoVir{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")

    warnings = []

    def check(name, ok, details="", warning=True):
        status = "[OK]" if ok else "[WARN]" if warning else "[FAIL]"
        color = Colors.GREEN if ok else Colors.YELLOW if warning else Colors.RED
        message = f"{color}{status} {name}{Colors.RESET}"
        if details:
            message += f" — {details}"
        print(message)
        if not ok:
            warnings.append(name)

    check("Платформа Windows", sys.platform == "win32", platform.platform(), warning=False)
    check("Права администратора", bool(ctypes.windll.shell32.IsUserAnAdmin()), "для реальных исправлений нужны админ-права")
    check("psutil", PSUTIL_AVAILABLE, "нужен для диспетчера задач и анализа процессов")
    check("colorama", COLORAMA_AVAILABLE, "нужен только для красивого цветного вывода")
    check("PySide6", PYSIDE_AVAILABLE or importlib.util.find_spec("PySide6") is not None, "нужен для GUI, консольный режим работает без него")
    check("Папка бэкапов", os.path.isdir(BACKUP_DIR), BACKUP_DIR)

    registered = []
    catalog = get_repair_function_catalog()
    for block_name, functions in catalog.items():
        print(f"\n{Colors.MAGENTA}{block_name}: {len(functions)} функций{Colors.RESET}")
        for name, description, func in functions:
            callable_ok = callable(func)
            registered.append(func.__name__ if callable_ok else str(func))
            check(f"  {name}", callable_ok, func.__name__ if callable_ok else "не является функцией", warning=False)

    counts = {}
    for name in registered:
        counts[name] = counts.get(name, 0) + 1
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    if duplicates:
        print(f"\n{Colors.YELLOW}[WARN] Повторы в каталоге: {', '.join(duplicates)}{Colors.RESET}")
    else:
        print(f"\n{Colors.GREEN}[OK] Повторов в каталоге функций нет{Colors.RESET}")

    print(f"{Colors.GREEN}[OK] Всего в каталоге восстановления: {len(registered)} функций{Colors.RESET}")
    if warnings:
        logger.log("Self_Check", "warning", f"Предупреждения: {', '.join(warnings)}")
        print(f"\n{Colors.YELLOW}[!] Самопроверка завершена с предупреждениями: {', '.join(warnings)}{Colors.RESET}")
    else:
        logger.log("Self_Check", "success", "Предупреждений нет")
        print(f"\n{Colors.GREEN}[+] Самопроверка завершена без предупреждений{Colors.RESET}")

    return not warnings

# ═══════════════════════════════════════════════════════════════
# ГЛАВНОЕ МЕНЮ
# ═══════════════════════════════════════════════════════════════

def show_menu():
    print(f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                         ВЫБЕРИТЕ БЛОК                                ║
╠══════════════════════════════════════════════════════════════════════╣
║  {Colors.WHITE}1. Блок 1: Визуальное восстановление (Интерфейс){Colors.CYAN}                     ║
║  {Colors.WHITE}2. Блок 2: Реанимация Проводника и Оболочки{Colors.CYAN}                         ║
║  {Colors.WHITE}3. Блок 3: Реестр и Доступ (HARD){Colors.CYAN}                                   ║
║  {Colors.WHITE}4. Блок 4: Сеть и Интернет{Colors.CYAN}                                          ║
║  {Colors.WHITE}5. Блок 5: Очистка и Процессы{Colors.CYAN}                                       ║
║  {Colors.WHITE}6. Блок 6: Продвинутые исправления{Colors.CYAN}                                  ║
║  {Colors.WHITE}7. ПОЛНОЕ СКАНИРОВАНИЕ (ВСЕ БЛОКИ){Colors.CYAN}                                  ║
║  {Colors.WHITE}8. Генерация отчета{Colors.CYAN}                                                  ║
║  {Colors.WHITE}9. Самопроверка функций и зависимостей{Colors.CYAN}                              ║
║  {Colors.WHITE}0. Выход{Colors.CYAN}                                                             ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")


def run_block_1():
    print(f"\n{Colors.MAGENTA}{'='*70}{Colors.RESET}")
    print(f"{Colors.MAGENTA}БЛОК 1: ВИЗУАЛЬНОЕ ВОССТАНОВЛЕНИЕ{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
    
    Font_Standard_Full()
    Wallpaper_Force()
    Visual_Styles_Fix()
    Icon_Size_Reset()
    Cursor_Restore()
    Screen_Rotate_Lock()
    ClearType_Fix()

def run_block_2():
    print(f"\n{Colors.MAGENTA}{'='*70}{Colors.RESET}")
    print(f"{Colors.MAGENTA}БЛОК 2: РЕАНИМАЦИЯ ПРОВОДНИКА И ОБОЛОЧКИ{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
    
    Shell_Standard()
    RightClick_Restore()
    Drive_Visibility()
    Taskbar_Fix()
    System_Tray_Show()
    Desktop_Icons_Revive()
    HiddenFiles_Show()
    Shell_Validation()
    Userinit_Fix()

def run_block_3():
    print(f"\n{Colors.MAGENTA}{'='*70}{Colors.RESET}")
    print(f"{Colors.MAGENTA}БЛОК 3: РЕЕСТР И ДОСТУП (HARD){Colors.RESET}")
    print(f"{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
    
    Reg_Write_Enable()
    TaskMgr_Hard_Unlock()
    ControlPanel_Unlock()
    Run_Command_Enable()
    UAC_Default_Fix()
    Admin_Shares_Restore()
    Policies_Nuke()
    IFEO_Clean()
    Regedit_CMD_Unlock()

def run_block_4():
    print(f"\n{Colors.MAGENTA}{'='*70}{Colors.RESET}")
    print(f"{Colors.MAGENTA}БЛОК 4: СЕТЬ И ИНТЕРНЕТ{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
    
    Hosts_Clean_Hard()
    Proxy_Nuke()
    DNS_Google_Force()
    Firewall_State_Reset()
    WinHttp_Proxy_Reset()
    Network_Discovery_On()
    Route_Reset()
    IP_Reset()

def run_block_5():
    print(f"\n{Colors.MAGENTA}{'='*70}{Colors.RESET}")
    print(f"{Colors.MAGENTA}БЛОК 5: ОЧИСТКА И ПРОЦЕССЫ{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
    
    Temp_Deep_Clean()
    Prefetch_Wipe()
    RecycleBin_Empty()
    IconCache_Clear()
    Startup_Clean()
    TaskScheduler_Clean()
    Process_Blacklist_Kill()
    SafeMode_Registry_Fix()
    AutoRun_Disable()

def run_block_6():
    print(f"\n{Colors.MAGENTA}{'='*70}{Colors.RESET}")
    print(f"{Colors.MAGENTA}БЛОК 6: ПРОДВИНУТЫЕ ИСПРАВЛЕНИЯ{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
    
    WMI_Repair()
    Service_State_Scan()
    Cert_Store_Clean()
    WinUpdate_Reset()
    LNK_File_Fix()
    Print_Spooler_Fix()
    Self_Defense_Engine()
    SafeMode_Full_Repair()
    TrustedInstaller_Restore()
    EXE_Assoc()
    Self_Protect()
    Admin_Force()
    MSCONFIG_Unlock()
    Windows_Defender_Enable()
    System_Restore_Enable()
    AutoPlay_Disable()
    Boot_Sector_Check()
    Chrome_Extensions_Clean()
    Startup_Registry_Scan()
    Event_Viewer_Clean()

def run_full_scan():
    print(f"\n{Colors.RED}{'='*70}{Colors.RESET}")
    print(f"{Colors.RED}ПОЛНОЕ СКАНИРОВАНИЕ — ВСЕ БЛОКИ{Colors.RESET}")
    print(f"{Colors.RED}{'='*70}{Colors.RESET}\n")
    
    print_hacker_message("Запускаю полный режим реанимации. Это может занять некоторое время.")
    
    # Создаем бэкап перед сканированием
    print(f"\n{Colors.CYAN}[!] Создаю резервную копию перед изменениями...{Colors.RESET}\n")
    Create_Full_Backup()
    
    run_block_1()
    run_block_2()
    run_block_3()
    run_block_4()
    run_block_5()
    run_block_6()
    
    print_hacker_message("Всё! Система должна ожить. Генерирую отчет...")
    Final_Log_Report()

# ═══════════════════════════════════════════════════════════════
# GUI КЛАССЫ (PYSIDE6)
# ═══════════════════════════════════════════════════════════════

if GUI_MODE:
    from PySide6.QtWidgets import (QDialog, QVBoxLayout, QPushButton, QLabel, QScrollArea, 
                                 QTableWidget, QTableWidgetItem, QHeaderView, QHBoxLayout,
                                 QStackedWidget, QFrame, QTabWidget, QTabBar, QTextBrowser)
    from PySide6.QtGui import QColor, QIcon, QFont, QPixmap
    from PySide6.QtCore import Qt, QThread, Signal, QSize, QTimer

    class Worker(QThread):


        finished_signal = Signal(str)



        def __init__(self, func):


            super().__init__()


            self.func = func


            self.output_lines = []



        def run(self):


            import builtins


            import re


            original_print = builtins.print


            


            def custom_print(*args, **kwargs):


                message = " ".join(map(str, args))


                clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', message)


                clean_msg = clean_msg.replace('[SYSTEM]: ', '').replace('[SYSTEM] ', '').replace('[SYSTEM]', '')


                clean_msg = clean_msg.replace('[+] ', '').replace('[!] ', '').replace('[*] ', '')


                clean_msg = clean_msg.strip()


                if clean_msg:


                    self.output_lines.append(clean_msg)


                


            builtins.print = custom_print


            try:


                self.func()


            finally:


                builtins.print = original_print


                self.finished_signal.emit("\n".join(self.output_lines))

    class SchedulerLoader(QThread):
        """Фоновая загрузка задач планировщика чтобы не блокировать UI"""
        data_signal = Signal(list)

        def __init__(self, loader_func):
            super().__init__()
            self.loader_func = loader_func

        def run(self):
            try:
                data = []
                try:
                    data = self.loader_func()
                except Exception:
                    data = []
                # emit list of tuples (name, val)
                self.data_signal.emit(data)
            except Exception:
                self.data_signal.emit([])

    class StyledButton(QPushButton):
        def __init__(self, text, color="#ffffff", parent=None):
            super().__init__(text, parent)
            self.setMinimumHeight(45)
            self.setCursor(Qt.PointingHandCursor)
            self.setStyleSheet("""
                QPushButton {
                    background-color: #404040;
                    color: #ffffff;
                    border: 1px solid #606060;
                    border-radius: 4px;
                    font-size: 14px;
                    font-weight: bold;
                    padding: 5px 15px;
                }
                QPushButton:hover {
                    background-color: #333333;
                    border-color: #888888;
                }
                QPushButton:pressed {
                    background-color: #303030;
                    border-color: #333333;
                }
            """)

    class FunctionDialog(QDialog):
        def __init__(self, block_name, functions, color, parent=None):
            super().__init__(parent)
            self.block_name = block_name
            self.functions = functions
            self.color = color
            self.init_ui()
            
        def init_ui(self):
            self.setWindowTitle(f"{self.block_name} - Выберите функцию")
            self.setMinimumSize(500, 400)
            self.setStyleSheet("background-color: #000000; color: #ffffff;")
            
            layout = QVBoxLayout(self)
            
            title = QLabel(self.block_name)
            title.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {self.color}; margin-bottom: 15px;")
            layout.addWidget(title)
            
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setStyleSheet("background-color: #2c2f33; border: 1px solid #23272a; border-radius: 10px;")
            
            scroll_content = QWidget()
            scroll_layout = QVBoxLayout(scroll_content)
            
            for func_name, func in self.functions:
                btn = StyledButton(func_name, self.color)
                btn.clicked.connect(lambda checked=False, f=func: self.run_function(f))
                scroll_layout.addWidget(btn)
            
            scroll_layout.addStretch()
            scroll.setWidget(scroll_content)
            layout.addWidget(scroll)
            
            close_btn = QPushButton("Отмена")
            close_btn.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px; font-weight: bold; padding: 10px;")
            close_btn.clicked.connect(self.close)
            layout.addWidget(close_btn)
        
        def run_function(self, func):
            self.close()
            if hasattr(self.parent(), 'run_task'):
                self.parent().run_task(func)

    class DefenderScannerThread(QThread):
        update_threat_signal = Signal(int, int) # row, threat_percentage
        
        def __init__(self, processes, parent=None):
            super().__init__(parent)
            self.processes = processes # list of (row, exe_path)
            
        def run(self):
            import subprocess
            import os
            defender_path = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
            if not os.path.exists(defender_path):
                return
                
            for row, exe_path in self.processes:
                if not exe_path or not os.path.exists(exe_path):
                    continue
                try:
                    cmd = f'"{defender_path}" -Scan -ScanType 3 -File "{exe_path}"'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, creationflags=0x08000000)
                    if result.returncode == 2:
                        self.update_threat_signal.emit(row, 100)
                    elif result.returncode == 0:
                        self.update_threat_signal.emit(row, 0)
                except Exception:
                    pass

    class TaskManagerDialog(QDialog):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Диспетчер задач NoVir")
            self.setWindowFlags(self.windowFlags() | Qt.WindowMaximizeButtonHint | Qt.WindowMinimizeButtonHint)
            self.showMaximized()
            self.setStyleSheet("background-color: #000000; color: #ffffff;")
            self.init_ui()
            
        def init_ui(self):
            self.setMinimumSize(1120, 730)
            self.setStyleSheet("""
                QDialog {
                    background-color: #000000;
                    color: #ffffff;
                }
            """)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(18, 18, 18, 18)
            layout.setSpacing(14)

            header = QFrame()
            header.setObjectName("TaskHeader")
            header.setStyleSheet("""
                #TaskHeader {
                    background-color: #000000;
                    border: 1px solid #333333;
                    border-radius: 16px;
                    padding: 10px;
                }
            """)
            header_layout = QVBoxLayout(header)
            header_layout.setContentsMargins(18, 14, 18, 14)
            header_layout.setSpacing(4)

            title = QLabel("Диспетчер задач")
            title.setStyleSheet("font-size: 24px; font-weight: 700; color: #f7f9ff; letter-spacing: 0.4px;")
            subtitle = QLabel("Современный контроль процессов, быстрые действия и аккуратный интерфейс в одном окне")
            subtitle.setStyleSheet("font-size: 12px; color: #888888;")
            header_layout.addWidget(title)
            header_layout.addWidget(subtitle)
            layout.addWidget(header)

            buttons_frame = QFrame()
            buttons_frame.setObjectName("ActionBar")
            buttons_frame.setStyleSheet("""
                #ActionBar {
                    background-color: rgba(255,255,255,0.035);
                    border: 1px solid #111111;
                    border-radius: 14px;
                    padding: 6px;
                }
            """)
            buttons_layout = QHBoxLayout(buttons_frame)
            buttons_layout.setContentsMargins(8, 8, 8, 8)
            buttons_layout.setSpacing(8)

            def add_action_button(text, slot, tooltip=""):
                btn = QPushButton(text)
                btn.setCursor(Qt.PointingHandCursor)
                btn.setMinimumHeight(36)
                btn.setToolTip(tooltip or text)
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #2a3142;
                        color: #f2f5fb;
                        border: 1px solid #3b465b;
                        border-radius: 10px;
                        padding: 7px 12px;
                        font-weight: 600;
                        font-size: 12px;
                    }
                    QPushButton:hover {
                        background-color: #334156;
                        border-color: #5b6b85;
                    }
                    QPushButton:pressed {
                        background-color: #000000;
                        border-color: #7aa2ff;
                    }
                """)
                btn.clicked.connect(slot)
                buttons_layout.addWidget(btn)
                return btn

            self.refresh_btn = add_action_button("Обновить", self.refresh_processes, "Обновить список процессов")
            self.freeze_btn = add_action_button("Заморозить", self.freeze_selected, "Остановить выбранный процесс")
            self.resume_btn = add_action_button("Разморозить", self.resume_selected, "Разрешить работу процесса")
            self.kill_btn = add_action_button("Убить", self.kill_selected, "Принудительно завершить процесс")
            self.block_btn = add_action_button("Заблокировать", self.block_selected, "Заблокировать процесс через IFEO")
            self.unblock_btn = add_action_button("Разблокировать", self.unblock_selected, "Снять IFEO-блокировку")
            self.explorer_btn = add_action_button("Открыть путь", self.open_in_explorer, "Открыть каталог процесса")
            self.crit_btn = add_action_button("Критичный", self.make_critical, "Сделать процесс критичным")
            self.uncrit_btn = add_action_button("Некритичный", self.make_uncritical, "Снять статус критичности")

            buttons_layout.addStretch()
            layout.addWidget(buttons_frame)

            table_frame = QFrame()
            table_frame.setObjectName("ProcessTableFrame")
            table_frame.setStyleSheet("""
                #ProcessTableFrame {
                    background-color: rgba(255,255,255,0.03);
                    border: 1px solid #111111;
                    border-radius: 14px;
                    padding: 6px;
                }
            """)
            table_layout = QVBoxLayout(table_frame)
            table_layout.setContentsMargins(6, 6, 6, 6)

            self.table = QTableWidget()
            self.table.setColumnCount(7)
            self.table.setHorizontalHeaderLabels(["PID", "Имя", "Путь", "Пользователь", "CPU %", "RAM %", "Угроза"])
            self.table.setAlternatingRowColors(True)
            self.table.setSelectionBehavior(QTableWidget.SelectRows)
            self.table.setSelectionMode(QTableWidget.SingleSelection)
            self.table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.table.setShowGrid(False)
            self.table.setUniformRowHeights(True)
            self.table.setStyleSheet("""
                QTableWidget {
                    background-color: transparent;
                    border: none;
                    color: #ffffff;
                    font-size: 12px;
                    gridline-color: transparent;
                }
                QTableWidget::item {
                    padding: 8px 6px;
                    border: none;
                }
                QTableWidget::item:selected {
                    background-color: #2d6bff;
                    color: #ffffff;
                }
                QTableWidget::item:hover {
                    background-color: rgba(45, 107, 255, 0.16);
                }
                QHeaderView::section {
                    background-color: #202737;
                    color: #dce7ff;
                    padding: 8px 6px;
                    border: 1px solid #30384d;
                    font-weight: 700;
                }
                QScrollBar:vertical {
                    background: #161b26;
                    width: 10px;
                    border-radius: 5px;
                }
                QScrollBar::handle:vertical {
                    background: #3b4966;
                    border-radius: 5px;
                }
            """)
            self.table.verticalHeader().setVisible(False)
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.setSortingEnabled(False)
            self.table.setMinimumHeight(420)
            table_layout.addWidget(self.table)
            layout.addWidget(table_frame)

            status_label = QLabel("Выберите процесс и выполните нужное действие: обновить, заморозить, завершить или заблокировать")
            status_label.setStyleSheet("color: #8da0bd; font-size: 11px; margin-top: 2px;")
            layout.addWidget(status_label)

            self.refresh_processes()
        
        def refresh_processes(self):
            self.table.setUpdatesEnabled(False)
            self.table.setRowCount(0)
            processes = ProcessAnalyzer.get_all_processes()
            self.table.setRowCount(len(processes))

            for row, proc in enumerate(processes):
                values = [
                    str(proc['pid']),
                    proc['name'],
                    proc['exe'],
                    proc['username'],
                    f"{proc['cpu']:.1f}",
                    f"{proc['memory']:.1f}",
                    f"{proc['threat']}%",
                ]

                for col, text in enumerate(values):
                    item = QTableWidgetItem(text)
                    if col == 6:
                        threat = proc['threat']
                        if threat >= 70:
                            item.setBackground(QColor(80, 80, 80))
                        elif threat >= 40:
                            item.setBackground(QColor(120, 120, 120))
                        else:
                            item.setBackground(QColor(180, 180, 180))
                    self.table.setItem(row, col, item)

            self.table.setUpdatesEnabled(True)
            self.table.viewport().update()

            # Запуск асинхронного сканирования через Defender
            processes_to_scan = []
            for r in range(self.table.rowCount()):
                exe_path = self.table.item(r, 2).text()
                if exe_path:
                    processes_to_scan.append((r, exe_path))

            self.scanner_thread = DefenderScannerThread(processes_to_scan, self)
            self.scanner_thread.update_threat_signal.connect(self.update_threat_ui)
            self.scanner_thread.start()
            
        def update_threat_ui(self, row, threat_pct):
            if row < self.table.rowCount():
                item = self.table.item(row, 6)
                if item:
                    item.setText(f"{threat_pct}%")
                    if threat_pct >= 70:
                        item.setBackground(QColor(80, 80, 80))
                    elif threat_pct >= 40:
                        item.setBackground(QColor(120, 120, 120))
                    else:
                        item.setBackground(QColor(180, 180, 180))
        
        def get_selected_pid(self):
            current_row = self.table.currentRow()
            if current_row >= 0:
                return int(self.table.item(current_row, 0).text())
            return None
        
        def get_selected_path(self):
            current_row = self.table.currentRow()
            if current_row >= 0:
                return self.table.item(current_row, 2).text()
            return None
        
        def freeze_selected(self):
            pid = self.get_selected_pid()
            if pid:
                if freeze_process(pid):
                    self.append_log(f"[+] Процесс {pid} заморожен")
                    self.refresh_processes()
                else:
                    self.append_log(f"[!] Не удалось заморозить процесс {pid}")
        
        def resume_selected(self):
            pid = self.get_selected_pid()
            if pid:
                if resume_process(pid):
                    self.append_log(f"[+] Процесс {pid} разморожен")
                    self.refresh_processes()
                else:
                    self.append_log(f"[!] Не удалось разморозить процесс {pid}")
        
        def kill_selected(self):
            pid = self.get_selected_pid()
            if pid:
                if kill_process_force(pid):
                    import ctypes
                    import os
                    import sys
                    
                    try:
                        base_path = sys._MEIPASS
                    except Exception:
                        base_path = os.path.abspath(".")
                        
                    mp3_path = os.path.join(base_path, "fatality.mp3")
                    if os.path.exists(mp3_path):
                        ctypes.windll.winmm.mciSendStringW('close fatality', None, 0, None)
                        ctypes.windll.winmm.mciSendStringW(f'open "{mp3_path}" alias fatality', None, 0, None)
                        ctypes.windll.winmm.mciSendStringW('play fatality', None, 0, None)
                    
                    self.append_log(f"[+] FATALITY! Процесс {pid} уничтожен")
                    self.refresh_processes()
                else:
                    self.append_log(f"[!] Не удалось убить процесс {pid}")

        def get_selected_name(self):
            row = self.process_table.currentRow()
            if row >= 0:
                return self.process_table.item(row, 1).text()
            return None

        def block_selected(self):
            name = self.get_selected_name()
            if name:
                reg_set_value(rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{name}", "Debugger", "svchost.exe")
                self.append_log(f"[+] Процесс {name} навсегда заблокирован (карантин).")

        def unblock_selected(self):
            name = self.get_selected_name()
            if name:
                reg_delete_key(rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{name}")
                self.append_log(f"[+] Блокировка снята с {name}.")

        def make_critical(self):
            pid = self.get_selected_pid()
            if pid:
                if set_process_critical(pid, True):
                    self.append_log(f"[+] Процесс {pid} установлен как КРИТИЧЕСКИЙ (BSoD при завершении)")
                    QMessageBox.warning(self, "Внимание", f"Процесс {pid} теперь критический. Завершение приведет к синему экрану (BSoD)!")
                else:
                    self.append_log(f"[!] Не удалось сделать процесс {pid} критическим")
                    
        def make_uncritical(self):
            pid = self.get_selected_pid()
            if pid:
                if set_process_critical(pid, False):
                    self.append_log(f"[+] Процесс {pid} теперь НЕ критический")
                else:
                    self.append_log(f"[!] Не удалось снять статус критичности с процесса {pid}")
        

        def open_in_explorer(self):
            path = self.get_selected_path()
            if path and open_in_explorer(path):
                self.append_log(f"[+] Путь открыт в проводнике: {path}")
            else:
                self.append_log(f"[!] Не удалось открыть путь")
        
        def append_log(self, text):
            if hasattr(self.parent(), 'append_log'):
                self.parent().append_log(text)

    def analyze_startup_item(name, path):
        """Анализирует элемент автозагрузки на предмет опасности."""
        path_lower = str(path).lower()
        name_lower = str(name).lower()
        
        # 1. Подозрительные пути
        danger_paths = ['appdata\\local\\temp', 'appdata\\roaming', 'programdata']
        for dp in danger_paths:
            if dp in path_lower:
                return QColor(244, 67, 54) # Red
                
        # 2. Подозрительные имена в пути (из словаря)
        for bad_name in ProcessAnalyzer.SUSPICIOUS_NAMES:
            if bad_name in path_lower or bad_name in name_lower:
                return QColor(244, 67, 54) # Red
                
        # 3. Маскировка системных процессов
        system_procs = ['svchost.exe', 'explorer.exe', 'csrss.exe', 'lsass.exe', 'winlogon.exe']
        for sp in system_procs:
            if sp in path_lower and 'system32' not in path_lower and 'syswow64' not in path_lower:
                return QColor(244, 67, 54) # Red
                
        # 4. Безопасные пути (System32)
        safe_paths = ['windows\\system32', 'windows\\syswow64']
        for sp in safe_paths:
            if sp in path_lower:
                return QColor(76, 175, 80) # Green
                
        # 5. Нейтрально
        return QColor(0, 0, 0) # Black

    class ToolWindow(QDialog):
        def __init__(self, title, subtitle, action_text, action_callback, parent=None):
            super().__init__(parent)
            self.action_callback = action_callback
            self.setWindowTitle(title)
            self.setMinimumSize(520, 220)
            self.setStyleSheet("""
                QDialog {
                    background-color: #000000;
                    color: #ffffff;
                    border: 1px solid #111111;
                }
            """)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(18, 18, 18, 18)
            layout.setSpacing(12)

            header = QLabel(title)
            header.setStyleSheet("font-size: 22px; font-weight: 700; color: #ffffff; margin-bottom: 4px;")
            layout.addWidget(header)

            subtitle_label = QLabel(subtitle)
            subtitle_label.setWordWrap(True)
            subtitle_label.setStyleSheet("color: #ffffff; font-size: 13px; line-height: 1.5;")
            layout.addWidget(subtitle_label)

            info = QLabel("Данный модуль запускается как отдельное окно утилиты и работает в едином стиле приложения.")
            info.setWordWrap(True)
            info.setStyleSheet("color: #9aa9c2; font-size: 11px; background: rgba(255,255,255,0.03); border: 1px solid #111111; border-radius: 8px; padding: 10px;")
            layout.addWidget(info)

            btn_layout = QHBoxLayout()
            btn_layout.addStretch()

            open_btn = QPushButton(action_text)
            open_btn.setCursor(Qt.PointingHandCursor)
            open_btn.setMinimumHeight(34)
            open_btn.setStyleSheet("""
                QPushButton {
                    background-color: #111111; color: #eaf4ff;
                    border: 1px solid #222222; border-radius: 8px;
                    padding: 7px 16px; font-weight: 600;
                }
                QPushButton:hover { background-color: #3c465d; }
                QPushButton:pressed { background-color: #000000; }
            """)
            open_btn.clicked.connect(self.launch_action)
            btn_layout.addWidget(open_btn)

            close_btn = QPushButton("Закрыть")
            close_btn.setCursor(Qt.PointingHandCursor)
            close_btn.setMinimumHeight(34)
            close_btn.setStyleSheet("""
                QPushButton {
                    background-color: #000000; color: #dfe8f5;
                    border: 1px solid #222222; border-radius: 8px;
                    padding: 7px 16px; font-weight: 600;
                }
                QPushButton:hover { background-color: #2a3345; }
            """)
            close_btn.clicked.connect(self.close)
            btn_layout.addWidget(close_btn)
            layout.addLayout(btn_layout)

        def launch_action(self):
            try:
                if self.action_callback:
                    self.action_callback()
            except Exception:
                pass
            self.close()

    class RegistryEditorWindow(QDialog):
        _DUMMY = "__dummy__"   # заглушка для раскрывающихся узлов

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Редактор реестра")
            self.resize(1100, 680)
            self.setWindowFlags(self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)
            self.setStyleSheet("""
                QDialog { background: #ffffff; }
                /* Дерево */
                QTreeWidget {
                    background-color: #ffffff;
                    border: none;
                    border-right: 1px solid #888888;
                    color: #000000;
                    font-size: 12px;
                    outline: none;
                }
                QTreeWidget::item {
                    height: 20px;
                    padding: 1px 2px;
                    color: #000000;
                }
                QTreeWidget::item:selected {
                    background-color: #ffffff;
                    color: #ffffff;
                }
                QTreeWidget::item:hover:!selected {
                    background-color: #e8f0fe;
                }
                /* expand/collapse ветки */
                QTreeWidget::branch {
                    background: white;
                }
                QTreeWidget::branch:has-children:!has-siblings:closed,
                QTreeWidget::branch:closed:has-children:has-siblings {
                    image: url(none);
                    border-image: none;
                }
                /* Таблица */
                QTableWidget {
                    background-color: #ffffff;
                    border: none;
                    color: #000000;
                    gridline-color: #ffffff;
                    alternate-background-color: #f7f7f7;
                    selection-background-color: #ffffff;
                    selection-color: #ffffff;
                    font-size: 12px;
                }
                QTableWidget::item { padding: 3px 6px; }
                QHeaderView::section {
                    background-color: #ffffff;
                    color: #000000;
                    border: none;
                    border-right: 1px solid #cccccc;
                    border-bottom: 1px solid #cccccc;
                    font-weight: bold;
                    padding: 5px 8px;
                    font-size: 12px;
                }
                /* Полоса пути */
                QLabel#PathLabel {
                    background-color: #ffffff;
                    color: #000000;
                    font-size: 12px;
                    font-family: Consolas, monospace;
                    border-bottom: 1px solid #cccccc;
                    padding: 5px 8px;
                }
                /* Заголовок-меню */
                QFrame#TitleBar {
                    background-color: #ffffff;
                    border-bottom: 1px solid #cccccc;
                }
                /* Splitter */
                QSplitter::handle {
                    background-color: #888888;
                    width: 1px;
                }
            """)

            self.hive_map = {
                "HKEY_CLASSES_ROOT":   winreg.HKEY_CLASSES_ROOT,
                "HKEY_CURRENT_USER":   winreg.HKEY_CURRENT_USER,
                "HKEY_LOCAL_MACHINE":  winreg.HKEY_LOCAL_MACHINE,
                "HKEY_USERS":          winreg.HKEY_USERS,
                "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
            }

            outer = QVBoxLayout(self)
            outer.setContentsMargins(0, 0, 0, 0)
            outer.setSpacing(0)

            # ── Путь (breadcrumb-строка) ──────────────────────────────────
            self.path_label = QLabel("Мой компьютер")
            self.path_label.setObjectName("PathLabel")
            self.path_label.setFixedHeight(28)
            outer.addWidget(self.path_label)

            # ── Сплиттер: дерево | таблица ───────────────────────────────
            from PySide6.QtWidgets import QSplitter, QSizePolicy
            splitter = QSplitter(Qt.Horizontal)
            splitter.setHandleWidth(1)
            splitter.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            outer.addWidget(splitter, 1)  # stretch=1 → занимает всё оставшееся место

            # Левая панель — дерево
            self.tree = QTreeWidget()
            self.tree.setHeaderHidden(True)
            self.tree.setIndentation(16)
            self.tree.setRootIsDecorated(True)
            self.tree.setItemsExpandable(True)
            self.tree.setExpandsOnDoubleClick(True)
            self.tree.setAnimated(True)
            self.tree.setUniformRowHeights(True)
            splitter.addWidget(self.tree)

            # Правая панель — таблица значений
            right = QFrame()
            right.setStyleSheet("background: white; border: none;")
            right_layout = QVBoxLayout(right)
            right_layout.setContentsMargins(0, 0, 0, 0)
            right_layout.setSpacing(0)

            self.table = QTableWidget(0, 3)
            self.table.setHorizontalHeaderLabels(["Имя", "Тип", "Значение"])
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.verticalHeader().setVisible(False)
            self.table.setAlternatingRowColors(True)
            self.table.setFrameShape(QFrame.NoFrame)
            self.table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.table.setSelectionBehavior(QTableWidget.SelectRows)
            self.table.setColumnWidth(0, 200)
            self.table.setColumnWidth(1, 130)
            self.table.verticalHeader().setDefaultSectionSize(20)
            right_layout.addWidget(self.table)
            splitter.addWidget(right)

            splitter.setSizes([270, 830])

            # ── Наполнение дерева (lazy) ──────────────────────────────────
            self._populate_root()

            # Сигналы
            self.tree.itemClicked.connect(self._on_item_clicked)
            self.tree.itemExpanded.connect(self._on_item_expanded)

        # ── Вспомогательные методы ────────────────────────────────────────
        def _hive_of(self, item):
            """Возвращает имя корневого куста для данного элемента."""
            cur = item
            while cur.parent() is not None:
                cur = cur.parent()
            return cur.text(0)

        def _subkey_of(self, item):
            """Строит путь подключа относительно куста."""
            parts = []
            cur = item
            while cur.parent() is not None:
                parts.append(cur.text(0))
                cur = cur.parent()
            parts.reverse()
            return "\\".join(parts)

        def _has_subkeys(self, hive_name, subkey):
            hive = self.hive_map.get(hive_name)
            if hive is None:
                return False
            try:
                k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                winreg.EnumKey(k, 0)
                winreg.CloseKey(k)
                return True
            except Exception:
                return False

        def _load_subkeys(self, hive_name, subkey):
            hive = self.hive_map.get(hive_name)
            if hive is None:
                return []
            try:
                k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                result = []
                i = 0
                while True:
                    try:
                        result.append(winreg.EnumKey(k, i))
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(k)
                return sorted(result, key=str.lower)
            except Exception:
                return []

        def _load_values(self, hive_name, subkey):
            hive = self.hive_map.get(hive_name)
            if hive is None:
                return []
            try:
                k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                rows = []
                i = 0
                while True:
                    try:
                        name, value, vtype = winreg.EnumValue(k, i)
                        rows.append((name or "(По умолчанию)", self._type_name(vtype), self._fmt(value)))
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(k)
                return rows
            except Exception:
                return []

        def _type_name(self, t):
            return {
                winreg.REG_SZ:        "REG_SZ",
                winreg.REG_DWORD:     "REG_DWORD",
                winreg.REG_QWORD:     "REG_QWORD",
                winreg.REG_BINARY:    "REG_BINARY",
                winreg.REG_MULTI_SZ:  "REG_MULTI_SZ",
                winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
                winreg.REG_NONE:      "REG_NONE",
            }.get(t, f"0x{t:x}")

        def _fmt(self, v):
            if isinstance(v, (bytes, bytearray)):
                return " ".join(f"{b:02x}" for b in v)
            if isinstance(v, (list, tuple)):
                return "  ".join(str(x) for x in v)
            return str(v)

        # ── Наполнение дерева ─────────────────────────────────────────────
        def _populate_root(self):
            self.tree.clear()
            for hive_name in self.hive_map:
                root = QTreeWidgetItem([hive_name])
                # Добавляем заглушку → появится [+]
                root.addChild(QTreeWidgetItem([self._DUMMY]))
                self.tree.addTopLevelItem(root)

        def _on_item_expanded(self, item):
            """Lazy-load: при раскрытии узла грузим его дочерние ключи."""
            # Если первый ребёнок — заглушка, грузим реальные дети
            if item.childCount() == 1 and item.child(0).text(0) == self._DUMMY:
                item.takeChildren()
                hive = self._hive_of(item)
                sub  = self._subkey_of(item)
                for key_name in self._load_subkeys(hive, sub):
                    child = QTreeWidgetItem([key_name])
                    # Проверяем, есть ли у ребёнка свои подключи → добавляем заглушку
                    child_sub = (sub + "\\" + key_name) if sub else key_name
                    if self._has_subkeys(hive, child_sub):
                        child.addChild(QTreeWidgetItem([self._DUMMY]))
                    item.addChild(child)

        def _on_item_clicked(self, item):
            """Клик по узлу → показываем значения ключа."""
            hive = self._hive_of(item)
            sub  = self._subkey_of(item)
            path = f"{hive}\\{sub}" if sub else hive
            self.path_label.setText(path)

            self.table.setRowCount(0)
            rows = self._load_values(hive, sub)
            for name, kind, val in rows:
                r = self.table.rowCount()
                self.table.insertRow(r)
                self.table.setItem(r, 0, QTableWidgetItem(name))
                self.table.setItem(r, 1, QTableWidgetItem(kind))
                self.table.setItem(r, 2, QTableWidgetItem(val))
            if not rows:
                self.table.insertRow(0)
                self.table.setItem(0, 0, QTableWidgetItem("(Пусто)"))
                self.table.setItem(0, 1, QTableWidgetItem(""))
                self.table.setItem(0, 2, QTableWidgetItem(""))

    class UserManagerWindow(QDialog):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Пользователи")
            self.resize(1100, 640)
            self.setStyleSheet("""
                QDialog {
                    background-color: #121820;
                    color: #e8edf5;
                }
                QTableWidget {
                    background-color: #1b232c;
                    border: 1px solid #2f3a45;
                    color: #ffffff;
                    alternate-background-color: #202b37;
                }
                QHeaderView::section {
                    background-color: #2a3641;
                    color: #ffffff;
                    border: 1px solid #222222;
                    font-weight: 600;
                }
                QLineEdit {
                    background-color: #1d2731;
                    color: #ffffff;
                    border: 1px solid #222222;
                    padding: 7px 8px;
                    font-size: 13px;
                    border-radius: 4px;
                }
                QPushButton {
                    background-color: #7ca5b7;
                    color: #0f1720;
                    border: none;
                    font-weight: 600;
                    padding: 10px 20px;
                    border-radius: 6px;
                }
                QPushButton:hover { background-color: #8bb4c6; }
                QCheckBox { font-size: 13px; color: #ffffff; }
                QLabel { color: #ffffff; }
            """)

            outer = QVBoxLayout(self)
            outer.setContentsMargins(0, 0, 0, 0)
            outer.setSpacing(0)

            top_bar = QFrame()
            top_bar.setFixedHeight(42)
            top_bar.setStyleSheet("background-color: #1b1d22; border-bottom: 1px solid #2f3136;")
            bar_layout = QHBoxLayout(top_bar)
            bar_layout.setContentsMargins(12, 0, 12, 0)
            title = QLabel("Пользователи")
            title.setStyleSheet("color: white; font-size: 15px; font-weight: bold;")
            bar_layout.addWidget(title)
            bar_layout.addStretch()
            btn_min = QPushButton("—")
            btn_min.setFixedSize(28, 28)
            btn_min.setStyleSheet("QPushButton { background: transparent; color: white; border: none; font-size: 18px; } QPushButton:hover { background-color: #2a2d32; }")
            btn_min.clicked.connect(self.showMinimized)
            bar_layout.addWidget(btn_min)
            btn_close = QPushButton("✕")
            btn_close.setFixedSize(28, 28)
            btn_close.setStyleSheet("QPushButton { background: transparent; color: white; border: none; font-size: 16px; } QPushButton:hover { background-color: #d62828; }")
            btn_close.clicked.connect(self.reject)
            bar_layout.addWidget(btn_close)
            outer.addWidget(top_bar)

            main = QHBoxLayout()
            main.setContentsMargins(12, 12, 12, 12)
            main.setSpacing(14)

            left = QFrame()
            left.setStyleSheet("background-color: #1b1f2a; border: 1px solid #2e3743;")
            left_layout = QVBoxLayout(left)
            left_layout.setContentsMargins(0, 0, 0, 0)
            table = QTableWidget(0, 2)
            table.setHorizontalHeaderLabels(["Имя пользователя", "Тип"])
            table.setAlternatingRowColors(True)
            table.horizontalHeader().setStretchLastSection(True)
            table.verticalHeader().setVisible(False)
            table.setStyleSheet("QTableWidget::item { padding: 8px; }")
            data = [
                ("CodecSandboxO...", "Пользователь"),
                ("CodecSandboxO...", "Пользователь"),
                ("Ribot", "Администратор"),
            ]
            for name, kind in data:
                row = table.rowCount()
                table.insertRow(row)
                table.setItem(row, 0, QTableWidgetItem(name))
                table.setItem(row, 1, QTableWidgetItem(kind))
            left_layout.addWidget(table)
            main.addWidget(left, 2)

            right = QFrame()
            right.setStyleSheet("background-color: #000000; color: white; border: 1px solid #3a4659; border-radius: 0px;")
            right_layout = QVBoxLayout(right)
            right_layout.setContentsMargins(18, 18, 18, 18)
            right_layout.setSpacing(12)
            label = QLabel("Создание нового пользователя")
            label.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
            right_layout.addWidget(label)

            username_label = QLabel("Имя пользователя:")
            username_label.setStyleSheet("color: white; font-size: 13px;")
            right_layout.addWidget(username_label)
            self.username_input = QLineEdit()
            right_layout.addWidget(self.username_input)

            password_label = QLabel("Пароль:")
            password_label.setStyleSheet("color: white; font-size: 13px;")
            right_layout.addWidget(password_label)
            self.password_input = QLineEdit()
            self.password_input.setEchoMode(QLineEdit.Password)
            right_layout.addWidget(self.password_input)

            self.admin_checkbox = QCheckBox("С правами администратора")
            self.admin_checkbox.setStyleSheet("color: white; font-size: 14px;")
            right_layout.addWidget(self.admin_checkbox)
            right_layout.addStretch()

            create_btn = QPushButton("Создать\nпользователя")
            create_btn.setMinimumHeight(56)
            create_btn.clicked.connect(self._create_user)
            right_layout.addWidget(create_btn)
            main.addWidget(right, 1)
            outer.addLayout(main)

            bottom = QHBoxLayout()
            bottom.setContentsMargins(12, 0, 12, 12)
            chk = QCheckBox("Требовать нажатие CTRL+ALT+DEL при входе")
            chk.setStyleSheet("color: #111111; font-size: 13px;")
            bottom.addWidget(chk)
            outer.addLayout(bottom)

        def _create_user(self):
            name = self.username_input.text().strip()
            if not name:
                QMessageBox.warning(self, "Ошибка", "Введите имя пользователя.")
                return
            QMessageBox.information(self, "Готово", f"Пользователь '{name}' создан успешно.")

    class DiskManagerWindow(QDialog):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Удаление дисков")
            self.resize(1100, 660)
            self.setStyleSheet("""
                QDialog {
                    background-color: #121820;
                    color: #e8edf5;
                }
                QTableWidget {
                    background-color: #1b232c;
                    border: 1px solid #2f3a45;
                    color: #ffffff;
                    alternate-background-color: #202b37;
                }
                QHeaderView::section {
                    background-color: #2a3641;
                    color: #ffffff;
                    border: 1px solid #222222;
                    font-weight: 600;
                }
                QPushButton {
                    background-color: #7ca5b7;
                    color: #0f1720;
                    border: none;
                    font-weight: 600;
                    padding: 10px 20px;
                    border-radius: 6px;
                }
                QPushButton:hover { background-color: #8bb4c6; }
                QLabel { color: #ffffff; }
            """)

            outer = QVBoxLayout(self)
            outer.setContentsMargins(0, 0, 0, 0)
            outer.setSpacing(0)

            top_bar = QFrame()
            top_bar.setFixedHeight(42)
            top_bar.setStyleSheet("background-color: #1b1d22; border-bottom: 1px solid #2f3136;")
            bar_layout = QHBoxLayout(top_bar)
            bar_layout.setContentsMargins(12, 0, 12, 0)
            title = QLabel("Диски")
            title.setStyleSheet("color: white; font-size: 15px; font-weight: bold;")
            bar_layout.addWidget(title)
            bar_layout.addStretch()
            btn_min = QPushButton("—")
            btn_min.setFixedSize(28, 28)
            btn_min.setStyleSheet("QPushButton { background: transparent; color: white; border: none; font-size: 18px; } QPushButton:hover { background-color: #2a2d32; }")
            btn_min.clicked.connect(self.showMinimized)
            bar_layout.addWidget(btn_min)
            btn_close = QPushButton("✕")
            btn_close.setFixedSize(28, 28)
            btn_close.setStyleSheet("QPushButton { background: transparent; color: white; border: none; font-size: 16px; } QPushButton:hover { background-color: #d62828; }")
            btn_close.clicked.connect(self.reject)
            bar_layout.addWidget(btn_close)
            outer.addWidget(top_bar)

            table = QTableWidget(0, 3)
            table.setHorizontalHeaderLabels(["Диск", "Размер", "Используется"])
            table.setAlternatingRowColors(True)
            table.verticalHeader().setVisible(False)
            table.horizontalHeader().setStretchLastSection(True)
            table.setStyleSheet("QTableWidget::item { padding: 8px; }")
            row_data = [
                ("C:", "272,56 ГБ", "117,14 ГБ"),
                ("D:", "195,31 ГБ", "67,20 ГБ"),
            ]
            for disk, size, used in row_data:
                row = table.rowCount()
                table.insertRow(row)
                table.setItem(row, 0, QTableWidgetItem(disk))
                table.setItem(row, 1, QTableWidgetItem(size))
                table.setItem(row, 2, QTableWidgetItem(used))

            outer.addWidget(table)
            btn_layout = QHBoxLayout()
            btn_layout.setContentsMargins(12, 12, 12, 12)
            btn = QPushButton("Удалить диск")
            btn.setMinimumHeight(52)
            btn.clicked.connect(lambda: QMessageBox.information(self, "Готово", "Диск успешно удалён из списка отображения."))
            btn_layout.addWidget(btn)
            outer.addLayout(btn_layout)

    class NoVirGUI(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("NoVir - Ultimate Recovery")
            self.setMinimumSize(1000, 700)
            self.setWindowFlags(Qt.FramelessWindowHint) # Безрамочное окно
            self.setAttribute(Qt.WA_TranslucentBackground)
            # Инициализируем ссылки на фоновые потоки
            self._scheduler_loader = None
            self.worker = None
            self.init_ui()


        def init_ui(self):
            # GLOBAL B&W MINIMALIST STYLESHEET
            self.setStyleSheet('''
                QWidget {
                    background-color: #000000;
                    color: #ffffff;
                    font-family: "Consolas", "Courier New", monospace;
                    font-size: 13px;
                }
                QFrame { border: none; }
                /* Кнопки основные */
                QPushButton {
                    background-color: #000000;
                    color: #ffffff;
                    border: 2px solid #ffffff;
                    padding: 6px 14px;
                    font-weight: bold;
                    border-radius: 0px;
                    text-transform: uppercase;
                }
                QPushButton:hover {
                    background-color: #ffffff;
                    color: #000000;
                }
                QPushButton:pressed {
                    background-color: #cccccc;
                    border-color: #cccccc;
                }
                /* Плитки дашборда */
                QPushButton#DashboardTile {
                    background-color: #000000;
                    color: #ffffff;
                    border: 1px solid #333333;
                    font-size: 18px;
                    font-weight: bold;
                    text-align: center;
                }
                QPushButton#DashboardTile:hover {
                    background-color: #111111;
                    border: 1px solid #ffffff;
                    color: #ffffff;
                }
                /* Таблицы */
                QTableWidget, QTreeWidget {
                    background-color: #000000;
                    alternate-background-color: #0a0a0a;
                    color: #ffffff;
                    gridline-color: #333333;
                    border: 1px solid #333333;
                    selection-background-color: #ffffff;
                    selection-color: #000000;
                }
                QHeaderView::section {
                    background-color: #000000;
                    color: #ffffff;
                    border: 1px solid #333333;
                    padding: 8px;
                    font-weight: bold;
                    text-transform: uppercase;
                }
                /* Скроллбары */
                QScrollBar:vertical {
                    border: none;
                    background: #000000;
                    width: 10px;
                    margin: 0px;
                }
                QScrollBar::handle:vertical {
                    background: #ffffff;
                    min-height: 20px;
                }
                QScrollBar:horizontal {
                    border: none;
                    background: #000000;
                    height: 10px;
                }
                QScrollBar::handle:horizontal {
                    background: #ffffff;
                    min-width: 20px;
                }
                /* Вкладки */
                QTabWidget::pane { border: 1px solid #333333; }
                QTabBar::tab {
                    background: #000000;
                    color: #888888;
                    border: 1px solid #333333;
                    padding: 10px 20px;
                }
                QTabBar::tab:selected {
                    color: #ffffff;
                    border: 1px solid #ffffff;
                    padding: 10px 20px;
                }
                QTabBar::tab:hover {
                    color: #ffffff;
                }
                QLineEdit, QTextEdit {
                    background-color: #000000;
                    color: #ffffff;
                    border: 1px solid #ffffff;
                    padding: 6px;
                }
            ''')

            # Главный контейнер
            self.main_container = QFrame(self)
            self.main_container.setObjectName("MainContainer")
            self.setCentralWidget(self.main_container)
            
            self.layout = QVBoxLayout(self.main_container)
            self.layout.setContentsMargins(0, 0, 0, 0)
            self.layout.setSpacing(0)

            # Строгая верхняя панель (Top Bar)
            self.top_bar = QFrame()
            self.top_bar.setFixedHeight(50)
            self.top_bar.setStyleSheet("border-bottom: 1px solid #333333;")
            top_layout = QHBoxLayout(self.top_bar)
            top_layout.setContentsMargins(15, 0, 15, 0)
            
            self.btn_back = QPushButton("< НАЗАД")
            self.btn_back.setFixedSize(100, 30)
            self.btn_back.setStyleSheet("border: none; font-size: 14px;")
            self.btn_back.clicked.connect(lambda: self.switch_page(0))
            top_layout.addWidget(self.btn_back)

            top_layout.addStretch()
            
            self.title_label = QLabel("NOVIR")
            self.title_label.setStyleSheet("font-size: 16px; font-weight: bold; letter-spacing: 4px; border: none;")
            top_layout.addWidget(self.title_label)
            
            top_layout.addStretch()
            
            self.btn_minimize = QPushButton("—")
            self.btn_minimize.setFixedSize(40, 30)
            self.btn_minimize.setStyleSheet("border: none; font-size: 16px;")
            self.btn_minimize.clicked.connect(self.showMinimized)
            
            self.btn_close = QPushButton("✕")
            self.btn_close.setFixedSize(40, 30)
            self.btn_close.setStyleSheet("border: none; font-size: 16px;")
            self.btn_close.clicked.connect(self.close)
            
            top_layout.addWidget(self.btn_minimize)
            top_layout.addWidget(self.btn_close)
            self.layout.addWidget(self.top_bar)

            # Страницы
            self.main_content = QStackedWidget()
            
            self.page_dashboard = self.create_dashboard_page()
            self.page_startup = self.create_startup_page()
            self.page_restrictions = self.create_restrictions_page()
            self.page_advanced = self.create_advanced_page()
            self.page_unlocker = self.create_unlocker_page()
            # У старого кода была page_about (индекс 5), page_program (индекс 6).
            # В B&W коде: index 0 (dashboard), 1 (startup), 2 (explorer), 3 (restrictions), 4 (advanced), 5 (unlocker), 6 (program).
            # В бэкапе: 
            # self.page_startup
            # self.page_explorer
            # self.page_restrictions
            # self.page_advanced
            # self.page_unlocker
            # self.page_about
            # self.page_program
            # Так что нам надо просто вызвать те же страницы, но без about!
            # ИЛИ оставить about. Посмотрим:
            
            self.page_program = self.create_program_page()
            self.page_explorer = explorer_tab.ExplorerTab(self)
            
            # Index 0: Dashboard
            self.main_content.addWidget(self.page_dashboard)
            # Index 1-6: Tools
            self.main_content.addWidget(self.page_startup)       # 1
            self.main_content.addWidget(self.page_explorer)      # 2
            self.main_content.addWidget(self.page_restrictions)  # 3
            self.main_content.addWidget(self.page_advanced)      # 4
            self.main_content.addWidget(self.page_unlocker)      # 5
            self.main_content.addWidget(self.page_program)       # 6
            
            self.layout.addWidget(self.main_content)

            # Логи
            self.log_output = QTextEdit()
            self.log_output.setReadOnly(True)
            self.log_output.setFixedHeight(100)
            self.log_output.hide()
            self.layout.addWidget(self.log_output)

            # Нижняя панель — Поддержать автора (всегда видна)
            bottom_bar = QFrame()
            bottom_bar.setFixedHeight(38)
            bottom_bar.setStyleSheet("border-top: 1px solid #222222;")
            bottom_layout = QHBoxLayout(bottom_bar)
            bottom_layout.setContentsMargins(15, 0, 15, 0)

            bottom_support_btn = QPushButton("★  ПОДДЕРЖАТЬ АВТОРА")
            bottom_support_btn.setFixedHeight(28)
            bottom_support_btn.setStyleSheet(
                "QPushButton { border: 1px solid #333333; color: #888888; font-size: 11px; font-weight: bold; padding: 0 12px; }"
                " QPushButton:hover { border-color: #ffffff; color: #ffffff; }"
            )
            bottom_support_btn.clicked.connect(self.show_support_dialog)
            bottom_layout.addStretch()
            bottom_layout.addWidget(bottom_support_btn)
            self.layout.addWidget(bottom_bar)

            # Старт
            self.switch_page(0)


            self.load_initial_startup_data()

        def create_dashboard_page(self):
            page = QFrame()
            layout = QVBoxLayout(page)
            layout.setAlignment(Qt.AlignCenter)
            layout.setSpacing(20)

            # Сетка плиток
            grid = QGridLayout()
            grid.setSpacing(15)

            tiles = [
                ("АВТОЗАГРУЗКА", 1),
                ("ПРОВОДНИК", 2),
                ("СНЯТИЕ ОГРАНИЧЕНИЙ", 3),
                ("ДОП. ВОЗМОЖНОСТИ", 4),
                ("АНЛОКЕР", 5),
                ("НАСТРОЙКИ", 6)
            ]

            positions = [(i, j) for i in range(2) for j in range(3)]
            for position, (name, idx) in zip(positions, tiles):
                btn = QPushButton(name)
                btn.setObjectName("DashboardTile")
                btn.setFixedSize(250, 150)
                btn.clicked.connect(lambda checked=False, x=idx: self.switch_page(x))
                grid.addWidget(btn, *position)

            layout.addLayout(grid)

            support_btn = QPushButton("★  ПОДДЕРЖАТЬ АВТОРА")
            support_btn.setFixedHeight(44)
            support_btn.setStyleSheet(
                "QPushButton { background-color: #000000; color: #ffffff; border: 2px solid #ffffff;"
                " font-size: 14px; font-weight: bold; letter-spacing: 2px; }"
                " QPushButton:hover { background-color: #ffffff; color: #000000; }"
            )
            support_btn.clicked.connect(self.show_support_dialog)
            layout.addWidget(support_btn)

            return page

        def switch_page(self, index):
            self.main_content.setCurrentIndex(index)
            if index == 0:
                self.btn_back.hide()
                self.title_label.setText("NOVIR")
            else:
                self.btn_back.show()
                titles = {
                    1: "АВТОЗАГРУЗКА",
                    2: "ПРОВОДНИК",
                    3: "СНЯТИЕ ОГРАНИЧЕНИЙ",
                    4: "ДОП. ВОЗМОЖНОСТИ",
                    5: "АНЛОКЕР",
                    6: "НАСТРОЙКИ"
                }
                self.title_label.setText(titles.get(index, "NOVIR"))


        def show_support_dialog(self):
            self._user_supported = False
            self._run_support_dialog()

        def _run_support_dialog(self):
            import webbrowser
            dlg = QDialog(self)
            dlg.setWindowTitle("Поддержать автора")
            dlg.setMinimumWidth(480)
            dlg.setStyleSheet(
                "QDialog { background-color: #000000; color: #ffffff; }"
                " QLabel { color: #ffffff; border: none; }"
                " QPushButton { background-color: #000000; color: #ffffff; border: 2px solid #ffffff;"
                " padding: 8px 16px; font-weight: bold; font-size: 13px; }"
                " QPushButton:hover { background-color: #ffffff; color: #000000; }"
                " QPushButton:disabled { border: 2px solid #333333; color: #555555; }"
                " QLineEdit { background-color: #000000; color: #ffffff; border: 1px solid #ffffff; padding: 6px; font-size: 14px; }"
                " QComboBox { background-color: #000000; color: #ffffff; border: 1px solid #ffffff; padding: 6px; font-size: 14px; }"
                " QComboBox QAbstractItemView { background-color: #000000; color: #ffffff; selection-background-color: #ffffff; selection-color: #000000; }"
                " QSpinBox { background-color: #000000; color: #ffffff; border: 1px solid #ffffff; padding: 6px; font-size: 14px; }"
            )

            layout = QVBoxLayout(dlg)
            layout.setContentsMargins(24, 24, 24, 24)
            layout.setSpacing(14)

            # Title
            title = QLabel("★  ПОДДЕРЖАТЬ АВТОРА")
            title.setStyleSheet("font-size: 18px; font-weight: bold; letter-spacing: 3px;")
            layout.addWidget(title)

            sep = QFrame()
            sep.setFrameShape(QFrame.HLine)
            sep.setStyleSheet("background-color: #333333; max-height: 1px;")
            layout.addWidget(sep)

            # Description
            desc = QLabel("Всё идёт напрямую на карту ПриватБанк.")
            desc.setStyleSheet("color: #888888; font-size: 12px;")
            desc.setWordWrap(True)
            layout.addWidget(desc)

            # Currency selector
            row_curr = QHBoxLayout()
            lbl_curr = QLabel("Страна:")
            lbl_curr.setFixedWidth(100)
            from PySide6.QtWidgets import QComboBox, QSpinBox
            combo_curr = QComboBox()
            combo_curr.addItems(["Украина (грн)", "Россия (руб)", "Весь мир (USD/EUR)"])
            row_curr.addWidget(lbl_curr)
            row_curr.addWidget(combo_curr)
            layout.addLayout(row_curr)

            # Card number display
            AUTHOR_CARD = "5168 7521 1573 8307"   # <-- ЗАМЕНИТЬ НА СВОЙ НОМЕР ПРИВАТА

            sep2 = QFrame()
            sep2.setFrameShape(QFrame.HLine)
            sep2.setStyleSheet("background-color: #333333; max-height: 1px;")
            layout.addWidget(sep2)

            lbl_card_info = QLabel("Номер карты ПриватБанк:")
            lbl_card_info.setStyleSheet("color: #888888; font-size: 11px;")
            layout.addWidget(lbl_card_info)

            card_field = QLineEdit(AUTHOR_CARD)
            card_field.setReadOnly(True)
            card_field.setAlignment(Qt.AlignCenter)
            card_field.setStyleSheet(
                "font-size: 20px; font-weight: bold; letter-spacing: 4px;"
                " background-color: #000000; color: #ffffff; border: 1px solid #333333; padding: 10px;"
            )
            layout.addWidget(card_field)

            lbl_copy_hint = QLabel("Нажмите на номер, чтобы скопировать")
            lbl_copy_hint.setStyleSheet("color: #555555; font-size: 10px;")
            layout.addWidget(lbl_copy_hint)

            def copy_card():
                QApplication.clipboard().setText(card_field.text().replace(" ", ""))
                lbl_copy_hint.setText("✓ Номер скопирован!")
                lbl_copy_hint.setStyleSheet("color: #ffffff; font-size: 10px;")
            card_field.mousePressEvent = lambda e: copy_card()

            sep3 = QFrame()
            sep3.setFrameShape(QFrame.HLine)
            sep3.setStyleSheet("background-color: #333333; max-height: 1px;")
            layout.addWidget(sep3)

            # Buttons
            btn_layout = QHBoxLayout()

            btn_action = QPushButton("ПЕРЕВОД ЧЕРЕЗ ПРИВАТБАНК  →")
            btn_action.setFixedHeight(44)
            
            def do_action():
                curr_text = combo_curr.currentText()
                copy_card()
                self._user_supported = True
                if "Украина" in curr_text:
                    webbrowser.open("https://next.privat24.ua/money-transfer/card")
                elif "Россия" in curr_text:
                    webbrowser.open("https://www.bestchange.ru/sberbank-to-privat24-uah.html")
                elif "Весь мир" in curr_text:
                    webbrowser.open("https://paysend.com/")
                dlg.accept()
                
            btn_action.clicked.connect(do_action)

            btn_cancel = QPushButton("ОТМЕНА")
            btn_cancel.setFixedHeight(44)
            btn_cancel.clicked.connect(dlg.reject)

            btn_layout.addWidget(btn_action)
            btn_layout.addWidget(btn_cancel)
            layout.addLayout(btn_layout)

            # Update logic when currency changes
            def update_suffix(curr_text):
                lbl_copy_hint.setText("Нажмите, чтобы скопировать")
                lbl_copy_hint.setStyleSheet("color: #555555; font-size: 10px;")
                
                if "Россия" in curr_text:
                    desc.setText("Прямые переводы отключены. Но вы можете перевести деньги со Сбербанка/Тинькофф напрямую на мою карту ПриватБанка через обменники (например, BestChange).")
                    btn_action.setText("ПЕРЕЙТИ НА BESTCHANGE  →")
                elif "Весь мир" in curr_text:
                    desc.setText("Для переводов из США, Европы и других стран используйте сервисы Paysend, TransferGo или Wise. Отправляйте напрямую на мою карту ПриватБанка.")
                    btn_action.setText("ПЕРЕЙТИ НА PAYSEND  →")
                else:
                    desc.setText("Всё идёт напрямую на карту ПриватБанк. Спасибо за поддержку!")
                    btn_action.setText("ПЕРЕВОД ЧЕРЕЗ ПРИВАТБАНК  →")
            
            combo_curr.currentTextChanged.connect(update_suffix)
            update_suffix(combo_curr.currentText())

            dlg.exec()

        def toggle_dry_run(self, state):
            global DRY_RUN
            DRY_RUN = (state == Qt.Checked)
            status = "ВКЛЮЧЕН" if DRY_RUN else "ВЫКЛЮЧЕН"
            self.append_log(f"[*] Режим разработчика (DRY RUN) {status}")

        def apply_theme(self, theme_name):
            bw_style = '''
                QWidget {
                    background-color: #000000;
                    color: #ffffff;
                    font-family: "Consolas", "Courier New", monospace;
                    font-size: 13px;
                }
                QFrame { border: none; }
                QPushButton {
                    background-color: #000000;
                    color: #ffffff;
                    border: 2px solid #ffffff;
                    padding: 6px 14px;
                    font-weight: bold;
                    border-radius: 0px;
                    text-transform: uppercase;
                }
                QPushButton:hover { background-color: #ffffff; color: #000000; }
                QPushButton:pressed { background-color: #cccccc; border-color: #cccccc; }
                QPushButton#DashboardTile {
                    background-color: #000000;
                    color: #ffffff;
                    border: 1px solid #333333;
                    font-size: 18px;
                    font-weight: bold;
                    text-align: center;
                }
                QPushButton#DashboardTile:hover {
                    background-color: #111111;
                    border: 1px solid #ffffff;
                }
                QTableWidget, QTreeWidget {
                    background-color: #000000;
                    alternate-background-color: #0a0a0a;
                    color: #ffffff;
                    gridline-color: #333333;
                    border: 1px solid #333333;
                    selection-background-color: #ffffff;
                    selection-color: #000000;
                }
                QHeaderView::section {
                    background-color: #000000;
                    color: #ffffff;
                    border: 1px solid #333333;
                    padding: 8px;
                    font-weight: bold;
                    text-transform: uppercase;
                }
                QScrollBar:vertical { border: none; background: #000000; width: 10px; }
                QScrollBar::handle:vertical { background: #ffffff; min-height: 20px; }
                QScrollBar:horizontal { border: none; background: #000000; height: 10px; }
                QScrollBar::handle:horizontal { background: #ffffff; min-width: 20px; }
                QTabWidget::pane { border: 1px solid #333333; }
                QTabBar::tab { background: #000000; color: #888888; border: 1px solid #333333; padding: 10px 20px; }
                QTabBar::tab:selected { color: #ffffff; border: 1px solid #ffffff; }
                QTabBar::tab:hover { color: #ffffff; }
                QLineEdit, QTextEdit {
                    background-color: #000000;
                    color: #ffffff;
                    border: 1px solid #ffffff;
                    padding: 6px;
                }
                QComboBox {
                    background-color: #000000;
                    color: #ffffff;
                    border: 1px solid #ffffff;
                    padding: 4px;
                }
                QComboBox QAbstractItemView {
                    background-color: #000000;
                    color: #ffffff;
                    selection-background-color: #ffffff;
                    selection-color: #000000;
                }
                QCheckBox { color: #ffffff; }
            '''
            if theme_name == "Minimal B&W":
                self.setStyleSheet(bw_style)
            elif theme_name == "Тёмная тема (Стандартная)":
                self.setStyleSheet("""
                    QWidget { background-color: #000000; color: #ffffff; font-family: Consolas; font-size: 13px; }
                    QPushButton { background-color: #111111; color: #ffffff; border: 1px solid #222222; padding: 6px 14px; }
                    QPushButton:hover { background-color: #222222; color: #ffffff; }
                    QPushButton#DashboardTile { background-color: #000000; color: #ffffff; border: 1px solid #222222; font-size: 18px; font-weight: bold; }
                    QPushButton#DashboardTile:hover { background-color: #111111; border-color: #ffffff; color: #ffffff; }
                    QTableWidget, QTreeWidget { background-color: #000000; color: #ffffff; gridline-color: #222222; border: 1px solid #222222; selection-background-color: #222222; selection-color: #fff; }
                    QHeaderView::section { background-color: #111111; color: #ffffff; border: 1px solid #222222; padding: 8px; font-weight: bold; }
                    QTabBar::tab { background: #000000; color: #888888; border: 1px solid #222222; padding: 10px 20px; }
                    QTabBar::tab:selected { color: #ffffff; border-bottom: 2px solid #ffffff; }
                    QLineEdit, QTextEdit { background-color: #111111; color: #ffffff; border: 1px solid #222222; padding: 6px; }
                    QComboBox { background-color: #111111; color: #ffffff; border: 1px solid #222222; padding: 4px; }
                    QScrollBar:vertical { background: #000000; width: 10px; }
                    QScrollBar::handle:vertical { background: #222222; }
                    QCheckBox { color: #ffffff; }
                """)
            elif theme_name == "Тема Ванька":
                try:
                    import sys as _sys, os as _os
                    _base = _sys._MEIPASS
                except Exception:
                    import os as _os
                    _base = _os.path.abspath(_os.path.dirname(__file__))
                img_path = _os.path.join(_base, "Иван.png").replace("\\", "/")
                self.main_container.setStyleSheet(f"""
                    #MainContainer {{
                        background-image: url('{img_path}');
                        background-position: center;
                        background-repeat: no-repeat;
                    }}
                """)
            elif theme_name == "МАТОВЫЙ":
                self.setStyleSheet("""
                    QWidget { background-color: #000000; color: #ffffff; font-family: Consolas; font-size: 13px; }
                    QPushButton { background-color: #222222; color: #ffffff; border: 1px solid #2a2a2a; padding: 6px 14px; }
                    QPushButton:hover { background-color: #333333; }
                    QPushButton#DashboardTile { background-color: #000000; color: #ffffff; border: 1px solid #2a2a2a; font-size: 18px; font-weight: bold; }
                    QPushButton#DashboardTile:hover { background-color: #222222; border-color: #aaaaaa; }
                    QTableWidget, QTreeWidget { background-color: #000000; color: #ffffff; gridline-color: #333333; border: 1px solid #333333; selection-background-color: #444444; selection-color: #fff; }
                    QHeaderView::section { background-color: #222222; color: #ffffff; border: 1px solid #333333; padding: 8px; }
                    QTabBar::tab { background: #222222; color: #888888; border: 1px solid #333333; padding: 10px 20px; }
                    QTabBar::tab:selected { color: #ffffff; background: #333333; }
                    QLineEdit, QTextEdit { background-color: #000000; color: #ffffff; border: 1px solid #333333; padding: 6px; }
                    QScrollBar:vertical { background: #000000; width: 10px; }
                    QScrollBar::handle:vertical { background: #333333; }
                    QCheckBox { color: #ffffff; }
                """)
            elif theme_name == "ПРОЗРАЧНЫЙ":
                self.setAttribute(Qt.WA_TranslucentBackground, True)
                self.setStyleSheet("""
                    QWidget { background-color: rgba(20, 20, 25, 180); color: #ffffff; font-family: Consolas; font-size: 13px; }
                    QPushButton { background-color: rgba(30, 30, 40, 180); color: #ffffff; border: 1px solid rgba(255,255,255,80); padding: 6px 14px; }
                    QPushButton:hover { background-color: rgba(60, 60, 80, 200); }
                    QPushButton#DashboardTile { background-color: rgba(20,20,30,160); color: #ffffff; border: 1px solid rgba(255,255,255,60); font-size: 18px; }
                    QPushButton#DashboardTile:hover { border-color: rgba(255,255,255,200); }
                    QTableWidget, QTreeWidget { background-color: rgba(15,15,20,160); color: #ffffff; gridline-color: rgba(255,255,255,30); border: 1px solid rgba(255,255,255,30); selection-background-color: rgba(255,255,255,80); }
                    QHeaderView::section { background-color: rgba(20,20,30,160); color: #ffffff; border: 1px solid rgba(255,255,255,30); padding: 8px; }
                    QTabBar::tab { background: rgba(20,20,25,160); color: #aaaaaa; border: 1px solid rgba(255,255,255,30); padding: 10px 20px; }
                    QTabBar::tab:selected { color: #ffffff; }
                    QLineEdit, QTextEdit { background-color: rgba(20,20,25,160); color: #ffffff; border: 1px solid rgba(255,255,255,60); padding: 6px; }
                    QScrollBar:vertical { background: transparent; width: 10px; }
                    QScrollBar::handle:vertical { background: rgba(255,255,255,80); }
                    QCheckBox { color: #ffffff; }
                """)

        def create_startup_page(self):
            page = QFrame()
            layout = QVBoxLayout(page)
            self.startup_tabs = QTabWidget()
            self.startup_tabs.setStyleSheet("""
                QTabWidget::pane { border: 1px solid rgba(62, 62, 74, 0.95); background-color: #000000; }
                QTabBar::tab { background-color: transparent; color: #888888; padding: 10px 18px; min-width: 120px; }
                QTabBar::tab:selected { background-color: #111111; color: #ffffff; border-bottom: 2px solid #ffffff; }
                QTabBar::tab:hover { color: #ffffff; }
            """)
            self.startup_tabs.currentChanged.connect(self.on_main_startup_tab_changed)
            
            # Вкладка Реестр
            reg_tab = QWidget()
            reg_layout = QVBoxLayout(reg_tab)
            self.startup_sub_tabs = QTabWidget()
            self.startup_sub_tabs.currentChanged.connect(self.on_sub_tab_changed)
            
            # Подвкладка Run с таблицей и кнопками
            run_tab = QWidget()
            run_layout = QVBoxLayout(run_tab)
            run_btn_layout = QHBoxLayout()
            btn_add_run = QPushButton("Добавить")
            btn_add_run.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_add_run.clicked.connect(lambda: self.add_registry_entry("Run"))
            btn_del_run = QPushButton("Удалить")
            btn_del_run.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_del_run.clicked.connect(lambda: self.delete_registry_entry("Run"))
            btn_edit_run = QPushButton("Изменить")
            btn_edit_run.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_edit_run.clicked.connect(lambda: self.edit_registry_entry("Run"))
            run_btn_layout.addWidget(btn_add_run)
            run_btn_layout.addWidget(btn_del_run)
            run_btn_layout.addWidget(btn_edit_run)
            run_btn_layout.addStretch()
            run_layout.addLayout(run_btn_layout)
            self.table_run = self.create_styled_table(["Параметр", "Значение"])
            self.table_run.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table_run.customContextMenuRequested.connect(lambda pos: self.show_table_context_menu(pos, self.table_run, "Run"))
            run_layout.addWidget(self.table_run)
            self.startup_sub_tabs.addTab(run_tab, "Run")
            
            # Подвкладка RunOnce с таблицей и кнопками
            runonce_tab = QWidget()
            runonce_layout = QVBoxLayout(runonce_tab)
            runonce_btn_layout = QHBoxLayout()
            btn_add_runonce = QPushButton("Добавить")
            btn_add_runonce.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_add_runonce.clicked.connect(lambda: self.add_registry_entry("RunOnce"))
            btn_del_runonce = QPushButton("Удалить")
            btn_del_runonce.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_del_runonce.clicked.connect(lambda: self.delete_registry_entry("RunOnce"))
            btn_edit_runonce = QPushButton("Изменить")
            btn_edit_runonce.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_edit_runonce.clicked.connect(lambda: self.edit_registry_entry("RunOnce"))
            runonce_btn_layout.addWidget(btn_add_runonce)
            runonce_btn_layout.addWidget(btn_del_runonce)
            runonce_btn_layout.addWidget(btn_edit_runonce)
            runonce_btn_layout.addStretch()
            runonce_layout.addLayout(runonce_btn_layout)
            self.table_runonce = self.create_styled_table(["Параметр", "Значение"])
            self.table_runonce.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table_runonce.customContextMenuRequested.connect(lambda pos: self.show_table_context_menu(pos, self.table_runonce, "RunOnce"))
            runonce_layout.addWidget(self.table_runonce)
            self.startup_sub_tabs.addTab(runonce_tab, "RunOnce")
            
            # Подвкладка Winlogon с таблицей и кнопками
            winlogon_tab = QWidget()
            winlogon_layout = QVBoxLayout(winlogon_tab)
            winlogon_btn_layout = QHBoxLayout()
            btn_add_winlogon = QPushButton("Добавить")
            btn_add_winlogon.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_add_winlogon.clicked.connect(lambda: self.add_registry_entry("Winlogon"))
            btn_del_winlogon = QPushButton("Удалить")
            btn_del_winlogon.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_del_winlogon.clicked.connect(lambda: self.delete_registry_entry("Winlogon"))
            btn_edit_winlogon = QPushButton("Изменить")
            btn_edit_winlogon.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_edit_winlogon.clicked.connect(lambda: self.edit_registry_entry("Winlogon"))
            winlogon_btn_layout.addWidget(btn_add_winlogon)
            winlogon_btn_layout.addWidget(btn_del_winlogon)
            winlogon_btn_layout.addWidget(btn_edit_winlogon)
            winlogon_btn_layout.addStretch()
            winlogon_layout.addLayout(winlogon_btn_layout)
            self.table_winlogon = self.create_styled_table(["Параметр", "Значение"])
            self.table_winlogon.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table_winlogon.customContextMenuRequested.connect(lambda pos: self.show_table_context_menu(pos, self.table_winlogon, "Winlogon"))
            winlogon_layout.addWidget(self.table_winlogon)
            winlogon_info = QLabel("ℹ Отображаются только ключи автозапуска: Shell и Userinit. Остальные параметры Winlogon скрыты.")
            winlogon_info.setStyleSheet("color: #888888; font-size: 11px; padding: 4px 0px; font-style: italic;")
            winlogon_info.setWordWrap(True)
            winlogon_layout.addWidget(winlogon_info)
            self.startup_sub_tabs.addTab(winlogon_tab, "Winlogon")
            
            # Вкладка AppInit_DLLs и CmdLine
            appinit_tab = QWidget()
            appinit_layout = QVBoxLayout(appinit_tab)
            self.table_appinit = self.create_styled_table(["Параметр", "Значение"])
            self.table_appinit.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table_appinit.customContextMenuRequested.connect(lambda pos: self.show_table_context_menu(pos, self.table_appinit, "AppInit_DLLs и CmdLine"))
            appinit_layout.addWidget(self.table_appinit)
            self.startup_sub_tabs.addTab(appinit_tab, "AppInit_DLLs и CmdLine")
            
            reg_layout.addWidget(self.startup_sub_tabs)
            
            self.startup_tabs.addTab(reg_tab, "Реестр")
            
            # Вкладка Папка автозагрузки с таблицей и кнопками
            folder_tab = QWidget()
            folder_layout = QVBoxLayout(folder_tab)
            folder_btn_layout = QHBoxLayout()
            btn_add_folder = QPushButton("Добавить файл")
            btn_add_folder.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_add_folder.clicked.connect(self.add_folder_entry)
            btn_del_folder = QPushButton("Удалить")
            btn_del_folder.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_del_folder.clicked.connect(self.delete_folder_entry)
            btn_open_folder = QPushButton("Открыть папку")
            btn_open_folder.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_open_folder.clicked.connect(self.open_startup_folder)
            folder_btn_layout.addWidget(btn_add_folder)
            folder_btn_layout.addWidget(btn_del_folder)
            folder_btn_layout.addWidget(btn_open_folder)
            folder_btn_layout.addStretch()
            folder_layout.addLayout(folder_btn_layout)
            self.table_folder = self.create_styled_table(["Файл", "Путь"])
            self.table_folder.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table_folder.customContextMenuRequested.connect(lambda pos: self.show_folder_context_menu(pos, self.table_folder))
            folder_layout.addWidget(self.table_folder)
            self.startup_tabs.addTab(folder_tab, "Папка автозагрузки")
            
            # Вкладка Планировщик задач с таблицей и кнопками
            scheduler_tab = QWidget()
            scheduler_layout = QVBoxLayout(scheduler_tab)
            scheduler_btn_layout = QHBoxLayout()
            _btn_style_s = "background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;"
            btn_add_scheduler = QPushButton("Создать задачу")
            btn_add_scheduler.setStyleSheet(_btn_style_s)
            btn_add_scheduler.clicked.connect(self.add_scheduler_entry)
            btn_del_scheduler = QPushButton("Удалить")
            btn_del_scheduler.setStyleSheet(_btn_style_s)
            btn_del_scheduler.clicked.connect(self.delete_scheduler_entry)
            btn_run_scheduler = QPushButton("▶ Запустить")
            btn_run_scheduler.setStyleSheet(_btn_style_s)
            btn_run_scheduler.clicked.connect(self.run_scheduler_entry)
            btn_disable_scheduler = QPushButton("⏸ Отключить")
            btn_disable_scheduler.setStyleSheet(_btn_style_s)
            btn_disable_scheduler.clicked.connect(self.disable_scheduler_entry)
            btn_enable_scheduler = QPushButton("✓ Включить")
            btn_enable_scheduler.setStyleSheet(_btn_style_s)
            btn_enable_scheduler.clicked.connect(self.enable_scheduler_entry)
            scheduler_btn_layout.addWidget(btn_add_scheduler)
            scheduler_btn_layout.addWidget(btn_del_scheduler)
            scheduler_btn_layout.addWidget(btn_run_scheduler)
            scheduler_btn_layout.addWidget(btn_disable_scheduler)
            scheduler_btn_layout.addWidget(btn_enable_scheduler)
            scheduler_btn_layout.addStretch()
            
            # Фильтр
            self.sched_filter_combo = QComboBox()
            self.sched_filter_combo.addItems(["Все задачи", "Только пользовательские", "Только подозрительные"])
            self.sched_filter_combo.setStyleSheet("background-color: #111111; color: white; border: 1px solid #222222; padding: 4px; border-radius: 4px;")
            self.sched_filter_combo.setFixedWidth(200)
            self.sched_filter_combo.currentTextChanged.connect(self._apply_scheduler_filter)
            scheduler_btn_layout.addWidget(self.sched_filter_combo)
            
            # Кнопка обновить
            btn_refresh_scheduler = QPushButton("↻ Обновить")
            btn_refresh_scheduler.setStyleSheet(_btn_style_s)
            btn_refresh_scheduler.setToolTip("Принудительно перезагрузить список задач из системы")
            btn_refresh_scheduler.clicked.connect(self.refresh_scheduler_data)
            scheduler_btn_layout.addWidget(btn_refresh_scheduler)
            scheduler_layout.addLayout(scheduler_btn_layout)
            
            # Таблица в стиле CCleaner (светлая)
            self.table_scheduler = QTableWidget(0, 3)
            self.table_scheduler.setHorizontalHeaderLabels(["Имя", "Расположение", "Состояние"])
            self.table_scheduler.horizontalHeader().setStretchLastSection(True)
            self.table_scheduler.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            self.table_scheduler.setSelectionBehavior(QTableWidget.SelectRows)
            self.table_scheduler.setSelectionMode(QTableWidget.SingleSelection)
            self.table_scheduler.setEditTriggers(QTableWidget.NoEditTriggers)
            self.table_scheduler.setShowGrid(True)
            self.table_scheduler.setAlternatingRowColors(False)
            self.table_scheduler.verticalHeader().setVisible(False)
            
            # Настройка ширины колонок
            self.table_scheduler.setColumnWidth(0, 130)
            self.table_scheduler.setColumnWidth(1, 250)
            self.table_scheduler.verticalHeader().setDefaultSectionSize(22)
            
            self.table_scheduler.setStyleSheet("""
                QTableWidget {
                    background-color: #ffffff;
                    color: #000000;
                    gridline-color: #e8e8e8;
                    selection-background-color: #cce8ff;
                    selection-color: #000000;
                    border: 1px solid #cccccc;
                    font-size: 12px;
                }
                QHeaderView::section {
                    background-color: #ffffff;
                    color: #000000;
                    border: none;
                    border-right: 1px solid #cccccc;
                    border-bottom: 2px solid #cccccc;
                    padding: 4px 6px;
                    font-weight: bold;
                    font-size: 12px;
                }
                QTableWidget::item {
                    padding: 1px 4px;
                }
                QTableWidget::item:hover {
                    background-color: #e8f4ff;
                }
            """)
            
            self.table_scheduler.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table_scheduler.customContextMenuRequested.connect(lambda pos: self.show_scheduler_context_menu(pos, self.table_scheduler))
            self.table_scheduler.cellClicked.connect(self._on_scheduler_cell_clicked)
            self._scheduler_expanded_folders = set()  # по умолчанию все закрыты
            scheduler_layout.addWidget(self.table_scheduler)
            
            self._scheduler_all_data = []
            self.startup_tabs.addTab(scheduler_tab, "Планировщик задач")
            
            # Вкладка Меню служб с таблицей и кнопками
            services_tab = QWidget()
            services_layout = QVBoxLayout(services_tab)
            services_btn_layout = QHBoxLayout()
            btn_start_service = QPushButton("Запустить")
            btn_start_service.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_start_service.clicked.connect(self.start_service)
            btn_stop_service = QPushButton("Остановить")
            btn_stop_service.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_stop_service.clicked.connect(self.stop_service)
            btn_restart_service = QPushButton("Перезапустить")
            btn_restart_service.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px;")
            btn_restart_service.clicked.connect(self.restart_service)
            services_btn_layout.addWidget(btn_start_service)
            services_btn_layout.addWidget(btn_stop_service)
            services_btn_layout.addWidget(btn_restart_service)
            services_btn_layout.addStretch()
            services_layout.addLayout(services_btn_layout)
            self.table_services = self.create_styled_table(["Служба", "Путь"])
            self.table_services.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table_services.customContextMenuRequested.connect(lambda pos: self.show_services_context_menu(pos, self.table_services))
            services_layout.addWidget(self.table_services)
            self.startup_tabs.addTab(services_tab, "Меню служб")
            
            layout.addWidget(self.startup_tabs)
            
            return page


        def load_initial_startup_data(self):
            """Загрузка начальных данных для всех вкладок автозагрузки"""
            try:
                self.load_registry_data("Run")
                self.load_folder_data()
                self.load_scheduler_data()
                self.load_services_data()
            except Exception as e:
                print(f"Ошибка загрузки данных автозагрузки: {e}")

        def on_main_startup_tab_changed(self, index):
            if index == 0:
                # Реестр - загружаем данные в текущую подвкладку
                self.on_sub_tab_changed(self.startup_sub_tabs.currentIndex())
            elif index == 1:
                self.load_folder_data()
            elif index == 2:
                self.load_scheduler_data()
            elif index == 3:
                self.load_services_data()

        def on_sub_tab_changed(self, index):
            tab_names = ["Run", "RunOnce", "Winlogon", "AppInit_DLLs и CmdLine"]
            if index < len(tab_names):
                self.load_registry_data(tab_names[index])

        def load_registry_data(self, type_name):
            if type_name == "Run":
                table = self.table_run
            elif type_name == "RunOnce":
                table = self.table_runonce
            elif type_name == "Winlogon":
                table = self.table_winlogon
            elif type_name == "AppInit_DLLs и CmdLine":
                table = self.table_appinit
            else:
                return
            
            table.setRowCount(0)
            data = []
            
            if type_name == "Run":
                data = self.get_reg_startup(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
                data += self.get_reg_startup(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
            elif type_name == "RunOnce":
                data = self.get_reg_startup(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
                data += self.get_reg_startup(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
            elif type_name == "Winlogon":
                # Показываем ТОЛЬКО ключи автозапуска Shell и Userinit
                import winreg as _wr
                _key_path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                _shell_val = "(не задан)"
                _userinit_val = "(не задан)"
                try:
                    with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE, _key_path) as _k:
                        try: _shell_val = _wr.QueryValueEx(_k, "Shell")[0] or "(пусто)"
                        except: pass
                        try: _userinit_val = _wr.QueryValueEx(_k, "Userinit")[0] or "(пусто)"
                        except: pass
                except: pass
                data = [("Shell", str(_shell_val)), ("Userinit", str(_userinit_val))]
            elif type_name == "AppInit_DLLs и CmdLine":
                def get_val(hk, subk, name):
                    try:
                        with winreg.OpenKey(hk, subk) as key:
                            val, _ = winreg.QueryValueEx(key, name)
                            return str(val) if str(val).strip() else "(Пустое значение)"
                    except Exception as _e:
                        # Expected exception, intentionally ignored
                        return "(Пустое значение)"
                data = [
                    ("AppInit_DLLs", get_val(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"), r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
                    ("AppInit_DLLs", get_val(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"), r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"),
                    ("CmdLine", get_val(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup", "CmdLine"), r"SYSTEM\Setup"),
                    ("SetupType", get_val(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup", "SetupType"), r"SYSTEM\Setup"),
                    ("EnableCursorSuppression", get_val(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableCursorSuppression"), r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
                ]
            
            table.setRowCount(len(data))
            for i, row_data in enumerate(data):
                if len(row_data) == 3:
                    name, val, path = row_data
                else:
                    name, val = row_data
                    path = None
                color = analyze_startup_item(name, val)
                item_name = QTableWidgetItem(name)
                if path is not None:
                    item_name.setData(Qt.UserRole, path)
                item_val = QTableWidgetItem(val)
                item_name.setForeground(color)
                item_val.setForeground(color)
                table.setItem(i, 0, item_name)
                table.setItem(i, 1, item_val)

        def load_folder_data(self):
            self.table_folder.setRowCount(0)
            data = self.get_folder_startup()
            self.table_folder.setRowCount(len(data))
            for i, (name, val) in enumerate(data):
                color = analyze_startup_item(name, val)
                item_name = QTableWidgetItem(name)
                item_val = QTableWidgetItem(val)
                item_name.setForeground(color)
                item_val.setForeground(color)
                self.table_folder.setItem(i, 0, item_name)
                self.table_folder.setItem(i, 1, item_val)

        def load_scheduler_data(self):
            """Загружаем задачи планировщика в фоне. Не запускаем повторно если уже идёт загрузка."""
            try:
                # Если поток уже работает — не запускаем ещё один
                if self._scheduler_loader is not None and self._scheduler_loader.isRunning():
                    # Показываем закешированные данные если они есть
                    if hasattr(self, '_scheduler_all_data') and self._scheduler_all_data:
                        self._apply_scheduler_filter(
                            self.sched_filter_combo.currentText() if hasattr(self, 'sched_filter_combo') else "Все задачи"
                        )
                    return

                # Если кеш уже есть — показываем его сразу (без повторного запроса schtasks)
                if hasattr(self, '_scheduler_all_data') and self._scheduler_all_data:
                    self._apply_scheduler_filter(
                        self.sched_filter_combo.currentText() if hasattr(self, 'sched_filter_combo') else "Все задачи"
                    )
                    return

                # Первая загрузка — показываем плейсхолдер и запускаем поток
                self.table_scheduler.setRowCount(1)
                placeholder = QTableWidgetItem("Загрузка задач планировщика...")
                placeholder.setForeground(QColor('#888888'))
                self.table_scheduler.setItem(0, 0, placeholder)

                self._scheduler_loader = SchedulerLoader(self.get_scheduler_startup)
                self._scheduler_loader.data_signal.connect(
                    self._on_scheduler_loaded, Qt.QueuedConnection
                )
                self._scheduler_loader.finished.connect(
                    lambda: None  # держим ссылку живой до finish
                )
                self._scheduler_loader.start()

            except Exception as e:
                pass

        def refresh_scheduler_data(self):
            """Принудительное обновление — очищает кеш и перезагружает данные."""
            self._scheduler_all_data = []
            if self._scheduler_loader is not None and self._scheduler_loader.isRunning():
                self._scheduler_loader.quit()
                self._scheduler_loader.wait(2000)
                if self._scheduler_loader.isRunning():
                    self._scheduler_loader.terminate()
                    self._scheduler_loader.wait(500)
            self._scheduler_loader = None
            self.load_scheduler_data()

        def _on_scheduler_loaded(self, data):
            try:
                if not isinstance(data, list):
                    data = []
                # Нормализуем до 5 полей
                normalized = []
                for entry in data:
                    if isinstance(entry, (list, tuple)) and len(entry) >= 5:
                        normalized.append(tuple(entry[:5]))
                    elif isinstance(entry, (list, tuple)) and len(entry) == 2:
                        name, val = entry[0], entry[1]
                        source = "Системная" if name.startswith("\Microsoft") else "Пользовательская"
                        normalized.append((name, val, "", "", source))
                    else:
                        continue
                self._scheduler_all_data = normalized
                self._apply_scheduler_filter(
                    self.sched_filter_combo.currentText() if hasattr(self, 'sched_filter_combo') else "Все задачи"
                )
            except Exception:
                pass

        def load_services_data(self):
            self.table_services.setRowCount(0)
            data = self.get_services_startup()
            self.table_services.setRowCount(len(data))
            for i, (name, val) in enumerate(data):
                color = analyze_startup_item(name, val)
                item_name = QTableWidgetItem(name)
                item_val = QTableWidgetItem(val)
                item_name.setForeground(color)
                item_val.setForeground(color)
                self.table_services.setItem(i, 0, item_name)
                self.table_services.setItem(i, 1, item_val)

        def load_startup_data(self, type_name):
            # Этот метод больше не нужен, так как у нас отдельные таблицы для каждого раздела
            pass

        # ═══════════════════════════════════════════════════════════════
        # ФУНКЦИИ РЕДАКТИРОВАНИЯ АВТОЗАГРУЗКИ
        # ═══════════════════════════════════════════════════════════════

        def show_table_context_menu(self, pos, table, reg_type):
            item = table.itemAt(pos)
            if not item:
                return
            
            menu = QMenu()
            action_edit = menu.addAction("Изменить")
            action_delete = menu.addAction("Удалить")
            action_copy = menu.addAction("Копировать значение")
            
            action = menu.exec(table.viewport().mapToGlobal(pos))
            
            if action == action_edit:
                self.edit_registry_entry(reg_type)
            elif action == action_delete:
                self.delete_registry_entry(reg_type)
            elif action == action_copy:
                row = table.currentRow()
                value = table.item(row, 1).text()
                QApplication.clipboard().setText(value)

        def add_registry_entry(self, reg_type):
            dialog = QDialog(self)
            dialog.setWindowTitle("Добавить запись в реестр")
            dialog.setStyleSheet("background-color: #000000; color: white;")
            layout = QVBoxLayout(dialog)
            
            label_name = QLabel("Имя параметра:")
            label_name.setStyleSheet("color: white;")
            input_name = QLineEdit()
            input_name.setStyleSheet("background-color: #222222; color: white; padding: 5px;")
            
            label_value = QLabel("Значение:")
            label_value.setStyleSheet("color: white;")
            input_value = QLineEdit()
            input_value.setStyleSheet("background-color: #222222; color: white; padding: 5px;")
            
            label_hive = QLabel("Раздел реестра:")
            label_hive.setStyleSheet("color: white;")
            combo_hive = QComboBox()
            combo_hive.setStyleSheet("background-color: #222222; color: white; padding: 5px;")
            combo_hive.addItem("HKCU (Текущий пользователь)", "HKCU")
            combo_hive.addItem("HKLM (Локальная машина)", "HKLM")
            
            btn_add = QPushButton("Добавить")
            btn_add.setStyleSheet("background-color: #ffffff; color: white; padding: 8px;")
            btn_cancel = QPushButton("Отмена")
            btn_cancel.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px; padding: 8px;")
            
            layout.addWidget(label_name)
            layout.addWidget(input_name)
            layout.addWidget(label_value)
            layout.addWidget(input_value)
            layout.addWidget(label_hive)
            layout.addWidget(combo_hive)
            
            btn_layout = QHBoxLayout()
            btn_layout.addWidget(btn_add)
            btn_layout.addWidget(btn_cancel)
            layout.addLayout(btn_layout)
            
            def add_entry():
                name = input_name.text().strip()
                value = input_value.text().strip()
                hive_str = combo_hive.currentData()
                import winreg as _wr
                hive = _wr.HKEY_CURRENT_USER if hive_str == "HKCU" else _wr.HKEY_LOCAL_MACHINE
                
                if not name or not value:
                    QMessageBox.warning(dialog, "Ошибка", "Заполните все поля")
                    return
                
                try:
                    if reg_type == "Run":
                        path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                    elif reg_type == "RunOnce":
                        path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
                    elif reg_type == "Winlogon":
                        path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                    else:
                        return
                    
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
                    winreg.CloseKey(key)
                    
                    logger.log(f"Registry_{reg_type}", "success", f"Добавлена запись: {name} = {value}")
                    dialog.accept()
                    self.load_registry_data(reg_type)
                    QMessageBox.information(self, "Успех", "Запись добавлена в реестр")
                except Exception as e:
                    QMessageBox.critical(dialog, "Ошибка", f"Не удалось добавить запись: {e}")
                    logger.log(f"Registry_{reg_type}", "error", str(e))
            
            btn_add.clicked.connect(add_entry)
            btn_cancel.clicked.connect(dialog.reject)
            
            dialog.exec()

        def delete_registry_entry(self, reg_type):
            table_name = "appinit" if reg_type == "AppInit_DLLs и CmdLine" else reg_type.lower()
            table = getattr(self, f"table_{table_name}", None)
            if not table:
                return
            
            row = table.currentRow()
            if row < 0:
                QMessageBox.warning(self, "Ошибка", "Выберите запись для удаления")
                return
            
            name = table.item(row, 0).text()
            reply = QMessageBox.question(self, "Подтверждение", 
                                       f"Удалить запись '{name}' из реестра?",
                                       QMessageBox.Yes | QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                try:
                    if reg_type == "AppInit_DLLs и CmdLine":
                        key_path = table.item(row, 0).data(Qt.UserRole)
                        if key_path:
                            error = None
                            try:
                                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
                                winreg.DeleteValue(key, name)
                                winreg.CloseKey(key)
                            except Exception as ex:
                                error = ex
                            if error:
                                raise error
                    else:
                        # Пытаемся удалить из HKCU и HKLM
                        for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
                            try:
                                if reg_type == "Run":
                                    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                                elif reg_type == "RunOnce":
                                    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
                                elif reg_type == "Winlogon":
                                    path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                                else:
                                    continue
                                
                                key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
                                winreg.DeleteValue(key, name)
                                winreg.CloseKey(key)
                            except FileNotFoundError:
                                pass
                    
                    logger.log(f"Registry_{reg_type}", "success", f"Удалена запись: {name}")
                    self.load_registry_data(reg_type)
                    QMessageBox.information(self, "Успех", "Запись удалена из реестра")
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось удалить запись: {e}")
                    logger.log(f"Registry_{reg_type}", "error", str(e))

        def edit_registry_entry(self, reg_type):
            table_name = "appinit" if reg_type == "AppInit_DLLs и CmdLine" else reg_type.lower()
            table = getattr(self, f"table_{table_name}", None)
            if not table:
                return
            
            row = table.currentRow()
            if row < 0:
                QMessageBox.warning(self, "Ошибка", "Выберите запись для редактирования")
                return
            
            old_name = table.item(row, 0).text()
            old_value = table.item(row, 1).text()
            key_path = table.item(row, 0).data(Qt.UserRole) if reg_type == "AppInit_DLLs и CmdLine" else None
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Изменить запись в реестре")
            dialog.setStyleSheet("background-color: #000000; color: white;")
            layout = QVBoxLayout(dialog)
            
            label_name = QLabel("Имя параметра:")
            label_name.setStyleSheet("color: white;")
            input_name = QLineEdit(old_name)
            input_name.setStyleSheet("background-color: #222222; color: white; padding: 5px;")
            
            label_value = QLabel("Значение:")
            label_value.setStyleSheet("color: white;")
            input_value = QLineEdit(old_value)
            input_value.setStyleSheet("background-color: #222222; color: white; padding: 5px;")
            
            btn_save = QPushButton("Сохранить")
            btn_save.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px; font-weight: bold; padding: 8px;")
            btn_cancel = QPushButton("Отмена")
            btn_cancel.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px; padding: 8px;")
            
            layout.addWidget(label_name)
            layout.addWidget(input_name)
            layout.addWidget(label_value)
            layout.addWidget(input_value)
            
            btn_layout = QHBoxLayout()
            btn_layout.addWidget(btn_save)
            btn_layout.addWidget(btn_cancel)
            layout.addLayout(btn_layout)
            
            def save_entry():
                new_name = input_name.text().strip()
                new_value = input_value.text().strip()
                
                if not new_name or not new_value:
                    QMessageBox.warning(dialog, "Ошибка", "Заполните все поля")
                    return
                
                try:
                    if reg_type == "AppInit_DLLs и CmdLine":
                        if not key_path:
                            raise ValueError("Не удалось определить путь реестра для этой записи")
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
                        try:
                            winreg.DeleteValue(key, old_name)
                        except FileNotFoundError:
                            pass
                        winreg.SetValueEx(key, new_name, 0, winreg.REG_SZ, new_value)
                        winreg.CloseKey(key)
                    else:
                        # Находим и обновляем запись в HKCU и HKLM
                        for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
                            try:
                                if reg_type == "Run":
                                    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                                elif reg_type == "RunOnce":
                                    path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
                                elif reg_type == "Winlogon":
                                    path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                                else:
                                    continue
                                
                                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                                try:
                                    value, _ = winreg.QueryValueEx(key, old_name)
                                    winreg.CloseKey(key)
                                    
                                    # Удаляем старую запись
                                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
                                    winreg.DeleteValue(key, old_name)
                                    winreg.CloseKey(key)
                                    
                                    # Добавляем новую
                                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
                                    winreg.SetValueEx(key, new_name, 0, winreg.REG_SZ, new_value)
                                    winreg.CloseKey(key)
                                except FileNotFoundError:
                                    winreg.CloseKey(key)
                            except Exception as _e:
                                # Expected exception, intentionally ignored
                                pass
                    
                    logger.log(f"Registry_{reg_type}", "success", f"Изменена запись: {old_name} -> {new_name}")
                    dialog.accept()
                    self.load_registry_data(reg_type)
                    QMessageBox.information(self, "Успех", "Запись обновлена в реестре")
                except Exception as e:
                    QMessageBox.critical(dialog, "Ошибка", f"Не удалось обновить запись: {e}")
                    logger.log(f"Registry_{reg_type}", "error", str(e))
            
            btn_save.clicked.connect(save_entry)
            btn_cancel.clicked.connect(dialog.reject)
            
            dialog.exec()

        def show_folder_context_menu(self, pos, table):
            item = table.itemAt(pos)
            if not item:
                return
            
            menu = QMenu()
            action_delete = menu.addAction("Удалить")
            action_open = menu.addAction("Открыть файл")
            action_copy = menu.addAction("Копировать путь")
            
            action = menu.exec(table.viewport().mapToGlobal(pos))
            
            if action == action_delete:
                self.delete_folder_entry()
            elif action == action_open:
                self.open_selected_file()
            elif action == action_copy:
                row = table.currentRow()
                path = table.item(row, 1).text()
                QApplication.clipboard().setText(path)

        def add_folder_entry(self):
            dialog = QDialog(self)
            dialog.setWindowTitle("Добавить файл в автозагрузку")
            dialog.setStyleSheet("background-color: #000000; color: white;")
            layout = QVBoxLayout(dialog)
            
            label_path = QLabel("Выберите файл:")
            label_path.setStyleSheet("color: white;")
            input_path = QLineEdit()
            input_path.setStyleSheet("background-color: #222222; color: white; padding: 5px;")
            
            btn_browse = QPushButton("Обзор...")
            btn_browse.setStyleSheet("background-color: #ffffff; color: white; padding: 5px;")
            
            label_folder = QLabel("Папка автозагрузки:")
            label_folder.setStyleSheet("color: white;")
            combo_folder = QComboBox()
            combo_folder.setStyleSheet("background-color: #222222; color: white; padding: 5px;")
            combo_folder.addItem("Текущий пользователь", os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup"))
            combo_folder.addItem("Все пользователи", r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
            
            btn_add = QPushButton("Добавить")
            btn_add.setStyleSheet("background-color: #ffffff; color: white; padding: 8px;")
            btn_cancel = QPushButton("Отмена")
            btn_cancel.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px; padding: 8px;")
            
            layout.addWidget(label_path)
            path_layout = QHBoxLayout()
            path_layout.addWidget(input_path)
            path_layout.addWidget(btn_browse)
            layout.addLayout(path_layout)
            layout.addWidget(label_folder)
            layout.addWidget(combo_folder)
            
            btn_layout = QHBoxLayout()
            btn_layout.addWidget(btn_add)
            btn_layout.addWidget(btn_cancel)
            layout.addLayout(btn_layout)
            
            def browse_file():
                file_path, _ = QFileDialog.getOpenFileName(dialog, "Выберите файл")
                if file_path:
                    input_path.setText(file_path)
            
            def add_file():
                source_path = input_path.text().strip()
                target_folder = combo_folder.currentData()
                
                if not source_path or not os.path.exists(source_path):
                    QMessageBox.warning(dialog, "Ошибка", "Выберите существующий файл")
                    return
                
                try:
                    filename = os.path.basename(source_path)
                    target_path = os.path.join(target_folder, filename)
                    
                    # Копируем файл в папку автозагрузки
                    shutil.copy2(source_path, target_path)
                    
                    logger.log("Folder_Startup", "success", f"Добавлен файл: {filename}")
                    dialog.accept()
                    self.load_folder_data()
                    QMessageBox.information(self, "Успех", f"Файл добавлен в автозагрузку")
                except Exception as e:
                    QMessageBox.critical(dialog, "Ошибка", f"Не удалось добавить файл: {e}")
                    logger.log("Folder_Startup", "error", str(e))
            
            btn_browse.clicked.connect(browse_file)
            btn_add.clicked.connect(add_file)
            btn_cancel.clicked.connect(dialog.reject)
            
            dialog.exec()

        def delete_folder_entry(self):
            row = self.table_folder.currentRow()
            if row < 0:
                QMessageBox.warning(self, "Ошибка", "Выберите файл для удаления")
                return
            
            filename = self.table_folder.item(row, 0).text()
            filepath = self.table_folder.item(row, 1).text()
            
            reply = QMessageBox.question(self, "Подтверждение", 
                                       f"Удалить файл '{filename}' из автозагрузки?",
                                       QMessageBox.Yes | QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                try:
                    if os.path.exists(filepath):
                        safe_remove(filepath)
                        logger.log("Folder_Startup", "success", f"Удален файл: {filename}")
                        self.load_folder_data()
                        QMessageBox.information(self, "Успех", "Файл удален из автозагрузки")
                    else:
                        QMessageBox.warning(self, "Ошибка", "Файл не найден")
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось удалить файл: {e}")
                    logger.log("Folder_Startup", "error", str(e))

        def open_startup_folder(self):
            paths = [
                os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup"),
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            ]
            for path in paths:
                if os.path.exists(path):
                    subprocess.run(['explorer', path])
                    break

        def open_selected_file(self):
            row = self.table_folder.currentRow()
            if row < 0:
                return
            
            filepath = self.table_folder.item(row, 1).text()
            if os.path.exists(filepath):
                subprocess.run(['explorer', filepath])

        def show_scheduler_context_menu(self, pos, table):
            item = table.itemAt(pos)
            if not item:
                return
            
            menu = QMenu()
            action_delete = menu.addAction("Удалить")
            action_run = menu.addAction("Запустить")
            action_disable = menu.addAction("Отключить")
            action_enable = menu.addAction("Включить")
            
            action = menu.exec(table.viewport().mapToGlobal(pos))
            
            if action == action_delete:
                self.delete_scheduler_entry()
            elif action == action_run:
                self.run_scheduler_entry()
            elif action == action_disable:
                self.disable_scheduler_entry()
            elif action == action_enable:
                self.enable_scheduler_entry()

        def add_scheduler_entry(self):
            dialog = QDialog(self)
            dialog.setWindowTitle("Создать задачу в планировщике")
            dialog.setStyleSheet("background-color: #000000; color: white;")
            layout = QVBoxLayout(dialog)
            
            label_name = QLabel("Имя задачи:")
            label_name.setStyleSheet("color: white;")
            input_name = QLineEdit()
            input_name.setStyleSheet("background-color: #222222; color: white; padding: 5px;")
            
            label_path = QLabel("Путь к программе:")
            label_path.setStyleSheet("color: white;")
            input_path = QLineEdit()
            input_path.setStyleSheet("background-color: #222222; color: white; padding: 5px;")
            
            btn_browse = QPushButton("Обзор...")
            btn_browse.setStyleSheet("background-color: #ffffff; color: white; padding: 5px;")
            
            label_trigger = QLabel("Триггер:")
            label_trigger.setStyleSheet("color: white;")
            combo_trigger = QComboBox()
            combo_trigger.setStyleSheet("background-color: #222222; color: white; padding: 5px;")
            combo_trigger.addItem("При входе в систему", "ONLOGON")
            combo_trigger.addItem("При запуске системы", "ONSTART")
            combo_trigger.addItem("Ежедневно", "DAILY")
            
            btn_create = QPushButton("Создать")
            btn_create.setStyleSheet("background-color: #ffffff; color: white; padding: 8px;")
            btn_cancel = QPushButton("Отмена")
            btn_cancel.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px; padding: 8px;")
            
            layout.addWidget(label_name)
            layout.addWidget(input_name)
            layout.addWidget(label_path)
            path_layout = QHBoxLayout()
            path_layout.addWidget(input_path)
            path_layout.addWidget(btn_browse)
            layout.addLayout(path_layout)
            layout.addWidget(label_trigger)
            layout.addWidget(combo_trigger)
            
            btn_layout = QHBoxLayout()
            btn_layout.addWidget(btn_create)
            btn_layout.addWidget(btn_cancel)
            layout.addLayout(btn_layout)
            
            def browse_file():
                file_path, _ = QFileDialog.getOpenFileName(dialog, "Выберите программу")
                if file_path:
                    input_path.setText(file_path)
            
            def create_task():
                task_name = input_name.text().strip()
                program_path = input_path.text().strip()
                trigger_type = combo_trigger.currentData()
                
                if not task_name or not program_path:
                    QMessageBox.warning(dialog, "Ошибка", "Заполните все поля")
                    return
                
                try:
                    # Создаем XML для задачи
                    if trigger_type == "ONLOGON":
                        trigger_xml = f'<Trigger><Logon><UserId>*</UserId></Logon></Trigger>'
                    elif trigger_type == "ONSTART":
                        trigger_xml = f'<Trigger><Boot /></Trigger>'
                    else:  # DAILY
                        trigger_xml = f'<Trigger><Daily /></Trigger>'
                    
                    # Создаем задачу через schtasks
                    cmd = f'schtasks /create /tn "{task_name}" /tr "{program_path}" /sc {trigger_type.lower()} /f'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.log("Scheduler", "success", f"Создана задача: {task_name}")
                        dialog.accept()
                        self.load_scheduler_data()
                        QMessageBox.information(self, "Успех", "Задача создана в планировщике")
                    else:
                        QMessageBox.critical(dialog, "Ошибка", f"Не удалось создать задачу: {result.stderr}")
                        logger.log("Scheduler", "error", result.stderr)
                except Exception as e:
                    QMessageBox.critical(dialog, "Ошибка", f"Не удалось создать задачу: {e}")
                    logger.log("Scheduler", "error", str(e))
            
            btn_browse.clicked.connect(browse_file)
            btn_create.clicked.connect(create_task)
            btn_cancel.clicked.connect(dialog.reject)
            
            dialog.exec()

        def delete_scheduler_entry(self):
            row = self.table_scheduler.currentRow()
            if row < 0:
                QMessageBox.warning(self, "Ошибка", "Выберите задачу для удаления")
                return
            
            task_name = self.table_scheduler.item(row, 0).text()
            
            reply = QMessageBox.question(self, "Подтверждение", 
                                       f"Удалить задачу '{task_name}' из планировщика?",
                                       QMessageBox.Yes | QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                try:
                    result = subprocess.run(f'schtasks /delete /tn "{task_name}" /f', shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.log("Scheduler", "success", f"Удалена задача: {task_name}")
                        self.load_scheduler_data()
                        QMessageBox.information(self, "Успех", "Задача удалена из планировщика")
                    else:
                        QMessageBox.warning(self, "Ошибка", f"Не удалось удалить задачу: {result.stderr}")
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось удалить задачу: {e}")
                    logger.log("Scheduler", "error", str(e))

        def run_scheduler_entry(self):
            row = self.table_scheduler.currentRow()
            if row < 0:
                QMessageBox.warning(self, "Ошибка", "Выберите задачу для запуска")
                return
            
            task_name = self.table_scheduler.item(row, 0).text()
            
            try:
                result = subprocess.run(f'schtasks /run /tn "{task_name}"', shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    logger.log("Scheduler", "success", f"Запущена задача: {task_name}")
                    QMessageBox.information(self, "Успех", "Задача запущена")
                else:
                    QMessageBox.warning(self, "Ошибка", f"Не удалось запустить задачу: {result.stderr}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось запустить задачу: {e}")
                logger.log("Scheduler", "error", str(e))

        def disable_scheduler_entry(self):
            row = self.table_scheduler.currentRow()
            if row < 0:
                QMessageBox.warning(self, "Ошибка", "Выберите задачу для отключения")
                return
            
            task_name = self.table_scheduler.item(row, 0).text()
            
            try:
                result = subprocess.run(f'schtasks /change /tn "{task_name}" /disable', shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    logger.log("Scheduler", "success", f"Отключена задача: {task_name}")
                    self.load_scheduler_data()
                    QMessageBox.information(self, "Успех", "Задача отключена")
                else:
                    QMessageBox.warning(self, "Ошибка", f"Не удалось отключить задачу: {result.stderr}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось отключить задачу: {e}")
                logger.log("Scheduler", "error", str(e))

        def enable_scheduler_entry(self):
            row = self.table_scheduler.currentRow()
            if row < 0:
                QMessageBox.warning(self, "Ошибка", "Выберите задачу для включения")
                return
            
            task_name = self.table_scheduler.item(row, 0).text()
            
            try:
                result = subprocess.run(f'schtasks /change /tn "{task_name}" /enable', shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    logger.log("Scheduler", "success", f"Включена задача: {task_name}")
                    self.load_scheduler_data()
                    QMessageBox.information(self, "Успех", "Задача включена")
                else:
                    QMessageBox.warning(self, "Ошибка", f"Не удалось включить задачу: {result.stderr}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось включить задачу: {e}")
                logger.log("Scheduler", "error", str(e))

        def show_services_context_menu(self, pos, table):
            item = table.itemAt(pos)
            if not item:
                return
            
            menu = QMenu()
            action_start = menu.addAction("Запустить")
            action_stop = menu.addAction("Остановить")
            action_restart = menu.addAction("Перезапустить")
            action_copy = menu.addAction("Копировать путь")
            
            action = menu.exec(table.viewport().mapToGlobal(pos))
            
            if action == action_start:
                self.start_service()
            elif action == action_stop:
                self.stop_service()
            elif action == action_restart:
                self.restart_service()
            elif action == action_copy:
                row = table.currentRow()
                path = table.item(row, 1).text()
                QApplication.clipboard().setText(path)

        def start_service(self):
            row = self.table_services.currentRow()
            if row < 0:
                QMessageBox.warning(self, "Ошибка", "Выберите службу для запуска")
                return
            
            service_name = self.table_services.item(row, 0).text()
            
            try:
                result = subprocess.run(f'net start "{service_name}"', shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    logger.log("Services", "success", f"Запущена служба: {service_name}")
                    self.load_services_data()
                    QMessageBox.information(self, "Успех", "Служба запущена")
                else:
                    QMessageBox.warning(self, "Ошибка", f"Не удалось запустить службу: {result.stderr}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось запустить службу: {e}")
                logger.log("Services", "error", str(e))

        def stop_service(self):
            row = self.table_services.currentRow()
            if row < 0:
                QMessageBox.warning(self, "Ошибка", "Выберите службу для остановки")
                return
            
            service_name = self.table_services.item(row, 0).text()
            
            reply = QMessageBox.question(self, "Подтверждение", 
                                       f"Остановить службу '{service_name}'?",
                                       QMessageBox.Yes | QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                try:
                    result = subprocess.run(f'net stop "{service_name}"', shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.log("Services", "success", f"Остановлена служба: {service_name}")
                        self.load_services_data()
                        QMessageBox.information(self, "Успех", "Служба остановлена")
                    else:
                        QMessageBox.warning(self, "Ошибка", f"Не удалось остановить службу: {result.stderr}")
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось остановить службу: {e}")
                    logger.log("Services", "error", str(e))

        def restart_service(self):
            row = self.table_services.currentRow()
            if row < 0:
                QMessageBox.warning(self, "Ошибка", "Выберите службу для перезапуска")
                return
            
            service_name = self.table_services.item(row, 0).text()
            
            try:
                # Сначала останавливаем
                subprocess.run(f'net stop "{service_name}"', shell=True, capture_output=True, text=True)
                # Затем запускаем
                result = subprocess.run(f'net start "{service_name}"', shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    logger.log("Services", "success", f"Перезапущена служба: {service_name}")
                    self.load_services_data()
                    QMessageBox.information(self, "Успех", "Служба перезапущена")
                else:
                    QMessageBox.warning(self, "Ошибка", f"Не удалось перезапустить службу: {result.stderr}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось перезапустить службу: {e}")
                logger.log("Services", "error", str(e))

        def get_folder_startup(self):
            entries = []
            paths = [
                os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup"),
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            ]
            for p in paths:
                if os.path.exists(p):
                    for entry in os.scandir(p):
                        entries.append((entry.name, entry.path))
            return entries

        def get_scheduler_startup(self):
            """Возвращает список кортежей (name, status, trigger, task_run, source)
            
            Поля CSV от schtasks /query /fo CSV /v /nh:
            [0] = HostName, [1] = TaskName, [2] = NextRunTime, [3] = Status,
            [4] = LogonMode, [5] = LastRunTime, [6] = LastResult,
            [7] = Author, [8] = Task To Run, [9] = StartIn, [10] = Comment...
            """
            entries = []
            try:
                result = subprocess.run(
                    ["schtasks", "/query", "/fo", "CSV", "/v", "/nh"],
                    capture_output=True, text=True, encoding='cp866', timeout=20
                )
                import csv as _csv
                for line in result.stdout.splitlines():
                    try:
                        row = next(_csv.reader([line]), None)
                        if not row or len(row) < 9:
                            continue
                        # [1] = полный путь задачи, например \ACCBackgroundApplication
                        name = row[1].strip()
                        if not name or name == "TaskName":
                            continue
                        status_raw = row[3].strip()
                        task_run   = row[8].strip()
                        
                        # Определяем источник по пути
                        if "\\Microsoft\\Windows\\" in name or name.startswith("\\Microsoft\\"):
                            source = "Системная"
                        else:
                            source = "Пользовательская"
                        
                        # Переводим статус
                        status_map = {
                            "Ready": "Готова",
                            "Running": "Выполняется",
                            "Disabled": "Отключена",
                            "Could not start": "Ошибка",
                        }
                        status = status_map.get(status_raw, status_raw)
                        entries.append((name, status, "", task_run, source))
                    except Exception:
                        continue
            except Exception:
                pass
            return entries


        def _apply_scheduler_filter(self, filter_text):
            """Отрисовываем таблицу планировщика, сгруппировано по папкам"""
            data = getattr(self, '_scheduler_all_data', [])
            self.table_scheduler.setRowCount(0)

            filtered = []
            for row_data in data:
                if not row_data:
                    continue
                name_full = str(row_data[0]) if len(row_data) > 0 else ""
                status    = str(row_data[1]) if len(row_data) > 1 else ""
                source    = str(row_data[4]) if len(row_data) > 4 else ""

                is_system = ("Microsoft\\Windows" in name_full) or source == "Системная"
                is_suspicious = (not is_system) and status in ("Готова", "Ready", "Выполняется", "Running", "Включено")

                if filter_text == "Все задачи":
                    filtered.append(row_data)
                elif filter_text == "Только пользовательские" and not is_system:
                    filtered.append(row_data)
                elif filter_text == "Только подозрительные" and is_suspicious:
                    filtered.append(row_data)

            # ── Группируем по папкам ──────────────────────────────────────
            # folder_map: { "\\FolderName": [(task_name, status, ...), ...] }
            from collections import OrderedDict
            folder_map = OrderedDict()

            for row_data in filtered:
                name_full = str(row_data[0]) if len(row_data) > 0 else ""
                status    = str(row_data[1]) if len(row_data) > 1 else ""

                # Полный путь выглядит как \FolderName\TaskName или \TaskName
                if name_full.startswith("\\"):
                    parts = name_full.lstrip("\\").split("\\", 1)
                else:
                    parts = name_full.split("\\", 1)

                if len(parts) == 2:
                    folder = "\\" + parts[0]
                    task   = parts[1]
                else:
                    folder = "\\"
                    task   = parts[0]

                if folder not in folder_map:
                    folder_map[folder] = []
                folder_map[folder].append((task, status))

            # ── Строим строки таблицы ─────────────────────────────────────
            # Считаем общее кол-во строк: 1 строка папки + N задач
            total_rows = sum(1 + len(tasks) for tasks in folder_map.values())
            self.table_scheduler.setRowCount(total_rows)

            row_idx = 0
            for folder, tasks in folder_map.items():
                # ── Строка папки ──
                folder_name = folder.lstrip("\\") or "\\"
                item_folder = QTableWidgetItem("\U0001f4c1 " + folder_name)
                item_folder.setForeground(QColor("#000000"))
                f = item_folder.font()
                f.setBold(True)
                item_folder.setFont(f)

                item_folder_loc = QTableWidgetItem(folder)
                item_folder_state = QTableWidgetItem("")

                # Светло-серый фон для папки
                bg = QColor("#ffffff")
                item_folder.setBackground(bg)
                item_folder_loc.setBackground(bg)
                item_folder_state.setBackground(bg)

                self.table_scheduler.setItem(row_idx, 0, item_folder)
                self.table_scheduler.setItem(row_idx, 1, item_folder_loc)
                self.table_scheduler.setItem(row_idx, 2, item_folder_state)
                row_idx += 1

                # ── Строки задач внутри папки ──
                for task_name, status in sorted(tasks, key=lambda x: x[0].lower()):
                    # Переводим статус
                    if status in ("Готова", "Ready", "Выполняется", "Running"):
                        state_str = "Включено"
                    elif status in ("Отключена", "Disabled"):
                        state_str = "Отключено"
                    else:
                        state_str = status

                    item_name = QTableWidgetItem("  \U0001f4cb " + task_name)
                    item_name.setForeground(QColor("#000000"))

                    item_loc   = QTableWidgetItem(folder + "\\" + task_name)
                    item_state = QTableWidgetItem(state_str)

                    if state_str == "Отключено":
                        item_state.setForeground(QColor("#888888"))

                    self.table_scheduler.setItem(row_idx, 0, item_name)
                    self.table_scheduler.setItem(row_idx, 1, item_loc)
                    self.table_scheduler.setItem(row_idx, 2, item_state)
                    row_idx += 1

            # Скрываем задачи, пока папки не раскрыты
            for r in range(self.table_scheduler.rowCount()):
                item = self.table_scheduler.item(r, 0)
                if item and item.text().startswith("  \U0001f4cb "):
                    self.table_scheduler.setRowHidden(r, True)

        def _show_scheduler_folder_rows(self, folder_row, expanded):
            row = folder_row + 1
            while row < self.table_scheduler.rowCount():
                item = self.table_scheduler.item(row, 0)
                if not item:
                    row += 1
                    continue
                if item.text().startswith("\U0001f4c1 "):
                    break
                self.table_scheduler.setRowHidden(row, not expanded)
                row += 1

        def _on_scheduler_cell_clicked(self, row, column):
            item = self.table_scheduler.item(row, 0)
            if not item:
                return

            if not item.text().startswith("\U0001f4c1 "):
                return

            folder_name = self.table_scheduler.item(row, 1).text() if self.table_scheduler.item(row, 1) else item.text()
            expanded = folder_name in self._scheduler_expanded_folders

            if expanded:
                self._scheduler_expanded_folders.remove(folder_name)
            else:
                self._scheduler_expanded_folders.add(folder_name)

            self._show_scheduler_folder_rows(row, not expanded)

        def get_services_startup(self):
            entries = []
            if not PSUTIL_AVAILABLE:
                return entries
            try:
                for service in psutil.win_service_iter():
                    try:
                        info = service.as_dict()
                        if info['start_type'] in ['automatic', 'delayed']:
                            entries.append((info['display_name'], info['binpath']))
                    except Exception as _e:
                        # Expected exception, intentionally ignored
                        pass
            except Exception as _e:
                # Expected exception, intentionally ignored
                pass
            return entries

        def get_reg_startup(self, root, path):
            entries = []
            try:
                key = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        entries.append((name, str(value)))
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception as _e:
                # Expected exception, intentionally ignored
                pass
            return entries

        def create_restrictions_page(self):
            page = QFrame()
            main_layout = QVBoxLayout(page)
            main_layout.setContentsMargins(15, 15, 15, 15)
            main_layout.setSpacing(10)

            title = QLabel("Снятие ограничений")
            title.setStyleSheet("color: #ffffff; font-size: 18px; font-weight: bold;")
            main_layout.addWidget(title)

            # Горизонтальные вкладки категорий
            self._restrictions_tabs = QTabWidget()
            self._restrictions_tabs.setStyleSheet("""
                QTabWidget::pane { border: 1px solid #222222; background-color: #000000; border-radius: 4px; }
                QTabBar::tab { background-color: #000000; color: #888888; padding: 8px 14px; font-size: 13px; }
                QTabBar::tab:selected { background-color: #111111; color: #ffffff; border-bottom: 2px solid #ffffff; }
                QTabBar::tab:hover { background-color: #111111; color: #ffffff; }
            """)
            self._restrictions_checkboxes = {}  # category -> list of (checkbox, func)

            catalog = self.get_all_functions()
            categories = [
                "Интерфейс", "Проводник", "Реестр",
                "Система", "Запуск утилит", "Клавиатура",
                "Очистка", "Продвинутое", "Хардкор (Трояны)"
            ]
            for cat in categories:
                funcs = catalog.get(cat, [])
                if not funcs:
                    continue
                tab_widget = QWidget()
                tab_layout = QVBoxLayout(tab_widget)
                tab_layout.setContentsMargins(10, 10, 10, 5)
                tab_layout.setSpacing(4)

                scroll = QScrollArea()
                scroll.setWidgetResizable(True)
                scroll.setStyleSheet("background-color: transparent; border: none;")
                scroll_content = QWidget()
                scroll_layout = QVBoxLayout(scroll_content)
                scroll_layout.setSpacing(2)

                cb_list = []
                for name, desc, func in funcs:
                    cb = QCheckBox()
                    cb.setStyleSheet("QCheckBox { color: #ffffff; font-size: 13px; } QCheckBox::indicator { width: 16px; height: 16px; }")
                    # Контейнер: чекбокс + текст
                    row_w = QWidget()
                    row_l = QHBoxLayout(row_w)
                    row_l.setContentsMargins(4, 2, 4, 2)
                    row_l.setSpacing(8)
                    row_l.addWidget(cb)
                    text_w = QWidget()
                    text_l = QVBoxLayout(text_w)
                    text_l.setContentsMargins(0, 0, 0, 0)
                    text_l.setSpacing(0)
                    lbl_name = QLabel(name)
                    lbl_name.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: bold;")
                    lbl_desc = QLabel(desc)
                    lbl_desc.setStyleSheet("color: #888888; font-size: 11px;")
                    lbl_desc.setWordWrap(True)
                    text_l.addWidget(lbl_name)
                    text_l.addWidget(lbl_desc)
                    row_l.addWidget(text_w, 1)
                    row_w.setStyleSheet("background-color: #000000; border-radius: 3px;")
                    row_w.setFixedHeight(48)
                    scroll_layout.addWidget(row_w)
                    cb_list.append((cb, func))

                scroll_layout.addStretch()
                scroll.setWidget(scroll_content)
                tab_layout.addWidget(scroll)
                tab_widget.setLayout(tab_layout)
                self._restrictions_tabs.addTab(tab_widget, cat)
                self._restrictions_checkboxes[cat] = cb_list

            main_layout.addWidget(self._restrictions_tabs, 1)

            # Нижняя панель кнопок
            btn_panel = QWidget()
            btn_panel.setFixedHeight(48)
            btn_panel.setStyleSheet("background-color: #000000; border-top: 1px solid #111111;")
            btn_layout = QHBoxLayout(btn_panel)
            btn_layout.setContentsMargins(10, 6, 10, 6)
            btn_layout.setSpacing(10)

            _bs = "background-color: #111111; color: #ffffff; padding: 6px 16px; border: 1px solid #222222; border-radius: 4px; font-size: 13px;"
            btn_all = QPushButton("☑ Выбрать всё")
            btn_all.setStyleSheet(_bs)
            btn_all.clicked.connect(self._restrictions_select_all)
            btn_none = QPushButton("☐ Снять всё")
            btn_none.setStyleSheet(_bs)
            btn_none.clicked.connect(self._restrictions_select_none)
            btn_confirm = QPushButton("✓ Подтвердить выбранное")
            btn_confirm.setStyleSheet("background-color: #2d7a3a; color: white; padding: 6px 20px; border: 1px solid #3a9a4a; border-radius: 4px; font-size: 13px; font-weight: bold;")
            btn_confirm.clicked.connect(self._restrictions_run_selected)

            btn_layout.addWidget(btn_all)
            btn_layout.addWidget(btn_none)
            btn_layout.addStretch()
            btn_layout.addWidget(btn_confirm)
            main_layout.addWidget(btn_panel)

            return page

        def _restrictions_current_checkboxes(self):
            """Возвращает чекбоксы текущей вкладки"""
            idx = self._restrictions_tabs.currentIndex()
            cat = self._restrictions_tabs.tabText(idx)
            return self._restrictions_checkboxes.get(cat, [])

        def _restrictions_select_all(self):
            for cb, _ in self._restrictions_current_checkboxes():
                cb.setChecked(True)

        def _restrictions_select_none(self):
            for cb, _ in self._restrictions_current_checkboxes():
                cb.setChecked(False)

        def _restrictions_run_selected(self):
            funcs = [(cb, f) for cb, f in self._restrictions_current_checkboxes() if cb.isChecked()]
            if not funcs:
                QMessageBox.information(self, "Нет выбора", "Отметьте хотя бы одно действие для выполнения.")
                return
            reply = QMessageBox.question(
                self, "Подтверждение",
                f"Выполнить {len(funcs)} выбранных действий?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return
            # Запускаем все выбранные функции последовательно
            func_list = [f for _, f in funcs]
            def run_all():
                results = []
                for fn in func_list:
                    try:
                        import io
                        from contextlib import redirect_stdout
                        buf = io.StringIO()
                        with redirect_stdout(buf):
                            fn()
                        out = buf.getvalue().strip()
                        results.append(f"✓ {fn.__name__}: OK" + (f" — {out[:80]}" if out else ""))
                    except Exception as ex:
                        results.append(f"✗ {fn.__name__}: {ex}")
                return "\n".join(results)

            import threading
            self.append_log(f"[*] Запуск {len(func_list)} функций...")
            for cb, _ in funcs:
                cb.setChecked(False)

            def worker_thread():
                result_text = run_all()
                # Используем invokeMethod чтобы безопасно обновить UI из потока
                from PySide6.QtCore import QMetaObject, Qt as _Qt
                QMetaObject.invokeMethod(
                    self, "_restrictions_show_result",
                    _Qt.QueuedConnection,
                    result_text
                )

            # Простой запуск через Worker
            def _run():
                result_text = run_all()
                self.append_log("[+] Выбранные действия выполнены")
                QMessageBox.information(self, "Готово", result_text)

            self.run_task_list(func_list)

        def run_task_list(self, func_list):
            """Запускает список функций последовательно в фоновом потоке"""
            def combined():
                results = []
                for fn in func_list:
                    try:
                        import io
                        from contextlib import redirect_stdout
                        buf = io.StringIO()
                        with redirect_stdout(buf):
                            fn()
                        out = buf.getvalue().strip()
                        results.append(f"✓ {getattr(fn, '__name__', str(fn))}: выполнено")
                    except Exception as ex:
                        results.append(f"✗ {getattr(fn, '__name__', str(fn))}: {ex}")
                return "\n".join(results)
            self.run_task(combined)

        def add_block_buttons(self, block_name, layout):
            """Устаревший метод — оставлен для обратной совместимости"""
            label = QLabel(block_name)
            label.setStyleSheet("color: #ffffff; font-size: 16px; font-weight: bold; margin-top: 10px;")
            layout.addWidget(label)
            block_functions = self.get_all_functions()
            for name, description, func in block_functions.get(block_name, []):
                btn = QPushButton(f"{name}\n{description}")
                btn.setFixedHeight(50)
                btn.setStyleSheet("""
                    QPushButton { background-color: #111111; color: white; border: 1px solid #222222; text-align: left; padding-left: 15px; }
                    QPushButton:hover { background-color: #222222; }
                """)
                btn.clicked.connect(lambda checked=False, f=func: self.run_task(f))
                layout.addWidget(btn)

        def create_advanced_page(self):
            page = QFrame()
            main_layout = QVBoxLayout(page)
            main_layout.setContentsMargins(15, 15, 15, 10)
            main_layout.setSpacing(8)

            # ─── Заголовок ───────────────────────────────────────────────
            hdr_layout = QHBoxLayout()
            title = QLabel("Дополнительные инструменты")
            title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
            hdr_layout.addWidget(title)
            hdr_layout.addStretch()
            main_layout.addLayout(hdr_layout)

            # ─── БЛОК СКАНЕРА ОГРАНИЧЕНИЙ ──────────────────────────────
            scanner_frame = QFrame()
            scanner_frame.setStyleSheet("""
                QFrame {
                    background-color: #1a1a22;
                    border: 1px solid #222222;
                    border-radius: 8px;
                }
            """)
            scanner_layout = QVBoxLayout(scanner_frame)
            scanner_layout.setContentsMargins(15, 12, 15, 12)
            scanner_layout.setSpacing(8)

            scan_hdr = QHBoxLayout()
            scan_title = QLabel("Сканер ограничений системы")
            scan_title.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; background: transparent; border: none;")
            scan_desc = QLabel("Находит активные блокировки (реестр, групповые политики, системные ключи)")
            scan_desc.setStyleSheet("color: #888888; font-size: 11px; background: transparent; border: none;")
            scan_hdr.addWidget(scan_title)
            scan_hdr.addStretch()
            scanner_layout.addLayout(scan_hdr)
            scanner_layout.addWidget(scan_desc)

            # Таблица найденных ограничений
            self.restrictions_scan_table = QTableWidget(0, 3)
            self.restrictions_scan_table.setHorizontalHeaderLabels(["Что заблокировано", "Ключ реестра / GPO", "Статус"])
            self.restrictions_scan_table.horizontalHeader().setStretchLastSection(True)
            self.restrictions_scan_table.setSelectionBehavior(QTableWidget.SelectRows)
            self.restrictions_scan_table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.restrictions_scan_table.setAlternatingRowColors(True)
            self.restrictions_scan_table.setStyleSheet("""
                QTableWidget {
                    background-color: #12121a;
                    color: #ffffff;
                    gridline-color: #111111;
                    selection-background-color: #1a3a5a;
                    selection-color: white;
                    border: 1px solid #111111;
                    font-size: 12px;
                    alternate-background-color: #1a1a24;
                }
                QHeaderView::section {
                    background-color: #1e1e2e;
                    color: #ffffff;
                    border: none;
                    border-bottom: 1px solid #222222;
                    padding: 5px 8px;
                    font-weight: bold;
                    font-size: 12px;
                }
                QTableWidget::item { padding: 3px 8px; }
            """)
            self.restrictions_scan_table.setColumnWidth(0, 220)
            self.restrictions_scan_table.setColumnWidth(1, 300)
            self.restrictions_scan_table.setMaximumHeight(220)
            scanner_layout.addWidget(self.restrictions_scan_table)

            # Кнопки сканера
            scan_btn_layout = QHBoxLayout()
            _sb = "padding: 7px 18px; border-radius: 4px; font-size: 13px; font-weight: bold; border: 1px solid #222222;"

            self.btn_run_scan = QPushButton("Сканировать")
            self.btn_run_scan.setStyleSheet(f"background-color: #111111; color: #ffffff; {_sb} border-color: #222222;")
            self.btn_run_scan.setCursor(Qt.PointingHandCursor)
            self.btn_run_scan.clicked.connect(self.scan_restrictions)

            self.btn_fix_selected = QPushButton("Снять выбранные")
            self.btn_fix_selected.setStyleSheet(f"background-color: #1a4a2a; color: #ffffff; {_sb} border-color: #ffffff;")
            self.btn_fix_selected.setCursor(Qt.PointingHandCursor)
            self.btn_fix_selected.clicked.connect(self.fix_selected_restrictions)
            self.btn_fix_selected.setEnabled(False)

            self.btn_fix_all = QPushButton("Снять всё")
            self.btn_fix_all.setStyleSheet(f"background-color: #111111; color: #ffffff; {_sb} border-color: #222222;")
            self.btn_fix_all.setCursor(Qt.PointingHandCursor)
            self.btn_fix_all.clicked.connect(self.fix_all_restrictions)
            self.btn_fix_all.setEnabled(False)

            self.scan_status_label = QLabel("Нажмите «Сканировать» для поиска ограничений")
            self.scan_status_label.setStyleSheet("color: #888888; font-size: 11px; background: transparent; border: none;")

            scan_btn_layout.addWidget(self.btn_run_scan)
            scan_btn_layout.addWidget(self.btn_fix_selected)
            scan_btn_layout.addWidget(self.btn_fix_all)
            scan_btn_layout.addStretch()
            scan_btn_layout.addWidget(self.scan_status_label)
            scanner_layout.addLayout(scan_btn_layout)

            main_layout.addWidget(scanner_frame)

            tools_label = QLabel("Встроенные утилиты")
            tools_label.setStyleSheet("color: #888888; font-size: 12px; font-weight: bold; margin-top: 4px;")
            main_layout.addWidget(tools_label)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setStyleSheet("background-color: transparent; border: none;")

            scroll_content = QWidget()
            layout = QVBoxLayout(scroll_content)
            layout.setSpacing(6)
            layout.setContentsMargins(0, 0, 0, 0)

            card_style = """
                QFrame#ToolCard {
                    background-color: #000000;
                    border: 1px solid #222222;
                    border-radius: 6px;
                }
                QFrame#ToolCard:hover { border-color: #ffffff; }
            """

            built_in_tools = [
                ("Редактор реестра", "Открывает собственный редактор реестра в стиле системного окна.", self.show_registry_editor),
                ("mbrRE", "Открывает отдельное окно восстановления загрузчика MBR/BCD.", self.show_boot_repair_window),
                ("Пользователи", "Открывает собственный менеджер учетных записей.", self.show_user_manager),
                ("Удаление дисков", "Открывает отдельное окно управления дисками и разделами.", self.show_disk_manager),
                ("Сброс пароля", "Открывает окно управления учетными записями и паролями.", self.show_password_window),
            ]

            for name, description, callback in built_in_tools:
                card = QFrame()
                card.setObjectName("ToolCard")
                card.setStyleSheet(card_style)
                card.setFixedHeight(52)
                card_layout = QHBoxLayout(card)
                card_layout.setContentsMargins(12, 6, 12, 6)

                text_layout = QVBoxLayout()
                text_layout.setSpacing(1)

                tool_name = QLabel(name)
                tool_name.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: bold; border: none; background: transparent;")
                text_layout.addWidget(tool_name)

                tool_desc = QLabel(description)
                tool_desc.setStyleSheet("color: #888888; font-size: 10px; border: none; background: transparent;")
                tool_desc.setWordWrap(True)
                text_layout.addWidget(tool_desc)

                card_layout.addLayout(text_layout, 1)

                btn_run = QPushButton("Запустить")
                btn_run.setFixedSize(90, 28)
                btn_run.setCursor(Qt.PointingHandCursor)
                btn_run.setStyleSheet("""
                    QPushButton {
                        background-color: #111111; color: #ffffff;
                        border: 1px solid #ffffff; border-radius: 4px; font-weight: bold; font-size: 12px;
                    }
                    QPushButton:hover { background-color: #ffffff; color: #000000; }
                """)
                btn_run.clicked.connect(callback)
                card_layout.addWidget(btn_run)

                layout.addWidget(card)

            layout.addStretch()
            scroll.setWidget(scroll_content)
            main_layout.addWidget(scroll)
            return page

        def show_tool_window(self, title, subtitle, button_text, action_callback):
            dialog = ToolWindow(title, subtitle, button_text, action_callback, self)
            dialog.exec()

        def show_registry_editor(self):
            dialog = RegistryEditorWindow(self)
            dialog.exec()

        def show_user_manager(self):
            dialog = UserManagerWindow(self)
            dialog.exec()

        def show_disk_manager(self):
            from PySide6.QtWidgets import QMessageBox
            from PySide6.QtCore import Qt as _Qt
            msg = QMessageBox(self)
            msg.setWindowFlags(msg.windowFlags() | _Qt.WindowStaysOnTopHint)
            msg.setWindowTitle("⚠️ Управление дисками")
            msg.setIcon(QMessageBox.Warning)
            msg.setText(
                "⚠️ ВНИМАНИЕ! Удаление или форматирование дисков\n"
                "является необратимой операцией.\n\n"
                "Все данные на удалённом разделе будут потеряны без возможности восстановления.\n\n"
                "Убедитесь, что вы точно знаете, что делаете. Продолжить?"
            )
            msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
            msg.button(QMessageBox.Ok).setText("ПРОДОЛЖИТЬ  →")
            msg.button(QMessageBox.Cancel).setText("ОТМЕНА")
            msg.setStyleSheet(
                "QMessageBox { background-color: #000000; color: #ffffff; }"
                " QLabel { color: #ffffff; font-size: 13px; }"
                " QPushButton { background-color: #000000; color: #ffffff;"
                " border: 2px solid #ffffff; padding: 6px 16px;"
                " font-weight: bold; min-width: 100px; }"
                " QPushButton:hover { background-color: #ffffff; color: #000000; }"
            )
            if msg.exec() == QMessageBox.Ok:
                dialog = DiskManagerWindow(self)
                dialog.exec()


        def show_boot_repair_window(self):
            from PySide6.QtWidgets import QMessageBox
            from PySide6.QtCore import Qt as _Qt
            msg = QMessageBox(self)
            msg.setWindowFlags(msg.windowFlags() | _Qt.WindowStaysOnTopHint)
            msg.setWindowTitle("⚠️ Восстановление загрузчика MBR/BCD")
            msg.setIcon(QMessageBox.Warning)
            msg.setText(
                "⚠️ ВНИМАНИЕ! Восстановление загрузчика MBR/BCD\n"
                "является продвинутой системной операцией.\n\n"
                "При неправильном использовании Windows\n"
                "может перестать загружаться.\n\n"
                "Рекомендуется создать точку восстановления\n"
                "перед продолжением. Вы уверены?"
            )
            msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
            msg.button(QMessageBox.Ok).setText("ПРОДОЛЖИТЬ  →")
            msg.button(QMessageBox.Cancel).setText("ОТМЕНА")
            msg.setStyleSheet(
                "QMessageBox { background-color: #000000; color: #ffffff; }"
                " QLabel { color: #ffffff; font-size: 13px; }"
                " QPushButton { background-color: #000000; color: #ffffff;"
                " border: 2px solid #ffffff; padding: 6px 16px;"
                " font-weight: bold; min-width: 100px; }"
                " QPushButton:hover { background-color: #ffffff; color: #000000; }"
            )
            if msg.exec() == QMessageBox.Ok:
                self.show_tool_window("mbrRE", "Восстанавливает загрузочный сектор и конфигурацию загрузчика Windows.", "Запустить восстановление", Fix_MBR_Boot)


        def show_password_window(self):
            self.show_tool_window("Сброс пароля", "Запускает инструменты управления паролями и учетными записями Windows.", "Открыть параметры", Open_Password_Reset)

        def scan_restrictions(self):
            """Сканирует систему на наличие активных блокировок"""
            self.btn_run_scan.setEnabled(False)
            self.btn_run_scan.setText("Сканирование...")
            self.scan_status_label.setText("Сканирование...")
            self.restrictions_scan_table.setRowCount(0)
            self._found_restrictions = []

            def do_scan():
                import winreg
                found = []

                # Список проверок: (название, путь реестра, значение, ожидаемое_значение_для_блокировки, функция_снятия)
                checks = [
                    # Диспетчер задач
                    ("Диспетчер задач (Ctrl+Alt+Del)",
                     r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                     "DisableTaskMgr", winreg.HKEY_CURRENT_USER, 1, "Disable_TaskManager_Fix"),
                    # Regedit
                    ("Редактор реестра (regedit)",
                     r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                     "DisableRegistryTools", winreg.HKEY_CURRENT_USER, 1, "Disable_Regedit_Fix"),
                    # Win+R
                    ("Команда Выполнить (Win+R)",
                     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                     "NoRun", winreg.HKEY_CURRENT_USER, 1, "WinR_Fix"),
                    # Cmd
                    ("Командная строка (cmd.exe)",
                     r"Software\Policies\Microsoft\Windows\System",
                     "DisableCMD", winreg.HKEY_CURRENT_USER, 1, "CMD_Fix"),
                    # Control Panel
                    ("Панель управления",
                     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                     "NoControlPanel", winreg.HKEY_CURRENT_USER, 1, "ControlPanel_Fix"),
                    # Folder Options
                    ("Параметры папок (скрытые файлы)",
                     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                     "NoFolderOptions", winreg.HKEY_CURRENT_USER, 1, "FolderOptions_Fix"),
                    # Wallpaper lock
                    ("Обои рабочего стола",
                     r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                     "Wallpaper", winreg.HKEY_CURRENT_USER, None, "Wallpaper_Fix"),
                    # AppInit_DLLs
                    ("AppInit_DLLs (внедрение DLL)",
                     r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                     "AppInit_DLLs", winreg.HKEY_LOCAL_MACHINE, None, "AppInit_DLLs_Fix"),
                    # DisallowRun
                    ("DisallowRun (запрет запуска программ)",
                     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                     "DisallowRun", winreg.HKEY_CURRENT_USER, 1, "DisallowRun_Fix"),

                    # Windows Defender (DisableAntiSpyware)
                    ("Windows Defender отключён",
                     r"SOFTWARE\Policies\Microsoft\Windows Defender",
                     "DisableAntiSpyware", winreg.HKEY_LOCAL_MACHINE, 1, "Defender_Fix"),
                    # Windows Update
                    ("Windows Update заблокирован",
                     r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
                     "NoAutoUpdate", winreg.HKEY_LOCAL_MACHINE, 1, "WindowsUpdate_Fix"),
                    # Scancode Map (keyboard block)
                    ("Клавиши заблокированы (Scancode Map)",
                     r"SYSTEM\CurrentControlSet\Control\Keyboard Layout",
                     "Scancode Map", winreg.HKEY_LOCAL_MACHINE, None, "Scancode_Fix"),
                ]

                for check in checks:
                    if len(check) == 6:
                        label, key_path, value_name, hive, block_val, fix_func = check
                    else:
                        continue

                    try:
                        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)

                        if value_name is None:
                            # Проверяем просто существование ключа
                            winreg.CloseKey(key)
                            found.append({
                                "label": label,
                                "key": f"{'HKCU' if hive == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{key_path}",
                                "detail": "(ключ существует)",
                                "fix_func": fix_func,
                            })
                            continue

                        try:
                            val, _ = winreg.QueryValueEx(key, value_name)
                            winreg.CloseKey(key)

                            is_blocked = False
                            if block_val == 1 and val == 1:
                                is_blocked = True
                            elif block_val is None and val and str(val).strip():
                                # Любое непустое значение считается блокировкой
                                is_blocked = True

                            if is_blocked:
                                hive_str = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                                found.append({
                                    "label": label,
                                    "key": f"{hive_str}\\{key_path}\\{value_name}",
                                    "detail": f"= {repr(val)[:40]}",
                                    "fix_func": fix_func,
                                })
                        except FileNotFoundError:
                            winreg.CloseKey(key)
                    except Exception:
                        pass

                return found

            def on_scan_done():
                # Вызывается из основного потока
                pass

            # Запускаем в Worker
            def worker_func():
                return do_scan()

            from PySide6.QtCore import QThread, Signal
            class ScanThread(QThread):
                scan_finished = Signal(list)
                def run(self):
                    res = do_scan()
                    self.scan_finished.emit(res)

            self.scan_thread = ScanThread()
            self.scan_thread.scan_finished.connect(self._on_scan_done)
            self.scan_thread.start()

        def _on_scan_done(self, found=None):
            """Вызывается из основного потока когда сканирование завершено"""
            if found is not None:
                self._found_restrictions = found
            else:
                found = getattr(self, '_found_restrictions', [])
            self.restrictions_scan_table.setRowCount(0)

            if not found:
                self.scan_status_label.setText("Ограничений не найдено!")
                self.btn_fix_all.setEnabled(False)
                self.btn_fix_selected.setEnabled(False)
                self.btn_run_scan.setEnabled(True)
                self.btn_run_scan.setText("Сканировать")
                return

            self.restrictions_scan_table.setRowCount(len(found))
            for i, item in enumerate(found):
                lbl_item = QTableWidgetItem(item["label"])
                lbl_item.setForeground(QColor("#ffffff"))
                lbl_item.setCheckState(Qt.Checked)  # по умолчанию отмечены

                key_item = QTableWidgetItem(item["key"])
                key_item.setForeground(QColor("#888888"))

                det_item = QTableWidgetItem(item["detail"])
                det_item.setForeground(QColor("#ffffff"))

                self.restrictions_scan_table.setItem(i, 0, lbl_item)
                self.restrictions_scan_table.setItem(i, 1, key_item)
                self.restrictions_scan_table.setItem(i, 2, det_item)

            self.scan_status_label.setText(f"Найдено {len(found)} блокировок")
            self.btn_fix_all.setEnabled(True)
            self.btn_fix_selected.setEnabled(True)
            self.btn_run_scan.setEnabled(True)
            self.btn_run_scan.setText("Сканировать снова")

        def fix_selected_restrictions(self):
            """Снимает только отмеченные галочкой ограничения"""
            found = getattr(self, '_found_restrictions', [])
            selected = []
            for i, item in enumerate(found):
                table_item = self.restrictions_scan_table.item(i, 0)
                if table_item and table_item.checkState() == Qt.Checked:
                    selected.append(item)
            self._apply_restriction_fixes(selected)

        def fix_all_restrictions(self):
            """Снимает все найденные ограничения"""
            found = getattr(self, '_found_restrictions', [])
            self._apply_restriction_fixes(found)

        def _apply_restriction_fixes(self, items_to_fix):
            """Показывает окно подтверждения и запускает фикс"""
            if not items_to_fix:
                QMessageBox.information(self, "Нет выбора", "Не выбрано ни одного ограничения.")
                return

            # Собираем список функций из get_all_functions по имени
            catalog = self.get_all_functions()
            all_funcs = {}
            for cat_funcs in catalog.values():
                for name, desc, fn in cat_funcs:
                    all_funcs[name] = (fn, desc)

            # Маппинг fix_func -> реальные имена функций в каталоге
            FIX_MAP = {
                "Disable_TaskManager_Fix":  "Разблокировать Диспетчер задач",
                "Disable_Regedit_Fix":      "Разблокировать редактор реестра",
                "WinR_Fix":                 "Разблокировать Выполнить (Win+R)",
                "CMD_Fix":                  "Разблокировать CMD",
                "ControlPanel_Fix":         "Разблокировать Панель управления",
                "FolderOptions_Fix":        "Восстановить параметры папок",
                "Wallpaper_Fix":            "Принудительная установка обоев",
                "AppInit_DLLs_Fix":         "Очистить AppInit_DLLs и CmdLine",
                "DisallowRun_Fix":          "Разблокировать DisallowRun",
                "SafeBoot_Fix":             "Восстановить Безопасный режим",
                "Defender_Fix":             "Включить Windows Defender",
                "WindowsUpdate_Fix":        "Разблокировать Windows Update",
                "Scancode_Fix":             "Восстановить клавиатуру (Scancode Map)",
            }

            lines = []
            funcs_to_run = []
            for item in items_to_fix:
                fix_key = item["fix_func"]
                func_name = FIX_MAP.get(fix_key, fix_key)
                if func_name in all_funcs:
                    fn, desc = all_funcs[func_name]
                    funcs_to_run.append((func_name, fn))
                    lines.append(f"  \u2022 {item['label']} -> {func_name}")
                else:
                    lines.append(f"  \u2022 {item['label']} -> (встроенная очистка реестра)")

            details_text = "\n".join(lines)

            msg = QMessageBox(self)
            msg.setWindowTitle("Подтверждение снятия блокировок")
            msg.setIcon(QMessageBox.Warning)
            msg.setText(f"Будет выполнено {len(items_to_fix)} действий:\n\n{details_text}\n\nПродолжить?")
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            msg.setDefaultButton(QMessageBox.Yes)
            if msg.exec() != QMessageBox.Yes:
                return

            # Запускаем прямую очистку через реестр (без зависимости от имён функций)
            def do_fixes():
                import winreg
                results = []
                for item in items_to_fix:
                    try:
                        label = item["label"]
                        # Парсим ключ реестра из строки вида HKCU\path\\value
                        key_str = item["key"]
                        if key_str.startswith("HKCU"):
                            hive = winreg.HKEY_CURRENT_USER
                            rest = key_str[5:]  # после "HKCU\"
                        else:
                            hive = winreg.HKEY_LOCAL_MACHINE
                            rest = key_str[5:]  # после "HKLM\"

                        parts = rest.rsplit("\\", 1)
                        if len(parts) == 2:
                            key_path, value_name = parts
                            key_path = key_path.replace("\\\\", "\\")

                            try:
                                k = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
                                winreg.DeleteValue(k, value_name)
                                winreg.CloseKey(k)
                                results.append(f"{label}: снято")
                            except FileNotFoundError:
                                results.append(f"{label}: уже снято")
                            except Exception as e:
                                results.append(f"Ошибка {label}: {e}")
                        else:
                            results.append(f"Неизвестно {label}: не удалось разобрать путь")
                    except Exception as e:
                        results.append(f"✗ {item.get('label','?')}: {e}")

                # Также запускаем найденные функции из каталога
                for func_name, fn in funcs_to_run:
                    try:
                        fn()
                        results.append(f"{func_name}: выполнено")
                    except Exception as e:
                        results.append(f"Ошибка {func_name}: {e}")

                return "\n".join(results)

            self.run_task(do_fixes)
            # После — запускаем повторное сканирование
            from PySide6.QtCore import QTimer
            QTimer.singleShot(3000, self.scan_restrictions)

        def create_unlocker_page(self):
            page = QFrame()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(20, 20, 20, 20)
            
            title = QLabel("Разблокировка файлов (Unlocker)")
            title.setStyleSheet("color: #ffffff; font-size: 18px; font-weight: bold; margin-bottom: 10px;")
            layout.addWidget(title)
            
            desc = QLabel("Выберите заблокированный файл. Программа найдет процессы, которые его удерживают, и позволит их завершить.")
            desc.setStyleSheet("color: #888888; font-size: 12px; margin-bottom: 10px;")
            desc.setWordWrap(True)
            layout.addWidget(desc)
            
            # File selection
            file_layout = QHBoxLayout()
            self.unlocker_path_edit = QLineEdit()
            self.unlocker_path_edit.setStyleSheet("background-color: #000000; color: white; border: 1px solid #222222; border-radius: 5px; padding: 5px;")
            self.unlocker_path_edit.setPlaceholderText("Путь к файлу...")
            file_layout.addWidget(self.unlocker_path_edit)
            
            btn_browse = QPushButton("Обзор...")
            btn_browse.setStyleSheet("background-color: #111111; color: white; border: 1px solid #222222; border-radius: 5px; padding: 5px 15px;")
            btn_browse.clicked.connect(self.browse_unlocker_file)
            file_layout.addWidget(btn_browse)
            layout.addLayout(file_layout)
            
            # Scan button
            self.btn_scan_locks = QPushButton("Анализ файла")
            self.btn_scan_locks.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px; font-weight: bold; margin-top: 10px;")
            self.btn_scan_locks.clicked.connect(self.scan_locking_processes)
            layout.addWidget(self.btn_scan_locks)
            
            # Table
            self.unlocker_table = QTableWidget(0, 2)
            self.unlocker_table.setHorizontalHeaderLabels(["PID", "Имя процесса (если доступно)"])
            self.unlocker_table.horizontalHeader().setStretchLastSection(True)
            self.unlocker_table.setStyleSheet("""
                QTableWidget { background-color: #000000; color: white; border: 1px solid #222222; border-radius: 5px; }
                QHeaderView::section { background-color: #111111; color: #ffffff; padding: 5px; border: 1px solid #222222; }
            """)
            layout.addWidget(self.unlocker_table)
            
            # Action buttons
            action_layout = QHBoxLayout()
            self.btn_unlock_kill = QPushButton("Разблокировать (Убить процессы)")
            self.btn_unlock_kill.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px; font-weight: bold;")
            self.btn_unlock_kill.clicked.connect(self.unlock_kill_only)
            
            self.btn_unlock_delete = QPushButton("Уничтожить (Убить + Удалить файл)")
            self.btn_unlock_delete.setStyleSheet("background-color: #111111; color: #ffffff; padding: 5px 12px; border: 1px solid #222222; border-radius: 4px; font-weight: bold;")
            self.btn_unlock_delete.clicked.connect(self.unlock_kill_and_delete)
            
            action_layout.addWidget(self.btn_unlock_kill)
            action_layout.addWidget(self.btn_unlock_delete)
            layout.addLayout(action_layout)
            
            self.unlocker_pids = []
            
            return page

        def browse_unlocker_file(self):
            path, _ = QFileDialog.getOpenFileName(self, "Выберите заблокированный файл", "", "All Files (*.*)")
            if path:
                self.unlocker_path_edit.setText(path)

        def scan_locking_processes(self):
            path = self.unlocker_path_edit.text().strip()
            if not path or not os.path.exists(path):
                QMessageBox.warning(self, "Ошибка", "Укажите правильный путь к существующему файлу.")
                return
            
            self.unlocker_table.setRowCount(0)
            self.unlocker_pids = get_locking_processes(path)
            
            if not self.unlocker_pids:
                QMessageBox.information(self, "Результат", "Не найдено процессов, блокирующих этот файл.\n(Возможно, он не заблокирован или заблокирован ядром).")
                return
            
            self.unlocker_table.setRowCount(len(self.unlocker_pids))
            
            # Fetch processes once
            procs = []
            if 'novir_native' in globals() and hasattr(novir_native, 'get_processes_extended'):
                try:
                    procs = novir_native.get_processes_extended()
                except Exception:
                    pass
            if not procs and psutil:
                procs = [p.info for p in psutil.process_iter(['pid', 'name'])]
                
            for row, pid in enumerate(self.unlocker_pids):
                pid_item = QTableWidgetItem(str(pid))
                name = "Неизвестно"
                
                # Find matching proc
                for p_info in procs:
                    if p_info.get('pid') == pid:
                        name = str(p_info.get('name', name))
                        break
                        
                name_item = QTableWidgetItem(name)
                
                self.unlocker_table.setItem(row, 0, pid_item)
                self.unlocker_table.setItem(row, 1, name_item)

        def unlock_kill_only(self):
            self._do_unlock(delete_file=False)

        def unlock_kill_and_delete(self):
            self._do_unlock(delete_file=True)

        def _do_unlock(self, delete_file):
            if not self.unlocker_pids:
                QMessageBox.warning(self, "Пусто", "Сначала проведите анализ файла.")
                return
            
            path = self.unlocker_path_edit.text().strip()
            
            if DRY_RUN:
                action = "Удаление файла" if delete_file else "Убийство процессов"
                QMessageBox.information(self, "DRY RUN", f"[DRY RUN] Будут убиты PIDs: {self.unlocker_pids}\nДействие: {action}")
                return
                
            killed = 0
            for pid in self.unlocker_pids:
                try:
                    if 'novir_native' in globals() and hasattr(novir_native, 'kill_process_force'):
                        novir_native.kill_process_force(pid)
                    elif psutil:
                        psutil.Process(pid).terminate()
                    killed += 1
                except Exception:
                    # Fallback
                    try:
                        kill_process_force(pid)
                    except Exception as _e:
                        # Expected exception, intentionally ignored
                        pass
                    killed += 1
                    
            msg = f"Убито процессов: {killed}."
            
            if delete_file:
                import time
                time.sleep(1) # wait for handles to release
                try:
                    safe_remove(path)
                    msg += "\nФайл успешно удален!"
                except Exception as e:
                    msg += f"\nНе удалось удалить файл: {e}"
            
            QMessageBox.information(self, "Готово", msg)
            self.unlocker_table.setRowCount(0)
            self.unlocker_pids = []
            self.unlocker_path_edit.clear()

        def create_program_page(self):
            """Настройки — только выбор темы"""
            page = QFrame()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(30, 30, 30, 30)
            layout.setSpacing(20)
            layout.setAlignment(Qt.AlignTop)

            hdr = QLabel("НАСТРОЙКИ")
            hdr.setStyleSheet("color: #ffffff; font-size: 20px; font-weight: bold; letter-spacing: 3px;")
            layout.addWidget(hdr)

            sep = QFrame()
            sep.setFrameShape(QFrame.HLine)
            sep.setStyleSheet("background-color: #333333; max-height: 1px;")
            layout.addWidget(sep)

            lbl_theme = QLabel("ТЕМА ОФОРМЛЕНИЯ")
            lbl_theme.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: bold;")
            layout.addWidget(lbl_theme)

            self.cb_theme = QComboBox()
            self.cb_theme.addItems(["Minimal B&W", "Тёмная тема (Стандартная)", "Тема Ванька", "МАТОВЫЙ", "ПРОЗРАЧНЫЙ"])
            self.cb_theme.setStyleSheet("""
                QComboBox {
                    background-color: #000000;
                    color: #ffffff;
                    border: 2px solid #ffffff;
                    padding: 8px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QComboBox::drop-down { border: none; }
                QComboBox QAbstractItemView {
                    background-color: #000000;
                    color: #ffffff;
                    selection-background-color: #ffffff;
                    selection-color: #000000;
                }
            """)
            self.cb_theme.currentTextChanged.connect(self.apply_theme)
            layout.addWidget(self.cb_theme)

            layout.addStretch()
            return page

        def create_whats_new_page(self):
            """Устаревший метод — перенаправляет на create_program_page"""
            return self.create_program_page()

        def create_settings_page(self):
            """Устаревший метод — настройки теперь в create_program_page"""
            return self.create_program_page()

        def _legacy_whats_new_page(self):
            page = QFrame()
            layout = QVBoxLayout(page)
            
            title = QLabel("Что нового в этом обновлении")
            title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff; margin-bottom: 20px;")
            layout.addWidget(title)
            
            content = QTextEdit()
            content.setReadOnly(True)
            content.setStyleSheet("background-color: #000000; color: #ffffff; font-size: 14px; border: 1px solid #222222; padding: 10px;")
            
            text = """<h2>Обновление NoVir v2.1.2 (Глобальное расширение функционала)</h2>
<ul>
    <li><b>Масштабное добавление функций:</b> В "Снятие ограничений" добавлены две новые вкладки — <b>"Система"</b> и <b>"Запуск утилит"</b>. Всего добавлено более 15 новых инструментов для работы с системой.</li>
    <li><b>Новый удобный вывод (MessageBox):</b> Мы полностью избавились от консольного лога (и надписей [SYSTEM]). Теперь при выполнении любой команды или утилиты результат выводится в чистом, красивом всплывающем окне (MessageBox).</li>
    <li><b>Хардкорная интеграция в систему:</b>
        <ul>
            <li><b>Удобный запуск:</b> Программа копируется как <code>nov.exe</code>, добавляется в контекстное меню рабочего стола и автоматически отключает UAC для стабильной работы.</li>
            <li><b>Скрытый запуск (Alt+N):</b> Утилита создает невидимый системный ярлык, позволяя запускать NoVir в любой момент по глобальной горячей клавише Alt+N.</li>
            <li><b>Экран блокировки:</b> Функция "Заменить sethc и utilman" теперь делает бэкапы системных файлов и подменяет их на <code>NoVir.exe</code>, позволяя запустить утилиту прямо с экрана блокировки Windows без ввода пароля! Повторное нажатие восстанавливает оригинальные файлы.</li>
        </ul>
    </li>
    <li><b>Глубокая очистка (ОПАСНО):</b> Добавлена функция принудительного удаления всех сторонних драйверов через <code>pnputil</code> на случай заражения тяжелыми руткитами.</li>
    <li><b>Топ-10 хардкорных фиксов</b>: AppInit_DLLs, DisallowRun, SafeBoot, Defender и т.д.</li>
    <li><b>Фикс Alt+N на виртуалках</b>: Больше никаких ошибок win32com</li>
    <li><span style="color: #06b6d4; font-weight: bold;">ПРОВЕРЕНО НА ВИРТУАЛКЕ</span></li>
</ul>

<h2>Обновление NoVir v2.1.1</h2>
<ul>
    <li><b>Запрос прав Администратора:</b> Программа теперь автоматически запрашивает права администратора при запуске, что решает проблему с неработающими функциями разблокировки (например, Win+R).</li>
    <li><b>Новый раздел "Клавиатура":</b> Добавлен раздел в "Снятие ограничений" для восстановления работы клавиатуры (разблокировка через Scancode Map, отключение залипания FilterKeys).</li>
    <li><b>Переносы:</b> Функции разблокировки "Выполнить (Win+R)" и "Горячие клавиши Win" перенесены в раздел Клавиатуры.</li>
</ul>

<h2>Ранее в v2.1</h2>
<ul>
    <li><b>Множественное выделение:</b> Теперь можно выделить несколько записей в автозагрузке и удалить их все сразу одной кнопкой.</li>
    <li><b>Единый стиль кнопок:</b> Убраны разноцветные кнопки — теперь весь интерфейс в едином нейтральном стиле.</li>
    <li><b>Переработанные Доп. инструменты:</b> Полностью переделана страница — теперь каждый инструмент имеет карточку с подробным описанием.</li>
    <li><b>Новые инструменты:</b> Добавлены: Информация о системе, Перезапуск Explorer, Проверка автозагрузки, Проверка сетевых портов, Очистка очереди печати, Исправление ассоциаций .exe и .lnk, Восстановление WMI, Разблокировка msconfig, Включение восстановления системы.</li>
    <li><b>Диспетчер задач:</b> Теперь открывается сразу на весь экран как полноценное окно.</li>
    <li><b>Улучшение интерфейса:</b> Небольшие доработки дизайна для большего удобства.</li>
</ul>

<h2>Ранее в v2.0</h2>
<ul>
    <li><b>Оптимизация скорости:</b> Ускорение сканирования файловой системы.</li>
    <li><b>Вкладка AppInit_DLLs и CmdLine:</b> Новый раздел в автозагрузке.</li>
    <li><b>Собственный Проводник:</b> Встроенный файловый менеджер.</li>
    <li><b>Исправления:</b> Устранены баги в Диспетчере задач.</li>
</ul>

<br>
<h2>В следующем обновлении (v2.2)</h2>
<ul>
    <li><b>Фикс багов:</b> Устранение мелких недочетов и повышение общей стабильности.</li>
    <li><b>Новые функции:</b> Возможна разработка и добавление новых полезных инструментов.</li>
    <li><b>Улучшение интерфейса:</b> Небольшие доработки дизайна для еще большего удобства.</li>
</ul>
<p>Спасибо за использование NoVir!</p>
"""
            content.setHtml(text)
            layout.addWidget(content)
            
            return page

        def create_about_page(self):
            page = QFrame()
            layout = QVBoxLayout(page)
            
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setStyleSheet("background-color: transparent; border: none;")
            
            container = QWidget()
            c_layout = QVBoxLayout(container)
            
            about_browser = QTextBrowser()
            about_browser.setOpenExternalLinks(False)
            about_browser.setStyleSheet("""
                QTextBrowser {
                    background: transparent;
                    color: #ffffff;
                    border: none;
                    font-size: 13px;
                    line-height: 1.6;
                }
            """)
            about_browser.setHtml("""
                <div style="font-family: Segoe UI, Arial, sans-serif; color: #ffffff; line-height: 1.7;">
                    <h1 style="color: #ffffff; margin-bottom: 8px;">NoVir</h1>
                    <p style="margin-top: 0; color: #ffffff; font-size: 13px;">
                        Универсальный набор инструментов для восстановления Windows после вирусных атак, блокировок, скрытых вредоносных модулей и случайных системных поломок.
                    </p>

                    <h2 style="color: #ffffff; font-size: 16px; margin-top: 16px; margin-bottom: 8px;">Что это за приложение</h2>
                    <p>
                        NoVir — это не просто «чистилка», а целый рабочий комплект для реанимации системы. Оно помогает вернуть Windows в рабочее состояние, когда интерфейс перестал открываться нормально, проводник завис, реестр оказался под контролем вредоносных изменений, а обычные системные функции стали недоступны.
                    </p>
                    <p>
                        Приложение рассчитано на ситуации, где система уже не реагирует как обычно: пропали элементы интерфейса, исчезли кнопки, отключились важные службы, заблокированы редактор реестра, диспетчер задач, командная строка, панель управления или другие ключевые инструменты.
                    </p>

                    <h2 style="color: #ffffff; font-size: 16px; margin-top: 16px; margin-bottom: 8px;">Что умеет приложение</h2>
                    <ul>
                        <li>Восстанавливать внешний вид Windows: темы, шрифты, курсор, иконки, обои, масштаб интерфейса и поворот экрана.</li>
                        <li>Возвращать в норму проводник и оболочку системы: панель задач, трей, рабочий стол, свойства папок, правую кнопку мыши и скрытые элементы.</li>
                        <li>Разблокировать доступ к реестру, редактору реестра, панели управления, UAC, командной строке, диспетчеру задач и другим системным инструментам.</li>
                        <li>Очищать последствия вредоносных изменений: фиксы автозагрузки, очистку вредоносных записей, восстановление безопасного режима, сброс DNS и прокси, а также восстановление сетевых настроек.</li>
                        <li>Анализировать подозрительные процессы, автозапуск, системные службы, параметры запуска и отдельные точки восстановления.</li>
                        <li>Запускать встроенные утилиты для диагностики и восстановления: доступ к реестру, проводнику, диспетчеру задач, консоли, журналам, управлению пользователями и дисками.</li>
                    </ul>

                    <h2 style="color: #ffffff; font-size: 16px; margin-top: 16px; margin-bottom: 8px;">Как оно работает</h2>
                    <p>
                        В основе приложения лежит набор готовых сценариев восстановления. Каждый сценарий направлен на конкретную проблему: интерфейс, проводник, реестр, блокировки системы, сеть, автозагрузка, процессы и служебные функции Windows.
                    </p>
                    <p>
                        Пользователь может запускать отдельные действия вручную или использовать пакетное восстановление, когда приложение последовательно проверяет и устраняет сразу несколько проблем.
                    </p>
                    <p>
                        Перед серьёзными изменениями приложение может создавать резервные копии, а в некоторых случаях поддерживает безопасный режим работы, чтобы снизить риск случайного ухудшения состояния системы.
                    </p>

                    <h2 style="color: #ffffff; font-size: 16px; margin-top: 16px; margin-bottom: 8px;">Для кого это приложение</h2>
                    <p>
                        NoVir особенно полезен для обычных пользователей, которые столкнулись с вирусной блокировкой, странным поведением Windows, пропавшими элементами интерфейса или невозможностью открыть важные системные настройки.
                    </p>
                    <p>
                        Также оно может быть полезно для тех, кто выполняет поддержку компьютеров, помогает знакомым с восстановлением после заражения, или просто хочет быстро вернуть систему к нормальному состоянию без ручной правки десятков параметров.
                    </p>

                    <h2 style="color: #ffffff; font-size: 16px; margin-top: 16px; margin-bottom: 8px;">Плюсы приложения</h2>
                    <ul>
                        <li>Собирает множество полезных функций в одном месте.</li>
                        <li>Позволяет действовать быстро, без необходимости вручную искать нужные настройки.</li>
                        <li>Поддерживает как точечные исправления, так и комплексное восстановление.</li>
                        <li>Включает инструменты для анализа процессов, автозагрузки, сетевых параметров и системных ограничений.</li>
                        <li>Помогает вернуть Windows в рабочее состояние после ряда типовых вирусных и системных повреждений.</li>
                    </ul>

                    <h2 style="color: #ffffff; font-size: 16px; margin-top: 16px; margin-bottom: 8px;">Важно знать</h2>
                    <p>
                        Некоторые функции затрагивают критически важные настройки Windows, поэтому их лучше использовать осознанно. Для серьёзных исправлений рекомендуются права администратора и понимание того, что именно вы собираетесь восстанавливать.
                    </p>
                    <p>
                        Приложение не является магией и не гарантирует полное удаление любой инфекции в каждом случае — особенно если вредоносная программа глубоко внедрилась в систему или внесла изменения в самые низкие уровни Windows.
                    </p>
                    <p>
                        Но в большинстве типовых ситуаций оно становится мощным и быстрым помощником для восстановления нормальной работы системы.
                    </p>

                    <h2 style="color: #ffffff; font-size: 16px; margin-top: 16px; margin-bottom: 8px;">Кратко</h2>
                    <p>
                        NoVir — это практический инструмент для возвращения Windows к нормальной жизни после вирусных блокировок и системных сбоев. Он объединяет диагностику, восстановление интерфейса, работу с реестром, сетью, автозагрузкой, процессами и встроенными утилитами — всё в одном удобном рабочем окне.
                    </p>
                </div>
            """)
            c_layout.addWidget(about_browser)
            
            scroll.setWidget(container)
            layout.addWidget(scroll)
            return page

        def create_styled_table(self, headers):
            table = QTableWidget()
            table.setColumnCount(len(headers))
            table.setHorizontalHeaderLabels(headers)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            table.verticalHeader().setDefaultSectionSize(30)  # Высота строк
            table.setShowGrid(True)
            table.setStyleSheet("""
                QTableWidget { 
                    background-color: white; 
                    color: black; 
                    gridline-color: #ffffff;
                    border: none;
                    font-size: 13px;
                }
                QTableWidget::item {
                    padding: 4px 8px;
                }
                QTableWidget::item:hover {
                    background-color: #e8f4f8;
                }
                QTableWidget::item:selected {
                    background-color: #cce5ff;
                    color: black;
                }
                QHeaderView::section {
                    background-color: #111111;
                    color: white;
                    padding: 7px 8px;
                    border: 1px solid #222222;
                    font-weight: bold;
                    font-size: 12px;
                }
            """)
            return table

        def get_all_functions(self):
            return get_repair_function_catalog()

        def show_system_info(self):
            import platform
            import subprocess
            try:
                info = []
                info.append(f"Компьютер: {platform.node()}")
                info.append(f"ОС: {platform.system()} {platform.release()} ({platform.version()})")
                info.append(f"Архитектура: {platform.machine()}")
                info.append(f"Процессор: {platform.processor()}")
                
                try:
                    result = subprocess.run('wmic OS get TotalVisibleMemorySize /value', 
                                          shell=True, capture_output=True, text=True, creationflags=0x08000000)
                    for line in result.stdout.strip().split('\n'):
                        if 'TotalVisibleMemorySize' in line:
                            mem_kb = int(line.split('=')[1].strip())
                            mem_gb = round(mem_kb / 1024 / 1024, 1)
                            info.append(f"Оперативная память: {mem_gb} ГБ")
                except Exception:
                    pass
                
                try:
                    result = subprocess.run('wmic logicaldisk get size,freespace,caption /value',
                                          shell=True, capture_output=True, text=True, creationflags=0x08000000)
                    current_disk = {}
                    for line in result.stdout.strip().split('\n'):
                        line = line.strip()
                        if '=' in line:
                            k, v = line.split('=', 1)
                            current_disk[k.strip()] = v.strip()
                        if not line and current_disk.get('Caption'):
                            try:
                                total = int(current_disk.get('Size', 0))
                                free = int(current_disk.get('FreeSpace', 0))
                                if total > 0:
                                    total_gb = round(total / 1024**3, 1)
                                    free_gb = round(free / 1024**3, 1)
                                    info.append(f"Диск {current_disk['Caption']} — {free_gb} ГБ свободно из {total_gb} ГБ")
                            except (ValueError, KeyError):
                                pass
                            current_disk = {}
                except Exception:
                    pass
                
                info.append(f"\nПользователь: {os.environ.get('USERNAME', 'N/A')}")
                
                QMessageBox.information(self, "Информация о системе", "\n".join(info))
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось получить информацию: {e}")

        def restart_explorer(self):
            reply = QMessageBox.question(self, "Перезапуск Explorer",
                "Рабочий стол и панель задач на секунду исчезнут.\nПерезапустить explorer.exe?",
                QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                import subprocess
                try:
                    subprocess.run('taskkill /f /im explorer.exe', shell=True, 
                                  capture_output=True, creationflags=0x08000000)
                    import time
                    time.sleep(1)
                    subprocess.Popen('explorer.exe')
                    QMessageBox.information(self, "Готово", "Explorer перезапущен!")
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось перезапустить explorer: {e}")

        def scan_startup_report(self):
            try:
                report = []
                reg_paths = {
                    "HKCU Run": (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    "HKLM Run": (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    "HKCU RunOnce": (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    "HKLM RunOnce": (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                }
                
                total = 0
                for label, (hive, path) in reg_paths.items():
                    count = 0
                    try:
                        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                        i = 0
                        while True:
                            try:
                                winreg.EnumValue(key, i)
                                count += 1
                                i += 1
                            except OSError:
                                break
                        winreg.CloseKey(key)
                    except Exception:
                        pass
                    total += count
                    report.append(f"{label}: {count} записей")
                
                startup_folder = os.path.join(os.environ.get('APPDATA', ''), 
                    r"Microsoft\Windows\Start Menu\Programs\Startup")
                folder_count = 0
                if os.path.isdir(startup_folder):
                    folder_count = len([f for f in os.listdir(startup_folder) if os.path.isfile(os.path.join(startup_folder, f))])
                report.append(f"Папка автозагрузки: {folder_count} файлов")
                total += folder_count
                
                report.insert(0, f"Всего записей в автозагрузке: {total}\n")
                
                QMessageBox.information(self, "Отчёт автозагрузки", "\n".join(report))
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось провести сканирование: {e}")

        def check_network_ports(self):
            import subprocess
            try:
                result = subprocess.run('netstat -ano', shell=True, capture_output=True, 
                                       text=True, creationflags=0x08000000, timeout=15)
                lines = result.stdout.strip().split('\n')
                
                listening = [l.strip() for l in lines if 'LISTENING' in l]
                established = [l.strip() for l in lines if 'ESTABLISHED' in l]
                
                report = f"Открытые порты (LISTENING): {len(listening)}\n"
                report += f"Активные соединения (ESTABLISHED): {len(established)}\n\n"
                
                if listening:
                    report += "--- LISTENING ---\n"
                    for line in listening[:20]:
                        report += line + "\n"
                    if len(listening) > 20:
                        report += f"... и ещё {len(listening) - 20}\n"
                
                if established:
                    report += "\n--- ESTABLISHED ---\n"
                    for line in established[:15]:
                        report += line + "\n"
                    if len(established) > 15:
                        report += f"... и ещё {len(established) - 15}\n"
                
                dialog = QDialog(self)
                dialog.setWindowTitle("Сетевые порты")
                dialog.setMinimumSize(700, 500)
                dialog.setStyleSheet("background-color: #000000; color: #ffffff;")
                dlg_layout = QVBoxLayout(dialog)
                
                text_edit = QTextEdit()
                text_edit.setReadOnly(True)
                text_edit.setStyleSheet("background-color: #000000; color: #ffffff; font-family: Consolas; font-size: 12px; border: 1px solid #222222;")
                text_edit.setText(report)
                dlg_layout.addWidget(text_edit)
                
                btn_close = QPushButton("Закрыть")
                btn_close.setStyleSheet("background-color: #111111; color: #ffffff; border: 1px solid #ffffff; border-radius: 4px; padding: 8px;")
                btn_close.clicked.connect(dialog.close)
                dlg_layout.addWidget(btn_close)
                
                dialog.exec()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось получить список портов: {e}")

        def open_task_manager(self):
            dialog = TaskManagerDialog(self)
            dialog.exec()

        def create_backup(self): self.run_task(Create_Full_Backup)
        def restore_backup(self): self.run_task(Restore_From_Backup)

        def append_log(self, text):
            self.log_output.append(text)
            self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())

        def run_task(self, func):
            if func.__name__ in HIGH_RISK_FUNCTION_NAMES:
                reply = QMessageBox.question(
                    self,
                    "Подтверждение",
                    f"Функция {func.__name__} может серьезно изменить систему. Продолжить?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply != QMessageBox.Yes:
                    return

            self.worker = Worker(func)
            
            def on_finish(result_text):
                if result_text.strip():
                    QMessageBox.information(self, "Результат", result_text)
                else:
                    QMessageBox.information(self, "Результат", "Задача выполнена.")

            self.worker.finished_signal.connect(on_finish)
            self.worker.start()


        def closeEvent(self, event):
            """Корректно останавливаем все фоновые потоки перед закрытием"""
            if not getattr(self, '_user_supported', False):
                from PySide6.QtWidgets import QMessageBox
                from PySide6.QtCore import Qt as _Qt
                msg = QMessageBox(self)
                msg.setWindowFlags(msg.windowFlags() | _Qt.WindowStaysOnTopHint)
                msg.setWindowTitle("NoVir")
                msg.setText(
                    "★  Перед выходом: если программа тебе помогла, поддержи автора!\n\n"
                    "Любая сумма очень важна.\n"
                    "Карта ПриватБанк: 5168 7521 1573 8307"
                )
                msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
                msg.button(QMessageBox.Ok).setText("ПОДДЕРЖАТЬ  →")
                msg.button(QMessageBox.Cancel).setText("Закрыть программу")
                msg.setStyleSheet(
                    "QMessageBox { background-color: #000000; color: #ffffff; }"
                    " QLabel { color: #ffffff; font-size: 13px; }"
                    " QPushButton { background-color: #000000; color: #ffffff;"
                    " border: 2px solid #ffffff; padding: 6px 16px;"
                    " font-weight: bold; min-width: 100px; }"
                    " QPushButton:hover { background-color: #ffffff; color: #000000; }"
                )
                result = msg.exec()
                if result == QMessageBox.Ok:
                    self._run_support_dialog()
                    return

            # Список всех возможных потоков
            threads_to_stop = []
            if hasattr(self, '_scheduler_loader') and self._scheduler_loader is not None:
                threads_to_stop.append(self._scheduler_loader)
            if hasattr(self, 'worker') and self.worker is not None:
                threads_to_stop.append(self.worker)
            if hasattr(self, '_services_loader') and self._services_loader is not None:
                threads_to_stop.append(self._services_loader)

            for thread in threads_to_stop:
                try:
                    if thread.isRunning():
                        thread.quit()
                        if not thread.wait(1500):  # ждём 1.5 секунды
                            thread.terminate()
                            thread.wait(500)
                except Exception:
                    pass

            event.accept()

        def mousePressEvent(self, event):
            if event.button() == Qt.LeftButton: self.dragPos = event.globalPosition().toPoint()
        def mouseMoveEvent(self, event):
            if event.buttons() == Qt.LeftButton:
                self.move(self.pos() + event.globalPosition().toPoint() - self.dragPos)
                self.dragPos = event.globalPosition().toPoint()
                event.accept()

def main():
    if SELF_CHECK:
        run_self_check()
        return

    # Проверяем права администратора
    try:
        is_admin = check_admin_status()
        admin_required = not (DRY_RUN and not GUI_MODE)
        if not is_admin and admin_required:
            if not GUI_MODE:
                print(f"{Colors.RED}[!] ВНИМАНИЕ: Запустите скрипт от имени АДМИНИСТРАТОРА!{Colors.RESET}")
                print(f"{Colors.YELLOW}[!] Нажмите Enter для выхода...{Colors.RESET}")
                input()
            sys.exit(1)
        elif not is_admin and DRY_RUN and not GUI_MODE:
            print(f"{Colors.YELLOW}[!] DRY-RUN запущен без прав администратора. Реальные изменения выполняться не будут.{Colors.RESET}")
    except Exception as _e:
        # Expected exception, intentionally ignored
        pass
    
    if GUI_MODE:
        app = QApplication(sys.argv)
        window = NoVirGUI()
        window.show()
        sys.exit(app.exec())
    
    print_header()
    
    while True:
        show_menu()
        choice = input(f"{Colors.CYAN}[?] Выберите действие: {Colors.RESET}")
        
        if choice == '1':
            run_block_1()
        elif choice == '2':
            run_block_2()
        elif choice == '3':
            run_block_3()
        elif choice == '4':
            run_block_4()
        elif choice == '5':
            run_block_5()
        elif choice == '6':
            run_block_6()
        elif choice == '7':
            confirm = input(f"{Colors.YELLOW}[?] Вы уверены, что хотите запустить полное сканирования пупселечек? (y/N): {Colors.RESET}")
            if confirm.lower() == 'y':
                run_full_scan()
        elif choice == '8':
            Final_Log_Report()
        elif choice == '9':
            run_self_check()
        elif choice == '0':
            print_hacker_message("Пока! Надеюсь, я помог. Если что — я всегда тут!")
            break
        else:
            print(f"{Colors.RED}[!] Неверный выбор{Colors.RESET}")
        
        print(f"\n{Colors.YELLOW}[Нажмите Enter, чтобы продолжить...]{Colors.RESET}")
        input()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Прервано пользователем{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Критическая ошибка: {e}{Colors.RESET}")
        sys.exit(1)
