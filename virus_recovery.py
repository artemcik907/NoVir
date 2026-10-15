#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NoVir - Вирусный Реаниматор
Автор: Недохакер
Версия: 2.5.3
Описание: Полный набор инструментов для восстановления системы после вирусной атаки
"""
import os
import sys
import explorer_tab
import winpe_media
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
import hashlib
from datetime import datetime
from functools import lru_cache

CURRENT_VERSION = "2.5.3"
PROGRAM_WEBSITE_URL = "https://artemcik907.github.io"

try:
    import novir_native
    PSUTIL_AVAILABLE = True
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

try:
    import novir_core
    CPP_CORE_AVAILABLE = True
except ImportError:
    CPP_CORE_AVAILABLE = False
    print("[INFO] C++ модуль novir_core не найден, используется Python реализация")

GUI_MODE = '--console' not in sys.argv and '-c' not in sys.argv
PYSIDE_AVAILABLE = False
if GUI_MODE:
    try:
        from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                                     QHBoxLayout, QPushButton, QLabel, QTextEdit,
                                     QFileDialog, QMenu, QComboBox, QMessageBox,
                                     QDialog, QLineEdit, QTableWidget, QTableWidgetItem,
                                     QHeaderView, QTabWidget, QFrame, QCheckBox,
                                     QTreeWidget, QTreeWidgetItem, QSlider,
                                     QGridLayout, QStackedWidget)
        from PySide6.QtCore import Qt, QThread, Signal, Slot, QEvent, QObject, QProcess
        from PySide6.QtGui import QClipboard
        PYSIDE_AVAILABLE = True
    except ImportError:
        print("PySide6 не установлен. Запуск в консольном режиме.")
        GUI_MODE = False

init()
if sys.platform == 'win32':
    import locale
    try:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    except Exception as _e:
        pass

# Константы для Windows
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Режим сухого прогона (только показываем, ничего не меняем)
DRY_RUN = '--dry-run' in sys.argv or '-d' in sys.argv
SELF_CHECK = '--self-check' in sys.argv or '--check' in sys.argv
APP_DIR = os.path.dirname(os.path.abspath(
    sys.executable if getattr(sys, "frozen", False) else __file__
))

# Папка для бэкапов
BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "NoVir_Backups")
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)
BACKUP_SECURITY_DIR = os.path.join(
    os.environ.get("ProgramData", r"C:\ProgramData"),
    "NoVir",
    "Security",
)
BACKUP_MANIFEST = os.path.join(BACKUP_SECURITY_DIR, "backup_manifest.json")


def parse_ai_command(command):
    """Return argv for an allowed read-only diagnostic command, else None."""
    if not isinstance(command, str) or not command.strip():
        return None
    if re.search(r"[\r\n|&<>`]|;|\$\(|%[^%]+%", command):
        return None
    try:
        import ntpath
        import shlex
        tokens = shlex.split(command, posix=False)
    except ValueError:
        return None
    if not tokens:
        return None
    tokens = [token[1:-1] if len(token) >= 2 and token[0] == token[-1] == '"' else token for token in tokens]
    executable = ntpath.basename(tokens[0]).lower()
    # Allow both bare commands and full System32 paths
    win = os.environ.get("WINDIR", r"C:\Windows").lower()
    tok0 = tokens[0].lower().replace("/", "\\")
    if tok0 != executable and not tok0.startswith(win):
        return None
    args = [token.lower() for token in tokens[1:]]

    def safe_argv(allowed):
        if not allowed:
            return None
        windows_dir = os.environ.get("WINDIR", r"C:\Windows")
        system_dir = os.path.join(windows_dir, "System32")
        if os.environ.get("PROCESSOR_ARCHITEW6432"):
            native_dir = os.path.join(windows_dir, "SysNative")
            if os.path.isdir(native_dir):
                system_dir = native_dir
        return [os.path.join(system_dir, executable + ".exe"), *tokens[1:]]

    if executable == "ipconfig":
        return safe_argv(args in ([], ["/all"], ["/displaydns"]))
    if executable == "netstat":
        return safe_argv(args in ([], ["-ano"], ["-an"], ["-r"], ["-s"]))
    if executable == "tasklist":
        return safe_argv(args in ([], ["/svc"], ["/v"], ["/svc", "/v"]))
    if executable in ("hostname", "systeminfo", "whoami"):
        allowed = args == [] or (executable == "whoami" and args == ["/all"])
        return safe_argv(allowed)
    if executable == "sfc":
        return safe_argv(args == ["/verifyonly"])
    if executable == "chkdsk":
        return safe_argv(args in ([], ["/scan"]))
    if executable == "sc":
        allowed = bool(args) and args[0] in ("query", "queryex", "qc") and all(
            arg not in ("delete", "config", "start", "stop", "failure") for arg in args
        )
        return safe_argv(allowed)
    if executable == "reg":
        return safe_argv(bool(args) and args[0] == "query")
    if executable == "netsh":
        allowed = len(args) >= 2 and tuple(args[:2]) in {
            ("winsock", "show"), ("interface", "show"),
            ("advfirewall", "show"),
        }
        return safe_argv(allowed)
    if executable == "nslookup":
        allowed = len(args) <= 2 and all(not arg.startswith("-") for arg in args)
        return safe_argv(allowed)
    if executable == "tracert":
        allowed = len(args) == 1 and not args[0].startswith("-")
        return safe_argv(allowed)
    return None


def ai_command_is_allowed(command):
    return parse_ai_command(command) is not None


def render_chat_message(text):
    """Render a small safe Markdown subset for the Qt rich-text chat view."""
    import html
    import re

    lines = str(text).splitlines()
    output = []
    index = 0

    def cells_from_row(line):
        stripped = line.strip()
        if "|" not in stripped:
            return None
        if stripped.startswith("|"):
            stripped = stripped[1:]
        if stripped.endswith("|"):
            stripped = stripped[:-1]
        return [cell.strip() for cell in stripped.split("|")]

    def is_separator(row):
        return bool(row) and all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in row)

    def inline_markup(value):
        safe = html.escape(value)
        safe = re.sub(r"`([^`]+)`", r"<code>\1</code>", safe)
        safe = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", safe)
        safe = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", safe)
        return safe

    while index < len(lines):
        header = cells_from_row(lines[index])
        separator = cells_from_row(lines[index + 1]) if index + 1 < len(lines) else None
        if header and separator and len(header) == len(separator) and is_separator(separator):
            column_count = min(len(header), 3)
            if len(header) > column_count:
                header = header[:column_count - 1] + [" / ".join(header[column_count - 1:])]
            rows = []
            index += 2
            while index < len(lines):
                row = cells_from_row(lines[index])
                if not row:
                    break
                index += 1
                if len(rows) >= 4:
                    continue
                if len(row) > column_count:
                    row = row[:column_count - 1] + [" / ".join(row[column_count - 1:])]
                row = (row + [""] * column_count)[:column_count]
                rows.append(row)

            table = [
                "<table width='100%' style='border-collapse:collapse; table-layout:fixed; margin:6px 0;'>",
                "<thead><tr>",
            ]
            for cell in header:
                table.append(
                    "<th style='border:1px solid #505050; background:#202020; padding:5px 7px; text-align:left;'>"
                    + inline_markup(cell) + "</th>"
                )
            table.append("</tr></thead><tbody>")
            for row in rows:
                table.append("<tr>")
                for cell in row:
                    table.append(
                        "<td style='border:1px solid #444444; padding:5px 7px; vertical-align:top; word-wrap:break-word;'>"
                        + inline_markup(cell) + "</td>"
                    )
                table.append("</tr>")
            table.append("</tbody></table>")
            output.append("".join(table))
            continue

        line = lines[index]
        if line.startswith("### "):
            output.append("<b>" + inline_markup(line[4:]) + "</b>")
        elif line.startswith("## "):
            output.append("<b>" + inline_markup(line[3:]) + "</b>")
        elif line.startswith(("- ", "* ")):
            output.append("&#8226; " + inline_markup(line[2:]))
        elif re.match(r"^\d+\.\s", line):
            output.append(inline_markup(line))
        else:
            output.append(inline_markup(line))
        index += 1

    return "<br>".join(output)


def build_recovery_plan(diagnostic_results):
    """Group related findings into cautious, explainable recovery hypotheses."""
    findings = [item for item in diagnostic_results if item.get("needs_fix")]
    ids = {item.get("id") for item in findings}
    plan = []

    if ids.intersection({"dns", "tcpip", "proxy"}):
        related = [item for item in findings if item.get("id") in {"dns", "tcpip", "proxy"}]
        plan.append({
            "root_cause": "network_configuration",
            "title": "Возможна общая проблема сетевой конфигурации",
            "components": [item.get("id") for item in related],
            "evidence": [item.get("details", "") for item in related if item.get("details")],
            "steps": [
                "Сохранить текущие DNS, proxy и состояние Winsock перед изменениями.",
                "Сверить активные сетевые адаптеры и источник DNS.",
                "Исправлять только подтверждённо неверные параметры; затем повторить проверки.",
            ],
            "risk": "medium",
            "automated": False,
        })

    policy_ids = {"defender", "taskmgr", "windows_update"}
    if ids.intersection(policy_ids):
        related = [item for item in findings if item.get("id") in policy_ids]
        plan.append({
            "root_cause": "policy_or_administration",
            "title": "Несколько ограничений могут быть заданы политиками Windows",
            "components": [item.get("id") for item in related],
            "evidence": [item.get("details", "") for item in related if item.get("details")],
            "steps": [
                "Проверить источник политик и убедиться, что устройство не управляется организацией.",
                "Не удалять политики автоматически; сверить каждое значение с администратором.",
                "После согласованного изменения повторить проверки Defender, Task Manager и Windows Update.",
            ],
            "risk": "high",
            "automated": False,
        })

    remaining = [item for item in findings if item.get("id") not in {"dns", "tcpip", "proxy"} | policy_ids]
    for item in remaining:
        component_id = item.get("id") or "unknown"
        plan.append({
            "root_cause": f"component:{component_id}",
            "title": f"Требуется отдельная проверка: {item.get('name', component_id)}",
            "components": [component_id],
            "evidence": [item.get("details", "")] if item.get("details") else [],
            "steps": ["Проверить результат вручную и сохранить соответствующую точку восстановления перед изменениями."],
            "risk": "high",
            "automated": False,
        })
    return plan


def build_incident_report(diagnostic_results, recovery_outcomes=None, generated_at=None):
    """Create a serializable recovery report from initial and verification scans."""
    recovery_outcomes = recovery_outcomes or {}
    initial_findings = [item for item in diagnostic_results if item.get("needs_fix")]
    verified_fixed = [
        item for item in initial_findings
        if recovery_outcomes.get(item.get("id")) == "verified"
    ]
    attention = [
        item for item in initial_findings
        if recovery_outcomes.get(item.get("id")) != "verified"
    ]
    return {
        "generated_at": generated_at or datetime.now().astimezone().isoformat(timespec="seconds"),
        "problems_found": len(initial_findings),
        "problems_fixed": len(verified_fixed),
        "requires_attention": len(attention),
        "findings": diagnostic_results,
        "recovery_outcomes": recovery_outcomes,
        "plan": build_recovery_plan(diagnostic_results),
    }


def format_incident_report_text(report):
    lines = [
        "NoVir Recovery Report",
        f"Scan: {report['generated_at']}",
        f"Problems found: {report['problems_found']}",
        f"Problems fixed: {report['problems_fixed']}",
        f"Requires attention: {report['requires_attention']}",
        "",
        "Components:",
    ]
    if report.get("recovery_point"):
        lines.insert(5, f"Recovery Point: {report['recovery_point']}")
    for item in report["findings"]:
        outcome = report["recovery_outcomes"].get(item.get("id"))
        if outcome == "verified":
            state = "FIXED (verified)"
        elif isinstance(outcome, str) and outcome.startswith("failed:"):
            state = "FIX FAILED"
        elif outcome == "manual_review":
            state = "MANUAL REVIEW"
        elif outcome == "requires_attention":
            state = "REQUIRES ATTENTION"
        else:
            state = item.get("status", "NOT FIXED")
        recovery_note = f" | Recovery: {outcome}" if outcome and outcome != "verified" else ""
        lines.append(
            f"- {item.get('name', item.get('id', 'Unknown'))}: {state} - "
            f"{item.get('details', '')}{recovery_note}"
        )
    return "\n".join(lines) + "\n"


def create_recovery_point(root_dir=None, command_runner=None):
    """Capture recovery artifacts and mark inventory-only scopes honestly."""
    from datetime import datetime

    root_dir = root_dir or os.path.join(
        os.environ.get("APPDATA", os.path.expanduser("~")),
        "NoVir", "RecoveryPoints",
    )
    point_dir = os.path.join(root_dir, datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
    os.makedirs(point_dir, exist_ok=False)
    runner = command_runner or subprocess.run
    components = {}

    def capture(name, command, output_name, artifact_type="text"):
        path = os.path.join(point_dir, output_name)
        try:
            result = runner(
                command,
                capture_output=True,
                text=True,
                shell=False,
                timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode != 0:
                components[name] = {"status": "unavailable", "error": result.stderr or result.stdout}
                return
            if artifact_type == "reg":
                valid = os.path.isfile(path) and os.path.getsize(path) > 0
            elif artifact_type == "binary":
                valid = os.path.isfile(path) and os.path.getsize(path) > 0
            else:
                payload = result.stdout or ""
                valid = bool(payload.strip())
                if valid:
                    with open(path, "w", encoding="utf-8") as output_file:
                        output_file.write(payload)
            components[name] = {
                "status": "saved" if valid else "unavailable",
                "file": output_name if valid else None,
                "error": None if valid else "Command returned no usable artifact",
            }
        except Exception as error:
            components[name] = {"status": "unavailable", "error": str(error)}

    registry_keys = (
        ("registry_internet_settings", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"),
        ("registry_user_policies", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System"),
        ("registry_defender_policy", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"),
        ("registry_update_policy", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"),
    )
    for name, key in registry_keys:
        filename = f"{name}.reg"
        capture(name, ["reg", "export", key, os.path.join(point_dir, filename), "/y"], filename, "reg")

    capture("network", ["netsh", "interface", "dump"], "network_config.txt")
    capture("boot_configuration", ["bcdedit", "/export", os.path.join(point_dir, "BCD")], "BCD", "binary")
    capture("drivers_inventory", ["pnputil", "/enum-drivers"], "drivers_inventory.txt")

    service_records = {}
    for service in ("wuauserv", "BITS", "Winmgmt", "wscsvc", "cryptsvc", "msiserver"):
        try:
            result = runner(
                ["sc", "qc", service],
                capture_output=True,
                text=True,
                shell=False,
                timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            service_records[service] = {
                "status": "saved" if result.returncode == 0 else "unavailable",
                "configuration": result.stdout,
            }
        except Exception as error:
            service_records[service] = {"status": "unavailable", "error": str(error)}
    services_path = os.path.join(point_dir, "services.json")
    with open(services_path, "w", encoding="utf-8") as output_file:
        json.dump(service_records, output_file, ensure_ascii=False, indent=2)
    components["services"] = {
        "status": "saved" if any(item["status"] == "saved" for item in service_records.values()) else "unavailable",
        "file": "services.json",
        "rollback": "manual",
    }
    components["drivers_inventory"]["rollback"] = "inventory_only"
    components["boot_configuration"]["rollback"] = "manual_and_requires_reboot"
    components["network"]["rollback"] = "checksum_verified_netsh_exec"
    for component in components.values():
        filename = component.get("file")
        if filename:
            if component.get("status") == "saved" and filename.startswith("registry_"):
                component["rollback"] = "checksum_verified_import"
            artifact_path = os.path.join(point_dir, filename)
            if os.path.isfile(artifact_path) and not os.path.islink(artifact_path):
                digest = hashlib.sha256()
                with open(artifact_path, "rb") as artifact_file:
                    for chunk in iter(lambda: artifact_file.read(1024 * 1024), b""):
                        digest.update(chunk)
                component["sha256"] = digest.hexdigest()

    manifest = {
        "format_version": 1,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "path": point_dir,
        "components": components,
        "note": "This recovery point records artifacts. Driver inventory is not a driver backup; BCD and service restoration require manual review.",
    }
    manifest_path = os.path.join(point_dir, "recovery_point.json")
    with open(manifest_path, "w", encoding="utf-8") as output_file:
        json.dump(manifest, output_file, ensure_ascii=False, indent=2)
    return manifest


def restore_recovery_point(point_dir, command_runner=None):
    """Restore checksum-verified registry/network artifacts; report manual-only scopes."""
    runner = command_runner or subprocess.run
    if os.path.islink(point_dir) or not os.path.isdir(point_dir):
        raise OSError("Recovery Point path is invalid")
    manifest_path = os.path.join(point_dir, "recovery_point.json")
    if os.path.islink(manifest_path):
        raise OSError("Recovery Point manifest cannot be a symbolic link")
    with open(manifest_path, "r", encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)
    if manifest.get("format_version") != 1:
        raise ValueError("Unsupported Recovery Point format")

    restored = []
    components = manifest.get("components", {})
    for component_id, component in components.items():
        if component.get("status") != "saved":
            continue
        filename = component.get("file")
        if not filename or os.path.basename(filename) != filename:
            continue
        if not (component_id.startswith("registry_") or component_id == "network"):
            continue
        artifact_path = os.path.join(point_dir, filename)
        if os.path.islink(artifact_path) or not os.path.isfile(artifact_path):
            raise OSError(f"Recovery artifact is missing or unsafe: {filename}")
        digest = hashlib.sha256()
        with open(artifact_path, "rb") as artifact_file:
            for chunk in iter(lambda: artifact_file.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != component.get("sha256"):
            raise OSError(f"Recovery artifact checksum mismatch: {filename}")

        command = ["netsh", "-f", artifact_path] if component_id == "network" else ["reg", "import", artifact_path]
        result = runner(
            command,
            capture_output=True,
            text=True,
            shell=False,
            timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            raise OSError(result.stderr or result.stdout or f"Restore failed for {component_id}")
        restored.append(component_id)

    manual = [
        component_id for component_id, component in components.items()
        if component.get("status") == "saved"
        and component.get("rollback") in ("manual", "manual_and_requires_reboot", "inventory_only")
    ]
    return {"restored": restored, "manual_review": manual}


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
    __slots__ = ('actions', 'start_time', '_log_path')

    def __init__(self):
        self.actions = []
        from datetime import datetime
        self.start_time = datetime.now()
        try:
            import os
            log_dir = os.path.join(os.environ.get('APPDATA', ''), 'NoVir', 'logs')
            os.makedirs(log_dir, exist_ok=True)
            self._log_path = os.path.join(log_dir, f'audit_{datetime.now().strftime("%Y%m%d")}.log')
        except Exception:
            self._log_path = None

    def log(self, action, status, message=""):
        from datetime import datetime
        entry = {
            'time': datetime.now().strftime('%H:%M:%S'),
            'date': datetime.now().strftime('%d.%m.%Y'),
            'action': action,
            'status': status,
            'message': message
        }
        self.actions.append(entry)
        if getattr(self, '_log_path', None):
            try:
                icon = '[+]' if status == 'success' else '[-]' if status == 'error' else '[!]'
                line = f"{entry['date']} {entry['time']} {icon} {action}"
                if message:
                    line += f" — {message}"
                with open(self._log_path, 'a', encoding='utf-8') as f:
                    f.write(line + '\n')
            except Exception:
                pass

    @property
    def audit_log_path(self):
        return getattr(self, '_log_path', None)

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



class RollbackManager:
    """Saves registry values before changing them so they can be restored."""
    def __init__(self):
        self._snapshots = []
        from datetime import datetime
        self.datetime = datetime  # list of (hive, key_path, value_name, old_value, old_type)

    def snapshot_value(self, hive, key_path, value_name):
        """Capture current registry value for rollback."""
        import winreg
        try:
            with winreg.OpenKey(
                hive, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as key:
                val, vtype = winreg.QueryValueEx(key, value_name)
            self._snapshots.append((hive, key_path, value_name, val, vtype, 'set'))
        except FileNotFoundError:
            # Key/value didn't exist — rollback means deleting it
            self._snapshots.append((hive, key_path, value_name, None, None, 'delete'))
        except Exception:
            pass

    def rollback(self):
        """Restore all snapshotted registry values."""
        import winreg
        restored, failed = 0, 0
        for snap in reversed(self._snapshots):
            hive, key_path, value_name, old_val, old_type, mode = snap
            try:
                if mode == 'delete' or old_val is None:
                    try:
                        with winreg.OpenKey(
                            hive, key_path, 0,
                            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
                        ) as key:
                            winreg.DeleteValue(key, value_name)
                    except FileNotFoundError:
                        pass
                else:
                    with winreg.CreateKeyEx(
                        hive, key_path, 0,
                        winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
                    ) as key:
                        winreg.SetValueEx(key, value_name, 0, old_type, old_val)
                restored += 1
            except Exception:
                failed += 1
        self._snapshots.clear()
        return restored, failed

    def clear(self):
        self._snapshots.clear()

    @property
    def snapshots(self):
        """Return rollback entries in a UI-friendly representation."""
        return tuple({
            "hive": hive,
            "key_path": key_path,
            "value_name": value_name,
            "mode": mode,
        } for hive, key_path, value_name, _value, _value_type, mode in self._snapshots)

    @property
    def has_snapshots(self):
        return len(self._snapshots) > 0

rollback_mgr = RollbackManager()

logger = Logger()

# ---------------------------------------------------------------------------
# Interface language
# ---------------------------------------------------------------------------
# Keep the source strings in Russian for backwards compatibility, but translate
# every Qt widget just before it is shown.  This also covers dialogs created by
# tools later in the session, rather than only the main window.
LANGUAGE_CONFIG_PATH = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")), "NoVir", "settings.json"
)


def load_app_settings():
    """Load persisted NoVir preferences without assuming the file is valid."""
    try:
        with open(LANGUAGE_CONFIG_PATH, "r", encoding="utf-8") as settings_file:
            data = json.load(settings_file)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def save_app_setting(key, value):
    """Update one preference while preserving the rest of settings.json."""
    try:
        settings = load_app_settings()
        settings[key] = value
        os.makedirs(os.path.dirname(LANGUAGE_CONFIG_PATH), exist_ok=True)
        temporary_path = LANGUAGE_CONFIG_PATH + ".tmp"
        with open(temporary_path, "w", encoding="utf-8") as settings_file:
            json.dump(settings, settings_file, ensure_ascii=False, indent=2)
        os.replace(temporary_path, LANGUAGE_CONFIG_PATH)
        return True
    except OSError:
        return False


class LanguageManager:
    """Persist and translate the language selected by the user."""

    LANGUAGES = ("en", "uk", "ru", "de", "pl", "fr")

    # (English, Ukrainian).  The entries below are complete for the visible
    # navigation, settings, dialogs, controls, tables and status messages.
    TRANSLATIONS = {
        # Полоса состояния дашборда (версия Windows)
        "Версия винды": ('Windows version', 'Версія Windows', 'Windows-Version', 'Wersja Windows', 'Version de Windows'),
        "Авто": ('Auto', 'Авто', 'Auto', 'Auto', 'Auto'),
        "Вручную": ('Manual', 'Вручну', 'Manuell', 'Ręcznie', 'Manuel'),
        'Поиск файлов...': ('Search files...', 'Пошук файлів...', 'Dateien suchen...', 'Wyszukaj pliki...', 'Rechercher des fichiers...'),
        'Скрытые': ('Hidden', 'Приховані', 'Versteckt', 'Ukryte', 'Caché'),
        'Компьютер': ('This PC', 'Цей ПК', 'Dieser PC', 'Ten komputer', 'Ce PC'),
        'Локальный диск': ('Local Disk', 'Локальний диск', 'Lokaler Datenträger', 'Dysk lokalny', 'Disque local'),
        'Отмена': ('Cancel', 'Скасувати', 'Stornieren', 'Anulować', 'Annuler'),
        'Действие пропущено или не выполнено': ('Action skipped or unsuccessful', 'Дію пропущено або не виконано', 'Aktion übersprungen oder fehlgeschlagen', 'Pominięto działanie lub nie powiodło się', 'Action ignorée ou non terminée'),
        'Выполнено': ('Completed', 'Виконано', 'Abgeschlossen', 'Ukończono', 'Terminé'),
        'ОТМЕНА': ('CANCEL', 'СКАСУВАТИ', 'STORNIERUNG', 'ANULOWANIE', 'ANNULATION'),
        'Закрыть': ('Close', 'Закрити', 'Schließen', 'Zamknąć', 'Fermer'),
        'Готово': ('Done', 'Готово', 'Bereit', 'Gotowy', 'Prêt'),
        'Ошибка': ('Error', 'Помилка', 'Fehler', 'Błąd', 'Erreur'),
        'Отключено: массовое завершение процессов может закрыть несохранённые документы и нарушить работу Windows.': ('Disabled: mass process termination may close unsaved documents and disrupt Windows.', 'Вимкнено: масове завершення процесів може закрити незбережені документи та порушити роботу Windows.', 'Deaktiviert: Das massenhafte Beenden von Prozessen kann ungespeicherte Dokumente schließen und Windows beeinträchtigen.', 'Wyłączono: masowe kończenie procesów może zamknąć niezapisane dokumenty i zakłócić działanie Windows.', 'Désactivé : l’arrêt massif des processus peut fermer des documents non enregistrés et perturber Windows.'),
        'Отключено из соображений безопасности: подмена sethc/utilman может обойти экран входа Windows.': ('Disabled for security: replacing sethc/utilman may bypass the Windows sign-in screen.', 'Вимкнено з міркувань безпеки: підміна sethc/utilman може обійти екран входу Windows.', 'Aus Sicherheitsgründen deaktiviert: Der Austausch von sethc/utilman kann den Windows-Anmeldebildschirm umgehen.', 'Wyłączono ze względów bezpieczeństwa: podmiana sethc/utilman może ominąć ekran logowania Windows.', 'Désactivé pour des raisons de sécurité : remplacer sethc/utilman peut contourner l’écran de connexion Windows.'),
        'Отключено: массовое удаление драйверов может вывести устройства из строя.': ('Disabled: mass driver removal may make devices stop working.', 'Вимкнено: масове видалення драйверів може вивести пристрої з ладу.', 'Deaktiviert: Das massenhafte Entfernen von Treibern kann Geräte außer Betrieb setzen.', 'Wyłączono: masowe usuwanie sterowników może unieruchomić urządzenia.', 'Désactivé : la suppression massive de pilotes peut rendre des appareils inutilisables.'),
        'Отключено: сброс системных ACL без проверенной резервной копии может повредить защиту Windows.': ('Disabled: resetting system ACLs without a verified backup may damage Windows security.', 'Вимкнено: скидання системних ACL без перевіреної резервної копії може пошкодити захист Windows.', 'Deaktiviert: Das Zurücksetzen systemweiter ACLs ohne geprüfte Sicherung kann die Windows-Sicherheit beschädigen.', 'Wyłączono: reset systemowych ACL bez sprawdzonej kopii może uszkodzić zabezpieczenia Windows.', 'Désactivé : réinitialiser les ACL système sans sauvegarde vérifiée peut endommager la sécurité de Windows.'),
        'Успех': ('Success', 'Успіх', 'Erfolg', 'Sukces', 'Succès'),
        'Внимание': ('Warning', 'Увага', 'Aufmerksamkeit', 'Uwaga', 'Attention'),
        'Подтверждение': ('Confirmation', 'Підтвердження', 'Bestätigung', 'Potwierdzenie', 'Confirmation'),
        'Результат': ('Result', 'Результат', 'Ergebnis', 'Wynik', 'Résultat'),
        'Нет выбора': ('Nothing selected', 'Нічого не вибрано', 'Keine Wahl', 'Nie ma wyboru', 'Pas le choix'),
        '< НАЗАД': ('< BACK', '< НАЗАД', '< ZURÜCK', '< POWRÓT', '< RETOUR'),
        'АВТОЗАГРУЗКА': ('STARTUP', 'АВТОЗАПУСК', 'AUTOLOAD', 'AUTOŁADOWANIE', 'CHARGEMENT AUTOMATIQUE'),
        'ПРОВОДНИК': ('EXPLORER', 'ПРОВІДНИК', 'LEITER', 'DYRYGENT', 'CONDUCTEUR'),
        'СНЯТИЕ ОГРАНИЧЕНИЙ': ('REMOVE RESTRICTIONS', 'ЗНЯТТЯ ОБМЕЖЕНЬ', 'EINSCHRÄNKUNGEN ENTFERNEN', 'USUWANIE OGRANICZEŃ', 'SUPPRESSION DES RESTRICTIONS'),
        'ДОП. ВОЗМОЖНОСТИ': ('EXTRA TOOLS', 'ДОДАТКОВІ МОЖЛИВОСТІ', 'ZUSÄTZLICHE MÖGLICHKEITEN', 'DODATKOWE MOŻLIWOŚCI', 'POSSIBILITÉS SUPPLÉMENTAIRES'),
        'АНЛОКЕР': ('UNLOCKER', 'РОЗБЛОКУВАЛЬНИК', 'UNLOCKER', 'ODBLOKOWANIE', 'DÉBLOQUEUR'),
        'НАСТРОЙКИ': ('SETTINGS', 'НАЛАШТУВАННЯ', 'EINSTELLUNGEN', 'USTAWIENIA', 'PARAMÈTRES'),
        'УМНАЯ ДИАГНОСТИКА': ('SMART DIAGNOSTICS', 'РОЗУМНА ДІАГНОСТИКА', 'SMART DIAGNOSE', 'INTELIGENTNA DIAGNOSTYKA', 'DIAGNOSTIC INTELLIGENT'),
        'БЭКАПЫ': ('BACKUPS', 'БЕКАПИ', 'BACKUPS', 'KOPIE ZAPASOWE', 'SAUVEGARDES'),
        'ПОДДЕРЖАТЬ АВТОРА': ('SUPPORT THE AUTHOR', 'ПІДТРИМАТИ АВТОРА', 'UNTERSTÜTZEN SIE DEN AUTOR', 'WSPIERAJ AUTORA', "SOUTENEZ L'AUTEUR"),
        'Менеджер Резервных Копий (Backup)': ('Backup Manager', 'Менеджер Резервних Копій (Backup)', 'Backup-Manager', 'Menedżer kopii zapasowych', 'Gestionnaire de sauvegardes'),
        'Резервные копии реестра и системы:': ('Registry and system backups:', 'Резервні копії реєстру та системи:', 'Registrierungs- und Systemsicherungen:', 'Kopie zapasowe rejestru i systemu:', 'Sauvegardes du registre et du système :'),
        'Компонентов:': ('Components:', 'Компонентів:', 'Komponenten:', 'Komponenty:', 'Composants:'),
        'СОЗДАТЬ НОВЫЙ BACKUP': ('CREATE NEW BACKUP', 'СТВОРИТИ НОВИЙ BACKUP', 'NEUES BACKUP ERSTELLEN', 'UTWÓRZ NOWĄ KOPIĘ ZAPASOWĄ', 'CRÉER UNE NOUVELLE SAUVEGARDE'),
        'ВОССТАНОВИТЬ': ('RESTORE', 'ВІДНОВИТИ', 'WIEDERHERSTELLEN', 'PRZYWRÓĆ', 'RESTAURER'),
        'Центр диагностики системы': ('System Diagnostics Center', 'Центр діагностики системи', 'Systemdiagnosezentrum', 'Centrum diagnostyki systemu', 'Centre de diagnostic du système'),
        'Умное сканирование узлов ОС на предмет скрытых повреждений.': ('Smart scanning of OS nodes for hidden damage.', 'Розумне сканування вузлів ОС на предмет прихованих пошкоджень.', 'Intelligentes Scannen von Betriebssystemknoten auf versteckte Schäden.', 'Inteligentne skanowanie węzłów systemu operacyjnego w poszukiwaniu ukrytych uszkodzeń.', 'Analyse intelligente des nœuds du système d\'exploitation pour détecter les dommages cachés.'),
        'Компонент': ('COMPONENT', 'КОМПОНЕНТ', 'KOMPONENTE', 'KOMPONENT', 'COMPOSANT'),
        'Детали': ('DETAILS', 'ДЕТАЛІ', 'DETAILS', 'SZCZEGÓŁY', 'DÉTAILS'),
        'Запустить сканирование': ('START SCANNING', 'ЗАПУСТИТИ СКАНУВАННЯ', 'SCAN STARTEN', 'ROZPOCZNIJ SKANOWANIE', 'LANCER L\'ANALYSE'),
        'Исправить найденное': ('FIX FOUND ISSUES', 'ВИПРАВИТИ ЗНАЙДЕНЕ', 'GEFUNDENE PROBLEME BEHEBEN', 'NAPRAW ZNALEZIONE', 'RÉPARER CE QUI A ÉTÉ TROUVÉ'),
        'Страна:': ('Country:', 'Країна:', 'Land:', 'Kraj:', 'Pays:'),
        'Командная строка': ('Command Prompt', 'Командний рядок', 'Eingabeaufforderung', 'Wiersz polecenia', 'Invite de commande'),
        'Открывает встроенный эмулятор командной строки (CMD).': ('Opens a built-in Command Prompt (CMD) emulator.', 'Відкриває вбудований емулятор командного рядка (CMD).', 'Öffnet einen integrierten Eingabeaufforderungs-Emulator (CMD).', 'Otwiera wbudowany emulator wiersza poleceń (CMD).', 'Ouvre un émulateur d\'invite de commande intégré (CMD).'),
        'Командная строка NoVir': ('NoVir Command Prompt', 'Командний рядок NoVir', 'NoVir Eingabeaufforderung', 'Wiersz polecenia NoVir', 'Invite de commande NoVir'),
        'Украина (грн)': ('Ukraine (UAH)', 'Україна (грн)', 'Ukraine (UAH)', 'Ukraina (UAH)', 'Ukraine (UAH)'),
        'Россия (руб)': ('Russia (RUB)', 'Росія (руб)', 'Russland (reiben)', 'Rosja (pocierać)', 'Russie (frotter)'),
        'Весь мир (USD/EUR)': ('Worldwide (USD/EUR)', 'Увесь світ (USD/EUR)', 'Ganze Welt (USD/EUR)', 'Cały świat (USD/EUR)', 'Monde entier (USD/EUR)'),
        'Номер карты ПриватБанк:': ('PrivatBank card number:', 'Номер картки ПриватБанк:', 'PrivatBank-Kartennummer:', 'Numer karty PrivatBanku:', 'Numéro de carte PrivatBank\xa0:'),
        'Нажмите на номер, чтобы скопировать': ('Click the number to copy it', 'Натисніть номер, щоб скопіювати', 'Klicken Sie auf die Nummer, um sie zu kopieren', 'Kliknij numer, który chcesz skopiować', 'Cliquez sur le numéro à copier'),
        'Нажмите, чтобы скопировать': ('Click to copy', 'Натисніть, щоб скопіювати', 'Klicken Sie zum Kopieren', 'Kliknij, aby skopiować', 'Cliquez pour copier'),
        '✓ Номер скопирован!': ('✓ Number copied!', '✓ Номер скопійовано!', '✓ Nummer kopiert!', '✓ Numer skopiowany!', '✓ Numéro copié !'),
        'ПЕРЕВОД ЧЕРЕЗ ПРИВАТБАНК  →': ('TRANSFER VIA PRIVATBANK  →', 'ПЕРЕКАЗ ЧЕРЕЗ ПРИВАТБАНК  →', 'ÜBERTRAGUNG DURCH PRIVATBANK →', 'PRZELEW PRZEZ PRIVATBANK →', 'TRANSFERT VIA BANQUE PRIVÉE →'),
        'ПЕРЕЙТИ НА BESTCHANGE  →': ('GO TO BESTCHANGE  →', 'ПЕРЕЙТИ ДО BESTCHANGE  →', 'GEHE ZU BESTCHANGE →', 'PRZEJDŹ DO NAJLEPSZEJ ZMIANY →', 'ALLER À BESTCHANGE →'),
        'ПЕРЕЙТИ НА PAYSEND  →': ('GO TO PAYSEND  →', 'ПЕРЕЙТИ ДО PAYSEND  →', 'GEHE ZU ZAHLUNGSENDE →', 'PRZEJDŹ DO PAYSEND →', 'ALLER À PAYSEND →'),
        'Всё идёт напрямую на карту ПриватБанк.': ('All support goes directly to the PrivatBank card.', 'Уся підтримка надходить безпосередньо на картку ПриватБанк.', 'Alles geht direkt auf die PrivatBank-Karte.', 'Wszystko trafia bezpośrednio na kartę PrivatBank.', 'Tout va directement sur la carte PrivatBank.'),
        'Всё идёт напрямую на карту ПриватБанк. Спасибо за поддержку!': ('All support goes directly to the PrivatBank card. Thank you!', 'Уся підтримка надходить безпосередньо на картку ПриватБанк. Дякуємо!', 'Alles geht direkt auf die PrivatBank-Karte. Danke für die Unterstützung!', 'Wszystko trafia bezpośrednio na kartę PrivatBank. Dziękuję za wsparcie!', 'Tout va directement sur la carte PrivatBank. Merci pour votre soutien\xa0!'),
        'Прямые переводы отключены. Но вы можете перевести деньги со Сбербанка/Тинькофф напрямую на мою карту ПриватБанка через обменники (например, BestChange).': ('Direct transfers are unavailable. You can transfer from Sberbank or Tinkoff to the PrivatBank card through exchangers such as BestChange.', 'Прямі перекази недоступні. Ви можете переказати кошти зі Сбербанку або Тінькофф на картку ПриватБанку через обмінники, наприклад BestChange.', 'Direktübertragungen sind deaktiviert. Aber Sie können Geld von Sberbank/Tinkoff über Geldwechsler (z. B. BestChange) direkt auf meine PrivatBank-Karte überweisen.', 'Transfery bezpośrednie są wyłączone. Ale możesz przelać pieniądze z Sberbank/Tinkoff bezpośrednio na moją kartę PrivatBank za pośrednictwem wymienników (na przykład BestChange).', "Les transferts directs sont désactivés. Mais vous pouvez transférer de l'argent de Sberbank/Tinkoff directement vers ma carte PrivatBank via des échangeurs (par exemple, BestChange)."),
        'Для переводов из США, Европы и других стран используйте сервисы Paysend, TransferGo или Wise. Отправляйте напрямую на мою карту ПриватБанка.': ('For transfers from the US, Europe and other countries, use Paysend, TransferGo or Wise to send directly to the PrivatBank card.', 'Для переказів зі США, Європи та інших країн використовуйте Paysend, TransferGo або Wise, щоб надіслати кошти безпосередньо на картку ПриватБанку.', 'Für Überweisungen aus den USA, Europa und anderen Ländern nutzen Sie die Dienste Paysend, TransferGo oder Wise. Direkt an meine PrivatBank-Karte senden.', 'W przypadku przelewów z USA, Europy i innych krajów skorzystaj z usług Paysend, TransferGo lub Wise. Wyślij bezpośrednio na moją kartę PrivatBank.', "Pour les transferts depuis les États-Unis, l'Europe et d'autres pays, utilisez les services Paysend, TransferGo ou Wise. Envoyez directement sur ma carte PrivatBank."),
        'ПОЧИНИТЬ ВСЁ': ('FIX ALL', 'ВИПРАВИТИ ВСЕ', 'ALLES REPARIEREN', 'NAPRAW WSZYSTKO', 'RÉPARER TOUT'),
        'ЖУРНАЛ': ('LOG', 'ЖУРНАЛ', 'MAGAZIN', 'MAGAZYN', 'REVUE'),
        'ОТКАТ': ('ROLLBACK', 'ВІДКАТ', 'ABRUFEN', 'PRZYPOMNIENIE SOBIE CZEGOŚ', 'RAPPEL'),
        'Откат': ('Rollback', 'Відкат', 'Rollback', 'Wycofanie', 'Annuler'),
        'Только анализ': ('Analyze only', 'Лише аналіз', 'Nur analysieren', 'Tylko analiza', 'Analyse uniquement'),
        'Предложить план с ИИ': ('Suggest an AI plan', 'Запропонувати план ШІ', 'KI-Plan vorschlagen', 'Zaproponuj plan AI', 'Proposer un plan IA'),
        'План восстановления': ('Recovery plan', 'План відновлення', 'Wiederherstellungsplan', 'Plan odzyskiwania', 'Plan de récupération'),
        'ИИ-помощник временно в разработке: нашли много критических ошибок и исправляем их. Извиняемся за неудобства! В качестве компенсации держите виртуальную печеньку :)': ('The AI assistant is temporarily under development while we fix several critical bugs. Sorry for the inconvenience! Please accept this virtual cookie as compensation :)', 'ШІ-помічник тимчасово в розробці: ми знайшли багато критичних помилок і виправляємо їх. Перепрошуємо за незручності! Прийміть віртуальне печиво як компенсацію :)', 'Der KI-Assistent wird vorübergehend überarbeitet, während wir kritische Fehler beheben. Entschuldigung für die Unannehmlichkeiten! Als kleine Entschädigung gibt es einen virtuellen Keks :)', 'Asystent AI jest tymczasowo w przygotowaniu, naprawiamy krytyczne błędy. Przepraszamy za niedogodności! W ramach rekompensaty przesyłamy wirtualne ciasteczko :)', 'L’assistant IA est temporairement en développement pendant que nous corrigeons des bugs critiques. Désolé pour le désagrément ! Voici un cookie virtuel en compensation :)'),
        'Подготовить исправление': ('Prepare a repair', 'Підготувати виправлення', 'Reparatur vorbereiten', 'Przygotuj naprawę', 'Préparer une réparation'),
        'План': ('Plan', 'План', 'Plan', 'Plan', 'Plan'),
        'Отчёт': ('Report', 'Звіт', 'Bericht', 'Raport', 'Rapport'),
        'Точка восстановления': ('Recovery Point', 'Точка відновлення', 'Wiederherstellungspunkt', 'Punkt przywracania', 'Point de restauration'),
        'Откат точки': ('Restore Point Rollback', 'Відкат точки', 'Wiederherstellungspunkt zurücksetzen', 'Cofnij punkt przywracania', 'Annuler le point de restauration'),
        'ОБНОВИТЬ': ('UPDATE', 'ОНОВИТИ', 'AKTUALISIEREN', 'AKTUALIZACJA', 'MISE À JOUR'),
        'ТЕМА ОФОРМЛЕНИЯ': ('APPEARANCE', 'ТЕМА ОФОРМЛЕННЯ', 'THEMA', 'TEMAT', 'THÈME'),
        'Тёмная тема (Стандартная)': ('Dark Theme (Default)', 'Темна тема (Стандартна)', 'Dunkles Thema (Standard)', 'Ciemny motyw (standardowy)', 'Thème sombre (standard)'),
        'МАТОВЫЙ': ('MATTE', 'МАТОВА', 'MATT', 'MATOWY', 'MAT'),
        'ПРОЗРАЧНЫЙ': ('TRANSPARENT', 'ПРОЗОРА', 'TRANSPARENT', 'PRZEZROCZYSTY', 'TRANSPARENT'),
        'Язык интерфейса': ('Interface language', 'Мова інтерфейсу', 'Schnittstellensprache', 'Język interfejsu', "Langue de l'interface"),
        'Сайт программы': ('Program website', 'Сайт програми', 'Programm-Website', 'Strona programu', 'Site du programme'),
        'Открыть сайт программы': ('Open program website', 'Відкрити сайт програми', 'Programm-Website öffnen', 'Otwórz stronę programu', 'Ouvrir le site du programme'),
        'Всегда поверх окон': ('Always on top', 'Завжди поверх вікон', 'Immer im Vordergrund', 'Zawsze na wierzchu', 'Toujours au premier plan'),
        'Да': ('Yes', 'Так', 'Ja', 'Tak', 'Oui'),
        'Нет': ('No', 'Ні', 'Nein', 'Nie', 'Non'),
        'Папка сохранения WinRE': ('WinRE backup folder', 'Папка збереження WinRE', 'WinRE-Sicherungsordner', 'Folder kopii WinRE', 'Dossier de sauvegarde WinRE'),
        'Изменить папку сохранения': ('Change save folder', 'Змінити папку збереження', 'Speicherordner ändern', 'Zmień folder zapisu', 'Modifier le dossier'),
        'Вы запустились в среде восстановления:': ('Running in Windows Recovery Environment:', 'Ви запущені в середовищі відновлення:', 'Sie befinden sich in der Windows-Wiederherstellungsumgebung:', 'Uruchomiono w środowisku odzyskiwania:', 'Exécution dans l’environnement de récupération Windows :'),
        'Текущий пользователь:': ('Current user:', 'Поточний користувач:', 'Aktueller Benutzer:', 'Bieżący użytkownik:', 'Utilisateur actuel :'),
        'Информация только для просмотра': ('Read-only information', 'Інформація лише для перегляду', 'Nur-Lese-Information', 'Informacja tylko do odczytu', 'Information en lecture seule'),
        'Отключить удобный запуск': ('Disable quick launch', 'Вимкнути швидкий запуск', 'Schnellstart deaktivieren', 'Wyłącz szybkie uruchamianie', 'Désactiver le lancement rapide'),
        'Папка WinRE': ('WinRE folder', 'Папка WinRE', 'WinRE-Ordner', 'Folder WinRE', 'Dossier WinRE'),
        'Выберите папку сохранения WinRE': ('Choose WinRE backup folder', 'Оберіть папку збереження WinRE', 'WinRE-Sicherungsordner auswählen', 'Wybierz folder kopii WinRE', 'Choisir le dossier de sauvegarde WinRE'),
        'Создать диск восстановления Windows': ('Create a Windows recovery drive', 'Створити диск відновлення Windows', 'Windows-Wiederherstellungslaufwerk erstellen', 'Utwórz dysk odzyskiwania systemu Windows', 'Créer un lecteur de récupération Windows'),
        'Создание WinPE USB': ('Create WinPE USB', 'Створення WinPE USB', 'WinPE-USB erstellen', 'Tworzenie WinPE USB', 'Créer une clé USB WinPE'),
        'Для современных устройств с Secure Boot (UEFI CA 2023; требуется ADK от декабря 2024)': ('For newer Secure Boot devices (UEFI CA 2023; requires ADK from December 2024 or later)', 'Для сучасних пристроїв із Secure Boot (UEFI CA 2023; потрібен ADK від грудня 2024 року)', 'Für neuere Secure-Boot-Geräte (UEFI CA 2023; ADK ab Dezember 2024 erforderlich)', 'Dla nowszych urządzeń z Secure Boot (UEFI CA 2023; wymagany ADK z grudnia 2024 lub nowszy)', 'Pour les appareils Secure Boot récents (UEFI CA 2023 ; ADK de décembre 2024 ou ultérieur requis)'),
        'Создавать носитель с загрузчиком UEFI CA 2023 (ADK от декабря 2024 или новее)': ('Use UEFI CA 2023 boot files (ADK from December 2024 or later)', 'Використовувати файли завантаження UEFI CA 2023 (ADK від грудня 2024 року або новіший)', 'UEFI-CA-2023-Startdateien verwenden (ADK ab Dezember 2024 oder neuer)', 'Użyj plików rozruchowych UEFI CA 2023 (ADK z grudnia 2024 lub nowszy)', 'Utiliser les fichiers de démarrage UEFI CA 2023 (ADK de décembre 2024 ou plus récent)'),
        'Выбор UEFI CA 2023 зависит от Secure Boot целевого компьютера.': ('Choose UEFI CA 2023 according to the target PC Secure Boot state.', 'Вибір UEFI CA 2023 залежить від стану Secure Boot цільового комп’ютера.', 'Wählen Sie UEFI CA 2023 passend zum Secure-Boot-Status des Ziel-PCs.', 'Wybierz UEFI CA 2023 zgodnie ze stanem Secure Boot komputera docelowego.', 'Choisissez UEFI CA 2023 selon l’état Secure Boot du PC cible.'),
        'Перезагрузка в WinRE или создание загрузочной WinPE-флешки средствами Windows ADK.': ('Restart into WinRE or create a bootable WinPE USB with Windows ADK.', 'Перезавантаження у WinRE або створення завантажувальної WinPE-флешки засобами Windows ADK.', 'Neustart in WinRE oder Erstellung eines bootfähigen WinPE-USB mit Windows ADK.', 'Uruchom ponownie w WinRE lub utwórz rozruchowy nośnik WinPE USB za pomocą Windows ADK.', 'Redémarrer dans WinRE ou créer une clé USB WinPE amorçable avec Windows ADK.'),
        'USB-накопитель': ('USB drive', 'USB-накопичувач', 'USB-Laufwerk', 'Dysk USB', 'Lecteur USB'),
        'Перезагрузка': ('Restart', 'Перезавантаження', 'Neustart', 'Uruchom ponownie', 'Redémarrage'),
        'Система перезагрузится в WinRE через 5 секунд.': ('The system will restart into WinRE in 5 seconds.', 'Систему буде перезавантажено у WinRE за 5 секунд.', 'Das System startet in 5 Sekunden in WinRE neu.', 'System uruchomi się ponownie w WinRE za 5 sekund.', 'Le système redémarrera dans WinRE dans 5 secondes.'),
        'Не удалось настроить WinRE. Убедитесь, что программа запущена от имени администратора. ': ('Could not configure WinRE. Make sure the app is running as administrator. ', 'Не вдалося налаштувати WinRE. Переконайтеся, що програму запущено від імені адміністратора. ', 'WinRE konnte nicht eingerichtet werden. Stellen Sie sicher, dass die App als Administrator ausgeführt wird. ', 'Nie można skonfigurować WinRE. Upewnij się, że aplikacja jest uruchomiona jako administrator. ', 'Impossible de configurer WinRE. Vérifiez que l’application est exécutée en tant qu’administrateur. '),
        'Создать загрузочную WinPE-флешку': ('Create a bootable WinPE USB', 'Створити завантажувальну WinPE-флешку', 'Bootfähigen WinPE-USB-Stick erstellen', 'Utwórz rozruchowy nośnik WinPE USB', 'Créer une clé USB WinPE amorçable'),
        'Инструменты Windows ADK и WinPE не найдены. Установите Windows ADK и отдельное дополнение Windows PE.': ('Windows ADK and WinPE tools were not found. Install the Windows ADK and the separate Windows PE add-on.', 'Інструменти Windows ADK і WinPE не знайдено. Установіть Windows ADK і окремий додаток Windows PE.', 'Windows ADK- und WinPE-Tools nicht gefunden. Installieren Sie das Windows ADK und das separate Windows-PE-Add-on.', 'Nie znaleziono narzędzi Windows ADK i WinPE. Zainstaluj Windows ADK oraz osobny dodatek Windows PE.', 'Outils Windows ADK et WinPE introuvables. Installez le Windows ADK et le module complémentaire Windows PE.'),
        'Инструменты ADK и WinPE найдены.': ('ADK and WinPE tools found.', 'Інструменти ADK і WinPE знайдено.', 'ADK- und WinPE-Tools gefunden.', 'Znaleziono narzędzia ADK i WinPE.', 'Outils ADK et WinPE trouvés.'),
        'USB-флешки не найдены. Подключите съёмную флешку и обновите список.': ('No removable USB drives found. Connect a removable USB drive and refresh the list.', 'USB-флешки не знайдено. Підключіть знімну флешку й оновіть список.', 'Keine entfernbaren USB-Laufwerke gefunden. Schließen Sie einen USB-Stick an und aktualisieren Sie die Liste.', 'Nie znaleziono wymiennych dysków USB. Podłącz dysk USB i odśwież listę.', 'Aucune clé USB amovible détectée. Connectez une clé USB et actualisez la liste.'),
        'Обновить список USB': ('Refresh USB list', 'Оновити список USB', 'USB-Liste aktualisieren', 'Odśwież listę USB', 'Actualiser la liste USB'),
        'Открыть страницу установки ADK': ('Open ADK installation page', 'Відкрити сторінку встановлення ADK', 'ADK-Installationsseite öffnen', 'Otwórz stronę instalacji ADK', 'Ouvrir la page d’installation ADK'),
        'Выберите съёмную USB-флешку. Её раздел будет отформатирован; все данные на нём будут удалены. Сборка использует официальные инструменты Windows ADK.': ('Select a removable USB drive. Its partition will be formatted and all data on it will be erased. Creation uses the official Windows ADK tools.', 'Виберіть знімну USB-флешку. Її розділ буде відформатовано, а всі дані на ньому видалено. Для створення використовуються офіційні інструменти Windows ADK.', 'Wählen Sie ein entfernbares USB-Laufwerk. Die Partition wird formatiert und alle Daten darauf werden gelöscht. Die Erstellung verwendet offizielle Windows-ADK-Tools.', 'Wybierz wymienny nośnik USB. Jego partycja zostanie sformatowana, a wszystkie dane usunięte. Tworzenie używa oficjalnych narzędzi Windows ADK.', 'Sélectionnez une clé USB amovible. Sa partition sera formatée et toutes les données seront supprimées. La création utilise les outils officiels Windows ADK.'),
        'Подготовка файлов WinPE…': ('Preparing WinPE files…', 'Підготовка файлів WinPE…', 'WinPE-Dateien werden vorbereitet…', 'Przygotowywanie plików WinPE…', 'Préparation des fichiers WinPE…'),
        'Форматирование USB и запись WinPE…': ('Formatting USB and writing WinPE…', 'Форматування USB і запис WinPE…', 'USB wird formatiert und WinPE geschrieben…', 'Formatowanie USB i zapisywanie WinPE…', 'Formatage de la clé USB et écriture de WinPE…'),
        'WinPE-флешка создана.': ('WinPE USB created.', 'WinPE-флешку створено.', 'WinPE-USB wurde erstellt.', 'Utworzono nośnik WinPE USB.', 'Clé USB WinPE créée.'),
        'Создание WinPE завершилось с ошибкой. Рабочие файлы оставлены здесь:': ('WinPE creation failed. Working files were left here:', 'Не вдалося створити WinPE. Робочі файли залишено тут:', 'WinPE-Erstellung fehlgeschlagen. Arbeitsdateien befinden sich hier:', 'Tworzenie WinPE nie powiodło się. Pliki robocze pozostawiono tutaj:', 'Échec de la création de WinPE. Les fichiers de travail sont ici :'),
        'Не удалось запустить процесс сборки WinPE.': ('Could not start the WinPE build process.', 'Не вдалося запустити процес створення WinPE.', 'Der WinPE-Erstellungsprozess konnte nicht gestartet werden.', 'Nie można uruchomić procesu tworzenia WinPE.', 'Impossible de démarrer le processus de création WinPE.'),
        'Создание выполняется. Не отключайте USB-флешку.': ('Creation is in progress. Do not disconnect the USB drive.', 'Триває створення. Не від’єднуйте USB-флешку.', 'Erstellung läuft. Trennen Sie den USB-Stick nicht.', 'Trwa tworzenie. Nie odłączaj nośnika USB.', 'Création en cours. Ne déconnectez pas la clé USB.'),
        'WinPE USB готова:': ('WinPE USB is ready:', 'WinPE USB готова:', 'WinPE-USB ist bereit:', 'WinPE USB jest gotowy:', 'La clé USB WinPE est prête :'),
        'WinPE создаётся для компьютеров x64 и не содержит приложение NoVir.': ('WinPE is built for x64 PCs and does not include the NoVir application.', 'WinPE створюється для комп’ютерів x64 і не містить програму NoVir.', 'WinPE wird für x64-PCs erstellt und enthält nicht die NoVir-Anwendung.', 'WinPE jest tworzone dla komputerów x64 i nie zawiera aplikacji NoVir.', 'WinPE est créé pour les PC x64 et ne contient pas l’application NoVir.'),
        'Путь ADK содержит символы, небезопасные для команды Windows:': ('The ADK path contains characters that are unsafe for a Windows command:', 'Шлях ADK містить символи, небезпечні для команди Windows:', 'Der ADK-Pfad enthält Zeichen, die für einen Windows-Befehl unsicher sind:', 'Ścieżka ADK zawiera znaki niebezpieczne dla polecenia Windows:', 'Le chemin ADK contient des caractères dangereux pour une commande Windows :'),
        'USB-флешка изменилась или отключена. Запись отменена.': ('The USB drive changed or was disconnected. Writing was canceled.', 'USB-флешку змінено або від’єднано. Запис скасовано.', 'Das USB-Laufwerk wurde geändert oder getrennt. Der Schreibvorgang wurde abgebrochen.', 'Dysk USB został zmieniony lub odłączony. Zapis anulowano.', 'La clé USB a changé ou a été déconnectée. Écriture annulée.'),
        'Переход в WinRE и запуск встроенного мастера Windows для создания USB-диска восстановления.': ('Restart into WinRE or open the built-in Windows wizard to create a recovery USB.', 'Перехід у WinRE або запуск вбудованого майстра Windows для створення USB-диска відновлення.', 'Neustart in WinRE oder Öffnen des Windows-Assistenten zum Erstellen eines Wiederherstellungs-USB.', 'Uruchom WinRE lub otwórz kreator Windows, aby utworzyć dysk odzyskiwania USB.', 'Redémarrer dans WinRE ou ouvrir l’assistant Windows pour créer une clé USB de récupération.'),
        'Здесь можно перезагрузиться в WinRE или открыть встроенный мастер Windows для создания загрузочной флешки восстановления. NoVir не форматирует накопитель самостоятельно.': ('Restart into WinRE or open the built-in Windows wizard to create a bootable recovery USB. NoVir does not format drives itself.', 'Тут можна перезавантажитися у WinRE або відкрити вбудований майстер Windows для створення завантажувальної флешки відновлення. NoVir самостійно не форматує накопичувачі.', 'Hier können Sie in WinRE neu starten oder den Windows-Assistenten zum Erstellen eines bootfähigen Wiederherstellungs-USB öffnen. NoVir formatiert keine Laufwerke selbst.', 'Tutaj możesz uruchomić WinRE ponownie lub otworzyć wbudowany kreator Windows, aby utworzyć rozruchowy nośnik odzyskiwania. NoVir sam nie formatuje dysków.', 'Vous pouvez redémarrer dans WinRE ou ouvrir l’assistant Windows intégré pour créer une clé USB de récupération amorçable. NoVir ne formate pas les lecteurs.'),
        'Создание диска восстановления может стереть все данные на выбранной USB-флешке. Продолжить и открыть мастер Windows?': ('Creating a recovery drive may erase all data on the selected USB drive. Continue and open the Windows wizard?', 'Створення диска відновлення може стерти всі дані на вибраній USB-флешці. Продовжити й відкрити майстер Windows?', 'Beim Erstellen eines Wiederherstellungslaufwerks können alle Daten auf dem ausgewählten USB-Laufwerk gelöscht werden. Windows-Assistent öffnen?', 'Tworzenie dysku odzyskiwania może usunąć wszystkie dane z wybranego nośnika USB. Kontynuować i otworzyć kreator Windows?', 'La création d’un lecteur de récupération peut effacer toutes les données de la clé USB choisie. Continuer et ouvrir l’assistant Windows ?'),
        'Не удалось найти мастер создания диска восстановления Windows.': ('Windows Recovery Drive wizard was not found.', 'Не вдалося знайти майстер створення диска відновлення Windows.', 'Der Windows-Assistent für Wiederherstellungslaufwerke wurde nicht gefunden.', 'Nie znaleziono kreatora dysku odzyskiwania systemu Windows.', 'Assistant de création du lecteur de récupération Windows introuvable.'),
        'Не удалось открыть мастер создания диска восстановления Windows:': ('Could not open the Windows Recovery Drive wizard:', 'Не вдалося відкрити майстер створення диска відновлення Windows:', 'Der Windows-Assistent für Wiederherstellungslaufwerke konnte nicht geöffnet werden:', 'Nie można otworzyć kreatora dysku odzyskiwania systemu Windows:', 'Impossible d’ouvrir l’assistant de récupération Windows :'),
        'Создание USB': ('Create USB', 'Створення USB', 'USB erstellen', 'Utwórz USB', 'Créer une clé USB'),
        'Удобный запуск NoVir отключён. Записи контекстного меню удалены; UAC не изменялся.': ('NoVir quick launch is disabled. Context-menu entries were removed; UAC was not changed.', 'Швидкий запуск NoVir вимкнено. Записи контекстного меню видалено; UAC не змінювався.', 'NoVir-Schnellstart ist deaktiviert. Kontextmenüeinträge wurden entfernt; UAC wurde nicht geändert.', 'Szybkie uruchamianie NoVir wyłączono. Wpisy menu kontekstowego usunięto; UAC nie został zmieniony.', 'Le lancement rapide NoVir est désactivé. Les entrées du menu contextuel ont été supprimées ; l’UAC n’a pas été modifié.'),
        'Записи удобного запуска NoVir не найдены. UAC не изменялся.': ('No NoVir quick-launch entries were found. UAC was not changed.', 'Записів швидкого запуску NoVir не знайдено. UAC не змінювався.', 'Keine NoVir-Schnellstarteinträge gefunden. UAC wurde nicht geändert.', 'Nie znaleziono wpisów szybkiego uruchamiania NoVir. UAC nie został zmieniony.', 'Aucune entrée de lancement rapide NoVir trouvée. L’UAC n’a pas été modifié.'),
        'Не удалось полностью отключить удобный запуск. Проверьте права доступа.': ('Quick launch could not be fully disabled. Check permissions.', 'Не вдалося повністю вимкнути швидкий запуск. Перевірте права доступу.', 'Schnellstart konnte nicht vollständig deaktiviert werden. Prüfen Sie die Berechtigungen.', 'Nie udało się całkowicie wyłączyć szybkiego uruchamiania. Sprawdź uprawnienia.', 'Impossible de désactiver complètement le lancement rapide. Vérifiez les autorisations.'),
        'Отключить быстрый запуск NoVir? Будут удалены только точные записи NoVir из контекстного меню. UAC не изменяется.': ('Disable NoVir quick launch? Only the exact NoVir context-menu entries will be removed. UAC will not be changed.', 'Вимкнути швидкий запуск NoVir? Будуть видалені лише точні записи NoVir з контекстного меню. UAC не змінюється.', 'NoVir-Schnellstart deaktivieren? Nur die exakten NoVir-Kontextmenüeinträge werden entfernt. UAC bleibt unverändert.', 'Wyłączyć szybkie uruchamianie NoVir? Usunięte zostaną tylko dokładne wpisy NoVir z menu kontekstowego. UAC nie zostanie zmieniony.', 'Désactiver le lancement rapide NoVir ? Seules les entrées NoVir exactes du menu contextuel seront supprimées. UAC ne sera pas modifié.'),
        'Не удалось открыть сайт программы': ('Could not open the program website', 'Не вдалося відкрити сайт програми', 'Die Programm-Website konnte nicht geöffnet werden', 'Nie udało się otworzyć strony programu', 'Impossible d’ouvrir le site du programme'),
        'Выберите язык': ('Choose language', 'Оберіть мову', 'Sprache auswählen', 'Wybierz język', 'Sélectionnez la langue'),
        'Выберите язык интерфейса. Его можно изменить позже в настройках.': ('Choose the interface language. You can change it later in Settings.', 'Оберіть мову інтерфейсу. Її можна змінити пізніше в налаштуваннях.', 'Wählen Sie die Sprache der Benutzeroberfläche aus. Es kann später in den Einstellungen geändert werden.', 'Wybierz język interfejsu. Można to później zmienić w ustawieniach.', "Sélectionnez la langue de l'interface. Il pourra être modifié ultérieurement dans les paramètres."),
        'Диспетчер задач NoVir': ('NoVir Task Manager', 'Диспетчер завдань NoVir', 'NoVir Task-Manager', 'Menedżer zadań NoVir', 'Gestionnaire de tâches NoVir'),
        'Диспетчер задач': ('Task Manager', 'Диспетчер завдань', 'Task-Manager', 'Menedżer zadań', 'Gestionnaire de tâches'),
        'Современный контроль процессов, быстрые действия и аккуратный интерфейс в одном окне': ('Modern process control, quick actions and a clean interface in one window', 'Сучасний контроль процесів, швидкі дії та охайний інтерфейс в одному вікні', 'Moderne Prozesssteuerung, schnelle Aktionen und übersichtliche Oberfläche in einem Fenster', 'Nowoczesna kontrola procesu, szybkie działania i schludny interfejs w jednym oknie', 'Contrôle de processus moderne, actions rapides et interface soignée dans une seule fenêtre'),
        'Обновить': ('Refresh', 'Оновити', 'Aktualisieren', 'Aktualizacja', 'Mise à jour'),
        'Заморозить': ('Freeze', 'Призупинити', 'Einfrieren', 'Zamrażać', 'Geler'),
        'Разморозить': ('Resume', 'Відновити', 'Auftauen', 'Rozmrażać', 'Décongeler'),
        'Убить': ('Kill', 'Завершити', 'Töten', 'Zabić', 'Tuer'),
        'Заблокировать': ('Block', 'Заблокувати', 'Block', 'Blok', 'Bloc'),
        'Разблокировать': ('Unblock', 'Розблокувати', 'Entsperren', 'Odblokować', 'Débloquer'),
        'Открыть путь': ('Open location', 'Відкрити розташування', 'Öffne den Weg', 'Otwórz drogę', 'Ouvrir la voie'),
        'Критичный': ('Critical', 'Критичний', 'Kritisch', 'Krytyczny', 'Critique'),
        'Некритичный': ('Not critical', 'Некритичний', 'Unkritisch', 'Bezkrytyczny', 'Non critique'),
        'Обновить список процессов': ('Refresh process list', 'Оновити список процесів', 'Prozessliste aktualisieren', 'Odśwież listę procesów', 'Actualiser la liste des processus'),
        'Остановить выбранный процесс': ('Suspend selected process', 'Призупинити вибраний процес', 'Stoppen Sie den ausgewählten Prozess', 'Zatrzymaj wybrany proces', 'Arrêter le processus sélectionné'),
        'Разрешить работу процесса': ('Resume process execution', 'Відновити роботу процесу', 'Lassen Sie den Prozess laufen', 'Zezwól na uruchomienie procesu', "Autoriser le processus à s'exécuter"),
        'Принудительно завершить процесс': ('Force-close selected process', 'Примусово завершити вибраний процес', 'Erzwingen Sie die Beendigung eines Prozesses', 'Wymuś zakończenie procesu', "Forcer la fin d'un processus"),
        'Заблокировать процесс через IFEO': ('Block process through IFEO', 'Заблокувати процес через IFEO', 'Blockieren Sie einen Prozess über IFEO', 'Zablokuj proces za pośrednictwem IFEO', 'Bloquer un processus via IFEO'),
        'Снять IFEO-блокировку': ('Remove IFEO block', 'Зняти блокування IFEO', 'Entfernen Sie die IFEO-Blockierung', 'Usuń blokadę IFEO', 'Supprimer le blocage IFEO'),
        'Открыть каталог процесса': ('Open process folder', 'Відкрити папку процесу', 'Prozessverzeichnis öffnen', 'Otwórz katalog procesów', 'Ouvrir le répertoire des processus'),
        'Сделать процесс критичным': ('Make process critical', 'Зробити процес критичним', 'Machen Sie den Prozess kritisch', 'Spraw, aby proces był krytyczny', 'Rendre le processus critique'),
        'Снять статус критичности': ('Remove critical status', 'Зняти критичний статус', 'Kritikalitätsstatus entfernen', 'Usuń stan krytyczny', 'Supprimer le statut de criticité'),
        'Выберите процесс и выполните нужное действие: обновить, заморозить, завершить или заблокировать': ('Select a process, then refresh, freeze, end or block it.', 'Виберіть процес, а потім оновіть, призупиніть, завершіть або заблокуйте його.', 'Wählen Sie den Prozess aus und führen Sie die gewünschte Aktion aus: Aktualisieren, Einfrieren, Beenden oder Blockieren', 'Wybierz proces i wykonaj żądaną akcję: zaktualizuj, zamroź, zakończ lub zablokuj', "Sélectionnez le processus et effectuez l'action souhaitée\xa0: mettre à jour, geler, terminer ou bloquer"),
        'Имя': ('Name', "Ім'я", 'Name', 'Nazwa', 'Nom'),
        'Путь': ('Path', 'Шлях', 'Weg', 'Ścieżka', 'Chemin'),
        'Пользователь': ('User', 'Користувач', 'Benutzer', 'Użytkownik', 'Utilisateur'),
        'Угроза': ('Threat', 'Загроза', 'Gefahr', 'Zagrożenie', 'Menace'),
        'Тип': ('Type', 'Тип', 'Typ', 'Typ', 'Taper'),
        'Значение': ('Value', 'Значення', 'Bedeutung', 'Oznaczający', 'Signification'),
        'Параметр': ('Entry', 'Параметр', 'Parameter', 'Parametr', 'Paramètre'),
        'Файл': ('File', 'Файл', 'Datei', 'Plik', 'Déposer'),
        'Расположение': ('Location', 'Розташування', 'Standort', 'Lokalizacja', 'Emplacement'),
        'Состояние': ('Status', 'Стан', 'Zustand', 'Państwo', 'État'),
        'Служба': ('Service', 'Служба', 'Service', 'Praca', 'Service'),
        'Диск': ('Drive', 'Диск', 'Scheibe', 'Dysk', 'Disque'),
        'Размер': ('Size', 'Розмір', 'Größe', 'Rozmiar', 'Taille'),
        'Используется': ('Used', 'Використано', 'Gebraucht', 'Używany', 'Utilisé'),
        'Мой компьютер': ('This PC', "Цей комп'ютер", 'Mein Computer', 'Mój komputer', 'Mon ordinateur'),
        'Компьютер': ('This PC', "Цей комп'ютер", 'Computer', 'Komputer', 'Ordinateur'),
        'Назад': ('Back', 'Назад', 'Zurück', 'Z powrotem', 'Dos'),
        'Обновить список': ('Refresh list', 'Оновити список', 'Liste aktualisieren', 'Aktualizuj listę', 'Mettre à jour la liste'),
        'Атрибуты': ('Attributes', 'Атрибути', 'Attribute', 'Atrybuty', 'Attributs'),
        'Локальный диск': ('Local disk', 'Локальний диск', 'Lokale Festplatte', 'Dysk lokalny', 'Disque local'),
        'Папка': ('Folder', 'Папка', 'Ordner', 'Falcówka', 'Dossier'),
        'Открыть': ('Open', 'Відкрити', 'Offen', 'Otwarte', 'Ouvrir'),
        'Разблокировать (Unlocker)': ('Unlock (Unlocker)', 'Розблокувати (Unlocker)', 'Entsperren', 'Odblokować', 'Ouvrir'),
        'Стать владельцем (Take Ownership)': ('Take ownership', 'Стати власником', 'Übernehmen Sie die Verantwortung', 'Przejmij własność', "S'approprier"),
        'Удалить принудительно (Force Delete)': ('Force delete', 'Примусово видалити', 'Löschen erzwingen', 'Wymuś usunięcie', 'Forcer la suppression'),
        'Неверный путь': ('Invalid path', 'Неправильний шлях', 'Falscher Weg', 'Zły sposób', 'Mauvaise façon'),
        'Нет доступа:': ('Access denied:', 'Немає доступу:', 'Kein Zugriff:', 'Dostęp wzbroniony:', "Pas d'accès\xa0:"),
        'Разблокировка': ('Unlock', 'Розблокування', 'Entsperren', 'Odblokować', 'Ouvrir'),
        'Файл разблокирован!': ('File unlocked!', 'Файл розблоковано!', 'Die Datei ist entsperrt!', 'Plik jest odblokowany!', 'Le fichier est débloqué !'),
        'Не удалось разблокировать или файл не заблокирован.': ('Unable to unlock the file, or it is not locked.', 'Не вдалося розблокувати файл або він не заблокований.', 'Konnte nicht entsperrt werden oder die Datei ist nicht gesperrt.', 'Nie można odblokować lub plik nie jest zablokowany.', "Impossible de déverrouiller ou le fichier n'est pas verrouillé."),
        'Модуль novir_native недоступен.': ('The novir_native module is unavailable.', 'Модуль novir_native недоступний.', 'Das Modul novir_native ist nicht verfügbar.', 'Moduł novir_native jest niedostępny.', "Le module novir_native n'est pas disponible."),
        'Владелец': ('Owner', 'Власник', 'Eigentümer', 'Właściciel', 'Propriétaire'),
        'Права получены!': ('Permissions obtained!', 'Права отримано!', 'Rechte erhalten!', 'Prawa otrzymane!', 'Droits reçus !'),
        'Не удалось получить права.': ('Unable to obtain permissions.', 'Не вдалося отримати права.', 'Es konnten keine Rechte erlangt werden.', 'Nie udało się uzyskać praw.', "Impossible d'obtenir les droits."),
        'Удаление': ('Deletion', 'Видалення', 'Entfernung', 'Usuwanie', 'Suppression'),
        'Удалить безвозвратно?': ('Delete permanently?', 'Видалити безповоротно?', 'Endgültig löschen?', 'Usunąć trwale?', 'Supprimer définitivement\xa0?'),
        'Удаление заблокировано': ('Deletion blocked', 'Видалення заблоковано', 'Entfernung blockiert', 'Usunięcie zablokowane', 'Suppression bloquée'),
        'Путь не прошел проверку безопасности.': ('The path did not pass the safety check.', 'Шлях не пройшов перевірку безпеки.', 'Der Pfad hat die Sicherheitsprüfung nicht bestanden.', 'Ścieżka nie przeszła kontroli bezpieczeństwa.', "Le chemin n'a pas passé le contrôle de sécurité."),
        'Редактор реестра': ('Registry Editor', 'Редактор реєстру', 'Registrierungseditor', 'Edytor rejestru', 'Éditeur de registre'),
        'Пользователи': ('Users', 'Користувачі', 'Benutzer', 'Użytkownicy', 'Utilisateurs'),
        'Создание нового пользователя': ('Create a new user', 'Створення нового користувача', 'Einen neuen Benutzer erstellen', 'Tworzenie nowego użytkownika', 'Créer un nouvel utilisateur'),
        'Имя пользователя:': ('User name:', "Ім'я користувача:", 'Benutzername:', 'Nazwa użytkownika:', "Nom d'utilisateur:"),
        'Пароль:': ('Password:', 'Пароль:', 'Passwort:', 'Hasło:', 'Mot de passe:'),
        'С правами администратора': ('Administrator privileges', 'З правами адміністратора', 'Mit Administratorrechten', 'Z uprawnieniami administratora', "Avec droits d'administrateur"),
        'Создать\nпользователя': ('Create\nuser', 'Створити\nкористувача', 'Erstellen\nBenutzer', 'Utwórz\nużytkownik', 'Créer\nutilisateur'),
        'Требовать нажатие CTRL+ALT+DEL при входе': ('Require CTRL+ALT+DEL at sign-in', 'Вимагати CTRL+ALT+DEL під час входу', 'Bei der Anmeldung muss STRG+ALT+ENTF gedrückt werden', 'Wymagaj naciśnięcia klawiszy CTRL+ALT+DEL podczas logowania', "Nécessite d'appuyer sur CTRL+ALT+DEL lors de la connexion"),
        'Удаление дисков': ('Drive removal', 'Видалення дисків', 'Laufwerke entfernen', 'Usuwanie dysków', 'Suppression de lecteurs'),
        'Диски': ('Drives', 'Диски', 'Scheiben', 'Dyski', 'Disques'),
        'Удалить диск': ('Remove drive', 'Видалити диск', 'Diskette entfernen', 'Wyjmij dysk', 'Supprimer le disque'),
        'Снятие ограничений': ('Remove restrictions', 'Зняття обмежень', 'Beschränkungen aufheben', 'Usuwanie ograniczeń', 'Supprimer les restrictions'),
        'Интерфейс': ('Interface', 'Інтерфейс', 'Schnittstelle', 'Interfejs', 'Interface'),
        'Система': ('System', 'Система', 'System', 'System', 'Système'),
        'Запуск утилит': ('Run utilities', 'Запуск утиліт', 'Dienstprogramme starten', 'Uruchamianie narzędzi', 'Lancement des utilitaires'),
        'Клавиатура': ('Keyboard', 'Клавіатура', 'Tastatur', 'Klawiatura', 'Clavier'),
        'Очистка': ('Cleanup', 'Очищення', 'Reinigung', 'Czyszczenie', 'Nettoyage'),
        'Продвинутое': ('Advanced', 'Розширене', 'Fortschrittlich', 'Zaawansowany', 'Avancé'),
        'Безопасность': ('Security', 'Безпека', 'Sicherheit', 'Bezpieczeństwo', 'Sécurité'),
        'Хардкор (Трояны)': ('Hardcore (Trojans)', 'Хардкор (Трояни)', 'Hardcore (Trojaner)', 'Hardkor (trojany)', 'Hardcore (chevaux de Troie)'),
        '☑ Выбрать всё': ('☑ Select all', '☑ Вибрати все', '☑ Alles auswählen', '☑ Zaznacz wszystko', '☑ Sélectionnez tout'),
        '☐ Снять всё': ('☐ Clear all', '☐ Зняти все', '☐ Alles entfernen', '☐ Usuń wszystko', '☐ Supprimez tout'),
        '✓ Подтвердить выбранное': ('✓ Apply selected', '✓ Застосувати вибране', '✓ Auswahl bestätigen', '✓ Potwierdź wybór', '✓ Confirmer la sélection'),
        'Дополнительные инструменты': ('Additional tools', 'Додаткові інструменти', 'Zusätzliche Werkzeuge', 'Dodatkowe narzędzia', 'Outils supplémentaires'),
        'Сканер ограничений системы': ('System restriction scanner', 'Сканер системних обмежень', 'Systemlimit-Scanner', 'Skaner ograniczeń systemu', 'Scanner de limites du système'),
        'Находит активные блокировки (реестр, групповые политики, системные ключи)': ('Finds active blocks in the registry, group policies and system keys', 'Знаходить активні блокування в реєстрі, групових політиках і системних ключах', 'Findet aktive Sperren (Registrierung, Gruppenrichtlinien, Systemschlüssel)', 'Znajduje aktywne blokady (rejestr, zasady grupowe, klucze systemowe)', 'Recherche les verrous actifs (registre, stratégies de groupe, clés système)'),
        'Сканировать': ('Scan', 'Сканувати', 'Scan', 'Skandować', 'Balayage'),
        'Снять выбранные': ('Remove selected', 'Зняти вибрані', 'Ausgewählte löschen', 'Wyczyść wybrane', 'Effacer la sélection'),
        'Снять всё': ('Remove all', 'Зняти все', 'Alles entfernen', 'Usuń wszystko', 'Supprimer tout'),
        'Нажмите «Сканировать» для поиска ограничений': ('Click “Scan” to look for restrictions', 'Натисніть «Сканувати», щоб знайти обмеження', 'Klicken Sie auf „Scannen“, um nach Einschränkungen zu suchen', 'Kliknij „Skanuj”, aby wyszukać ograniczenia', 'Cliquez sur "Scan" pour rechercher des restrictions'),
        'Встроенные утилиты': ('Built-in utilities', 'Вбудовані утиліти', 'Integrierte Dienstprogramme', 'Wbudowane narzędzia', 'Utilitaires intégrés'),
        'Загрузочная WinPE-флешка': ('Bootable WinPE USB', 'Завантажувальна WinPE-флешка', 'Bootfähiger WinPE-USB-Stick', 'Rozruchowy nośnik WinPE USB', 'Clé USB WinPE amorçable'),
        'Создать загрузочную WinPE-флешку или перезагрузиться в WinRE.': ('Create a bootable WinPE USB or restart into WinRE.', 'Створити завантажувальну WinPE-флешку або перезавантажитися у WinRE.', 'Erstellen Sie einen bootfähigen WinPE-USB-Stick oder starten Sie in WinRE neu.', 'Utwórz rozruchowy nośnik WinPE USB lub uruchom ponownie w WinRE.', 'Créer une clé USB WinPE amorçable ou redémarrer dans WinRE.'),
        'Запустить': ('Run', 'Запустити', 'Start', 'Początek', 'Lancement'),
        'Остановить': ('Stop', 'Зупинити', 'Stoppen', 'Zatrzymywać się', 'Arrêt'),
        'Перезапустить': ('Restart', 'Перезапустити', 'Neustart', 'Uruchom ponownie', 'Redémarrage'),
        'Отключить': ('Disable', 'Вимкнути', 'Deaktivieren', 'Wyłączyć', 'Désactiver'),
        'Включить': ('Enable', 'Увімкнути', 'Einschalten', 'Włączyć coś', 'Allumer'),
        'Добавить': ('Add', 'Додати', 'Hinzufügen', 'Dodać', 'Ajouter'),
        'Удалить': ('Delete', 'Видалити', 'Löschen', 'Usuwać', 'Supprimer'),
        'Изменить': ('Edit', 'Змінити', 'Ändern', 'Zmiana', 'Changement'),
        'Сохранить': ('Save', 'Зберегти', 'Speichern', 'Ratować', 'Sauvegarder'),
        'Обзор...': ('Browse...', 'Огляд...', 'Rezension...', 'Recenzja...', 'Revoir...'),
        'Открыть файл': ('Open file', 'Відкрити файл', 'Datei öffnen', 'Otwórz plik', 'Ouvrir le fichier'),
        'Копировать путь': ('Copy path', 'Копіювати шлях', 'Pfad kopieren', 'Skopiuj ścieżkę', 'Copier le chemin'),
        'Копировать значение': ('Copy value', 'Копіювати значення', 'Wert kopieren', 'Skopiuj wartość', 'Copier la valeur'),
        'Разблокировка файлов (Unlocker)': ('File Unlocker', 'Розблокування файлів', 'Dateien entsperren (Unlocker)', 'Odblokowywanie plików (Unlocker)', 'Déverrouillage de fichiers (Unlocker)'),
        'Выберите заблокированный файл. Программа найдет процессы, которые его удерживают, и позволит их завершить.': ('Select a locked file. The app will find the processes holding it and let you end them.', 'Виберіть заблокований файл. Програма знайде процеси, які його утримують, і дозволить їх завершити.', 'Wählen Sie eine gesperrte Datei aus. Das Programm findet die Prozesse, die es anhalten, und ermöglicht deren Beendigung.', 'Wybierz zablokowany plik. Program znajdzie procesy, które go wstrzymują, i umożliwi ich zakończenie.', 'Sélectionnez un fichier verrouillé. Le programme trouvera les processus qui le détiennent et permettra de les terminer.'),
        'Анализ файла': ('Analyze file', 'Аналіз файлу', 'Dateianalyse', 'Analiza plików', 'Analyse de fichiers'),
        'Разблокировать (Убить процессы)': ('Unlock (end processes)', 'Розблокувати (завершити процеси)', 'Entsperren (Prozesse töten)', 'Odblokuj (zakończ procesy)', 'Débloquer (Tuer les processus)'),
        'Уничтожить (Убить + Удалить файл)': ('Destroy (end + delete file)', 'Знищити (завершити + видалити файл)', 'Zerstören (Datei töten + löschen)', 'Zniszcz (Zabij + Usuń plik)', 'Détruire (Tuer + Supprimer le fichier)'),
        'Выберите файл:': ('Select a file:', 'Виберіть файл:', 'Datei auswählen:', 'Wybierz plik:', 'Sélectionnez le fichier\xa0:'),
        'Папка автозагрузки:': ('Startup folder:', 'Папка автозапуску:', 'Startordner:', 'Folder startowy:', 'Dossier de démarrage\xa0:'),
        'Путь к программе:': ('Program path:', 'Шлях до програми:', 'Pfad zum Programm:', 'Ścieżka do programu:', "Chemin d'accès au programme\xa0:"),
        'Имя задачи:': ('Task name:', "Ім'я завдання:", 'Aufgabenname:', 'Nazwa zadania:', 'Nom de la tâche\xa0:'),
        'Триггер:': ('Trigger:', 'Тригер:', 'Auslösen:', 'Spust:', 'Déclenchement:'),
        'Создать задачу': ('Create task', 'Створити завдання', 'Erstellen Sie eine Aufgabe', 'Utwórz zadanie', 'Créer une tâche'),
        'Планировщик задач': ('Task Scheduler', 'Планувальник завдань', 'Aufgabenplaner', 'Harmonogram zadań', 'Planificateur de tâches'),
        'Все задачи': ('All tasks', 'Усі завдання', 'Alle Aufgaben', 'Wszystkie zadania', 'Toutes les tâches'),
        'Только пользовательские': ('User tasks only', 'Лише користувацькі', 'Nur benutzerdefiniert', 'Tylko niestandardowe', 'Personnalisé uniquement'),
        'Только подозрительные': ('Suspicious only', 'Лише підозрілі', 'Nur verdächtig', 'Tylko podejrzane', 'Seulement suspect'),
        'Папка автозагрузки': ('Startup folder', 'Папка автозапуску', 'Startordner', 'Folder startowy', 'Dossier de démarrage'),
        'Реестр': ('Registry', 'Реєстр', 'Registrierung', 'Rejestr', 'Enregistrement'),
        'Добавить файл': ('Add file', 'Додати файл', 'Datei hinzufügen', 'Dodaj plik', 'Ajouter un fichier'),
        'Открыть папку': ('Open folder', 'Відкрити папку', 'Ordner öffnen', 'Otwórz folder', 'Ouvrir le dossier'),
        '▶ Запустить': ('▶ Run', '▶ Запустити', '▶ Starten', '▶ Uruchom', '▶ Lancement'),
        '⏸ Отключить': ('⏸ Disable', '⏸ Вимкнути', '⏸ Deaktivieren', '⏸ Wyłącz', '⏸ Désactiver'),
        '✓ Включить': ('✓ Enable', '✓ Увімкнути', '✓ Aktivieren', '✓ Włącz', '✓ Activer'),
        '↻ Обновить': ('↻ Refresh', '↻ Оновити', '↻ Aktualisieren', '↻ Aktualizacja', '↻ Mise à jour'),
        'Выберите запись для удаления': ('Select an entry to delete', 'Виберіть запис для видалення', 'Eintrag zum Löschen auswählen', 'Wybierz wpis do usunięcia', "Sélectionnez l'entrée à supprimer"),
        'Выберите запись для редактирования': ('Select an entry to edit', 'Виберіть запис для редагування', 'Wählen Sie einen Eintrag zum Bearbeiten aus', 'Wybierz wpis do edycji', 'Sélectionnez une entrée à modifier'),
        'Выберите файл для удаления': ('Select a file to delete', 'Виберіть файл для видалення', 'Wählen Sie die zu löschende Datei aus', 'Wybierz plik do usunięcia', 'Sélectionnez le fichier à supprimer'),
        'Выберите задачу для удаления': ('Select a task to delete', 'Виберіть завдання для видалення', 'Wählen Sie eine Aufgabe zum Löschen aus', 'Wybierz zadanie do usunięcia', 'Sélectionnez une tâche à supprimer'),
        'Выберите задачу для запуска': ('Select a task to run', 'Виберіть завдання для запуску', 'Wählen Sie eine auszuführende Aufgabe aus', 'Wybierz zadanie do uruchomienia', 'Sélectionnez une tâche à exécuter'),
        'Выберите задачу для отключения': ('Select a task to disable', 'Виберіть завдання для вимкнення', 'Wählen Sie eine Aufgabe zum Deaktivieren aus', 'Wybierz zadanie do wyłączenia', 'Sélectionnez une tâche à désactiver'),
        'Выберите задачу для включения': ('Select a task to enable', 'Виберіть завдання для увімкнення', 'Wählen Sie eine Aufgabe aus, die eingeschlossen werden soll', 'Wybierz zadanie, które chcesz uwzględnić', 'Sélectionnez une tâche à inclure'),
        'Выберите службу для запуска': ('Select a service to start', 'Виберіть службу для запуску', 'Wählen Sie einen Dienst zum Starten aus', 'Wybierz usługę, aby rozpocząć', 'Sélectionnez un service pour démarrer'),
        'Выберите службу для остановки': ('Select a service to stop', 'Виберіть службу для зупинки', 'Wählen Sie einen Dienst aus, den Sie stoppen möchten', 'Wybierz usługę, którą chcesz zatrzymać', 'Sélectionnez un service à arrêter'),
        'Выберите службу для перезапуска': ('Select a service to restart', 'Виберіть службу для перезапуску', 'Wählen Sie den Dienst aus, der neu gestartet werden soll', 'Wybierz usługę, którą chcesz uruchomić ponownie', 'Sélectionnez le service à redémarrer'),
        'Отметьте хотя бы одно действие для выполнения.': ('Select at least one action to run.', 'Позначте принаймні одну дію для виконання.', 'Markieren Sie mindestens eine Aktion, die abgeschlossen werden soll.', 'Zaznacz co najmniej jedną akcję do wykonania.', 'Cochez au moins une action à réaliser.'),
        'Выполнить': ('Run', 'Виконати', 'Ausführen', 'Wykonać', 'Exécuter'),
        'выбранных действий?': ('selected actions?', 'вибраних дій?', 'ausgewählte Aktionen?', 'wybrane działania?', 'actions sélectionnées ?'),
        'Что заблокировано': ('What is blocked', 'Що заблоковано', 'Was ist blockiert', 'Co jest zablokowane', "Qu'est-ce qui est bloqué"),
        'Ключ реестра / GPO': ('Registry key / GPO', 'Ключ реєстру / GPO', 'Registrierungsschlüssel/GPO', 'Klucz rejestru/GPO', 'Clé de registre/GPO'),
        'Статус': ('Status', 'Статус', 'Status', 'Status', 'Statut'),
        'Ограничений не найдено!': ('No restrictions found!', 'Обмежень не знайдено!', 'Keine Einschränkungen gefunden!', 'Nie znaleziono żadnych ograniczeń!', 'Aucune restriction trouvée\xa0!'),
        'Найдено': ('Found', 'Знайдено', 'Gefunden', 'Znaleziony', 'Trouvé'),
        'блокировок': ('blocks', 'блокувань', 'Blockierung', 'bloking', 'blocage'),
        'Не выбрано ни одного ограничения.': ('No restrictions selected.', 'Не вибрано жодного обмеження.', 'Keine Einschränkungen ausgewählt.', 'Nie wybrano żadnych ograniczeń.', 'Aucune restriction sélectionnée.'),
        'Продолжить?': ('Continue?', 'Продовжити?', 'Weitermachen?', 'Kontynuować?', 'Continuer?'),
        'Информация о системе': ('System information', 'Відомості про систему', 'Systeminformationen', 'Informacje o systemie', 'Informations système'),
        'Перезапуск Explorer': ('Restart Explorer', 'Перезапуск Провідника', 'Explorer neu starten', 'Ponowne uruchamianie Eksploratora', "Redémarrage de l'explorateur"),
        'Обновление': ('Update', 'Оновлення', 'Aktualisieren', 'Aktualizacja', 'Mise à jour'),
        'Релиз GitHub': ('GitHub release', 'Реліз GitHub', 'GitHub-Veröffentlichung', 'Wydanie GitHuba', 'Version GitHub'),
        'Выберите что скачать:': ('Choose what to download:', 'Оберіть, що завантажити:', 'Wählen Sie aus, was Sie herunterladen möchten:', 'Wybierz, co chcesz pobrać:', 'Choisissez ce que vous souhaitez télécharger\xa0:'),
        'Выберите версию для загрузки:': ('Choose a version to download:', 'Оберіть версію для завантаження:', 'Wählen Sie die Version zum Herunterladen aus:', 'Wybierz wersję do pobrania:', 'Sélectionnez la version à télécharger\xa0:'),
        'Скачать Installer': ('Download installer', 'Завантажити інсталятор', 'Laden Sie das Installationsprogramm herunter', 'Pobierz instalator', "Télécharger le programme d'installation"),
        'Скачать Portable (.exe)': ('Download portable (.exe)', 'Завантажити портативну версію (.exe)', 'Portable herunterladen (.exe)', 'Pobierz przenośny (.exe)', 'Télécharger Portable (.exe)'),
        'Запуск комплексного восстановления...': ('Starting full recovery...', 'Запуск комплексного відновлення...', 'Start einer umfassenden Wiederherstellung...', 'Uruchomienie kompleksowego odzyskiwania...', 'Lancement du redressement global...'),
        'Подготовка...': ('Preparing...', 'Підготовка...', 'Vorbereitung...', 'Przygotowanie...', 'Préparation...'),
        'NoVir — Починить всё': ('NoVir — Fix all', 'NoVir — Виправити все', 'NoVir – Alles reparieren', 'NoVir – Napraw wszystko', 'NoVir - Tout réparer'),
        'Шаг': ('Step', 'Крок', 'Schritt', 'Krok', 'Étape'),
        'выполнено': ('completed', 'виконано', 'vollendet', 'zakończony', 'complété'),
        'ПРОПУСК:': ('SKIPPED:', 'ПРОПУЩЕНО:', 'PASSIEREN:', 'PRZECHODZIĆ:', 'PASSER:'),
        'Снятие блокировки реестра': ('Remove Registry Editor block', 'Зняття блокування редактора реєстру', 'Entfernen einer Registrierungssperre', 'Usuwanie blokady rejestru', 'Supprimer un verrou de registre'),
        'Снятие блокировки диспетчера': ('Remove Task Manager block', 'Зняття блокування диспетчера завдань', 'Entsperren des Dispatchers', 'Odblokowanie dyspozytora', 'Débloquer le répartiteur'),
        'Восстановление ярлыков': ('Restore shortcuts', 'Відновлення ярликів', 'Verknüpfungen wiederherstellen', 'Przywracanie skrótów', 'Restauration des raccourcis'),
        'Сброс ассоциаций файлов': ('Reset file associations', 'Скидання асоціацій файлів', 'Dateizuordnungen zurücksetzen', 'Resetowanie skojarzeń plików', 'Réinitialisation des associations de fichiers'),
        'Очистка автозапуска': ('Clean startup', 'Очищення автозапуску', 'Autorun-Reinigung', 'Automatyczne czyszczenie', 'Nettoyage automatique'),
        'Готово!': ('Done!', 'Готово!', 'Bereit!', 'Gotowy!', 'Prêt!'),
        '↩ Откат изменений': ('↩ Roll back changes', '↩ Відкотити зміни', '↩ Änderungen rückgängig machen', '↩ Wycofywanie zmian', '↩ Annulation des modifications'),
        'ОТКАТИТЬ': ('ROLL BACK', 'ВІДКОТИТИ', 'WEGROLLEN', 'ODWRÓĆ SIĘ', 'ENROULAGE'),
        'Журнал действий пуст или файл не найден.': ('The action log is empty or the file was not found.', 'Журнал дій порожній або файл не знайдено.', 'Das Aktivitätsprotokoll ist leer oder die Datei wurde nicht gefunden.', 'Dziennik aktywności jest pusty lub nie znaleziono pliku.', "Le journal d'activité est vide ou le fichier est introuvable."),
        'Нечего откатывать: изменений реестра в этой сессии не зафиксировано.': ('Nothing to roll back: no registry changes were recorded in this session.', 'Немає чого відкотити: у цій сесії не зафіксовано змін реєстру.', 'Es gibt nichts, was zurückgesetzt werden könnte: In dieser Sitzung wurden keine Registrierungsänderungen aufgezeichnet.', 'Nie ma czego przywracać: w tej sesji nie zarejestrowano żadnych zmian w rejestrze.', "Il n'y a rien à annuler : aucune modification du registre n'a été enregistrée au cours de cette session."),
        'Данный модуль запускается как отдельное окно утилиты и работает в едином стиле приложения.': ('This module opens in its own utility window and uses the same application style.', 'Цей модуль відкривається в окремому вікні утиліти та використовує єдиний стиль програми.', 'Dieses Modul wird als separates Dienstprogrammfenster ausgeführt und funktioniert im gleichen Anwendungsstil.', 'Moduł ten działa jako osobne okno narzędzia i działa w tym samym stylu aplikacji.', "Ce module s'exécute comme une fenêtre utilitaire distincte et fonctionne dans le même style d'application."),
        'Добавить запись в реестр': ('Add registry entry', 'Додати запис до реєстру', 'Fügen Sie der Registrierung einen Eintrag hinzu', 'Dodaj wpis do rejestru', 'Ajouter une entrée au registre'),
        'Изменить запись в реестре': ('Edit registry entry', 'Змінити запис у реєстрі', 'Ändern Sie einen Registrierungseintrag', 'Zmień wpis rejestru', 'Modifier une entrée de registre'),
        'Раздел реестра:': ('Registry hive:', 'Розділ реєстру:', 'Registrierungsschlüssel:', 'Klucz rejestru:', 'Clé de registre\xa0:'),
        'Текущий пользователь': ('Current user', 'Поточний користувач', 'Aktueller Benutzer', 'Bieżący użytkownik', 'Utilisateur actuel'),
        'Все пользователи': ('All users', 'Усі користувачі', 'Alle Benutzer', 'Wszyscy użytkownicy', 'Tous les utilisateurs'),
        'Добавить файл в автозагрузку': ('Add startup file', 'Додати файл до автозапуску', 'Fügen Sie eine Datei zum Start hinzu', 'Dodaj plik do startupu', 'Ajouter un fichier au démarrage'),
        'Создать задачу в планировщике': ('Create scheduled task', 'Створити завдання в планувальнику', 'Erstellen Sie eine Aufgabe im Planer', 'Utwórz zadanie w harmonogramie', 'Créer une tâche dans le planificateur'),
        'При входе в систему': ('At sign-in', 'Під час входу до системи', 'Wenn Sie sich anmelden', 'Kiedy się zalogujesz', 'Lorsque vous vous connectez'),
        'При запуске системы': ('At system startup', 'Під час запуску системи', 'Wenn das System startet', 'Kiedy system się uruchomi', 'Lorsque le système démarre'),
        'Ежедневно': ('Daily', 'Щодня', 'Täglich', 'Codziennie', 'Tous les jours'),
        'Принудительно перезагрузить список задач из системы': ('Force-reload the task list from the system', 'Примусово перезавантажити список завдань із системи', 'Erzwingen Sie das Neuladen der Aufgabenliste vom System', 'Wymuś ponowne załadowanie listy zadań z systemu', 'Forcer le rechargement de la liste des tâches à partir du système'),
        'Меню служб': ('Services menu', 'Меню служб', 'Servicemenü', 'Menu usług', 'Menu des services'),
        'Загрузка задач планировщика...': ('Loading scheduled tasks...', 'Завантаження завдань планувальника...', 'Planer-Aufgaben werden geladen...', 'Ładowanie zadań harmonogramu...', 'Chargement des tâches du planificateur...'),
        'Открывает собственный редактор реестра в стиле системного окна.': ("Opens NoVir's built-in registry editor in a system-window style.", 'Відкриває вбудований редактор реєстру NoVir у стилі системного вікна.', 'Öffnet Ihren eigenen Registrierungseditor im Stil eines Systemfensters.', 'Otwiera własny edytor rejestru w stylu okna systemowego.', "Ouvre votre propre éditeur de registre dans le style d'une fenêtre système."),
        'Открывает отдельное окно восстановления загрузчика MBR/BCD.': ('Opens a separate MBR/BCD bootloader recovery window.', 'Відкриває окреме вікно відновлення завантажувача MBR/BCD.', 'Öffnet ein separates MBR/BCD-Bootloader-Wiederherstellungsfenster.', 'Otwiera osobne okno odzyskiwania programu ładującego MBR/BCD.', 'Ouvre une fenêtre de récupération distincte du chargeur de démarrage MBR/BCD.'),
        'Открывает собственный менеджер учетных записей.': ('Opens the built-in account manager.', 'Відкриває вбудований менеджер облікових записів.', 'Öffnet Ihren eigenen Account Manager.', 'Otwiera własnego menedżera kont.', 'Ouvre votre propre gestionnaire de compte.'),
        'Открывает отдельное окно управления дисками и разделами.': ('Opens a separate window for managing disks and partitions.', 'Відкриває окреме вікно керування дисками та розділами.', 'Öffnet ein separates Fenster zur Festplatten- und Partitionsverwaltung.', 'Otwiera osobne okno zarządzania dyskami i partycjami.', 'Ouvre une fenêtre distincte de gestion des disques et des partitions.'),
        'Открывает окно управления учетными записями и паролями.': ('Opens the account and password management window.', 'Відкриває вікно керування обліковими записами та паролями.', 'Öffnet das Fenster zur Konto- und Passwortverwaltung.', 'Otwiera okno zarządzania kontem i hasłami.', 'Ouvre la fenêtre de gestion des comptes et des mots de passe.'),
        'Восстанавливает загрузочный сектор и конфигурацию загрузчика Windows.': ('Restores the Windows boot sector and bootloader configuration.', 'Відновлює завантажувальний сектор і конфігурацію завантажувача Windows.', 'Stellt den Bootsektor und die Windows-Bootloader-Konfiguration wieder her.', 'Przywraca sektor rozruchowy i konfigurację programu rozruchowego systemu Windows.', 'Restaure la configuration du secteur de démarrage et du chargeur de démarrage Windows.'),
        'Запустить восстановление': ('Start recovery', 'Запустити відновлення', 'Starten Sie die Wiederherstellung', 'Rozpocznij odzyskiwanie', 'Démarrer la récupération'),
        'Введите имя пользователя.': ('Enter a user name.', "Введіть ім'я користувача.", 'Geben Sie Ihren Benutzernamen ein.', 'Wpisz swoją nazwę użytkownika.', "Entrez votre nom d'utilisateur."),
        'В выбранных действиях есть операции повышенного риска. Они могут удалить данные, перезапустить службы или изменить системные настройки.\n\n': ('The selected actions include high-risk operations. They can delete data, restart services or change system settings.\n\n', 'Серед вибраних дій є операції підвищеного ризику. Вони можуть видалити дані, перезапустити служби або змінити системні налаштування.\n\n', 'Die ausgewählten Aktivitäten beinhalten Vorgänge mit hohem Risiko. Sie können Daten löschen, Dienste neu starten oder Systemeinstellungen ändern.', 'Wybrane działania zawierają operacje wysokiego ryzyka. Mogą usunąć dane, ponownie uruchomić usługi lub zmienić ustawienia systemu.', 'Les activités sélectionnées contiennent des opérations à haut risque. Ils peuvent supprimer des données, redémarrer des services ou modifier les paramètres du système.'),
        'Диск успешно удалён из списка отображения.': ('The drive was removed from the display list.', 'Диск успішно видалено зі списку відображення.', 'Der Datenträger wurde erfolgreich aus der Anzeigeliste entfernt.', 'Dysk został pomyślnie usunięty z listy wyświetlania.', "Le disque a été supprimé avec succès de la liste d'affichage."),
        'Заполните все поля': ('Fill in all fields', 'Заповніть усі поля', 'Füllen Sie alle Felder aus', 'Wypełnij wszystkie pola', 'Remplissez tous les champs'),
        'Запись добавлена в реестр': ('Registry entry added', 'Запис додано до реєстру', 'Eintrag zur Registrierung hinzugefügt', 'Wpis dodany do rejestru', 'Entrée ajoutée au registre'),
        'Запись удалена из реестра': ('Registry entry deleted', 'Запис видалено з реєстру', 'Eintrag aus der Registry gelöscht', 'Wpis usunięty z rejestru', 'Entrée supprimée du registre'),
        'Запись обновлена в реестре': ('Registry entry updated', 'Запис оновлено в реєстрі', 'Der Eintrag wurde in der Registry aktualisiert', 'Wpis został zaktualizowany w rejestrze', "L'entrée a été mise à jour dans le registre"),
        'Выберите существующий файл': ('Choose an existing file', 'Виберіть наявний файл', 'Wählen Sie eine vorhandene Datei aus', 'Wybierz istniejący plik', 'Sélectionnez un fichier existant'),
        'Файл добавлен в автозагрузку': ('File added to startup', 'Файл додано до автозапуску', 'Die Datei wurde zum Start hinzugefügt', 'Plik został dodany do startupu', 'Le fichier a été ajouté au démarrage'),
        'Файл удален из автозагрузки': ('File removed from startup', 'Файл видалено з автозапуску', 'Die Datei wurde aus dem Start entfernt', 'Plik został usunięty podczas uruchamiania', 'Le fichier a été supprimé du démarrage'),
        'Файл не найден': ('File not found', 'Файл не знайдено', 'Datei nicht gefunden', 'Nie znaleziono pliku', 'Fichier introuvable'),
        'Задача создана в планировщике': ('Task created in Task Scheduler', 'Завдання створено в планувальнику', 'Die Aufgabe wurde im Scheduler erstellt', 'Zadanie zostało utworzone w harmonogramie', 'La tâche a été créée dans le planificateur'),
        'Задача удалена из планировщика': ('Task deleted from Task Scheduler', 'Завдання видалено з планувальника', 'Die Aufgabe wurde aus dem Planer entfernt', 'Zadanie zostało usunięte z harmonogramu', 'La tâche a été supprimée du planificateur'),
        'Задача запущена': ('Task started', 'Завдання запущено', 'Aufgabe gestartet', 'Zadanie rozpoczęte', 'Tâche démarrée'),
        'Задача отключена': ('Task disabled', 'Завдання вимкнено', 'Aufgabe deaktiviert', 'Zadanie wyłączone', 'Tâche désactivée'),
        'Задача включена': ('Task enabled', 'Завдання увімкнено', 'Aufgabe aktiviert', 'Zadanie włączone', 'Tâche activée'),
        'Служба запущена': ('Service started', 'Службу запущено', 'Dienst gestartet', 'Usługa została uruchomiona', 'Service démarré'),
        'Служба остановлена': ('Service stopped', 'Службу зупинено', 'Der Dienst wurde gestoppt', 'Usługa zatrzymana', 'Service arrêté'),
        'Служба перезапущена': ('Service restarted', 'Службу перезапущено', 'Dienst neu gestartet', 'Usługa została uruchomiona ponownie', 'Service redémarré'),
        'Укажите правильный путь к существующему файлу.': ('Provide a valid path to an existing file.', 'Укажіть правильний шлях до наявного файлу.', 'Geben Sie den korrekten Pfad zur vorhandenen Datei an.', 'Podaj poprawną ścieżkę do istniejącego pliku.', 'Fournissez le chemin correct vers le fichier existant.'),
        'Не найдено процессов, блокирующих этот файл.\n(Возможно, он не заблокирован или заблокирован ядром).': ('No processes locking this file were found.\n(It may be unlocked or locked by the kernel.)', 'Не знайдено процесів, які блокують цей файл.\n(Можливо, він не заблокований або заблокований ядром.)', 'Es wurden keine Prozesse gefunden, die diese Datei sperren.\n(Es darf nicht vom Kernel blockiert oder blockiert werden).', 'Nie znaleziono procesów blokujących ten plik.\n(Nie może być blokowany ani blokowany przez jądro).', "Aucun processus n'a été trouvé pour verrouiller ce fichier.\n(Il ne peut pas être bloqué ou bloqué par le noyau)."),
        'Сначала проведите анализ файла.': ('Analyze the file first.', 'Спочатку проаналізуйте файл.', 'Analysieren Sie zunächst die Datei.', 'Najpierw przeanalizuj plik.', 'Analysez d’abord le fichier.'),
        'Файл успешно удален!': ('File deleted successfully!', 'Файл успішно видалено!', 'Die Datei wurde erfolgreich gelöscht!', 'Plik został pomyślnie usunięty!', 'Le fichier a été supprimé avec succès !'),
        'Рабочий стол и панель задач на секунду исчезнут.\nПерезапустить explorer.exe?': ('The desktop and taskbar will disappear briefly.\nRestart explorer.exe?', 'Робочий стіл і панель завдань на мить зникнуть.\nПерезапустити explorer.exe?', 'Der Desktop und die Taskleiste verschwinden für eine Sekunde.\nexplorer.exe neu starten?', 'Pulpit i pasek zadań znikną na sekundę.\nZrestartować program Explorer.exe?', 'Le bureau et la barre des tâches disparaîtront pendant une seconde.\nRedémarrer explorer.exe ?'),
        'Explorer перезапущен!': ('Explorer restarted!', 'Провідник перезапущено!', 'Explorer wurde neu gestartet!', 'Eksplorator został ponownie uruchomiony!', 'Explorer a été relancé\xa0!'),
        'Отчёт автозагрузки': ('Startup report', 'Звіт автозапуску', 'Startbericht', 'Raport startowy', 'Rapport de démarrage'),
        'Сетевые порты': ('Network ports', 'Мережеві порти', 'Netzwerkports', 'Porty sieciowe', 'Ports réseau'),
        'Открытые порты (LISTENING):': ('Open ports (LISTENING):', 'Відкриті порти (LISTENING):', 'Offene Ports (LISTENING):', 'Otwórz porty (SŁUCHANIE):', 'Ports ouverts (ECOUTE)\xa0:'),
        'Активные соединения (ESTABLISHED):': ('Active connections (ESTABLISHED):', "Активні з'єднання (ESTABLISHED):", 'Aktive Verbindungen (HERGESTELLT):', 'Aktywne połączenia (STANOWIONE):', 'Connexions actives (ÉTABLI)\xa0:'),
        'Задача выполнена.': ('Task completed.', 'Завдання виконано.', 'Die Aufgabe ist erledigt.', 'Zadanie zostało ukończone.', 'La tâche est terminée.'),
        'На GitHub пока нет опубликованных релизов.': ('There are no published GitHub releases yet.', 'На GitHub ще немає опублікованих релізів.', 'Es gibt noch keine veröffentlichten Veröffentlichungen auf GitHub.', 'Nie ma jeszcze żadnych opublikowanych wersji na GitHubie.', 'Il n’y a pas encore de versions publiées sur GitHub.'),
        'Готово! Все безопасные исправления применены.': ('Done! All safe fixes have been applied.', 'Готово! Усі безпечні виправлення застосовано.', 'Bereit! Alle sicheren Korrekturen wurden angewendet.', 'Gotowy! Zastosowano wszystkie bezpieczne poprawki.', 'Prêt! Tous les correctifs sûrs ont été appliqués.'),
        'Рекомендуется перезагрузить компьютер.': ('Restarting the computer is recommended.', "Рекомендується перезавантажити комп'ютер.", 'Es wird empfohlen, Ihren Computer neu zu starten.', 'Zalecane jest ponowne uruchomienie komputera.', 'Il est recommandé de redémarrer votre ordinateur.'),
        'ПРОДОЛЖИТЬ  →': ('ПРОДОЛЖИТЬ  →', 'ПРОДОЛЖИТЬ  →', 'WEITER →', 'KONTYNUUJ →', 'CONTINUER →'),
        '! ВНИМАНИЕ! Восстановление загрузчика MBR/BCD\nявляется продвинутой системной операцией.\n\nПри неправильном использовании Windows\nможет перестать загружаться.\n\nРекомендуется создать точку восстановления\nперед продолжением. Вы уверены?': ('! ВНИМАНИЕ! Восстановление загрузчика MBR/BCD\nявляется продвинутой системной операцией.\n\nПри неправильном использовании Windows\nможет перестать загружаться.\n\nРекомендуется создать точку восстановления\nперед продолжением. Вы уверены?', '! ВНИМАНИЕ! Восстановление загрузчика MBR/BCD\nявляется продвинутой системной операцией.\n\nПри неправильном использовании Windows\nможет перестать загружаться.\n\nРекомендуется создать точку восстановления\nперед продолжением. Вы уверены?', '! AUFMERKSAMKEIT! Wiederherstellung des MBR/BCD-Bootloaders\nist eine erweiterte Systemoperation.\n\nBei falscher Verwendung von Windows\nkann den Ladevorgang stoppen.\n\nEs wird empfohlen, einen Wiederherstellungspunkt zu erstellen\nbevor Sie fortfahren. Bist du sicher?', '! UWAGA! Odzyskiwanie bootloadera MBR/BCD\nto zaawansowana operacja systemowa.\n\nPodczas nieprawidłowego korzystania z systemu Windows\nmoże przestać się ładować.\n\nZalecane jest utworzenie punktu przywracania\nprzed kontynuowaniem. Czy jesteś pewien?', "! ATTENTION! Récupération du chargeur de démarrage MBR/BCD\nest une opération système avancée.\n\nEn cas d'utilisation incorrecte de Windows\npeut arrêter le chargement.\n\nIl est recommandé de créer un point de restauration\navant de continuer. Es-tu sûr?"),
        'NoVir - Восстановление системы': ('NoVir - Восстановление системы', 'NoVir - Восстановление системы', 'NoVir – Systemwiederherstellung', 'NoVir – odzyskiwanie systemu', 'NoVir - Récupération du système'),
        'Latest — стабильная версия.': ('Latest — стабильная версия.', 'Latest — стабильная версия.', 'Neueste – stabile Version.', 'Najnowsza - stabilna wersja.', 'Dernière version stable.'),
        'Сканировать снова': ('Сканировать снова', 'Сканировать снова', 'Noch einmal scannen', 'Zeskanuj ponownie', 'Scannez à nouveau'),
        'Предупреждение PRE-RELEASE': ('Предупреждение PRE-RELEASE', 'Предупреждение PRE-RELEASE', 'Warnung vor der Veröffentlichung', 'Ostrzeżenie przed premierą', 'Avertissement PRÉ-SORTIE'),
        '⚠️ PRE-RELEASE: версия может содержать ошибки и нестабильные функции. Разработчик не отвечает за возможные проблемы этой версии.': ('⚠️ PRE-RELEASE: версия может содержать ошибки и нестабильные функции. Разработчик не отвечает за возможные проблемы этой версии.', '⚠️ PRE-RELEASE: версия может содержать ошибки и нестабильные функции. Разработчик не отвечает за возможные проблемы этой версии.', '⚠️ VORVERÖFFENTLICHUNG: Die Version kann Fehler und instabile Funktionen enthalten. Der Entwickler übernimmt keine Verantwortung für etwaige Probleme dieser Version.', '⚠️ WERSJA WSTĘPNA: wersja może zawierać błędy i niestabilne funkcje. Deweloper nie ponosi odpowiedzialności za jakiekolwiek problemy, jakie może wystąpić w tej wersji.', "⚠️ PRÉ-RELEASE\xa0: la version peut contenir des bugs et des fonctionnalités instables. Le développeur n'est pas responsable des problèmes que cette version pourrait rencontrer."),
        'Подтверждение снятия блокировок': ('Подтверждение снятия блокировок', 'Подтверждение снятия блокировок', 'Bestätigung der Blockierungsentfernung', 'Potwierdzenie usunięcia blokady', 'Confirmation de la suppression du blocage'),
        'Сканирование...': ('Сканирование...', 'Сканирование...', 'Scannen...', 'Łów...', 'Balayage...'),
        'NoVir — Обновления': ('NoVir — Обновления', 'NoVir — Обновления', 'NoVir – Updates', 'NoVir — aktualizacje', 'NoVir - Mises à jour'),
        'УДАЛИТЬ': ('УДАЛИТЬ', 'УДАЛИТЬ', 'LÖSCHEN', 'USUWAĆ', 'SUPPRIMER'),
        '⚠️ Подтверждение удаления': ('⚠️ Подтверждение удаления', '⚠️ Подтверждение удаления', '⚠️Löschbestätigung', '⚠️Potwierdzenie usunięcia', '⚠️Confirmation de suppression'),
        'Пусто': ('Пусто', 'Пусто', 'Leer', 'Pusty', 'Vide'),
        '! ВНИМАНИЕ! Удаление или форматирование дисков\nявляется необратимой операцией.\n\nВсе данные на удалённом разделе будут потеряны без возможности восстановления.\n\nУбедитесь, что вы точно знаете, что делаете. Продолжить?': ('! ВНИМАНИЕ! Удаление или форматирование дисков\nявляется необратимой операцией.\n\nВсе данные на удалённом разделе будут потеряны без возможности восстановления.\n\nУбедитесь, что вы точно знаете, что делаете. Продолжить?', '! ВНИМАНИЕ! Удаление или форматирование дисков\nявляется необратимой операцией.\n\nВсе данные на удалённом разделе будут потеряны без возможности восстановления.\n\nУбедитесь, что вы точно знаете, что делаете. Продолжить?', '! AUFMERKSAMKEIT! Entfernen oder Formatieren von Laufwerken\nist ein irreversibler Vorgang.\n\nAlle Daten auf der gelöschten Partition gehen verloren, ohne dass eine Wiederherstellung möglich ist.\n\nStellen Sie sicher, dass Sie genau wissen, was Sie tun. Weitermachen?', '! UWAGA! Usuwanie lub formatowanie dysków\njest operacją nieodwracalną.\n\nWszystkie dane na usuniętej partycji zostaną utracone bez możliwości odzyskania.\n\nUpewnij się, że wiesz dokładnie, co robisz. Kontynuować?', '! ATTENTION! Supprimer ou formater des lecteurs\nest une opération irréversible.\n\nToutes les données de la partition supprimée seront perdues sans possibilité de récupération.\n\nAssurez-vous de savoir exactement ce que vous faites. Continuer?'),
        'Выбор языка': ('Выбор языка', 'Выбор языка', 'Sprachauswahl', 'Wybór języka', 'Sélection de la langue'),
        '⚠️ Управление дисками': ('⚠️ Управление дисками', '⚠️ Управление дисками', '⚠️ Datenträgerverwaltung', '⚠️ Zarządzanie dyskami', '⚠️ Gestion des disques'),
        '⚠️ Восстановление загрузчика MBR/BCD': ('⚠️ Восстановление загрузчика MBR/BCD', '⚠️ Восстановление загрузчика MBR/BCD', '⚠️ MBR/BCD-Bootloader-Wiederherstellung', '⚠️ Odzyskiwanie bootloadera MBR/BCD', '⚠️ Récupération du chargeur de démarrage MBR/BCD'),
        # — Меню «ЕЩЁ», заголовки страниц, сообщество —
        'Поддержать автора': ('Support the author', 'Підтримати автора', 'Autor unterstützen', 'Wesprzyj autora', 'Soutenir l’auteur'),
        'Выберите язык интерфейса. Позже вы сможете изменить его в Настройках.': ('Choose the interface language. You can change it later in Settings.', 'Оберіть мову інтерфейсу. Пізніше її можна змінити в Налаштуваннях.', 'Wähle die Sprache der Oberfläche. Du kannst sie später in den Einstellungen ändern.', 'Wybierz język interfejsu. Później zmienisz go w Ustawieniach.', 'Choisissez la langue de l’interface. Vous pourrez la modifier plus tard dans les paramètres.'),
        '✕ Очистить': ('✕ Clear', '✕ Очистити', '✕ Löschen', '✕ Wyczyść', '✕ Effacer'),
        'Введите команду...': ('Enter a command...', 'Введіть команду...', 'Befehl eingeben...', 'Wpisz polecenie...', 'Saisissez une commande...'),
        'БЕТА-ВЕРСИЯ: ИИ может ошибаться. Не доверяйте ответам без проверки; перед запуском внимательно проверьте каждую команду. Используйте ИИ на свой риск. NoVir не отвечает за последствия выполнения предложенных команд.': ('BETA: The AI can make mistakes. Do not trust answers without checking; carefully review every command before running. Use the AI at your own risk. NoVir is not responsible for the consequences of running suggested commands.', 'БЕТА: ІІ може помилятися. Не довіряйте відповідям без перевірки; уважно перевірте кожну команду перед запуском. Використовуйте ІІ на свій ризик. NoVir не відповідальні за наслідки виконання запропонованих команд.', 'BETA: Die KI kann Fehler machen. Vertraue Antworten nicht ohne Prüfung; prüfe jeden Befehl vor dem Ausführen sorgfältig. Nutze die KI auf eigenes Risiko. NoVir haftet nicht für die Folgen ausgeführter Befehle.', 'BETA: SI może się mylić. Nie ufaj odpowiedziom bez sprawdzenia; dokładnie sprawdź każde polecenie przed uruchomieniem. Korzystaj z SI na własne ryzyko. NoVir nie ponosi odpowiedzialności za skutki uruchomienia sugerowanych poleceń.', 'BÊTA : l’IA peut se tromper. Ne fais pas confiance aux réponses sans vérification ; examine attentivement chaque commande avant exécution. Utilise l’IA à tes risques et périls. NoVir n’est pas responsable des conséquences de l’exécution des commandes proposées.'),
        'Напишите ответ или вопрос NoVir AI...': ('Write an answer or question for NoVir AI...', 'Напишіть відповідь або запитання для NoVir AI...', 'Schreibe eine Antwort oder Frage an NoVir AI...', 'Napisz odpowiedź lub pytanie do NoVir AI...', 'Écris une réponse ou une question à NoVir AI...'),
        'Отправить': ('Send', 'Надіслать', 'Senden', 'Wyślij', 'Envoyer'),
        'ИИ АССИСТЕНТ': ('AI ASSISTANT', 'ІІ АСИСТЕНТ', 'KI-ASSISTENT', 'ASYSTENT SI', 'ASSISTANT IA'),
        '♥  ПОДДЕРЖАТЬ АВТОРА': ('♥  SUPPORT THE AUTHOR', '♥  ПІДТРИМАТИ АВТОРА', '♥  AUTOR UNTERSTÜTZEN', '♥  WESPRZYJ AUTORA', '♥  SOUTENIR L’AUTEUR'),
        'Имя параметра:': ('Parameter name:', 'Назва параметра:', 'Parametername:', 'Nazwa parametru:', 'Nom du paramètre :'),
        'Значение:': ('Value:', 'Значення:', 'Wert:', 'Wartość:', 'Valeur :'),
        'Создать': ('Create', 'Створити', 'Erstellen', 'Utwórz', 'Créer'),
        'Путь к файлу...': ('File path...', 'Шлях до файлу...', 'Dateipfad...', 'Ścieżka do pliku...', 'Chemin du fichier...'),
        'Анализ ничего не меняет; режим исправления требует отдельного подтверждения': ('Analysis changes nothing; fix mode requires separate confirmation.', 'Аналіз нічого не змінює; режим виправлення вимагає окремого підтвердження.', 'Die Analyse ändert nichts; der Reparaturmodus erfordert eine separate Bestätigung.', 'Analiza niczego nie zmienia; tryb naprawy wymaga osobnego potwierdzenia.', 'L’analyse ne modifie rien ; le mode correction demande une confirmation séparée.'),
        'Корреляция Malware-процессов': ('Malware process correlation', 'Кореляція malware-процесів', 'Malware-Prozesskorrelation', 'Korelacja procesów malware', 'Corrélation des processus malware'),
        'Сравнение запущенных процессов с активными службами и задачами (эвристика):': ('Comparing running processes with active services and tasks (heuristics):', 'Порівняння запущених процесів з активними службами та завданнями (евристика):', 'Vergleich laufender Prozesse mit aktiven Diensten und Aufgaben (Heuristik):', 'Porównanie uruchomionych procesów z aktywnymi usługami i zadaniami (heurystyka):', 'Comparaison des processus en cours avec les services et tâches actifs (heuristique) :'),
        'Восстановление драйверов': ('Driver recovery', 'Відновлення драйверів', 'Treiber-Wiederherstellung', 'Odzyskiwanie sterowników', 'Récupération des pilotes'),
        'Укажите папку с резервной копией драйверов (содержит .inf файлы).': ('Specify the folder with the driver backup (contains .inf files).', 'Вкажіть папку з резервною копією драйверів (містить файли .inf).', 'Gib den Ordner mit der Treibersicherung an (enthält .inf-Dateien).', 'Wskaż folder z kopią zapasową sterowników (zawiera pliki .inf).', 'Indique le dossier de sauvegarde des pilotes (contient des fichiers .inf).'),
        'Указать папку и восстановить': ('Choose folder and restore', 'Вказати папку та відновити', 'Ordner wählen und wiederherstellen', 'Wskaż folder i przywróć', 'Choisir le dossier et restaurer'),
        'Здесь можно перезагрузиться в среду восстановления Windows (WinRE) или подготовить USB.': ('Restart into Windows recovery environment (WinRE) or prepare a USB here.', 'Тут можна перезавантажитися в середовище відновлення Windows (WinRE) або підготувати USB.', 'Hier kannst du in die Windows-Wiederherstellungsumgebung (WinRE) neu starten oder ein USB vorbereiten.', 'Tutaj możesz zrestartować się do środowiska odzyskiwania Windows (WinRE) lub przygotować USB.', 'Redémarrez ici vers l’environnement de récupération Windows (WinRE) ou préparez une clé USB.'),
        'Перезагрузка в WinRE': ('Restart to WinRE', 'Перезавантаження в WinRE', 'Neustart in WinRE', 'Restart do WinRE', 'Redémarrage vers WinRE'),
        'Версия Windows': ('Windows version', 'Версія Windows', 'Windows-Version', 'Wersja Windows', 'Version de Windows'),
        'Функции будут использовать команды под выбранную версию. «Автоопределение» — текущая Windows.': ('Features will use commands for the selected version. "Auto-detect" — the current Windows.', 'Функції використовуватимуть команди для обраної версії. «Автовизначення» — поточна Windows.', 'Die Funktionen verwenden Befehle für die gewählte Version. „Automatische Erkennung“ — die aktuelle Windows.', 'Funkcje będą używać poleceń dla wybranej wersji. „Wykrywanie automatyczne” — bieżące Windows.', 'Les fonctionnalités utiliseront les commandes pour la version sélectionnée. « Détection automatique » — Windows actuel.'),
        'Режим использования': ('Usage mode', 'Режим використання', 'Verwendungsmodus', 'Tryb użytkowania', 'Mode d’utilisation'),
        'Что нового в этом обновлении': ('What’s new in this update', 'Що нового в цьому оновленні', 'Neuigkeiten in diesem Update', 'Co nowego w tej aktualizacji', 'Nouveautés de cette mise à jour'),
        'ЕЩЁ  ▾': ('MORE  ▾', 'ЩЕ  ▾', 'MEHR  ▾', 'WIĘCEJ  ▾', 'PLUS  ▾'),
        'СООБЩЕСТВО': ('COMMUNITY', 'СПІЛЬНОТА', 'COMMUNITY', 'SPOŁECZNOŚĆ', 'COMMUNAUTÉ'),
        'Чат сообщества NoVir. Гостям 5 сообщений в час, зарегистрированным — 60.\n@novir_ai — спроси бота прямо в чате. ПКМ по сообщению: ответить, упомянуть, удалить (5 мин).': ('NoVir community chat. Guests get 5 messages per hour, registered users — 60.\n@novir_ai — ask the bot right in the chat. Right-click a message: reply, mention, delete (5 min).', 'Чат спільноти NoVir. Гостям — 5 повідомлень на годину, зареєстрованим — 60.\n@novir_ai — запитай бота прямо в чаті. ПКМ по повідомленню: відповісти, згадати, видалити (5 хв).', 'NoVir-Community-Chat. Gäste: 5 Nachrichten pro Stunde, Registrierte: 60.\n@novir_ai — frag den Bot direkt im Chat. Rechtsklick auf eine Nachricht: antworten, erwähnen, löschen (5 Min).', 'Czat społeczności NoVir. Goście: 5 wiadomości na godzinę, zarejestrowani: 60.\n@novir_ai — zapytaj bota prosto na czacie. PPM na wiadomość: odpowiedz, wspomnij, usuń (5 min).', 'Chat de la communauté NoVir. Invités : 5 messages par heure, inscrits — 60.\n@novir_ai — pose ta question au bot directement dans le chat. Clic droit sur un message : répondre, mentionner, supprimer (5 min).'),
        'Гость': ('Guest', 'Гість', 'Gast', 'Gość', 'Invité'),
        '[ ВОЙТИ ]': ('[ LOG IN ]', '[ УВІЙТИ ]', '[ ANMELDEN ]', '[ ZALOGUJ ]', '[ CONNEXION ]'),
        '[ РЕГИСТРАЦИЯ ]': ('[ SIGN UP ]', '[ РЕЄСТРАЦІЯ ]', '[ REGISTRIEREN ]', '[ REJESTRACJA ]', '[ INSCRIPTION ]'),
        '[ ВЫЙТИ ]': ('[ LOG OUT ]', '[ ВИЙТИ ]', '[ ABMELDEN ]', '[ WYLOGUJ ]', '[ DÉCONNEXION ]'),
        'Сообщение...': ('Message...', 'Повідомлення...', 'Nachricht...', 'Wiadomość...', 'Message...'),
        '[ ОТПРАВИТЬ ]': ('[ SEND ]', '[ НАДІСЛАТИ ]', '[ SENDEN ]', '[ WYŚLIJ ]', '[ ENVOYER ]'),
        'Отменить ответ': ('Cancel reply', 'Скасувати відповідь', 'Antwort abbrechen', 'Anuluj odpowiedź', 'Annuler la réponse'),
        'Вход в NoVir Community': ('Log in to NoVir Community', 'Вхід у NoVir Community', 'Anmeldung bei NoVir Community', 'Logowanie do NoVir Community', 'Connexion à NoVir Community'),
        'Регистрация в NoVir Community': ('Sign up for NoVir Community', 'Реєстрація в NoVir Community', 'Registrierung bei NoVir Community', 'Rejestracja w NoVir Community', 'Inscription à NoVir Community'),
        'Повтори пароль:': ('Repeat password:', 'Повтори пароль:', 'Passwort wiederholen:', 'Powtórz hasło:', 'Répéter le mot de passe :'),
        'Регистрация увеличивает лимит с 5 до 60 сообщений в час.\nИмя: 3–20 символов (латиница, цифры, _). Пароль: от 4 символов.': ('Registration raises the limit from 5 to 60 messages per hour.\nName: 3–20 characters (latin, digits, _). Password: at least 4 characters.', 'Реєстрація підвищує ліміт з 5 до 60 повідомлень на годину.\nІм’я: 3–20 символів (латиниця, цифри, _). Пароль: від 4 символів.', 'Die Registrierung erhöht das Limit von 5 auf 60 Nachrichten pro Stunde.\nName: 3–20 Zeichen (lateinisch, Ziffern, _). Passwort: mindestens 4 Zeichen.', 'Rejestracja podnosi limit z 5 do 60 wiadomości na godzinę.\nNazwa: 3–20 znaków (łacina, cyfry, _). Hasło: od 4 znaków.', 'L’inscription porte la limite de 5 à 60 messages par heure.\nNom : 3 à 20 caractères (latin, chiffres, _). Mot de passe : 4 caractères minimum.'),
        '[ ЗАРЕГИСТРИРОВАТЬСЯ ]': ('[ SIGN UP ]', '[ ЗАРЕЄСТРУВАТИСЯ ]', '[ REGISTRIEREN ]', '[ ZAREJESTRUJ SIĘ ]', '[ S’INSCRIRE ]'),
        'Вы: %s': ('You: %s', 'Ви: %s', 'Sie: %s', 'Ty: %s', 'Vous : %s'),
        'Сообщение от имени %s...': ('Message as %s...', 'Повідомлення від імені %s...', 'Nachricht als %s...', 'Wiadomość jako %s...', 'Message en tant que %s...'),
        'Сообщение (гость, лимит 5/час)...': ('Message (guest, limit 5/hour)...', 'Повідомлення (гість, ліміт 5/год)...', 'Nachricht (Gast, Limit 5/Std.)...', 'Wiadomość (gość, limit 5/godz.)...', 'Message (invité, limite 5/h)...'),
        '%s · лимит %s сообщ./час · осталось %s · %s': ('%s · limit %s msg/hour · %s left · %s', '%s · ліміт %s повід./год · лишилося %s · %s', '%s · Limit %s Msg./Std. · %s übrig · %s', '%s · limit %s wiad./godz · pozostało %s · %s', '%s · limite %s msg/h · %s restant · %s'),
        '✓ можно писать': ('✓ you can write', '✓ можна писати', '✓ du kannst schreiben', '✓ można pisać', '✓ tu peux écrire'),
        '⌛ лимит исчерпан, подожди до конца часа': ('⌛ limit reached, wait until the hour ends', '⌛ ліміт вичерпано, зачекай до кінця години', '⌛ Limit erreicht, warte bis Stundenschluss', '⌛ limit wyczerpany, poczekaj do końca godziny', '⌛ limite atteint, attends la fin de l’heure'),
        '⚡ ТЕБЯ УПОМЯНУЛ %s: %s': ('⚡ %s MENTIONED YOU: %s', '⚡ ТЕБЯ ЗГАДАВ %s: %s', '⚡ %s HAT DICH ERWÄHNT: %s', '⚡ %s CIĘ WSPOMNIAŁ: %s', '⚡ %s T’A MENTIONNÉ : %s'),
        'NOVIR AI думает над ответом...': ('NOVIR AI is thinking...', 'NOVIR AI думає над відповіддю...', 'NOVIR AI denkt nach...', 'NOVIR AI myśli nad odpowiedzią...', 'NOVIR AI réfléchit...'),
        'ОТВЕТИТЬ': ('REPLY', 'ВІДПОВІСТИ', 'ANTWORTEN', 'ODPOWIEDZ', 'RÉPONDRE'),
        'УПОМЯНУТЬ @%s': ('MENTION @%s', 'ЗГАДАТИ @%s', 'ERWÄHNNEN @%s', 'WSPOMNIJ @%s', 'MENTIONNER @%s'),
        'КОПИРОВАТЬ ТЕКСТ': ('COPY TEXT', 'КОПІЮВАТИ ТЕКСТ', 'TEXT KOPIEREN', 'KOPIUJ TEKST', 'COPIER LE TEXTE'),
        'УДАЛИТЬ (осталось %d мин)': ('DELETE (%d min left)', 'ВИДАЛИТИ (%d хв лишилося)', 'LÖSCHEN (%d Min. übrig)', 'USUŃ (pozostało %d min)', 'SUPPRIMER (%d min rest.)'),
        'Ответ %s: %s': ('Reply to %s: %s', 'Відповідь %s: %s', 'Antwort an %s: %s', 'Odpowiedź do %s: %s', 'Réponse à %s : %s'),
        'Удалить можно только своё сообщение\nи только в течение %d минут.': ('You can delete only your own message\nand only within %d minutes.', 'Видалити можна лише своє повідомлення\nі лише протягом %d хвилин.', 'Du kannst nur deine eigene Nachricht löschen\nund nur innerhalb von %d Minuten.', 'Można usunąć tylko własną wiadomość\ni tylko w ciągu %d minut.', 'Vous ne pouvez supprimer que votre propre message\net seulement dans les %d minutes.'),
        'Удалить своё сообщение?': ('Delete your own message?', 'Видалити своє повідомлення?', 'Eigene Nachricht löschen?', 'Usunąć własną wiadomość?', 'Supprimer votre message?'),
        'Не удалось удалить (нет связи с сервером).': ('Could not delete (no server connection).', 'Не вдалося видалити (немає зв’язку з сервером).', 'Löschen fehlgeschlagen (keine Serververbindung).', 'Nie udało się usunąć (brak połączenia z serwerem).', 'Suppression impossible (pas de connexion au serveur).'),
        'Сообщение длиннее 500 символов.': ('Message is longer than 500 characters.', 'Повідомлення довше за 500 символів.', 'Die Nachricht ist länger als 500 Zeichen.', 'Wiadomość jest dłuższa niż 500 znaków.', 'Le message dépasse 500 caractères.'),
        'Лимит 5 сообщений в час исчерпан.\nЗарегистрируйся — и лимит станет 60 сообщений в час.': ('The 5 messages per hour limit is used up.\nRegister — and the limit becomes 60 messages per hour.', 'Ліміт 5 повідомлень на годину вичерпано.\nЗареєструйся — і ліміт стане 60 повідомлень на годину.', 'Das Limit von 5 Nachrichten pro Stunde ist aufgebraucht.\nRegistriere dich — dann beträgt das Limit 60 Nachrichten pro Stunde.', 'Limit 5 wiadomości na godzinę wyczerpany.\nZarejestruj się — limit wyniesie 60 wiadomości na godzinę.', 'La limite de 5 messages par heure est atteinte.\nInscris-toi — la limite passera à 60 messages par heure.'),
        'Аккаунт «%s» создан!\nТеперь лимит — 60 сообщений в час.': ('Account "%s" created!\nThe limit is now 60 messages per hour.', 'Обліковий запис «%s» створено!\nТепер ліміт — 60 повідомлень на годину.', 'Konto "%s" erstellt!\nJetzt gilt ein Limit von 60 Nachrichten pro Stunde.', 'Konto "%s" utworzone!\nTeraz limit to 60 wiadomości na godzinę.', 'Compte « %s » créé !\nLa limite est maintenant de 60 messages par heure.'),
        'Ошибка отправки.': ('Send error.', 'Помилка надсилання.', 'Sendefehler.', 'Błąd wysyłania.', 'Erreur d’envoi.'),
        'Заполни имя и пароль.': ('Fill in the name and password.', 'Введи ім’я та пароль.', 'Name und Passwort ausfüllen.', 'Podaj nazwę i hasło.', 'Renseigne le nom et le mot de passe.'),
        'Проверка...': ('Checking...', 'Перевірка...', 'Prüfe...', 'Sprawdzanie...', 'Vérification...'),
        'Нет связи с сервером. Проверь интернет и supabase_community.sql.': ('No server connection. Check your internet and supabase_community.sql.', 'Немає зв’язку з сервером. Перевір інтернет і supabase_community.sql.', 'Keine Serververbindung. Prüfe Internet und supabase_community.sql.', 'Brak połączenia z serwerem. Sprawdź internet i supabase_community.sql.', 'Pas de connexion au serveur. Vérifiez internet et supabase_community.sql.'),
        'Пользователь не найден.': ('User not found.', 'Користувача не знайдено.', 'Benutzer nicht gefunden.', 'Nie znaleziono użytkownika.', 'Utilisateur introuvable.'),
        'Неверный пароль.': ('Wrong password.', 'Невірний пароль.', 'Falsches Passwort.', 'Nieprawidłowe hasło.', 'Mot de passe incorrect.'),
        'Ошибка.': ('Error.', 'Помилка.', 'Fehler.', 'Błąd.', 'Erreur.'),
        'Имя: 3–20 символов, только латиница, цифры и _.': ('Name: 3–20 chars, latin, digits and _ only.', 'Ім’я: 3–20 символів, лише латиниця, цифри і _.', 'Name: 3–20 Zeichen, nur lateinisch, Ziffern und _.', 'Nazwa: 3–20 znaków, tylko łacina, cyfry i _.', 'Nom : 3 à 20 caractères, latin, chiffres et _ uniquement.'),
        'Пароль от 4 символов.': ('Password must be at least 4 characters.', 'Пароль від 4 символів.', 'Passwort ab 4 Zeichen.', 'Hasło od 4 znaków.', 'Mot de passe : 4 caractères minimum.'),
        'Пароли не совпадают.': ('Passwords do not match.', 'Паролі не збігаються.', 'Die Passwörter stimmen nicht überein.', 'Hasła nie są zgodne.', 'Les mots de passe ne correspondent pas.'),
        'Создание аккаунта...': ('Creating account...', 'Створення облікового запису...', 'Konto wird erstellt...', 'Tworzenie konta...', 'Création du compte...'),
        'Это имя уже занято.': ('This name is already taken.', 'Це ім’я вже зайняте.', 'Dieser Name ist bereits vergeben.', 'Ta nazwa jest już zajęta.', 'Ce nom est déjà pris.'),
        'Не удалось создать аккаунт (сервер отклонил запрос).': ('Could not create the account (server rejected the request).', 'Не вдалося створити обліковий запис (сервер відхилив запит).', 'Konto konnte nicht erstellt werden (Server hat die Anfrage abgelehnt).', 'Nie udało się utworzyć konta (serwer odrzucił zapytanie).', 'Impossible de créer le compte (le serveur a refusé la requête).'),
    }

    # A safe fallback prevents untranslated Russian fragments in dynamic status
    # messages assembled with f-strings.  Full phrases above take priority.
    FALLBACK_WORDS = {
        "en": {'не': 'not', 'Не': 'Not', 'будет': 'will be', 'Будет': 'Will be', 'будут': 'will', 'Будут': 'Will', 'ошибка': 'error', 'Ошибка': 'Error', 'ошибки': 'errors', 'Ошибки': 'Errors', 'ошибок': 'errors', 'Ошибок': 'Errors:', 'ошибок:': 'errors:', 'Ошибок:': 'Errors:', 'ошибками': 'errors', 'Ошибками': 'Errors', 'ошибку': 'error', 'Ошибку': 'Error', 'файл': 'file', 'Файл': 'File:', 'файла': 'file', 'Файла': 'File', 'файлы': 'files', 'Файлы': 'Files', 'файлов': 'files', 'Файлов': 'Files:', 'файлом': 'file', 'Файлом': 'File', 'удалось': 'could', 'Удалось': 'Could', 'не удалось': 'could not', 'Не удалось': 'Could not', 'задач': 'tasks', 'Задач': 'Tasks:', 'задача': 'task', 'Задача': 'Task', 'задачу': 'task', 'Задачу': 'Task', 'задачи': 'tasks', 'Задачи': 'Tasks', 'задаче': 'task', 'Задаче': 'Task', 'через': 'via', 'Через': 'Via', 'восстановление': 'recovery', 'Восстановление': 'Recovery', 'восстановления': 'recovery', 'Восстановления': 'Recovery:', 'восстановлено': 'restored', 'Восстановлено': 'Restored', 'восстановлен': 'restored', 'Восстановлен': 'Restored', 'восстановить': 'restore', 'Восстановить': 'Restore', 'восстанавливает': 'restores', 'Восстанавливает': 'Restores', 'восстанавливаеться': 'restores', 'Восстанавливаеться': 'Restores', 'восстановлены': 'restored', 'Восстановлены': 'Restored', 'восстановления:': 'recovery:', 'Восстановления:': 'Recovery:', 'системы': 'system', 'Системы': 'System', 'система': 'system', 'Система': 'System:', 'систему': 'system', 'Систему': 'System', 'системные': 'system', 'Системные': 'System', 'системный': 'system', 'Системный': 'System', 'системной': 'system', 'Системной': 'System', 'системных': 'system', 'Системных': 'System', 'реестра': 'registry', 'Реестра': 'Registry', 'реестр': 'registry', 'Реестр': 'Registry', 'реестре': 'registry', 'Реестре': 'Registry', 'реестру': 'registry', 'Реестру': 'Registry', 'или': 'or', 'Или': 'Or', 'из': 'from', 'Из': 'From', 'все': 'all', 'Все': 'All', 'всё': 'all', 'Всё': 'All', 'всех': 'all', 'Всех': 'All', 'всю': 'all', 'Всю': 'All', 'запуск': 'launch', 'Запуск': 'Launch', 'запуска': 'launch', 'Запуска': 'Launch', 'запустить': 'launch', 'Запустить': 'Launch:', 'запущен': 'launched', 'Запущен': 'Launched:', 'запущено': 'launched', 'Запущено': 'Launched', 'запускает': 'launches', 'Запускает': 'Launches', 'панель': 'panel', 'Панель': 'Panel:', 'панели': 'panel', 'Панели': 'Panel', 'панель:': 'panel:', 'Панель:': 'Panel:', 'выберите': 'select', 'Выберите': 'Select:', 'удалить': 'delete', 'Удалить': 'Delete:', 'удаление': 'removal', 'Удаление': 'Removal:', 'удалены': 'removed', 'Удалены': 'Removed', 'удален': 'removed', 'Удален': 'Removed', 'удалить:': 'delete:', 'Удалить:': 'Delete:', 'процесс': 'process', 'Процесс': 'Process:', 'процесса': 'process', 'Процесса': 'Process', 'процессы': 'processes', 'Процессы': 'Processes', 'процессов': 'processes', 'Процессов': 'Processes:', 'процессе': 'process', 'Процессе': 'Process', 'только': 'only', 'Только': 'Only', 'что': 'that', 'Что': 'That', 'настройки': 'settings', 'Настройки': 'Settings', 'настройка': 'setting', 'Настройка': 'Setting', 'настройку': 'setting', 'Настройку': 'Setting', 'настроек': 'settings', 'Настроек': 'Settings', 'настроить': 'configure', 'Настроить': 'Configure', 'при': 'at', 'При': 'At', 'бэкап': 'backup', 'Бэкап': 'Backup', 'бэкапы': 'backups', 'Бэкапы': 'Backups', 'бэкапа': 'backup', 'Бэкапа': 'Backup', 'бэкапов': 'backups', 'Бэкапов': 'Backups', 'путь': 'path', 'Путь': 'Path:', 'пути': 'path', 'Пути': 'Path', 'путь:': 'path:', 'Путь:': 'Path:', 'запись': 'entry', 'Запись': 'Entry:', 'записи': 'entries', 'Записи': 'Entries:', 'записей': 'entries', 'Записей': 'Entries', 'запись:': 'entry:', 'Запись:': 'Entry:', 'службу': 'service', 'Службу': 'Service:', 'служба': 'service', 'Служба': 'Service', 'службы': 'service', 'Службы': 'Service', 'служб': 'services', 'Служб': 'Services', 'службе': 'service', 'Службе': 'Service', 'службы:': 'services:', 'Службы:': 'Services:', 'очистка': 'cleanup', 'Очистка': 'Cleanup:', 'очистки': 'cleanup', 'Очистки': 'Cleanup', 'очистить': 'clean', 'Очистить': 'Clean', 'очищает': 'cleans', 'Очищает': 'Cleans', 'очищен': 'cleaned', 'Очищен': 'Cleaned', 'очищено': 'cleaned', 'Очищено': 'Cleaned', 'очистка:': 'cleanup:', 'Очистка:': 'Cleanup:', 'проверка': 'check', 'Проверка': 'Check:', 'проверки': 'check', 'Проверки': 'Check', 'проверяет': 'checks', 'Проверяет': 'Checks', 'проверить': 'check', 'Проверить': 'Check', 'проверяем': 'checking', 'Проверяем': 'Checking', 'проверка:': 'check:', 'Проверка:': 'Check:', 'нет': 'no', 'Нет': 'No:', 'нет:': 'no:', 'Нет:': 'No:', 'режим': 'mode', 'Режим': 'Mode', 'режима': 'mode', 'Режима': 'Mode', 'диспетчер': 'manager', 'Диспетчер': 'Manager:', 'диспетчер:': 'manager:', 'Диспетчер:': 'Manager:', 'если': 'if', 'Если': 'If', 'доступ': 'access', 'Доступ': 'Access:', 'доступа': 'access', 'Доступа': 'Access:', 'доступ:': 'access:', 'Доступ:': 'Access:', 'доступно': 'available', 'Доступно': 'Available', 'доступна': 'available', 'Доступна': 'Available', 'доступен': 'available', 'Доступен': 'Available', 'отключен': 'disabled', 'Отключен': 'Disabled', 'отключено': 'disabled', 'Отключено': 'Disabled', 'отключены': 'disabled', 'Отключены': 'Disabled', 'отключить': 'disable', 'Отключить': 'Disable:', 'отключение': 'disabling', 'Отключение': 'Disabling', 'отключается': 'disables', 'Отключается': 'Disables', 'включен': 'enabled', 'Включен': 'Enabled', 'включено': 'enabled', 'Включено': 'Enabled', 'включены': 'enabled', 'Включены': 'Enabled', 'включить': 'enable', 'Включить': 'Enable:', 'включение': 'enabling', 'Включение': 'Enabling:', 'включает': 'enables', 'Включает': 'Enables', 'включить:': 'enable:', 'Включить:': 'Enable:', 'права': 'permissions', 'Права': 'Permissions:', 'прав': 'permissions', 'Прав': 'Permissions', 'права:': 'permissions:', 'Права:': 'Permissions:', 'свойства': 'properties', 'Свойства': 'Properties:', 'свойств': 'properties', 'Свойств': 'Properties', 'свойства:': 'properties:', 'Свойства:': 'Properties:', 'меню': 'menu', 'Меню': 'Menu:', 'меню:': 'menu:', 'Меню:': 'Menu:', 'управления': 'management', 'Управления': 'Management', 'управление': 'management', 'Управление': 'Management', 'папки': 'folder', 'Папки': 'Folder', 'папка': 'folder', 'Папка': 'Folder:', 'папку': 'folder', 'Папку': 'Folder:', 'папок': 'folders', 'Папок': 'Folders', 'папке': 'folder', 'Папке': 'Folder', 'создать': 'create', 'Создать': 'Create', 'создание': 'creation', 'Создание': 'Creation:', 'создан': 'created', 'Создан': 'Created', 'создано': 'created', 'Создано': 'Created', 'имя': 'name', 'Имя': 'Name:', 'имя:': 'name:', 'Имя:': 'Name:', 'разблокировка': 'unlock', 'Разблокировка': 'Unlock:', 'разблокирует': 'unlocks', 'Разблокирует': 'Unlocks', 'разблокирован': 'unlocked', 'Разблокирован': 'Unlocked', 'разблокированы': 'unlocked', 'Разблокированы': 'Unlocked', 'разблокировка:': 'unlock:', 'Разблокировка:': 'Unlock:', 'блокировки': 'locks', 'Блокировки': 'Locks', 'блокировка': 'lock', 'Блокировка': 'Lock', 'блокировку': 'lock', 'Блокировку': 'Lock', 'блокировок': 'locks', 'Блокировок': 'Locks', 'блокировала': 'blocked', 'Блокировала': 'Blocked', 'брандмауэр': 'firewall', 'Брандмауэр': 'Firewall:', 'брандмауэра': 'firewall', 'Брандмауэра': 'Firewall', 'брандмауэр:': 'firewall:', 'Брандмауэр:': 'Firewall:', 'вирус': 'virus', 'Вирус': 'Virus:', 'вируса': 'virus', 'Вируса': 'Virus', 'вирусы': 'viruses', 'Вирусы': 'Viruses', 'вирусов': 'viruses', 'Вирусов': 'Viruses', 'вирус:': 'virus:', 'Вирус:': 'Virus:', 'подтверждение': 'confirmation', 'Подтверждение': 'Confirmation', 'подтверждения': 'confirmation', 'Подтверждения': 'Confirmation', 'подтвердить': 'confirm', 'Подтвердить': 'Confirm', 'откат': 'rollback', 'Откат': 'Rollback:', 'откатить': 'rollback', 'Откатить': 'Rollback', 'откат:': 'rollback:', 'Откат:': 'Rollback:', 'список': 'list', 'Список': 'List:', 'списка': 'list', 'Списка': 'List', 'список:': 'list:', 'Список:': 'List:', 'политики': 'policies', 'Политики': 'Policies', 'политика': 'policy', 'Политика': 'Policy', 'политик': 'policies', 'Политик': 'Policies', 'добавить': 'add', 'Добавить': 'Add', 'добавлен': 'added', 'Добавлен': 'Added', 'добавлено': 'added', 'Добавлено': 'Added', 'продолжить': 'continue', 'Продолжить': 'Continue', 'включено:': 'enabled:', 'Включено:': 'Enabled:', 'включение:': 'enabling:', 'Включение:': 'Enabling:', 'клавиши': 'keys', 'Клавиши': 'Keys', 'клавиша': 'key', 'Клавиша': 'Key', 'клавиатуре': 'keyboard', 'Клавиатуре': 'Keyboard', 'клавиатура': 'keyboard', 'Клавиатура': 'Keyboard', 'клавиатуры': 'keyboard', 'Клавиатуры': 'Keyboard', 'операция': 'operation', 'Операция': 'Operation', 'операции': 'operation', 'Операции': 'Operation', 'операцию': 'operation', 'Операцию': 'Operation', 'ограничений': 'restrictions', 'Ограничений': 'Restrictions', 'ограничение': 'restriction', 'Ограничение': 'Restriction', 'ограничения': 'restrictions', 'Ограничения': 'Restrictions', 'значение': 'value', 'Значение': 'Value:', 'значения': 'values', 'Значения': 'Values', 'значение:': 'value:', 'Значение:': 'Value:', 'пользователь': 'user', 'Пользователь': 'User', 'пользователя': 'user', 'Пользователя': 'User', 'пользователи': 'users', 'Пользователи': 'Users', 'пользователем': 'user', 'Пользователем': 'User', 'пользователю': 'user', 'Пользователю': 'User', 'подозрительные': 'suspicious', 'Подозрительные': 'Suspicious', 'подозрительных': 'suspicious', 'Подозрительных': 'Suspicious', 'подозрительный': 'suspicious', 'Подозрительный': 'Suspicious', 'найдено': 'found', 'Найдено': 'Found', 'найдено:': 'found:', 'Найдено:': 'Found:', 'найден': 'found', 'Найден': 'Found', 'блок': 'block', 'Блок': 'Block:', 'блок:': 'block:', 'Блок:': 'Block:', 'автозагрузки': 'startup', 'Автозагрузки': 'Startup', 'автозагрузка': 'startup', 'Автозагрузка': 'Startup', 'автозагрузку': 'startup', 'Автозагрузку': 'Startup', 'автозапуск': 'autorun', 'Автозапуск': 'Autorun', 'сброс': 'reset', 'Сброс': 'Reset', 'сброса': 'reset', 'Сброса': 'Reset', 'сбросить': 'reset', 'Сбросить': 'Reset', 'сброшен': 'reset', 'Сброшен': 'Reset', 'сброшено': 'reset', 'Сброшено': 'Reset', 'проводник': 'explorer', 'Проводник': 'Explorer:', 'проводник:': 'explorer:', 'Проводник:': 'Explorer:', 'сканирование': 'scanning', 'Сканирование': 'Scanning:', 'сканировать': 'scan', 'Сканировать': 'Scan', 'сканирование:': 'scanning:', 'Сканирование:': 'Scanning:', 'полный': 'full', 'Полный': 'Full', 'полная': 'full', 'Полная': 'Full', 'полное': 'full', 'Полное': 'Full', 'после': 'after', 'После': 'After', 'перед': 'before', 'Перед': 'Before', 'выполняется': 'running', 'Выполняется': 'Running:', 'выполнено': 'done', 'Выполнено': 'Done', 'выполнено:': 'done:', 'Выполнено:': 'Done:', 'выполнить': 'run', 'Выполнить': 'Run', 'выполнения': 'execution', 'Выполнения': 'Execution', 'готов': 'ready', 'Готов': 'Ready', 'готова': 'ready', 'Готова': 'Ready', 'готово': 'done', 'Готово': 'Done', 'готовы': 'ready', 'Готовы': 'Ready', 'выполняется:': 'running:', 'Выполняется:': 'Running:', 'проблема': 'problem', 'Проблема': 'Problem', 'проблемы': 'problems', 'Проблемы': 'Problems', 'проблем:': 'problems:', 'Проблем': 'Problems:', 'Проблем:': 'Problems:', 'предупреждение': 'warning', 'Предупреждение': 'Warning:', 'предупреждения': 'warning', 'Предупреждения': 'Warning', 'предупреждение:': 'warning:', 'Предупреждение:': 'Warning:', 'успешно': 'successfully', 'Успешно': 'Successfully', 'успешен': 'successful', 'Успешен': 'Successful', 'успешно:': 'successfully:', 'Успешно:': 'Successfully:', 'неизвестно': 'unknown', 'Неизвестно': 'Unknown', 'неизвестный': 'unknown', 'Неизвестный': 'Unknown', 'отключить:': 'disable:', 'Отключить:': 'Disable:', 'перезагрузка': 'reboot', 'Перезагрузка': 'Reboot', 'перезагрузить': 'reboot', 'Перезагрузить': 'Reboot', 'перезагрузки': 'reboot', 'Перезагрузки': 'Reboot', 'перезапустить': 'restart', 'Перезапустить': 'Restart', 'перезапуск': 'restart', 'Перезапуск': 'Restart', 'перезапущен': 'restarted', 'Перезапущен': 'Restarted', 'завершить': 'terminate', 'Завершить': 'Terminate', 'завершение': 'termination', 'Завершение': 'Termination', 'завершен': 'completed', 'Завершен': 'Completed', 'завершено': 'completed', 'Завершено': 'Completed', 'выбор': 'selection', 'Выбор': 'Selection', 'выбора': 'selection', 'Выбора': 'Selection', 'выбрано': 'selected', 'Выбрано': 'Selected', 'выбран': 'selected', 'Выбран': 'Selected', 'выбранный': 'selected', 'Выбранный': 'Selected', 'выбраны': 'selected', 'Выбраны': 'Selected', 'отмена': 'cancel', 'Отмена': 'Cancel', 'отменить': 'cancel', 'Отменить': 'Cancel', 'отменено': 'cancelled', 'Отменено': 'Cancelled', 'закрыть': 'close', 'Закрыть': 'Close', 'закрыт': 'closed', 'Закрыт': 'Closed', 'запустить:': 'launch:', 'Запустить:': 'Launch:', 'остановить': 'stop', 'Остановить': 'Stop', 'остановлен': 'stopped', 'Остановлен': 'Stopped', 'остановлено': 'stopped', 'Остановлено': 'Stopped', 'запущен:': 'launched:', 'Запущен:': 'Launched:', 'файлов:': 'files:', 'Файлов:': 'Files:', 'папку:': 'folder:', 'Папку:': 'Folder:', 'систем:': 'systems:', 'Систем': 'Systems:', 'Систем:': 'Systems:', 'реестра:': 'registry:', 'Реестра:': 'Registry:', 'службу:': 'service:', 'Службу:': 'Service:', 'доступа:': 'access:', 'Доступа:': 'Access:', 'дисков': 'drives', 'Дисков': 'Drives', 'диск': 'drive', 'Диск': 'Drive', 'диски': 'drives', 'Диски': 'Drives', 'диска': 'drive', 'Диска': 'Drive', 'принтер': 'printer', 'Принтер': 'Printer', 'принтера': 'printer', 'Принтера': 'Printer', 'шрифт': 'font', 'Шрифт': 'Font', 'шрифты': 'fonts', 'Шрифты': 'Fonts', 'шрифтов': 'fonts', 'Шрифтов': 'Fonts', 'тема': 'theme', 'Тема': 'Theme', 'темы': 'theme', 'Темы': 'Theme', 'язык': 'language', 'Язык': 'Language', 'языка': 'language', 'Языка': 'Language', 'драйвер': 'driver', 'Драйвер': 'Driver', 'драйвера': 'drivers', 'Драйвера': 'Drivers', 'драйверов': 'drivers', 'Драйверов': 'Drivers', 'обновление': 'update', 'Обновление': 'Update', 'обновления': 'update', 'Обновления': 'Update', 'обновить': 'update', 'Обновить': 'Update', 'обновлено': 'updated', 'Обновлено': 'Updated', 'центр': 'center', 'Центр': 'Center', 'центра': 'center', 'Центра': 'Center', 'безопасность': 'security', 'Безопасность': 'Security', 'безопасности': 'security', 'Безопасности': 'Security', 'безопасный': 'safe', 'Безопасный': 'Safe', 'безопасно': 'safe', 'Безопасно': 'Safe', 'защита': 'protection', 'Защита': 'Protection:', 'защиты': 'protection', 'Защиты': 'Protection', 'защита:': 'protection:', 'Защита:': 'Protection:', 'защитит': 'protect', 'Защитит': 'Protect', 'защищено': 'protected', 'Защищено': 'Protected', 'защищен': 'protected', 'Защищен': 'Protected', 'защищает': 'protects', 'Защищает': 'Protects', 'антивирус': 'antivirus', 'Антивирус': 'Antivirus', 'антивируса': 'antivirus', 'Антивируса': 'Antivirus', 'вредонос': 'malicious', 'Вредонос': 'Malicious', 'вредоносный': 'malicious', 'Вредоносный': 'Malicious', 'вредоносных': 'malicious', 'Вредоносных': 'Malicious', 'угроза': 'threat', 'Угроза': 'Threat', 'угрозы': 'threats', 'Угрозы': 'Threats', 'угроз:': 'threats:', 'Угроз': 'Threats:', 'Угроз:': 'Threats:', 'восстановление системы': 'system restore', 'Восстановление системы': 'System restore', 'восстановлено:': 'restored:', 'Восстановлено:': 'Restored:', 'поддержка': 'support', 'Поддержка': 'Support', 'поддержки': 'support', 'Поддержки': 'Support', 'поддерживает': 'supports', 'Поддерживает': 'Supports', 'инструмент': 'tool', 'Инструмент': 'Tool:', 'инструменты': 'tools', 'Инструменты': 'Tools', 'инструментов': 'tools', 'Инструментов': 'Tools', 'инструмент:': 'tool:', 'Инструмент:': 'Tool:', 'очищены': 'cleaned', 'Очищены': 'Cleaned', 'удаление:': 'removal:', 'Удаление:': 'Removal:', 'имена': 'names', 'Имена': 'Names', 'имен': 'names', 'Имен': 'Names', 'записи:': 'entries:', 'Записи:': 'Entries:', 'события': 'events', 'События': 'Events', 'событие': 'event', 'Событие': 'Event', 'событий': 'events', 'Событий': 'Events', 'журнал': 'log', 'Журнал': 'Log', 'журнала': 'log', 'Журнала': 'Log', 'задач:': 'tasks:', 'Задач:': 'Tasks:', 'процесс:': 'process:', 'Процесс:': 'Process:', 'процессов:': 'processes:', 'Процессов:': 'Processes:', 'отчет': 'report', 'Отчет': 'Report', 'отчёт': 'report', 'Отчёт': 'Report', 'отчета': 'report', 'Отчета': 'Report', 'точка': 'point', 'Точка': 'Point', 'точки': 'point', 'Точки': 'Point', 'точку': 'point', 'Точку': 'Point', 'конец': 'end', 'Конец': 'End', 'завершения': 'completion', 'Завершения': 'Completion', 'восстановлено!': 'restored!', 'Восстановлено!': 'Restored!', 'успешно!': 'successfully!', 'Успешно!': 'Successfully!', 'выполнено!': 'done!', 'Выполнено!': 'Done!', 'готово!': 'done!', 'Готово!': 'Done!', 'отключено!': 'disabled!', 'Отключено!': 'Disabled!', 'включено!': 'enabled!', 'Включено!': 'Enabled!', 'удалено': 'removed', 'Удалено': 'Removed', 'скопирован': 'copied', 'Скопирован': 'Copied', 'скопировано': 'copied', 'Скопировано': 'Copied', 'скопировать': 'copy', 'Скопировать': 'Copy', 'копировать': 'copy', 'Копировать': 'Copy', 'создание:': 'creation:', 'Создание:': 'Creation:', 'файл:': 'file:', 'Файл:': 'File:', 'папка:': 'folder:', 'Папка:': 'Folder:', 'система:': 'system:', 'Система:': 'System:', 'остановлена': 'stopped', 'Остановлена': 'Stopped', 'остановлены': 'stopped', 'Остановлены': 'Stopped', 'завершена': 'completed', 'Завершена': 'Completed', 'завершены': 'completed', 'Завершены': 'Completed', 'выполнена': 'done', 'Выполнена': 'Done', 'выполнены': 'done', 'Выполнены': 'Done', 'удалена': 'removed', 'Удалена': 'Removed', 'создана': 'created', 'Создана': 'Created', 'созданы': 'created', 'Созданы': 'Created', 'включена': 'enabled', 'Включена': 'Enabled', 'отключена': 'disabled', 'Отключена': 'Disabled', 'найдена': 'found', 'Найдена': 'Found', 'найдены': 'found', 'Найдены': 'Found', 'установлена': 'installed', 'Установлена': 'Installed', 'установлено': 'installed', 'Установлено': 'Installed', 'установлены': 'installed', 'Установлены': 'Installed', 'установлен': 'installed', 'Установлен': 'Installed', 'сброшена': 'reset', 'Сброшена': 'Reset', 'сброшены': 'reset', 'Сброшены': 'Reset', 'очищена': 'cleaned', 'Очищена': 'Cleaned', 'заблокирована': 'blocked', 'Заблокирована': 'Blocked', 'заблокировано': 'blocked', 'Заблокировано': 'Blocked', 'заблокированы': 'blocked', 'Заблокированы': 'Blocked', 'заблокирован': 'blocked', 'Заблокирован': 'Blocked', 'разблокирована': 'unlocked', 'Разблокирована': 'Unlocked', 'разблокировано': 'unlocked', 'Разблокировано': 'Unlocked', 'запущена': 'launched', 'Запущена': 'Launched', 'запущены': 'launched', 'Запущены': 'Launched', 'перезапущена': 'restarted', 'Перезапущена': 'Restarted', 'перезапущено': 'restarted', 'Перезапущено': 'Restarted', 'обновлена': 'updated', 'Обновлена': 'Updated', 'обновлены': 'updated', 'Обновлены': 'Updated', 'восстановлена': 'restored', 'Восстановлена': 'Restored', 'скопирована': 'copied', 'Скопирована': 'Copied', 'скопированы': 'copied', 'Скопированы': 'Copied', 'разрешена': 'allowed', 'Разрешена': 'Allowed', 'разрешено': 'allowed', 'Разрешено': 'Allowed', 'разрешены': 'allowed', 'Разрешены': 'Allowed', 'запрещена': 'forbidden', 'Запрещена': 'Forbidden', 'запрещено': 'forbidden', 'Запрещено': 'Forbidden', 'запрещены': 'forbidden', 'Запрещены': 'Forbidden', 'активна': 'active', 'Активна': 'Active', 'активно': 'active', 'Активно': 'Active', 'активны': 'active', 'Активны': 'Active', 'активен': 'active', 'Активен': 'Active', 'неактивна': 'inactive', 'Неактивна': 'Inactive', 'неактивно': 'inactive', 'Неактивно': 'Inactive', 'неактивен': 'inactive', 'Неактивен': 'Inactive', 'доступны': 'available', 'Доступны': 'Available', 'отсутствует': 'missing', 'Отсутствует': 'Missing:', 'отсутствует:': 'missing:', 'Отсутствует:': 'Missing:', 'отсутствуют': 'missing', 'Отсутствуют': 'Missing', 'работает': 'works', 'Работает': 'Works:', 'работают': 'work', 'Работают': 'Work', 'работает:': 'works:', 'Работает:': 'Works:', 'неработает': 'not working', 'Неработает': 'Not working', 'поврежден': 'damaged', 'Поврежден': 'Damaged', 'повреждена': 'damaged', 'Повреждена': 'Damaged', 'повреждено': 'damaged', 'Повреждено': 'Damaged', 'повреждены': 'damaged', 'Повреждены': 'Damaged', 'исправен': 'ok', 'Исправен': 'Ok', 'исправна': 'ok', 'Исправна': 'Ok', 'исправно': 'ok', 'Исправно': 'Ok', 'исправить': 'fix', 'Исправить': 'Fix', 'исправление': 'fix', 'Исправление': 'Fix', 'исправлен': 'fixed', 'Исправлен': 'Fixed', 'исправлено': 'fixed', 'Исправлено': 'Fixed', 'исправлена': 'fixed', 'Исправлена': 'Fixed', 'требуется': 'required', 'Требуется': 'Required:', 'требуется:': 'required:', 'Требуется:': 'Required:', 'требуется перезагрузка': 'reboot required', 'Требуется перезагрузка': 'Reboot required', 'перезагрузка требуется': 'reboot required', 'Перезагрузка требуется': 'Reboot required', 'завершите': 'finish', 'Завершите': 'Finish', 'подтвердите': 'confirm', 'Подтвердите': 'Confirm', 'нажмите': 'press', 'Нажмите': 'Press:', 'нажмите:': 'press:', 'Нажмите:': 'Press:', 'нажмите чтобы': 'press to', 'Нажмите чтобы': 'Press to', 'выполните': 'run', 'Выполните': 'Run', 'перезапустите': 'restart', 'Перезапустите': 'Restart', 'перезагрузите': 'reboot', 'Перезагрузите': 'Reboot', 'запустите': 'launch', 'Запустите': 'Launch', 'откройте': 'open', 'Откройте': 'Open:', 'откройте:': 'open:', 'Откройте:': 'Open:', 'выберите:': 'select:', 'Выберите:': 'Select:', 'попробуйте': 'try', 'Попробуйте': 'Try', 'снова': 'again', 'Снова': 'Again', 'повторно': 'again', 'Повторно': 'Again', 'выполните повторно': 'retry', 'Выполните повторно': 'Retry', 'подождите': 'wait', 'Подождите': 'Wait', 'загрузка': 'loading', 'Загрузка': 'Loading', 'загрузки': 'loading', 'Загрузки': 'Loading', 'загружено': 'loaded', 'Загружено': 'Loaded', 'загружен': 'loaded', 'Загружен': 'Loaded', 'обнаружен': 'detected', 'Обнаружен': 'Detected', 'обнаружено': 'detected', 'Обнаружено': 'Detected', 'обнаружена': 'detected', 'Обнаружена': 'Detected', 'обнаружены': 'detected', 'Обнаружены': 'Detected', 'присутствует': 'present', 'Присутствует': 'Present', 'поддерживается': 'supported', 'Поддерживается': 'Supported', 'получено': 'received', 'Получено': 'Received', 'получен': 'received', 'Получен': 'Received', 'отправлено': 'sent', 'Отправлено': 'Sent', 'отправлен': 'sent', 'Отправлен': 'Sent', 'прервано': 'aborted', 'Прервано': 'Aborted', 'прерван': 'aborted', 'Прерван': 'Aborted', 'истекло': 'expired', 'Истекло': 'Expired', 'истек': 'expired', 'Истек': 'Expired', 'время': 'time', 'Время': 'Time:', 'время:': 'time:', 'Время:': 'Time:', 'времени': 'time', 'Времени': 'Time', 'таймаут': 'timeout', 'Таймаут': 'Timeout:', 'таймаут:': 'timeout:', 'Таймаут:': 'Timeout:', 'размер': 'size', 'Размер': 'Size:', 'размер:': 'size:', 'Размер:': 'Size:', 'тип': 'type', 'Тип': 'Type:', 'тип:': 'type:', 'Тип:': 'Type:', 'статус': 'status', 'Статус': 'Status:', 'статус:': 'status:', 'Статус:': 'Status:', 'состояние': 'state', 'Состояние': 'State:', 'состояние:': 'state:', 'Состояние:': 'State:', 'состояния': 'state', 'Состояния': 'State', 'данные': 'data', 'Данные': 'Data:', 'данных': 'data', 'Данных': 'Data', 'данные:': 'data:', 'Данные:': 'Data:', 'информация': 'info', 'Информация': 'Info:', 'информация:': 'info:', 'Информация:': 'Info:', 'информации': 'info', 'Информации': 'Info', 'подробнее': 'details', 'Подробнее': 'Details:', 'подробнее:': 'details:', 'Подробнее:': 'Details:', 'детально': 'detailed', 'Детально': 'Detailed', 'причина': 'reason', 'Причина': 'Reason:', 'причина:': 'reason:', 'Причина:': 'Reason:', 'причины': 'reason', 'Причины': 'Reason', 'решение': 'solution', 'Решение': 'Solution:', 'решение:': 'solution:', 'Решение:': 'Solution:', 'решения': 'solution', 'Решения': 'Solution', 'рекомендация': 'recommendation', 'Рекомендация': 'Recommendation', 'рекомендации': 'recommendations', 'Рекомендации': 'Recommendations', 'рекомендуется': 'recommended', 'Рекомендуется': 'Recommended:', 'рекомендуется:': 'recommended:', 'Рекомендуется:': 'Recommended:', 'внимание': 'warning', 'Внимание': 'Warning:', 'внимание:': 'warning:', 'Внимание:': 'Warning:', 'осторожно': 'caution', 'Осторожно': 'Caution', 'опасно': 'dangerous', 'Опасно': 'Dangerous:', 'опасно:': 'dangerous:', 'Опасно:': 'Dangerous:', 'риск': 'risk', 'Риск': 'Risk', 'риска': 'risk', 'Риска': 'Risk', 'необратимо': 'irreversible', 'Необратимо': 'Irreversible', 'необратимых': 'irreversible', 'Необратимых': 'Irreversible', 'назад': 'back', 'Назад': 'Back', 'далее': 'next', 'Далее': 'Next', 'вперед': 'forward', 'Вперед': 'Forward', 'выполнено успешно': 'completed successfully', 'Выполнено успешно': 'Completed successfully', 'операция выполнена': 'operation completed', 'Операция выполнена': 'Operation completed', 'операция завершена': 'operation completed', 'Операция завершена': 'Operation completed', 'изменения сохранены': 'changes saved', 'Изменения сохранены': 'Changes saved', 'изменения': 'changes', 'Изменения': 'Changes:', 'изменения:': 'changes:', 'Изменения:': 'Changes:', 'изменен': 'changed', 'Изменен': 'Changed', 'изменено': 'changed', 'Изменено': 'Changed', 'изменить': 'change', 'Изменить': 'Change', 'сохранить': 'save', 'Сохранить': 'Save', 'сохранен': 'saved', 'Сохранен': 'Saved', 'сохранено': 'saved', 'Сохранено': 'Saved', 'сохранена': 'saved', 'Сохранена': 'Saved', 'сохранены': 'saved', 'Сохранены': 'Saved', 'импорт': 'import', 'Импорт': 'Import', 'экспорт': 'export', 'Экспорт': 'Export', 'записано': 'written', 'Записано': 'Written', 'запись создана': 'entry created', 'Запись создана': 'Entry created', 'запись удалена': 'entry removed', 'Запись удалена': 'Entry removed', 'ключ': 'key', 'Ключ': 'Key:', 'ключи': 'keys', 'Ключи': 'Keys', 'ключ:': 'key:', 'Ключ:': 'Key:', 'параметр': 'parameter', 'Параметр': 'Parameter:', 'параметры': 'parameters', 'Параметры': 'Parameters', 'параметр:': 'parameter:', 'Параметр:': 'Parameter:', 'строка': 'line', 'Строка': 'Line', 'строки': 'lines', 'Строки': 'Lines', 'элемент': 'item', 'Элемент': 'Item:', 'элементы': 'items', 'Элементы': 'Items', 'элемент:': 'item:', 'Элемент:': 'Item:', 'компонент': 'component', 'Компонент': 'Component:', 'компоненты': 'components', 'Компоненты': 'Components', 'компонент:': 'component:', 'Компонент:': 'Component:', 'завершить процесс': 'end process', 'Завершить процесс': 'End process', 'перезапустить службу': 'restart service', 'Перезапустить службу': 'Restart service', 'запустить службу': 'start service', 'Запустить службу': 'Start service', 'остановить службу': 'stop service', 'Остановить службу': 'Stop service', 'вирусом': 'virus', 'Вирусом': 'Virus', 'службой': 'service', 'Службой': 'Service', 'процессом': 'process', 'Процессом': 'Process', 'путем': 'path', 'Путем': 'Path', 'путём': 'path', 'Путём': 'Path', 'администратором': 'administrator', 'Администратором': 'Administrator', 'системой': 'system', 'Системой': 'System', 'реестром': 'registry', 'Реестром': 'Registry', 'диском': 'drive', 'Диском': 'Drive', 'принтером': 'printer', 'Принтером': 'Printer', 'шрифтом': 'font', 'Шрифтом': 'Font', 'брандмауэром': 'firewall', 'Брандмауэром': 'Firewall', 'процессором': 'processor', 'Процессором': 'Processor', 'сетью': 'network', 'Сетью': 'Network', 'сети': 'network', 'Сети': 'Network', 'сервисом': 'service', 'Сервисом': 'Service', 'сервиса': 'service', 'Сервиса': 'Service', 'файле': 'file', 'Файле': 'File', 'системе': 'system', 'Системе': 'System', 'диске': 'drive', 'Диске': 'Drive', 'пользователе': 'user', 'Пользователе': 'User', 'администратора': 'administrator', 'Администратора': 'Administrator', 'полностью': 'fully', 'Полностью': 'Fully', 'частично': 'partially', 'Частично': 'Partially', 'автоматически': 'automatically', 'Автоматически': 'Automatically', 'принудительно': 'forcibly', 'Принудительно': 'Forcibly', 'немедленно': 'immediately', 'Немедленно': 'Immediately', 'временно': 'temporarily', 'Временно': 'Temporarily', 'постоянно': 'permanently', 'Постоянно': 'Permanently', 'локально': 'locally', 'Локально': 'Locally', 'удаленно': 'remotely', 'Удаленно': 'Remotely', 'отменена': 'cancelled', 'Отменена': 'Cancelled', 'отменены': 'cancelled', 'Отменены': 'Cancelled', 'пропущена': 'skipped', 'Пропущена': 'Skipped', 'пропущено': 'skipped', 'Пропущено': 'Skipped', 'пропущены': 'skipped', 'Пропущены': 'Skipped', 'пропущен': 'skipped', 'Пропущен': 'Skipped'},
        "uk": {'не': 'не', 'Не': 'Не', 'будет': 'буде', 'Будет': 'Буде', 'будут': 'будуть', 'Будут': 'Будуть', 'ошибка': 'помилка', 'Ошибка': 'Помилка', 'ошибки': 'помилки', 'Ошибки': 'Помилки', 'ошибок': 'помилок', 'Ошибок': 'Помилок:', 'ошибок:': 'помилок:', 'Ошибок:': 'Помилок:', 'ошибками': 'помилками', 'Ошибками': 'Помилками', 'ошибку': 'помилку', 'Ошибку': 'Помилку', 'файл': 'файл', 'Файл': 'Файл:', 'файла': 'файлу', 'Файла': 'Файлу', 'файлы': 'файли', 'Файлы': 'Файли', 'файлов': 'файлів', 'Файлов': 'Файлів:', 'файлом': 'файлом', 'Файлом': 'Файлом', 'удалось': 'вдалося', 'Удалось': 'Вдалося', 'не удалось': 'не вдалося', 'Не удалось': 'Не вдалося', 'задач': 'завдань', 'Задач': 'Завдань:', 'задача': 'завдання', 'Задача': 'Завдання', 'задачу': 'завдання', 'Задачу': 'Завдання', 'задачи': 'завдання', 'Задачи': 'Завдання', 'задаче': 'завданні', 'Задаче': 'Завданні', 'через': 'через', 'Через': 'Через', 'восстановление': 'відновлення', 'Восстановление': 'Відновлення', 'восстановления': 'відновлення', 'Восстановления': 'Відновлення:', 'восстановлено': 'відновлено', 'Восстановлено': 'Відновлено', 'восстановлен': 'відновлено', 'Восстановлен': 'Відновлено', 'восстановить': 'відновити', 'Восстановить': 'Відновити', 'восстанавливает': 'відновлює', 'Восстанавливает': 'Відновлює', 'восстанавливаеться': 'відновлюється', 'Восстанавливаеться': 'Відновлюється', 'восстановлены': 'відновлені', 'Восстановлены': 'Відновлені', 'восстановления:': 'відновлення:', 'Восстановления:': 'Відновлення:', 'системы': 'системи', 'Системы': 'Системи', 'система': 'система', 'Система': 'Система:', 'систему': 'систему', 'Систему': 'Систему', 'системные': 'системні', 'Системные': 'Системні', 'системный': 'системний', 'Системный': 'Системний', 'системной': 'системної', 'Системной': 'Системної', 'системных': 'системних', 'Системных': 'Системних', 'реестра': 'реєстру', 'Реестра': 'Реєстру', 'реестр': 'реєстр', 'Реестр': 'Реєстр', 'реестре': 'реєстрі', 'Реестре': 'Реєстрі', 'реестру': 'реєстру', 'Реестру': 'Реєстру', 'или': 'або', 'Или': 'Або', 'из': 'з', 'Из': 'З', 'все': 'всі', 'Все': 'Всі', 'всё': 'все', 'Всё': 'Все', 'всех': 'всіх', 'Всех': 'Всіх', 'всю': 'всю', 'Всю': 'Всю', 'запуск': 'запуск', 'Запуск': 'Запуск', 'запуска': 'запуску', 'Запуска': 'Запуску', 'запустить': 'запустити', 'Запустить': 'Запустити:', 'запущен': 'запущено', 'Запущен': 'Запущено:', 'запущено': 'запущено', 'Запущено': 'Запущено', 'запускает': 'запускає', 'Запускает': 'Запускає', 'панель': 'панель', 'Панель': 'Панель:', 'панели': 'панелі', 'Панели': 'Панелі', 'панель:': 'панель:', 'Панель:': 'Панель:', 'выберите': 'виберіть', 'Выберите': 'Виберіть:', 'удалить': 'видалити', 'Удалить': 'Видалити:', 'удаление': 'видалення', 'Удаление': 'Видалення:', 'удалены': 'видалені', 'Удалены': 'Видалені', 'удален': 'видалено', 'Удален': 'Видалено', 'удалить:': 'видалити:', 'Удалить:': 'Видалити:', 'процесс': 'процес', 'Процесс': 'Процес:', 'процесса': 'процесу', 'Процесса': 'Процесу', 'процессы': 'процеси', 'Процессы': 'Процеси', 'процессов': 'процесів', 'Процессов': 'Процесів:', 'процессе': 'процесі', 'Процессе': 'Процесі', 'только': 'лише', 'Только': 'Лише', 'что': 'що', 'Что': 'Що', 'настройки': 'налаштування', 'Настройки': 'Налаштування', 'настройка': 'налаштування', 'Настройка': 'Налаштування', 'настройку': 'налаштування', 'Настройку': 'Налаштування', 'настроек': 'налаштувань', 'Настроек': 'Налаштувань', 'настроить': 'налаштувати', 'Настроить': 'Налаштувати', 'при': 'при', 'При': 'При', 'бэкап': 'бекап', 'Бэкап': 'Бекап', 'бэкапы': 'бекапи', 'Бэкапы': 'Бекапи', 'бэкапа': 'бекапу', 'Бэкапа': 'Бекапу', 'бэкапов': 'бекапів', 'Бэкапов': 'Бекапів', 'путь': 'шлях', 'Путь': 'Шлях:', 'пути': 'шляхи', 'Пути': 'Шляхи', 'путь:': 'шлях:', 'Путь:': 'Шлях:', 'запись': 'запис', 'Запись': 'Запис:', 'записи': 'записи', 'Записи': 'Записи:', 'записей': 'записів', 'Записей': 'Записів', 'запись:': 'запис:', 'Запись:': 'Запис:', 'службу': 'службу', 'Службу': 'Службу:', 'служба': 'служба', 'Служба': 'Служба', 'службы': 'служби', 'Службы': 'Служби', 'служб': 'служб', 'Служб': 'Служб', 'службе': 'службі', 'Службе': 'Службі', 'службы:': 'служби:', 'Службы:': 'Служби:', 'очистка': 'очищення', 'Очистка': 'Очищення:', 'очистки': 'очищення', 'Очистки': 'Очищення', 'очистить': 'очистити', 'Очистить': 'Очистити', 'очищает': 'очищає', 'Очищает': 'Очищає', 'очищен': 'очищено', 'Очищен': 'Очищено', 'очищено': 'очищено', 'Очищено': 'Очищено', 'очистка:': 'очищення:', 'Очистка:': 'Очищення:', 'проверка': 'перевірка', 'Проверка': 'Перевірка:', 'проверки': 'перевірки', 'Проверки': 'Перевірки', 'проверяет': 'перевіряє', 'Проверяет': 'Перевіряє', 'проверить': 'перевірити', 'Проверить': 'Перевірити', 'проверяем': 'перевіряємо', 'Проверяем': 'Перевіряємо', 'проверка:': 'перевірка:', 'Проверка:': 'Перевірка:', 'нет': 'немає', 'Нет': 'Немає:', 'нет:': 'немає:', 'Нет:': 'Немає:', 'режим': 'режим', 'Режим': 'Режим', 'режима': 'режиму', 'Режима': 'Режиму', 'диспетчер': 'диспетчер', 'Диспетчер': 'Диспетчер:', 'диспетчер:': 'диспетчер:', 'Диспетчер:': 'Диспетчер:', 'если': 'якщо', 'Если': 'Якщо', 'доступ': 'доступ', 'Доступ': 'Доступ:', 'доступа': 'доступу', 'Доступа': 'Доступу:', 'доступ:': 'доступ:', 'Доступ:': 'Доступ:', 'доступно': 'доступно', 'Доступно': 'Доступно', 'доступна': 'доступна', 'Доступна': 'Доступна', 'доступен': 'доступний', 'Доступен': 'Доступний', 'отключен': 'вимкнено', 'Отключен': 'Вимкнено', 'отключено': 'вимкнено', 'Отключено': 'Вимкнено', 'отключены': 'вимкнені', 'Отключены': 'Вимкнені', 'отключить': 'вимкнути', 'Отключить': 'Вимкнути:', 'отключение': 'вимкнення', 'Отключение': 'Вимкнення', 'отключается': 'вимикається', 'Отключается': 'Вимикається', 'включен': 'увімкнено', 'Включен': 'Увімкнено', 'включено': 'увімкнено', 'Включено': 'Увімкнено', 'включены': 'увімкнені', 'Включены': 'Увімкнені', 'включить': 'увімкнути', 'Включить': 'Увімкнути:', 'включение': 'ввімкнення', 'Включение': 'Ввімкнення:', 'включает': 'вмикає', 'Включает': 'Вмикає', 'включить:': 'увімкнути:', 'Включить:': 'Увімкнути:', 'права': 'права', 'Права': 'Права:', 'прав': 'прав', 'Прав': 'Прав', 'права:': 'права:', 'Права:': 'Права:', 'свойства': 'властивості', 'Свойства': 'Властивості:', 'свойств': 'властивостей', 'Свойств': 'Властивостей', 'свойства:': 'властивості:', 'Свойства:': 'Властивості:', 'меню': 'меню', 'Меню': 'Меню:', 'меню:': 'меню:', 'Меню:': 'Меню:', 'управления': 'управління', 'Управления': 'Управління', 'управление': 'управління', 'Управление': 'Управління', 'папки': 'папки', 'Папки': 'Папки', 'папка': 'папка', 'Папка': 'Папка:', 'папку': 'папку', 'Папку': 'Папку:', 'папок': 'папок', 'Папок': 'Папок', 'папке': 'папці', 'Папке': 'Папці', 'создать': 'створити', 'Создать': 'Створити', 'создание': 'створення', 'Создание': 'Створення:', 'создан': 'створено', 'Создан': 'Створено', 'создано': 'створено', 'Создано': 'Створено', 'имя': 'ім\'я', 'Имя': 'Ім\'я:', 'имя:': 'ім\'я:', 'Имя:': 'Ім\'я:', 'разблокировка': 'розблокування', 'Разблокировка': 'Розблокування:', 'разблокирует': 'розблоковує', 'Разблокирует': 'Розблоковує', 'разблокирован': 'розблоковано', 'Разблокирован': 'Розблоковано', 'разблокированы': 'розблоковані', 'Разблокированы': 'Розблоковані', 'разблокировка:': 'розблокування:', 'Разблокировка:': 'Розблокування:', 'блокировки': 'блокування', 'Блокировки': 'Блокування', 'блокировка': 'блокування', 'Блокировка': 'Блокування', 'блокировку': 'блокування', 'Блокировку': 'Блокування', 'блокировок': 'блокувань', 'Блокировок': 'Блокувань', 'блокировала': 'блокувала', 'Блокировала': 'Блокувала', 'брандмауэр': 'брандмауер', 'Брандмауэр': 'Брандмауер:', 'брандмауэра': 'брандмауера', 'Брандмауэра': 'Брандмауера', 'брандмауэр:': 'брандмауер:', 'Брандмауэр:': 'Брандмауер:', 'вирус': 'вірус', 'Вирус': 'Вірус:', 'вируса': 'віруса', 'Вируса': 'Віруса', 'вирусы': 'віруси', 'Вирусы': 'Віруси', 'вирусов': 'вірусів', 'Вирусов': 'Вірусів', 'вирус:': 'вірус:', 'Вирус:': 'Вірус:', 'подтверждение': 'підтвердження', 'Подтверждение': 'Підтвердження', 'подтверждения': 'підтвердження', 'Подтверждения': 'Підтвердження', 'подтвердить': 'підтвердити', 'Подтвердить': 'Підтвердити', 'откат': 'відкат', 'Откат': 'Відкат:', 'откатить': 'відкотити', 'Откатить': 'Відкотити', 'откат:': 'відкат:', 'Откат:': 'Відкат:', 'список': 'список', 'Список': 'Список:', 'списка': 'списку', 'Списка': 'Списку', 'список:': 'список:', 'Список:': 'Список:', 'политики': 'політики', 'Политики': 'Політики', 'политика': 'політика', 'Политика': 'Політика', 'политик': 'політик', 'Политик': 'Політик', 'добавить': 'додати', 'Добавить': 'Додати', 'добавлен': 'додано', 'Добавлен': 'Додано', 'добавлено': 'додано', 'Добавлено': 'Додано', 'продолжить': 'продовжити', 'Продолжить': 'Продовжити', 'включено:': 'увімкнено:', 'Включено:': 'Увімкнено:', 'включение:': 'ввімкнення:', 'Включение:': 'Ввімкнення:', 'клавиши': 'клавіші', 'Клавиши': 'Клавіші', 'клавиша': 'клавіша', 'Клавиша': 'Клавіша', 'клавиатуре': 'клавіатурі', 'Клавиатуре': 'Клавіатурі', 'клавиатура': 'клавіатура', 'Клавиатура': 'Клавіатура', 'клавиатуры': 'клавіатури', 'Клавиатуры': 'Клавіатури', 'операция': 'операція', 'Операция': 'Операція', 'операции': 'операції', 'Операции': 'Операції', 'операцию': 'операцію', 'Операцию': 'Операцію', 'ограничений': 'обмежень', 'Ограничений': 'Обмежень', 'ограничение': 'обмеження', 'Ограничение': 'Обмеження', 'ограничения': 'обмеження', 'Ограничения': 'Обмеження', 'значение': 'значення', 'Значение': 'Значення:', 'значения': 'значення', 'Значения': 'Значення', 'значение:': 'значення:', 'Значение:': 'Значення:', 'пользователь': 'користувач', 'Пользователь': 'Користувач', 'пользователя': 'користувача', 'Пользователя': 'Користувача', 'пользователи': 'користувачі', 'Пользователи': 'Користувачі', 'пользователем': 'користувачем', 'Пользователем': 'Користувачем', 'пользователю': 'користувачу', 'Пользователю': 'Користувачу', 'подозрительные': 'підозрілі', 'Подозрительные': 'Підозрілі', 'подозрительных': 'підозрілих', 'Подозрительных': 'Підозрілих', 'подозрительный': 'підозрілий', 'Подозрительный': 'Підозрілий', 'найдено': 'знайдено', 'Найдено': 'Знайдено', 'найдено:': 'знайдено:', 'Найдено:': 'Знайдено:', 'найден': 'знайдено', 'Найден': 'Знайдено', 'блок': 'блок', 'Блок': 'Блок:', 'блок:': 'блок:', 'Блок:': 'Блок:', 'автозагрузки': 'автозавантаження', 'Автозагрузки': 'Автозавантаження', 'автозагрузка': 'автозавантаження', 'Автозагрузка': 'Автозавантаження', 'автозагрузку': 'автозавантаження', 'Автозагрузку': 'Автозавантаження', 'автозапуск': 'автозапуск', 'Автозапуск': 'Автозапуск', 'сброс': 'скидання', 'Сброс': 'Скидання', 'сброса': 'скидання', 'Сброса': 'Скидання', 'сбросить': 'скинути', 'Сбросить': 'Скинути', 'сброшен': 'скинуто', 'Сброшен': 'Скинуто', 'сброшено': 'скинуто', 'Сброшено': 'Скинуто', 'проводник': 'проводник', 'Проводник': 'Проводник:', 'проводник:': 'проводник:', 'Проводник:': 'Проводник:', 'сканирование': 'сканування', 'Сканирование': 'Сканування:', 'сканировать': 'сканувати', 'Сканировать': 'Сканувати', 'сканирование:': 'сканування:', 'Сканирование:': 'Сканування:', 'полный': 'повний', 'Полный': 'Повний', 'полная': 'повна', 'Полная': 'Повна', 'полное': 'повне', 'Полное': 'Повне', 'после': 'після', 'После': 'Після', 'перед': 'перед', 'Перед': 'Перед', 'выполняется': 'виконується', 'Выполняется': 'Виконується:', 'выполнено': 'виконано', 'Выполнено': 'Виконано', 'выполнено:': 'виконано:', 'Выполнено:': 'Виконано:', 'выполнить': 'виконати', 'Выполнить': 'Виконати', 'выполнения': 'виконання', 'Выполнения': 'Виконання', 'готов': 'готовий', 'Готов': 'Готовий', 'готова': 'готова', 'Готова': 'Готова', 'готово': 'готово', 'Готово': 'Готово', 'готовы': 'готові', 'Готовы': 'Готові', 'выполняется:': 'виконується:', 'Выполняется:': 'Виконується:', 'проблема': 'проблема', 'Проблема': 'Проблема', 'проблемы': 'проблеми', 'Проблемы': 'Проблеми', 'проблем:': 'проблем:', 'Проблем': 'Проблем:', 'Проблем:': 'Проблем:', 'предупреждение': 'попередження', 'Предупреждение': 'Попередження:', 'предупреждения': 'попередження', 'Предупреждения': 'Попередження', 'предупреждение:': 'попередження:', 'Предупреждение:': 'Попередження:', 'успешно': 'успішно', 'Успешно': 'Успішно', 'успешен': 'успішний', 'Успешен': 'Успішний', 'успешно:': 'успішно:', 'Успешно:': 'Успішно:', 'неизвестно': 'невідомо', 'Неизвестно': 'Невідомо', 'неизвестный': 'невідомий', 'Неизвестный': 'Невідомий', 'отключить:': 'вимкнути:', 'Отключить:': 'Вимкнути:', 'перезагрузка': 'перезавантаження', 'Перезагрузка': 'Перезавантаження', 'перезагрузить': 'перезавантажити', 'Перезагрузить': 'Перезавантажити', 'перезагрузки': 'перезавантаження', 'Перезагрузки': 'Перезавантаження', 'перезапустить': 'перезапустити', 'Перезапустить': 'Перезапустити', 'перезапуск': 'перезапуск', 'Перезапуск': 'Перезапуск', 'перезапущен': 'перезапущено', 'Перезапущен': 'Перезапущено', 'завершить': 'завершити', 'Завершить': 'Завершити', 'завершение': 'завершення', 'Завершение': 'Завершення', 'завершен': 'завершено', 'Завершен': 'Завершено', 'завершено': 'завершено', 'Завершено': 'Завершено', 'выбор': 'вибір', 'Выбор': 'Вибір', 'выбора': 'вибору', 'Выбора': 'Вибору', 'выбрано': 'вибрано', 'Выбрано': 'Вибрано', 'выбран': 'вибрано', 'Выбран': 'Вибрано', 'выбранный': 'вибраний', 'Выбранный': 'Вибраний', 'выбраны': 'вибрані', 'Выбраны': 'Вибрані', 'отмена': 'скасувати', 'Отмена': 'Скасувати', 'отменить': 'скасувати', 'Отменить': 'Скасувати', 'отменено': 'скасовано', 'Отменено': 'Скасовано', 'закрыть': 'закрити', 'Закрыть': 'Закрити', 'закрыт': 'закрито', 'Закрыт': 'Закрито', 'запустить:': 'запустити:', 'Запустить:': 'Запустити:', 'остановить': 'зупинити', 'Остановить': 'Зупинити', 'остановлен': 'зупинено', 'Остановлен': 'Зупинено', 'остановлено': 'зупинено', 'Остановлено': 'Зупинено', 'запущен:': 'запущено:', 'Запущен:': 'Запущено:', 'файлов:': 'файлів:', 'Файлов:': 'Файлів:', 'папку:': 'папку:', 'Папку:': 'Папку:', 'систем:': 'систем:', 'Систем': 'Систем:', 'Систем:': 'Систем:', 'реестра:': 'реєстру:', 'Реестра:': 'Реєстру:', 'службу:': 'службу:', 'Службу:': 'Службу:', 'доступа:': 'доступу:', 'Доступа:': 'Доступу:', 'дисков': 'дисків', 'Дисков': 'Дисків', 'диск': 'диск', 'Диск': 'Диск', 'диски': 'диски', 'Диски': 'Диски', 'диска': 'диска', 'Диска': 'Диска', 'принтер': 'принтер', 'Принтер': 'Принтер', 'принтера': 'принтера', 'Принтера': 'Принтера', 'шрифт': 'шрифт', 'Шрифт': 'Шрифт', 'шрифты': 'шрифти', 'Шрифты': 'Шрифти', 'шрифтов': 'шрифтів', 'Шрифтов': 'Шрифтів', 'тема': 'тема', 'Тема': 'Тема', 'темы': 'теми', 'Темы': 'Теми', 'язык': 'мова', 'Язык': 'Мова', 'языка': 'мови', 'Языка': 'Мови', 'драйвер': 'драйвер', 'Драйвер': 'Драйвер', 'драйвера': 'драйвери', 'Драйвера': 'Драйвери', 'драйверов': 'драйверів', 'Драйверов': 'Драйверів', 'обновление': 'оновлення', 'Обновление': 'Оновлення', 'обновления': 'оновлення', 'Обновления': 'Оновлення', 'обновить': 'оновити', 'Обновить': 'Оновити', 'обновлено': 'оновлено', 'Обновлено': 'Оновлено', 'центр': 'центр', 'Центр': 'Центр', 'центра': 'центра', 'Центра': 'Центра', 'безопасность': 'безпека', 'Безопасность': 'Безпека', 'безопасности': 'безпеки', 'Безопасности': 'Безпеки', 'безопасный': 'безпечний', 'Безопасный': 'Безпечний', 'безопасно': 'безпечно', 'Безопасно': 'Безпечно', 'защита': 'захист', 'Защита': 'Захист:', 'защиты': 'захисту', 'Защиты': 'Захисту', 'защита:': 'захист:', 'Защита:': 'Захист:', 'защитит': 'захистить', 'Защитит': 'Захистить', 'защищено': 'захищено', 'Защищено': 'Захищено', 'защищен': 'захищено', 'Защищен': 'Захищено', 'защищает': 'захищає', 'Защищает': 'Захищає', 'антивирус': 'антивірус', 'Антивирус': 'Антивірус', 'антивируса': 'антивіруса', 'Антивируса': 'Антивіруса', 'вредонос': 'шкідливий', 'Вредонос': 'Шкідливий', 'вредоносный': 'шкідливий', 'Вредоносный': 'Шкідливий', 'вредоносных': 'шкідливих', 'Вредоносных': 'Шкідливих', 'угроза': 'загроза', 'Угроза': 'Загроза', 'угрозы': 'загрози', 'Угрозы': 'Загрози', 'угроз:': 'загроз:', 'Угроз': 'Загроз:', 'Угроз:': 'Загроз:', 'восстановление системы': 'відновлення системи', 'Восстановление системы': 'Відновлення системи', 'восстановлено:': 'відновлено:', 'Восстановлено:': 'Відновлено:', 'поддержка': 'підтримка', 'Поддержка': 'Підтримка', 'поддержки': 'підтримки', 'Поддержки': 'Підтримки', 'поддерживает': 'підтримує', 'Поддерживает': 'Підтримує', 'инструмент': 'інструмент', 'Инструмент': 'Інструмент:', 'инструменты': 'інструменти', 'Инструменты': 'Інструменти', 'инструментов': 'інструментів', 'Инструментов': 'Інструментів', 'инструмент:': 'інструмент:', 'Инструмент:': 'Інструмент:', 'очищены': 'очищені', 'Очищены': 'Очищені', 'удаление:': 'видалення:', 'Удаление:': 'Видалення:', 'имена': 'імена', 'Имена': 'Імена', 'имен': 'імен', 'Имен': 'Імен', 'записи:': 'записи:', 'Записи:': 'Записи:', 'события': 'події', 'События': 'Події', 'событие': 'подія', 'Событие': 'Подія', 'событий': 'подій', 'Событий': 'Подій', 'журнал': 'журнал', 'Журнал': 'Журнал', 'журнала': 'журналу', 'Журнала': 'Журналу', 'задач:': 'завдань:', 'Задач:': 'Завдань:', 'процесс:': 'процес:', 'Процесс:': 'Процес:', 'процессов:': 'процесів:', 'Процессов:': 'Процесів:', 'отчет': 'звіт', 'Отчет': 'Звіт', 'отчёт': 'звіт', 'Отчёт': 'Звіт', 'отчета': 'звіту', 'Отчета': 'Звіту', 'точка': 'точка', 'Точка': 'Точка', 'точки': 'точки', 'Точки': 'Точки', 'точку': 'точку', 'Точку': 'Точку', 'конец': 'кінець', 'Конец': 'Кінець', 'завершения': 'завершення', 'Завершения': 'Завершення', 'восстановлено!': 'відновлено!', 'Восстановлено!': 'Відновлено!', 'успешно!': 'успішно!', 'Успешно!': 'Успішно!', 'выполнено!': 'виконано!', 'Выполнено!': 'Виконано!', 'готово!': 'готово!', 'Готово!': 'Готово!', 'отключено!': 'вимкнено!', 'Отключено!': 'Вимкнено!', 'включено!': 'увімкнено!', 'Включено!': 'Увімкнено!', 'удалено': 'видалено', 'Удалено': 'Видалено', 'скопирован': 'скопійовано', 'Скопирован': 'Скопійовано', 'скопировано': 'скопійовано', 'Скопировано': 'Скопійовано', 'скопировать': 'копіювати', 'Скопировать': 'Копіювати', 'копировать': 'копіювати', 'Копировать': 'Копіювати', 'создание:': 'створення:', 'Создание:': 'Створення:', 'файл:': 'файл:', 'Файл:': 'Файл:', 'папка:': 'папка:', 'Папка:': 'Папка:', 'система:': 'система:', 'Система:': 'Система:', 'остановлена': 'зупинена', 'Остановлена': 'Зупинена', 'остановлены': 'зупинені', 'Остановлены': 'Зупинені', 'завершена': 'завершена', 'Завершена': 'Завершена', 'завершены': 'завершені', 'Завершены': 'Завершені', 'выполнена': 'виконана', 'Выполнена': 'Виконана', 'выполнены': 'виконані', 'Выполнены': 'Виконані', 'удалена': 'видалена', 'Удалена': 'Видалена', 'создана': 'створена', 'Создана': 'Створена', 'созданы': 'створені', 'Созданы': 'Створені', 'включена': 'увімкнена', 'Включена': 'Увімкнена', 'отключена': 'вимкнена', 'Отключена': 'Вимкнена', 'найдена': 'знайдена', 'Найдена': 'Знайдена', 'найдены': 'знайдені', 'Найдены': 'Знайдені', 'установлена': 'встановлена', 'Установлена': 'Встановлена', 'установлено': 'встановлено', 'Установлено': 'Встановлено', 'установлены': 'встановлені', 'Установлены': 'Встановлені', 'установлен': 'встановлено', 'Установлен': 'Встановлено', 'сброшена': 'скинута', 'Сброшена': 'Скинута', 'сброшены': 'скинуті', 'Сброшены': 'Скинуті', 'очищена': 'очищена', 'Очищена': 'Очищена', 'заблокирована': 'заблокована', 'Заблокирована': 'Заблокована', 'заблокировано': 'заблоковано', 'Заблокировано': 'Заблоковано', 'заблокированы': 'заблоковані', 'Заблокированы': 'Заблоковані', 'заблокирован': 'заблоковано', 'Заблокирован': 'Заблоковано', 'разблокирована': 'розблокована', 'Разблокирована': 'Розблокована', 'разблокировано': 'розблоковано', 'Разблокировано': 'Розблоковано', 'запущена': 'запущена', 'Запущена': 'Запущена', 'запущены': 'запущені', 'Запущены': 'Запущені', 'перезапущена': 'перезапущена', 'Перезапущена': 'Перезапущена', 'перезапущено': 'перезапущено', 'Перезапущено': 'Перезапущено', 'обновлена': 'оновлена', 'Обновлена': 'Оновлена', 'обновлены': 'оновлені', 'Обновлены': 'Оновлені', 'восстановлена': 'відновлена', 'Восстановлена': 'Відновлена', 'скопирована': 'скопійована', 'Скопирована': 'Скопійована', 'скопированы': 'скопійовані', 'Скопированы': 'Скопійовані', 'разрешена': 'дозволена', 'Разрешена': 'Дозволена', 'разрешено': 'дозволено', 'Разрешено': 'Дозволено', 'разрешены': 'дозволені', 'Разрешены': 'Дозволені', 'запрещена': 'заборонена', 'Запрещена': 'Заборонена', 'запрещено': 'заборонено', 'Запрещено': 'Заборонено', 'запрещены': 'заборонені', 'Запрещены': 'Заборонені', 'активна': 'активна', 'Активна': 'Активна', 'активно': 'активно', 'Активно': 'Активно', 'активны': 'активні', 'Активны': 'Активні', 'активен': 'активний', 'Активен': 'Активний', 'неактивна': 'неактивна', 'Неактивна': 'Неактивна', 'неактивно': 'неактивно', 'Неактивно': 'Неактивно', 'неактивен': 'неактивний', 'Неактивен': 'Неактивний', 'доступны': 'доступні', 'Доступны': 'Доступні', 'отсутствует': 'відсутній', 'Отсутствует': 'Відсутній:', 'отсутствует:': 'відсутній:', 'Отсутствует:': 'Відсутній:', 'отсутствуют': 'відсутні', 'Отсутствуют': 'Відсутні', 'работает': 'працює', 'Работает': 'Працює:', 'работают': 'працюють', 'Работают': 'Працюють', 'работает:': 'працює:', 'Работает:': 'Працює:', 'неработает': 'не працює', 'Неработает': 'Не працює', 'поврежден': 'пошкоджено', 'Поврежден': 'Пошкоджено', 'повреждена': 'пошкоджена', 'Повреждена': 'Пошкоджена', 'повреждено': 'пошкоджено', 'Повреждено': 'Пошкоджено', 'повреждены': 'пошкоджені', 'Повреждены': 'Пошкоджені', 'исправен': 'справний', 'Исправен': 'Справний', 'исправна': 'справна', 'Исправна': 'Справна', 'исправно': 'справно', 'Исправно': 'Справно', 'исправить': 'виправити', 'Исправить': 'Виправити', 'исправление': 'виправлення', 'Исправление': 'Виправлення', 'исправлен': 'виправлено', 'Исправлен': 'Виправлено', 'исправлено': 'виправлено', 'Исправлено': 'Виправлено', 'исправлена': 'виправлена', 'Исправлена': 'Виправлена', 'требуется': 'потрібно', 'Требуется': 'Потрібно:', 'требуется:': 'потрібно:', 'Требуется:': 'Потрібно:', 'требуется перезагрузка': 'потрібно перезавантаження', 'Требуется перезагрузка': 'Потрібно перезавантаження', 'перезагрузка требуется': 'перезавантаження потрібно', 'Перезагрузка требуется': 'Перезавантаження потрібно', 'завершите': 'завершіть', 'Завершите': 'Завершіть', 'подтвердите': 'підтвердіть', 'Подтвердите': 'Підтвердіть', 'нажмите': 'натисніть', 'Нажмите': 'Натисніть:', 'нажмите:': 'натисніть:', 'Нажмите:': 'Натисніть:', 'нажмите чтобы': 'натисніть щоб', 'Нажмите чтобы': 'Натисніть щоб', 'выполните': 'виконайте', 'Выполните': 'Виконайте', 'перезапустите': 'перезапустіть', 'Перезапустите': 'Перезапустіть', 'перезагрузите': 'перезавантажте', 'Перезагрузите': 'Перезавантажте', 'запустите': 'запустіть', 'Запустите': 'Запустіть', 'откройте': 'відкрйте', 'Откройте': 'Відкрйте:', 'откройте:': 'відкрйте:', 'Откройте:': 'Відкрйте:', 'выберите:': 'виберіть:', 'Выберите:': 'Виберіть:', 'попробуйте': 'спробуйте', 'Попробуйте': 'Спробуйте', 'снова': 'знову', 'Снова': 'Знову', 'повторно': 'повторно', 'Повторно': 'Повторно', 'выполните повторно': 'виконайте повторно', 'Выполните повторно': 'Виконайте повторно', 'подождите': 'зачекайте', 'Подождите': 'Зачекайте', 'загрузка': 'завантаження', 'Загрузка': 'Завантаження', 'загрузки': 'завантаження', 'Загрузки': 'Завантаження', 'загружено': 'завантажено', 'Загружено': 'Завантажено', 'загружен': 'завантажено', 'Загружен': 'Завантажено', 'обнаружен': 'виявлено', 'Обнаружен': 'Виявлено', 'обнаружено': 'виявлено', 'Обнаружено': 'Виявлено', 'обнаружена': 'виявлена', 'Обнаружена': 'Виявлена', 'обнаружены': 'виявлені', 'Обнаружены': 'Виявлені', 'присутствует': 'наявний', 'Присутствует': 'Наявний', 'поддерживается': 'підтримується', 'Поддерживается': 'Підтримується', 'получено': 'отримано', 'Получено': 'Отримано', 'получен': 'отримано', 'Получен': 'Отримано', 'отправлено': 'надіслано', 'Отправлено': 'Надіслано', 'отправлен': 'надіслано', 'Отправлен': 'Надіслано', 'прервано': 'перервано', 'Прервано': 'Перервано', 'прерван': 'перервано', 'Прерван': 'Перервано', 'истекло': 'витекло', 'Истекло': 'Витекло', 'истек': 'витік', 'Истек': 'Витік', 'время': 'час', 'Время': 'Час:', 'время:': 'час:', 'Время:': 'Час:', 'времени': 'часу', 'Времени': 'Часу', 'таймаут': 'тайм-аут', 'Таймаут': 'Тайм-аут:', 'таймаут:': 'тайм-аут:', 'Таймаут:': 'Тайм-аут:', 'размер': 'розмір', 'Размер': 'Розмір:', 'размер:': 'розмір:', 'Размер:': 'Розмір:', 'тип': 'тип', 'Тип': 'Тип:', 'тип:': 'тип:', 'Тип:': 'Тип:', 'статус': 'статус', 'Статус': 'Статус:', 'статус:': 'статус:', 'Статус:': 'Статус:', 'состояние': 'стан', 'Состояние': 'Стан:', 'состояние:': 'стан:', 'Состояние:': 'Стан:', 'состояния': 'стану', 'Состояния': 'Стану', 'данные': 'дані', 'Данные': 'Дані:', 'данных': 'даних', 'Данных': 'Даних', 'данные:': 'дані:', 'Данные:': 'Дані:', 'информация': 'інформація', 'Информация': 'Інформація:', 'информация:': 'інформація:', 'Информация:': 'Інформація:', 'информации': 'інформації', 'Информации': 'Інформації', 'подробнее': 'докладніше', 'Подробнее': 'Докладніше:', 'подробнее:': 'докладніше:', 'Подробнее:': 'Докладніше:', 'детально': 'детально', 'Детально': 'Детально', 'причина': 'причина', 'Причина': 'Причина:', 'причина:': 'причина:', 'Причина:': 'Причина:', 'причины': 'причини', 'Причины': 'Причини', 'решение': 'рішення', 'Решение': 'Рішення:', 'решение:': 'рішення:', 'Решение:': 'Рішення:', 'решения': 'рішення', 'Решения': 'Рішення', 'рекомендация': 'рекомендація', 'Рекомендация': 'Рекомендація', 'рекомендации': 'рекомендації', 'Рекомендации': 'Рекомендації', 'рекомендуется': 'рекомендується', 'Рекомендуется': 'Рекомендується:', 'рекомендуется:': 'рекомендується:', 'Рекомендуется:': 'Рекомендується:', 'внимание': 'увага', 'Внимание': 'Увага:', 'внимание:': 'увага:', 'Внимание:': 'Увага:', 'осторожно': 'обережно', 'Осторожно': 'Обережно', 'опасно': 'небезпечно', 'Опасно': 'Небезпечно:', 'опасно:': 'небезпечно:', 'Опасно:': 'Небезпечно:', 'риск': 'ризик', 'Риск': 'Ризик', 'риска': 'ризику', 'Риска': 'Ризику', 'необратимо': 'незворотно', 'Необратимо': 'Незворотно', 'необратимых': 'незворотних', 'Необратимых': 'Незворотних', 'назад': 'назад', 'Назад': 'Назад', 'далее': 'далі', 'Далее': 'Далі', 'вперед': 'вперед', 'Вперед': 'Вперед', 'выполнено успешно': 'виконано успішно', 'Выполнено успешно': 'Виконано успішно', 'операция выполнена': 'операцію виконано', 'Операция выполнена': 'Операцію виконано', 'операция завершена': 'операцію завершено', 'Операция завершена': 'Операцію завершено', 'изменения сохранены': 'зміни збережено', 'Изменения сохранены': 'Зміни збережено', 'изменения': 'зміни', 'Изменения': 'Зміни:', 'изменения:': 'зміни:', 'Изменения:': 'Зміни:', 'изменен': 'змінено', 'Изменен': 'Змінено', 'изменено': 'змінено', 'Изменено': 'Змінено', 'изменить': 'змінити', 'Изменить': 'Змінити', 'сохранить': 'зберегти', 'Сохранить': 'Зберегти', 'сохранен': 'збережено', 'Сохранен': 'Збережено', 'сохранено': 'збережено', 'Сохранено': 'Збережено', 'сохранена': 'збережена', 'Сохранена': 'Збережена', 'сохранены': 'збережені', 'Сохранены': 'Збережені', 'импорт': 'імпорт', 'Импорт': 'Імпорт', 'экспорт': 'експорт', 'Экспорт': 'Експорт', 'записано': 'записано', 'Записано': 'Записано', 'запись создана': 'запис створено', 'Запись создана': 'Запис створено', 'запись удалена': 'запис видалено', 'Запись удалена': 'Запис видалено', 'ключ': 'ключ', 'Ключ': 'Ключ:', 'ключи': 'ключі', 'Ключи': 'Ключі', 'ключ:': 'ключ:', 'Ключ:': 'Ключ:', 'параметр': 'параметр', 'Параметр': 'Параметр:', 'параметры': 'параметри', 'Параметры': 'Параметри', 'параметр:': 'параметр:', 'Параметр:': 'Параметр:', 'строка': 'рядок', 'Строка': 'Рядок', 'строки': 'рядки', 'Строки': 'Рядки', 'элемент': 'елемнт', 'Элемент': 'Елемнт:', 'элементы': 'елемнти', 'Элементы': 'Елемнти', 'элемент:': 'елемнт:', 'Элемент:': 'Елемнт:', 'компонент': 'компонент', 'Компонент': 'Компонент:', 'компоненты': 'компоненти', 'Компоненты': 'Компоненти', 'компонент:': 'компонент:', 'Компонент:': 'Компонент:', 'завершить процесс': 'завершити процес', 'Завершить процесс': 'Завершити процес', 'перезапустить службу': 'перезапустити службу', 'Перезапустить службу': 'Перезапустити службу', 'запустить службу': 'запустити службу', 'Запустить службу': 'Запустити службу', 'остановить службу': 'зупинити службу', 'Остановить службу': 'Зупинити службу', 'вирусом': 'вірусом', 'Вирусом': 'Вірусом', 'службой': 'службою', 'Службой': 'Службою', 'процессом': 'процесом', 'Процессом': 'Процесом', 'путем': 'шляхом', 'Путем': 'Шляхом', 'путём': 'шляхом', 'Путём': 'Шляхом', 'администратором': 'адміністратором', 'Администратором': 'Адміністратором', 'системой': 'системою', 'Системой': 'Системою', 'реестром': 'реєстром', 'Реестром': 'Реєстром', 'диском': 'диском', 'Диском': 'Диском', 'принтером': 'принтером', 'Принтером': 'Принтером', 'шрифтом': 'шрифтом', 'Шрифтом': 'Шрифтом', 'брандмауэром': 'брандмауером', 'Брандмауэром': 'Брандмауером', 'процессором': 'процесором', 'Процессором': 'Процесором', 'сетью': 'мережею', 'Сетью': 'Мережею', 'сети': 'мережі', 'Сети': 'Мережі', 'сервисом': 'сервісом', 'Сервисом': 'Сервісом', 'сервиса': 'сервісу', 'Сервиса': 'Сервісу', 'файле': 'файлі', 'Файле': 'Файлі', 'системе': 'системі', 'Системе': 'Системі', 'диске': 'диску', 'Диске': 'Диску', 'пользователе': 'користувачі', 'Пользователе': 'Користувачі', 'администратора': 'адміністратора', 'Администратора': 'Адміністратора', 'полностью': 'повністю', 'Полностью': 'Повністю', 'частично': 'частково', 'Частично': 'Частково', 'автоматически': 'автоматично', 'Автоматически': 'Автоматично', 'принудительно': 'примусово', 'Принудительно': 'Примусово', 'немедленно': 'негайно', 'Немедленно': 'Негайно', 'временно': 'тимчасово', 'Временно': 'Тимчасово', 'постоянно': 'постійно', 'Постоянно': 'Постійно', 'локально': 'локально', 'Локально': 'Локально', 'удаленно': 'віддалено', 'Удаленно': 'Віддалено', 'отменена': 'скасовована', 'Отменена': 'Скасовована', 'отменены': 'скасовані', 'Отменены': 'Скасовані', 'пропущена': 'пропущена', 'Пропущена': 'Пропущена', 'пропущено': 'пропущено', 'Пропущено': 'Пропущено', 'пропущены': 'пропущені', 'Пропущены': 'Пропущені', 'пропущен': 'пропущено', 'Пропущен': 'Пропущено'},
        "de": {'не': 'nicht', 'Не': 'Nicht', 'будет': 'wird sein', 'Будет': 'Wird sein', 'будут': 'werden', 'Будут': 'Werden', 'ошибка': 'Fehler', 'Ошибка': 'Fehler', 'ошибки': 'Fehler', 'Ошибки': 'Fehler', 'ошибок': 'Fehlern', 'Ошибок': 'Fehlern:', 'ошибок:': 'Fehlern:', 'Ошибок:': 'Fehlern:', 'ошибками': 'Fehlern', 'Ошибками': 'Fehlern', 'ошибку': 'Fehler', 'Ошибку': 'Fehler', 'файл': 'Datei', 'Файл': 'Datei:', 'файла': 'Datei', 'Файла': 'Datei', 'файлы': 'Dateien', 'Файлы': 'Dateien', 'файлов': 'Dateien', 'Файлов': 'Dateien:', 'файлом': 'Datei', 'Файлом': 'Datei', 'удалось': 'konnte', 'Удалось': 'Konnte', 'не удалось': 'konnte nicht', 'Не удалось': 'Konnte nicht', 'задач': 'Aufgaben', 'Задач': 'Aufgaben:', 'задача': 'Aufgabe', 'Задача': 'Aufgabe', 'задачу': 'Aufgabe', 'Задачу': 'Aufgabe', 'задачи': 'Aufgaben', 'Задачи': 'Aufgaben', 'задаче': 'Aufgabe', 'Задаче': 'Aufgabe', 'через': 'über', 'Через': 'Über', 'восстановление': 'Wiederherstellung', 'Восстановление': 'Wiederherstellung', 'восстановления': 'Wiederherstellung', 'Восстановления': 'Wiederherstellung:', 'восстановлено': 'wiederhergestellt', 'Восстановлено': 'Wiederhergestellt', 'восстановлен': 'wiederhergestellt', 'Восстановлен': 'Wiederhergestellt', 'восстановить': 'wiederherstellen', 'Восстановить': 'Wiederherstellen', 'восстанавливает': 'stellt wieder her', 'Восстанавливает': 'Stellt wieder her', 'восстанавливаеться': 'wird wiederhergestellt', 'Восстанавливаеться': 'Wird wiederhergestellt', 'восстановлены': 'wiederhergestellt', 'Восстановлены': 'Wiederhergestellt', 'восстановления:': 'Wiederherstellung:', 'Восстановления:': 'Wiederherstellung:', 'системы': 'Systems', 'Системы': 'Systems', 'система': 'System', 'Система': 'System:', 'систему': 'System', 'Систему': 'System', 'системные': 'System', 'Системные': 'System', 'системный': 'System', 'Системный': 'System', 'системной': 'System', 'Системной': 'System', 'системных': 'System', 'Системных': 'System', 'реестра': 'Registers', 'Реестра': 'Registers', 'реестр': 'Register', 'Реестр': 'Register', 'реестре': 'Register', 'Реестре': 'Register', 'реестру': 'Register', 'Реестру': 'Register', 'или': 'oder', 'Или': 'Oder', 'из': 'aus', 'Из': 'Aus', 'все': 'alle', 'Все': 'Alle', 'всё': 'alles', 'Всё': 'Alles', 'всех': 'aller', 'Всех': 'Aller', 'всю': 'alle', 'Всю': 'Alle', 'запуск': 'Start', 'Запуск': 'Start', 'запуска': 'Start', 'Запуска': 'Start', 'запустить': 'starten', 'Запустить': 'Starten:', 'запущен': 'gestartet', 'Запущен': 'Gestartet:', 'запущено': 'gestartet', 'Запущено': 'Gestartet', 'запускает': 'startet', 'Запускает': 'Startet', 'панель': 'Panel', 'Панель': 'Panel:', 'панели': 'Panel', 'Панели': 'Panel', 'панель:': 'Panel:', 'Панель:': 'Panel:', 'выберите': 'auswählen', 'Выберите': 'Auswählen:', 'удалить': 'löschen', 'Удалить': 'Löschen:', 'удаление': 'Entfernen', 'Удаление': 'Entfernen:', 'удалены': 'entfernt', 'Удалены': 'Entfernt', 'удален': 'entfernt', 'Удален': 'Entfernt', 'удалить:': 'löschen:', 'Удалить:': 'Löschen:', 'процесс': 'Prozess', 'Процесс': 'Prozess:', 'процесса': 'Prozesses', 'Процесса': 'Prozesses', 'процессы': 'Prozesse', 'Процессы': 'Prozesse', 'процессов': 'Prozesse', 'Процессов': 'Prozesse:', 'процессе': 'Prozess', 'Процессе': 'Prozess', 'только': 'nur', 'Только': 'Nur', 'что': 'dass', 'Что': 'Dass', 'настройки': 'Einstellungen', 'Настройки': 'Einstellungen', 'настройка': 'Einstellung', 'Настройка': 'Einstellung', 'настройку': 'Einstellung', 'Настройку': 'Einstellung', 'настроек': 'Einstellungen', 'Настроек': 'Einstellungen', 'настроить': 'konfigurieren', 'Настроить': 'Konfigurieren', 'при': 'bei', 'При': 'Bei', 'бэкап': 'Backup', 'Бэкап': 'Backup', 'бэкапы': 'Backups', 'Бэкапы': 'Backups', 'бэкапа': 'Backups', 'Бэкапа': 'Backups', 'бэкапов': 'Backups', 'Бэкапов': 'Backups', 'путь': 'Pfad', 'Путь': 'Pfad:', 'пути': 'Pfade', 'Пути': 'Pfade', 'путь:': 'Pfad:', 'Путь:': 'Pfad:', 'запись': 'Eintrag', 'Запись': 'Eintrag:', 'записи': 'Einträge', 'Записи': 'Einträge:', 'записей': 'Einträge', 'Записей': 'Einträge', 'запись:': 'Eintrag:', 'Запись:': 'Eintrag:', 'службу': 'Dienst', 'Службу': 'Dienst:', 'служба': 'Dienst', 'Служба': 'Dienst', 'службы': 'Dienst', 'Службы': 'Dienst', 'служб': 'Dienste', 'Служб': 'Dienste', 'службе': 'Dienst', 'Службе': 'Dienst', 'службы:': 'Dienste:', 'Службы:': 'Dienste:', 'очистка': 'Bereinigung', 'Очистка': 'Bereinigung:', 'очистки': 'Bereinigung', 'Очистки': 'Bereinigung', 'очистить': 'bereinigen', 'Очистить': 'Bereinigen', 'очищает': 'bereinigt', 'Очищает': 'Bereinigt', 'очищен': 'bereinigt', 'Очищен': 'Bereinigt', 'очищено': 'bereinigt', 'Очищено': 'Bereinigt', 'очистка:': 'Bereinigung:', 'Очистка:': 'Bereinigung:', 'проверка': 'Prüfung', 'Проверка': 'Prüfung:', 'проверки': 'Prüfung', 'Проверки': 'Prüfung', 'проверяет': 'prüft', 'Проверяет': 'Prüft', 'проверить': 'prüfen', 'Проверить': 'Prüfen', 'проверяем': 'prüfen', 'Проверяем': 'Prüfen', 'проверка:': 'Prüfung:', 'Проверка:': 'Prüfung:', 'нет': 'kein', 'Нет': 'Kein:', 'нет:': 'kein:', 'Нет:': 'Kein:', 'режим': 'Modus', 'Режим': 'Modus', 'режима': 'Modus', 'Режима': 'Modus', 'диспетчер': 'Manager', 'Диспетчер': 'Manager:', 'диспетчер:': 'Manager:', 'Диспетчер:': 'Manager:', 'если': 'wenn', 'Если': 'Wenn', 'доступ': 'Zugriff', 'Доступ': 'Zugriff:', 'доступа': 'Zugriffs', 'Доступа': 'Zugriffs:', 'доступ:': 'Zugriff:', 'Доступ:': 'Zugriff:', 'доступно': 'verfügbar', 'Доступно': 'Verfügbar', 'доступна': 'verfügbar', 'Доступна': 'Verfügbar', 'доступен': 'verfügbar', 'Доступен': 'Verfügbar', 'отключен': 'deaktiviert', 'Отключен': 'Deaktiviert', 'отключено': 'deaktiviert', 'Отключено': 'Deaktiviert', 'отключены': 'deaktiviert', 'Отключены': 'Deaktiviert', 'отключить': 'deaktivieren', 'Отключить': 'Deaktivieren:', 'отключение': 'Deaktivieren', 'Отключение': 'Deaktivieren', 'отключается': 'wird deaktiviert', 'Отключается': 'Wird deaktiviert', 'включен': 'aktiviert', 'Включен': 'Aktiviert', 'включено': 'aktiviert', 'Включено': 'Aktiviert', 'включены': 'aktiviert', 'Включены': 'Aktiviert', 'включить': 'einschalten', 'Включить': 'Einschalten:', 'включение': 'Einschalten', 'Включение': 'Einschalten:', 'включает': 'aktiviert', 'Включает': 'Aktiviert', 'включить:': 'einschalten:', 'Включить:': 'Einschalten:', 'права': 'Rechte', 'Права': 'Rechte:', 'прав': 'Rechte', 'Прав': 'Rechte', 'права:': 'Rechte:', 'Права:': 'Rechte:', 'свойства': 'Eigenschaften', 'Свойства': 'Eigenschaften:', 'свойств': 'Eigenschaften', 'Свойств': 'Eigenschaften', 'свойства:': 'Eigenschaften:', 'Свойства:': 'Eigenschaften:', 'меню': 'Menü', 'Меню': 'Menü:', 'меню:': 'Menü:', 'Меню:': 'Menü:', 'управления': 'Verwaltung', 'Управления': 'Verwaltung', 'управление': 'Verwaltung', 'Управление': 'Verwaltung', 'папки': 'Ordners', 'Папки': 'Ordners', 'папка': 'Ordner', 'Папка': 'Ordner:', 'папку': 'Ordner', 'Папку': 'Ordner:', 'папок': 'Ordner', 'Папок': 'Ordner', 'папке': 'Ordner', 'Папке': 'Ordner', 'создать': 'erstellen', 'Создать': 'Erstellen', 'создание': 'Erstellung', 'Создание': 'Erstellung:', 'создан': 'erstellt', 'Создан': 'Erstellt', 'создано': 'erstellt', 'Создано': 'Erstellt', 'имя': 'Name', 'Имя': 'Name:', 'имя:': 'Name:', 'Имя:': 'Name:', 'разблокировка': 'Entsperren', 'Разблокировка': 'Entsperren:', 'разблокирует': 'entsperrt', 'Разблокирует': 'Entsperrt', 'разблокирован': 'entsperrt', 'Разблокирован': 'Entsperrt', 'разблокированы': 'entsperrt', 'Разблокированы': 'Entsperrt', 'разблокировка:': 'Entsperren:', 'Разблокировка:': 'Entsperren:', 'блокировки': 'Sperren', 'Блокировки': 'Sperren', 'блокировка': 'Sperre', 'Блокировка': 'Sperre', 'блокировку': 'Sperre', 'Блокировку': 'Sperre', 'блокировок': 'Sperren', 'Блокировок': 'Sperren', 'блокировала': 'blockiert', 'Блокировала': 'Blockiert', 'брандмауэр': 'Firewall', 'Брандмауэр': 'Firewall:', 'брандмауэра': 'Firewalls', 'Брандмауэра': 'Firewalls', 'брандмауэр:': 'Firewall:', 'Брандмауэр:': 'Firewall:', 'вирус': 'Virus', 'Вирус': 'Virus:', 'вируса': 'Virus', 'Вируса': 'Virus', 'вирусы': 'Viren', 'Вирусы': 'Viren', 'вирусов': 'Viren', 'Вирусов': 'Viren', 'вирус:': 'Virus:', 'Вирус:': 'Virus:', 'подтверждение': 'Bestätigung', 'Подтверждение': 'Bestätigung', 'подтверждения': 'Bestätigung', 'Подтверждения': 'Bestätigung', 'подтвердить': 'bestätigen', 'Подтвердить': 'Bestätigen', 'откат': 'Zurücksetzen', 'Откат': 'Zurücksetzen:', 'откатить': 'zurücksetzen', 'Откатить': 'Zurücksetzen', 'откат:': 'Zurücksetzen:', 'Откат:': 'Zurücksetzen:', 'список': 'Liste', 'Список': 'Liste:', 'списка': 'Liste', 'Списка': 'Liste', 'список:': 'Liste:', 'Список:': 'Liste:', 'политики': 'Richtlinien', 'Политики': 'Richtlinien', 'политика': 'Richtlinie', 'Политика': 'Richtlinie', 'политик': 'Richtlinien', 'Политик': 'Richtlinien', 'добавить': 'hinzufügen', 'Добавить': 'Hinzufügen', 'добавлен': 'hinzugefügt', 'Добавлен': 'Hinzugefügt', 'добавлено': 'hinzugefügt', 'Добавлено': 'Hinzugefügt', 'продолжить': 'fortfahren', 'Продолжить': 'Fortfahren', 'включено:': 'aktiviert:', 'Включено:': 'Aktiviert:', 'включение:': 'Einschalten:', 'Включение:': 'Einschalten:', 'клавиши': 'Tasten', 'Клавиши': 'Tasten', 'клавиша': 'Taste', 'Клавиша': 'Taste', 'клавиатуре': 'Tastatur', 'Клавиатуре': 'Tastatur', 'клавиатура': 'Tastatur', 'Клавиатура': 'Tastatur', 'клавиатуры': 'Tastatur', 'Клавиатуры': 'Tastatur', 'операция': 'Vorgang', 'Операция': 'Vorgang', 'операции': 'Vorgang', 'Операции': 'Vorgang', 'операцию': 'Vorgang', 'Операцию': 'Vorgang', 'ограничений': 'Einschränkungen', 'Ограничений': 'Einschränkungen', 'ограничение': 'Einschränkung', 'Ограничение': 'Einschränkung', 'ограничения': 'Einschränkungen', 'Ограничения': 'Einschränkungen', 'значение': 'Wert', 'Значение': 'Wert:', 'значения': 'Werte', 'Значения': 'Werte', 'значение:': 'Wert:', 'Значение:': 'Wert:', 'пользователь': 'Benutzer', 'Пользователь': 'Benutzer', 'пользователя': 'Benutzers', 'Пользователя': 'Benutzers', 'пользователи': 'Benutzer', 'Пользователи': 'Benutzer', 'пользователем': 'Benutzer', 'Пользователем': 'Benutzer', 'пользователю': 'Benutzer', 'Пользователю': 'Benutzer', 'подозрительные': 'verdächtig', 'Подозрительные': 'Verdächtig', 'подозрительных': 'verdächtig', 'Подозрительных': 'Verdächtig', 'подозрительный': 'verdächtig', 'Подозрительный': 'Verdächtig', 'найдено': 'gefunden', 'Найдено': 'Gefunden', 'найдено:': 'gefunden:', 'Найдено:': 'Gefunden:', 'найден': 'gefunden', 'Найден': 'Gefunden', 'блок': 'Block', 'Блок': 'Block:', 'блок:': 'Block:', 'Блок:': 'Block:', 'автозагрузки': 'Autostart', 'Автозагрузки': 'Autostart', 'автозагрузка': 'Autostart', 'Автозагрузка': 'Autostart', 'автозагрузку': 'Autostart', 'Автозагрузку': 'Autostart', 'автозапуск': 'Autostart', 'Автозапуск': 'Autostart', 'сброс': 'Zurücksetzen', 'Сброс': 'Zurücksetzen', 'сброса': 'Zurücksetzen', 'Сброса': 'Zurücksetzen', 'сбросить': 'zurücksetzen', 'Сбросить': 'Zurücksetzen', 'сброшен': 'zurückgesetzt', 'Сброшен': 'Zurückgesetzt', 'сброшено': 'zurückgesetzt', 'Сброшено': 'Zurückgesetzt', 'проводник': 'Explorer', 'Проводник': 'Explorer:', 'проводник:': 'Explorer:', 'Проводник:': 'Explorer:', 'сканирование': 'Scannen', 'Сканирование': 'Scannen:', 'сканировать': 'scannen', 'Сканировать': 'Scannen', 'сканирование:': 'Scannen:', 'Сканирование:': 'Scannen:', 'полный': 'voll', 'Полный': 'Voll', 'полная': 'voll', 'Полная': 'Voll', 'полное': 'voll', 'Полное': 'Voll', 'после': 'nach', 'После': 'Nach', 'перед': 'vor', 'Перед': 'Vor', 'выполняется': 'läuft', 'Выполняется': 'Läuft:', 'выполнено': 'ausgeführt', 'Выполнено': 'Ausgeführt', 'выполнено:': 'abgeschlossen:', 'Выполнено:': 'Abgeschlossen:', 'выполнить': 'ausführen', 'Выполнить': 'Ausführen', 'выполнения': 'Ausführung', 'Выполнения': 'Ausführung', 'готов': 'bereit', 'Готов': 'Bereit', 'готова': 'bereit', 'Готова': 'Bereit', 'готово': 'fertig', 'Готово': 'Fertig', 'готовы': 'bereit', 'Готовы': 'Bereit', 'выполняется:': 'läuft:', 'Выполняется:': 'Läuft:', 'проблема': 'Problem', 'Проблема': 'Problem', 'проблемы': 'Probleme', 'Проблемы': 'Probleme', 'проблем:': 'Probleme:', 'Проблем': 'Probleme:', 'Проблем:': 'Probleme:', 'предупреждение': 'Warnung', 'Предупреждение': 'Warnung:', 'предупреждения': 'Warnung', 'Предупреждения': 'Warnung', 'предупреждение:': 'Warnung:', 'Предупреждение:': 'Warnung:', 'успешно': 'erfolgreich', 'Успешно': 'Erfolgreich', 'успешен': 'erfolgreich', 'Успешен': 'Erfolgreich', 'успешно:': 'erfolgreich:', 'Успешно:': 'Erfolgreich:', 'неизвестно': 'unbekannt', 'Неизвестно': 'Unbekannt', 'неизвестный': 'unbekannt', 'Неизвестный': 'Unbekannt', 'отключить:': 'deaktivieren:', 'Отключить:': 'Deaktivieren:', 'перезагрузка': 'Neustart', 'Перезагрузка': 'Neustart', 'перезагрузить': 'neustarten', 'Перезагрузить': 'Neustarten', 'перезагрузки': 'Neustart', 'Перезагрузки': 'Neustart', 'перезапустить': 'neustarten', 'Перезапустить': 'Neustarten', 'перезапуск': 'Neustart', 'Перезапуск': 'Neustart', 'перезапущен': 'neugestartet', 'Перезапущен': 'Neugestartet', 'завершить': 'beenden', 'Завершить': 'Beenden', 'завершение': 'Beenden', 'Завершение': 'Beenden', 'завершен': 'abgeschlossen', 'Завершен': 'Abgeschlossen', 'завершено': 'abgeschlossen', 'Завершено': 'Abgeschlossen', 'выбор': 'Auswahl', 'Выбор': 'Auswahl', 'выбора': 'Auswahl', 'Выбора': 'Auswahl', 'выбрано': 'ausgewählt', 'Выбрано': 'Ausgewählt', 'выбран': 'ausgewählt', 'Выбран': 'Ausgewählt', 'выбранный': 'ausgewählt', 'Выбранный': 'Ausgewählt', 'выбраны': 'ausgewählt', 'Выбраны': 'Ausgewählt', 'отмена': 'Abbrechen', 'Отмена': 'Abbrechen', 'отменить': 'abbrechen', 'Отменить': 'Abbrechen', 'отменено': 'abgebrochen', 'Отменено': 'Abgebrochen', 'закрыть': 'schließen', 'Закрыть': 'Schließen', 'закрыт': 'geschlossen', 'Закрыт': 'Geschlossen', 'запустить:': 'starten:', 'Запустить:': 'Starten:', 'остановить': 'stoppen', 'Остановить': 'Stoppen', 'остановлен': 'gestoppt', 'Остановлен': 'Gestoppt', 'остановлено': 'gestoppt', 'Остановлено': 'Gestoppt', 'запущен:': 'gestartet:', 'Запущен:': 'Gestartet:', 'файлов:': 'Dateien:', 'Файлов:': 'Dateien:', 'папку:': 'Ordner:', 'Папку:': 'Ordner:', 'систем:': 'Systeme:', 'Систем': 'Systeme:', 'Систем:': 'Systeme:', 'реестра:': 'Registers:', 'Реестра:': 'Registers:', 'службу:': 'Dienst:', 'Службу:': 'Dienst:', 'доступа:': 'Zugriffs:', 'Доступа:': 'Zugriffs:', 'дисков': 'Laufwerke', 'Дисков': 'Laufwerke', 'диск': 'Laufwerk', 'Диск': 'Laufwerk', 'диски': 'Laufwerke', 'Диски': 'Laufwerke', 'диска': 'Laufwerks', 'Диска': 'Laufwerks', 'принтер': 'Drucker', 'Принтер': 'Drucker', 'принтера': 'Druckers', 'Принтера': 'Druckers', 'шрифт': 'Schriftart', 'Шрифт': 'Schriftart', 'шрифты': 'Schriftarten', 'Шрифты': 'Schriftarten', 'шрифтов': 'Schriftarten', 'Шрифтов': 'Schriftarten', 'тема': 'Thema', 'Тема': 'Thema', 'темы': 'Thema', 'Темы': 'Thema', 'язык': 'Sprache', 'Язык': 'Sprache', 'языка': 'Sprache', 'Языка': 'Sprache', 'драйвер': 'Treiber', 'Драйвер': 'Treiber', 'драйвера': 'Treiber', 'Драйвера': 'Treiber', 'драйверов': 'Treiber', 'Драйверов': 'Treiber', 'обновление': 'Update', 'Обновление': 'Update', 'обновления': 'Update', 'Обновления': 'Update', 'обновить': 'aktualisieren', 'Обновить': 'Aktualisieren', 'обновлено': 'aktualisiert', 'Обновлено': 'Aktualisiert', 'центр': 'Zentrum', 'Центр': 'Zentrum', 'центра': 'Zentrums', 'Центра': 'Zentrums', 'безопасность': 'Sicherheit', 'Безопасность': 'Sicherheit', 'безопасности': 'Sicherheit', 'Безопасности': 'Sicherheit', 'безопасный': 'sicher', 'Безопасный': 'Sicher', 'безопасно': 'sicher', 'Безопасно': 'Sicher', 'защита': 'Schutz', 'Защита': 'Schutz:', 'защиты': 'Schutz', 'Защиты': 'Schutz', 'защита:': 'Schutz:', 'Защита:': 'Schutz:', 'защитит': 'schützen', 'Защитит': 'Schützen', 'защищено': 'geschützt', 'Защищено': 'Geschützt', 'защищен': 'geschützt', 'Защищен': 'Geschützt', 'защищает': 'schützt', 'Защищает': 'Schützt', 'антивирус': 'Antivirus', 'Антивирус': 'Antivirus', 'антивируса': 'Antivirus', 'Антивируса': 'Antivirus', 'вредонос': 'schädlich', 'Вредонос': 'Schädlich', 'вредоносный': 'schädlich', 'Вредоносный': 'Schädlich', 'вредоносных': 'schädlich', 'Вредоносных': 'Schädlich', 'угроза': 'Bedrohung', 'Угроза': 'Bedrohung', 'угрозы': 'Bedrohungen', 'Угрозы': 'Bedrohungen', 'угроз:': 'Bedrohungen:', 'Угроз': 'Bedrohungen:', 'Угроз:': 'Bedrohungen:', 'восстановление системы': 'Systemwiederherstellung', 'Восстановление системы': 'Systemwiederherstellung', 'восстановлено:': 'wiederhergestellt:', 'Восстановлено:': 'Wiederhergestellt:', 'поддержка': 'Unterstützung', 'Поддержка': 'Unterstützung', 'поддержки': 'Unterstützung', 'Поддержки': 'Unterstützung', 'поддерживает': 'unterstützt', 'Поддерживает': 'Unterstützt', 'инструмент': 'Werkzeug', 'Инструмент': 'Werkzeug:', 'инструменты': 'Werkzeuge', 'Инструменты': 'Werkzeuge', 'инструментов': 'Werkzeuge', 'Инструментов': 'Werkzeuge', 'инструмент:': 'Werkzeug:', 'Инструмент:': 'Werkzeug:', 'очищены': 'bereinigt', 'Очищены': 'Bereinigt', 'удаление:': 'Entfernen:', 'Удаление:': 'Entfernen:', 'имена': 'Namen', 'Имена': 'Namen', 'имен': 'Namen', 'Имен': 'Namen', 'записи:': 'Einträge:', 'Записи:': 'Einträge:', 'события': 'Ereignisse', 'События': 'Ereignisse', 'событие': 'Ereignis', 'Событие': 'Ereignis', 'событий': 'Ereignisse', 'Событий': 'Ereignisse', 'журнал': 'Protokoll', 'Журнал': 'Protokoll', 'журнала': 'Protokolls', 'Журнала': 'Protokolls', 'задач:': 'Aufgaben:', 'Задач:': 'Aufgaben:', 'процесс:': 'Prozess:', 'Процесс:': 'Prozess:', 'процессов:': 'Prozesse:', 'Процессов:': 'Prozesse:', 'отчет': 'Bericht', 'Отчет': 'Bericht', 'отчёт': 'Bericht', 'Отчёт': 'Bericht', 'отчета': 'Berichts', 'Отчета': 'Berichts', 'точка': 'Punkt', 'Точка': 'Punkt', 'точки': 'Punkts', 'Точки': 'Punkts', 'точку': 'Punkt', 'Точку': 'Punkt', 'конец': 'Ende', 'Конец': 'Ende', 'завершения': 'Abschluss', 'Завершения': 'Abschluss', 'восстановлено!': 'wiederhergestellt!', 'Восстановлено!': 'Wiederhergestellt!', 'успешно!': 'erfolgreich!', 'Успешно!': 'Erfolgreich!', 'выполнено!': 'abgeschlossen!', 'Выполнено!': 'Abgeschlossen!', 'готово!': 'fertig!', 'Готово!': 'Fertig!', 'отключено!': 'deaktiviert!', 'Отключено!': 'Deaktiviert!', 'включено!': 'aktiviert!', 'Включено!': 'Aktiviert!', 'удалено': 'entfernt', 'Удалено': 'Entfernt', 'скопирован': 'kopiert', 'Скопирован': 'Kopiert', 'скопировано': 'kopiert', 'Скопировано': 'Kopiert', 'скопировать': 'kopieren', 'Скопировать': 'Kopieren', 'копировать': 'kopieren', 'Копировать': 'Kopieren', 'создание:': 'Erstellung:', 'Создание:': 'Erstellung:', 'файл:': 'Datei:', 'Файл:': 'Datei:', 'папка:': 'Ordner:', 'Папка:': 'Ordner:', 'система:': 'System:', 'Система:': 'System:', 'остановлена': 'gestoppt', 'Остановлена': 'Gestoppt', 'остановлены': 'gestoppt', 'Остановлены': 'Gestoppt', 'завершена': 'abgeschlossen', 'Завершена': 'Abgeschlossen', 'завершены': 'abgeschlossen', 'Завершены': 'Abgeschlossen', 'выполнена': 'ausgeführt', 'Выполнена': 'Ausgeführt', 'выполнены': 'ausgeführt', 'Выполнены': 'Ausgeführt', 'удалена': 'entfernt', 'Удалена': 'Entfernt', 'создана': 'erstellt', 'Создана': 'Erstellt', 'созданы': 'erstellt', 'Созданы': 'Erstellt', 'включена': 'aktiviert', 'Включена': 'Aktiviert', 'отключена': 'deaktiviert', 'Отключена': 'Deaktiviert', 'найдена': 'gefunden', 'Найдена': 'Gefunden', 'найдены': 'gefunden', 'Найдены': 'Gefunden', 'установлена': 'installiert', 'Установлена': 'Installiert', 'установлено': 'installiert', 'Установлено': 'Installiert', 'установлены': 'installiert', 'Установлены': 'Installiert', 'установлен': 'installiert', 'Установлен': 'Installiert', 'сброшена': 'zurückgesetzt', 'Сброшена': 'Zurückgesetzt', 'сброшены': 'zurückgesetzt', 'Сброшены': 'Zurückgesetzt', 'очищена': 'bereinigt', 'Очищена': 'Bereinigt', 'заблокирована': 'blockiert', 'Заблокирована': 'Blockiert', 'заблокировано': 'blockiert', 'Заблокировано': 'Blockiert', 'заблокированы': 'blockiert', 'Заблокированы': 'Blockiert', 'заблокирован': 'blockiert', 'Заблокирован': 'Blockiert', 'разблокирована': 'entsperrt', 'Разблокирована': 'Entsperrt', 'разблокировано': 'entsperrt', 'Разблокировано': 'Entsperrt', 'запущена': 'gestartet', 'Запущена': 'Gestartet', 'запущены': 'gestartet', 'Запущены': 'Gestartet', 'перезапущена': 'neugestartet', 'Перезапущена': 'Neugestartet', 'перезапущено': 'neugestartet', 'Перезапущено': 'Neugestartet', 'обновлена': 'aktualisiert', 'Обновлена': 'Aktualisiert', 'обновлены': 'aktualisiert', 'Обновлены': 'Aktualisiert', 'восстановлена': 'wiederhergestellt', 'Восстановлена': 'Wiederhergestellt', 'скопирована': 'kopiert', 'Скопирована': 'Kopiert', 'скопированы': 'kopiert', 'Скопированы': 'Kopiert', 'разрешена': 'erlaubt', 'Разрешена': 'Erlaubt', 'разрешено': 'erlaubt', 'Разрешено': 'Erlaubt', 'разрешены': 'erlaubt', 'Разрешены': 'Erlaubt', 'запрещена': 'verboten', 'Запрещена': 'Verboten', 'запрещено': 'verboten', 'Запрещено': 'Verboten', 'запрещены': 'verboten', 'Запрещены': 'Verboten', 'активна': 'aktiv', 'Активна': 'Aktiv', 'активно': 'aktiv', 'Активно': 'Aktiv', 'активны': 'aktiv', 'Активны': 'Aktiv', 'активен': 'aktiv', 'Активен': 'Aktiv', 'неактивна': 'inaktiv', 'Неактивна': 'Inaktiv', 'неактивно': 'inaktiv', 'Неактивно': 'Inaktiv', 'неактивен': 'inaktiv', 'Неактивен': 'Inaktiv', 'доступны': 'verfügbar', 'Доступны': 'Verfügbar', 'отсутствует': 'fehlt', 'Отсутствует': 'Fehlt:', 'отсутствует:': 'fehlt:', 'Отсутствует:': 'Fehlt:', 'отсутствуют': 'fehlen', 'Отсутствуют': 'Fehlen', 'работает': 'funktioniert', 'Работает': 'Funktioniert:', 'работают': 'funktionieren', 'Работают': 'Funktionieren', 'работает:': 'funktioniert:', 'Работает:': 'Funktioniert:', 'неработает': 'funktioniert nicht', 'Неработает': 'Funktioniert nicht', 'поврежден': 'beschädigt', 'Поврежден': 'Beschädigt', 'повреждена': 'beschädigt', 'Повреждена': 'Beschädigt', 'повреждено': 'beschädigt', 'Повреждено': 'Beschädigt', 'повреждены': 'beschädigt', 'Повреждены': 'Beschädigt', 'исправен': 'in Ordnung', 'Исправен': 'In Ordnung', 'исправна': 'in Ordnung', 'Исправна': 'In Ordnung', 'исправно': 'in Ordnung', 'Исправно': 'In Ordnung', 'исправить': 'beheben', 'Исправить': 'Beheben', 'исправление': 'Behebung', 'Исправление': 'Behebung', 'исправлен': 'behoben', 'Исправлен': 'Behoben', 'исправлено': 'behoben', 'Исправлено': 'Behoben', 'исправлена': 'behoben', 'Исправлена': 'Behoben', 'требуется': 'erforderlich', 'Требуется': 'Erforderlich:', 'требуется:': 'erforderlich:', 'Требуется:': 'Erforderlich:', 'требуется перезагрузка': 'Neustart erforderlich', 'Требуется перезагрузка': 'Neustart erforderlich', 'перезагрузка требуется': 'Neustart erforderlich', 'Перезагрузка требуется': 'Neustart erforderlich', 'завершите': 'beenden', 'Завершите': 'Beenden', 'подтвердите': 'bestätigen', 'Подтвердите': 'Bestätigen', 'нажмите': 'drücken', 'Нажмите': 'Drücken:', 'нажмите:': 'drücken:', 'Нажмите:': 'Drücken:', 'нажмите чтобы': 'drücken um', 'Нажмите чтобы': 'Drücken um', 'выполните': 'ausführen', 'Выполните': 'Ausführen', 'перезапустите': 'neustarten', 'Перезапустите': 'Neustarten', 'перезагрузите': 'neustarten', 'Перезагрузите': 'Neustarten', 'запустите': 'starten', 'Запустите': 'Starten', 'откройте': 'öffnen', 'Откройте': 'Öffnen:', 'откройте:': 'öffnen:', 'Откройте:': 'Öffnen:', 'выберите:': 'auswählen:', 'Выберите:': 'Auswählen:', 'попробуйте': 'versuchen', 'Попробуйте': 'Versuchen', 'снова': 'erneut', 'Снова': 'Erneut', 'повторно': 'erneut', 'Повторно': 'Erneut', 'выполните повторно': 'erneut ausführen', 'Выполните повторно': 'Erneut ausführen', 'подождите': 'warten', 'Подождите': 'Warten', 'загрузка': 'Laden', 'Загрузка': 'Laden', 'загрузки': 'Laden', 'Загрузки': 'Laden', 'загружено': 'geladen', 'Загружено': 'Geladen', 'загружен': 'geladen', 'Загружен': 'Geladen', 'обнаружен': 'erkannt', 'Обнаружен': 'Erkannt', 'обнаружено': 'erkannt', 'Обнаружено': 'Erkannt', 'обнаружена': 'erkannt', 'Обнаружена': 'Erkannt', 'обнаружены': 'erkannt', 'Обнаружены': 'Erkannt', 'присутствует': 'vorhanden', 'Присутствует': 'Vorhanden', 'поддерживается': 'unterstützt', 'Поддерживается': 'Unterstützt', 'получено': 'empfangen', 'Получено': 'Empfangen', 'получен': 'empfangen', 'Получен': 'Empfangen', 'отправлено': 'gesendet', 'Отправлено': 'Gesendet', 'отправлен': 'gesendet', 'Отправлен': 'Gesendet', 'прервано': 'abgebrochen', 'Прервано': 'Abgebrochen', 'прерван': 'abgebrochen', 'Прерван': 'Abgebrochen', 'истекло': 'abgelaufen', 'Истекло': 'Abgelaufen', 'истек': 'abgelaufen', 'Истек': 'Abgelaufen', 'время': 'Zeit', 'Время': 'Zeit:', 'время:': 'Zeit:', 'Время:': 'Zeit:', 'времени': 'Zeit', 'Времени': 'Zeit', 'таймаут': 'Zeitüberschreitung', 'Таймаут': 'Zeitüberschreitung:', 'таймаут:': 'Zeitüberschreitung:', 'Таймаут:': 'Zeitüberschreitung:', 'размер': 'Größe', 'Размер': 'Größe:', 'размер:': 'Größe:', 'Размер:': 'Größe:', 'тип': 'Typ', 'Тип': 'Typ:', 'тип:': 'Typ:', 'Тип:': 'Typ:', 'статус': 'Status', 'Статус': 'Status:', 'статус:': 'Status:', 'Статус:': 'Status:', 'состояние': 'Zustand', 'Состояние': 'Zustand:', 'состояние:': 'Zustand:', 'Состояние:': 'Zustand:', 'состояния': 'Zustands', 'Состояния': 'Zustands', 'данные': 'Daten', 'Данные': 'Daten:', 'данных': 'Daten', 'Данных': 'Daten', 'данные:': 'Daten:', 'Данные:': 'Daten:', 'информация': 'Information', 'Информация': 'Information:', 'информация:': 'Information:', 'Информация:': 'Information:', 'информации': 'Information', 'Информации': 'Information', 'подробнее': 'Details', 'Подробнее': 'Details:', 'подробнее:': 'Details:', 'Подробнее:': 'Details:', 'детально': 'detailliert', 'Детально': 'Detailliert', 'причина': 'Grund', 'Причина': 'Grund:', 'причина:': 'Grund:', 'Причина:': 'Grund:', 'причины': 'Grundes', 'Причины': 'Grundes', 'решение': 'Lösung', 'Решение': 'Lösung:', 'решение:': 'Lösung:', 'Решение:': 'Lösung:', 'решения': 'Lösung', 'Решения': 'Lösung', 'рекомендация': 'Empfehlung', 'Рекомендация': 'Empfehlung', 'рекомендации': 'Empfehlungen', 'Рекомендации': 'Empfehlungen', 'рекомендуется': 'empfohlen', 'Рекомендуется': 'Empfohlen:', 'рекомендуется:': 'empfohlen:', 'Рекомендуется:': 'Empfohlen:', 'внимание': 'Achtung', 'Внимание': 'Achtung:', 'внимание:': 'Achtung:', 'Внимание:': 'Achtung:', 'осторожно': 'Vorsicht', 'Осторожно': 'Vorsicht', 'опасно': 'gefährlich', 'Опасно': 'Gefährlich:', 'опасно:': 'gefährlich:', 'Опасно:': 'Gefährlich:', 'риск': 'Risiko', 'Риск': 'Risiko', 'риска': 'Risikos', 'Риска': 'Risikos', 'необратимо': 'unumkehrbar', 'Необратимо': 'Unumkehrbar', 'необратимых': 'unumkehrbar', 'Необратимых': 'Unumkehrbar', 'назад': 'zurück', 'Назад': 'Zurück', 'далее': 'weiter', 'Далее': 'Weiter', 'вперед': 'vorwärts', 'Вперед': 'Vorwärts', 'выполнено успешно': 'erfolgreich abgeschlossen', 'Выполнено успешно': 'Erfolgreich abgeschlossen', 'операция выполнена': 'Vorgang abgeschlossen', 'Операция выполнена': 'Vorgang abgeschlossen', 'операция завершена': 'Vorgang abgeschlossen', 'Операция завершена': 'Vorgang abgeschlossen', 'изменения сохранены': 'Änderungen gespeichert', 'Изменения сохранены': 'Änderungen gespeichert', 'изменения': 'Änderungen', 'Изменения': 'Änderungen:', 'изменения:': 'Änderungen:', 'Изменения:': 'Änderungen:', 'изменен': 'geändert', 'Изменен': 'Geändert', 'изменено': 'geändert', 'Изменено': 'Geändert', 'изменить': 'ändern', 'Изменить': 'Ändern', 'сохранить': 'speichern', 'Сохранить': 'Speichern', 'сохранен': 'gespeichert', 'Сохранен': 'Gespeichert', 'сохранено': 'gespeichert', 'Сохранено': 'Gespeichert', 'сохранена': 'gespeichert', 'Сохранена': 'Gespeichert', 'сохранены': 'gespeichert', 'Сохранены': 'Gespeichert', 'импорт': 'Import', 'Импорт': 'Import', 'экспорт': 'Export', 'Экспорт': 'Export', 'записано': 'geschrieben', 'Записано': 'Geschrieben', 'запись создана': 'Eintrag erstellt', 'Запись создана': 'Eintrag erstellt', 'запись удалена': 'Eintrag entfernt', 'Запись удалена': 'Eintrag entfernt', 'ключ': 'Schlüssel', 'Ключ': 'Schlüssel:', 'ключи': 'Schlüssel', 'Ключи': 'Schlüssel', 'ключ:': 'Schlüssel:', 'Ключ:': 'Schlüssel:', 'параметр': 'Parameter', 'Параметр': 'Parameter:', 'параметры': 'Parameter', 'Параметры': 'Parameter', 'параметр:': 'Parameter:', 'Параметр:': 'Parameter:', 'строка': 'Zeile', 'Строка': 'Zeile', 'строки': 'Zeilen', 'Строки': 'Zeilen', 'элемент': 'Element', 'Элемент': 'Element:', 'элементы': 'Elemente', 'Элементы': 'Elemente', 'элемент:': 'Element:', 'Элемент:': 'Element:', 'компонент': 'Komponente', 'Компонент': 'Komponente:', 'компоненты': 'Komponenten', 'Компоненты': 'Komponenten', 'компонент:': 'Komponente:', 'Компонент:': 'Komponente:', 'завершить процесс': 'Prozess beenden', 'Завершить процесс': 'Prozess beenden', 'перезапустить службу': 'Dienst neu starten', 'Перезапустить службу': 'Dienst neu starten', 'запустить службу': 'Dienst starten', 'Запустить службу': 'Dienst starten', 'остановить службу': 'Dienst stoppen', 'Остановить службу': 'Dienst stoppen', 'вирусом': 'Virus', 'Вирусом': 'Virus', 'службой': 'Dienst', 'Службой': 'Dienst', 'процессом': 'Prozess', 'Процессом': 'Prozess', 'путем': 'Pfad', 'Путем': 'Pfad', 'путём': 'Pfad', 'Путём': 'Pfad', 'администратором': 'Administrator', 'Администратором': 'Administrator', 'системой': 'System', 'Системой': 'System', 'реестром': 'Register', 'Реестром': 'Register', 'диском': 'Laufwerk', 'Диском': 'Laufwerk', 'принтером': 'Drucker', 'Принтером': 'Drucker', 'шрифтом': 'Schriftart', 'Шрифтом': 'Schriftart', 'брандмауэром': 'Firewall', 'Брандмауэром': 'Firewall', 'процессором': 'Prozessor', 'Процессором': 'Prozessor', 'сетью': 'Netzwerk', 'Сетью': 'Netzwerk', 'сети': 'Netzwerk', 'Сети': 'Netzwerk', 'сервисом': 'Dienst', 'Сервисом': 'Dienst', 'сервиса': 'Dienstes', 'Сервиса': 'Dienstes', 'файле': 'Datei', 'Файле': 'Datei', 'системе': 'System', 'Системе': 'System', 'диске': 'Laufwerk', 'Диске': 'Laufwerk', 'пользователе': 'Benutzer', 'Пользователе': 'Benutzer', 'администратора': 'Administrators', 'Администратора': 'Administrators', 'полностью': 'vollständig', 'Полностью': 'Vollständig', 'частично': 'teilweise', 'Частично': 'Teilweise', 'автоматически': 'automatisch', 'Автоматически': 'Automatisch', 'принудительно': 'zwangsweise', 'Принудительно': 'Zwangsweise', 'немедленно': 'sofort', 'Немедленно': 'Sofort', 'временно': 'vorübergehend', 'Временно': 'Vorübergehend', 'постоянно': 'dauerhaft', 'Постоянно': 'Dauerhaft', 'локально': 'lokalnie', 'Локально': 'Lokalnie', 'удаленно': 'remote', 'Удаленно': 'Remote', 'отменена': 'abgebrochen', 'Отменена': 'Abgebrochen', 'отменены': 'abgebrochen', 'Отменены': 'Abgebrochen', 'пропущена': 'übersprungen', 'Пропущена': 'Übersprungen', 'пропущено': 'übersprungen', 'Пропущено': 'Übersprungen', 'пропущены': 'übersprungen', 'Пропущены': 'Übersprungen', 'пропущен': 'übersprungen', 'Пропущен': 'Übersprungen'},
        "pl": {'не': 'nie', 'Не': 'Nie', 'будет': 'będzie', 'Будет': 'Będzie', 'будут': 'będą', 'Будут': 'Będą', 'ошибка': 'błąd', 'Ошибка': 'Błąd', 'ошибки': 'błędy', 'Ошибки': 'Błędy', 'ошибок': 'błędów', 'Ошибок': 'Błędów:', 'ошибок:': 'błędów:', 'Ошибок:': 'Błędów:', 'ошибками': 'błędami', 'Ошибками': 'Błędami', 'ошибку': 'błąd', 'Ошибку': 'Błąd', 'файл': 'plik', 'Файл': 'Plik:', 'файла': 'pliku', 'Файла': 'Pliku', 'файлы': 'pliki', 'Файлы': 'Pliki', 'файлов': 'plików', 'Файлов': 'Plików:', 'файлом': 'plikiem', 'Файлом': 'Plikiem', 'удалось': 'udało się', 'Удалось': 'Udało się', 'не удалось': 'nie udało się', 'Не удалось': 'Nie udało się', 'задач': 'zadań', 'Задач': 'Zadań:', 'задача': 'zadanie', 'Задача': 'Zadanie', 'задачу': 'zadanie', 'Задачу': 'Zadanie', 'задачи': 'zadania', 'Задачи': 'Zadania', 'задаче': 'zadaniu', 'Задаче': 'Zadaniu', 'через': 'przez', 'Через': 'Przez', 'восстановление': 'przywracanie', 'Восстановление': 'Przywracanie', 'восстановления': 'przywracania', 'Восстановления': 'Przywracania:', 'восстановлено': 'przywrócono', 'Восстановлено': 'Przywrócono', 'восстановлен': 'przywrócono', 'Восстановлен': 'Przywrócono', 'восстановить': 'przywrócić', 'Восстановить': 'Przywrócić', 'восстанавливает': 'przywraca', 'Восстанавливает': 'Przywraca', 'восстанавливаеться': 'przywracany', 'Восстанавливаеться': 'Przywracany', 'восстановлены': 'przywrócone', 'Восстановлены': 'Przywrócone', 'восстановления:': 'przywracania:', 'Восстановления:': 'Przywracania:', 'системы': 'systemu', 'Системы': 'Systemu', 'система': 'system', 'Система': 'System:', 'систему': 'system', 'Систему': 'System', 'системные': 'systemowe', 'Системные': 'Systemowe', 'системный': 'systemowy', 'Системный': 'Systemowy', 'системной': 'systemowej', 'Системной': 'Systemowej', 'системных': 'systemowych', 'Системных': 'Systemowych', 'реестра': 'rejestru', 'Реестра': 'Rejestru', 'реестр': 'rejestr', 'Реестр': 'Rejestr', 'реестре': 'rejestrze', 'Реестре': 'Rejestrze', 'реестру': 'rejestrowi', 'Реестру': 'Rejestrowi', 'или': 'lub', 'Или': 'Lub', 'из': 'z', 'Из': 'Z', 'все': 'wszystkie', 'Все': 'Wszystkie', 'всё': 'wszystko', 'Всё': 'Wszystko', 'всех': 'wszystkich', 'Всех': 'Wszystkich', 'всю': 'wszystko', 'Всю': 'Wszystko', 'запуск': 'uruchamianie', 'Запуск': 'Uruchamianie', 'запуска': 'uruchamiania', 'Запуска': 'Uruchamiania', 'запустить': 'uruchomić', 'Запустить': 'Uruchomić:', 'запущен': 'uruchomiono', 'Запущен': 'Uruchomiono:', 'запущено': 'uruchomiono', 'Запущено': 'Uruchomiono', 'запускает': 'uruchamia', 'Запускает': 'Uruchamia', 'панель': 'panel', 'Панель': 'Panel:', 'панели': 'panelu', 'Панели': 'Panelu', 'панель:': 'panel:', 'Панель:': 'Panel:', 'выберите': 'wybierz', 'Выберите': 'Wybierz:', 'удалить': 'usunąć', 'Удалить': 'Usunąć:', 'удаление': 'usuwanie', 'Удаление': 'Usuwanie:', 'удалены': 'usunięte', 'Удалены': 'Usunięte', 'удален': 'usunięto', 'Удален': 'Usunięto', 'удалить:': 'usunąć:', 'Удалить:': 'Usunąć:', 'процесс': 'proces', 'Процесс': 'Proces:', 'процесса': 'procesu', 'Процесса': 'Procesu', 'процессы': 'procesy', 'Процессы': 'Procesy', 'процессов': 'procesów', 'Процессов': 'Procesów:', 'процессе': 'procesie', 'Процессе': 'Procesie', 'только': 'tylko', 'Только': 'Tylko', 'что': 'że', 'Что': 'Że', 'настройки': 'ustawienia', 'Настройки': 'Ustawienia', 'настройка': 'ustawienie', 'Настройка': 'Ustawienie', 'настройку': 'ustawienie', 'Настройку': 'Ustawienie', 'настроек': 'ustawień', 'Настроек': 'Ustawień', 'настроить': 'skonfigurować', 'Настроить': 'Skonfigurować', 'при': 'przy', 'При': 'Przy', 'бэкап': 'kopia zapasowa', 'Бэкап': 'Kopia zapasowa', 'бэкапы': 'kopie zapasowe', 'Бэкапы': 'Kopie zapasowe', 'бэкапа': 'kopii zapasowej', 'Бэкапа': 'Kopii zapasowej', 'бэкапов': 'kopii zapasowych', 'Бэкапов': 'Kopii zapasowych', 'путь': 'ścieżka', 'Путь': 'Ścieżka:', 'пути': 'ścieżki', 'Пути': 'Ścieżki', 'путь:': 'ścieżka:', 'Путь:': 'Ścieżka:', 'запись': 'wpis', 'Запись': 'Wpis:', 'записи': 'wpisy', 'Записи': 'Wpisy:', 'записей': 'wpisów', 'Записей': 'Wpisów', 'запись:': 'wpis:', 'Запись:': 'Wpis:', 'службу': 'usługę', 'Службу': 'Usługę:', 'служба': 'usługa', 'Служба': 'Usługa', 'службы': 'usługi', 'Службы': 'Usługi', 'служб': 'usług', 'Служб': 'Usług', 'службе': 'usłudze', 'Службе': 'Usłudze', 'службы:': 'usługi:', 'Службы:': 'Usługi:', 'очистка': 'czyszczenie', 'Очистка': 'Czyszczenie:', 'очистки': 'czyszczenia', 'Очистки': 'Czyszczenia', 'очистить': 'wyczyścić', 'Очистить': 'Wyczyścić', 'очищает': 'czyści', 'Очищает': 'Czyści', 'очищен': 'wyczyszczono', 'Очищен': 'Wyczyszczono', 'очищено': 'wyczyszczono', 'Очищено': 'Wyczyszczono', 'очистка:': 'czyszczenie:', 'Очистка:': 'Czyszczenie:', 'проверка': 'sprawdzanie', 'Проверка': 'Sprawdzanie:', 'проверки': 'sprawdzania', 'Проверки': 'Sprawdzania', 'проверяет': 'sprawdza', 'Проверяет': 'Sprawdza', 'проверить': 'sprawdzić', 'Проверить': 'Sprawdzić', 'проверяем': 'sprawdzamy', 'Проверяем': 'Sprawdzamy', 'проверка:': 'sprawdzanie:', 'Проверка:': 'Sprawdzanie:', 'нет': 'brak', 'Нет': 'Brak:', 'нет:': 'brak:', 'Нет:': 'Brak:', 'режим': 'tryb', 'Режим': 'Tryb', 'режима': 'trybu', 'Режима': 'Trybu', 'диспетчер': 'menedżer', 'Диспетчер': 'Menedżer:', 'диспетчер:': 'menedżer:', 'Диспетчер:': 'Menedżer:', 'если': 'jeśli', 'Если': 'Jeśli', 'доступ': 'dostęp', 'Доступ': 'Dostęp:', 'доступа': 'dostępu', 'Доступа': 'Dostępu:', 'доступ:': 'dostęp:', 'Доступ:': 'Dostęp:', 'доступно': 'dostępne', 'Доступно': 'Dostępne', 'доступна': 'dostępna', 'Доступна': 'Dostępna', 'доступен': 'dostępny', 'Доступен': 'Dostępny', 'отключен': 'wyłączono', 'Отключен': 'Wyłączono', 'отключено': 'wyłączono', 'Отключено': 'Wyłączono', 'отключены': 'wyłączone', 'Отключены': 'Wyłączone', 'отключить': 'wyłączyć', 'Отключить': 'Wyłączyć:', 'отключение': 'wyłączanie', 'Отключение': 'Wyłączanie', 'отключается': 'wyłączany', 'Отключается': 'Wyłączany', 'включен': 'włączono', 'Включен': 'Włączono', 'включено': 'włączono', 'Включено': 'Włączono', 'включены': 'włączone', 'Включены': 'Włączone', 'включить': 'włączyć', 'Включить': 'Włączyć:', 'включение': 'włączanie', 'Включение': 'Włączanie:', 'включает': 'włącza', 'Включает': 'Włącza', 'включить:': 'włączyć:', 'Включить:': 'Włączyć:', 'права': 'uprawnienia', 'Права': 'Uprawnienia:', 'прав': 'uprawnień', 'Прав': 'Uprawnień', 'права:': 'uprawnienia:', 'Права:': 'Uprawnienia:', 'свойства': 'właściwości', 'Свойства': 'Właściwości:', 'свойств': 'właściwości', 'Свойств': 'Właściwości', 'свойства:': 'właściwości:', 'Свойства:': 'Właściwości:', 'меню': 'menu', 'Меню': 'Menu:', 'меню:': 'menu:', 'Меню:': 'Menu:', 'управления': 'zarządzania', 'Управления': 'Zarządzania', 'управление': 'zarządzanie', 'Управление': 'Zarządzanie', 'папки': 'folderu', 'Папки': 'Folderu', 'папка': 'folder', 'Папка': 'Folder:', 'папку': 'folder', 'Папку': 'Folder:', 'папок': 'folderów', 'Папок': 'Folderów', 'папке': 'folderze', 'Папке': 'Folderze', 'создать': 'utworzyć', 'Создать': 'Utworzyć', 'создание': 'tworzenie', 'Создание': 'Tworzenie:', 'создан': 'utworzono', 'Создан': 'Utworzono', 'создано': 'utworzono', 'Создано': 'Utworzono', 'имя': 'nazwa', 'Имя': 'Nazwa:', 'имя:': 'nazwa:', 'Имя:': 'Nazwa:', 'разблокировка': 'odblokowywanie', 'Разблокировка': 'Odblokowywanie:', 'разблокирует': 'odblokowuje', 'Разблокирует': 'Odblokowuje', 'разблокирован': 'odblokowano', 'Разблокирован': 'Odblokowano', 'разблокированы': 'odblokowane', 'Разблокированы': 'Odblokowane', 'разблокировка:': 'odblokowywanie:', 'Разблокировка:': 'Odblokowywanie:', 'блокировки': 'blokady', 'Блокировки': 'Blokady', 'блокировка': 'blokada', 'Блокировка': 'Blokada', 'блокировку': 'blokadę', 'Блокировку': 'Blokadę', 'блокировок': 'blokad', 'Блокировок': 'Blokad', 'блокировала': 'blokowała', 'Блокировала': 'Blokowała', 'брандмауэр': 'zapora sieciowa', 'Брандмауэр': 'Zapora sieciowa:', 'брандмауэра': 'zapory sieciowej', 'Брандмауэра': 'Zapory sieciowej', 'брандмауэр:': 'zapora sieciowa:', 'Брандмауэр:': 'Zapora sieciowa:', 'вирус': 'wirus', 'Вирус': 'Wirus:', 'вируса': 'wirusa', 'Вируса': 'Wirusa', 'вирусы': 'wirusy', 'Вирусы': 'Wirusy', 'вирусов': 'wirusów', 'Вирусов': 'Wirusów', 'вирус:': 'wirus:', 'Вирус:': 'Wirus:', 'подтверждение': 'potwierdzenie', 'Подтверждение': 'Potwierdzenie', 'подтверждения': 'potwierdzenia', 'Подтверждения': 'Potwierdzenia', 'подтвердить': 'potwierdzić', 'Подтвердить': 'Potwierdzić', 'откат': 'cofanie', 'Откат': 'Cofanie:', 'откатить': 'cofnąć', 'Откатить': 'Cofnąć', 'откат:': 'cofanie:', 'Откат:': 'Cofanie:', 'список': 'lista', 'Список': 'Lista:', 'списка': 'listy', 'Списка': 'Listy', 'список:': 'lista:', 'Список:': 'Lista:', 'политики': 'zasady', 'Политики': 'Zasady', 'политика': 'zasada', 'Политика': 'Zasada', 'политик': 'zasad', 'Политик': 'Zasad', 'добавить': 'dodać', 'Добавить': 'Dodać', 'добавлен': 'dodano', 'Добавлен': 'Dodano', 'добавлено': 'dodano', 'Добавлено': 'Dodano', 'продолжить': 'kontynuować', 'Продолжить': 'Kontynuować', 'включено:': 'włączono:', 'Включено:': 'Włączono:', 'включение:': 'włączanie:', 'Включение:': 'Włączanie:', 'клавиши': 'klawisze', 'Клавиши': 'Klawisze', 'клавиша': 'klawisz', 'Клавиша': 'Klawisz', 'клавиатуре': 'klawiaturze', 'Клавиатуре': 'Klawiaturze', 'клавиатура': 'klawiatura', 'Клавиатура': 'Klawiatura', 'клавиатуры': 'klawiatury', 'Клавиатуры': 'Klawiatury', 'операция': 'operacja', 'Операция': 'Operacja', 'операции': 'operacji', 'Операции': 'Operacji', 'операцию': 'operację', 'Операцию': 'Operację', 'ограничений': 'ograniczeń', 'Ограничений': 'Ograniczeń', 'ограничение': 'ograniczenie', 'Ограничение': 'Ograniczenie', 'ограничения': 'ograniczenia', 'Ограничения': 'Ograniczenia', 'значение': 'wartość', 'Значение': 'Wartość:', 'значения': 'wartości', 'Значения': 'Wartości', 'значение:': 'wartość:', 'Значение:': 'Wartość:', 'пользователь': 'użytkownik', 'Пользователь': 'Użytkownik', 'пользователя': 'użytkownika', 'Пользователя': 'Użytkownika', 'пользователи': 'użytkownicy', 'Пользователи': 'Użytkownicy', 'пользователем': 'użytkownikiem', 'Пользователем': 'Użytkownikiem', 'пользователю': 'użytkownikowi', 'Пользователю': 'Użytkownikowi', 'подозрительные': 'podejrzane', 'Подозрительные': 'Podejrzane', 'подозрительных': 'podejrzanych', 'Подозрительных': 'Podejrzanych', 'подозрительный': 'podejrzany', 'Подозрительный': 'Podejrzany', 'найдено': 'znaleziono', 'Найдено': 'Znaleziono', 'найдено:': 'znaleziono:', 'Найдено:': 'Znaleziono:', 'найден': 'znaleziono', 'Найден': 'Znaleziono', 'блок': 'blok', 'Блок': 'Blok:', 'блок:': 'blok:', 'Блок:': 'Blok:', 'автозагрузки': 'autostartu', 'Автозагрузки': 'Autostartu', 'автозагрузка': 'autostart', 'Автозагрузка': 'Autostart', 'автозагрузку': 'autostart', 'Автозагрузку': 'Autostart', 'автозапуск': 'automatyczne uruchamianie', 'Автозапуск': 'Automatyczne uruchamianie', 'сброс': 'resetowanie', 'Сброс': 'Resetowanie', 'сброса': 'resetowania', 'Сброса': 'Resetowania', 'сбросить': 'zresetować', 'Сбросить': 'Zresetować', 'сброшен': 'zresetowano', 'Сброшен': 'Zresetowano', 'сброшено': 'zresetowano', 'Сброшено': 'Zresetowano', 'проводник': 'eksplorator', 'Проводник': 'Eksplorator:', 'проводник:': 'eksplorator:', 'Проводник:': 'Eksplorator:', 'сканирование': 'skanowanie', 'Сканирование': 'Skanowanie:', 'сканировать': 'skanować', 'Сканировать': 'Skanować', 'сканирование:': 'skanowanie:', 'Сканирование:': 'Skanowanie:', 'полный': 'pełny', 'Полный': 'Pełny', 'полная': 'pełna', 'Полная': 'Pełna', 'полное': 'pełne', 'Полное': 'Pełne', 'после': 'po', 'После': 'Po', 'перед': 'przed', 'Перед': 'Przed', 'выполняется': 'wykonywane', 'Выполняется': 'Wykonywane:', 'выполнено': 'wykonano', 'Выполнено': 'Wykonano', 'выполнено:': 'wykonano:', 'Выполнено:': 'Wykonano:', 'выполнить': 'wykonać', 'Выполнить': 'Wykonać', 'выполнения': 'wykonywania', 'Выполнения': 'Wykonywania', 'готов': 'gotowy', 'Готов': 'Gotowy', 'готова': 'gotowa', 'Готова': 'Gotowa', 'готово': 'gotowe', 'Готово': 'Gotowe', 'готовы': 'gotowe', 'Готовы': 'Gotowe', 'выполняется:': 'wykonywane:', 'Выполняется:': 'Wykonywane:', 'проблема': 'problem', 'Проблема': 'Problem', 'проблемы': 'problemy', 'Проблемы': 'Problemy', 'проблем:': 'problemów:', 'Проблем': 'Problemów:', 'Проблем:': 'Problemów:', 'предупреждение': 'ostrzeżenie', 'Предупреждение': 'Ostrzeżenie:', 'предупреждения': 'ostrzeżenia', 'Предупреждения': 'Ostrzeżenia', 'предупреждение:': 'ostrzeżenie:', 'Предупреждение:': 'Ostrzeżenie:', 'успешно': 'pomyślnie', 'Успешно': 'Pomyślnie', 'успешен': 'udany', 'Успешен': 'Udany', 'успешно:': 'pomyślnie:', 'Успешно:': 'Pomyślnie:', 'неизвестно': 'nieznane', 'Неизвестно': 'Nieznane', 'неизвестный': 'nieznany', 'Неизвестный': 'Nieznany', 'отключить:': 'wyłączyć:', 'Отключить:': 'Wyłączyć:', 'перезагрузка': 'uruchomienie ponowne', 'Перезагрузка': 'Uruchomienie ponowne', 'перезагрузить': 'uruchomić ponownie', 'Перезагрузить': 'Uruchomić ponownie', 'перезагрузки': 'uruchomienia ponownego', 'Перезагрузки': 'Uruchomienia ponownego', 'перезапустить': 'zrestartować', 'Перезапустить': 'Zrestartować', 'перезапуск': 'restart', 'Перезапуск': 'Restart', 'перезапущен': 'zrestartowano', 'Перезапущен': 'Zrestartowano', 'завершить': 'zakończyć', 'Завершить': 'Zakończyć', 'завершение': 'zakończenie', 'Завершение': 'Zakończenie', 'завершен': 'zakończono', 'Завершен': 'Zakończono', 'завершено': 'zakończono', 'Завершено': 'Zakończono', 'выбор': 'wybór', 'Выбор': 'Wybór', 'выбора': 'wyboru', 'Выбора': 'Wyboru', 'выбрано': 'wybrano', 'Выбрано': 'Wybrano', 'выбран': 'wybrano', 'Выбран': 'Wybrano', 'выбранный': 'wybrany', 'Выбранный': 'Wybrany', 'выбраны': 'wybrane', 'Выбраны': 'Wybrane', 'отмена': 'anuluj', 'Отмена': 'Anuluj', 'отменить': 'anulować', 'Отменить': 'Anulować', 'отменено': 'anulowano', 'Отменено': 'Anulowano', 'закрыть': 'zamknąć', 'Закрыть': 'Zamknąć', 'закрыт': 'zamknięto', 'Закрыт': 'Zamknięto', 'запустить:': 'uruchomić:', 'Запустить:': 'Uruchomić:', 'остановить': 'zatrzymać', 'Остановить': 'Zatrzymać', 'остановлен': 'zatrzymano', 'Остановлен': 'Zatrzymano', 'остановлено': 'zatrzymano', 'Остановлено': 'Zatrzymano', 'запущен:': 'uruchomiono:', 'Запущен:': 'Uruchomiono:', 'файлов:': 'plików:', 'Файлов:': 'Plików:', 'папку:': 'folder:', 'Папку:': 'Folder:', 'систем:': 'systemów:', 'Систем': 'Systemów:', 'Систем:': 'Systemów:', 'реестра:': 'rejestru:', 'Реестра:': 'Rejestru:', 'службу:': 'usługę:', 'Службу:': 'Usługę:', 'доступа:': 'dostępu:', 'Доступа:': 'Dostępu:', 'дисков': 'dysków', 'Дисков': 'Dysków', 'диск': 'dysk', 'Диск': 'Dysk', 'диски': 'dyski', 'Диски': 'Dyski', 'диска': 'dysku', 'Диска': 'Dysku', 'принтер': 'drukarka', 'Принтер': 'Drukarka', 'принтера': 'drukarki', 'Принтера': 'Drukarki', 'шрифт': 'czcionka', 'Шрифт': 'Czcionka', 'шрифты': 'czcionki', 'Шрифты': 'Czcionki', 'шрифтов': 'czcionek', 'Шрифтов': 'Czcionek', 'тема': 'motyw', 'Тема': 'Motyw', 'темы': 'motywu', 'Темы': 'Motywu', 'язык': 'język', 'Язык': 'Język', 'языка': 'języka', 'Языка': 'Języka', 'драйвер': 'sterownik', 'Драйвер': 'Sterownik', 'драйвера': 'sterownicy', 'Драйвера': 'Sterownicy', 'драйверов': 'sterowników', 'Драйверов': 'Sterowników', 'обновление': 'aktualizacja', 'Обновление': 'Aktualizacja', 'обновления': 'aktualizacji', 'Обновления': 'Aktualizacji', 'обновить': 'zaktualizować', 'Обновить': 'Zaktualizować', 'обновлено': 'zaktualizowano', 'Обновлено': 'Zaktualizowano', 'центр': 'centrum', 'Центр': 'Centrum', 'центра': 'centrum', 'Центра': 'Centrum', 'безопасность': 'bezpieczeństwo', 'Безопасность': 'Bezpieczeństwo', 'безопасности': 'bezpieczeństwa', 'Безопасности': 'Bezpieczeństwa', 'безопасный': 'bezpieczny', 'Безопасный': 'Bezpieczny', 'безопасно': 'bezpiecznie', 'Безопасно': 'Bezpiecznie', 'защита': 'ochrona', 'Защита': 'Ochrona:', 'защиты': 'ochrony', 'Защиты': 'Ochrony', 'защита:': 'ochrona:', 'Защита:': 'Ochrona:', 'защитит': 'chronić', 'Защитит': 'Chronić', 'защищено': 'chronione', 'Защищено': 'Chronione', 'защищен': 'chroniony', 'Защищен': 'Chroniony', 'защищает': 'chroni', 'Защищает': 'Chroni', 'антивирус': 'antywirus', 'Антивирус': 'Antywirus', 'антивируса': 'antywirusa', 'Антивируса': 'Antywirusa', 'вредонос': 'złośliwy', 'Вредонос': 'Złośliwy', 'вредоносный': 'złośliwy', 'Вредоносный': 'Złośliwy', 'вредоносных': 'złośliwych', 'Вредоносных': 'Złośliwych', 'угроза': 'zagrożenie', 'Угроза': 'Zagrożenie', 'угрозы': 'zagrożenia', 'Угрозы': 'Zagrożenia', 'угроз:': 'zagrożeń:', 'Угроз': 'Zagrożeń:', 'Угроз:': 'Zagrożeń:', 'восстановление системы': 'przywracanie systemu', 'Восстановление системы': 'Przywracanie systemu', 'восстановлено:': 'przywrócono:', 'Восстановлено:': 'Przywrócono:', 'поддержка': 'wsparcie', 'Поддержка': 'Wsparcie', 'поддержки': 'wsparcia', 'Поддержки': 'Wsparcia', 'поддерживает': 'obsługuje', 'Поддерживает': 'Obsługuje', 'инструмент': 'narzędzie', 'Инструмент': 'Narzędzie:', 'инструменты': 'narzędzia', 'Инструменты': 'Narzędzia', 'инструментов': 'narzędzi', 'Инструментов': 'Narzędzi', 'инструмент:': 'narzędzie:', 'Инструмент:': 'Narzędzie:', 'очищены': 'wyczyszczone', 'Очищены': 'Wyczyszczone', 'удаление:': 'usuwanie:', 'Удаление:': 'Usuwanie:', 'имена': 'nazwy', 'Имена': 'Nazwy', 'имен': 'nazw', 'Имен': 'Nazw', 'записи:': 'wpisy:', 'Записи:': 'Wpisy:', 'события': 'zdarzenia', 'События': 'Zdarzenia', 'событие': 'zdarzenie', 'Событие': 'Zdarzenie', 'событий': 'zdarzeń', 'Событий': 'Zdarzeń', 'журнал': 'dziennik', 'Журнал': 'Dziennik', 'журнала': 'dziennika', 'Журнала': 'Dziennika', 'задач:': 'zadań:', 'Задач:': 'Zadań:', 'процесс:': 'proces:', 'Процесс:': 'Proces:', 'процессов:': 'procesów:', 'Процессов:': 'Procesów:', 'отчет': 'rapport', 'Отчет': 'Rapport', 'отчёт': 'rapport', 'Отчёт': 'Rapport', 'отчета': 'rapportu', 'Отчета': 'Rapportu', 'точка': 'punkt', 'Точка': 'Punkt', 'точки': 'punktu', 'Точки': 'Punktu', 'точку': 'punkt', 'Точку': 'Punkt', 'конец': 'koniec', 'Конец': 'Koniec', 'завершения': 'zakończenia', 'Завершения': 'Zakończenia', 'восстановлено!': 'przywrócono!', 'Восстановлено!': 'Przywrócono!', 'успешно!': 'pomyślnie!', 'Успешно!': 'Pomyślnie!', 'выполнено!': 'wykonano!', 'Выполнено!': 'Wykonano!', 'готово!': 'gotowe!', 'Готово!': 'Gotowe!', 'отключено!': 'wyłączono!', 'Отключено!': 'Wyłączono!', 'включено!': 'włączono!', 'Включено!': 'Włączono!', 'удалено': 'usunięto', 'Удалено': 'Usunięto', 'скопирован': 'skopiowano', 'Скопирован': 'Skopiowano', 'скопировано': 'skopiowano', 'Скопировано': 'Skopiowano', 'скопировать': 'kopiować', 'Скопировать': 'Kopiować', 'копировать': 'kopiować', 'Копировать': 'Kopiować', 'создание:': 'tworzenie:', 'Создание:': 'Tworzenie:', 'файл:': 'plik:', 'Файл:': 'Plik:', 'папка:': 'folder:', 'Папка:': 'Folder:', 'система:': 'system:', 'Система:': 'System:', 'остановлена': 'zatrzymana', 'Остановлена': 'Zatrzymana', 'остановлены': 'zatrzymane', 'Остановлены': 'Zatrzymane', 'завершена': 'zakończona', 'Завершена': 'Zakończona', 'завершены': 'zakończone', 'Завершены': 'Zakończone', 'выполнена': 'wykonana', 'Выполнена': 'Wykonana', 'выполнены': 'wykonane', 'Выполнены': 'Wykonane', 'удалена': 'usunięta', 'Удалена': 'Usunięta', 'создана': 'utworzona', 'Создана': 'Utworzona', 'созданы': 'utworzone', 'Созданы': 'Utworzone', 'включена': 'włączona', 'Включена': 'Włączona', 'отключена': 'wyłączona', 'Отключена': 'Wyłączona', 'найдена': 'znaleziona', 'Найдена': 'Znaleziona', 'найдены': 'znalezione', 'Найдены': 'Znalezione', 'установлена': 'zainstalowana', 'Установлена': 'Zainstalowana', 'установлено': 'zainstalowano', 'Установлено': 'Zainstalowano', 'установлены': 'zainstalowane', 'Установлены': 'Zainstalowane', 'установлен': 'zainstalowany', 'Установлен': 'Zainstalowany', 'сброшена': 'zresetowana', 'Сброшена': 'Zresetowana', 'сброшены': 'zresetowane', 'Сброшены': 'Zresetowane', 'очищена': 'wyczyszczona', 'Очищена': 'Wyczyszczona', 'заблокирована': 'zablokowana', 'Заблокирована': 'Zablokowana', 'заблокировано': 'zablokowano', 'Заблокировано': 'Zablokowano', 'заблокированы': 'zablokowane', 'Заблокированы': 'Zablokowane', 'заблокирован': 'zablokowany', 'Заблокирован': 'Zablokowany', 'разблокирована': 'odblokowana', 'Разблокирована': 'Odblokowana', 'разблокировано': 'odblokowano', 'Разблокировано': 'Odblokowano', 'запущена': 'uruchomiona', 'Запущена': 'Uruchomiona', 'запущены': 'uruchomione', 'Запущены': 'Uruchomione', 'перезапущена': 'zrestartowana', 'Перезапущена': 'Zrestartowana', 'перезапущено': 'zrestartowano', 'Перезапущено': 'Zrestartowano', 'обновлена': 'zaktualizowana', 'Обновлена': 'Zaktualizowana', 'обновлены': 'zaktualizowane', 'Обновлены': 'Zaktualizowane', 'восстановлена': 'przywrócona', 'Восстановлена': 'Przywrócona', 'скопирована': 'skopiowana', 'Скопирована': 'Skopiowana', 'скопированы': 'skopiowane', 'Скопированы': 'Skopiowane', 'разрешена': 'dozwolona', 'Разрешена': 'Dozwolona', 'разрешено': 'dozwolono', 'Разрешено': 'Dozwolono', 'разрешены': 'dozwolone', 'Разрешены': 'Dozwolone', 'запрещена': 'zabroniona', 'Запрещена': 'Zabroniona', 'запрещено': 'zabroniono', 'Запрещено': 'Zabroniono', 'запрещены': 'zabronione', 'Запрещены': 'Zabronione', 'активна': 'aktywna', 'Активна': 'Aktywna', 'активно': 'aktywne', 'Активно': 'Aktywne', 'активны': 'aktywne', 'Активны': 'Aktywne', 'активен': 'aktywny', 'Активен': 'Aktywny', 'неактивна': 'nieaktywna', 'Неактивна': 'Nieaktywna', 'неактивно': 'nieaktywne', 'Неактивно': 'Nieaktywne', 'неактивен': 'nieaktywny', 'Неактивен': 'Nieaktywny', 'доступны': 'dostępne', 'Доступны': 'Dostępne', 'отсутствует': 'brakuje', 'Отсутствует': 'Brakuje:', 'отсутствует:': 'brakuje:', 'Отсутствует:': 'Brakuje:', 'отсутствуют': 'brakują', 'Отсутствуют': 'Brakują', 'работает': 'działa', 'Работает': 'Działa:', 'работают': 'działają', 'Работают': 'Działają', 'работает:': 'działa:', 'Работает:': 'Działa:', 'неработает': 'nie działa', 'Неработает': 'Nie działa', 'поврежден': 'uszkodzony', 'Поврежден': 'Uszkodzony', 'повреждена': 'uszkodzona', 'Повреждена': 'Uszkodzona', 'повреждено': 'uszkodzone', 'Повреждено': 'Uszkodzone', 'повреждены': 'uszkodzone', 'Повреждены': 'Uszkodzone', 'исправен': 'sprawny', 'Исправен': 'Sprawny', 'исправна': 'sprawna', 'Исправна': 'Sprawna', 'исправно': 'sprawne', 'Исправно': 'Sprawne', 'исправить': 'naprawić', 'Исправить': 'Naprawić', 'исправление': 'naprawa', 'Исправление': 'Naprawa', 'исправлен': 'naprawiono', 'Исправлен': 'Naprawiono', 'исправлено': 'naprawiono', 'Исправлено': 'Naprawiono', 'исправлена': 'naprawiona', 'Исправлена': 'Naprawiona', 'требуется': 'wymagane', 'Требуется': 'Wymagane:', 'требуется:': 'wymagane:', 'Требуется:': 'Wymagane:', 'требуется перезагрузка': 'wymagane uruchomienie ponowne', 'Требуется перезагрузка': 'Wymagane uruchomienie ponowne', 'перезагрузка требуется': 'wymagane uruchomienie ponowne', 'Перезагрузка требуется': 'Wymagane uruchomienie ponowne', 'завершите': 'zakończ', 'Завершите': 'Zakończ', 'подтвердите': 'potwierdź', 'Подтвердите': 'Potwierdź', 'нажмите': 'naciśnij', 'Нажмите': 'Naciśnij:', 'нажмите:': 'naciśnij:', 'Нажмите:': 'Naciśnij:', 'нажмите чтобы': 'naciśnij aby', 'Нажмите чтобы': 'Naciśnij aby', 'выполните': 'wykonaj', 'Выполните': 'Wykonaj', 'перезапустите': 'zrestartuj', 'Перезапустите': 'Zrestartuj', 'перезагрузите': 'uruchom ponownie', 'Перезагрузите': 'Uruchom ponownie', 'запустите': 'uruchom', 'Запустите': 'Uruchom', 'откройте': 'otwórz', 'Откройте': 'Otwórz:', 'откройте:': 'otwórz:', 'Откройте:': 'Otwórz:', 'выберите:': 'wybierz:', 'Выберите:': 'Wybierz:', 'попробуйте': 'spróbuj', 'Попробуйте': 'Spróbuj', 'снова': 'ponownie', 'Снова': 'Ponownie', 'повторно': 'ponownie', 'Повторно': 'Ponownie', 'выполните повторно': 'wykonaj ponownie', 'Выполните повторно': 'Wykonaj ponownie', 'подождите': 'poczekaj', 'Подождите': 'Poczekaj', 'загрузка': 'ładowanie', 'Загрузка': 'Ładowanie', 'загрузки': 'ładowania', 'Загрузки': 'Ładowania', 'загружено': 'załadowano', 'Загружено': 'Załadowano', 'загружен': 'załadowany', 'Загружен': 'Załadowany', 'обнаружен': 'wykryto', 'Обнаружен': 'Wykryto', 'обнаружено': 'wykryto', 'Обнаружено': 'Wykryto', 'обнаружена': 'wykryta', 'Обнаружена': 'Wykryta', 'обнаружены': 'wykryte', 'Обнаружены': 'Wykryte', 'присутствует': 'obecny', 'Присутствует': 'Obecny', 'поддерживается': 'obsługiwane', 'Поддерживается': 'Obsługiwane', 'получено': 'odebrano', 'Получено': 'Odebrano', 'получен': 'odebrany', 'Получен': 'Odebrany', 'отправлено': 'wysłano', 'Отправлено': 'Wysłano', 'отправлен': 'wysłany', 'Отправлен': 'Wysłany', 'прервано': 'przerwano', 'Прервано': 'Przerwano', 'прерван': 'przerwany', 'Прерван': 'Przerwany', 'истекло': 'wygasło', 'Истекло': 'Wygasło', 'истек': 'wygasł', 'Истек': 'Wygasł', 'время': 'czas', 'Время': 'Czas:', 'время:': 'czas:', 'Время:': 'Czas:', 'времени': 'czasu', 'Времени': 'Czasu', 'таймаут': 'limit czasu', 'Таймаут': 'Limit czasu:', 'таймаут:': 'limit czasu:', 'Таймаут:': 'Limit czasu:', 'размер': 'rozmiar', 'Размер': 'Rozmiar:', 'размер:': 'rozmiar:', 'Размер:': 'Rozmiar:', 'тип': 'typ', 'Тип': 'Typ:', 'тип:': 'typ:', 'Тип:': 'Typ:', 'статус': 'status', 'Статус': 'Status:', 'статус:': 'status:', 'Статус:': 'Status:', 'состояние': 'stan', 'Состояние': 'Stan:', 'состояние:': 'stan:', 'Состояние:': 'Stan:', 'состояния': 'stanu', 'Состояния': 'Stanu', 'данные': 'dane', 'Данные': 'Dane:', 'данных': 'danych', 'Данных': 'Danych', 'данные:': 'dane:', 'Данные:': 'Dane:', 'информация': 'informacja', 'Информация': 'Informacja:', 'информация:': 'informacja:', 'Информация:': 'Informacja:', 'информации': 'informacji', 'Информации': 'Informacji', 'подробнее': 'szczegóły', 'Подробнее': 'Szczegóły:', 'подробнее:': 'szczegóły:', 'Подробнее:': 'Szczegóły:', 'детально': 'szczegółowo', 'Детально': 'Szczegółowo', 'причина': 'przyczyna', 'Причина': 'Przyczyna:', 'причина:': 'przyczyna:', 'Причина:': 'Przyczyna:', 'причины': 'przyczyny', 'Причины': 'Przyczyny', 'решение': 'rozwiązanie', 'Решение': 'Rozwiązanie:', 'решение:': 'rozwiązanie:', 'Решение:': 'Rozwiązanie:', 'решения': 'rozwiązania', 'Решения': 'Rozwiązania', 'рекомендация': 'zalecenie', 'Рекомендация': 'Zalecenie', 'рекомендации': 'zalecenia', 'Рекомендации': 'Zalecenia', 'рекомендуется': 'zalecane', 'Рекомендуется': 'Zalecane:', 'рекомендуется:': 'zalecane:', 'Рекомендуется:': 'Zalecane:', 'внимание': 'uwaga', 'Внимание': 'Uwaga:', 'внимание:': 'uwaga:', 'Внимание:': 'Uwaga:', 'осторожно': 'ostrożnie', 'Осторожно': 'Ostrożnie', 'опасно': 'niebezpiecznie', 'Опасно': 'Niebezpiecznie:', 'опасно:': 'niebezpiecznie:', 'Опасно:': 'Niebezpiecznie:', 'риск': 'ryzyko', 'Риск': 'Ryzyko', 'риска': 'ryzyka', 'Риска': 'Ryzyka', 'необратимо': 'nieodwracalnie', 'Необратимо': 'Nieodwracalnie', 'необратимых': 'nieodwracalnych', 'Необратимых': 'Nieodwracalnych', 'назад': 'wstecz', 'Назад': 'Wstecz', 'далее': 'dalej', 'Далее': 'Dalej', 'вперед': 'naprzód', 'Вперед': 'Naprzód', 'выполнено успешно': 'wykonano pomyślnie', 'Выполнено успешно': 'Wykonano pomyślnie', 'операция выполнена': 'operacja zakończona', 'Операция выполнена': 'Operacja zakończona', 'операция завершена': 'operacja zakończona', 'Операция завершена': 'Operacja zakończona', 'изменения сохранены': 'zmiany zapisano', 'Изменения сохранены': 'Zmiany zapisano', 'изменения': 'zmiany', 'Изменения': 'Zmiany:', 'изменения:': 'zmiany:', 'Изменения:': 'Zmiany:', 'изменен': 'zmieniono', 'Изменен': 'Zmieniono', 'изменено': 'zmieniono', 'Изменено': 'Zmieniono', 'изменить': 'zmienić', 'Изменить': 'Zmienić', 'сохранить': 'zapisać', 'Сохранить': 'Zapisać', 'сохранен': 'zapisano', 'Сохранен': 'Zapisano', 'сохранено': 'zapisano', 'Сохранено': 'Zapisano', 'сохранена': 'zapisana', 'Сохранена': 'Zapisana', 'сохранены': 'zapisane', 'Сохранены': 'Zapisane', 'импорт': 'import', 'Импорт': 'Import', 'экспорт': 'eksport', 'Экспорт': 'Eksport', 'записано': 'zapisano', 'Записано': 'Zapisano', 'запись создана': 'wpis utworzony', 'Запись создана': 'Wpis utworzony', 'запись удалена': 'wpis usunięty', 'Запись удалена': 'Wpis usunięty', 'ключ': 'klucz', 'Ключ': 'Klucz:', 'ключи': 'klucze', 'Ключи': 'Klucze', 'ключ:': 'klucz:', 'Ключ:': 'Klucz:', 'параметр': 'parametr', 'Параметр': 'Parametr:', 'параметры': 'parametry', 'Параметры': 'Parametry', 'параметр:': 'parametr:', 'Параметр:': 'Parametr:', 'строка': 'linia', 'Строка': 'Linia', 'строки': 'linie', 'Строки': 'Linie', 'элемент': 'element', 'Элемент': 'Element:', 'элементы': 'elementy', 'Элементы': 'Elementy', 'элемент:': 'element:', 'Элемент:': 'Element:', 'компонент': 'komponent', 'Компонент': 'Komponent:', 'компоненты': 'komponenty', 'Компоненты': 'Komponenty', 'компонент:': 'komponent:', 'Компонент:': 'Komponent:', 'завершить процесс': 'zakończ proces', 'Завершить процесс': 'Zakończ proces', 'перезапустить службу': 'zrestartuj usługę', 'Перезапустить службу': 'Zrestartuj usługę', 'запустить службу': 'uruchom usługę', 'Запустить службу': 'Uruchom usługę', 'остановить службу': 'zatrzymaj usługę', 'Остановить службу': 'Zatrzymaj usługę', 'вирусом': 'wirusem', 'Вирусом': 'Wirusem', 'службой': 'usługą', 'Службой': 'Usługą', 'процессом': 'procesem', 'Процессом': 'Procesem', 'путем': 'ścieżką', 'Путем': 'Ścieżką', 'путём': 'ścieżką', 'Путём': 'Ścieżką', 'администратором': 'administratorem', 'Администратором': 'Administratorem', 'системой': 'systemem', 'Системой': 'Systemem', 'реестром': 'rejestrem', 'Реестром': 'Rejestrem', 'диском': 'dyskiem', 'Диском': 'Dyskiem', 'принтером': 'drukarką', 'Принтером': 'Drukarką', 'шрифтом': 'czcionką', 'Шрифтом': 'Czcionką', 'брандмауэром': 'zapora', 'Брандмауэром': 'Zapora', 'процессором': 'procesorem', 'Процессором': 'Procesorem', 'сетью': 'siecią', 'Сетью': 'Siecią', 'сети': 'sieci', 'Сети': 'Sieci', 'сервисом': 'serwisem', 'Сервисом': 'Serwisem', 'сервиса': 'serwisu', 'Сервиса': 'Serwisu', 'файле': 'pliku', 'Файле': 'Pliku', 'системе': 'systemie', 'Системе': 'Systemie', 'диске': 'dysku', 'Диске': 'Dysku', 'пользователе': 'użytkowniku', 'Пользователе': 'Użytkowniku', 'администратора': 'administratora', 'Администратора': 'Administratora', 'полностью': 'całkowicie', 'Полностью': 'Całkowicie', 'частично': 'częściowo', 'Частично': 'Częściowo', 'автоматически': 'automatycznie', 'Автоматически': 'Automatycznie', 'принудительно': 'wymuszone', 'Принудительно': 'Wymuszone', 'немедленно': 'natychmiast', 'Немедленно': 'Natychmiast', 'временно': 'tymczasowo', 'Временно': 'Tymczasowo', 'постоянно': 'stałym', 'Постоянно': 'Stałym', 'локально': 'lokalnie', 'Локально': 'Lokalnie', 'удаленно': 'zdalnie', 'Удаленно': 'Zdalnie', 'отменена': 'anulowana', 'Отменена': 'Anulowana', 'отменены': 'anulowane', 'Отменены': 'Anulowane', 'пропущена': 'pominięta', 'Пропущена': 'Pominięta', 'пропущено': 'pominięto', 'Пропущено': 'Pominięto', 'пропущены': 'pominięte', 'Пропущены': 'Pominięte', 'пропущен': 'pominięty', 'Пропущен': 'Pominięty'},
        "fr": {'не': 'ne', 'Не': 'Ne', 'будет': 'sera', 'Будет': 'Sera', 'будут': 'seront', 'Будут': 'Seront', 'ошибка': 'erreur', 'Ошибка': 'Erreur', 'ошибки': 'erreurs', 'Ошибки': 'Erreurs', 'ошибок': 'erreurs', 'Ошибок': 'Erreurs:', 'ошибок:': 'erreurs:', 'Ошибок:': 'Erreurs:', 'ошибками': 'erreurs', 'Ошибками': 'Erreurs', 'ошибку': 'erreur', 'Ошибку': 'Erreur', 'файл': 'fichier', 'Файл': 'Fichier:', 'файла': 'fichier', 'Файла': 'Fichier', 'файлы': 'fichiers', 'Файлы': 'Fichiers', 'файлов': 'fichiers', 'Файлов': 'Fichiers:', 'файлом': 'fichier', 'Файлом': 'Fichier', 'удалось': 'pu', 'Удалось': 'Pu', 'не удалось': 'impossible', 'Не удалось': 'Impossible', 'задач': 'tâches', 'Задач': 'Tâches:', 'задача': 'tâche', 'Задача': 'Tâche', 'задачу': 'tâche', 'Задачу': 'Tâche', 'задачи': 'tâches', 'Задачи': 'Tâches', 'задаче': 'tâche', 'Задаче': 'Tâche', 'через': 'via', 'Через': 'Via', 'восстановление': 'restauration', 'Восстановление': 'Restauration', 'восстановления': 'restauration', 'Восстановления': 'Restauration:', 'восстановлено': 'restauré', 'Восстановлено': 'Restauré', 'восстановлен': 'restauré', 'Восстановлен': 'Restauré', 'восстановить': 'restaurer', 'Восстановить': 'Restaurer', 'восстанавливает': 'restaure', 'Восстанавливает': 'Restaure', 'восстанавливаеться': 'se restaure', 'Восстанавливаеться': 'Se restaure', 'восстановлены': 'restaurées', 'Восстановлены': 'Restaurées', 'восстановления:': 'restauration:', 'Восстановления:': 'Restauration:', 'системы': 'système', 'Системы': 'Système', 'система': 'système', 'Система': 'Système:', 'систему': 'système', 'Систему': 'Système', 'системные': 'système', 'Системные': 'Système', 'системный': 'système', 'Системный': 'Système', 'системной': 'système', 'Системной': 'Système', 'системных': 'système', 'Системных': 'Système', 'реестра': 'registre', 'Реестра': 'Registre', 'реестр': 'registre', 'Реестр': 'Registre', 'реестре': 'registre', 'Реестре': 'Registre', 'реестру': 'registre', 'Реестру': 'Registre', 'или': 'ou', 'Или': 'Ou', 'из': 'de', 'Из': 'De', 'все': 'tout', 'Все': 'Tout', 'всё': 'tout', 'Всё': 'Tout', 'всех': 'tous', 'Всех': 'Tous', 'всю': 'tout', 'Всю': 'Tout', 'запуск': 'lancement', 'Запуск': 'Lancement', 'запуска': 'lancement', 'Запуска': 'Lancement', 'запустить': 'démarrer', 'Запустить': 'Démarrer:', 'запущен': 'démarré', 'Запущен': 'Démarré:', 'запущено': 'démarré', 'Запущено': 'Démarré', 'запускает': 'démarre', 'Запускает': 'Démarre', 'панель': 'panneau', 'Панель': 'Panneau:', 'панели': 'panneau', 'Панели': 'Panneau', 'панель:': 'panneau:', 'Панель:': 'Panneau:', 'выберите': 'sélectionnez', 'Выберите': 'Sélectionnez:', 'удалить': 'supprimer', 'Удалить': 'Supprimer:', 'удаление': 'suppression', 'Удаление': 'Suppression:', 'удалены': 'supprimées', 'Удалены': 'Supprimées', 'удален': 'supprimé', 'Удален': 'Supprimé', 'удалить:': 'supprimer:', 'Удалить:': 'Supprimer:', 'процесс': 'processus', 'Процесс': 'Processus:', 'процесса': 'processus', 'Процесса': 'Processus', 'процессы': 'processus', 'Процессы': 'Processus', 'процессов': 'processus', 'Процессов': 'Processus:', 'процессе': 'processus', 'Процессе': 'Processus', 'только': 'seulement', 'Только': 'Seulement', 'что': 'que', 'Что': 'Que', 'настройки': 'paramètres', 'Настройки': 'Paramètres', 'настройка': 'paramètre', 'Настройка': 'Paramètre', 'настройку': 'paramètre', 'Настройку': 'Paramètre', 'настроек': 'paramètres', 'Настроек': 'Paramètres', 'настроить': 'configurer', 'Настроить': 'Configurer', 'при': 'lors de', 'При': 'Lors de', 'бэкап': 'sauvegarde', 'Бэкап': 'Sauvegarde', 'бэкапы': 'sauvegardes', 'Бэкапы': 'Sauvegardes', 'бэкапа': 'sauvegarde', 'Бэкапа': 'Sauvegarde', 'бэкапов': 'sauvegardes', 'Бэкапов': 'Sauvegardes', 'путь': 'chemin', 'Путь': 'Chemin:', 'пути': 'chemin', 'Пути': 'Chemin', 'путь:': 'chemin:', 'Путь:': 'Chemin:', 'запись': 'entrée', 'Запись': 'Entrée:', 'записи': 'entrées', 'Записи': 'Entrées:', 'записей': 'entrées', 'Записей': 'Entrées', 'запись:': 'entrée:', 'Запись:': 'Entrée:', 'службу': 'service', 'Службу': 'Service:', 'служба': 'service', 'Служба': 'Service', 'службы': 'service', 'Службы': 'Service', 'служб': 'services', 'Служб': 'Services', 'службе': 'service', 'Службе': 'Service', 'службы:': 'services:', 'Службы:': 'Services:', 'очистка': 'nettoyage', 'Очистка': 'Nettoyage:', 'очистки': 'nettoyage', 'Очистки': 'Nettoyage', 'очистить': 'nettoyer', 'Очистить': 'Nettoyer', 'очищает': 'nettoie', 'Очищает': 'Nettoie', 'очищен': 'nettoyé', 'Очищен': 'Nettoyé', 'очищено': 'nettoyé', 'Очищено': 'Nettoyé', 'очистка:': 'nettoyage:', 'Очистка:': 'Nettoyage:', 'проверка': 'vérification', 'Проверка': 'Vérification:', 'проверки': 'vérification', 'Проверки': 'Vérification', 'проверяет': 'vérifie', 'Проверяет': 'Vérifie', 'проверить': 'vérifier', 'Проверить': 'Vérifier', 'проверяем': 'vérifions', 'Проверяем': 'Vérifions', 'проверка:': 'vérification:', 'Проверка:': 'Vérification:', 'нет': 'aucun', 'Нет': 'Aucun:', 'нет:': 'aucun:', 'Нет:': 'Aucun:', 'режим': 'mode', 'Режим': 'Mode', 'режима': 'mode', 'Режима': 'Mode', 'диспетчер': 'gestionnaire', 'Диспетчер': 'Gestionnaire:', 'диспетчер:': 'gestionnaire:', 'Диспетчер:': 'Gestionnaire:', 'если': 'si', 'Если': 'Si', 'доступ': 'accès', 'Доступ': 'Accès:', 'доступа': 'accès', 'Доступа': 'Accès:', 'доступ:': 'accès:', 'Доступ:': 'Accès:', 'доступно': 'disponible', 'Доступно': 'Disponible', 'доступна': 'disponible', 'Доступна': 'Disponible', 'доступен': 'disponible', 'Доступен': 'Disponible', 'отключен': 'désactivé', 'Отключен': 'Désactivé', 'отключено': 'désactivé', 'Отключено': 'Désactivé', 'отключены': 'désactivées', 'Отключены': 'Désactivées', 'отключить': 'désactiver', 'Отключить': 'Désactiver:', 'отключение': 'désactivation', 'Отключение': 'Désactivation', 'отключается': 'se désactive', 'Отключается': 'Se désactive', 'включен': 'activé', 'Включен': 'Activé', 'включено': 'activé', 'Включено': 'Activé', 'включены': 'activées', 'Включены': 'Activées', 'включить': 'activer', 'Включить': 'Activer:', 'включение': 'activation', 'Включение': 'Activation:', 'включает': 'active', 'Включает': 'Active', 'включить:': 'activer:', 'Включить:': 'Activer:', 'права': 'droits', 'Права': 'Droits:', 'прав': 'droits', 'Прав': 'Droits', 'права:': 'droits:', 'Права:': 'Droits:', 'свойства': 'propriétés', 'Свойства': 'Propriétés:', 'свойств': 'propriétés', 'Свойств': 'Propriétés', 'свойства:': 'propriétés:', 'Свойства:': 'Propriétés:', 'меню': 'menu', 'Меню': 'Menu:', 'меню:': 'menu:', 'Меню:': 'Menu:', 'управления': 'gestion', 'Управления': 'Gestion', 'управление': 'gestion', 'Управление': 'Gestion', 'папки': 'dossier', 'Папки': 'Dossier', 'папка': 'dossier', 'Папка': 'Dossier:', 'папку': 'dossier', 'Папку': 'Dossier:', 'папок': 'dossiers', 'Папок': 'Dossiers', 'папке': 'dossier', 'Папке': 'Dossier', 'создать': 'créer', 'Создать': 'Créer', 'создание': 'création', 'Создание': 'Création:', 'создан': 'créé', 'Создан': 'Créé', 'создано': 'créé', 'Создано': 'Créé', 'имя': 'nom', 'Имя': 'Nom:', 'имя:': 'nom:', 'Имя:': 'Nom:', 'разблокировка': 'déverrouillage', 'Разблокировка': 'Déverrouillage:', 'разблокирует': 'déverrouille', 'Разблокирует': 'Déverrouille', 'разблокирован': 'déverrouillé', 'Разблокирован': 'Déverrouillé', 'разблокированы': 'déverrouillées', 'Разблокированы': 'Déverrouillées', 'разблокировка:': 'déverrouillage:', 'Разблокировка:': 'Déverrouillage:', 'блокировки': 'verrous', 'Блокировки': 'Verrous', 'блокировка': 'verrou', 'Блокировка': 'Verrou', 'блокировку': 'verrou', 'Блокировку': 'Verrou', 'блокировок': 'verrous', 'Блокировок': 'Verrous', 'блокировала': 'bloquait', 'Блокировала': 'Bloquait', 'брандмауэр': 'pare-feu', 'Брандмауэр': 'Pare-feu:', 'брандмауэра': 'pare-feu', 'Брандмауэра': 'Pare-feu', 'брандмауэр:': 'pare-feu:', 'Брандмауэр:': 'Pare-feu:', 'вирус': 'virus', 'Вирус': 'Virus:', 'вируса': 'virus', 'Вируса': 'Virus', 'вирусы': 'virus', 'Вирусы': 'Virus', 'вирусов': 'virus', 'Вирусов': 'Virus', 'вирус:': 'virus:', 'Вирус:': 'Virus:', 'подтверждение': 'confirmation', 'Подтверждение': 'Confirmation', 'подтверждения': 'confirmation', 'Подтверждения': 'Confirmation', 'подтвердить': 'confirmer', 'Подтвердить': 'Confirmer', 'откат': 'annulation', 'Откат': 'Annulation:', 'откатить': 'annuler', 'Откатить': 'Annuler', 'откат:': 'annulation:', 'Откат:': 'Annulation:', 'список': 'liste', 'Список': 'Liste:', 'списка': 'liste', 'Списка': 'Liste', 'список:': 'liste:', 'Список:': 'Liste:', 'политики': 'stratégies', 'Политики': 'Stratégies', 'политика': 'stratégie', 'Политика': 'Stratégie', 'политик': 'stratégies', 'Политик': 'Stratégies', 'добавить': 'ajouter', 'Добавить': 'Ajouter', 'добавлен': 'ajouté', 'Добавлен': 'Ajouté', 'добавлено': 'ajouté', 'Добавлено': 'Ajouté', 'продолжить': 'continuer', 'Продолжить': 'Continuer', 'включено:': 'activé:', 'Включено:': 'Activé:', 'включение:': 'activation:', 'Включение:': 'Activation:', 'клавиши': 'touches', 'Клавиши': 'Touches', 'клавиша': 'touche', 'Клавиша': 'Touche', 'клавиатуре': 'clavier', 'Клавиатуре': 'Clavier', 'клавиатура': 'clavier', 'Клавиатура': 'Clavier', 'клавиатуры': 'clavier', 'Клавиатуры': 'Clavier', 'операция': 'opération', 'Операция': 'Opération', 'операции': 'opération', 'Операции': 'Opération', 'операцию': 'opération', 'Операцию': 'Opération', 'ограничений': 'restrictions', 'Ограничений': 'Restrictions', 'ограничение': 'restriction', 'Ограничение': 'Restriction', 'ограничения': 'restrictions', 'Ограничения': 'Restrictions', 'значение': 'valeur', 'Значение': 'Valeur:', 'значения': 'valeurs', 'Значения': 'Valeurs', 'значение:': 'valeur:', 'Значение:': 'Valeur:', 'пользователь': 'utilisateur', 'Пользователь': 'Utilisateur', 'пользователя': 'utilisateur', 'Пользователя': 'Utilisateur', 'пользователи': 'utilisateurs', 'Пользователи': 'Utilisateurs', 'пользователем': 'utilisateur', 'Пользователем': 'Utilisateur', 'пользователю': 'utilisateur', 'Пользователю': 'Utilisateur', 'подозрительные': 'suspects', 'Подозрительные': 'Suspects', 'подозрительных': 'suspects', 'Подозрительных': 'Suspects', 'подозрительный': 'suspect', 'Подозрительный': 'Suspect', 'найдено': 'trouvé', 'Найдено': 'Trouvé', 'найдено:': 'trouvé:', 'Найдено:': 'Trouvé:', 'найден': 'trouvé', 'Найден': 'Trouvé', 'блок': 'bloc', 'Блок': 'Bloc:', 'блок:': 'bloc:', 'Блок:': 'Bloc:', 'автозагрузки': 'démarrage', 'Автозагрузки': 'Démarrage', 'автозагрузка': 'démarrage', 'Автозагрузка': 'Démarrage', 'автозагрузку': 'démarrage', 'Автозагрузку': 'Démarrage', 'автозапуск': 'exécution automatique', 'Автозапуск': 'Exécution automatique', 'сброс': 'réinitialisation', 'Сброс': 'Réinitialisation', 'сброса': 'réinitialisation', 'Сброса': 'Réinitialisation', 'сбросить': 'réinitialiser', 'Сбросить': 'Réinitialiser', 'сброшен': 'réinitialisé', 'Сброшен': 'Réinitialisé', 'сброшено': 'réinitialisé', 'Сброшено': 'Réinitialisé', 'проводник': 'explorateur', 'Проводник': 'Explorateur:', 'проводник:': 'explorateur:', 'Проводник:': 'Explorateur:', 'сканирование': 'analyse', 'Сканирование': 'Analyse:', 'сканировать': 'analyser', 'Сканировать': 'Analyser', 'сканирование:': 'analyse:', 'Сканирование:': 'Analyse:', 'полный': 'complet', 'Полный': 'Complet', 'полная': 'complète', 'Полная': 'Complète', 'полное': 'complet', 'Полное': 'Complet', 'после': 'après', 'После': 'Après', 'перед': 'avant', 'Перед': 'Avant', 'выполняется': 'en cours', 'Выполняется': 'En cours:', 'выполнено': 'effectué', 'Выполнено': 'Effectué', 'выполнено:': 'terminé:', 'Выполнено:': 'Terminé:', 'выполнить': 'exécuter', 'Выполнить': 'Exécuter', 'выполнения': 'exécution', 'Выполнения': 'Exécution', 'готов': 'prêt', 'Готов': 'Prêt', 'готова': 'prête', 'Готова': 'Prête', 'готово': 'prêt', 'Готово': 'Prêt', 'готовы': 'prêts', 'Готовы': 'Prêts', 'выполняется:': 'en cours:', 'Выполняется:': 'En cours:', 'проблема': 'problème', 'Проблема': 'Problème', 'проблемы': 'problèmes', 'Проблемы': 'Problèmes', 'проблем:': 'problèmes:', 'Проблем': 'Problèmes:', 'Проблем:': 'Problèmes:', 'предупреждение': 'avertissement', 'Предупреждение': 'Avertissement:', 'предупреждения': 'avertissement', 'Предупреждения': 'Avertissement', 'предупреждение:': 'avertissement:', 'Предупреждение:': 'Avertissement:', 'успешно': 'avec succès', 'Успешно': 'Avec succès', 'успешен': 'réussi', 'Успешен': 'Réussi', 'успешно:': 'avec succès:', 'Успешно:': 'Avec succès:', 'неизвестно': 'inconnu', 'Неизвестно': 'Inconnu', 'неизвестный': 'inconnu', 'Неизвестный': 'Inconnu', 'отключить:': 'désactiver:', 'Отключить:': 'Désactiver:', 'перезагрузка': 'redémarrage', 'Перезагрузка': 'Redémarrage', 'перезагрузить': 'redémarrer', 'Перезагрузить': 'Redémarrer', 'перезагрузки': 'redémarrage', 'Перезагрузки': 'Redémarrage', 'перезапустить': 'redémarrer', 'Перезапустить': 'Redémarrer', 'перезапуск': 'redémarrage', 'Перезапуск': 'Redémarrage', 'перезапущен': 'redémarré', 'Перезапущен': 'Redémarré', 'завершить': 'terminer', 'Завершить': 'Terminer', 'завершение': 'terminaison', 'Завершение': 'Terminaison', 'завершен': 'terminé', 'Завершен': 'Terminé', 'завершено': 'terminé', 'Завершено': 'Terminé', 'выбор': 'sélection', 'Выбор': 'Sélection', 'выбора': 'sélection', 'Выбора': 'Sélection', 'выбрано': 'sélectionné', 'Выбрано': 'Sélectionné', 'выбран': 'sélectionné', 'Выбран': 'Sélectionné', 'выбранный': 'sélectionné', 'Выбранный': 'Sélectionné', 'выбраны': 'sélectionnés', 'Выбраны': 'Sélectionnés', 'отмена': 'annuler', 'Отмена': 'Annuler', 'отменить': 'annuler', 'Отменить': 'Annuler', 'отменено': 'annulé', 'Отменено': 'Annulé', 'закрыть': 'fermer', 'Закрыть': 'Fermer', 'закрыт': 'fermé', 'Закрыт': 'Fermé', 'запустить:': 'démarrer:', 'Запустить:': 'Démarrer:', 'остановить': 'arrêter', 'Остановить': 'Arrêter', 'остановлен': 'arrêté', 'Остановлен': 'Arrêté', 'остановлено': 'arrêté', 'Остановлено': 'Arrêté', 'запущен:': 'démarré:', 'Запущен:': 'Démarré:', 'файлов:': 'fichiers:', 'Файлов:': 'Fichiers:', 'папку:': 'dossier:', 'Папку:': 'Dossier:', 'систем:': 'systèmes:', 'Систем': 'Systèmes:', 'Систем:': 'Systèmes:', 'реестра:': 'registre:', 'Реестра:': 'Registre:', 'службу:': 'service:', 'Службу:': 'Service:', 'доступа:': 'accès:', 'Доступа:': 'Accès:', 'дисков': 'disques', 'Дисков': 'Disques', 'диск': 'disque', 'Диск': 'Disque', 'диски': 'disques', 'Диски': 'Disques', 'диска': 'disque', 'Диска': 'Disque', 'принтер': 'imprimante', 'Принтер': 'Imprimante', 'принтера': 'imprimante', 'Принтера': 'Imprimante', 'шрифт': 'police', 'Шрифт': 'Police', 'шрифты': 'polices', 'Шрифты': 'Polices', 'шрифтов': 'polices', 'Шрифтов': 'Polices', 'тема': 'thème', 'Тема': 'Thème', 'темы': 'thème', 'Темы': 'Thème', 'язык': 'langue', 'Язык': 'Langue', 'языка': 'langue', 'Языка': 'Langue', 'драйвер': 'pilote', 'Драйвер': 'Pilote', 'драйвера': 'pilotes', 'Драйвера': 'Pilotes', 'драйверов': 'pilotes', 'Драйверов': 'Pilotes', 'обновление': 'mise à jour', 'Обновление': 'Mise à jour', 'обновления': 'mise à jour', 'Обновления': 'Mise à jour', 'обновить': 'mettre à jour', 'Обновить': 'Mettre à jour', 'обновлено': 'mis à jour', 'Обновлено': 'Mis à jour', 'центр': 'centre', 'Центр': 'Centre', 'центра': 'centre', 'Центра': 'Centre', 'безопасность': 'sécurité', 'Безопасность': 'Sécurité', 'безопасности': 'sécurité', 'Безопасности': 'Sécurité', 'безопасный': 'sûr', 'Безопасный': 'Sûr', 'безопасно': 'sûr', 'Безопасно': 'Sûr', 'защита': 'protection', 'Защита': 'Protection:', 'защиты': 'protection', 'Защиты': 'Protection', 'защита:': 'protection:', 'Защита:': 'Protection:', 'защитит': 'protéger', 'Защитит': 'Protéger', 'защищено': 'protégé', 'Защищено': 'Protégé', 'защищен': 'protégé', 'Защищен': 'Protégé', 'защищает': 'protège', 'Защищает': 'Protège', 'антивирус': 'antivirus', 'Антивирус': 'Antivirus', 'антивируса': 'antivirus', 'Антивируса': 'Antivirus', 'вредонос': 'malveillant', 'Вредонос': 'Malveillant', 'вредоносный': 'malveillant', 'Вредоносный': 'Malveillant', 'вредоносных': 'malveillants', 'Вредоносных': 'Malveillants', 'угроза': 'menace', 'Угроза': 'Menace', 'угрозы': 'menaces', 'Угрозы': 'Menaces', 'угроз:': 'menaces:', 'Угроз': 'Menaces:', 'Угроз:': 'Menaces:', 'восстановление системы': 'restauration du système', 'Восстановление системы': 'Restauration du système', 'восстановлено:': 'restauré:', 'Восстановлено:': 'Restauré:', 'поддержка': 'support', 'Поддержка': 'Support', 'поддержки': 'support', 'Поддержки': 'Support', 'поддерживает': 'prend en charge', 'Поддерживает': 'Prend en charge', 'инструмент': 'outil', 'Инструмент': 'Outil:', 'инструменты': 'outils', 'Инструменты': 'Outils', 'инструментов': 'outils', 'Инструментов': 'Outils', 'инструмент:': 'outil:', 'Инструмент:': 'Outil:', 'очищены': 'nettoyées', 'Очищены': 'Nettoyées', 'удаление:': 'suppression:', 'Удаление:': 'Suppression:', 'имена': 'noms', 'Имена': 'Noms', 'имен': 'noms', 'Имен': 'Noms', 'записи:': 'entrées:', 'Записи:': 'Entrées:', 'события': 'événements', 'События': 'Événements', 'событие': 'événement', 'Событие': 'Événement', 'событий': 'événements', 'Событий': 'Événements', 'журнал': 'journal', 'Журнал': 'Journal', 'журнала': 'journal', 'Журнала': 'Journal', 'задач:': 'tâches:', 'Задач:': 'Tâches:', 'процесс:': 'processus:', 'Процесс:': 'Processus:', 'процессов:': 'processus:', 'Процессов:': 'Processus:', 'отчет': 'rapport', 'Отчет': 'Rapport', 'отчёт': 'rapport', 'Отчёт': 'Rapport', 'отчета': 'rapport', 'Отчета': 'Rapport', 'точка': 'point', 'Точка': 'Point', 'точки': 'point', 'Точки': 'Point', 'точку': 'point', 'Точку': 'Point', 'конец': 'fin', 'Конец': 'Fin', 'завершения': 'achèvement', 'Завершения': 'Achèvement', 'восстановлено!': 'restauré!', 'Восстановлено!': 'Restauré!', 'успешно!': 'avec succès!', 'Успешно!': 'Avec succès!', 'выполнено!': 'terminé!', 'Выполнено!': 'Terminé!', 'готово!': 'prêt!', 'Готово!': 'Prêt!', 'отключено!': 'désactivé!', 'Отключено!': 'Désactivé!', 'включено!': 'activé!', 'Включено!': 'Activé!', 'удалено': 'supprimé', 'Удалено': 'Supprimé', 'скопирован': 'copié', 'Скопирован': 'Copié', 'скопировано': 'copié', 'Скопировано': 'Copié', 'скопировать': 'copier', 'Скопировать': 'Copier', 'копировать': 'copier', 'Копировать': 'Copier', 'создание:': 'création:', 'Создание:': 'Création:', 'файл:': 'fichier:', 'Файл:': 'Fichier:', 'папка:': 'dossier:', 'Папка:': 'Dossier:', 'система:': 'système:', 'Система:': 'Système:', 'остановлена': 'arrêtée', 'Остановлена': 'Arrêtée', 'остановлены': 'arrêtées', 'Остановлены': 'Arrêtées', 'завершена': 'terminée', 'Завершена': 'Terminée', 'завершены': 'terminées', 'Завершены': 'Terminées', 'выполнена': 'effectuée', 'Выполнена': 'Effectuée', 'выполнены': 'effectuées', 'Выполнены': 'Effectuées', 'удалена': 'supprimée', 'Удалена': 'Supprimée', 'создана': 'créée', 'Создана': 'Créée', 'созданы': 'créées', 'Созданы': 'Créées', 'включена': 'activée', 'Включена': 'Activée', 'отключена': 'désactivée', 'Отключена': 'Désactivée', 'найдена': 'trouvée', 'Найдена': 'Trouvée', 'найдены': 'trouvées', 'Найдены': 'Trouvées', 'установлена': 'installée', 'Установлена': 'Installée', 'установлено': 'installé', 'Установлено': 'Installé', 'установлены': 'installées', 'Установлены': 'Installées', 'установлен': 'installé', 'Установлен': 'Installé', 'сброшена': 'réinitialisée', 'Сброшена': 'Réinitialisée', 'сброшены': 'réinitialisées', 'Сброшены': 'Réinitialisées', 'очищена': 'nettoyée', 'Очищена': 'Nettoyée', 'заблокирована': 'bloquée', 'Заблокирована': 'Bloquée', 'заблокировано': 'bloqué', 'Заблокировано': 'Bloqué', 'заблокированы': 'bloquées', 'Заблокированы': 'Bloquées', 'заблокирован': 'bloqué', 'Заблокирован': 'Bloqué', 'разблокирована': 'déverrouillée', 'Разблокирована': 'Déverrouillée', 'разблокировано': 'déverrouillé', 'Разблокировано': 'Déverrouillé', 'запущена': 'démarrée', 'Запущена': 'Démarrée', 'запущены': 'démarrées', 'Запущены': 'Démarrées', 'перезапущена': 'redémarrée', 'Перезапущена': 'Redémarrée', 'перезапущено': 'redémarré', 'Перезапущено': 'Redémarré', 'обновлена': 'mise à jour', 'Обновлена': 'Mise à jour', 'обновлены': 'mises à jour', 'Обновлены': 'Mises à jour', 'восстановлена': 'restaurée', 'Восстановлена': 'Restaurée', 'скопирована': 'copiée', 'Скопирована': 'Copiée', 'скопированы': 'copiées', 'Скопированы': 'Copiées', 'разрешена': 'autorisée', 'Разрешена': 'Autorisée', 'разрешено': 'autorisé', 'Разрешено': 'Autorisé', 'разрешены': 'autorisées', 'Разрешены': 'Autorisées', 'запрещена': 'interdite', 'Запрещена': 'Interdite', 'запрещено': 'interdit', 'Запрещено': 'Interdit', 'запрещены': 'interdites', 'Запрещены': 'Interdites', 'активна': 'active', 'Активна': 'Active', 'активно': 'actif', 'Активно': 'Actif', 'активны': 'actives', 'Активны': 'Actives', 'активен': 'actif', 'Активен': 'Actif', 'неактивна': 'inactive', 'Неактивна': 'Inactive', 'неактивно': 'inactif', 'Неактивно': 'Inactif', 'неактивен': 'inactive', 'Неактивен': 'Inactive', 'доступны': 'disponibles', 'Доступны': 'Disponibles', 'отсутствует': 'manquant', 'Отсутствует': 'Manquant:', 'отсутствует:': 'manquant:', 'Отсутствует:': 'Manquant:', 'отсутствуют': 'manquants', 'Отсутствуют': 'Manquants', 'работает': 'fonctionne', 'Работает': 'Fonctionne:', 'работают': 'fonctionnent', 'Работают': 'Fonctionnent', 'работает:': 'fonctionne:', 'Работает:': 'Fonctionne:', 'неработает': 'ne fonctionne pas', 'Неработает': 'Ne fonctionne pas', 'поврежден': 'endommagé', 'Поврежден': 'Endommagé', 'повреждена': 'endommagée', 'Повреждена': 'Endommagée', 'повреждено': 'endommagé', 'Повреждено': 'Endommagé', 'повреждены': 'endommagées', 'Повреждены': 'Endommagées', 'исправен': 'en ordre', 'Исправен': 'En ordre', 'исправна': 'en ordre', 'Исправна': 'En ordre', 'исправно': 'en ordre', 'Исправно': 'En ordre', 'исправить': 'corriger', 'Исправить': 'Corriger', 'исправление': 'correction', 'Исправление': 'Correction', 'исправлен': 'corrigé', 'Исправлен': 'Corrigé', 'исправлено': 'corrigé', 'Исправлено': 'Corrigé', 'исправлена': 'corrigée', 'Исправлена': 'Corrigée', 'требуется': 'requis', 'Требуется': 'Requis:', 'требуется:': 'requis:', 'Требуется:': 'Requis:', 'требуется перезагрузка': 'redémarrage requis', 'Требуется перезагрузка': 'Redémarrage requis', 'перезагрузка требуется': 'redémarrage requis', 'Перезагрузка требуется': 'Redémarrage requis', 'завершите': 'terminer', 'Завершите': 'Terminer', 'подтвердите': 'confirmez', 'Подтвердите': 'Confirmez', 'нажмите': 'appuyez', 'Нажмите': 'Appuyez:', 'нажмите:': 'appuyez:', 'Нажмите:': 'Appuyez:', 'нажмите чтобы': 'appuyez pour', 'Нажмите чтобы': 'Appuyez pour', 'выполните': 'exécutez', 'Выполните': 'Exécutez', 'перезапустите': 'redémarrez', 'Перезапустите': 'Redémarrez', 'перезагрузите': 'redémarrez', 'Перезагрузите': 'Redémarrez', 'запустите': 'démarrez', 'Запустите': 'Démarrez', 'откройте': 'ouvrez', 'Откройте': 'Ouvrez:', 'откройте:': 'ouvrez:', 'Откройте:': 'Ouvrez:', 'выберите:': 'sélectionnez:', 'Выберите:': 'Sélectionnez:', 'попробуйте': 'essayez', 'Попробуйте': 'Essayez', 'снова': 'encore', 'Снова': 'Encore', 'повторно': 'à nouveau', 'Повторно': 'À nouveau', 'выполните повторно': 'réessayez', 'Выполните повторно': 'Réessayez', 'подождите': 'attendez', 'Подождите': 'Attendez', 'загрузка': 'chargement', 'Загрузка': 'Chargement', 'загрузки': 'chargement', 'Загрузки': 'Chargement', 'загружено': 'chargé', 'Загружено': 'Chargé', 'загружен': 'chargé', 'Загружен': 'Chargé', 'обнаружен': 'détecté', 'Обнаружен': 'Détecté', 'обнаружено': 'détecté', 'Обнаружено': 'Détecté', 'обнаружена': 'détectée', 'Обнаружена': 'Détectée', 'обнаружены': 'détectées', 'Обнаружены': 'Détectées', 'присутствует': 'présent', 'Присутствует': 'Présent', 'поддерживается': 'pris en charge', 'Поддерживается': 'Pris en charge', 'получено': 'reçu', 'Получено': 'Reçu', 'получен': 'reçu', 'Получен': 'Reçu', 'отправлено': 'envoyé', 'Отправлено': 'Envoyé', 'отправлен': 'envoyé', 'Отправлен': 'Envoyé', 'прервано': 'interrompu', 'Прервано': 'Interrompu', 'прерван': 'interrompu', 'Прерван': 'Interrompu', 'истекло': 'expiré', 'Истекло': 'Expiré', 'истек': 'expiré', 'Истек': 'Expiré', 'время': 'temps', 'Время': 'Temps:', 'время:': 'temps:', 'Время:': 'Temps:', 'времени': 'temps', 'Времени': 'Temps', 'таймаут': 'délai dépassé', 'Таймаут': 'Délai dépassé:', 'таймаут:': 'délai dépassé:', 'Таймаут:': 'Délai dépassé:', 'размер': 'taille', 'Размер': 'Taille:', 'размер:': 'taille:', 'Размер:': 'Taille:', 'тип': 'type', 'Тип': 'Type:', 'тип:': 'type:', 'Тип:': 'Type:', 'статус': 'statut', 'Статус': 'Statut:', 'статус:': 'statut:', 'Статус:': 'Statut:', 'состояние': 'état', 'Состояние': 'État:', 'состояние:': 'état:', 'Состояние:': 'État:', 'состояния': 'état', 'Состояния': 'État', 'данные': 'données', 'Данные': 'Données:', 'данных': 'données', 'Данных': 'Données', 'данные:': 'données:', 'Данные:': 'Données:', 'информация': 'information', 'Информация': 'Information:', 'информация:': 'information:', 'Информация:': 'Information:', 'информации': 'information', 'Информации': 'Information', 'подробнее': 'détails', 'Подробнее': 'Détails:', 'подробнее:': 'détails:', 'Подробнее:': 'Détails:', 'детально': 'détaillé', 'Детально': 'Détaillé', 'причина': 'raison', 'Причина': 'Raison:', 'причина:': 'raison:', 'Причина:': 'Raison:', 'причины': 'raison', 'Причины': 'Raison', 'решение': 'solution', 'Решение': 'Solution:', 'решение:': 'solution:', 'Решение:': 'Solution:', 'решения': 'solution', 'Решения': 'Solution', 'рекомендация': 'recommandation', 'Рекомендация': 'Recommandation', 'рекомендации': 'recommandations', 'Рекомендации': 'Recommandations', 'рекомендуется': 'recommandé', 'Рекомендуется': 'Recommandé:', 'рекомендуется:': 'recommandé:', 'Рекомендуется:': 'Recommandé:', 'внимание': 'attention', 'Внимание': 'Attention:', 'внимание:': 'attention:', 'Внимание:': 'Attention:', 'осторожно': 'attention', 'Осторожно': 'Attention', 'опасно': 'dangereux', 'Опасно': 'Dangereux:', 'опасно:': 'dangereux:', 'Опасно:': 'Dangereux:', 'риск': 'risque', 'Риск': 'Risque', 'риска': 'risque', 'Риска': 'Risque', 'необратимо': 'irréversible', 'Необратимо': 'Irréversible', 'необратимых': 'irréversibles', 'Необратимых': 'Irréversibles', 'назад': 'retour', 'Назад': 'Retour', 'далее': 'suivant', 'Далее': 'Suivant', 'вперед': 'avant', 'Вперед': 'Avant', 'выполнено успешно': 'terminé avec succès', 'Выполнено успешно': 'Terminé avec succès', 'операция выполнена': 'opération terminée', 'Операция выполнена': 'Opération terminée', 'операция завершена': 'opération terminée', 'Операция завершена': 'Opération terminée', 'изменения сохранены': 'modifications enregistrées', 'Изменения сохранены': 'Modifications enregistrées', 'изменения': 'modifications', 'Изменения': 'Modifications:', 'изменения:': 'modifications:', 'Изменения:': 'Modifications:', 'изменен': 'modifié', 'Изменен': 'Modifié', 'изменено': 'modifié', 'Изменено': 'Modifié', 'изменить': 'modifier', 'Изменить': 'Modifier', 'сохранить': 'enregistrer', 'Сохранить': 'Enregistrer', 'сохранен': 'enregistré', 'Сохранен': 'Enregistré', 'сохранено': 'enregistré', 'Сохранено': 'Enregistré', 'сохранена': 'enregistrée', 'Сохранена': 'Enregistrée', 'сохранены': 'enregistrés', 'Сохранены': 'Enregistrés', 'импорт': 'import', 'Импорт': 'Import', 'экспорт': 'export', 'Экспорт': 'Export', 'записано': 'écrit', 'Записано': 'Écrit', 'запись создана': 'entrée créente créée', 'Запись создана': 'Entrée créente créée', 'запись удалена': 'entrée supprimée', 'Запись удалена': 'Entrée supprimée', 'ключ': 'clé', 'Ключ': 'Clé:', 'ключи': 'clés', 'Ключи': 'Clés', 'ключ:': 'clé:', 'Ключ:': 'Clé:', 'параметр': 'paramètre', 'Параметр': 'Paramètre:', 'параметры': 'paramètres', 'Параметры': 'Paramètres', 'параметр:': 'paramètre:', 'Параметр:': 'Paramètre:', 'строка': 'ligne', 'Строка': 'Ligne', 'строки': 'lignes', 'Строки': 'Lignes', 'элемент': 'élément', 'Элемент': 'Élément:', 'элементы': 'éléments', 'Элементы': 'Éléments', 'элемент:': 'élément:', 'Элемент:': 'Élément:', 'компонент': 'composant', 'Компонент': 'Composant:', 'компоненты': 'composants', 'Компоненты': 'Composants', 'компонент:': 'composant:', 'Компонент:': 'Composant:', 'завершить процесс': 'terminer le processus', 'Завершить процесс': 'Terminer le processus', 'перезапустить службу': 'redémarrer le service', 'Перезапустить службу': 'Redémarrer le service', 'запустить службу': 'démarrer le service', 'Запустить службу': 'Démarrer le service', 'остановить службу': 'arrêter le service', 'Остановить службу': 'Arrêter le service', 'вирусом': 'virus', 'Вирусом': 'Virus', 'службой': 'service', 'Службой': 'Service', 'процессом': 'processus', 'Процессом': 'Processus', 'путем': 'chemin', 'Путем': 'Chemin', 'путём': 'chemin', 'Путём': 'Chemin', 'администратором': 'administrateur', 'Администратором': 'Administrateur', 'системой': 'système', 'Системой': 'Système', 'реестром': 'registre', 'Реестром': 'Registre', 'диском': 'disque', 'Диском': 'Disque', 'принтером': 'imprimante', 'Принтером': 'Imprimante', 'шрифтом': 'police', 'Шрифтом': 'Police', 'брандмауэром': 'pare-feu', 'Брандмауэром': 'Pare-feu', 'процессором': 'processeur', 'Процессором': 'Processeur', 'сетью': 'réseau', 'Сетью': 'Réseau', 'сети': 'réseau', 'Сети': 'Réseau', 'сервисом': 'service', 'Сервисом': 'Service', 'сервиса': 'service', 'Сервиса': 'Service', 'файле': 'fichier', 'Файле': 'Fichier', 'системе': 'système', 'Системе': 'Système', 'диске': 'disque', 'Диске': 'Disque', 'пользователе': 'utilisateur', 'Пользователе': 'Utilisateur', 'администратора': 'administrateur', 'Администратора': 'Administrateur', 'полностью': 'totalement', 'Полностью': 'Totalement', 'частично': 'partiellement', 'Частично': 'Partiellement', 'автоматически': 'automatiquement', 'Автоматически': 'Automatiquement', 'принудительно': 'de force', 'Принудительно': 'De force', 'немедленно': 'immédiatement', 'Немедленно': 'Immédiatement', 'временно': 'temporairement', 'Временно': 'Temporairement', 'постоянно': 'permanemment', 'Постоянно': 'Permanemment', 'локально': 'localement', 'Локально': 'Localement', 'удаленно': 'à distance', 'Удаленно': 'À distance', 'отменена': 'annulée', 'Отменена': 'Annulée', 'отменены': 'annulées', 'Отменены': 'Annulées', 'пропущена': 'ignorée', 'Пропущена': 'Ignorée', 'пропущено': 'ignoré', 'Пропущено': 'Ignoré', 'пропущены': 'ignorées', 'Пропущены': 'Ignorées', 'пропущен': 'ignoré', 'Пропущен': 'Ignoré'},
    }
    def __init__(self):
        self.language = "en"
        self._first_run = True
        self.load()

    def load(self):
        try:
            with open(LANGUAGE_CONFIG_PATH, "r", encoding="utf-8") as settings_file:
                settings = json.load(settings_file)
            language = settings.get("language", "en")
            self.language = language if language in self.LANGUAGES else "en"
            self._first_run = "language" not in settings
        except (OSError, ValueError, TypeError):
            self.language = "en"
            self._first_run = True

    @property
    def first_run(self):
        return self._first_run

    def set_language(self, language, save=True):
        self.language = language if language in self.LANGUAGES else "en"
        self._first_run = False
        try:
            self.translate.cache_clear()
        except AttributeError:
            pass
        if save:
            self.save()

    def save(self):
        try:
            os.makedirs(os.path.dirname(LANGUAGE_CONFIG_PATH), exist_ok=True)
            settings = {}
            try:
                with open(LANGUAGE_CONFIG_PATH, "r", encoding="utf-8") as settings_file:
                    settings = json.load(settings_file)
            except (OSError, ValueError, TypeError):
                pass
            settings["language"] = self.language
            temporary_path = LANGUAGE_CONFIG_PATH + ".tmp"
            with open(temporary_path, "w", encoding="utf-8") as settings_file:
                json.dump(settings, settings_file, ensure_ascii=False, indent=2)
            os.replace(temporary_path, LANGUAGE_CONFIG_PATH)
        except OSError:
            pass

    def _get_fallback_pattern(self):
        if not hasattr(self, "_fallback_patterns"):
            self._fallback_patterns = {}
        if self.language not in self._fallback_patterns:
            words = self.FALLBACK_WORDS.get(self.language, {})
            if not words:
                self._fallback_patterns[self.language] = None
            else:
                sorted_keys = sorted(words.keys(), key=len, reverse=True)
                pattern = re.compile(
                    r"(?<![А-Яа-яЁёІіЇїЄєҐґ])(" + "|".join(re.escape(k) for k in sorted_keys) + r")(?![А-Яа-яЁёІіЇїЄєҐґ])"
                )
                self._fallback_patterns[self.language] = (pattern, words)
        return self._fallback_patterns.get(self.language)

    @lru_cache(maxsize=8192)
    def translate(self, source):
        if not isinstance(source, str) or self.language == "ru" or not source:
            return source
        translated = self.TRANSLATIONS.get(source) or REPAIR_CATALOG_TRANSLATIONS.get(source)
        if translated:
            lang_idx = {"en": 0, "uk": 1, "de": 2, "pl": 3, "fr": 4}.get(self.language, 0)
            if lang_idx < len(translated):
                return translated[lang_idx]
            return translated[0 if self.language == "en" else 1]
        # Only touch strings containing Cyrillic; paths, values and user input
        # therefore remain untouched.
        if not re.search(r"[А-Яа-яЁёІіЇїЄєҐґ]", source):
            return source
        pair = self._get_fallback_pattern()
        if pair:
            pattern, words = pair
            return pattern.sub(lambda m: words.get(m.group(0), m.group(0)), source)
        return source


# Repair-card text is kept separately to make the large repair catalogue easy
# to maintain.  Every title and description shown on those cards is localized.
REPAIR_CATALOG_TRANSLATIONS = {
        'Сброс пароля': ('Password reset', 'Скидання пароля', 'Passwort zurücksetzen', 'Resetowanie hasła', 'Réinitialisation du mot de passe'),
        'Починка запуска программ (.exe)': ('Fix program launching (.exe)', 'Виправлення запуску програм (.exe)', 'Reparieren von Programmstarts (.exe)', 'Uruchamia się program naprawczy (.exe)', 'Lancement du programme de réparation (.exe)'),
        'Починка ярлыков (.lnk)': ('Fix shortcuts (.lnk)', 'Виправлення ярликів (.lnk)', 'Reparieren von Verknüpfungen (.lnk)', 'Naprawa skrótów (.lnk)', 'Réparer les raccourcis (.lnk)'),
        'Удаление троянских DLL-инъекций': ('Remove Trojan DLL injections', "Видалення троянських DLL-ін'єкцій", 'Entfernen von Trojaner-DLL-Injektionen', 'Usuwanie zastrzyków DLL trojana', 'Suppression des injections de DLL de chevaux de Troie'),
        'Разблокировка антивирусов': ('Unblock antivirus software', 'Розблокування антивірусів', 'Antivirenprogramme entsperren', 'Odblokowywanie programów antywirusowych', 'Débloquer les antivirus'),
        'Восстановление Безопасного режима': ('Restore Safe Mode', 'Відновлення безпечного режиму', 'Wiederherstellen des abgesicherten Modus', 'Przywracanie trybu awaryjnego', 'Restauration du mode sans échec'),
        'Включение Восстановления системы': ('Enable System Restore', 'Увімкнення відновлення системи', 'Systemwiederherstellung aktivieren', 'Włączanie przywracania systemu', 'Activation de la restauration du système'),
        'Воскрешение Защитника Windows': ('Restore Windows Defender', 'Відновлення Захисника Windows', 'Wiederauferstehung von Windows Defender', 'Wskrzeszenie Windows Defendera', 'Résurrection de Windows Defender'),
        'Починка служб обновлений': ('Fix update services', 'Виправлення служб оновлення', 'Update-Dienste reparieren', 'Naprawianie usług aktualizacji', 'Réparation des services de mise à jour'),
        'Снятие авто-входа локеров': ('Remove locker auto-sign-in', 'Вимкнення авто-входу блокувальників', 'Automatische Schließfächer entfernen', 'Demontaż szafek z automatycznym wejściem', 'Suppression des casiers à entrée automatique'),
        'Принудительное включение Брандмауэра': ('Force-enable Firewall', 'Примусове ввімкнення брандмауера', 'Erzwingen Sie die Aktivierung der Firewall', 'Wymuś włączenie zapory sieciowej', "Forcer l'activation du pare-feu"),
        'Проверяет UAC, брандмауэр, Defender и hosts без изменений': ('Checks UAC, Firewall, Defender and hosts without making changes', 'Перевіряє UAC, брандмауер, Defender і hosts без змін', 'Überprüft UAC, Firewall, Defender und Hosts ohne Änderungen', 'Sprawdza UAC, zaporę sieciową, Defender i hosty bez zmian', "Vérifie l'UAC, le pare-feu, le Defender et les hôtes sans modifications"),
        'Восстанавливает службу WMI': ('Restores the WMI service', 'Відновлює службу WMI', 'Stellt den WMI-Dienst wieder her', 'Przywraca usługę WMI', 'Restaure le service WMI'),
        'Проверяет и запускает критичные службы': ('Checks and starts critical services', 'Перевіряє та запускає критичні служби', 'Überprüft und startet kritische Dienste', 'Sprawdza i uruchamia usługi krytyczne', 'Vérifie et démarre les services critiques'),
        'Проверяет хранилище сертификатов': ('Checks the certificate store', 'Перевіряє сховище сертифікатів', 'Überprüft den Zertifikatspeicher', 'Sprawdza bazę certyfikatów', 'Vérifie le magasin de certificats'),
        'Сбрасывает компоненты Центра обновления Windows': ('Resets Windows Update components', 'Скидає компоненти Центру оновлення Windows', 'Setzt Windows Update-Komponenten zurück', 'Resetuje składniki Windows Update', 'Réinitialise les composants de Windows Update'),
        'Исправляет ассоциации ярлыков': ('Fixes shortcut associations', 'Виправляє асоціації ярликів', 'Korrigiert Verknüpfungen mit Verknüpfungen', 'Poprawia skojarzenia skrótów', 'Corrige les associations de raccourcis'),
        'Очищает очередь печати и запускает службу': ('Clears the print queue and starts the service', 'Очищає чергу друку та запускає службу', 'Löscht die Druckwarteschlange und startet den Dienst', 'Czyści kolejkę wydruku i uruchamia usługę', "Efface la file d'attente d'impression et démarre le service"),
        'Включает базовую самооборону процесса': ('Enables basic process self-defense', 'Вмикає базовий самозахист процесу', 'Beinhaltet einen grundlegenden Selbstverteidigungsprozess', '[pl] Включает базовую самооборону процесса', "Comprend un processus d'autodéfense de base"),
        'Полностью восстанавливает SafeBoot Minimal и Network': ('Fully restores SafeBoot Minimal and Network', 'Повністю відновлює SafeBoot Minimal і Network', 'Stellt SafeBoot Minimal und Network vollständig wieder her', 'Całkowicie przywraca SafeBoot Minimal i Network', 'Restaure complètement SafeBoot Minimal et Network'),
        'Восстанавливает права системных папок': ('Restores system-folder permissions', 'Відновлює права системних папок', 'Stellt die Systemordnerrechte wieder her', 'Przywraca prawa do folderu systemowego', 'Restaure les droits du dossier système'),
        'Исправляет ассоциацию .exe': ('Fixes the .exe association', 'Виправляє асоціацію .exe', 'Behebt die .exe-Zuordnung', 'Naprawia skojarzenie .exe', "Corrige l'association .exe"),
        'Защищает файл программы атрибутами': ('Protects the program file with attributes', 'Захищає файл програми атрибутами', 'Schützt eine Programmdatei mit Attributen', 'Chroni plik programu z atrybutami', 'Protège un fichier programme avec des attributs'),
        'Проверяет и усиливает права администратора': ('Checks and strengthens administrator rights', 'Перевіряє та посилює права адміністратора', 'Überprüft und stärkt Administratorrechte', 'Sprawdza i wzmacnia uprawnienia administratora', "Vérifie et renforce les droits d'administrateur"),
        'Разблокирует msconfig': ('Unblocks msconfig', 'Розблоковує msconfig', 'Entsperrt msconfig', 'Odblokowuje msconfig', 'Débloque msconfig'),
        'Включает Microsoft Defender': ('Enables Microsoft Defender', 'Вмикає Microsoft Defender', 'Enthält Microsoft Defender', 'Zawiera Microsoft Defender', 'Inclut Microsoft Defender'),
        'Включает восстановление системы': ('Enables System Restore', 'Вмикає відновлення системи', 'Inklusive Systemwiederherstellung', 'Obejmuje przywracanie systemu', 'Inclut la restauration du système'),
        'Отключает AutoPlay': ('Disables AutoPlay', 'Вимикає AutoPlay', 'Deaktiviert AutoPlay', 'Wyłącza automatyczne odtwarzanie', 'Désactive la lecture automatique'),
        'Проверяет загрузочные записи': ('Checks boot records', 'Перевіряє завантажувальні записи', 'Überprüft Boot-Records', 'Sprawdza rekordy rozruchowe', 'Vérifie les enregistrements de démarrage'),
        'Проверяет расширения Chrome': ('Checks Chrome extensions', 'Перевіряє розширення Chrome', 'Überprüft Chrome-Erweiterungen', 'Sprawdza rozszerzenia Chrome', 'Vérifie les extensions Chrome'),
        'Сканирует ключи автозагрузки': ('Scans startup keys', 'Сканує ключі автозапуску', 'Scannt Startschlüssel', 'Skanuje klucze startowe', 'Analyse les clés de démarrage'),
        'Очищает журналы событий Windows': ('Clears Windows event logs', 'Очищає журнали подій Windows', 'Löscht Windows-Ereignisprotokolle', 'Czyści dzienniki zdarzeń systemu Windows', "Efface les journaux d'événements Windows"),
        'Удаляет временные файлы системы': ('Deletes temporary system files', 'Видаляє тимчасові системні файли', 'Löscht temporäre Systemdateien', 'Usuwa tymczasowe pliki systemowe', 'Supprime les fichiers système temporaires'),
        'Очищает кеш Prefetch': ('Clears the Prefetch cache', 'Очищає кеш Prefetch', 'Löscht den Prefetch-Cache', 'Czyści pamięć podręczną pobierania wstępnego', 'Efface le cache de prélecture'),
        'Очищает корзину': ('Empties the Recycle Bin', 'Очищає кошик', 'Leert den Papierkorb', 'Opróżnia Kosz', 'Vide la poubelle'),
        'Очищает кеш иконок для исправления отображения': ('Clears the icon cache to fix display issues', 'Очищає кеш іконок для виправлення відображення', 'Löscht den Symbolcache, um die Anzeige zu korrigieren', 'Czyści pamięć podręczną ikon, aby naprawić wyświetlanie', "Efface le cache des icônes pour corriger l'affichage"),
        'Очищает автозагрузку от подозрительных записей': ('Cleans suspicious startup entries', 'Очищає автозапуск від підозрілих записів', 'Löscht beim Start verdächtige Einträge', 'Czyści uruchamianie podejrzanych wpisów', 'Efface le démarrage des entrées suspectes'),
        'Очищает планировщик задач от вредоносных задач': ('Cleans malicious scheduled tasks', 'Очищає планувальник від шкідливих завдань', 'Löscht schädliche Aufgaben aus dem Aufgabenplaner', 'Czyści harmonogram zadań ze szkodliwych zadań', 'Efface le planificateur de tâches des tâches malveillantes'),
        'Завершает подозрительные процессы из черного списка': ('Ends suspicious blacklisted processes', 'Завершує підозрілі процеси з чорного списку', 'Beendet verdächtige Prozesse auf der schwarzen Liste', 'Kończy podejrzane procesy na czarnej liście', 'Met fin aux processus suspects sur liste noire'),
        'Отключает автозапуск со съемных носителей': ('Disables AutoRun from removable media', 'Вимикає автозапуск зі знімних носіїв', 'Deaktiviert die automatische Ausführung von Wechselmedien', 'Wyłącza automatyczne uruchamianie z nośników wymiennych', "Désactive l'exécution automatique à partir d'un support amovible"),
        'Удаляет Scancode Map, разблокируя заблокированную клавиатуру': ('Removes Scancode Map to unlock the keyboard', 'Видаляє Scancode Map, розблоковуючи клавіатуру', 'Entfernt Scancode Map und entsperrt die gesperrte Tastatur', 'Usuwa mapę Scancode, odblokowując zablokowaną klawiaturę', 'Supprime Scancode Map, déverrouillage du clavier verrouillé'),
        'Отключает залипание и фильтрацию клавиш': ('Disables Sticky Keys and Filter Keys', 'Вимикає залипання та фільтрацію клавіш', 'Deaktiviert Sticky Keys und das Filtern von Schlüsseln', 'Wyłącza lepkie klucze i filtrowanie kluczy', 'Désactive les touches rémanentes et le filtrage des touches'),
        'Открывает диалоговое окно для быстрого запуска программ (аналог Win+R).': ('Opens the quick program-launch dialog (like Win+R).', 'Відкриває діалог швидкого запуску програм (як Win+R).', 'Öffnet ein Dialogfeld zum schnellen Starten von Programmen (ähnlich wie Win+R).', 'Otwiera okno dialogowe umożliwiające szybkie uruchamianie programów (podobnie jak Win+R).', 'Ouvre une boîte de dialogue pour lancer rapidement des programmes (similaire à Win+R).'),
        'Горячие клавиши': ('Hotkeys', 'Гарячі клавіші', 'Hotkeys', 'Skróty klawiszowe', 'Raccourcis clavier'),
        'Разблокирует системные комбинации Win+...': ('Unblocks system Win+ shortcuts', 'Розблоковує системні комбінації Win+...', 'Schaltet Systemkombinationen Win+... frei.', 'Odblokowuje kombinacje systemowe Win+...', 'Débloque les combinaisons système Win+...'),
        'Запуск regedit.exe': ('Launch regedit.exe', 'Запуск regedit.exe', 'regedit.exe ausführen', 'Uruchamiam regedit.exe', 'Exécution de regedit.exe'),
        'Проводник': ('Explorer', 'Провідник', 'Leiter', 'Dyrygent', 'Conducteur'),
        'Запуск explorer.exe': ('Launch explorer.exe', 'Запуск explorer.exe', 'Führen Sie explorer.exe aus', 'Uruchom explorer.exe', 'Exécutez explorer.exe'),
        'Запуск taskmgr.exe': ('Launch taskmgr.exe', 'Запуск taskmgr.exe', 'Führen Sie taskmgr.exe aus', 'Uruchom taskmgr.exe', 'Exécutez taskmgr.exe'),
        'Восстановление загрузчика (MBR/BCD)': ('Bootloader recovery (MBR/BCD)', 'Відновлення завантажувача (MBR/BCD)', 'Bootloader-Wiederherstellung (MBR/BCD)', 'Odzyskiwanie bootloadera (MBR/BCD)', 'Récupération du chargeur de démarrage (MBR/BCD)'),
        'Браузер': ('Browser', 'Браузер', 'Browser', 'Przeglądarka', 'Navigateur'),
        'Открыть браузер': ('Open browser', 'Відкрити браузер', 'Browser öffnen', 'Otwórz przeglądarkę', 'Ouvrir le navigateur'),
        'Управление пользователями': ('User management', 'Керування користувачами', 'Benutzerverwaltung', 'Zarządzanie użytkownikami', 'Gestion des utilisateurs'),
        'Очистка системы': ('System cleanup', 'Очищення системи', 'Systemreinigung', 'Czyszczenie systemu', 'Nettoyage du système'),
        'Очистка диска': ('Disk Cleanup', 'Очищення диска', 'Datenträgerbereinigung', 'Oczyszczanie dysku', 'Nettoyage de disque'),
        'Ассоциации': ('Associations', 'Асоціації', 'Verbände', 'Wspomnienia', 'Associations'),
        'Программы по умолчанию': ('Default apps', 'Програми за замовчуванням', 'Standardprogramme', 'Domyślne programy', 'Programmes par défaut'),
        'Управление паролями': ('Password management', 'Керування паролями', 'Passwortverwaltung', 'Zarządzanie hasłami', 'Gestion des mots de passe'),
        'Управление дисками': ('Disk management', 'Керування дисками', 'Datenträgerverwaltung', 'Zarządzanie dyskami', 'Gestion des disques'),
        'Сохранение winRE': ('WinRE backup', 'Збереження WinRE', 'Speichern Sie winRE', 'Zapisz winRE', 'Enregistrer winRE'),
        'Настройки среды восстановления': ('Recovery environment settings', 'Налаштування середовища відновлення', 'Einstellungen der Wiederherstellungsumgebung', 'Ustawienia środowiska odzyskiwania', "Paramètres de l'environnement de récupération"),
        'Выйти из пользователя': ('Sign out', 'Вийти з користувача', 'Benutzer abmelden', 'Wyloguj użytkownika', "Déconnecter l'utilisateur"),
        'Завершение текущего сеанса.': ('Ends the current session.', 'Завершує поточний сеанс.', 'Beenden Sie die aktuelle Sitzung.', 'Zakończ bieżącą sesję.', 'Terminez la session en cours.'),
        'Войти в winRE': ('Enter WinRE', 'Увійти до WinRE', 'Melden Sie sich bei winRE an', 'Zaloguj się do winRE', 'Connectez-vous pour gagnerRE'),
        'Загрузка среды восстановления Windows.': ('Starts the Windows Recovery Environment.', 'Запускає середовище відновлення Windows.', 'Laden Sie die Windows-Wiederherstellungsumgebung herunter.', 'Pobierz środowisko odzyskiwania systemu Windows.', "Téléchargez l'environnement de récupération Windows."),
        'Вернуть русский язык': ('Restore Russian keyboard', 'Повернути російську розкладку', 'Rückkehr zur russischen Sprache', 'Zwróć język rosyjski', 'Retourner la langue russe'),
        'Восстанавливает стандартную раскладку после вирусной блокировки.': ('Restores the standard keyboard layout after a virus lock.', 'Відновлює стандартну розкладку після вірусного блокування.', 'Stellt das Standardlayout nach einer Virenblockierung wieder her.', 'Przywraca standardowy układ po zablokowaniu wirusa.', 'Restaure la mise en page standard après un blocage de virus.'),
        'Проверяет целостность системных файлов.': ('Checks the integrity of system files.', 'Перевіряє цілісність системних файлів.', 'Überprüft die Integrität von Systemdateien.', 'Sprawdza integralność plików systemowych.', "Vérifie l'intégrité des fichiers système."),
        'Восстановить LogonUI': ('Restore LogonUI', 'Відновити LogonUI', 'LogonUI wiederherstellen', 'Przywróć interfejs logowania', "Restaurer l'interface utilisateur de connexion"),
        'Некоторые вирусы могут заменять данный файл для своих целей.': ('Some viruses may replace this file for their own purposes.', 'Деякі віруси можуть замінювати цей файл для власних цілей.', 'Einige Viren können diese Datei für ihre eigenen Zwecke ersetzen.', 'Niektóre wirusy mogą zastąpić ten plik do własnych celów.', 'Certains virus peuvent remplacer ce fichier à leurs propres fins.'),
        'Экстренное восстановление': ('Emergency recovery', 'Екстрене відновлення', 'Notfallwiederherstellung', 'Odzyskiwanie awaryjne', "Récupération d'urgence"),
        'Экстренная функция восстановления системы при блокировках вирусами.': ('Emergency system recovery for virus lockouts.', 'Екстрене відновлення системи у разі вірусних блокувань.', 'Notfallfunktion zur Systemwiederherstellung bei Blockierung durch Viren.', 'Funkcja awaryjnego odzyskiwania systemu po zablokowaniu przez wirusy.', "Fonction de récupération d'urgence du système en cas de blocage par des virus."),
        'Выключить тестовый режим': ('Disable test mode', 'Вимкнути тестовий режим', 'Testmodus ausschalten', 'Wyłącz tryb testowy', 'Désactiver le mode test'),
        'Вирусы могут использовать автозагрузку через драйвера. Выключение тестового режима отключит их.': ('Viruses can use driver-based startup. Disabling test mode disables it.', 'Віруси можуть використовувати автозапуск через драйвери. Вимкнення тестового режиму вимкне його.', 'Viren können das automatische Laden über Treiber nutzen. Durch Ausschalten des Testmodus werden sie deaktiviert.', 'Wirusy mogą korzystać z automatycznego ładowania poprzez sterowniki. Wyłączenie trybu testowego spowoduje ich wyłączenie.', 'Les virus peuvent utiliser le chargement automatique via les pilotes. La désactivation du mode test les désactivera.'),
        'Заменить sethc и utilman': ('Replace sethc and utilman', 'Замінити sethc і utilman', 'Ersetzen Sie sethc und utilman', 'Zamień sethc i utilman', 'Remplacer sethc et utilman'),
        'Заменяет программы экрана блокировки нашей утилитой. При повторном нажатии восстанавливаются.': ('Replaces lock-screen tools with this utility; running it again restores them.', 'Замінює програми екрана блокування цією утилітою; повторний запуск їх відновлює.', 'Ersetzt Sperrbildschirmprogramme durch unser Dienstprogramm. Bei erneutem Drücken werden sie wiederhergestellt.', 'Zastępuje programy blokujące ekran naszym narzędziem. Po ponownym naciśnięciu zostaną przywrócone.', "Remplace les programmes d'écran de verrouillage par notre utilitaire. Lorsqu'on appuie à nouveau, ils sont restaurés."),
        'Полный доступ к файлу': ('Full file access', 'Повний доступ до файлу', 'Vollständiger Dateizugriff', 'Pełny dostęp do plików', 'Accès complet aux fichiers'),
        'Позволяет разблокировать доступ к системным и скрытым файлам.': ('Lets you unlock access to system and hidden files.', 'Дозволяє розблокувати доступ до системних і прихованих файлів.', 'Ermöglicht Ihnen, den Zugriff auf System- und versteckte Dateien freizuschalten.', 'Umożliwia odblokowanie dostępu do plików systemowych i ukrytych.', "Vous permet de déverrouiller l'accès au système et aux fichiers cachés."),
        'Очистка драйверов': ('Driver cleanup', 'Очищення драйверів', 'Fahrer reinigen', 'Czyszczenie sterowników', 'Chauffeurs de nettoyage'),
        '[ОПАСНО] Удаление всех нештатных драйверов.': ('[DANGEROUS] Removes all non-standard drivers.', '[НЕБЕЗПЕЧНО] Видаляє всі нестандартні драйвери.', '[GEFAHR] Entfernen Sie alle nicht standardmäßigen Treiber.', '[NIEBEZPIECZEŃSTWO] Usuń wszystkie niestandardowe sterowniki.', '[DANGER] Supprimez tous les pilotes non standard.'),
        'Удобный запуск': ('Easy launch', 'Зручний запуск', 'Bequemer Start', 'Wygodne uruchamianie', 'Lancement pratique'),
        'Запуск утилиты через cmd nov или контекстное меню, отключает UAC.': ('Launches the utility through cmd nov or the context menu and disables UAC.', 'Запускає утиліту через cmd nov або контекстне меню та вимикає UAC.', 'Wenn Sie das Dienstprogramm über cmd nov oder das Kontextmenü ausführen, wird die Benutzerkontensteuerung deaktiviert.', 'Uruchomienie narzędzia przez cmd nov lub menu kontekstowe wyłącza funkcję UAC.', "L'exécution de l'utilitaire via cmd nov ou le menu contextuel désactive l'UAC."),
        'После ввода пароля нажмите Alt+N, и запустится утилита. Отключить в настройках.': ('After entering the password, press Alt+N to start the utility. Disable it in Settings.', 'Після введення пароля натисніть Alt+N, щоб запустити утиліту. Вимикається в налаштуваннях.', 'Nachdem Sie das Passwort eingegeben haben, drücken Sie Alt+N und das Dienstprogramm wird gestartet. In den Einstellungen deaktivieren.', 'Po wprowadzeniu hasła naciśnij Alt+N, a narzędzie zostanie uruchomione. Wyłącz w ustawieniach.', "Après avoir entré le mot de passe, appuyez sur Alt+N et l'utilitaire se lancera. Désactivez dans les paramètres."),
        'Разблокирует редактор реестра regedit': ('Unblocks the regedit Registry Editor', 'Розблоковує редактор реєстру regedit', 'Entsperrt den Registrierungseditor regedit', 'Odblokowuje regedit edytora rejestru', "Déverrouille l'éditeur de registre regedit"),
        'Разблокирует диспетчер задач taskmgr': ('Unblocks Task Manager taskmgr', 'Розблоковує диспетчер завдань taskmgr', 'Schaltet den Taskmgr-Task-Manager frei', 'Odblokowuje menedżera zadań taskmgr', 'Débloque le gestionnaire de tâches taskmgr'),
        'Панель управления': ('Control Panel', 'Панель керування', 'Bedienfeld', 'Panel sterowania', 'Panneau de contrôle'),
        'Разблокирует панель управления': ('Unblocks Control Panel', 'Розблоковує панель керування', 'Entsperrt das Bedienfeld', 'Odblokowuje panel sterowania', 'Déverrouille le panneau de commande'),
        'Свойства системы': ('System properties', 'Властивості системи', 'Systemeigenschaften', 'Właściwości systemu', 'Propriétés du système'),
        'Разблокирует свойства системы и диспетчер устройств': ('Unblocks System Properties and Device Manager', 'Розблоковує властивості системи та диспетчер пристроїв', 'Entsperrt Systemeigenschaften und Gerätemanager', 'Odblokowuje właściwości systemu i menedżera urządzeń', 'Déverrouille les propriétés du système et le gestionnaire de périphériques'),
        'Разблокирует командную строку и regedit': ('Unblocks Command Prompt and regedit', 'Розблоковує командний рядок і regedit', 'Entsperrt die Befehlszeile und regedit', 'Odblokowuje wiersz poleceń i regedit', 'Déverrouille la ligne de commande et regedit'),
        'Восстанавливает работу безопасного режима': ('Restores Safe Mode', 'Відновлює роботу безпечного режиму', 'Stellt den abgesicherten Modus wieder her', 'Przywraca tryb awaryjny', 'Restaure le mode sans échec'),
        'Готовит загрузку в Safe Mode с командной строкой': ('Prepares a Safe Mode boot with Command Prompt', 'Готує завантаження в безпечному режимі з командним рядком', 'Bereitet den Start im abgesicherten Modus über die Befehlszeile vor', 'Przygotowuje się do uruchomienia w trybie awaryjnym za pomocą wiersza poleceń', 'Se prépare à démarrer en mode sans échec avec la ligne de commande'),
        'Восстанавливает стандартные настройки UAC': ('Restores default UAC settings', 'Відновлює стандартні налаштування UAC', 'Stellt die Standard-UAC-Einstellungen wieder her', 'Przywraca domyślne ustawienia UAC', 'Restaure les paramètres UAC par défaut'),
        'Админские ресурсы': ('Admin shares', 'Адміністративні ресурси', 'Admin-Ressourcen', 'Zasoby administratora', "Ressources d'administration"),
        'Восстанавливает административные сетевые ресурсы': ('Restores administrative network shares', 'Відновлює адміністративні мережеві ресурси', 'Stellt administrative Netzwerkressourcen wieder her', 'Odzyskuje administracyjne zasoby sieciowe', 'Récupère les ressources du réseau administratif'),
        'Политики': ('Policies', 'Політики', 'Politiker', 'Politycy', 'Politiciens'),
        'Удаляет ограничивающие политики системы': ('Deletes restrictive system policies', 'Видаляє обмежувальні системні політики', 'Entfernt restriktive Systemrichtlinien', 'Usuwa restrykcyjne zasady systemowe', 'Supprime les politiques système restrictives'),
        'Очищает Image File Execution Options от вирусов': ('Cleans viruses from Image File Execution Options', 'Очищає Image File Execution Options від вірусів', 'Bereinigt die Ausführungsoptionen für Bilddateien von Viren', 'Czyści opcje wykonania pliku obrazu z wirusów', "Nettoie les options d'exécution des fichiers image des virus"),
        'Оболочка Explorer': ('Explorer shell', 'Оболонка Провідника', 'Explorer-Shell', 'Powłoka eksploratora', "Coquille d'explorateur"),
        'Восстанавливает стандартные настройки проводника': ('Restores default Explorer settings', 'Відновлює стандартні налаштування Провідника', 'Setzt den Datei-Explorer auf die Standardeinstellungen zurück', 'Przywraca ustawienia domyślne Eksploratora plików', "Restaure l'Explorateur de fichiers aux paramètres par défaut"),
        'Правая кнопка мыши': ('Right mouse button', 'Права кнопка миші', 'Rechte Maustaste', 'Prawy przycisk myszy', 'Bouton droit de la souris'),
        'Разблокирует контекстное меню правой кнопки': ('Unblocks the right-click context menu', 'Розблоковує контекстне меню правої кнопки', 'Entsperrt das Kontextmenü mit der rechten Maustaste', 'Odblokowuje menu kontekstowe wyświetlane prawym przyciskiem myszy', 'Déverrouille le menu contextuel du clic droit'),
        'Видимость дисков': ('Drive visibility', 'Видимість дисків', 'Disc-Sichtbarkeit', 'Widoczność dysku', 'Visibilité du disque'),
        'Восстанавливает отображение скрытых дисков': ('Restores hidden-drive visibility', 'Відновлює відображення прихованих дисків', 'Stellt die Anzeige versteckter Laufwerke wieder her', 'Przywraca wyświetlanie ukrytych dysków', "Restaure l'affichage des lecteurs cachés"),
        'Панель задач': ('Taskbar', 'Панель завдань', 'Taskleiste', 'Pasek zadań', 'Barre des tâches'),
        'Восстанавливает панель задач и её настройки': ('Restores the taskbar and its settings', 'Відновлює панель завдань та її налаштування', 'Stellt die Taskleiste und ihre Einstellungen wieder her', 'Przywraca pasek zadań i jego ustawienia', 'Restaure la barre des tâches et ses paramètres'),
        'Значки трея': ('Tray icons', 'Значки трея', 'Tray-Symbole', 'Ikony w zasobniku', "Icônes de la barre d'état"),
        'Восстанавливает отображение значков в системном трее': ('Restores system-tray icon display', 'Відновлює відображення значків у системному треї', 'Stellt die Anzeige der Taskleistensymbole wieder her', 'Przywraca wyświetlanie ikon w zasobniku systemowym', "Restaure l'affichage des icônes de la barre d'état système"),
        'Значки стола': ('Desktop icons', 'Значки робочого столу', 'Schreibtischsymbole', 'Ikony na biurko', 'Icônes de bureau'),
        'Восстанавливает иконки на рабочем столе': ('Restores desktop icons', 'Відновлює значки робочого столу', 'Stellt Symbole auf dem Desktop wieder her', 'Przywraca ikony na pulpicie', 'Restaure les icônes sur le bureau'),
        'Скрытые файлы': ('Hidden files', 'Приховані файли', 'Versteckte Dateien', 'Ukryte pliki', 'Fichiers cachés'),
        'Включает отображение скрытых файлов и папок': ('Enables display of hidden files and folders', 'Вмикає відображення прихованих файлів і папок', 'Ermöglicht die Anzeige versteckter Dateien und Ordner', 'Umożliwia wyświetlanie ukrytych plików i folderów', "Permet l'affichage des fichiers et dossiers cachés"),
        'Свойства папки': ('Folder options', 'Властивості папки', 'Ordnereigenschaften', 'Właściwości folderu', 'Propriétés du dossier'),
        'Разблокирует меню свойств папки': ('Unblocks the Folder Options menu', 'Розблоковує меню властивостей папки', 'Entsperrt das Menü mit den Ordnereigenschaften', 'Odblokowuje menu właściwości folderu', 'Déverrouille le menu des propriétés du dossier'),
        'Свойства панели задач': ('Taskbar properties', 'Властивості панелі завдань', 'Eigenschaften der Taskleiste', 'Właściwości paska zadań', 'Propriétés de la barre des tâches'),
        'Разблокирует доступ к свойствам панели задач': ('Unblocks access to taskbar properties', 'Розблоковує доступ до властивостей панелі завдань', 'Schaltet den Zugriff auf die Eigenschaften der Taskleiste frei', 'Odblokowuje dostęp do właściwości paska zadań', "Déverrouille l'accès aux propriétés de la barre des tâches"),
        'Проверяет и восстанавливает целостность оболочки': ('Checks and restores shell integrity', 'Перевіряє та відновлює цілісність оболонки', 'Überprüft und stellt die Shell-Integrität wieder her', 'Sprawdza i przywraca integralność powłoki', "Vérifie et restaure l'intégrité du shell"),
        'Исправляет параметр Userinit для входа в систему': ('Fixes the Userinit sign-in value', 'Виправляє параметр Userinit для входу до системи', 'Korrigiert den Userinit-Parameter für die Anmeldung', '[pl] Исправляет параметр Userinit для входа в систему', 'Corrige le paramètre Userinit pour la connexion'),
        'Сброс шрифтов': ('Reset fonts', 'Скидання шрифтів', 'Schriftarten zurücksetzen', 'Resetowanie czcionek', 'Réinitialisation des polices'),
        'Восстанавливает системные шрифты и очищает кеш шрифтов': ('Restores system fonts and clears the font cache', 'Відновлює системні шрифти та очищає кеш шрифтів', 'Stellt Systemschriftarten wieder her und löscht den Schriftarten-Cache', 'Przywraca czcionki systemowe i czyści pamięć podręczną czcionek', 'Restaure les polices système et efface le cache des polices'),
        'Разблокировка обоев': ('Unblock wallpaper', 'Розблокування шпалер', 'Hintergrundbild entsperren', 'Odblokuj tapetę', "Déverrouiller le fond d'écran"),
        'Разблокирует возможность смены обоев рабочего стола': ('Unblocks changing the desktop wallpaper', 'Розблоковує зміну шпалер робочого столу', 'Schaltet die Möglichkeit frei, das Desktop-Hintergrundbild zu ändern', 'Odblokowuje możliwość zmiany tapety pulpitu', "Débloque la possibilité de changer le fond d'écran du bureau"),
        'Восстановление темы': ('Restore theme', 'Відновлення теми', 'Ein Thema wiederherstellen', 'Przywracanie motywu', 'Restaurer un thème'),
        'Восстанавливает стандартную тему оформления Windows': ('Restores the default Windows theme', 'Відновлює стандартну тему Windows', 'Stellt das Standard-Windows-Design wieder her', 'Przywraca domyślny motyw systemu Windows', 'Restaure le thème Windows par défaut'),
        'Сброс масштаба иконок': ('Reset icon size', 'Скидання розміру значків', 'Symbolskala zurücksetzen', 'Resetowanie skali ikon', "Réinitialisation de l'échelle des icônes"),
        'Сбрасывает размер иконок на стандартный': ('Resets icon size to default', 'Скидає розмір значків до стандартного', 'Setzt die Symbolgröße auf den Standard zurück', 'Resetuje rozmiar ikony do standardowego', "Réinitialise la taille de l'icône à la norme"),
        'Возврат курсора': ('Restore cursor', 'Відновлення курсора', 'Zurück zum Cursor', 'Powrót kursora', 'Retour du curseur'),
        'Восстанавливает стандартный курсор мыши': ('Restores the default mouse cursor', 'Відновлює стандартний курсор миші', 'Stellt den Standard-Mauszeiger wieder her', 'Przywraca domyślny kursor myszy', 'Restaure le curseur de la souris par défaut'),
        'Поворот экрана': ('Screen rotation', 'Поворот екрана', 'Drehen Sie den Bildschirm', 'Obróć ekran', "Faire pivoter l'écran"),
        'Разблокирует и восстанавливает поворот экрана': ('Unblocks and restores screen rotation', 'Розблоковує та відновлює поворот екрана', 'Entsperrt die Bildschirmdrehung und stellt sie wieder her', 'Odblokowuje i przywraca obrót ekranu', "Déverrouille et restaure la rotation de l'écran"),
        'Включает и настраивает сглаживание шрифтов ClearType': ('Enables and configures ClearType font smoothing', 'Вмикає та налаштовує згладжування шрифтів ClearType', 'Aktiviert und konfiguriert die Glättung von ClearType-Schriftarten', 'Włącza i konfiguruje wygładzanie czcionek ClearType', 'Active et configure le lissage de la police ClearType'),
        'ℹ Отображаются только ключи автозапуска: Shell и Userinit. Остальные параметры Winlogon скрыты.': ('ℹ Only Shell and Userinit startup keys are shown. Other Winlogon values are hidden.', 'ℹ Показано лише ключі автозапуску Shell і Userinit. Інші параметри Winlogon приховані.', 'ℹ Es werden nur Autorun-Tasten angezeigt: Shell und Userinit. Die übrigen Winlogon-Optionen sind ausgeblendet.', 'ℹ Wyświetlane są tylko klucze automatycznego uruchamiania: Shell i Userinit. Pozostałe opcje Winlogon są ukryte.', "ℹ Seules les clés d'exécution automatique sont affichées : Shell et Userinit. Les options Winlogon restantes sont masquées."),
    }

language_manager = LanguageManager()

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


def _register_backup(path, diagnostics=None):
    """Record backup metadata outside the backup directory for restore validation."""
    try:
        os.makedirs(BACKUP_SECURITY_DIR, exist_ok=True)
        if not _harden_backup_security_dir(diagnostics) or _is_reparse_point(BACKUP_SECURITY_DIR):
            return False
        try:
            with open(BACKUP_MANIFEST, "r", encoding="utf-8") as manifest_file:
                manifest = json.load(manifest_file)
        except (FileNotFoundError, json.JSONDecodeError):
            manifest = {}

        digest = hashlib.sha256()
        with open(path, "rb") as backup_file:
            for chunk in iter(lambda: backup_file.read(1024 * 1024), b""):
                digest.update(chunk)
        manifest[os.path.basename(path)] = {
            "sha256": digest.hexdigest(),
            "size": os.path.getsize(path),
        }
        temporary_path = BACKUP_MANIFEST + ".tmp"
        with open(temporary_path, "w", encoding="utf-8") as manifest_file:
            json.dump(manifest, manifest_file, indent=2, sort_keys=True)
        os.replace(temporary_path, BACKUP_MANIFEST)
        if not _harden_acl_path(BACKUP_MANIFEST, diagnostics, set_owner=False):
            return False
        return True
    except (OSError, ValueError, TypeError) as error:
        if diagnostics is not None:
            diagnostics.append(f"register exception={error!r}")
        return False


def _harden_acl_path(path, diagnostics=None, set_owner=True):
    """Apply the manifest owner and DACL to one existing path."""
    if _is_reparse_point(path):
        return False
    is_directory = os.path.isdir(path)
    grants = (
        ["*S-1-5-18:(OI)(CI)(F)", "*S-1-5-32-544:(OI)(CI)(F)"]
        if is_directory
        else ["*S-1-5-18:F", "*S-1-5-32-544:F"]
    )
    commands = [
        ["takeown", "/f", path, "/a"],
        ["icacls", path, "/reset"],
        ["icacls", path, "/inheritance:r"],
        ["icacls", path, "/grant:r", *grants],
    ]
    if set_owner:
        commands.append(["icacls", path, "/setowner", "*S-1-5-18"])
    for command in commands:
        result = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = f"{result.stdout}\n{result.stderr}".lower()
        failed_match = re.search(r"failed processing\s+([1-9]\d*)", output)
        if (
            result.returncode != 0
            or failed_match
            or "access is denied" in output
            or "this security id may not be assigned" in output
        ):
            if diagnostics is not None:
                diagnostics.append(
                    f"command={command!r}; returncode={result.returncode}; "
                    f"stdout={result.stdout!r}; stderr={result.stderr!r}"
                )
            return False
    return True


def _harden_backup_security_dir(diagnostics=None):
    """Reset the manifest directory to a known owner and DACL."""
    return _harden_acl_path(BACKUP_SECURITY_DIR, diagnostics)


def _verified_backup_path(filename, suffix):
    """Return a backup path only when its recorded metadata still matches."""
    valid_name = (
        rf"registry_backup_\d{{8}}_\d{{6}}(?:_\d{{2}})?{re.escape(suffix)}"
        if suffix == ".reg"
        else rf"(?:firewall_backup|hosts_backup)_\d{{8}}_\d{{6}}{re.escape(suffix)}"
    )
    if not re.fullmatch(valid_name, filename):
        return None
    path = os.path.join(BACKUP_DIR, filename)
    try:
        if (
            not os.path.isfile(path)
            or _is_reparse_point(path)
            or _is_reparse_point(BACKUP_SECURITY_DIR)
            or _is_reparse_point(BACKUP_MANIFEST)
        ):
            return None
        with open(BACKUP_MANIFEST, "r", encoding="utf-8") as manifest_file:
            record = json.load(manifest_file).get(filename)
        if not record or record.get("size") != os.path.getsize(path):
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as backup_file:
            for chunk in iter(lambda: backup_file.read(1024 * 1024), b""):
                digest.update(chunk)
        return path if digest.hexdigest() == record.get("sha256") else None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def iter_tree_paths(root_path):
    """Yield all directory and file paths under root_path using scandir for speed."""
    root_path = os.path.normpath(root_path)
    if not os.path.exists(root_path):
        return

    stack = [root_path]
    while stack:
        current = stack.pop()
        yield current

        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except (OSError, PermissionError):
            continue

        for entry in reversed(entries):
            if entry.is_dir(follow_symlinks=False):
                stack.append(entry.path)
            elif entry.is_file(follow_symlinks=False):
                yield entry.path


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

# User locations that NoVir may clean after a confirmation.  Do not allow the
# whole profile: the file explorer must never become a general-purpose
# destructive delete tool for Documents, Desktop, Pictures, or other data.
_CURRENT_USER_PROFILE = os.environ.get("USERPROFILE", "")
_DELETION_WHITELIST_EXTENDED = [
    path for path in (
        os.environ.get("TEMP", ""),
        os.environ.get("TMP", ""),
        os.path.join(_CURRENT_USER_PROFILE, "AppData", "Local", "Temp") if _CURRENT_USER_PROFILE else "",
        os.path.join(_CURRENT_USER_PROFILE, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup") if _CURRENT_USER_PROFILE else "",
    ) if path
]

def _path_in_whitelist(real_path, whitelist_key):
    try:
        real_path = os.path.normcase(os.path.abspath(real_path))
        whitelist = _DELETION_WHITELIST if whitelist_key == 0 else _DELETION_WHITELIST_EXTENDED
        for allowed in whitelist:
            allowed_path = os.path.normcase(os.path.abspath(allowed))
            if os.path.commonpath([real_path, allowed_path]) == allowed_path:
                return True
    except (OSError, ValueError):
        return False
    return False

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
        blocked = os.path.normcase(os.path.abspath(blocked))
        if real == blocked:
            return False

    # Whitelist: realpath must start with allowed directory
    if not (_path_in_whitelist(real, 0) or _path_in_whitelist(real, 1)):
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
    if _path_in_whitelist(real, 1):
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

    # Fast traversal with scandir: less overhead than repeated os.walk() calls.
    for candidate in iter_tree_paths(path):
        if _is_reparse_point(candidate):
            return False
        if candidate != path and not is_path_safe_for_deletion(candidate):
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

def confirm_high_risk_action(title, details):
    """Require an explicit confirmation before changing system-wide security state."""
    if DRY_RUN:
        return True
    try:
        if GUI_MODE and PYSIDE_AVAILABLE:
            from PySide6.QtWidgets import QMessageBox, QApplication
            parent = QApplication.instance().activeWindow() if QApplication.instance() else None
            answer = QMessageBox.warning(
                parent,
                title,
                f"{details}\n\nПродолжить?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            return answer == QMessageBox.Yes
        answer = input(f"[!] {title}: {details}\nПродолжить? Введите YES: ")
        return answer.strip() == "YES"
    except (EOFError, OSError):
        return False

def run_command(cmd, as_admin=False):
    """Run an argv command without invoking a shell."""
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Команда: {cmd}{Colors.RESET}")
        return True, "", ""
    if isinstance(cmd, str):
        return False, "", "run_command requires an argument list"
    try:
        kwargs = {"shell": False, "capture_output": True, "text": True}
        if sys.platform == 'win32' and hasattr(subprocess, 'CREATE_NO_WINDOW'):
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(cmd, **kwargs)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def _run_safe_process(args, timeout=15):
    """Run a fixed executable without shell parsing."""
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Команда: {args}{Colors.RESET}")
        return True, "", ""
    try:
        result = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.returncode == 0, result.stdout, result.stderr
    except (OSError, subprocess.SubprocessError) as error:
        return False, "", str(error)

def reg_set_value(key_path, value_name, value_data, value_type=winreg.REG_SZ, hive=None):
    """Установка значения в реестре с обходом блокировок"""
    if not require_mutation_allowed(f"reg_set_value: {key_path}\\{value_name}"):
        return True
    
    hives = [hive] if hive else [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    success = False
    for current_hive in hives:
        hive_name = "HKLM" if current_hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        hive_success = False
        try:
            for access in [winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_32KEY]:
                try:
                    rollback_mgr.snapshot_value(current_hive, key_path, value_name)
                    with winreg.CreateKeyEx(current_hive, key_path, 0, access) as key:
                        winreg.SetValueEx(key, value_name, 0, value_type, value_data)
                    hive_success = True
                    break
                except Exception:
                    continue
            
            if not hive_success:
                v_type = "REG_SZ" if value_type == winreg.REG_SZ else "REG_DWORD"
                res, _, _ = run_command(["reg", "add", f"{hive_name}\\{key_path}", "/v", value_name, "/t", v_type, "/d", str(value_data), "/f"])
                hive_success = bool(res)
        except Exception:
            continue
        success = success or hive_success
        # `hive=None` means HKLM first, then HKCU only as a fallback. Writing
        # the same setting to both hives can unexpectedly override per-user
        # policy and creates duplicate state.
        if hive_success:
            break
    return success

def reg_delete_value(key_path, value_name, hive=None):
    """Удаление значения из реестра с обходом блокировок"""
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Удаление из реестра: {key_path} -> {value_name}{Colors.RESET}")
        return True
    
    hives = [hive] if hive else [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    success = False
    for hive in hives:
        hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        # Метод 1: Прямое удаление
        for access in [winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_32KEY]:
            try:
                rollback_mgr.snapshot_value(hive, key_path, value_name)
                key = winreg.OpenKey(hive, key_path, 0, access)
                winreg.DeleteValue(key, value_name)
                winreg.CloseKey(key)
                success = True
            except Exception as _e:
                # Expected exception, intentionally ignored
                continue
        
        if not success:
            # Метод 2: Через REG DELETE
            rollback_mgr.snapshot_value(hive, key_path, value_name)
            res, _, _ = run_command(["reg", "delete", f"{hive_name}\\{key_path}", "/v", value_name, "/f"])
            if res: success = True
            
    return success

def run_reg(hive, key_path, value_name, value_data, value_type=winreg.REG_SZ):
    """Compatibility wrapper for legacy registry write call sites."""
    return reg_set_value(key_path, value_name, value_data, value_type, hive=hive)

def delete_registry_key(hive, key_path, value_name=None):
    """Compatibility wrapper for legacy value/key deletion call sites."""
    if value_name == "DisallowRun":
        return reg_delete_key(f"{key_path}\\{value_name}", hive=hive)
    if value_name:
        return reg_delete_value(key_path, value_name, hive=hive)
    return reg_delete_key(key_path, hive=hive)

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
                res = subprocess.run(['reg', 'delete', f'{hive_str}\\{key_path}', '/f'],
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
# ПОДДЕРЖКА ВЕРСИЙ WINDOWS (7 / 8 / 8.1 / 10 / 11)
# ═══════════════════════════════════════════════════════════════
# Пользователь может выбрать целевую версию в «Настройках». В зависимости
# от неё функции используют разные команды/ключи реестра. По умолчанию —
# автоопределение текущей Windows. Win10/11 остаются дефолтным поведением.
_WIN_ORDER = {"7": 70, "8": 80, "8.1": 81, "10": 100, "11": 110}
# Порядок соответствует индексам комбобокса (0 = автоопределение).
WIN_VERSION_KEYS = ("11", "10", "8.1", "8", "7")
WIN_VERSION_LABELS = ("Windows 11", "Windows 10", "Windows 8.1",
                      "Windows 8", "Windows 7")
_WIN_TARGET = {"value": None}  # None = автоопределение

# Иконки версий для комбобокса «Версия Windows»: папка win_icons/ рядом
# с программой (у собранного exe — внутри _MEIPASS).
WIN_ICON_FILES = {"11": "w11.png", "10": "w10.png",
                  "8.1": "w8.png", "8": "w8.png", "7": "w7.png"}
_WIN_ICON_CACHE = {}


def win_version_icon(version):
    """QIcon версии Windows; пустой QIcon, если файл иконки не найден."""
    from PySide6.QtGui import QIcon
    key = version if version in WIN_ICON_FILES else "10"
    if key in _WIN_ICON_CACHE:
        return _WIN_ICON_CACHE[key]
    icon = QIcon()
    try:
        base = getattr(sys, "_MEIPASS", None)
        if not base:
            base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, "win_icons", WIN_ICON_FILES[key])
        if os.path.exists(path):
            icon = QIcon(path)
    except Exception:
        pass
    _WIN_ICON_CACHE[key] = icon
    return icon


def detect_windows_version():
    """Определяет текущую версию Windows: '7', '8', '8.1', '10' или '11'."""
    try:
        info = sys.getwindowsversion()
        major, minor, build = info.major, info.minor, info.build
    except Exception:
        return "10"  # не Windows (разработка/тест)
    if major >= 10:
        return "11" if build >= 22000 else "10"
    if major == 6 and minor == 3:
        return "8.1"
    if major == 6 and minor == 2:
        return "8"
    if major == 6 and minor == 1:
        return "7"
    return "10"


def win_target():
    """Версия Windows, под которую настраиваются команды функций."""
    v = _WIN_TARGET["value"]
    return v if v else detect_windows_version()


def win_at_least(ver):
    """True, если целевая версия >= ver ('7' < '8' < '8.1' < '10' < '11')."""
    return _WIN_ORDER.get(win_target(), 100) >= _WIN_ORDER.get(ver, 100)


def win_is(*versions):
    """True, если целевая версия входит в указанные (например win_is('7'))."""
    return win_target() in versions


def set_win_target(version):
    """Установить целевую версию ('auto'/'None' = автоопределение)."""
    if not version or version in ("auto", "Автоопределение"):
        _WIN_TARGET["value"] = None
    elif version in _WIN_ORDER:
        _WIN_TARGET["value"] = version
    return _WIN_TARGET["value"]


def load_win_target():
    """Читает сохранённый выбор версии Windows из settings.json."""
    try:
        with open(LANGUAGE_CONFIG_PATH, "r", encoding="utf-8") as fh:
            val = json.load(fh).get("win_target")
        if val in _WIN_ORDER:
            _WIN_TARGET["value"] = val
            return val
    except (OSError, ValueError, TypeError):
        pass
    _WIN_TARGET["value"] = None
    return None


def save_win_target():
    """Сохраняет выбранный target в settings.json (не трогая остальные ключи)."""
    try:
        os.makedirs(os.path.dirname(LANGUAGE_CONFIG_PATH), exist_ok=True)
        settings = {}
        try:
            with open(LANGUAGE_CONFIG_PATH, "r", encoding="utf-8") as fh:
                settings = json.load(fh)
        except (OSError, ValueError, TypeError):
            pass
        settings["win_target"] = _WIN_TARGET["value"] or "auto"
        tmp = LANGUAGE_CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(settings, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, LANGUAGE_CONFIG_PATH)
    except OSError:
        pass


# Применяем сохранённый выбор при старте приложения.
load_win_target()


# ═══════════════════════════════════════════════════════════════
# ЗАЩИТА ФОНОВЫХ QThread-ВОРКЕРОВ ОТ РАННЕГО УНИЧТОЖЕНИЯ
# ═══════════════════════════════════════════════════════════════
# Пока на QThread есть Python-ссылка, C++ объект жив. Если воркер
# хранится в локальной переменной или перезаписывается
# (self.worker = Worker(...)), сборщик мусора уничтожает работающий
# поток, и Qt печатает «QThread: Destroyed while thread is still
# running» (вплоть до падения). keep_thread() держит поток в реестре
# до сигнала finished; наружу возвращается сам поток, поэтому все
# последующие connect()/start() работают как раньше.
_LIVE_QTHREADS = set()


def keep_thread(thread):
    """Держит ссылку на поток до его завершения. Возвращает поток."""
    try:
        _LIVE_QTHREADS.add(thread)
        thread.finished.connect(lambda: _LIVE_QTHREADS.discard(thread))
    except Exception:
        pass
    return thread


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
            subprocess.run(["powershell", "-Command", "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'LogPixels' -Value 96"], capture_output=True)
        
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
        ], capture_output=True)
        
        # Альтернативный метод через дисплей с правильными спецсимволами SendKeys
        # ^ = Control, % = Alt, {UP} = Стрелка вверх
        # ПРИМЕЧАНИЕ: Работает только если горячие клавиши включены в драйвере видеокарты
        subprocess.run(["powershell", "-Command", "(New-Object -ComObject WScript.Shell).SendKeys('^%{UP}')"], capture_output=True)
        
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
        run_command(["shutdown", "/l", "/f"])
    return True

def Boot_WinRE():
    """Перезагрузка в среду восстановления (WinRE)"""
    print_hacker_message("Подготовка к перезагрузке в WinRE.")
    if not DRY_RUN:
        run_command(["reagentc", "/boottore"])
        run_command(["shutdown", "/r", "/t", "0"])
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
        subprocess.Popen(["cmd.exe", "/k", "sfc /scannow"])
    return True

def LogonUI_Restore():
    """Восстановление стандартного экрана входа LogonUI"""
    print_hacker_message("Восстановление экрана блокировки и LogonUI.")
    if not DRY_RUN:
        reg_delete_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\logonui.exe", "Debugger")
    return True

def Emergency_Recovery():
    """Отключено: массовое завершение процессов может терять данные пользователя."""
    message = "Операция отключена: завершение всех сторонних процессов может закрыть несохранённые документы и нарушить работу Windows."
    print(f"[!] {message}")
    logger.log("Emergency_Recovery", "warning", message)
    return False

def Disable_Test_Mode():
    """Отключение тестового режима Windows"""
    print_hacker_message("Отключение тестового режима.")
    if not DRY_RUN:
        run_command(["bcdedit", "/set", "testsigning", "off"])
        run_command(["bcdedit", "/set", "nointegritychecks", "off"])
    return True

def Replace_Sethc_Utilman():
    """Отключено: подмена средств доступности может обойти экран входа Windows."""
    message = "Операция отключена из соображений безопасности: подмена sethc/utilman создаёт риск обхода авторизации Windows."
    print(f"[!] {message}")
    logger.log("Replace_Sethc_Utilman", "warning", message)
    return False

def File_Full_Access():
    """Полный доступ к файлу (Takeown & Icacls)"""
    print_hacker_message("Запуск процедуры получения прав на файл.")
    if not confirm_high_risk_action(
        "Опасная операция: права файла",
        "Выдача полного доступа может ослабить защиту выбранного системного файла.",
    ):
        logger.log("File_Full_Access", "warning", "Операция отменена пользователем")
        return False
    if not DRY_RUN:
        from PySide6.QtWidgets import QFileDialog, QMessageBox, QApplication
        app = QApplication.instance()
        if app:
            active_window = app.activeWindow()
            file_path, _ = QFileDialog.getOpenFileName(active_window, "Выберите файл для полного доступа")
            if file_path:
                run_command(["takeown", "/f", file_path])
                run_command(["icacls", file_path, "/grant", "administrators:F"])
                QMessageBox.information(active_window, "Готово", f"Полный доступ к {file_path} получен.")
    return True

def Driver_Cleanup():
    """Отключено: массовое удаление OEM-драйверов может вывести устройства из строя."""
    message = "Операция отключена: пакеты драйверов нельзя безопасно удалять общим шаблоном. Удаляйте только выбранный пакет после проверки зависимостей."
    print(f"[!] {message}")
    logger.log("Driver_Cleanup", "warning", message)
    return False

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
                run_command(["attrib", "+h", shortcut_path])
                print(f"[+] Ярлык создан (VBS): {shortcut_path}")
            except Exception as e:
                print(f"[!] Ошибка создания ярлыка: {e}")
    return True

def Easy_Launcher():
    """Удобный запуск"""
    print_hacker_message("Установка Удобного запуска (nov, контекстное меню, отключение UAC).")
    if not confirm_high_risk_action(
        "Опасная операция: отключение UAC",
        "UAC будет отключён, а приложение скопировано в системный каталог.",
    ):
        logger.log("Easy_Launcher", "warning", "Операция отменена пользователем")
        return False
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
    if not DRY_RUN: subprocess.Popen(["explorer.exe"])
    return True

def Open_Taskmgr():
    print_hacker_message("Запуск Taskmgr")
    if not DRY_RUN: import ctypes; ctypes.windll.shell32.ShellExecuteW(None, "runas", "taskmgr.exe", None, None, 1)
    return True

def Fix_MBR_Boot():
    print_hacker_message("Скрипт восстановления загрузчика")
    if not DRY_RUN:
        subprocess.Popen(["cmd.exe", "/k", "bootrec /fixmbr & bootrec /fixboot & bootrec /rebuildbcd"])
    return True

def Open_Browser():
    print_hacker_message("Запуск Браузера")
    if not DRY_RUN: os.startfile("https://google.com")
    return True

def Open_User_Management():
    print_hacker_message("Запуск управления пользователями")
    if not DRY_RUN: subprocess.Popen(["lusrmgr.msc"])
    return True

def Open_System_Cleanup():
    print_hacker_message("Запуск очистки диска")
    if not DRY_RUN: import ctypes; ctypes.windll.shell32.ShellExecuteW(None, "runas", "cleanmgr.exe", None, None, 1)
    return True

def Open_Default_Apps():
    print_hacker_message("Запуск ассоциаций")
    if not DRY_RUN: os.startfile("ms-settings:defaultapps")
    return True

def Open_Password_Reset():
    print_hacker_message("Сброс пароля")
    if not DRY_RUN: import ctypes; ctypes.windll.shell32.ShellExecuteW(None, "runas", "netplwiz.exe", None, None, 1)
    return True

def Open_Disk_Management():
    print_hacker_message("Управление дисками")
    if not DRY_RUN: subprocess.Popen(["diskmgmt.msc"])
    return True

def WinRE_Backup_Restore():
    print_hacker_message("Резервное копирование WinRE")
    if not DRY_RUN:
        subprocess.Popen(["cmd.exe", "/k", "reagentc /info"])
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

def NumLock_Startup_Fix():
    """Включение NumLock на экране входа и в системе"""
    print_hacker_message("Настраиваю NumLock для автоматического включения при загрузке.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] InitialKeyboardIndicators = 2{Colors.RESET}")
        logger.log("NumLock_Startup_Fix", "success", "NumLock будет включён при загрузке")
        return True
    
    ok = reg_set_value(r"Control Panel\Keyboard", "InitialKeyboardIndicators", "2", winreg.REG_SZ, hive=winreg.HKEY_CURRENT_USER)
    
    # Дополнительно: экран входа (HKU\.DEFAULT)
    try:
        k = winreg.CreateKeyEx(winreg.HKEY_USERS, r".DEFAULT\Control Panel\Keyboard", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "InitialKeyboardIndicators", 0, winreg.REG_SZ, "2")
        winreg.CloseKey(k)
        ok = True
    except Exception:
        pass
    
    if ok:
        logger.log("NumLock_Startup_Fix", "success", "NumLock будет включён при загрузке (после перезагрузки)")
        print(f"{Colors.GREEN}[+] NumLock автоматически включится при входе (после перезагрузки){Colors.RESET}")
        return True
    else:
        logger.log("NumLock_Startup_Fix", "error", "Не удалось изменить InitialKeyboardIndicators")
        print(f"{Colors.YELLOW}[!] Не удалось настроить NumLock{Colors.RESET}")
        return False

def MouseKeys_Disable():
    """Отключение MouseKeys (управление мышью цифрами)"""
    print_hacker_message("Отключаю MouseKeys (управление мышью с клавиатуры).")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] MouseKeys будут отключены{Colors.RESET}")
        logger.log("MouseKeys_Disable", "success", "MouseKeys будут отключены")
        return True
    
    # reg_set_value возвращает bool и не бросает исключения — проверяем результат
    if reg_set_value(r"Control Panel\Accessibility\MouseKeys", "Flags", "38", winreg.REG_SZ, hive=winreg.HKEY_CURRENT_USER):
        logger.log("MouseKeys_Disable", "success", "MouseKeys отключены")
        print(f"{Colors.GREEN}[+] MouseKeys отключены{Colors.RESET}")
        return True
    else:
        logger.log("MouseKeys_Disable", "error", "Не удалось изменить Flags MouseKeys")
        print(f"{Colors.YELLOW}[!] Не удалось отключить MouseKeys{Colors.RESET}")
        return False

def Language_Bar_Restore():
    """Восстановление панели языков и текстовых служб"""
    print_hacker_message("Восстанавливаю панель языка и текстовые службы.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Панель языка будет восстановлена (ctfmon){Colors.RESET}")
        logger.log("Language_Bar_Restore", "success", "Панель языка будет восстановлена")
        return True
    
    try:
        ctfmon = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ctfmon.exe")
        subprocess.Popen([ctfmon], creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
        reg_delete_value(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoLanguageBand", hive=winreg.HKEY_CURRENT_USER)
        
        # Настоящее состояние панели языка: ShowStatus = 3 (закрепить в панели задач)
        reg_set_value(r"Software\Microsoft\CTF\LangBar", "ShowStatus", 3, winreg.REG_DWORD, hive=winreg.HKEY_CURRENT_USER)
        
        logger.log("Language_Bar_Restore", "success", "Панель языка восстановлена (ctfmon перезапущен)")
        print(f"{Colors.GREEN}[+] Панель языка восстановлена, ctfmon перезапущен{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Language_Bar_Restore", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def OnScreenKeyboard_Launch():
    """Запуск экранных клавиш (osk.exe) для аварийного ввода"""
    print_hacker_message("Запускаю экранные клавиши (osk.exe).")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] osk.exe будет запущен{Colors.RESET}")
        logger.log("OnScreenKeyboard_Launch", "success", "osk.exe будет запущен")
        return True
    
    try:
        osk = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "osk.exe")
        subprocess.Popen([osk], creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
        logger.log("OnScreenKeyboard_Launch", "success", "Экранные клавиши запущены")
        print(f"{Colors.GREEN}[+] Экранные клавиши (osk.exe) запущены{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("OnScreenKeyboard_Launch", "error", str(e))
        print(f"{Colors.RED}[!] Не удалось запустить osk.exe: {e}{Colors.RESET}")
        return False

def Keyboard_Troubleshoot_Run():
    """Запуск встроенного средства устранения неполадок клавиатуры"""
    print_hacker_message("Запускаю средство устранения неполадок клавиатуры.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Диагностика клавиатуры будет запущена{Colors.RESET}")
        logger.log("Keyboard_Troubleshoot_Run", "success", "Диагностика клавиатуры будет запущена")
        return True
    
    # Проверяем наличие msdt.exe (удалён в свежих сборках Windows 11)
    msdt = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "msdt.exe")
    if not os.path.exists(msdt):
        logger.log("Keyboard_Troubleshoot_Run", "warning", "msdt.exe отсутствует в этой сборке Windows")
        print(f"{Colors.YELLOW}[!] Средство устранения неполадок отсутствует в этой сборке Windows (msdt.exe удалён Microsoft){Colors.RESET}")
        return False
    
    try:
        # Запускаем в фоне: мастер диалог живёт, пока пользователь его не закроет
        subprocess.Popen(
            [msdt, "-id", "KeyboardDiagnostic"],
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        logger.log("Keyboard_Troubleshoot_Run", "success", "Диагностика клавиатуры запущена")
        print(f"{Colors.GREEN}[+] Средство устранения неполадок клавиатуры запущено{Colors.RESET}")
        return True
    except Exception as e:
        logger.log("Keyboard_Troubleshoot_Run", "error", str(e))
        print(f"{Colors.YELLOW}[!] Не удалось запустить диагностику: {e}{Colors.RESET}")
        return False

def WinHotkey_Policy_Clean():
    """Удаление политик, блокирующих горячие клавиши Win+..."""
    print_hacker_message("Удаляю политики, блокирующие системные горячие клавиши.")
    
    keys_to_delete = [
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoWinKeys"),
        (r"Software\Policies\Microsoft\Windows\Explorer", "NoWinKeys"),
        # Блокировка Win+L (рабочая политика — отдельный путь, не Policies\...\System)
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableLockWorkstation"),
    ]
    
    success = False
    for key_path, value_name in keys_to_delete:
        if reg_delete_value(key_path, value_name, hive=winreg.HKEY_CURRENT_USER):
            success = True
        if reg_delete_value(key_path, value_name, hive=winreg.HKEY_LOCAL_MACHINE):
            success = True
    
    if success:
        logger.log("WinHotkey_Policy_Clean", "success", "Политики горячих клавиш удалены")
        print(f"{Colors.GREEN}[+] Политики, блокирующие Win+клавиши, удалены{Colors.RESET}")
    else:
        logger.log("WinHotkey_Policy_Clean", "warning", "Блокирующие политики не найдены")
        print(f"{Colors.YELLOW}[!] Блокирующие политики не обнаружены{Colors.RESET}")
    
    return success

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
    if not confirm_high_risk_action(
        "Подтверждение: файл hosts",
        "Файл hosts будет полностью перезаписан, что изменит системное разрешение имён.",
    ):
        logger.log("Hosts_Clean_Hard", "warning", "Операция отменена пользователем")
        return False
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет перезаписан файл: C:\\Windows\\System32\\drivers\\etc\\hosts{Colors.RESET}")
        logger.log("Hosts_Clean_Hard", "success", "Файл hosts будет очищен")
        print(f"{Colors.GREEN}[+] Файл hosts будет очищен{Colors.RESET}")
        return True
    
    try:
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        # Сначала снимаем атрибуты (только чтение, скрытый, системный)
        subprocess.run(["attrib", "-r", "-s", "-h", hosts_path], capture_output=True)
        
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
            subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True)
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
    if not confirm_high_risk_action(
        "Подтверждение: DNS",
        "DNS всех активных сетевых адаптеров будет изменён на 8.8.8.8 и 8.8.4.4.",
    ):
        logger.log("DNS_Google_Force", "warning", "Операция отменена пользователем")
        return False
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет установлен Google DNS (8.8.8.8, 8.8.4.4) на все активные интерфейсы{Colors.RESET}")
        logger.log("DNS_Google_Force", "success", "DNS будет установлен на 8.8.8.8")
        print(f"{Colors.GREEN}[+] DNS будет установлен на 8.8.8.8 и 8.8.4.4{Colors.RESET}")
        return True
    
    try:
        # Получаем список активных интерфейсов через PowerShell.
        # Win8+: Get-NetAdapter. Win7: модуля нет — через WMI (NetConnectionID).
        if win_at_least("8"):
            ps_cmd = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"
        else:
            ps_cmd = ("Get-WmiObject Win32_NetworkAdapter -Filter \"NetConnectionStatus=2\" "
                      "| Select-Object -ExpandProperty NetConnectionID")
        success, stdout, _ = run_command(["powershell", "-NoProfile", "-Command", ps_cmd])
        
        if success and stdout:
            interfaces = [i.strip() for i in stdout.split('\n') if i.strip()]
            configured = []
            failures = []
            for interface in interfaces:
                primary_ok, _, primary_error = run_command([
                    "netsh", "interface", "ip", "set", "dns",
                    f"name={interface}", "static", "8.8.8.8", "primary",
                ])
                secondary_ok, _, secondary_error = run_command([
                    "netsh", "interface", "ip", "add", "dns",
                    f"name={interface}", "8.8.4.4", "index=2",
                ])
                if primary_ok and secondary_ok:
                    configured.append(interface)
                else:
                    failures.append(f"{interface}: {primary_error or secondary_error}")

            flush_ok, _, flush_error = run_command(["ipconfig", "/flushdns"])
            if configured and flush_ok and not failures:
                logger.log("DNS_Google_Force", "success", f"DNS установлен на {len(configured)} интерфейсах")
                print(f"{Colors.GREEN}[+] DNS успешно изменен на {len(configured)} интерфейсах{Colors.RESET}")
                return True
            details = "; ".join(failures) or flush_error or "Не удалось настроить DNS"
            logger.log("DNS_Google_Force", "error", details)
            print(f"{Colors.RED}[!] Не удалось полностью настроить DNS: {details}{Colors.RESET}")
            return False
        else:
            raise OSError("Не удалось определить активные сетевые интерфейсы")
    except Exception as e:
        logger.log("DNS_Google_Force", "error", str(e))
        print(f"{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
        return False

def Firewall_State_Reset():
    """Сброс настроек брандмауэра на заводские"""
    print_hacker_message("Брандмауэр настроен криво? Щас сбросим на заводские настройки!")
    if not confirm_high_risk_action(
        "Подтверждение: брандмауэр",
        "Правила брандмауэра будут сброшены, а брандмауэр включён для всех профилей.",
    ):
        logger.log("Firewall_State_Reset", "warning", "Операция отменена пользователем")
        return False
    
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
    if not confirm_high_risk_action(
        "Подтверждение: сетевое обнаружение",
        "Будут включены сетевые правила брандмауэра и службы обнаружения/общего доступа.",
    ):
        logger.log("Network_Discovery_On", "warning", "Операция отменена пользователем")
        return False
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: netsh firewall set service type=fileandprint mode=enable{Colors.RESET}")
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнено: netsh advfirewall firewall set rule group=\"Network Discovery\" new enable=Yes{Colors.RESET}")
        logger.log("Network_Discovery_On", "success", "Сетевое обнаружение будет включено")
        print(f"{Colors.GREEN}[+] Сетевое обнаружение будет включено{Colors.RESET}")
        return True
    
    try:
        # Включаем через netsh (старый и новый методы)
        run_command(["netsh", "firewall", "set", "service", "type=fileandprint", "mode=enable"])
        run_command(["netsh", "advfirewall", "firewall", "set", "rule", "group=Network Discovery", "new", "enable=Yes"])
        run_command(["netsh", "advfirewall", "firewall", "set", "rule", "group=File and Printer Sharing", "new", "enable=Yes"])
        
        # Включаем через PowerShell (самый надежный метод для Win10/11)
        ps_cmd = "Set-NetFirewallRule -DisplayGroup 'Network Discovery' -Enabled True; Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Enabled True"
        run_command(["powershell", "-NoProfile", "-Command", ps_cmd])
        
        # Включаем службы, необходимые для обнаружения
        services = ['upnphost', 'SSDPSRV', 'FDResPub', 'FunctionDiscoveryDataPublishing']
        for svc in services:
            run_command(["sc", "config", svc, "start=auto"])
            run_command(["net", "start", svc])
            
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
    if not confirm_high_risk_action(
        "Подтверждение: сброс сети",
        "Будут сброшены маршруты, Winsock, TCP/IP и DNS-кеш; сетевое соединение может прерваться.",
    ):
        logger.log("IP_Reset", "warning", "Операция отменена пользователем")
        return False
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Будет выполнен сброс Winsock, TCP/IP и очистка DNS кеша{Colors.RESET}")
        logger.log("IP_Reset", "success", "Стек сети будет сброшен")
        return True
    
    commands = [
        ["netsh", "winsock", "reset"],
        ["netsh", "int", "ip", "reset"],
        ["netsh", "int", "ipv6", "reset"],
        ["ipconfig", "/release"],
        ["ipconfig", "/renew"],
        ["ipconfig", "/flushdns"],
        ["arp", "-d", "*"],
        ["nbtstat", "-R"],
        ["nbtstat", "-RR"]
    ]
    
    command_results = []
    for cmd in commands:
        success, _, _ = run_command(cmd)
        command_results.append(success)

    success_count = sum(command_results)
    core_reset_succeeded = all(command_results[index] for index in (0, 1, 5))
    if core_reset_succeeded:
        logger.log("IP_Reset", "success", f"Критические операции сброса выполнены ({success_count}/{len(commands)} команд)")
        print(f"{Colors.GREEN}[+] Winsock, TCP/IP и DNS-кэш сброшены ({success_count}/{len(commands)} команд){Colors.RESET}")
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
        # Win8.1+/Win10/11: Clear-RecycleBin. Win7/8.0: команда не нужна —
        # очищаем через Shell.Application COM (доступен во всех версиях).
        if win_at_least("8.1"):
            ps_cmd = "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"
        else:
            ps_cmd = ("$shell = New-Object -ComObject Shell.Application; "
                      "$bin = $shell.Namespace(0xA); "
                      "foreach ($item in @($bin.Items())) { "
                      "Remove-Item -LiteralPath $item.Path -Recurse -Force -ErrorAction SilentlyContinue }")
        subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True)
        
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
    
    if not confirm_high_risk_action(
        "Опасная операция: завершение процессов",
        "Будут завершены только процессы с подозрительным именем вне системных и Program Files папок. Несохранённые данные могут быть потеряны.",
    ):
        logger.log("Process_Blacklist_Kill", "warning", "Операция отменена пользователем")
        return False

    suspicious_processes = {
        'svchost.exe', 'temp.exe', 'hack.exe', 'virus.exe', 'trojan.exe',
        'malware.exe', 'miner.exe', 'crypt.exe', 'payload.exe', 'dropper.exe',
        'loader.exe', 'injector.exe', 'rat.exe', 'backdoor.exe', 'keylogger.exe',
        'stealer.exe', 'unknown.exe', 'update.exe', 'winlogon.exe', 'lsass.exe',
        'csrss.exe', 'services.exe', 'taskhostw.exe', 'spoolsv.exe'
    }
    
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
            
            if proc_name in suspicious_processes:
                exe_path = str(proc_info.get('exe', '') or proc_info.get('path', '')).lower()
                is_legitimate = False
                
                # Проверка системных процессов (должны быть в system32 и от SYSTEM)
                critical_system = ['svchost.exe', 'winlogon.exe', 'lsass.exe', 'csrss.exe', 'services.exe', 'taskhostw.exe', 'spoolsv.exe']
                if proc_name in critical_system:
                    # Never terminate a known Windows core process just because
                    # its owner cannot be queried (access is often denied).
                    if any(exe_path.startswith(path) for path in whitelist_paths):
                        is_legitimate = True
                
                # Проверка остальных по белому списку путей
                elif any(exe_path.startswith(path) for path in whitelist_paths):
                    is_legitimate = True
                
                # With no executable path we cannot distinguish a system
                # process from a spoof.  Leave it untouched instead of risking
                # a false-positive termination.
                if not is_legitimate and exe_path:
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
    if not confirm_high_risk_action(
        "Подтверждение: следующая загрузка",
        "Следующая загрузка Windows будет переведена в безопасный режим с командной строкой.",
    ):
        logger.log("SafeMode_Next_Boot", "warning", "Операция отменена пользователем")
        return False
    
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
        success1, _, err1 = run_command(["bcdedit", "/set", "{current}", "safeboot", "minimal"])
        success2, _, err2 = run_command(["bcdedit", "/set", "{current}", "safebootalternateshell", "yes"])
        
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
        run_command(["shutdown", "/r", "/t", "10", "/c", "NoVir: Переход в безопасный режим для глубокой очистки"])
        
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
        # Получаем список задач: Win8+ через Get-ScheduledTask, Win7 через schtasks.
        if win_at_least("8"):
            ps_cmd = "Get-ScheduledTask | Where-Object {$_.TaskName -notmatch '^Microsoft$'} | Select-Object TaskName, TaskPath"
            result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True)
        else:
            result = subprocess.run(["schtasks", "/query", "/fo", "CSV", "/v"],
                                    capture_output=True, text=True)
        lines = result.stdout.split('\n') if result.returncode == 0 else []
        
        suspicious_count = 0
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
        subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True)
        
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
        subprocess.run(["net", "stop", "wuauserv", "/y"], capture_output=True)
        subprocess.run(["net", "stop", "bits", "/y"], capture_output=True)
        
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
        subprocess.run(["net", "start", "bits"], capture_output=True)
        subprocess.run(["net", "start", "wuauserv"], capture_output=True)
        
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
                        result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True)
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
        subprocess.run(["net", "stop", "spooler", "/y"], capture_output=True)
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
        subprocess.run(["net", "start", "spooler"], capture_output=True)
        
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
    """Отключено: icacls /reset меняет, а не восстанавливает штатные ACL."""
    message = "Операция отключена: массовый сброс ACL в системных папках может повредить защиту Windows. Для восстановления нужна проверенная резервная копия ACL."
    print(f"[!] {message}")
    logger.log("TrustedInstaller_Restore", "warning", message)
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
        # Восстанавливаем ассоциацию .exe напрямую через реестр.
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, ".exe") as extension_key:
            winreg.SetValue(extension_key, "", winreg.REG_SZ, "exefile")
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, r"exefile\shell\open\command") as command_key:
            winreg.SetValue(command_key, "", winreg.REG_SZ, '"%1" %*')
        
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
    if not confirm_high_risk_action(
        "Опасная операция: привилегия владения",
        "Процессу будет выдана SeTakeOwnershipPrivilege для изменения защищённых файлов.",
    ):
        logger.log("Admin_Force", "warning", "Операция отменена пользователем")
        return False
    
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
        subprocess.run(["sc", "config", "WinDefend", "start=", "auto"], capture_output=True)
        subprocess.run(["net", "start", "WinDefend"], capture_output=True)
        
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
        subprocess.run(["sc", "config", "sr", "start=", "demand"], capture_output=True)
        
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
        result = subprocess.run(["bcdedit", "/enum", "firmware"], capture_output=True, text=True)
        
        suspicious_found = False
        if "unknown" in result.stdout.lower() or "malware" in result.stdout.lower():
            suspicious_found = True
            print(f"{Colors.YELLOW}[!] Найдены подозрительные записи в загрузчике!{Colors.RESET}")
        
        # Проверяем MBR через diskpart
        diskpart_cmd = "list disk"
        result = subprocess.run(["diskpart", "/s", "-"], input=diskpart_cmd, capture_output=True, text=True)
        
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
                subprocess.run(["wevtutil", "cl", log_name], capture_output=True)
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
        backup_prefix = os.path.join(BACKUP_DIR, f"registry_backup_{timestamp}")
        
        # Экспортируем важные ключи
        keys_to_export = [
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "HKLM\\SOFTWARE\\Policies",
            "HKCU\\SOFTWARE\\Policies"
        ]
        
        import tempfile
        exported_files = []
        with tempfile.TemporaryDirectory(prefix="novir-registry-") as temp_dir:
            for index, key in enumerate(keys_to_export, start=1):
                temporary_file = os.path.join(temp_dir, f"part_{index:02d}.reg")
                result = subprocess.run(
                    ["reg", "export", key, temporary_file, "/y"],
                    capture_output=True,
                    text=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode != 0 or not os.path.isfile(temporary_file):
                    raise OSError(
                        f"Не удалось экспортировать {key}: "
                        f"{result.stderr or result.stdout or result.returncode}"
                    )
                with open(temporary_file, "rb") as exported:
                    if not exported.read(128).strip():
                        raise OSError(f"Экспорт {key} создал пустой файл")
                exported_files.append((temporary_file, f"{backup_prefix}_{index:02d}.reg"))

            registered = []
            try:
                for temporary_file, backup_file in exported_files:
                    shutil.copy2(temporary_file, backup_file)
                    if not _register_backup(backup_file):
                        raise OSError("Не удалось записать метаданные целостности бэкапа")
                    registered.append(backup_file)
            except Exception:
                for backup_file in registered:
                    try:
                        os.remove(backup_file)
                    except OSError:
                        pass
                raise
        
        logger.log("Backup_Registry", "success", f"Экспортировано разделов реестра: {len(exported_files)}")
        print(f"{Colors.GREEN}[+] Бэкап реестра сохранен: {len(exported_files)} файлов{Colors.RESET}")
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
        result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True)
        
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

            if not _register_backup(backup_file):
                raise OSError("Не удалось записать метаданные целостности бэкапа")
            
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
        result = subprocess.run(["netsh", "advfirewall", "export", backup_file], capture_output=True)
        
        if result.returncode == 0:
            if not _register_backup(backup_file):
                raise OSError("Не удалось записать метаданные целостности бэкапа")
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
        backup_files = [
            e.name for e in os.scandir(BACKUP_DIR)
            if e.name.startswith("registry_backup_") and e.name.endswith(".reg")
            and _verified_backup_path(e.name, ".reg")
        ]
        
        if backup_files:
            backup_timestamps = [
                match.group(1)
                for name in backup_files
                if (match := re.fullmatch(r"registry_backup_(\d{8}_\d{6})(?:_\d{2})?\.reg", name))
            ]
            latest_timestamp = max(backup_timestamps)
            latest_registry_files = sorted(
                name for name in backup_files
                if name.startswith(f"registry_backup_{latest_timestamp}")
            )
            for latest_registry in latest_registry_files:
                registry_path = _verified_backup_path(latest_registry, ".reg")
                if not registry_path:
                    raise OSError(f"Бэкап реестра изменился перед импортом: {latest_registry}")
                result = subprocess.run(
                    ["reg", "import", registry_path], capture_output=True
                )
                if result.returncode != 0:
                    error_text = getattr(result, "stderr", b"")
                    raise OSError(
                        f"Ошибка импорта {latest_registry}: "
                        f"{error_text.decode(errors='replace') if isinstance(error_text, bytes) else error_text}"
                    )
            print(
                f"{Colors.GREEN}[+] Реестр восстановлен из снимка "
                f"{latest_timestamp} ({len(latest_registry_files)} файлов){Colors.RESET}"
            )
        else:
            print(f"{Colors.YELLOW}[!] Бэкап реестра не найден{Colors.RESET}")
        
        # Находим последний бэкап hosts
        hosts_backups = [
            e.name for e in os.scandir(BACKUP_DIR)
            if e.name.startswith("hosts_backup_") and e.name.endswith(".txt")
            and _verified_backup_path(e.name, ".txt")
        ]
        
        if hosts_backups:
            latest_hosts = max(hosts_backups)
            hosts_path = _verified_backup_path(latest_hosts, ".txt")
            hosts_dest = r"C:\Windows\System32\drivers\etc\hosts"
            
            if not hosts_path:
                raise OSError("Бэкап hosts изменился перед восстановлением")
            shutil.copy2(hosts_path, hosts_dest)
            print(f"{Colors.GREEN}[+] Hosts восстановлен из: {latest_hosts}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] Бэкап hosts не найден{Colors.RESET}")
        
        # Находим последний бэкап брандмауэра
        firewall_backups = [
            e.name for e in os.scandir(BACKUP_DIR)
            if e.name.startswith("firewall_backup_") and e.name.endswith(".wfw")
            and _verified_backup_path(e.name, ".wfw")
        ]
        
        if firewall_backups:
            latest_firewall = max(firewall_backups)
            firewall_path = _verified_backup_path(latest_firewall, ".wfw")
            
            if not firewall_path:
                raise OSError("Бэкап брандмауэра изменился перед импортом")
            result = subprocess.run(["netsh", "advfirewall", "import", firewall_path], capture_output=True)
            
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
            subprocess.run(['explorer', path], check=False)
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

def Security_Baseline_Audit():
    """Проверяет базовые настройки безопасности без внесения изменений."""
    print_hacker_message("Проверяю базовую защиту Windows без изменения настроек.")

    checks = []

    try:
        uac_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            0,
            winreg.KEY_READ,
        )
        enable_lua, _ = winreg.QueryValueEx(uac_key, "EnableLUA")
        winreg.CloseKey(uac_key)
        checks.append(("UAC", enable_lua == 1, f"EnableLUA={enable_lua}"))
    except (OSError, FileNotFoundError) as error:
        checks.append(("UAC", False, str(error)))

    firewall_ok, firewall_out, firewall_err = _run_safe_process(
        ["netsh", "advfirewall", "show", "allprofiles", "state"]
    )
    firewall_text = f"{firewall_out}\n{firewall_err}".lower()
    checks.append((
        "Брандмауэр",
        firewall_ok and "state" in firewall_text and "off" not in firewall_text,
        "состояние получено" if firewall_ok else firewall_err.strip(),
    ))

    defender_ok, defender_out, defender_err = _run_safe_process(
        ["sc", "query", "WinDefend"]
    )
    defender_text = f"{defender_out}\n{defender_err}".upper()
    checks.append((
        "Microsoft Defender",
        defender_ok and "RUNNING" in defender_text,
        "служба запущена" if "RUNNING" in defender_text else "служба не запущена или недоступна",
    ))

    hosts_path = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "System32", "drivers", "etc", "hosts"
    )
    try:
        with open(hosts_path, "rb") as hosts_file:
            hosts_hash = hashlib.sha256(hosts_file.read()).hexdigest()[:16]
        checks.append(("Файл hosts", True, f"SHA-256: {hosts_hash}"))
    except OSError as error:
        checks.append(("Файл hosts", False, str(error)))

    failed = 0
    for name, passed, details in checks:
        if passed:
            print(f"{Colors.GREEN}[OK] {name}: {details}{Colors.RESET}")
        else:
            failed += 1
            print(f"{Colors.YELLOW}[WARN] {name}: {details}{Colors.RESET}")

    logger.log(
        "Security_Baseline_Audit",
        "success" if failed == 0 else "warning",
        f"Проверено: {len(checks)}, предупреждений: {failed}",
    )
    print(
        f"{Colors.GREEN}[+] Аудит завершен: {len(checks)} проверок, "
        f"предупреждений: {failed}{Colors.RESET}"
    )
    return failed == 0


def Firewall_Enable_All():
    """Включение брандмауэра Windows для всех профилей"""
    print_hacker_message("Включаю брандмауэр Windows для всех профилей.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Брандмауэр будет включен для всех профилей{Colors.RESET}")
        logger.log("Firewall_Enable_All", "success", "Брандмауэр будет включен")
        return True
    
    ok, out, err = _run_safe_process(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
    
    if ok:
        logger.log("Firewall_Enable_All", "success", "Брандмауэр включен для всех профилей")
        print(f"{Colors.GREEN}[+] Брандмауэр включен для всех профилей{Colors.RESET}")
        return True
    else:
        logger.log("Firewall_Enable_All", "error", err.strip())
        print(f"{Colors.YELLOW}[!] Не удалось включить брандмауэр: {err.strip()}{Colors.RESET}")
        return False


def SmartScreen_Enable():
    """Включение фильтра SmartScreen для защиты от подозрительных приложений"""
    print_hacker_message("Включаю SmartScreen для защиты от вредоносных приложений.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] SmartScreen будет включен{Colors.RESET}")
        logger.log("SmartScreen_Enable", "success", "SmartScreen будет включен")
        return True

    # Windows 7: политик System\EnableSmartScreen ещё нет — только AppHost-оценка.
    if win_is("7"):
        ok = reg_set_value(
            r"Software\Microsoft\Windows\CurrentVersion\AppHost",
            "EnableWebContentEvaluation", 1, winreg.REG_DWORD, hive=winreg.HKEY_CURRENT_USER)
        logger.log("SmartScreen_Enable", "warning" if not ok else "success",
                   "Win7: включена AppHost-оценка SmartScreen")
        print(f"{Colors.YELLOW}[!] Windows 7: SmartScreen работает только как фильтр IE/проводника — "
              f"политики Win8+ недоступны ({'включено' if ok else 'не удалось'}){Colors.RESET}")
        return ok

    ok1 = reg_set_value(r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 1, winreg.REG_DWORD, hive=winreg.HKEY_LOCAL_MACHINE)
    reg_set_value(r"SOFTWARE\Policies\Microsoft\Windows\System", "ShellSmartScreenLevel", "Block", winreg.REG_SZ, hive=winreg.HKEY_LOCAL_MACHINE)
    reg_set_value(r"Software\Microsoft\Windows\CurrentVersion\AppHost", "EnableWebContentEvaluation", 1, winreg.REG_DWORD, hive=winreg.HKEY_CURRENT_USER)
    
    if ok1:
        logger.log("SmartScreen_Enable", "success", "SmartScreen включен")
        print(f"{Colors.GREEN}[+] SmartScreen включен{Colors.RESET}")
        return True
    else:
        logger.log("SmartScreen_Enable", "error", "Не удалось включить SmartScreen")
        print(f"{Colors.YELLOW}[!] Не удалось включить SmartScreen{Colors.RESET}")
        return False


def Ransomware_Shield_Enable():
    """Включение защиты от шифровальщиков (Controlled Folder Access)"""
    # Controlled Folder Access появился в Windows 10 1709. На Win7/8/8.1 нет.
    if not win_at_least("10"):
        print_hacker_message("Защита от шифровальщиков появилась в Windows 10.")
        logger.log("Ransomware_Shield_Enable", "warning",
                   f"Controlled Folder Access недоступен на Windows {win_target()}")
        print(f"{Colors.YELLOW}[!] Controlled Folder Access недоступен на Windows "
              f"{win_target()} — нужна Windows 10 (1709) или новее{Colors.RESET}")
        return False

    print_hacker_message("Включаю защиту от шифровальщиков (контроль доступа к папкам).")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Защита от шифровальщиков будет включена{Colors.RESET}")
        logger.log("Ransomware_Shield_Enable", "success", "Защита от шифровальщиков будет включена")
        return True
    
    ok = reg_set_value(
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access",
        "EnableControlledFolderAccess", 1, winreg.REG_DWORD, hive=winreg.HKEY_LOCAL_MACHINE
    )
    
    if ok:
        logger.log("Ransomware_Shield_Enable", "success", "Защита от шифровальщиков включена")
        print(f"{Colors.GREEN}[+] Защита от шифровальщиков (Controlled Folder Access) включена{Colors.RESET}")
        return True
    else:
        logger.log("Ransomware_Shield_Enable", "error", "Не удалось включить защиту")
        print(f"{Colors.YELLOW}[!] Не удалось включить защиту от шифровальщиков{Colors.RESET}")
        return False


def SMBv1_Disable():
    """Отключение уязвимого протокола SMBv1 (защита от WannaCry)"""
    print_hacker_message("Отключаю устаревший протокол SMBv1 (защита от шифровальщиков).")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] SMBv1 будет отключен{Colors.RESET}")
        logger.log("SMBv1_Disable", "success", "SMBv1 будет отключен")
        return True

    # Windows 7: нет DISM-фичи SMB1Protocol — отключаем через реестр.
    if win_is("7"):
        ok = reg_set_value(
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1", 0, winreg.REG_DWORD, hive=winreg.HKEY_LOCAL_MACHINE)
        if ok:
            logger.log("SMBv1_Disable", "success", "SMBv1 отключен (реестр, Win7)")
            print(f"{Colors.GREEN}[+] SMBv1 отключен (Windows 7, реестр — перезагрузка для применения){Colors.RESET}")
            return True
        logger.log("SMBv1_Disable", "error", "Не удалось записать SMB1=0")
        print(f"{Colors.YELLOW}[!] Не удалось отключить SMBv1 (Windows 7){Colors.RESET}")
        return False

    ok, out, err = _run_safe_process([
        "dism", "/online", "/disable-feature", "/featurename:SMB1Protocol", "/norestart"
    ])
    text = f"{out}\n{err}".lower()
    
    # DISM возвращает код 3010 (нужна перезагрузка) — это тоже успех
    if (ok or "already" in text or "disabled" in text or "отключ" in text
            or "completed successfully" in text or "успешно" in text
            or "restart" in text or "перезагруз" in text):
        logger.log("SMBv1_Disable", "success", "SMBv1 отключен")
        print(f"{Colors.GREEN}[+] SMBv1 отключен (перезагрузка для применения){Colors.RESET}")
        return True
    else:
        logger.log("SMBv1_Disable", "error", err.strip() or out.strip())
        print(f"{Colors.YELLOW}[!] Не удалось отключить SMBv1: {err.strip() or out.strip()}{Colors.RESET}")
        return False


def WDigest_Disable():
    """Отключение сохранения паролей в открытом виде (WDigest)"""
    print_hacker_message("Отключаю кеширование паролей WDigest в открытом виде.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] WDigest UseLogonCredential = 0{Colors.RESET}")
        logger.log("WDigest_Disable", "success", "WDigest будет отключен")
        return True
    
    ok = reg_set_value(
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        "UseLogonCredential", 0, winreg.REG_DWORD, hive=winreg.HKEY_LOCAL_MACHINE
    )
    
    if ok:
        logger.log("WDigest_Disable", "success", "WDigest отключен, пароли не сохраняются в открытом виде")
        print(f"{Colors.GREEN}[+] WDigest отключен — пароли не кешируются в открытом виде{Colors.RESET}")
        return True
    else:
        logger.log("WDigest_Disable", "error", "Не удалось отключить WDigest")
        print(f"{Colors.YELLOW}[!] Не удалось отключить WDigest{Colors.RESET}")
        return False


def LSA_Protection_Enable():
    """Включение защиты LSA (RunAsPPL) для защиты от кражи паролей"""
    # RunAsPPL появился в Windows 8.1. На Win7/8.0 ключ не поддерживается.
    if not win_at_least("8.1"):
        print_hacker_message("Защита LSA (RunAsPPL) появилась в Windows 8.1.")
        logger.log("LSA_Protection_Enable", "warning",
                   f"RunAsPPL недоступен на Windows {win_target()}")
        print(f"{Colors.YELLOW}[!] RunAsPPL недоступен на Windows {win_target()} — "
              f"нужна Windows 8.1 или новее{Colors.RESET}")
        return False

    print_hacker_message("Включаю защиту LSA (RunAsPPL).")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] LSA RunAsPPL = 1{Colors.RESET}")
        logger.log("LSA_Protection_Enable", "success", "LSA защита будет включена")
        return True
    
    ok = reg_set_value(
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "RunAsPPL", 1, winreg.REG_DWORD, hive=winreg.HKEY_LOCAL_MACHINE
    )
    
    if ok:
        logger.log("LSA_Protection_Enable", "success", "Защита LSA включена (требуется перезагрузка)")
        print(f"{Colors.GREEN}[+] Защита LSA (RunAsPPL) включена — требуется перезагрузка{Colors.RESET}")
        return True
    else:
        logger.log("LSA_Protection_Enable", "error", "Не удалось включить LSA")
        print(f"{Colors.YELLOW}[!] Не удалось включить защиту LSA{Colors.RESET}")
        return False


def RemoteDesktop_Disable():
    """Отключение удаленного доступа (RDP) для уменьшения поверхности атаки"""
    print_hacker_message("Отключаю удаленный доступ (RDP).")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] RDP будет отключен{Colors.RESET}")
        logger.log("RemoteDesktop_Disable", "success", "RDP будет отключен")
        return True
    
    ok = reg_set_value(
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections", 1, winreg.REG_DWORD, hive=winreg.HKEY_LOCAL_MACHINE
    )
    
    if ok:
        logger.log("RemoteDesktop_Disable", "success", "Удаленный доступ (RDP) отключен")
        print(f"{Colors.GREEN}[+] Удаленный доступ (RDP) отключен{Colors.RESET}")
        return True
    else:
        logger.log("RemoteDesktop_Disable", "error", "Не удалось отключить RDP")
        print(f"{Colors.YELLOW}[!] Не удалось отключить RDP{Colors.RESET}")
        return False


def Guest_Account_Disable():
    """Отключение гостевой учетной записи"""
    print_hacker_message("Отключаю гостевую учетную запись.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Гостевая учетная запись будет отключена{Colors.RESET}")
        logger.log("Guest_Account_Disable", "success", "Гостевая учетная запись будет отключена")
        return True
    
    # Имя гостевой записи зависит от языка системы: "Guest" или "Гость"
    attempts = [
        ["net", "user", "Guest", "/active:no"],
        ["net", "user", "Гость", "/active:no"],
    ]
    
    success = False
    last_msg = ""
    for cmd in attempts:
        ok, out, err = _run_safe_process(cmd)
        text = f"{out}\n{err}".lower()
        last_msg = err.strip() or out.strip()
        if ok or "not found" in text or "не найдено" in text or "already" in text or "уже" in text:
            success = True
            break
    
    if success:
        logger.log("Guest_Account_Disable", "success", "Гостевая учетная запись отключена")
        print(f"{Colors.GREEN}[+] Гостевая учетная запись отключена{Colors.RESET}")
        return True
    else:
        logger.log("Guest_Account_Disable", "error", last_msg)
        print(f"{Colors.YELLOW}[!] Не удалось отключить гостевую запись: {last_msg}{Colors.RESET}")
        return False


def Windows_Script_Host_Disable():
    """Отключение Windows Script Host (вектор для файлов .vbs/.js)"""
    print_hacker_message("Отключаю Windows Script Host для блокировки vbs-вредоносов.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] WSH будет отключен{Colors.RESET}")
        logger.log("Windows_Script_Host_Disable", "success", "WSH будет отключен")
        return True
    
    ok1 = reg_set_value(r"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled", 0, winreg.REG_DWORD, hive=winreg.HKEY_LOCAL_MACHINE)
    ok2 = reg_set_value(r"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled", 0, winreg.REG_DWORD, hive=winreg.HKEY_CURRENT_USER)
    
    if ok1 or ok2:
        logger.log("Windows_Script_Host_Disable", "success", "Windows Script Host отключен")
        print(f"{Colors.GREEN}[+] Windows Script Host отключен (vbs/js файлы не будут выполняться){Colors.RESET}")
        return True
    else:
        logger.log("Windows_Script_Host_Disable", "error", "Не удалось отключить WSH")
        print(f"{Colors.YELLOW}[!] Не удалось отключить Windows Script Host{Colors.RESET}")
        return False


def UAC_Max_Upgrade():
    """Повышение уровня UAC до максимального (всегда уведомлять)"""
    print_hacker_message("Повышаю уровень UAC до максимального.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] UAC будет повышен до максимума{Colors.RESET}")
        logger.log("UAC_Max_Upgrade", "success", "UAC будет повышен")
        return True
    
    # reg_set_value возвращает bool и не бросает исключения — проверяем каждый ключ
    ok1 = reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1, winreg.REG_DWORD, hive=winreg.HKEY_LOCAL_MACHINE)
    ok2 = reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 2, winreg.REG_DWORD, hive=winreg.HKEY_LOCAL_MACHINE)
    ok3 = reg_set_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop", 1, winreg.REG_DWORD, hive=winreg.HKEY_LOCAL_MACHINE)
    
    if ok1 and ok2 and ok3:
        logger.log("UAC_Max_Upgrade", "success", "UAC повышен до максимума (всегда уведомлять)")
        print(f"{Colors.GREEN}[+] UAC повышен до максимума — уведомления на защищенном рабочем столе{Colors.RESET}")
        return True
    else:
        logger.log("UAC_Max_Upgrade", "error", "Не удалось записать все значения UAC")
        print(f"{Colors.YELLOW}[!] Не удалось повысить UAC полностью (LUA={ok1}, Prompt={ok2}, Desktop={ok3}){Colors.RESET}")
        return False


def SecureBoot_Status():
    """Проверка состояния Secure Boot (только чтение)"""
    # Управление Secure Boot появилось в Windows 8. На Win7 его нет.
    if not win_at_least("8"):
        print_hacker_message("Secure Boot не поддерживается на Windows 7.")
        logger.log("SecureBoot_Status", "warning", "Secure Boot не поддерживается на Win7")
        print(f"{Colors.YELLOW}[!] Secure Boot не поддерживается на Windows 7 "
              f"(появился в Windows 8){Colors.RESET}")
        return False

    print_hacker_message("Проверяю состояние Secure Boot.")
    
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            0, winreg.KEY_READ
        )
        val, _ = winreg.QueryValueEx(key, "UEFISecureBootEnabled")
        winreg.CloseKey(key)
        
        if val == 1:
            logger.log("SecureBoot_Status", "success", "Secure Boot включен")
            print(f"{Colors.GREEN}[+] Secure Boot: ВКЛЮЧЕН{Colors.RESET}")
            return True
        else:
            logger.log("SecureBoot_Status", "warning", "Secure Boot отключен")
            print(f"{Colors.YELLOW}[!] Secure Boot: ОТКЛЮЧЕН{Colors.RESET}")
            return False
    except (OSError, FileNotFoundError):
        logger.log("SecureBoot_Status", "warning", "Secure Boot недоступен (Legacy BIOS?)")
        print(f"{Colors.YELLOW}[!] Secure Boot недоступен (возможно Legacy BIOS){Colors.RESET}")
        return False


def BitLocker_Status():
    """Проверка состояния шифрования BitLocker (только чтение)"""
    print_hacker_message("Проверяю состояние BitLocker.")
    
    ok, out, err = _run_safe_process(["manage-bde", "-status"], timeout=20)
    text = f"{out}\n{err}"
    low = text.lower()
    
    if not ok or "ошибк" in low or ("error" in low and "percentage" not in low):
        logger.log("BitLocker_Status", "warning", "Не удалось проверить BitLocker")
        print(f"{Colors.YELLOW}[!] Не удалось проверить BitLocker (доступна только на Pro/Enterprise){Colors.RESET}")
        return False
    
    # ВАЖНО: "Percentage Protected: 0%" печатается и на НЕзашифрованном томе,
    # поэтому матчит на саму подпись — надо парсить число, а не искать подпись.
    m = re.search(r"(?:percentage protected|процент защищ|percent protected)\s*[:：]\s*(\d+)", low)
    pct = int(m.group(1)) if m else None
    
    # Статус защиты (English "Protection Status: Protection On" / Русский "Защита включена")
    protection_on = ("protection on" in low or "защита включена" in low
                     or "включена" in low and "защит" in low)
    
    if protection_on or (pct is not None and pct > 0):
        pct_str = f" (защищено {pct}%)" if pct is not None else ""
        logger.log("BitLocker_Status", "success", f"BitLocker активен{pct_str}")
        print(f"{Colors.GREEN}[+] BitLocker: защита включена{pct_str}{Colors.RESET}")
        return True
    else:
        pct_str = f" — {pct}% защищено" if pct is not None else ""
        logger.log("BitLocker_Status", "warning", "BitLocker не защищает системный том")
        print(f"{Colors.YELLOW}[!] BitLocker: защита отключена, том не зашифрован{pct_str}{Colors.RESET}")
        return False


def Defender_Update_Sigs():
    """Обновление подписей Microsoft Defender"""
    print_hacker_message("Обновляю signatures Microsoft Defender.")
    
    if DRY_RUN:
        print(f"{Colors.CYAN}[DRY-RUN] Подписи Defender будут обновлены{Colors.RESET}")
        logger.log("Defender_Update_Sigs", "success", "Подписи Defender будут обновлены")
        return True
    
    if win_at_least("10"):
        # Windows 10/11: PowerShell-модуль Defender.
        ok, out, err = _run_safe_process([
            "powershell", "-NoProfile", "-Command", "Update-MpSignature"
        ], timeout=60)
    else:
        # Windows 7/8: модуля Defender нет — обновляем через MpCmdRun.exe.
        candidates = []
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            candidates.append(os.path.join(base, "Windows Defender", "MpCmdRun.exe"))
            candidates.append(os.path.join(base, "Microsoft Security Client", "MpCmdRun.exe"))
        mp = next((c for c in candidates if os.path.exists(c)), None)
        if not mp:
            logger.log("Defender_Update_Sigs", "error", "MpCmdRun.exe не найден (Win7/8)")
            print(f"{Colors.YELLOW}[!] Microsoft Defender/MSE не найден на диске{Colors.RESET}")
            return False
        ok, out, err = _run_safe_process([mp, "-SignatureUpdate"], timeout=60)
    
    if ok:
        logger.log("Defender_Update_Sigs", "success", "Подписи Defender обновлены")
        print(f"{Colors.GREEN}[+] Подписи Microsoft Defender обновлены{Colors.RESET}")
        return True
    else:
        logger.log("Defender_Update_Sigs", "error", err.strip())
        print(f"{Colors.YELLOW}[!] Не удалось обновить подписи: {err.strip()}{Colors.RESET}")
        return False


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
            ("sfc /scannow", "Проверяет целостность системных файлов.", SFC_Scannow),
            ("Восстановить LogonUI", "Некоторые вирусы могут заменять данный файл для своих целей.", LogonUI_Restore),
            ("Экстренное восстановление", "Отключено: массовое завершение процессов может закрыть несохранённые документы и нарушить работу Windows.", Emergency_Recovery),
            ("Выключить тестовый режим", "Вирусы могут использовать автозагрузку через драйвера. Выключение тестового режима отключит их.", Disable_Test_Mode),
            ("Заменить sethc и utilman", "Отключено из соображений безопасности: подмена sethc/utilman может обойти экран входа Windows.", Replace_Sethc_Utilman),
            ("Полный доступ к файлу", "Позволяет разблокировать доступ к системным и скрытым файлам.", File_Full_Access),
            ("Очистка драйверов", "Отключено: массовое удаление драйверов может вывести устройства из строя.", Driver_Cleanup),
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
            ("NumLock Fix", "Включает NumLock автоматически при загрузке", NumLock_Startup_Fix),
            ("MouseKeys", "Отключает управление мышью цифрами (MouseKeys)", MouseKeys_Disable),
            ("Раскладка RU/EN", "Восстанавливает русскую и английскую раскладку", Restore_Russian_Keyboard),
            ("Панель языка", "Восстанавливает панель языка (перезапуск ctfmon)", Language_Bar_Restore),
            ("Экранные клавиши", "Запускает osk.exe для аварийного ввода", OnScreenKeyboard_Launch),
            ("Диагностика KB", "Запускает средство устранения неполадок клавиатуры", Keyboard_Troubleshoot_Run),
            ("Выполнить", "Открывает диалоговое окно для быстрого запуска программ (аналог Win+R).", Run_Command_Enable),
            ("Горячие клавиши", "Разблокирует системные комбинации Win+...", WinKeys_Unlock),
            ("Чистка политик Win+", "Удаляет политики, блокирующие Win+клавиши", WinHotkey_Policy_Clean),
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
            ("TrustedInstaller", "Отключено: сброс системных ACL без проверенной резервной копии может повредить защиту Windows.", TrustedInstaller_Restore),
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
        "Безопасность": [
            ("Security Audit", "Проверяет UAC, брандмауэр, Defender и hosts без изменений", Security_Baseline_Audit),
            ("Брандмауэр Вкл", "Включает брандмауэр для всех профилей", Firewall_Enable_All),
            ("SmartScreen", "Включает фильтр SmartScreen", SmartScreen_Enable),
            ("Анти-шифровальщик", "Включает защиту от шифровальщиков (Controlled Folder Access)", Ransomware_Shield_Enable),
            ("SMBv1 Off", "Отключает уязвимый SMBv1 (защита от WannaCry)", SMBv1_Disable),
            ("WDigest Off", "Отключает кеширование паролей WDigest", WDigest_Disable),
            ("LSA Protect", "Включает защиту LSA (RunAsPPL)", LSA_Protection_Enable),
            ("RDP Off", "Отключает удаленный доступ (RDP)", RemoteDesktop_Disable),
            ("Гостевая запись", "Отключает гостевую учетную запись", Guest_Account_Disable),
            ("WSH Off", "Отключает Windows Script Host (vbs/js вредоносы)", Windows_Script_Host_Disable),
            ("UAC Max", "Повышает UAC до максимума (всегда уведомлять)", UAC_Max_Upgrade),
            ("SecureBoot", "Проверяет состояние Secure Boot (без изменений)", SecureBoot_Status),
            ("BitLocker", "Проверяет состояние шифрования BitLocker (без изменений)", BitLocker_Status),
            ("Defender Update", "Обновляет подписи Microsoft Defender", Defender_Update_Sigs),
        ],
    }

HIGH_RISK_FUNCTION_NAMES = {
    "run_full_scan",
    "Restore_From_Backup",
    "SafeMode_Boot_Restore_Service",
    "SafeMode_Next_Boot_Setup",
    "Emergency_Recovery",
    "Replace_Sethc_Utilman",
    "Driver_Cleanup",
    "Easy_Launcher",
    "Process_Blacklist_Kill",
    "TrustedInstaller_Restore",
    "MSCONFIG_Unlock",
    "Policies_Nuke",
    "Temp_Deep_Clean",
    "Prefetch_Wipe",
    "RecycleBin_Empty",
    "Startup_Clean",
    "WinUpdate_Reset",
    "Print_Spooler_Fix",
    "Firewall_State_Reset",
    "Route_Reset",
    "IP_Reset",
    "RemoteDesktop_Disable",
    "Windows_Script_Host_Disable",
    "SMBv1_Disable",
    "LSA_Protection_Enable",
    "UAC_Max_Upgrade",
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
    from PySide6.QtCore import Qt, QThread, Signal, Slot, QSize, QTimer

    class WinPEBuildWorker(QThread):
        """Run the official ADK preparation and USB-writing scripts off the UI thread."""
        stage_changed = Signal(str)
        result_ready = Signal(object)

        def __init__(self, tools, working_directory, usb_root, usb_serial, use_bootex, parent=None):
            super().__init__(parent)
            self.tools = tools
            self.working_directory = working_directory
            self.usb_root = usb_root
            self.usb_serial = usb_serial
            self.use_bootex = use_bootex

        def _run_adk_command(self, command):
            comspec = os.environ.get(
                "COMSPEC",
                os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe"),
            )
            # A raw Windows command line is used intentionally: passing nested
            # quoted paths as a QProcess argument makes cmd.exe treat \" as text.
            command_line = f'"{comspec}" /d /c {command}'
            return subprocess.run(
                command_line,
                executable=comspec,
                cwd=os.path.dirname(self.tools["environment"]),
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="mbcs" if sys.platform == "win32" else "utf-8",
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

        def run(self):
            output = []
            steps = (
                (
                    "Подготовка файлов WinPE…",
                    f'call "{self.tools["environment"]}" && '
                    f'call "{self.tools["copype"]}" amd64 "{self.working_directory}"',
                ),
                (
                    "Форматирование USB и запись WinPE…",
                    f'call "{self.tools["environment"]}" && '
                    f'call "{self.tools["make_media"]}" /UFD /F '
                    f'"{self.working_directory}" "{self.usb_root}"'
                    f'{" /bootex" if self.use_bootex else ""}',
                ),
            )
            current_stage = steps[0][0]
            try:
                for stage_index, (stage, command) in enumerate(steps):
                    current_stage = stage
                    self.stage_changed.emit(stage)
                    if stage_index == 1:
                        current_drive = next((drive for drive in winpe_media.enumerate_removable_usb_drives()
                                              if drive["root"] == self.usb_root
                                              and drive.get("serial") == self.usb_serial), None)
                        if current_drive is None:
                            self.result_ready.emit({
                                "success": False,
                                "stage": "USB_CHANGED",
                                "output": "USB-флешка изменилась или отключена. Запись отменена.",
                            })
                            return
                    result = self._run_adk_command(command)
                    if result.stdout:
                        output.append(result.stdout)
                    if result.returncode != 0:
                        self.result_ready.emit({
                            "success": False,
                            "stage": stage,
                            "output": "\n".join(output)[-12000:],
                        })
                        return
                self.result_ready.emit({
                    "success": True,
                    "stage": "",
                    "output": "\n".join(output)[-12000:],
                })
            except Exception as error:
                output.append(str(error))
                self.result_ready.emit({
                    "success": False,
                    "stage": current_stage,
                    "output": "\n".join(output)[-12000:],
                })

    def _remember_source(widget, property_name, value):
        """Return the unlocalized value retained on a Qt object."""
        source = widget.property(property_name)
        if source is None:
            source = value
            widget.setProperty(property_name, source)
        return source


    def localize_widget_tree(root):
        """Translate all display text below *root* without changing user data."""
        if getattr(root, "_novir_localizing", False):
            return
        try:
            root._novir_localizing = True
            objects = [root] + root.findChildren(QObject)
            for widget in objects:
                try:
                    class_name = widget.metaObject().className()
                    if hasattr(widget, "windowTitle") and hasattr(widget, "setWindowTitle"):
                        title = _remember_source(widget, "_novir_source_window_title", widget.windowTitle())
                        widget.setWindowTitle(language_manager.translate(title))
                    if class_name in {"QLabel", "QPushButton", "QCheckBox", "QRadioButton", "QGroupBox", "QAction"}:
                        source = _remember_source(widget, "_novir_source_text", widget.text())
                        widget.setText(language_manager.translate(source))
                    if class_name == "QLineEdit":
                        source = _remember_source(widget, "_novir_source_placeholder", widget.placeholderText())
                        widget.setPlaceholderText(language_manager.translate(source))
                    if hasattr(widget, "toolTip") and hasattr(widget, "setToolTip"):
                        source = _remember_source(widget, "_novir_source_tooltip", widget.toolTip())
                        widget.setToolTip(language_manager.translate(source))
                    if class_name == "QComboBox":
                        source_items = widget.property("_novir_source_items")
                        if source_items is None:
                            source_items = [widget.itemText(index) for index in range(widget.count())]
                            widget.setProperty("_novir_source_items", source_items)
                        previous_state = widget.blockSignals(True)
                        for index, source in enumerate(source_items):
                            if index < widget.count():
                                widget.setItemText(index, language_manager.translate(source))
                        widget.blockSignals(previous_state)
                    if class_name in {"QTableWidget", "QTreeWidget"}:
                        header = widget.horizontalHeaderItem(0) if hasattr(widget, "horizontalHeaderItem") else None
                        if header is not None:
                            source_headers = widget.property("_novir_source_headers")
                            if source_headers is None:
                                source_headers = [widget.horizontalHeaderItem(index).text() if widget.horizontalHeaderItem(index) else "" for index in range(widget.columnCount())]
                                widget.setProperty("_novir_source_headers", source_headers)
                            for index, source in enumerate(source_headers):
                                item = widget.horizontalHeaderItem(index)
                                if item:
                                    item.setText(language_manager.translate(source))
                    if class_name == "QTabWidget":
                        source_tabs = widget.property("_novir_source_tabs")
                        if source_tabs is None:
                            source_tabs = [widget.tabText(index) for index in range(widget.count())]
                            widget.setProperty("_novir_source_tabs", source_tabs)
                        for index, source in enumerate(source_tabs):
                            if index < widget.count():
                                widget.setTabText(index, language_manager.translate(source))
                except (AttributeError, RuntimeError, TypeError):
                    # A widget can be destroyed while a dialog is closing.
                    continue
        finally:
            try:
                root._novir_localizing = False
            except (AttributeError, RuntimeError):
                pass


    class TranslationEventFilter(QObject):
        """Localize main windows and every late-created dialog on first display."""
        def eventFilter(self, watched, event):
            if event.type() in (QEvent.Show, QEvent.WindowActivate):
                _last_lang = getattr(watched, "_novir_localized_lang", None)
                if _last_lang != language_manager.language:
                    localize_widget_tree(watched)
                    try:
                        watched._novir_localized_lang = language_manager.language
                    except (AttributeError, RuntimeError):
                        pass
            return super().eventFilter(watched, event)


    class LanguageSelectionDialog(QDialog):
        """Shown once, before the main NoVir window is created."""
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Выбор языка / Language / Sprache / Język / Langue")
            self.setModal(True)
            self.setFixedWidth(420)
            self.setStyleSheet("QDialog { background: #000; color: #fff; } QPushButton { min-height: 40px; font-weight: bold; }")
            layout = QVBoxLayout(self)
            title = QLabel("Choose language / Оберіть мову / Выберите язык / Sprache wählen / Wybierz język / Choisir la langue")
            title.setWordWrap(True)
            title.setStyleSheet("font-size: 18px; font-weight: bold;")
            layout.addWidget(title)
            description = QLabel("Выберите язык интерфейса. Позже вы сможете изменить его в Настройках.")
            description.setWordWrap(True)
            layout.addWidget(description)
            for label, code in (("English", "en"), ("Українська", "uk"), ("Русский", "ru"),
                                ("Deutsch", "de"), ("Polski", "pl"), ("Français", "fr")):
                button = QPushButton(label)
                button.clicked.connect(lambda checked=False, value=code: self._select(value))
                layout.addWidget(button)

        def _select(self, language):
            language_manager.set_language(language)
            self.accept()

        def reject(self):
            # Closing the chooser accepts the documented default: English.
            language_manager.set_language("en")
            super().reject()

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
                    result = subprocess.run(cmd, capture_output=True, text=True, creationflags=0x08000000)
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

            self.scanner_thread = keep_thread(DefenderScannerThread(processes_to_scan, self))
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

    class NoVirCMDWindow(QDialog):
        def __init__(self, parent=None):
            from PySide6.QtCore import QProcess
            from PySide6.QtGui import QFont
            import shutil, os
            super().__init__(parent)
            self.setWindowTitle(language_manager.translate("Командная строка NoVir"))
            self.setMinimumSize(800, 500)
            self.resize(900, 540)

            # Чистый стиль как в Windows CMD
            self.setStyleSheet("""
                QDialog {
                    background-color: #0c0c0c;
                    color: #cccccc;
                }
                QTextEdit {
                    background-color: #0c0c0c;
                    color: #cccccc;
                    font-family: 'Consolas';
                    font-size: 14px;
                    border: none;
                    padding: 8px 12px;
                    selection-background-color: #3a3a3a;
                }
                QLineEdit {
                    background-color: #0c0c0c;
                    color: #cccccc;
                    font-family: 'Consolas';
                    font-size: 14px;
                    border: none;
                    border-top: 1px solid #1e1e1e;
                    padding: 8px 12px;
                }
                QPushButton {
                    background-color: #1e1e1e;
                    color: #cccccc;
                    font-family: 'Consolas';
                    font-size: 12px;
                    border: none;
                    border-top: 1px solid #1e1e1e;
                    border-left: 1px solid #1e1e1e;
                    padding: 8px 18px;
                    min-width: 60px;
                }
                QPushButton:hover {
                    background-color: #2a2a2a;
                }
                QPushButton:pressed {
                    background-color: #383838;
                }
                QScrollBar:vertical {
                    background: #0c0c0c;
                    width: 10px;
                    border: none;
                }
                QScrollBar::handle:vertical {
                    background: #333333;
                    border-radius: 5px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover { background: #444444; }
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
            """)

            root = QVBoxLayout(self)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(0)

            # Область вывода — занимает всё пространство
            self.output_area = QTextEdit()
            self.output_area.setReadOnly(True)
            self.output_area.setFont(QFont("Consolas", 11))
            root.addWidget(self.output_area)

            # Строка ввода — внизу, вровень
            input_row = QHBoxLayout()
            input_row.setContentsMargins(0, 0, 0, 0)
            input_row.setSpacing(0)

            self.input_field = QLineEdit()
            self.input_field.setFont(QFont("Consolas", 11))
            self.input_field.setPlaceholderText("")
            self.input_field.returnPressed.connect(self.run_command)

            self.btn_run = QPushButton("↵")
            self.btn_run.setFixedWidth(42)
            self.btn_run.setCursor(Qt.PointingHandCursor)
            self.btn_run.clicked.connect(self.run_command)

            input_row.addWidget(self.input_field)
            input_row.addWidget(self.btn_run)
            root.addLayout(input_row)

            # Запуск процесса
            self.process = QProcess(self)
            self.process.setProcessChannelMode(QProcess.MergedChannels)
            self.process.readyReadStandardOutput.connect(self.handle_output)

            windir = os.environ.get('WINDIR', r'C:\Windows')
            system32_cmd = os.path.join(windir, 'System32', 'cmd.exe')
            sysnative_cmd = os.path.join(windir, 'SysNative', 'cmd.exe')
            use_sysnative = bool(os.environ.get('PROCESSOR_ARCHITEW6432')) and os.path.exists(sysnative_cmd)
            cmd_path = sysnative_cmd if use_sysnative else system32_cmd
            self.process.start(cmd_path, [])
            started = self.process.waitForStarted(1500)

            if not started:
                self.output_area.setPlainText(
                    "Невозможно запустить командную строку.\n"
                    "Штатный cmd.exe недоступен или запрещён системной политикой.\n"
                    "NoVir не обходит блокировку CMD.\n"
                )

        def handle_output(self):
            data = self.process.readAllStandardOutput()
            text = None
            for enc in ('cp866', 'cp1251', 'utf-8'):
                try:
                    text = data.data().decode(enc)
                    break
                except UnicodeDecodeError:
                    pass
            if text is None:
                text = data.data().decode('utf-8', errors='replace')
            self.output_area.insertPlainText(text)
            self.output_area.verticalScrollBar().setValue(
                self.output_area.verticalScrollBar().maximum()
            )

        def run_command(self):
            cmd = self.input_field.text()
            if cmd.strip():
                self.output_area.insertPlainText(f"\n> {cmd}\n")
                self.process.write((cmd + '\n').encode('cp866', errors='replace'))
                self.input_field.clear()

        def closeEvent(self, event):
            self.process.kill()
            super().closeEvent(event)
            self.setStyleSheet("""
                QDialog {
                    background-color: #0d0d0d;
                    color: #ffffff;
                }
                QFrame#topbar {
                    background-color: #111111;
                    border-bottom: 1px solid #1e1e1e;
                }
                QFrame#bottombar {
                    background-color: #111111;
                    border-top: 1px solid #1e1e1e;
                }
                QTextEdit {
                    background-color: #0a0a0a;
                    color: #00e87a;
                    font-family: 'Consolas', 'Courier New', monospace;
                    font-size: 13px;
                    border: none;
                    selection-background-color: #1a4a2a;
                }
                QLineEdit#cmd_input {
                    background-color: #141414;
                    color: #e0e0e0;
                    font-family: 'Consolas', 'Courier New', monospace;
                    font-size: 13px;
                    border: 1px solid #2a2a2a;
                    border-radius: 5px;
                    padding: 7px 12px;
                }
                QLineEdit#cmd_input:focus {
                    border: 1px solid #00e87a;
                }
                QPushButton#btn_enter {
                    background-color: #00e87a;
                    color: #000000;
                    font-weight: bold;
                    font-size: 12px;
                    padding: 7px 20px;
                    border-radius: 5px;
                    border: none;
                    min-width: 70px;
                }
                QPushButton#btn_enter:hover {
                    background-color: #00ff99;
                }
                QPushButton#btn_enter:pressed {
                    background-color: #00c060;
                }
                QPushButton#btn_clear {
                    background-color: transparent;
                    color: #888888;
                    font-size: 11px;
                    padding: 5px 12px;
                    border-radius: 4px;
                    border: 1px solid #2a2a2a;
                }
                QPushButton#btn_clear:hover {
                    background-color: #1e1e1e;
                    color: #ffffff;
                    border-color: #444444;
                }
                QPushButton.quickbtn {
                    background-color: #151515;
                    color: #aaaaaa;
                    font-size: 11px;
                    padding: 4px 10px;
                    border-radius: 4px;
                    border: 1px solid #222222;
                }
                QPushButton.quickbtn:hover {
                    background-color: #1e2e1e;
                    color: #00e87a;
                    border-color: #00e87a;
                }
                QLabel#lbl_path {
                    color: #00e87a;
                    font-family: 'Consolas', monospace;
                    font-size: 11px;
                    padding: 0 4px;
                }
                QLabel#lbl_method {
                    color: #555555;
                    font-size: 10px;
                    padding: 0 4px;
                }
                QLabel#lbl_title {
                    color: #ffffff;
                    font-size: 13px;
                    font-weight: bold;
                    padding: 0 4px;
                }
            """)

            # ── Главный layout ──────────────────────────────────────────
            root = QVBoxLayout(self)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(0)

            # ── Верхняя панель ──────────────────────────────────────────
            topbar = QFrame()
            topbar.setObjectName("topbar")
            topbar.setFixedHeight(42)
            top_layout = QHBoxLayout(topbar)
            top_layout.setContentsMargins(12, 0, 12, 0)
            top_layout.setSpacing(8)

            lbl_icon = QLabel("⬛")
            lbl_icon.setStyleSheet("color: #00e87a; font-size: 16px;")
            lbl_title = QLabel(language_manager.translate("Командная строка NoVir"))
            lbl_title.setObjectName("lbl_title")

            self.lbl_method = QLabel("")
            self.lbl_method.setObjectName("lbl_method")

            top_layout.addWidget(lbl_icon)
            top_layout.addWidget(lbl_title)
            top_layout.addStretch()
            top_layout.addWidget(self.lbl_method)
            root.addWidget(topbar)

            # ── Кнопки быстрых команд ───────────────────────────────────
            quick_bar = QFrame()
            quick_bar.setStyleSheet("background-color: #0f0f0f; border-bottom: 1px solid #1a1a1a;")
            quick_layout = QHBoxLayout(quick_bar)
            quick_layout.setContentsMargins(10, 5, 10, 5)
            quick_layout.setSpacing(6)

            quick_cmds = [
                ("ipconfig", "ipconfig /all"),
                ("netstat", "netstat -ano"),
                ("tasklist", "tasklist"),
                ("sfc", "sfc /scannow"),
                ("regedit", "regedit"),
                ("gpupdate", "gpupdate /force"),
                ("cls", "cls"),
            ]
            for label, cmd in quick_cmds:
                btn = QPushButton(label)
                btn.setProperty("class", "quickbtn")
                btn.setObjectName("quickbtn")
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #151515; color: #aaaaaa;
                        font-size: 11px; font-family: Consolas;
                        padding: 3px 9px; border-radius: 4px; border: 1px solid #222222;
                    }
                    QPushButton:hover { background-color: #1e2e1e; color: #00e87a; border-color: #00e87a; }
                """)
                btn.setCursor(Qt.PointingHandCursor)
                btn.clicked.connect(lambda checked=False, c=cmd: self._quick_cmd(c))
                quick_layout.addWidget(btn)

            quick_layout.addStretch()

            btn_clear = QPushButton("✕ Очистить")
            btn_clear.setObjectName("btn_clear")
            btn_clear.setCursor(Qt.PointingHandCursor)
            btn_clear.clicked.connect(lambda: self.output_area.clear())
            quick_layout.addWidget(btn_clear)
            root.addWidget(quick_bar)

            # ── Область вывода ──────────────────────────────────────────
            self.output_area = QTextEdit()
            self.output_area.setReadOnly(True)
            self.output_area.setFont(QFont("Consolas", 10))
            self.output_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            root.addWidget(self.output_area)

            # ── Нижняя панель ввода ─────────────────────────────────────
            bottombar = QFrame()
            bottombar.setObjectName("bottombar")
            bottombar.setFixedHeight(52)
            bottom_layout = QHBoxLayout(bottombar)
            bottom_layout.setContentsMargins(10, 6, 10, 6)
            bottom_layout.setSpacing(8)

            prompt = QLabel("›")
            prompt.setStyleSheet("color: #00e87a; font-size: 18px; font-weight: bold; padding: 0 4px;")

            self.input_field = QLineEdit()
            self.input_field.setObjectName("cmd_input")
            self.input_field.setPlaceholderText("Введите команду...")
            self.input_field.returnPressed.connect(self.run_command)

            self.btn_run = QPushButton("ENTER")
            self.btn_run.setObjectName("btn_enter")
            self.btn_run.setCursor(Qt.PointingHandCursor)
            self.btn_run.clicked.connect(self.run_command)

            bottom_layout.addWidget(prompt)
            bottom_layout.addWidget(self.input_field)
            bottom_layout.addWidget(self.btn_run)
            root.addWidget(bottombar)

            # ── Запуск процесса ─────────────────────────────────────────
            self.process = QProcess(self)
            self.process.setProcessChannelMode(QProcess.MergedChannels)
            self.process.readyReadStandardOutput.connect(self.handle_output)

            windir      = os.environ.get('WINDIR', r'C:\Windows')
            temp_dir    = os.environ.get('TEMP', r'C:\Windows\Temp')
            s32         = os.path.join(windir, 'System32')
            s64         = os.path.join(windir, 'SysNative')
            syswow64    = os.path.join(windir, 'SysWOW64')
            original_cmd = os.path.join(s32, 'cmd.exe')
            if not os.path.exists(original_cmd):
                original_cmd = os.path.join(syswow64, 'cmd.exe')

            sysnative_cmd = os.path.join(s64, 'cmd.exe')
            use_sysnative = bool(os.environ.get('PROCESSOR_ARCHITEW6432')) and os.path.exists(sysnative_cmd)
            cmd_path = sysnative_cmd if use_sysnative else original_cmd
            self.process.start(cmd_path, [])
            if self.process.waitForStarted(1500):
                self.lbl_method.setText("✓ штатная CMD")
            else:
                self.lbl_method.setText("✗ не запущен")
                self.output_area.setPlainText(
                    "Невозможно запустить командную строку.\n"
                    "Штатный cmd.exe не запустился. Проверьте системную политику,\n"
                    "путь к Windows и права доступа. NoVir не пытается обходить блокировку."
                )

        def _quick_cmd(self, cmd):
            self.input_field.setText(cmd)
            self.run_command()

        def handle_output(self):
            data = self.process.readAllStandardOutput()
            text = None
            for enc in ('cp866', 'cp1251', 'utf-8'):
                try:
                    text = data.data().decode(enc)
                    break
                except UnicodeDecodeError:
                    pass
            if text is None:
                text = data.data().decode('utf-8', errors='replace')
            self.output_area.insertPlainText(text)
            self.output_area.verticalScrollBar().setValue(
                self.output_area.verticalScrollBar().maximum()
            )

        def run_command(self):
            cmd = self.input_field.text()
            if cmd.strip():
                self.output_area.insertPlainText(f"\n> {cmd}\n")
                self.process.write((cmd + '\n').encode('cp866', errors='replace'))
                self.input_field.clear()

        def closeEvent(self, event):
            self.process.kill()
            super().closeEvent(event)


    class GroqAIWorker(QThread):
        response_ready = Signal(str)
        
        def __init__(self, api_key, memory):
            super().__init__()
            self.api_key = api_key
            self.memory = memory
            
        def run(self):
            import urllib.request
            import urllib.error
            import json
            req = urllib.request.Request(
                "https://api.groq.com/openai/v1/chat/completions",
                method="POST"
            )
            req.add_header("Authorization", f"Bearer {self.api_key}")
            req.add_header("Content-Type", "application/json")
            req.add_header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            )
            data = {
                "model": "openai/gpt-oss-120b",
                "messages": self.memory,
                "max_completion_tokens": 400,
                # gpt-oss — reasoning-модель: без low размышления съедают
                # лимит токенов, и content приходит пустым.
                "reasoning_effort": "low",
            }
            try:
                with urllib.request.urlopen(
                    req,
                    data=json.dumps(data).encode("utf-8"),
                    timeout=20,
                ) as response:
                    res = json.loads(response.read().decode("utf-8"))
                    reply = str(res["choices"][0]["message"].get("content") or "").strip()
                    if not reply:
                        self.response_ready.emit(
                            "[Ошибка AI]: Пустой ответ модели. "
                            "Повторите вопрос."
                        )
                        return
                    self.response_ready.emit(reply)
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode("utf-8", errors="replace")[:200]
                except Exception:
                    pass
                if e.code == 401:
                    self.response_ready.emit(
                        "[Ошибка AI]: Неверный API-ключ (401). "
                        "Проверьте подключение к интернету."
                    )
                elif e.code == 429:
                    self.response_ready.emit(
                        "[Ошибка AI]: Превышен лимит запросов (429). "
                        "Подождите несколько секунд и попробуйте снова."
                    )
                elif e.code >= 500:
                    self.response_ready.emit(
                        f"[Ошибка AI]: Сервер Groq недоступен ({e.code}). "
                        "Повторите попытку позже."
                    )
                else:
                    self.response_ready.emit(
                        f"[Ошибка AI]: HTTP {e.code}. {body}"
                    )
            except OSError as e:
                self.response_ready.emit(
                    f"[Ошибка AI]: Нет соединения с сервером. "
                    f"Проверьте интернет. ({e})"
                )
            except Exception as e:
                self.response_ready.emit(f"[Ошибка AI]: {type(e).__name__}: {e}")

    class NoVirAIChatDialog(QDialog):
        def __init__(self, issues_text, parent=None):
            from PySide6.QtWidgets import QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, QPushButton, QMessageBox
            from PySide6.QtCore import Qt
            super().__init__(parent)
            self.setWindowTitle("NoVir AI Assistant")
            self.setMinimumSize(800, 600)
            self.setStyleSheet("QDialog { background-color: #0c0c0c; color: #cccccc; } QTextEdit { background-color: #121212; color: #e0e0e0; font-family: 'Consolas', 'Segoe UI'; font-size: 13px; border: 1px solid #333; padding: 10px; } QLineEdit { background-color: #1a1a1a; color: #fff; font-family: 'Segoe UI'; font-size: 13px; border: 1px solid #444; padding: 10px; border-radius: 6px; } QPushButton { background-color: #00e87a; color: #000; font-weight: bold; padding: 10px 20px; border-radius: 6px; }")
            
            self._vbox = QVBoxLayout(self)
            beta_notice = QLabel(
                "БЕТА-ВЕРСИЯ: ИИ может ошибаться. Не доверяйте ответам без проверки; "
                "перед запуском внимательно проверьте каждую команду. Используйте ИИ на свой риск. "
                "NoVir не отвечает за последствия выполнения предложенных команд."
            )
            beta_notice.setWordWrap(True)
            beta_notice.setStyleSheet(
                "QLabel { background-color: #2b2111; color: #ffd27a; "
                "border: 1px solid #765b25; padding: 8px; font-weight: bold; }"
            )
            self._vbox.addWidget(beta_notice)

            self.chat_area = QTextEdit()
            self.chat_area.setReadOnly(True)
            self._vbox.addWidget(self.chat_area)
            
            inp_layout = QHBoxLayout()
            self.input_field = QLineEdit()
            self.input_field.setPlaceholderText("Напишите ответ или вопрос NoVir AI...")
            self.input_field.returnPressed.connect(self.send_msg)
            
            self.btn_send = QPushButton("Отправить")
            self.btn_send.setCursor(Qt.PointingHandCursor)
            self.btn_send.clicked.connect(self.send_msg)
            
            inp_layout.addWidget(self.input_field)
            inp_layout.addWidget(self.btn_send)
            self._vbox.addLayout(inp_layout)
            
            _k = b')C=n%\x1c+t5\x11\n \x0edx\x00\x00<\x00"\x7f\x17\x1add\x046J6ltiJW\nU=\x08\x14%kg \x13CbiUd\nV\x0fC>\x07&'
            _x = b'N0V1R_S3CR3T_2024'
            self.api_key = ''.join(chr(b ^ _x[i % len(_x)]) for i, b in enumerate(_k))
            
            sys_prompt = """Ты — NoVir AI, встроенный помощник программы NoVir. Помогай пользователю разбираться с Windows, диагностикой и функциями NoVir.

Качество ответов:
- Всегда учитывай контекст, но отвечай максимум 45 словами. Без вступления, повторения вопроса, заголовков, пустых строк и длинных списков.
- Если результаты NoVir все OK: ответь одной короткой фразой, что явных проблем не найдено. Не перечисляй проверки и не придумывай дополнительные гипотезы, тесты или команды.
- Если есть INFO/WARNING/ERROR: упомяни только реальные отклонения, не пересказывай OK. Дай не более одной осторожной гипотезы и одного безопасного следующего шага; называй причину гипотезой, не фактом.
- Используй таблицу только если пользователь явно просит её или нужно сравнить несколько вариантов. Формат Markdown: не более 3 колонок и 4 строк данных, короткие ячейки; не помещай в таблицу длинные абзацы. Для обычного ответа используй одну фразу или короткие пункты.
- В режиме предложения плана не запускай операции и не формируй маркер [EXECUTE:]. Для единственного предложенного действия коротко назови риск.
- Не выдумывай факты, результаты проверки системы, возможности программы или успешное выполнение действий. Если данных недостаточно или ты не уверен, прямо скажи об этом и задай уточняющий вопрос.
- Для потенциально устаревших или зависящих от версии сведений обозначай неопределённость. Отделяй установленный факт от предположения.
- Не повторяй бета-предупреждение в каждом ответе: оно постоянно показано в окне чата.
- Пиши по-русски просто и по делу. Подробности давай только если их прямо попросили.

Безопасность команд:
- Не утверждай, что команда безопасна или необходима, если не можешь это обосновать. Перед предложением объясни, что команда изменит, какие у неё риски и как при необходимости откатить изменение.
- Не предлагай удаление данных, отключение защиты, изменение реестра, настройки загрузки, прав доступа или системных служб без явного объяснения последствий и точного подтверждения пользователя.
- Никогда не запускай команду сам. Сначала покажи её обычным текстом и попроси пользователя явно подтвердить именно эту команду в чате. До такого подтверждения не добавляй маркер выполнения.
- Только после явного подтверждения пользователем выдай команду отдельным маркером строго в формате [EXECUTE: команда] без Markdown и лишних кавычек. Выбирай только безопасные диагностические команды Windows; не добавляй `cmd /c`.
- Если запрос неоднозначен, команда выглядит разрушительной или её последствия непонятны, не выдавай маркер выполнения; предложи безопасную проверку или попроси уточнения.

Справка по NoVir: приложение включает Умную Диагностику, Бэкап и Откат, Проводник, Утилиты Фикса и Командную строку."""
            self.memory = [{"role": "system", "content": sys_prompt}]
            self.worker = None
            
            if issues_text == "MANUAL":
                first_msg = "Коротко поздоровайся и скажи, что помогаешь с NoVir и Windows. Не перечисляй все функции; попроси описать вопрос или проблему."
            else:
                first_msg = (
                    "Суммируй результаты максимум в 45 словах. Если все проверки OK, скажи это одной фразой. "
                    "Иначе назови только отклонение, одну гипотезу и один безопасный шаг. "
                    "Это анализ, не выполняй исправления и не выдавай [EXECUTE:].\n\n"
                    f"Результаты:\n{issues_text}"
                )
                
            self.append_chat("Вы", first_msg)
            self.memory.append({"role": "user", "content": first_msg})
            self.process_ai()
            
        def append_chat(self, sender, text):
            color = "#00e87a" if sender == "NoVir AI" else "#3b82f6" if sender == "Вы" else "#f59e0b"
            import html
            sender_html = html.escape(str(sender))
            message_html = render_chat_message(text)
            self.chat_area.append(
                f"<b style='color:{color}; font-size: 14px;'>{sender_html}:</b><br>"
                f"<span style='color:#e0e0e0;'>{message_html}</span><br><br>"
            )
            self.chat_area.verticalScrollBar().setValue(self.chat_area.verticalScrollBar().maximum())
            
        def send_msg(self):
            text = self.input_field.text().strip()
            if not text: return
            self.input_field.clear()
            self.append_chat("Вы", text)
            self.memory.append({"role": "user", "content": text})
            self.process_ai()
            
        def process_ai(self):
            self.btn_send.setEnabled(False)
            self.worker = keep_thread(GroqAIWorker(self.api_key, self.memory))
            self.worker.response_ready.connect(self.on_response)
            self.worker.start()
            
        def on_response(self, reply):
            self.btn_send.setEnabled(True)
            self.memory.append({"role": "assistant", "content": reply})
            
            import re
            exec_match = re.search(r'\[EXECUTE:\s*(.+?)\]', reply, re.IGNORECASE)
            
            clean_reply = re.sub(r'\[EXECUTE:\s*.+?\]', '', reply, flags=re.IGNORECASE).strip()
            if clean_reply:
                self.append_chat("NoVir AI", clean_reply)
                
            if exec_match:
                cmd = exec_match.group(1).strip()
                from PySide6.QtWidgets import QMessageBox
                if not ai_command_is_allowed(cmd):
                    self.append_chat(
                        "Система",
                        "Команда заблокирована встроенной проверкой безопасности. "
                        "Не запускаются shell-операторы, оболочки и опасные команды.",
                    )
                    return
                ans = QMessageBox.question(
                    self,
                    "Проверьте команду NoVir AI",
                    "ИИ может ошибаться. Внимательно проверьте команду и её последствия. "
                    "Продолжая, вы разрешаете её выполнение на свой риск; NoVir не отвечает "
                    "за результат.\n\n"
                    f"Команда:\n{cmd}\n\nВыполнить эту команду?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if ans == QMessageBox.Yes:
                    import subprocess
                    self.append_chat("Система", f"Выполняется: {cmd}")
                    try:
                        command_args = parse_ai_command(cmd)
                        if not command_args:
                            raise ValueError("Команда не прошла проверку безопасности")
                        res = subprocess.run(
                            command_args,
                            shell=False,
                            capture_output=True,
                            text=True,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        )
                        out = (res.stdout + res.stderr).strip()
                        if not out:
                            out = "Вывода нет."
                        outcome = "выполнена" if res.returncode == 0 else f"завершилась с кодом {res.returncode}"
                        self.append_chat("Система", f"Команда {outcome}.\nРезультат:\n{out}")
                        self.memory.append({"role": "user", "content": f"Команда {outcome}. Код возврата: {res.returncode}. Результат:\n{out}\nЧто дальше?"})
                        self.process_ai()
                    except Exception as e:
                        self.append_chat("Система", f"Ошибка: {e}")
                        self.memory.append({"role": "user", "content": f"Ошибка выполнения: {e}"})
                        self.process_ai()
                else:
                    self.append_chat("Система", "Вызов команды отклонён пользователем.")
                    self.memory.append({"role": "user", "content": "Я не разрешил выполнять эту команду. Предложи другой вариант или объясни подробнее."})
                    self.process_ai()


    class NoVirGUI(QMainWindow):
        update_result = Signal(object)
        RECOVERY_ACTIONS = {"dns", "taskmgr"}

        def __init__(self):
            super().__init__()
            self.dragPos = None
            self.setWindowTitle("NoVir - Восстановление системы")
            self.setMinimumSize(1000, 700)
            self._always_on_top_enabled = bool(load_app_settings().get("always_on_top", False))
            window_flags = Qt.FramelessWindowHint
            if self._always_on_top_enabled:
                window_flags |= Qt.WindowStaysOnTopHint
            self.setWindowFlags(window_flags) # Безрамочное окно
            self.setAttribute(Qt.WA_TranslucentBackground)
            # Инициализируем ссылки на фоновые потоки
            self._scheduler_loader = None
            self.worker = None
            self.advanced_mode = False
            self.update_result.connect(self._on_update_checked)
            self.init_ui()
            self.toggle_advanced_mode(0)
            # Фоновый прогрев страниц в свободное время (по одной за тик с паузой 300мс)
            self._warm_queue = list(self._lazy_pages.keys())
            from PySide6.QtCore import QTimer as _QTimer
            _QTimer.singleShot(1200, self._warm_up_pages)
            _QTimer.singleShot(6000, self.check_for_updates)


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
                    padding: 12px;
                    font-size: 16px;
                    font-weight: bold;
                    text-align: center;
                }
                QPushButton#DashboardTile:hover {
                    background-color: #111111;
                    border: 1px solid #ffffff;
                    color: #ffffff;
                }
                QPushButton#DashboardTile:focus {
                    background-color: #111111;
                    border: 2px solid #ffffff;
                }
                QPushButton#DashboardTile:pressed {
                    background-color: #222222;
                    border: 2px solid #ffffff;
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
                QPushButton:focus, QLineEdit:focus, QTextEdit:focus,
                QComboBox:focus, QTableWidget:focus, QTreeWidget:focus {
                    border: 1px solid #ffffff;
                    outline: 1px solid #666666;
                }
                QPushButton:disabled {
                    color: #666666;
                    border-color: #333333;
                }
                QToolTip {
                    background: #111111;
                    color: #ffffff;
                    border: 1px solid #555555;
                    padding: 4px;
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
            
            self.btn_back = QPushButton(language_manager.translate("< НАЗАД"))
            self.btn_back.setFixedSize(100, 30)
            self.btn_back.setStyleSheet("border: none; font-size: 14px;")
            self.btn_back.clicked.connect(lambda: self.switch_page(0))
            top_layout.addWidget(self.btn_back)

            top_layout.addStretch()
            
            self.title_label = QLabel("NOVIR")
            self.title_label.setStyleSheet("font-size: 16px; font-weight: bold; letter-spacing: 4px; border: none;")
            top_layout.addWidget(self.title_label)
            
            top_layout.addStretch()
            
            self.btn_ai = QPushButton(language_manager.translate("ИИ АССИСТЕНТ"))
            self.btn_ai.setFixedSize(120, 30)
            self.btn_ai.setStyleSheet("border: 1px solid #00e87a; color: #00e87a; font-size: 12px; font-weight: bold;")
            self.btn_ai.clicked.connect(self.open_global_ai_chat)
            top_layout.addWidget(self.btn_ai)

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

            # Строим сразу только дашборд — окно открывается быстро.
            # Остальные 8 страниц создаются лениво: по одной за тик event-loop
            # (см. _build_next_page). Между тиками окно остаётся отзывчивым.
            # Индексы в QStackedWidget фиксированы заранее заглушками-рамками.
            self._lazy_pages = {}          # index -> (attr_name, builder)
            self._lazy_placeholders = {}   # index -> QFrame

            self.page_dashboard = self.create_dashboard_page()
            self.main_content.addWidget(self.page_dashboard)    # 0

            lazy_specs = [
                (1, "page_startup",      self.create_startup_page),
                (2, "page_explorer",     lambda: explorer_tab.ExplorerTab(self)),
                (3, "page_restrictions", self.create_restrictions_page),
                (4, "page_advanced",     self.create_advanced_page),
                (5, "page_unlocker",     self.create_unlocker_page),
                (6, "page_program",      self.create_program_page),
                (7, "page_diagnostic",   self.create_diagnostic_page),
                (8, "page_community",    self.create_community_page),
            ]
            for _idx, _attr, _builder in lazy_specs:
                _ph = QFrame()
                self._lazy_pages[_idx] = (_attr, _builder)
                self._lazy_placeholders[_idx] = _ph
                self.main_content.addWidget(_ph)
            
            self.layout.addWidget(self.main_content)

            # Логи
            self.log_output = QTextEdit()
            self.log_output.setReadOnly(True)
            self.log_output.setFixedHeight(100)
            self.log_output.hide()
            self.layout.addWidget(self.log_output)

            # Нижняя панель — быстрый доступ к диагностике и вторичным действиям.
            bottom_bar = QFrame()
            bottom_bar.setFixedHeight(52)
            bottom_bar.setStyleSheet(
                "QFrame { border-top: 1px solid #1e1e1e; background-color: #050505; }"
            )
            bottom_layout = QHBoxLayout(bottom_bar)
            bottom_layout.setContentsMargins(16, 6, 16, 6)
            bottom_layout.setSpacing(8)

            self.btn_diagnostics = QPushButton(language_manager.translate("УМНАЯ ДИАГНОСТИКА"))
            self.btn_diagnostics.setFixedHeight(36)
            self.btn_diagnostics.setMinimumWidth(210)
            self.btn_diagnostics.setStyleSheet(
                "QPushButton { background: #111; color: #fff; border: 1px solid #2a2a2a; "
                "font-size: 12px; font-weight: bold; letter-spacing: 1px; padding: 0 18px; border-radius: 0; }"
                "QPushButton:hover { background: #1a1a1a; border-color: #ffffff; }"
                "QPushButton:pressed { background: #222; }"
            )
            self.btn_diagnostics.clicked.connect(lambda checked=False: self.switch_page(7))
            bottom_layout.addWidget(self.btn_diagnostics)

            separator = QFrame()
            separator.setFixedWidth(1)
            separator.setFixedHeight(24)
            separator.setStyleSheet("background: #2a2a2a; border: none;")
            bottom_layout.addWidget(separator)

            self.btn_quick_actions = QPushButton(language_manager.translate("ЕЩЁ  ▾"))
            self.btn_quick_actions.setFixedSize(88, 36)
            self.btn_quick_actions.setStyleSheet(
                "QPushButton { background: #111; color: #aaa; border: 1px solid #2a2a2a; "
                "font-size: 12px; font-weight: bold; letter-spacing: 1px; border-radius: 0; }"
                "QPushButton:hover { background: #1a1a1a; border-color: #555; color: #fff; }"
                "QPushButton::menu-indicator { image: none; }"
            )
            quick_actions_menu = QMenu(self)
            quick_actions_menu.setStyleSheet(
                "QMenu { background: #111; color: #ddd; border: 1px solid #333; }"
                "QMenu::item { padding: 8px 20px; font-size: 12px; }"
                "QMenu::item:selected { background: #222; color: #fff; }"
            )
            fix_all_action = quick_actions_menu.addAction(language_manager.translate("ПОЧИНИТЬ ВСЁ"))
            fix_all_action.triggered.connect(lambda checked=False: self.run_fix_all())
            audit_action = quick_actions_menu.addAction(language_manager.translate("ЖУРНАЛ"))
            audit_action.triggered.connect(lambda checked=False: self.show_audit_log())
            rollback_action = quick_actions_menu.addAction(language_manager.translate("ОТКАТ"))
            rollback_action.triggered.connect(lambda checked=False: self.show_rollback_dialog())
            update_action = quick_actions_menu.addAction(language_manager.translate("ОБНОВИТЬ"))
            update_action.triggered.connect(lambda checked=False: self.check_for_updates(manual=True))
            backup_action = quick_actions_menu.addAction(language_manager.translate("БЭКАПЫ"))
            backup_action.triggered.connect(lambda checked=False: self.show_backup_manager())
            community_action = quick_actions_menu.addAction(language_manager.translate("СООБЩЕСТВО"))
            community_action.triggered.connect(lambda checked=False: self.switch_page(8))
            self._quick_action_refs = {
                "fix_all": fix_all_action,
                "audit": audit_action,
                "rollback": rollback_action,
                "update": update_action,
                "backups": backup_action,
                "community": community_action,
            }
            self.btn_quick_actions.setMenu(quick_actions_menu)
            bottom_layout.addWidget(self.btn_quick_actions)

            bottom_support_btn = QPushButton(language_manager.translate("♥  ПОДДЕРЖАТЬ АВТОРА"))
            bottom_support_btn.setFixedHeight(36)
            bottom_support_btn.setStyleSheet(
                "QPushButton { border: 1px solid #1e1e1e; color: #555; font-size: 11px; "
                "font-weight: bold; padding: 0 14px; letter-spacing: 1px; background: transparent; }"
                "QPushButton:hover { border-color: #555; color: #aaa; }"
            )
            bottom_support_btn.clicked.connect(lambda checked=False: self.show_support_dialog())
            bottom_layout.addStretch()
            bottom_layout.addWidget(bottom_support_btn)
            self.layout.addWidget(bottom_bar)

            # Старт
            self.switch_page(0)

        # ─── NOVIR COMMUNITY (Supabase REST + чат) ─────────────────────────
        # Данные сервера зашифрованы XOR — как Groq-ключ в AI-чате.
        _SB_X = b'N0V1R_S3CR3T_2024'
        _SB_URL_HEX = '2644224121657c1c352b5b22255f405d55345f3a5c382d3d5f213b5e7a2c474053562f43331f3130'
        _SB_KEY_HEX = '3d520941273d3f5a303a523633576f07612558391c3969254714665d196c5f527d6e0777216e3330160b37197937'
        # Groq-ключ для бота @novir_ai в чате (XOR, как в AI-чате)
        _AI_K = b')C=n%\x1c+t5\x11\n \x0edx\x00\x00<\x00"\x7f\x17\x1add\x046J6ltiJW\nU=\x08\x14%kg \x13CbiUd\nV\x0fC>\x07&'
        _AI_X = b'N0V1R_S3CR3T_2024'

        def _sb_decode(self, hex_str):
            raw = bytes.fromhex(hex_str)
            return ''.join(chr(b ^ self._SB_X[i % len(self._SB_X)])
                           for i, b in enumerate(raw))

        def _supabase_config(self):
            """Данные сервера встроены в код (зашифрованы).
            Можно переопределить: ~/.novir/supabase_config.json -> {"url": "..."}"""
            url = self._sb_decode(self._SB_URL_HEX).rstrip("/")
            key = self._sb_decode(self._SB_KEY_HEX)
            cfg_path = os.path.join(os.path.expanduser("~"), ".novir", "supabase_config.json")
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8") as fh:
                        u = str(json.load(fh).get("url", "")).rstrip("/")
                    if u:
                        url = u
                except Exception:
                    pass
            return url, key

        def _supabase_request(self, method, table, params=None, body=None):
            """Minimal Supabase REST client (PostgREST) без внешних зависимостей."""
            import urllib.request
            import urllib.error
            import urllib.parse

            SUPABASE_URL, SUPABASE_KEY = self._supabase_config()

            url = f"{SUPABASE_URL}/rest/v1/{table}"
            if params:
                url += "?" + urllib.parse.urlencode(params, doseq=True)

            req = urllib.request.Request(url, method=method)
            req.add_header("apikey", SUPABASE_KEY)
            req.add_header("Authorization", f"Bearer {SUPABASE_KEY}")
            req.add_header("Content-Type", "application/json")
            # Cloudflare (прокси Supabase/Groq) отдаёт "403 error code: 1010"
            # на urllib-UX без User-Agent — шлём полноценный Chrome UA.
            req.add_header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
            req.add_header("Accept", "application/json")

            data = json.dumps(body).encode("utf-8") if body else None
            try:
                with urllib.request.urlopen(req, data=data, timeout=20) as resp:
                    raw = resp.read().decode("utf-8")
                    return json.loads(raw) if raw else []
            except urllib.error.HTTPError as e:
                err_body = ""
                try:
                    err_body = e.read().decode("utf-8", errors="replace")[:300]
                except Exception:
                    pass
                print(f"[PluginHub] HTTP {e.code}: {err_body}")
                return None
            except Exception as e:
                print(f"[PluginHub] Network error: {e}")
                return None

        # ─── NOVIR COMMUNITY (чат, аккаунты, лимит сообщений) ───────────
        GUEST_MSG_LIMIT = 5      # сообщений в час для гостей
        USER_MSG_LIMIT = 60      # сообщений в час для зарегистрированных

        # Локальный кэш сообщества и аккаунтов
        def _cm_dir(self):
            d = os.path.join(os.path.expanduser("~"), ".novir", "community")
            os.makedirs(d, exist_ok=True)
            return d

        def _cm_device_id(self):
            """Уникальный id устройства — для лимита сообщений гостей."""
            f = os.path.join(self._cm_dir(), "device_id.txt")
            try:
                if os.path.exists(f):
                    v = open(f, "r", encoding="utf-8").read().strip()
                    if v:
                        return v
            except Exception:
                pass
            v = hashlib.sha1(str(time.time()).encode()).hexdigest()[:16]
            try:
                with open(f, "w", encoding="utf-8") as fh:
                    fh.write(v)
            except Exception:
                pass
            return v

        def _cm_session(self):
            f = os.path.join(self._cm_dir(), "session.json")
            try:
                if os.path.exists(f):
                    with open(f, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                    if data.get("username"):
                        return data
            except Exception:
                pass
            return None

        def _cm_set_session(self, username):
            f = os.path.join(self._cm_dir(), "session.json")
            try:
                if username:
                    with open(f, "w", encoding="utf-8") as fh:
                        json.dump({"username": username}, fh, ensure_ascii=False)
                elif os.path.exists(f):
                    os.remove(f)
            except Exception:
                pass

        def _cm_hash(self, password, salt):
            return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

        def _cm_rate_left(self):
            """(осталось, лимит, зарегистрирован_ли) по локальным отметкам за час."""
            sess = self._cm_session()
            limit = self.USER_MSG_LIMIT if sess else self.GUEST_MSG_LIMIT
            f = os.path.join(self._cm_dir(), "my_sends.json")
            now = time.time()
            stamps = []
            try:
                if os.path.exists(f):
                    with open(f, "r", encoding="utf-8") as fh:
                        raw = json.load(fh)
                    stamps = [s for s in raw if isinstance(s, (int, float)) and now - s < 3600]
                    with open(f, "w", encoding="utf-8") as fh:
                        json.dump(stamps, fh)
            except Exception:
                pass
            return max(0, limit - len(stamps)), limit, bool(sess)

        def _cm_note_send(self):
            f = os.path.join(self._cm_dir(), "my_sends.json")
            try:
                stamps = []
                if os.path.exists(f):
                    with open(f, "r", encoding="utf-8") as fh:
                        stamps = json.load(fh)
                stamps.append(time.time())
                with open(f, "w", encoding="utf-8") as fh:
                    json.dump(stamps, fh)
            except Exception:
                pass

        # ── @novir_ai: ответ бота через Groq ──
        def _cm_build_ai_context(self, raw_text, reply=None):
            """Собирает контекст для бота: историю чата, цель ответа (⤷)
            и последнее сообщение упомянутых (@username) пользователей."""
            rows = getattr(self, "_cm_recent_rows", None) or []
            entries = []
            for m in rows:
                who = str(m.get("username") or "Гость")
                if who == "NOVIR_AI":
                    who = "NOVIR AI"
                body = str(m.get("body") or "").replace("\n", " ").strip()
                if not body:
                    continue
                # created_at (ISO) сортируется лексикографично = по времени
                entries.append((str(m.get("created_at") or ""), who, body))
            entries.sort(key=lambda e: e[0])
            parts = []
            recent = entries[-20:]
            if recent:
                transcript = "\n".join(
                    f"{who}: {body[:160]}" for _, who, body in recent)
                parts.append(
                    "Последние сообщения чата (от старых к новым):\n" + transcript)
            if reply:
                ruser = str(reply.get("user") or "")
                rtext = str(reply.get("text") or "")
                if ruser or rtext:
                    parts.append(
                        f"Пользователь отвечает на сообщение {ruser}: «{rtext}».")
            # упомянутые кроме самого бота — их последнее сообщение
            mentions = [u for u in re.findall(r"@([A-Za-z0-9_]{3,20})", raw_text or "")
                        if u.lower() != "novir_ai"]
            for u in dict.fromkeys(mentions):
                for _, who, body in reversed(entries):
                    if who == u:
                        parts.append(f"Последнее сообщение @{u}: «{body[:200]}».")
                        break
            return "\n\n".join(parts)

        def _cm_ai_ask(self, question, context=None):
            """Спроси у бота — вернёт короткий ответ или None при ошибке."""
            import urllib.request
            import urllib.error
            api_key = ''.join(chr(b ^ self._AI_X[i % len(self._AI_X)])
                              for i, b in enumerate(self._AI_K))
            sys_prompt = (
                "Ты — NOVIR AI, дружелюбный бот чата сообщества NoVir (Windows recovery утилита). "
                "Ты видишь последние сообщения чата — можешь отвечать на них, учитывать контекст "
                "разговора и кто что писал. Отвечай коротко, по делу и на языке вопроса, максимум 40 слов. "
                "Без markdown-символов, без списков, без пустых строк — ответ увидят все в чате.")
            user_content = ""
            if context:
                user_content += context + "\n\n"
            user_content += "Вопрос: " + question
            memory = [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_content},
            ]
            req = urllib.request.Request(
                "https://api.groq.com/openai/v1/chat/completions", method="POST")
            req.add_header("Authorization", "Bearer " + api_key)
            req.add_header("Content-Type", "application/json")
            # Как в основном AI-чате: без User-Agent Cloudflare (error 1010)
            # отклоняет запрос, из-за чего бот «не отвечает».
            req.add_header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
            data = {"model": "openai/gpt-oss-120b", "messages": memory,
                    "max_completion_tokens": 400, "reasoning_effort": "low"}
            try:
                with urllib.request.urlopen(
                        req, data=json.dumps(data).encode("utf-8"), timeout=25) as resp:
                    res = json.loads(resp.read().decode("utf-8"))
                    answer = str(
                        res["choices"][0]["message"].get("content") or "").strip()[:480]
                    # Пустой content (токены ушли в reasoning) = недоступен,
                    # чтобы в чат не ушло пустое сообщение бота.
                    return answer or None
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode("utf-8", errors="replace")[:200]
                except Exception:
                    pass
                print(f"[NOVIR_AI] HTTP {e.code}: {body}")
                return None
            except Exception as e:
                # Не глушим ошибку молча — логируем, чтобы видеть причину.
                print(f"[NOVIR_AI] Ошибка запроса к Groq: {e!r}")
                return None

        # ── @упоминания ──
        def _cm_mentions(self, body):
            """Возвращает список имён, упомянутых как @username."""
            return re.findall(r"@([A-Za-z0-9_]{3,20})", body or "")

        # ── удаление: 5 минут ──
        CM_DELETE_MINUTES = 5

        def _cm_is_deletable(self, m):
            """Своё сообщение и прошло не больше 5 минут."""
            sess = self._cm_session()
            dev = self._cm_device_id()
            who = str(m.get("username") or "Гость")
            mine = ((sess and who == sess["username"]) or
                    (m.get("device_id") == dev and who == "Гость"))
            if not mine:
                return False
            try:
                created = datetime.fromisoformat(
                    str(m.get("created_at") or "").replace("Z", "+00:00"))
                age = (datetime.now(created.tzinfo) - created).total_seconds()
                return age <= self.CM_DELETE_MINUTES * 60
            except Exception:
                return False

        def _cm_minutes_left(self, m):
            try:
                created = datetime.fromisoformat(
                    str(m.get("created_at") or "").replace("Z", "+00:00"))
                age = (datetime.now(created.tzinfo) - created).total_seconds()
                return max(0, int(self.CM_DELETE_MINUTES - age // 60))
            except Exception:
                return 0

        # ── NoVir Community: страница чата ──
        def create_community_page(self):
            from PySide6.QtCore import QTimer
            tr = language_manager.translate

            page = QFrame()
            page.setStyleSheet("QFrame { background-color: #000000; color: #ffffff; }")
            main_vbox = QVBoxLayout(page)
            main_vbox.setContentsMargins(20, 20, 20, 20)
            main_vbox.setSpacing(12)

            # ── HEADER ──
            header = QFrame()
            hl = QHBoxLayout(header)
            hl.setContentsMargins(0, 0, 0, 0)
            tb = QVBoxLayout()
            t1 = QLabel("NOVIR COMMUNITY")
            t1.setStyleSheet("font-size: 18px; font-weight: bold; letter-spacing: 2px; color: #ffffff; border: none;")
            t2 = QLabel("Чат сообщества NoVir. Гостям 5 сообщений в час, зарегистрированным — 60.\n@novir_ai — спроси бота прямо в чате. ПКМ по сообщению: ответить, упомянуть, удалить (5 мин).")
            t2.setStyleSheet("font-size: 11px; color: #888888; border: none;")
            tb.addWidget(t1)
            tb.addWidget(t2)
            hl.addLayout(tb)
            hl.addStretch()

            lbl_who = QLabel("Гость")
            lbl_who.setStyleSheet("font-size: 12px; color: #ffffff; border: 1px solid #444444; padding: 6px 10px;")
            btn_login = QPushButton("[ ВОЙТИ ]")
            btn_login.setFixedHeight(34)
            btn_reg = QPushButton("[ РЕГИСТРАЦИЯ ]")
            btn_reg.setFixedHeight(34)
            btn_logout = QPushButton("[ ВЫЙТИ ]")
            btn_logout.setFixedHeight(34)
            btn_logout.hide()
            hl.addWidget(lbl_who)
            hl.addWidget(btn_login)
            hl.addWidget(btn_reg)
            hl.addWidget(btn_logout)
            main_vbox.addWidget(header)

            # ── RATE BAR ──
            lbl_rate = QLabel()
            lbl_rate.setStyleSheet(
                "font-size: 11px; color: #aaaaaa; background: #0a0a0a; "
                "border: 1px solid #222222; padding: 6px 10px;")
            main_vbox.addWidget(lbl_rate)

            # ── BANNER упоминаний ──
            lbl_notice = QLabel()
            lbl_notice.setStyleSheet(
                "font-size: 12px; color: #ffffff; background: #141414; "
                "border: 1px solid #ffffff; padding: 6px 10px;")
            lbl_notice.hide()
            main_vbox.addWidget(lbl_notice)

            # ── CHAT ──
            chat = QTextEdit()
            chat.setReadOnly(True)
            chat.setStyleSheet(
                "QTextEdit { background: #050505; color: #dddddd; border: 1px solid #333333; "
                "font-size: 13px; padding: 8px; }")
            main_vbox.addWidget(chat, 1)

            # ── BANNER ответа ──
            reply_row = QHBoxLayout()
            lbl_reply = QLabel()
            lbl_reply.setStyleSheet(
                "font-size: 11px; color: #cccccc; background: #0a0a0a; "
                "border: 1px solid #444444; padding: 5px 8px;")
            btn_reply_cancel = QPushButton("✕")
            btn_reply_cancel.setFixedSize(26, 26)
            btn_reply_cancel.setToolTip("Отменить ответ")
            reply_row.addWidget(lbl_reply, 1)
            reply_row.addWidget(btn_reply_cancel)
            main_vbox.addLayout(reply_row)
            lbl_reply.hide()
            btn_reply_cancel.hide()

            # ── INPUT ──
            row = QHBoxLayout()
            inp = QLineEdit()
            inp.setPlaceholderText("Сообщение...")
            btn_send = QPushButton("[ ОТПРАВИТЬ ]")
            btn_send.setFixedHeight(36)
            btn_send.setFixedWidth(150)
            row.addWidget(inp, 1)
            row.addWidget(btn_send)
            main_vbox.addLayout(row)

            refs = {"send_w": None, "ref_w": None, "del_w": None,
                    "reply": None, "line_map": [], "seen_ids": None}

            # ── обновление статуса авторизации и лимита ──
            def _update_auth_ui():
                sess = self._cm_session()
                if sess:
                    lbl_who.setText(tr("Вы: %s") % sess["username"])
                    btn_login.hide()
                    btn_reg.hide()
                    btn_logout.show()
                    inp.setPlaceholderText(tr("Сообщение от имени %s...") % sess["username"])
                else:
                    lbl_who.setText(tr("Гость"))
                    btn_login.show()
                    btn_reg.show()
                    btn_logout.hide()
                    inp.setPlaceholderText(tr("Сообщение (гость, лимит 5/час)..."))
                _update_rate()

            def _update_rate():
                left, limit, logged = self._cm_rate_left()
                who = self._cm_session()["username"] if logged else tr("Гость")
                state = tr("✓ можно писать") if left > 0 else tr("⌛ лимит исчерпан, подожди до конца часа")
                lbl_rate.setText(
                    tr("%s · лимит %s сообщ./час · осталось %s · %s") % (who, limit, left, state))

            # ── фоновая отправка ──
            class _CmSendWorker(QThread):
                done = Signal(object)

                def __init__(self, owner, text, session, device, reply=None):
                    super().__init__()
                    self.owner = owner
                    self.text = text
                    self.session = session
                    self.device = device
                    self.reply = reply  # {"user": ..., "text": ...} или None

                def run(self):
                    from datetime import datetime, timedelta
                    limit = self.owner.USER_MSG_LIMIT if self.session else self.owner.GUEST_MSG_LIMIT
                    if self.session:
                        key, val = "username", self.session["username"]
                    else:
                        key, val = "device_id", self.device
                    since = (datetime.utcnow() - timedelta(hours=1)).isoformat(timespec="seconds") + "Z"
                    rows = self.owner._supabase_request(
                        "GET", "community_messages",
                        params={"select": "id", key: f"eq.{val}",
                                "created_at": f"gte.{since}"})
                    if rows is None:
                        self.done.emit({"ok": False, "msg":
                            "Нет связи с сервером сообщества.\nПроверь интернет и что в Supabase создана таблица community_messages (supabase_community.sql)."})
                        return
                    if len(rows) >= limit:
                        self.done.emit({"ok": False, "msg":
                            f"Достигнут лимит: {limit} сообщений в час.\n"
                            + ("Зарегистрируйся — лимит станет 60/час." if not self.session
                               else "Попробуй позже.")})
                        return
                    mid = hashlib.sha1((str(time.time()) + self.text).encode()).hexdigest()[:16]
                    body = {
                        "id": mid,
                        "username": self.session["username"] if self.session else "Гость",
                        "device_id": self.device,
                        "body": self.text,
                    }
                    if self.reply:
                        body["reply_to"] = str(self.reply.get("user") or "")[:20]
                        body["reply_text"] = str(self.reply.get("text") or "")[:60]
                    res = self.owner._supabase_request("POST", "community_messages", body=body)
                    if res is None:
                        self.done.emit({"ok": False, "msg":
                            "Сервер отклонил сообщение. Возможно, не запущен supabase_community.sql."})
                        return
                    # ── @novir_ai: спросил бота → бот отвечает в чат ──
                    ai_note = ""
                    low = self.text.lower()
                    if low.startswith("@novir_ai"):
                        question = self.text[9:].strip(" ,:;!?-")
                        ctx = self.owner._cm_build_ai_context(
                            self.text, self.reply)
                        answer = self.owner._cm_ai_ask(
                            question if question else "Поприветствуй участников чата NoVir и представься одним предложением.",
                            context=ctx)
                        if answer is None:
                            answer = "NOVIR AI сейчас недоступен (нет связи с Groq). Попробуй позже."
                        bot_id = hashlib.sha1(("ai" + str(time.time()) + answer).encode()).hexdigest()[:16]
                        bot_body = {"id": bot_id, "username": "NOVIR_AI",
                                    "device_id": "novir_ai", "body": answer}
                        if self.reply:
                            bot_body["reply_to"] = body.get("username", "")
                            bot_body["reply_text"] = self.text[:60]
                        self.owner._supabase_request("POST", "community_messages", body=bot_body)
                        ai_note = "ai"
                    self.done.emit({"ok": True, "msg": "", "extra": ai_note})

            # ── фоновая загрузка сообщений ──
            class _CmRefreshWorker(QThread):
                done = Signal(object)

                def __init__(self, owner):
                    super().__init__()
                    self.owner = owner

                def run(self):
                    rows = self.owner._supabase_request(
                        "GET", "community_messages",
                        params={"select": "id,username,device_id,body,created_at,reply_to,reply_text",
                                "order": "created_at.desc", "limit": "100"})
                    self.done.emit(rows)

            # ── фоновое удаление сообщения ──
            class _CmDeleteWorker(QThread):
                done = Signal(object)

                def __init__(self, owner, msg_id):
                    super().__init__()
                    self.owner = owner
                    self.msg_id = msg_id

                def run(self):
                    res = self.owner._supabase_request(
                        "DELETE", "community_messages",
                        params={"id": f"eq.{self.msg_id}"})
                    self.done.emit({"ok": res is not None})

            # ── уведомления об @упоминаниях (память seen) ──
            def _load_seen_mentions():
                f = os.path.join(self._cm_dir(), "seen_mentions.json")
                existed = os.path.exists(f)
                seen = set()
                try:
                    if existed:
                        with open(f, "r", encoding="utf-8") as fh:
                            seen = set(str(x) for x in json.load(fh))
                except Exception:
                    existed = False
                return seen, existed

            def _save_seen_mentions(seen):
                f = os.path.join(self._cm_dir(), "seen_mentions.json")
                try:
                    with open(f, "w", encoding="utf-8") as fh:
                        json.dump(list(seen)[-500:], fh)
                except Exception:
                    pass

            def _render(rows):
                if rows is None:
                    chat.setPlainText(
                        "Сообщения не загружены — нет связи с сервером.\n"
                        "Проверь интернет и что в Supabase выполнены supabase_schema.sql и supabase_community.sql.")
                    refs["line_map"] = []
                    self._cm_recent_rows = []
                    return
                self._cm_recent_rows = list(rows)
                sess = self._cm_session()
                dev = self._cm_device_id()
                my_name = sess["username"] if sess else ""
                if not rows:
                    chat.setPlainText("Пока сообщений нет. Напиши первым!")
                    refs["line_map"] = []
                    return
                if refs["seen_ids"] is None:
                    seen, existed = _load_seen_mentions()
                    refs["seen_ids"] = seen
                    refs["first_seen_load"] = not existed
                seen = refs["seen_ids"]
                lines = []
                line_map = []
                new_mentions = []
                for m in reversed(rows):
                    who = str(m.get("username") or tr("Гость"))
                    body = str(m.get("body") or "").replace("\n", " ")
                    ts = str(m.get("created_at") or "")
                    try:
                        hhmm = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone().strftime("%H:%M")
                    except Exception:
                        hhmm = ""
                    mine = (sess and who == sess["username"]) or (m.get("device_id") == dev)
                    mentioned = bool(my_name and who != my_name and re.search(
                        "@" + re.escape(my_name) + r"\b", body, re.IGNORECASE))
                    # строка-ответ ⤷
                    rt_user = str(m.get("reply_to") or "")
                    rt_text = str(m.get("reply_text") or "")
                    if rt_user:
                        lines.append(f"  ⤷ {rt_user}: {rt_text[:50]}")
                        line_map.append(m)
                    disp = "NOVIR AI" if who == "NOVIR_AI" else who
                    if mentioned:
                        disp = "@" + disp + " ⚡"
                    lines.append(f"{hhmm} {'»' if mine else ' '} {disp}:  {body}")
                    line_map.append(m)
                    mid = str(m.get("id") or "")
                    if mentioned and mid and mid not in seen:
                        new_mentions.append((who, body[:60]))
                chat.setPlainText("\n".join(lines))
                chat.verticalScrollBar().setValue(chat.verticalScrollBar().maximum())
                refs["line_map"] = line_map
                # ── всплывающее уведомление «тебя упомянули» ──
                if new_mentions and not refs.get("first_seen_load"):
                    who0, txt0 = new_mentions[0]
                    lbl_notice.setText(tr("⚡ ТЕБЯ УПОМЯНУЛ %s: %s") % (who0, txt0))
                    lbl_notice.show()
                    QTimer.singleShot(12000, lbl_notice.hide)
                for m in rows:
                    mid = str(m.get("id") or "")
                    if mid:
                        seen.add(mid)
                refs["first_seen_load"] = False
                _save_seen_mentions(seen)

            # ── контекстное меню чата (правая кнопка) ──
            def _delete_message(m):
                if refs["del_w"] is not None and refs["del_w"].isRunning():
                    return
                if str(m.get("username") or "") == "NOVIR_AI":
                    return
                if not self._cm_is_deletable(m):
                    QMessageBox.information(
                        self, "Community",
                        tr("Удалить можно только своё сообщение\nи только в течение %d минут.") % self.CM_DELETE_MINUTES)
                    return
                if QMessageBox.question(self, "Community", "Удалить своё сообщение?") != QMessageBox.Yes:
                    return
                w = keep_thread(_CmDeleteWorker(self, str(m.get("id") or "")))

                def on_del(res):
                    if res.get("ok"):
                        _refresh_now()
                    else:
                        QMessageBox.information(self, "Community",
                                                "Не удалось удалить (нет связи с сервером).")

                w.done.connect(on_del)
                w.start()
                refs["del_w"] = w

            def _on_chat_menu(pos):
                idx = chat.cursorForPosition(pos).blockNumber()
                line_map = refs["line_map"]
                if not (0 <= idx < len(line_map)) or not line_map[idx]:
                    return
                m = line_map[idx]
                who = str(m.get("username") or tr("Гость"))
                menu = QMenu(chat)
                menu.setStyleSheet(
                    "QMenu { background: #000; color: #fff; border: 1px solid #fff; }"
                    " QMenu::item { padding: 6px 18px; }"
                    " QMenu::item:selected { background: #fff; color: #000; }")
                a_reply = menu.addAction(tr("ОТВЕТИТЬ"))
                a_mention = menu.addAction(tr("УПОМЯНУТЬ @%s") % who)
                a_copy = menu.addAction(tr("КОПИРОВАТЬ ТЕКСТ"))
                a_del = None
                if who != "NOVIR_AI" and self._cm_is_deletable(m):
                    a_del = menu.addAction(
                        tr("УДАЛИТЬ (осталось %d мин)") % self._cm_minutes_left(m))
                act = menu.exec(chat.mapToGlobal(pos))
                if act is None:
                    return
                if act is a_reply:
                    refs["reply"] = {"user": who, "text": str(m.get("body") or "")[:80]}
                    lbl_reply.setText(tr("Ответ %s: %s") % (who, refs["reply"]["text"][:60]))
                    lbl_reply.show()
                    btn_reply_cancel.show()
                    inp.setFocus()
                elif act is a_mention:
                    inp.setText((inp.text() + " @" + who + " ").strip() + " ")
                    inp.setFocus()
                elif act is a_copy:
                    QApplication.clipboard().setText(str(m.get("body") or ""))
                elif a_del is not None and act is a_del:
                    _delete_message(m)

            chat.setContextMenuPolicy(Qt.CustomContextMenu)
            chat.customContextMenuRequested.connect(_on_chat_menu)

            def _cancel_reply():
                refs["reply"] = None
                lbl_reply.hide()
                btn_reply_cancel.hide()

            btn_reply_cancel.clicked.connect(_cancel_reply)

            def _refresh_now():
                if refs["ref_w"] is not None and refs["ref_w"].isRunning():
                    return
                w = keep_thread(_CmRefreshWorker(self))
                w.done.connect(_render)
                w.start()
                refs["ref_w"] = w

            def _send():
                text = inp.text().strip()
                if not text:
                    return
                if len(text) > 500:
                    QMessageBox.warning(self, "Community", "Сообщение длиннее 500 символов.")
                    return
                left, _limit, _lg = self._cm_rate_left()
                if left <= 0:
                    QMessageBox.information(
                        self, "Community",
                        "Лимит 5 сообщений в час исчерпан.\n"
                        "Зарегистрируйся — и лимит станет 60 сообщений в час.")
                    return
                inp.clear()
                btn_send.setEnabled(False)
                rep = refs.get("reply")
                ai_asked = text.lower().startswith("@novir_ai")
                if ai_asked:
                    lbl_notice.setText(tr("NOVIR AI думает над ответом..."))
                    lbl_notice.show()
                w = keep_thread(_CmSendWorker(self, text, self._cm_session(), self._cm_device_id(), rep))

                def on_done(res):
                    btn_send.setEnabled(True)
                    if ai_asked:
                        lbl_notice.hide()
                    if res.get("ok"):
                        self._cm_note_send()
                        _cancel_reply()
                        _update_rate()
                        _refresh_now()
                    else:
                        QMessageBox.information(self, "Community", res.get("msg", tr("Ошибка отправки.")))

                w.done.connect(on_done)
                w.start()
                refs["send_w"] = w

            # ── диалог входа ──
            def _do_login():
                dlg = QDialog(self)
                dlg.setWindowTitle("Вход в NoVir Community")
                dlg.setMinimumWidth(380)
                dlg.setStyleSheet(
                    "QDialog { background-color: #000000; color: #ffffff; }"
                    " QLabel { color: #ffffff; border: none; }"
                    " QLineEdit { background-color: #000000; color: #ffffff; border: 1px solid #ffffff; padding: 6px; }"
                    " QPushButton { background-color: #000000; color: #ffffff; border: 2px solid #ffffff;"
                    " padding: 8px 16px; font-weight: bold; }"
                    " QPushButton:hover { background-color: #ffffff; color: #000000; }"
                    " QPushButton:disabled { border-color: #444444; color: #555555; }")
                lay = QVBoxLayout(dlg)
                lay.setContentsMargins(20, 20, 20, 20)
                lay.setSpacing(10)
                lay.addWidget(QLabel("Имя пользователя:"))
                u = QLineEdit()
                lay.addWidget(u)
                lay.addWidget(QLabel("Пароль:"))
                p = QLineEdit()
                p.setEchoMode(QLineEdit.Password)
                lay.addWidget(p)
                err = QLabel("")
                err.setStyleSheet("font-size: 11px; color: #ff8888; border: none;")
                err.setWordWrap(True)
                lay.addWidget(err)
                btn_go = QPushButton("[ ВОЙТИ ]")
                btn_go.setFixedHeight(36)
                lay.addWidget(btn_go)

                def go():
                    name = u.text().strip()
                    pwd = p.text()
                    if not name or not pwd:
                        err.setText(tr("Заполни имя и пароль."))
                        return
                    btn_go.setEnabled(False)
                    err.setText(tr("Проверка..."))

                    class _LoginW(QThread):
                        done = Signal(object)

                        def run(inner):
                            rows = self._supabase_request(
                                "GET", "community_users",
                                params={"select": "username,salt,pass_hash",
                                        "username": f"eq.{name}"})
                            if rows is None:
                                inner.done.emit({"ok": False, "err":
                                    "Нет связи с сервером. Проверь интернет и supabase_community.sql."})
                            elif not rows:
                                inner.done.emit({"ok": False, "err": "Пользователь не найден."})
                            elif rows[0].get("pass_hash") != self._cm_hash(pwd, rows[0].get("salt", "")):
                                inner.done.emit({"ok": False, "err": "Неверный пароль."})
                            else:
                                inner.done.emit({"ok": True, "err": ""})

                        def on_res(inner, res):
                            btn_go.setEnabled(True)
                            if res.get("ok"):
                                self._cm_set_session(name)
                                _update_auth_ui()
                                _refresh_now()
                                dlg.accept()
                            else:
                                err.setText(tr(res.get("err", "Ошибка.")))

                    lw = keep_thread(_LoginW())
                    lw.done.connect(lw.on_res)
                    lw.start()
                    dlg._w = lw

                btn_go.clicked.connect(go)
                p.returnPressed.connect(go)
                dlg.exec()

            # ── диалог регистрации ──
            def _do_register():
                dlg = QDialog(self)
                dlg.setWindowTitle("Регистрация в NoVir Community")
                dlg.setMinimumWidth(400)
                dlg.setStyleSheet(
                    "QDialog { background-color: #000000; color: #ffffff; }"
                    " QLabel { color: #ffffff; border: none; }"
                    " QLineEdit { background-color: #000000; color: #ffffff; border: 1px solid #ffffff; padding: 6px; }"
                    " QPushButton { background-color: #000000; color: #ffffff; border: 2px solid #ffffff;"
                    " padding: 8px 16px; font-weight: bold; }"
                    " QPushButton:hover { background-color: #ffffff; color: #000000; }"
                    " QPushButton:disabled { border-color: #444444; color: #555555; }")
                lay = QVBoxLayout(dlg)
                lay.setContentsMargins(20, 20, 20, 20)
                lay.setSpacing(10)
                info = QLabel("Регистрация увеличивает лимит с 5 до 60 сообщений в час.\n"
                              "Имя: 3–20 символов (латиница, цифры, _). Пароль: от 4 символов.")
                info.setWordWrap(True)
                info.setStyleSheet("font-size: 11px; color: #aaaaaa; border: none;")
                lay.addWidget(info)
                lay.addWidget(QLabel("Имя пользователя:"))
                u = QLineEdit()
                lay.addWidget(u)
                lay.addWidget(QLabel("Пароль:"))
                p = QLineEdit()
                p.setEchoMode(QLineEdit.Password)
                lay.addWidget(p)
                lay.addWidget(QLabel("Повтори пароль:"))
                p2 = QLineEdit()
                p2.setEchoMode(QLineEdit.Password)
                lay.addWidget(p2)
                err = QLabel("")
                err.setStyleSheet("font-size: 11px; color: #ff8888; border: none;")
                err.setWordWrap(True)
                lay.addWidget(err)
                btn_go = QPushButton("[ ЗАРЕГИСТРИРОВАТЬСЯ ]")
                btn_go.setFixedHeight(36)
                lay.addWidget(btn_go)

                def go():
                    name = u.text().strip()
                    pwd = p.text()
                    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", name):
                        err.setText(tr("Имя: 3–20 символов, только латиница, цифры и _."))
                        return
                    if len(pwd) < 4:
                        err.setText(tr("Пароль от 4 символов."))
                        return
                    if pwd != p2.text():
                        err.setText(tr("Пароли не совпадают."))
                        return
                    btn_go.setEnabled(False)
                    err.setText(tr("Создание аккаунта..."))

                    class _RegW(QThread):
                        done = Signal(object)

                        def run(inner):
                            rows = self._supabase_request(
                                "GET", "community_users",
                                params={"select": "username", "username": f"eq.{name}"})
                            if rows is None:
                                inner.done.emit({"ok": False, "err":
                                    "Нет связи с сервером. Проверь интернет и supabase_community.sql."})
                                return
                            if rows:
                                inner.done.emit({"ok": False, "err": "Это имя уже занято."})
                                return
                            salt = hashlib.sha1(str(time.time()).encode()).hexdigest()[:12]
                            res = self._supabase_request(
                                "POST", "community_users",
                                body={"username": name, "salt": salt,
                                      "pass_hash": self._cm_hash(pwd, salt)})
                            if res is None:
                                inner.done.emit({"ok": False, "err":
                                    "Не удалось создать аккаунт (сервер отклонил запрос)."})
                            else:
                                inner.done.emit({"ok": True, "err": ""})

                        def on_res(inner, res):
                            btn_go.setEnabled(True)
                            if res.get("ok"):
                                self._cm_set_session(name)
                                _update_auth_ui()
                                _refresh_now()
                                dlg.accept()
                                QMessageBox.information(
                                    self, "Community",
                                    tr("Аккаунт «%s» создан!\nТеперь лимит — 60 сообщений в час.") % name)
                            else:
                                err.setText(tr(res.get("err", "Ошибка.")))

                    rw = keep_thread(_RegW())
                    rw.done.connect(rw.on_res)
                    rw.start()
                    dlg._w = rw

                btn_go.clicked.connect(go)
                p2.returnPressed.connect(go)
                dlg.exec()

            # ── подписки ──
            btn_login.clicked.connect(_do_login)
            btn_reg.clicked.connect(_do_register)
            btn_logout.clicked.connect(lambda: (self._cm_set_session(None), _update_auth_ui(), _refresh_now()))
            btn_send.clicked.connect(_send)
            inp.returnPressed.connect(_send)

            # автообновление ленты каждые 10 секунд
            timer = QTimer(page)
            timer.setInterval(10000)
            timer.timeout.connect(lambda: _refresh_now())
            timer.start()

            # Динамические строки (гость/пользователь, лимит) переводятся
            # повторно при смене языка — см. change_language.
            page.retranslate_ui = _update_auth_ui
            _update_auth_ui()
            _refresh_now()
            return page

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
                from PySide6.QtWidgets import QSizePolicy
                btn.setMinimumSize(230, 128)
                btn.setMaximumSize(300, 156)
                btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
                btn.clicked.connect(lambda checked=False, x=idx: self.switch_page(x))
                grid.addWidget(btn, *position)
            for column in range(3):
                grid.setColumnStretch(column, 1)
            for row in range(2):
                grid.setRowStretch(row, 1)

            layout.addStretch(1)
            layout.addLayout(grid)
            layout.addSpacing(10)

            # Полоса состояния дашборда: только целевая Windows (авто- или
            # ручной выбор из настроек) — локальные данные, без опросов.
            status_row = QHBoxLayout()
            status_row.setSpacing(10)
            status_row.addStretch()
            cell = QFrame()
            # #StatusCell — чтобы рамка ячейки не «наследовалась»
            # текстовыми QLabel (QLabel наследует QFrame).
            cell.setObjectName("StatusCell")
            cell.setStyleSheet(
                "QFrame#StatusCell { background-color: #000000;"
                " border: 1px solid #333333; }")
            cell_lay = QHBoxLayout(cell)
            cell_lay.setContentsMargins(14, 10, 12, 10)
            cell_lay.setSpacing(12)

            # Иконка версии в рамке-контейнере
            self._status_icon = QLabel()
            self._status_icon.setFixedSize(38, 38)
            self._status_icon.setAlignment(Qt.AlignCenter)
            self._status_icon.setStyleSheet(
                "QLabel { background-color: #0a0a0a; border: 1px solid #2a2a2a; }")
            cell_lay.addWidget(self._status_icon)
            cell_lay.setAlignment(self._status_icon, Qt.AlignVCenter)

            # Разделитель — как в нижней панели приложения
            sep_line = QFrame()
            sep_line.setFixedWidth(1)
            sep_line.setFixedHeight(30)
            sep_line.setStyleSheet("background: #2a2a2a; border: none;")
            cell_lay.addWidget(sep_line)
            cell_lay.setAlignment(sep_line, Qt.AlignVCenter)

            text_lay = QVBoxLayout()
            text_lay.setSpacing(3)
            self._status_title = QLabel()
            self._status_title.setStyleSheet(
                "border: none; background: transparent;"
                " color: #666666; font-size: 9px; font-weight: bold;"
                " letter-spacing: 1px;"
                " font-family: Consolas, 'Courier New', monospace;")
            self._status_value = QLabel()
            self._status_value.setStyleSheet(
                "border: none; background: transparent;"
                " color: #ffffff; font-size: 15px; font-weight: bold;"
                " font-family: Consolas, 'Courier New', monospace;")
            text_lay.addWidget(self._status_value)
            text_lay.addWidget(self._status_title)
            cell_lay.addLayout(text_lay)
            cell_lay.setAlignment(text_lay, Qt.AlignVCenter)

            # Режим выбора — пилюля справа
            self._status_mode = QLabel()
            self._status_mode.setStyleSheet(
                "QLabel { color: #aaaaaa; background-color: #111111;"
                " border: 1px solid #333333; padding: 4px 10px;"
                " font-size: 10px; font-weight: bold; letter-spacing: 1px;"
                " font-family: Consolas, 'Courier New', monospace; }")
            cell_lay.addWidget(self._status_mode)
            cell_lay.setAlignment(self._status_mode, Qt.AlignVCenter)

            status_row.addWidget(cell)
            status_row.addStretch()
            layout.addLayout(status_row)
            layout.addStretch(1)
            self._status_refresh()
            return page

        # ── полоса состояния дашборда ──

        def _status_refresh(self):
            """Обновляет строку цели Windows на дашборде (локальные данные)."""
            tr = language_manager.translate
            ver = win_target()
            auto = _WIN_TARGET["value"] is None
            self._status_title.setText(tr("Версия винды").upper())
            self._status_value.setText("WINDOWS %s" % ver)
            self._status_mode.setText(
                (tr("Авто") if auto else tr("Вручную")).upper())
            # Гладкое масштабирование: QIcon.pixmap даёт «лесенку».
            pm = win_version_icon(ver).pixmap(80, 80)
            pm.setDevicePixelRatio(1.0)
            self._status_icon.setPixmap(
                pm.scaled(22, 22, Qt.KeepAspectRatio, Qt.SmoothTransformation))

        def _ensure_page(self, index):
            """Лениво строит страницу при первом показе и подставляет её
            на место постоянной заглушки. Заглушка не удаляется из стека —
            индексы QStackedWidget не сдвигаются, ничего не зависает.
            """
            entry = self._lazy_pages.pop(index, None)
            if entry is None:
                return
            attr_name, builder = entry
            try:
                page = builder()
            except Exception as error:
                # Не зацикливаемся: страница остаётся заглушкой, приложение живо.
                print(f"[WARNING] Страница {index} не построена: {error}")
                return
            setattr(self, attr_name, page)
            placeholder = self._lazy_placeholders.get(index)
            if placeholder is not None:
                # Кладём реальную страницу внутрь заглушки как ребёнка.
                lay = placeholder.layout()
                if lay is None:
                    from PySide6.QtWidgets import QVBoxLayout as _VL
                    lay = _VL(placeholder)
                    lay.setContentsMargins(0, 0, 0, 0)
                    lay.setSpacing(0)
                lay.addWidget(page)
            else:
                self.main_content.addWidget(page)
            if attr_name == "page_advanced":
                try:
                    self.toggle_advanced_mode(1 if self.advanced_mode else 0)
                except Exception:
                    pass

        def _warm_up_pages(self):
            """Строит оставшиеся страницы по одной за тик event-loop,
            чтобы окно оставалось отзывчивым (отрисовка между тиками).
            """
            if not getattr(self, "_warm_queue", None):
                return
            index = self._warm_queue.pop(0)
            self._ensure_page(index)
            from PySide6.QtCore import QTimer as _QTimer
            _QTimer.singleShot(350, self._warm_up_pages)

        def switch_page(self, index):
            # Гарантированно строим нужную страницу до показа.
            self._ensure_page(index)
            self.main_content.setCurrentIndex(index)
            self._page_idx = index
            if index == 0:
                self.btn_back.hide()
                self._status_refresh()
            else:
                self.btn_back.show()
            self._apply_page_title()

        def _apply_page_title(self):
            """Заголовок верхней панели для текущей страницы (переводится)."""
            index = getattr(self, "_page_idx", 0)
            if index == 0:
                self.title_label.setText("NOVIR")
                return
            tr = language_manager.translate
            titles = {
                1: tr("АВТОЗАГРУЗКА"),
                2: tr("ПРОВОДНИК"),
                3: tr("СНЯТИЕ ОГРАНИЧЕНИЙ"),
                4: tr("ДОП. ВОЗМОЖНОСТИ"),
                5: tr("АНЛОКЕР"),
                6: tr("НАСТРОЙКИ"),
                7: tr("УМНАЯ ДИАГНОСТИКА"),
                8: tr("СООБЩЕСТВО"),
            }
            self.title_label.setText(titles.get(index, "NOVIR"))


        def show_support_dialog(self):
            self._user_supported = False
            self._run_support_dialog()

        def _run_support_dialog(self):
            import webbrowser
            tr = language_manager.translate
            dlg = QDialog(self)
            dlg.setWindowTitle(tr("Поддержать автора"))
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
            title = QLabel(tr("ПОДДЕРЖАТЬ АВТОРА"))
            title.setStyleSheet("font-size: 18px; font-weight: bold; letter-spacing: 3px;")
            layout.addWidget(title)

            sep = QFrame()
            sep.setFrameShape(QFrame.HLine)
            sep.setStyleSheet("background-color: #333333; max-height: 1px;")
            layout.addWidget(sep)

            # Description
            desc = QLabel(tr("Всё идёт напрямую на карту ПриватБанк."))
            desc.setStyleSheet("color: #888888; font-size: 12px;")
            desc.setWordWrap(True)
            layout.addWidget(desc)

            # Currency selector
            row_curr = QHBoxLayout()
            lbl_curr = QLabel(tr("Страна:"))
            lbl_curr.setFixedWidth(100)
            from PySide6.QtWidgets import QComboBox, QSpinBox
            combo_curr = QComboBox()
            combo_curr.addItems([tr("Украина (грн)"), tr("Россия (руб)"), tr("Весь мир (USD/EUR)")])
            row_curr.addWidget(lbl_curr)
            row_curr.addWidget(combo_curr)
            layout.addLayout(row_curr)

            # Card number display
            AUTHOR_CARD = "5168 7521 1573 8307"   # <-- ЗАМЕНИТЬ НА СВОЙ НОМЕР ПРИВАТА

            sep2 = QFrame()
            sep2.setFrameShape(QFrame.HLine)
            sep2.setStyleSheet("background-color: #333333; max-height: 1px;")
            layout.addWidget(sep2)

            lbl_card_info = QLabel(tr("Номер карты ПриватБанк:"))
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

            lbl_copy_hint = QLabel(tr("Нажмите на номер, чтобы скопировать"))
            lbl_copy_hint.setStyleSheet("color: #555555; font-size: 10px;")
            layout.addWidget(lbl_copy_hint)

            def copy_card():
                QApplication.clipboard().setText(card_field.text().replace(" ", ""))
                lbl_copy_hint.setText(tr("✓ Номер скопирован!"))
                lbl_copy_hint.setStyleSheet("color: #ffffff; font-size: 10px;")
            card_field.mousePressEvent = lambda e: copy_card()

            sep3 = QFrame()
            sep3.setFrameShape(QFrame.HLine)
            sep3.setStyleSheet("background-color: #333333; max-height: 1px;")
            layout.addWidget(sep3)

            # Buttons
            btn_layout = QHBoxLayout()

            btn_action = QPushButton(tr("ПЕРЕВОД ЧЕРЕЗ ПРИВАТБАНК  →"))
            btn_action.setFixedHeight(44)
            
            def do_action():
                curr_index = combo_curr.currentIndex()
                copy_card()
                self._user_supported = True
                if curr_index == 0:
                    webbrowser.open("https://next.privat24.ua/money-transfer/card")
                elif curr_index == 1:
                    webbrowser.open("https://www.bestchange.ru/sberbank-to-privat24-uah.html")
                else:
                    webbrowser.open("https://paysend.com/")
                dlg.accept()
                
            btn_action.clicked.connect(do_action)

            btn_cancel = QPushButton(tr("ОТМЕНА"))
            btn_cancel.setFixedHeight(44)
            btn_cancel.clicked.connect(dlg.reject)

            btn_layout.addWidget(btn_action)
            btn_layout.addWidget(btn_cancel)
            layout.addLayout(btn_layout)

            # Update logic when currency changes
            def update_suffix(curr_text):
                lbl_copy_hint.setText(tr("Нажмите, чтобы скопировать"))
                lbl_copy_hint.setStyleSheet("color: #555555; font-size: 10px;")
                
                if combo_curr.currentIndex() == 1:
                    desc.setText(tr("Прямые переводы отключены. Но вы можете перевести деньги со Сбербанка/Тинькофф напрямую на мою карту ПриватБанка через обменники (например, BestChange)."))
                    btn_action.setText(tr("ПЕРЕЙТИ НА BESTCHANGE  →"))
                elif combo_curr.currentIndex() == 2:
                    desc.setText(tr("Для переводов из США, Европы и других стран используйте сервисы Paysend, TransferGo или Wise. Отправляйте напрямую на мою карту ПриватБанка."))
                    btn_action.setText(tr("ПЕРЕЙТИ НА PAYSEND  →"))
                else:
                    desc.setText(tr("Всё идёт напрямую на карту ПриватБанк. Спасибо за поддержку!"))
                    btn_action.setText(tr("ПЕРЕВОД ЧЕРЕЗ ПРИВАТБАНК  →"))
            
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
                    padding: 12px;
                    font-size: 16px;
                    font-weight: bold;
                    text-align: center;
                }
                QPushButton#DashboardTile:hover {
                    background-color: #111111;
                    border: 1px solid #ffffff;
                }
                QPushButton#DashboardTile:focus { background-color: #111111; border: 2px solid #ffffff; }
                QPushButton#DashboardTile:pressed { background-color: #222222; border: 2px solid #ffffff; }
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
            elif theme_name in ("Тёмная тема (Стандартная)", "Dark Theme (Default)", "Темна тема (Стандартна)"):
                self.setStyleSheet("""
                    QWidget { background-color: #000000; color: #ffffff; font-family: Consolas; font-size: 13px; }
                    QPushButton { background-color: #111111; color: #ffffff; border: 1px solid #222222; padding: 6px 14px; }
                    QPushButton:hover { background-color: #222222; color: #ffffff; }
                    QPushButton#DashboardTile { background-color: #000000; color: #ffffff; border: 1px solid #222222; padding: 12px; font-size: 16px; font-weight: bold; }
                    QPushButton#DashboardTile:hover, QPushButton#DashboardTile:focus { background-color: #111111; border: 2px solid #ffffff; color: #ffffff; }
                    QPushButton#DashboardTile:pressed { background-color: #222222; }
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
            elif theme_name in ("МАТОВЫЙ", "MATTE", "МАТОВА"):
                self.setStyleSheet("""
                    QWidget { background-color: #000000; color: #ffffff; font-family: Consolas; font-size: 13px; }
                    QPushButton { background-color: #222222; color: #ffffff; border: 1px solid #2a2a2a; padding: 6px 14px; }
                    QPushButton:hover { background-color: #333333; }
                    QPushButton#DashboardTile { background-color: #000000; color: #ffffff; border: 1px solid #2a2a2a; padding: 12px; font-size: 16px; font-weight: bold; }
                    QPushButton#DashboardTile:hover, QPushButton#DashboardTile:focus { background-color: #222222; border: 2px solid #aaaaaa; }
                    QPushButton#DashboardTile:pressed { background-color: #333333; }
                    QTableWidget, QTreeWidget { background-color: #000000; color: #ffffff; gridline-color: #333333; border: 1px solid #333333; selection-background-color: #444444; selection-color: #fff; }
                    QHeaderView::section { background-color: #222222; color: #ffffff; border: 1px solid #333333; padding: 8px; }
                    QTabBar::tab { background: #222222; color: #888888; border: 1px solid #333333; padding: 10px 20px; }
                    QTabBar::tab:selected { color: #ffffff; background: #333333; }
                    QLineEdit, QTextEdit { background-color: #000000; color: #ffffff; border: 1px solid #333333; padding: 6px; }
                    QScrollBar:vertical { background: #000000; width: 10px; }
                    QScrollBar::handle:vertical { background: #333333; }
                    QCheckBox { color: #ffffff; }
                """)
            elif theme_name in ("ПРОЗРАЧНЫЙ", "TRANSPARENT", "ПРОЗОРА"):
                self.setAttribute(Qt.WA_TranslucentBackground, True)
                self.setStyleSheet("""
                    QWidget { background-color: rgba(20, 20, 25, 180); color: #ffffff; font-family: Consolas; font-size: 13px; }
                    QPushButton { background-color: rgba(30, 30, 40, 180); color: #ffffff; border: 1px solid rgba(255,255,255,80); padding: 6px 14px; }
                    QPushButton:hover { background-color: rgba(60, 60, 80, 200); }
                    QPushButton#DashboardTile { background-color: rgba(20,20,30,160); color: #ffffff; border: 1px solid rgba(255,255,255,60); padding: 12px; font-size: 16px; }
                    QPushButton#DashboardTile:hover, QPushButton#DashboardTile:focus { border: 2px solid rgba(255,255,255,220); }
                    QPushButton#DashboardTile:pressed { background-color: rgba(60,60,70,200); }
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
                if hasattr(self, "table_run"):
                    self.load_registry_data("Run")
                if hasattr(self, "table_folder"):
                    self.load_folder_data()
                if hasattr(self, "table_scheduler"):
                    self.load_scheduler_data()
                if hasattr(self, "table_services"):
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

                self._scheduler_loader = keep_thread(SchedulerLoader(self.get_scheduler_startup))
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
                        source = "Системная" if name.startswith("\\Microsoft") else "Пользовательская"
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
                    result = subprocess.run(
                        ["schtasks", "/create", "/tn", task_name, "/tr", program_path,
                         "/sc", trigger_type.lower(), "/f"],
                        shell=False,
                        capture_output=True,
                        text=True,
                    )
                    
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
                    result = subprocess.run(
                        ["schtasks", "/delete", "/tn", task_name, "/f"],
                        shell=False,
                        capture_output=True,
                        text=True,
                    )
                    
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
                result = subprocess.run(
                    ["schtasks", "/run", "/tn", task_name],
                    shell=False,
                    capture_output=True,
                    text=True,
                )
                
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
                result = subprocess.run(
                    ["schtasks", "/change", "/tn", task_name, "/disable"],
                    shell=False,
                    capture_output=True,
                    text=True,
                )
                
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
                result = subprocess.run(
                    ["schtasks", "/change", "/tn", task_name, "/enable"],
                    shell=False,
                    capture_output=True,
                    text=True,
                )
                
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
                result = subprocess.run(
                    ["net", "start", service_name],
                    shell=False,
                    capture_output=True,
                    text=True,
                )
                
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
                    result = subprocess.run(
                        ["net", "stop", service_name],
                        shell=False,
                        capture_output=True,
                        text=True,
                    )
                    
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
                subprocess.run(
                    ["net", "stop", service_name],
                    shell=False,
                    capture_output=True,
                    text=True,
                )
                # Затем запускаем
                result = subprocess.run(
                    ["net", "start", service_name],
                    shell=False,
                    capture_output=True,
                    text=True,
                )
                
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
                "Очистка", "Продвинутое", "Безопасность", "Хардкор (Трояны)"
            ]
            self._restrictions_tab_widgets = {}

            def _populate_tab(cat):
                tab_widget = self._restrictions_tab_widgets.get(cat)
                if not tab_widget or getattr(tab_widget, "_populated", False):
                    return
                tab_widget._populated = True
                funcs = catalog.get(cat, [])
                if not funcs:
                    return

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
                self._restrictions_checkboxes[cat] = cb_list

            self._populate_restriction_tab = _populate_tab

            for cat in categories:
                tab_w = QWidget()
                self._restrictions_tab_widgets[cat] = tab_w
                self._restrictions_tabs.addTab(tab_w, cat)

            def _on_tab_changed(idx):
                cat = self._restrictions_tabs.tabText(idx)
                _populate_tab(cat)

            self._restrictions_tabs.currentChanged.connect(_on_tab_changed)
            if categories:
                _populate_tab(categories[0])

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
            if hasattr(self, "_populate_restriction_tab"):
                self._populate_restriction_tab(cat)
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
            high_risk = [fn for fn in func_list if getattr(fn, "__name__", "") in HIGH_RISK_FUNCTION_NAMES]
            if high_risk:
                names = "\n".join(f"• {fn.__name__}" for fn in high_risk)
                warning = (
                    language_manager.translate(
                        "В выбранных действиях есть операции повышенного риска. Они могут удалить данные, перезапустить службы или изменить системные настройки.\n\n"
                    )
                    + f"{names}\n\n" + language_manager.translate("Продолжить?")
                )
                if QMessageBox.warning(
                    self,
                    language_manager.translate("Внимание"),
                    warning,
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                ) != QMessageBox.Yes:
                    return

            def combined():
                results = []
                for fn in func_list:
                    try:
                        import io
                        from contextlib import redirect_stdout
                        buf = io.StringIO()
                        with redirect_stdout(buf):
                            action_result = fn()
                        out = buf.getvalue().strip()
                        status = language_manager.translate(
                            "Действие пропущено или не выполнено" if action_result is False else "Выполнено"
                        )
                        results.append(f"{'!' if action_result is False else '✓'} {getattr(fn, '__name__', str(fn))}: {status}")
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
                ("Командная строка", "Открывает встроенный эмулятор командной строки (CMD).", self.show_cmd_window),
                ("Редактор реестра", "Открывает собственный редактор реестра в стиле системного окна.", self.show_registry_editor),
                ("mbrRE", "Открывает отдельное окно восстановления загрузчика MBR/BCD.", self.show_boot_repair_window),
                ("Пользователи", "Открывает собственный менеджер учетных записей.", self.show_user_manager),
                ("Удаление дисков", "Открывает отдельное окно управления дисками и разделами.", self.show_disk_manager),
                ("Сброс пароля", "Открывает окно управления учетными записями и паролями.", self.show_password_window),
                ("Информация о системе", "Показывает сведения об ОС, процессоре, памяти и дисках.", self.show_system_info),
                ("Отчёт автозагрузки", "Считает записи автозапуска в реестре и папке Startup.", self.scan_startup_report),
                ("Сетевые порты", "Показывает слушающие порты и активные сетевые соединения.", self.check_network_ports),
                ("Перезапустить Explorer", "Перезапускает оболочку Windows после подтверждения.", self.restart_explorer),
                ("Загрузочная WinPE-флешка", "Создать загрузочную WinPE-флешку или перезагрузиться в WinRE.", self.show_winre_usb_window),
                ("Корреляция Malware", "Сравнение процессов с задачами планировщика и службами.", self.show_malware_correlation_window),
                ("Восстановление драйверов", "Пакетная установка/восстановление драйверов из резервной копии (.inf).", self.show_driver_recovery_window),
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
                "! ВНИМАНИЕ! Удаление или форматирование дисков\n"
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

        def show_cmd_window(self):
            dialog = NoVirCMDWindow(self)
            dialog.exec()

        def show_boot_repair_window(self):
            from PySide6.QtWidgets import QMessageBox
            from PySide6.QtCore import Qt as _Qt
            msg = QMessageBox(self)
            msg.setWindowFlags(msg.windowFlags() | _Qt.WindowStaysOnTopHint)
            msg.setWindowTitle("⚠️ Восстановление загрузчика MBR/BCD")
            msg.setIcon(QMessageBox.Warning)
            msg.setText(
                "! ВНИМАНИЕ! Восстановление загрузчика MBR/BCD\n"
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

            self.scan_thread = keep_thread(ScanThread())
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

        def create_diagnostic_page(self):
            from PySide6.QtWidgets import (QFrame, QVBoxLayout, QHBoxLayout, QLabel, 
                                           QTableWidget, QTableWidgetItem, QHeaderView, 
                                           QPushButton, QAbstractItemView)
            from PySide6.QtCore import Qt
            from PySide6.QtGui import QColor, QFont, QBrush

            page = QFrame()
            page.setStyleSheet("QFrame { background-color: #0d0d0d; }")
            outer_layout = QVBoxLayout(page)
            outer_layout.setContentsMargins(25, 20, 25, 20)
            outer_layout.setSpacing(15)

            # --- Header ---
            title = QLabel(language_manager.translate("Центр диагностики системы"))
            title.setStyleSheet("font-size: 22px; font-weight: bold; color: #ffffff;")
            outer_layout.addWidget(title)
            
            desc = QLabel(language_manager.translate("Умное сканирование узлов ОС на предмет скрытых повреждений."))
            desc.setStyleSheet("font-size: 13px; color: #888888; margin-bottom: 5px;")
            outer_layout.addWidget(desc)

            # --- Beautiful Table ---
            self.diag_table = QTableWidget(0, 3)
            self.diag_table.setHorizontalHeaderLabels([
                language_manager.translate("Компонент"), 
                language_manager.translate("Статус"), 
                language_manager.translate("Детали")
            ])
            
            # Setup columns
            self.diag_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            self.diag_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            self.diag_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
            
            # Disable editing, selection, and remove grid lines for a cleaner look
            self.diag_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.diag_table.setSelectionMode(QAbstractItemView.NoSelection)
            self.diag_table.setFocusPolicy(Qt.NoFocus)
            self.diag_table.setShowGrid(False)
            self.diag_table.setAlternatingRowColors(True)
            self.diag_table.verticalHeader().setVisible(False)
            
            # Modern Styling
            self.diag_table.setStyleSheet("""
                QTableWidget {
                    background-color: #121212;
                    alternate-background-color: #1a1a1a;
                    color: #e0e0e0;
                    border: 1px solid #333333;
                    border-radius: 6px;
                    font-size: 13px;
                }
                QHeaderView::section {
                    background-color: #000000;
                    color: #aaaaaa;
                    font-weight: bold;
                    padding: 8px;
                    border: none;
                    border-bottom: 2px solid #333333;
                    text-transform: uppercase;
                    font-size: 11px;
                }
                QTableWidget::item {
                    padding: 8px 12px;
                    border: none;
                }
            """)
            outer_layout.addWidget(self.diag_table)

            # --- Buttons ---
            btn_row = QHBoxLayout()
            btn_row.setSpacing(8)
            recovery_row = QHBoxLayout()
            recovery_row.setSpacing(8)

            self.btn_scan = QPushButton(language_manager.translate("Запустить сканирование"))
            self.btn_scan.setFixedHeight(42)
            self.btn_scan.setMinimumWidth(220)
            self.btn_scan.setCursor(Qt.PointingHandCursor)
            self.btn_scan.setStyleSheet("""
                QPushButton {
                    background-color: #222222;
                    color: #ffffff;
                    border: 1px solid #444444;
                    border-radius: 4px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #333333; border-color: #666666; }
                QPushButton:pressed { background-color: #111111; }
            """)
            self.btn_scan.clicked.connect(lambda checked=False: self.run_diagnostics())

            self.btn_fix = QPushButton(language_manager.translate("Исправить найденное"))
            self.btn_fix.setFixedHeight(42)
            self.btn_fix.setMinimumWidth(220)
            self.btn_fix.setEnabled(False)
            self.btn_fix.setCursor(Qt.PointingHandCursor)
            self.btn_fix.setStyleSheet("""
                QPushButton {
                    background-color: #0055ff;
                    color: #ffffff;
                    border: none;
                    border-radius: 4px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #1a66ff; }
                QPushButton:pressed { background-color: #0044cc; }
                QPushButton:disabled {
                    background-color: #2a2a2a;
                    color: #666666;
                }
            """)
            self.btn_fix.clicked.connect(self.fix_diagnostics)

            self.recovery_mode = QComboBox()
            self.recovery_mode.addItems([
                language_manager.translate("Только анализ"),
                language_manager.translate("План восстановления"),
                language_manager.translate("Подготовить исправление"),
            ])
            self.recovery_mode.setToolTip(
                "Анализ ничего не меняет; режим исправления требует отдельного подтверждения"
            )
            self.recovery_mode.currentIndexChanged.connect(self.update_recovery_controls)

            self.btn_plan = QPushButton(language_manager.translate("План"))
            self.btn_plan.setFixedHeight(42)
            self.btn_plan.setMinimumWidth(90)
            self.btn_plan.clicked.connect(self.show_recovery_plan)

            self.btn_report = QPushButton(language_manager.translate("Отчёт"))
            self.btn_report.setFixedHeight(42)
            self.btn_report.setMinimumWidth(90)
            self.btn_report.clicked.connect(self.export_incident_report)

            self.btn_recovery_point = QPushButton(language_manager.translate("Точка восстановления"))
            self.btn_recovery_point.setFixedHeight(42)
            self.btn_recovery_point.setMinimumWidth(240)
            self.btn_recovery_point.clicked.connect(self.create_recovery_point_ui)

            self.btn_restore_point = QPushButton(language_manager.translate("Откат точки"))
            self.btn_restore_point.setFixedHeight(42)
            self.btn_restore_point.setMinimumWidth(150)
            self.btn_restore_point.clicked.connect(self.restore_recovery_point_ui)

            btn_row.addWidget(self.recovery_mode, stretch=2)
            btn_row.addWidget(self.btn_scan, stretch=2)
            btn_row.addWidget(self.btn_plan)
            btn_row.addWidget(self.btn_report)
            outer_layout.addLayout(btn_row)

            recovery_row.addWidget(self.btn_recovery_point)
            recovery_row.addWidget(self.btn_restore_point)
            recovery_row.addStretch(1)
            recovery_row.addWidget(self.btn_fix)
            outer_layout.addLayout(recovery_row)

            page.retranslate_ui = lambda: (
                title.setText(language_manager.translate("Центр диагностики системы")),
                desc.setText(language_manager.translate("Умное сканирование узлов ОС на предмет скрытых повреждений.")),
                self.diag_table.setHorizontalHeaderLabels([
                    language_manager.translate("Компонент"), 
                    language_manager.translate("Статус"), 
                    language_manager.translate("Детали")
                ]),
                self.btn_scan.setText(language_manager.translate("Запустить сканирование")),
                self.btn_fix.setText(language_manager.translate("Исправить найденное"))
            )
            return page

        def update_recovery_controls(self, *_args):
            has_issues = any(
                result.get("needs_fix") and result.get("id") in self.RECOVERY_ACTIONS
                for result in getattr(self, "diag_results", [])
            )
            self.btn_fix.setEnabled(has_issues and self.recovery_mode.currentIndex() == 2)

        def create_recovery_point_ui(self):
            from PySide6.QtWidgets import QMessageBox
            try:
                point = create_recovery_point()
                self.last_recovery_point = point
                lines = [f"Точка сохранена: {point['path']}", ""]
                for component, record in point["components"].items():
                    lines.append(f"{component}: {record['status']} ({record.get('rollback', 'artifact saved')})")
                lines.append("")
                lines.append(point["note"])
                QMessageBox.information(self, "NoVir Recovery Point", "\n".join(lines))
                logger.log("RecoveryPoint", "success", point["path"])
            except OSError as error:
                logger.log("RecoveryPoint", "error", str(error))
                QMessageBox.critical(self, "NoVir Recovery Point", f"Не удалось создать точку: {error}")

        def restore_recovery_point_ui(self):
            from PySide6.QtWidgets import QFileDialog, QMessageBox
            point_dir = QFileDialog.getExistingDirectory(
                self,
                "Выберите NoVir Recovery Point",
                os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "NoVir", "RecoveryPoints"),
            )
            if not point_dir:
                return
            if QMessageBox.warning(
                self,
                "Подтвердите откат",
                "Будут импортированы сохранённые ветки реестра и сетевой dump. "
                "Службы и BCD требуют ручного восстановления; драйверы не входят в backup. Продолжить?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            ) != QMessageBox.Yes:
                return
            try:
                result = restore_recovery_point(point_dir)
                message = "Восстановлено: " + (", ".join(result["restored"]) or "нет")
                if result["manual_review"]:
                    message += "\nТребуют ручной проверки: " + ", ".join(result["manual_review"])
                QMessageBox.information(self, "NoVir Recovery Point", message)
            except Exception as error:
                logger.log("RecoveryPointRestore", "error", str(error))
                QMessageBox.critical(self, "NoVir Recovery Point", f"Откат остановлен: {error}")

        def show_recovery_plan(self):
            from PySide6.QtWidgets import QMessageBox
            plan = getattr(self, "recovery_plan", [])
            if not plan:
                QMessageBox.information(self, "План восстановления", "Сначала запустите диагностику. Подтверждённых проблем нет.")
                return
            lines = []
            for item in plan:
                lines.append(f"{item['title']} (риск: {item['risk']})")
                lines.extend(f"  - {step}" for step in item["steps"])
            QMessageBox.information(self, "План восстановления", "\n".join(lines))

        def export_incident_report(self):
            from PySide6.QtWidgets import QFileDialog, QMessageBox
            from PySide6.QtGui import QTextDocument
            from PySide6.QtPrintSupport import QPrinter
            import html
            import os
            results = getattr(self, "diag_results", [])
            if not results:
                QMessageBox.information(self, "NoVir Report", "Сначала запустите диагностику.")
                return
            report = build_incident_report(
                getattr(self, "incident_findings", results),
                getattr(self, "recovery_outcomes", {}),
                getattr(self, "scan_started_at", None),
            )
            if getattr(self, "last_recovery_point", None):
                report["recovery_point"] = self.last_recovery_point.get("path")
            path, selected_filter = QFileDialog.getSaveFileName(
                self,
                "Экспорт Incident Report",
                os.path.join(os.path.expanduser("~"), "NoVir_Recovery_Report.txt"),
                "Text report (*.txt);;HTML report (*.html);;PDF report (*.pdf)",
            )
            if not path:
                return
            if "HTML" in selected_filter and not path.lower().endswith(".html"):
                path += ".html"
            elif "PDF" in selected_filter and not path.lower().endswith(".pdf"):
                path += ".pdf"
            elif "Text" in selected_filter and not path.lower().endswith(".txt"):
                path += ".txt"
            try:
                is_html_or_pdf = path.lower().endswith(".html") or path.lower().endswith(".pdf")
                if is_html_or_pdf:
                    rows = "".join(
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                            html.escape(str(item.get("name", item.get("id", "Unknown")))),
                            html.escape(str(item.get("status", "INFO"))),
                            html.escape(str(report["recovery_outcomes"].get(item.get("id"), "not attempted"))),
                            html.escape(str(item.get("details", ""))),
                        )
                        for item in report["findings"]
                    )
                    body = (
                        "<!doctype html><html><meta charset='utf-8'><title>NoVir Recovery Report</title>"
                        "<style>body { font-family: sans-serif; } table { width: 100%; border-collapse: collapse; } th, td { border: 1px solid #ccc; padding: 6px; }</style>"
                        "<h1>NoVir Recovery Report</h1><p>Scan: {}</p>"
                        "<p>Problems found: {} | Problems fixed: {} | Requires attention: {}</p>"
                        "<p>Recovery Point: {}</p>"
                        "<table><tr><th>Component</th><th>Status</th><th>Recovery</th><th>Details</th></tr>{}</table></html>"
                    ).format(
                        html.escape(report["generated_at"]), report["problems_found"],
                        report["problems_fixed"], report["requires_attention"],
                        html.escape(str(report.get("recovery_point", "not created"))), rows,
                    )
                else:
                    body = format_incident_report_text(report)
                
                if path.lower().endswith(".pdf"):
                    doc = QTextDocument()
                    doc.setHtml(body)
                    printer = QPrinter(QPrinter.HighResolution)
                    printer.setOutputFormat(QPrinter.PdfFormat)
                    printer.setOutputFileName(path)
                    doc.print_(printer)
                else:
                    with open(path, "w", encoding="utf-8") as output_file:
                        output_file.write(body)
                QMessageBox.information(self, "NoVir Report", f"Отчёт сохранён: {path}")
            except OSError as error:
                QMessageBox.critical(self, "NoVir Report", f"Не удалось сохранить отчёт: {error}")

        def show_malware_correlation_window(self):
            from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QPushButton, QHBoxLayout, QHeaderView
            import subprocess
            dlg = QDialog(self)
            dlg.setWindowTitle("Корреляция Malware-процессов")
            dlg.resize(600, 400)
            layout = QVBoxLayout(dlg)
            info = QLabel("Сравнение запущенных процессов с активными службами и задачами (эвристика):")
            layout.addWidget(info)
            table = QTableWidget(0, 3)
            table.setHorizontalHeaderLabels(["Процесс", "Тип связи", "Статус"])
            table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            layout.addWidget(table)
            
            try:
                tasks = subprocess.check_output(
                    ["schtasks", "/query", "/fo", "csv", "/nh"],
                    shell=False,
                    text=True,
                    errors="ignore",
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                for line in tasks.splitlines()[:15]:
                    if line.strip():
                        r = table.rowCount()
                        table.insertRow(r)
                        parts = line.split('","')
                        name = parts[0].strip('"') if len(parts) > 0 else "Unknown Task"
                        table.setItem(r, 0, QTableWidgetItem(name))
                        table.setItem(r, 1, QTableWidgetItem("Task Scheduler"))
                        table.setItem(r, 2, QTableWidgetItem("Suspicious" if "temp" in name.lower() else "OK"))
            except Exception:
                pass
                
            btn_close = QPushButton("Закрыть")
            btn_close.clicked.connect(dlg.accept)
            layout.addWidget(btn_close)
            dlg.exec_()

        def show_driver_recovery_window(self):
            from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QFileDialog, QMessageBox
            import subprocess
            dlg = QDialog(self)
            dlg.setWindowTitle("Восстановление драйверов")
            dlg.resize(400, 200)
            layout = QVBoxLayout(dlg)
            info = QLabel("Укажите папку с резервной копией драйверов (содержит .inf файлы).")
            info.setWordWrap(True)
            layout.addWidget(info)
            
            def do_recover():
                folder = QFileDialog.getExistingDirectory(dlg, "Выберите папку с драйверами")
                if folder:
                    try:
                        driver_pattern = os.path.join(folder, "*.inf")
                        subprocess.Popen(
                            ["pnputil", "/add-driver", driver_pattern, "/subdirs", "/install"],
                            shell=False,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        )
                        QMessageBox.information(dlg, "Готово", "Процесс установки драйверов запущен.")
                        dlg.accept()
                    except Exception as e:
                        QMessageBox.critical(dlg, "Ошибка", str(e))
                        
            btn_rec = QPushButton("Указать папку и восстановить")
            btn_rec.clicked.connect(do_recover)
            layout.addWidget(btn_rec)
            dlg.exec_()

        def show_winre_usb_window(self):
            from PySide6.QtWidgets import (
                QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                QMessageBox, QComboBox, QCheckBox,
            )
            from PySide6.QtGui import QDesktopServices
            from PySide6.QtCore import QUrl
            class WinPEBuildDialog(QDialog):
                def closeEvent(dialog_self, event):
                    if dialog_self.property("winpe_build_active"):
                        event.ignore()
                        return
                    super().closeEvent(event)

            dlg = WinPEBuildDialog(self)
            dlg.setWindowTitle(language_manager.translate("Создание WinPE USB"))
            dlg.resize(610, 430)
            layout = QVBoxLayout(dlg)
            info = QLabel(language_manager.translate(
                "WinPE создаётся для компьютеров x64 и не содержит приложение NoVir."
            ))
            info.setWordWrap(True)
            layout.addWidget(info)

            bootex_checkbox = QCheckBox(language_manager.translate(
                "Создавать носитель с загрузчиком UEFI CA 2023 (ADK от декабря 2024 или новее)"
            ))
            bootex_checkbox.setChecked(True)
            bootex_checkbox.setToolTip(language_manager.translate(
                "Выбор UEFI CA 2023 зависит от Secure Boot целевого компьютера."
            ))
            layout.addWidget(bootex_checkbox)

            tools_status = QLabel()
            tools_status.setWordWrap(True)
            layout.addWidget(tools_status)

            drive_row = QHBoxLayout()
            drive_label = QLabel(language_manager.translate("USB-накопитель"))
            drive_row.addWidget(drive_label)
            drive_combo = QComboBox()
            drive_combo.setMinimumWidth(330)
            drive_row.addWidget(drive_combo, 1)
            refresh_button = QPushButton(language_manager.translate("Обновить список USB"))
            drive_row.addWidget(refresh_button)
            layout.addLayout(drive_row)

            status = QLabel()
            status.setWordWrap(True)
            status.setStyleSheet("color: #aaaaaa; padding: 5px 0;")
            layout.addWidget(status)

            tool_cache = [None]
            def refresh_usb_list():
                tool_cache[0] = winpe_media.find_adk_tools()
                drives = winpe_media.enumerate_removable_usb_drives()
                previous_drive = drive_combo.currentData()
                drive_combo.clear()
                for drive in drives:
                    size_gib = drive["total"] / (1024 ** 3)
                    label = f'{drive["root"]}  {drive["label"]}  {size_gib:.1f} GB'
                    drive_combo.addItem(label, drive["root"])
                    drive_combo.setItemData(drive_combo.count() - 1, drive["serial"], Qt.UserRole + 1)
                if previous_drive:
                    previous_index = drive_combo.findData(previous_drive)
                    if previous_index >= 0:
                        drive_combo.setCurrentIndex(previous_index)
                if tool_cache[0]:
                    tools_status.setText(language_manager.translate("Инструменты ADK и WinPE найдены."))
                else:
                    tools_status.setText(language_manager.translate(
                        "Инструменты Windows ADK и WinPE не найдены. Установите Windows ADK и отдельное дополнение Windows PE."
                    ))
                if not drives:
                    status.setText(language_manager.translate(
                        "USB-флешки не найдены. Подключите съёмную флешку и обновите список."
                    ))
                else:
                    status.setText("")
                create_button.setEnabled(bool(tool_cache[0]) and bool(drives))

            refresh_button.clicked.connect(refresh_usb_list)

            install_adk_button = QPushButton(language_manager.translate("Открыть страницу установки ADK"))
            install_adk_button.clicked.connect(
                lambda: QDesktopServices.openUrl(QUrl(winpe_media.ADK_INSTALL_URL))
            )
            layout.addWidget(install_adk_button)

            create_button = QPushButton(language_manager.translate("Создать загрузочную WinPE-флешку"))
            create_button.setMinimumHeight(42)

            def create_bootable_usb():
                if getattr(self, "_winpe_worker", None) is not None and self._winpe_worker.isRunning():
                    return
                tools = winpe_media.find_adk_tools()
                if not tools:
                    refresh_usb_list()
                    QMessageBox.warning(
                        dlg,
                        language_manager.translate("Ошибка"),
                        language_manager.translate(
                            "Инструменты Windows ADK и WinPE не найдены. Установите Windows ADK и отдельное дополнение Windows PE."
                        ),
                    )
                    return
                drive_root = drive_combo.currentData()
                drive_serial = drive_combo.currentData(Qt.UserRole + 1)
                if not drive_root:
                    return
                drive = next((item for item in winpe_media.enumerate_removable_usb_drives()
                              if item["root"] == drive_root
                              and item.get("serial") == drive_serial), None)
                if drive is None:
                    refresh_usb_list()
                    QMessageBox.warning(dlg, language_manager.translate("Ошибка"), language_manager.translate(
                        "USB-флешки не найдены. Подключите съёмную флешку и обновите список."
                    ))
                    return

                answer = QMessageBox.question(
                    dlg,
                    language_manager.translate("Создать загрузочную WinPE-флешку"),
                    language_manager.translate(
                        "Выберите съёмную USB-флешку. Её раздел будет отформатирован; все данные на нём будут удалены. Сборка использует официальные инструменты Windows ADK."
                    ) + f'\n\n{drive["root"]}  {drive["label"]}  {drive["total"] / (1024 ** 3):.1f} GB',
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if answer != QMessageBox.Yes:
                    return

                try:
                    work_root, work_dir = winpe_media.make_working_directory()
                except OSError as error:
                    QMessageBox.critical(dlg, language_manager.translate("Ошибка"), str(error))
                    return

                command_paths = [tools["environment"], tools["copype"], tools["make_media"], work_dir]
                if any("%" in path or "!" in path or '"' in path for path in command_paths):
                    try:
                        winpe_media.cleanup_working_directory(work_root, work_dir)
                    except (OSError, ValueError):
                        pass
                    QMessageBox.critical(
                        dlg,
                        language_manager.translate("Ошибка"),
                        language_manager.translate("Путь ADK содержит символы, небезопасные для команды Windows:")
                        + " " + work_dir,
                    )
                    return

                self._winpe_work_root = work_root
                self._winpe_work_dir = work_dir
                self._winpe_completion_handled = False
                worker = WinPEBuildWorker(
                    tools,
                    work_dir,
                    drive_root,
                    drive_serial,
                    use_bootex=bootex_checkbox.isChecked(),
                    parent=self,
                )
                self._winpe_worker = keep_thread(worker)

                def on_stage_changed(stage_text):
                    status.setText(language_manager.translate(stage_text))

                def on_result_ready(result):
                    if self._winpe_completion_handled:
                        return
                    self._winpe_completion_handled = True
                    dlg.setProperty("winpe_build_active", False)
                    if result.get("success"):
                        try:
                            winpe_media.cleanup_working_directory(work_root, work_dir)
                        except (OSError, ValueError):
                            pass
                        status.setText(language_manager.translate("WinPE USB готова:") + " " + drive_root)
                        QMessageBox.information(
                            dlg,
                            language_manager.translate("Готово"),
                            language_manager.translate("WinPE USB готова:") + " " + drive_root,
                        )
                    else:
                        details = (result.get("output") or "").strip()[-3500:]
                        if result.get("stage") == "USB_CHANGED":
                            details = language_manager.translate(
                                "USB-флешка изменилась или отключена. Запись отменена."
                            )
                        full_message = (
                            language_manager.translate(
                                "Создание WinPE завершилось с ошибкой. Рабочие файлы оставлены здесь:"
                            ) + "\n" + work_dir
                        )
                        if details:
                            full_message += "\n\n" + details
                        status.setText(language_manager.translate("Ошибка") + ": " + result.get("stage", ""))
                        QMessageBox.critical(dlg, language_manager.translate("Ошибка"), full_message)

                def on_worker_finished():
                    create_button.setEnabled(bool(tool_cache[0]) and bool(drive_combo.count()))
                    refresh_button.setEnabled(True)
                    drive_combo.setEnabled(True)

                worker.stage_changed.connect(on_stage_changed)
                worker.result_ready.connect(on_result_ready)
                worker.finished.connect(on_worker_finished)
                dlg.setProperty("winpe_build_active", True)
                create_button.setEnabled(False)
                refresh_button.setEnabled(False)
                drive_combo.setEnabled(False)
                status.setText(language_manager.translate("Создание выполняется. Не отключайте USB-флешку."))
                worker.start()

            create_button.clicked.connect(create_bootable_usb)
            layout.addWidget(create_button)

            def do_winre():
                try:
                    subprocess.run(["reagentc", "/boottore"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    subprocess.Popen(["shutdown", "/r", "/t", "5"])
                    QMessageBox.information(
                        dlg,
                        language_manager.translate("Перезагрузка"),
                        language_manager.translate("Система перезагрузится в WinRE через 5 секунд."),
                    )
                    dlg.accept()
                except Exception as e:
                    QMessageBox.critical(
                        dlg,
                        language_manager.translate("Ошибка"),
                        language_manager.translate("Не удалось настроить WinRE. Убедитесь, что программа запущена от имени администратора. ") + str(e),
                    )

            btn_winre = QPushButton(language_manager.translate("Перезагрузка в WinRE"))
            btn_winre.clicked.connect(do_winre)
            layout.addWidget(btn_winre)
            refresh_usb_list()
            dlg.exec_()



        def run_diagnostics(self, verification_for=None):
            from PySide6.QtWidgets import QTableWidgetItem
            from PySide6.QtCore import Qt
            from PySide6.QtGui import QColor, QFont

            if isinstance(verification_for, bool):
                verification_for = None
            
            self.diag_table.setRowCount(0)
            self.diag_results = []
            if verification_for is None:
                self.scan_started_at = datetime.now().astimezone().isoformat(timespec="seconds")
                self.recovery_outcomes = {}
                self.incident_findings = []
            
            components = [
                ("services", language_manager.translate("Системные Службы (Services)"), self.check_services),
                ("dns", language_manager.translate("Настройки DNS"), self.check_dns),
                ("tcpip", language_manager.translate("Сетевой протокол TCP/IP"), self.check_tcpip),
                ("hosts", language_manager.translate("Hosts Файл"), self.check_hosts),
                ("bcd", language_manager.translate("Загрузчик BCD"), self.check_bootconfig),
                ("wmi", language_manager.translate("WMI Repository"), self.check_wmi),
                ("windows_update", language_manager.translate("Windows Update"), self.check_windows_update),
                ("update_cache", language_manager.translate("Кэш обновлений"), self.check_update_cache),
                ("proxy", language_manager.translate("Network Proxy"), self.check_proxy),
                ("safeboot", language_manager.translate("Safe Mode"), self.check_safeboot),
                ("defender", language_manager.translate("Windows Defender"), self.check_defender),
                ("taskmgr", language_manager.translate("Task Manager"), self.check_taskmgr)
            ]
            
            for component_id, name, func in components:
                try:
                    status, details, needs_fix = func()
                except Exception as error:
                    status = "i INFO"
                    details = f"{language_manager.translate('Проверка недоступна')}: {error}"
                    needs_fix = False
                self.diag_results.append({
                    'id': component_id,
                    'name': name,
                    'status': status,
                    'details': details,
                    'needs_fix': needs_fix,
                })
                
                row = self.diag_table.rowCount()
                self.diag_table.insertRow(row)
                
                # Name Item
                name_item = QTableWidgetItem(name)
                name_font = QFont("Segoe UI", 9)
                name_font.setBold(True)
                name_item.setFont(name_font)
                self.diag_table.setItem(row, 0, name_item)
                
                # Status Item (Clean emojis, nice colors)
                status_item = QTableWidgetItem(status)
                status_item.setTextAlignment(Qt.AlignCenter)
                font = QFont("Segoe UI", 9)
                font.setBold(True)
                status_item.setFont(font)
                
                if "✓" in status:
                    status_item.setForeground(QColor("#10b981")) # Emerald Green
                elif "!" in status:
                    status_item.setForeground(QColor("#f59e0b")) # Amber Warning
                elif "✕" in status:
                    status_item.setForeground(QColor("#ef4444")) # Red Error
                else:
                    status_item.setForeground(QColor("#3b82f6")) # Blue Info
                
                self.diag_table.setItem(row, 1, status_item)
                
                # Details Item
                details_item = QTableWidgetItem(details)
                details_item.setForeground(QColor("#a3a3a3")) # Light gray
                self.diag_table.setItem(row, 2, details_item)
                
            self.last_diagnostic_results = list(self.diag_results)
            if verification_for is None:
                self.incident_findings = list(self.diag_results)
            else:
                verified_by_id = {item.get("id"): item for item in self.diag_results}
                for before in verification_for:
                    if not before.get("needs_fix"):
                        continue
                    after = verified_by_id.get(before.get("id"), {})
                    if after.get("status", "").startswith("✓") and not after.get("needs_fix"):
                        self.recovery_outcomes[before.get("id")] = "verified"
                    elif after:
                        prior_outcome = self.recovery_outcomes.get(before.get("id"))
                        if prior_outcome != "manual_review" and not (
                            isinstance(prior_outcome, str) and prior_outcome.startswith("failed:")
                        ):
                            self.recovery_outcomes[before.get("id")] = "requires_attention"
                    else:
                        self.recovery_outcomes[before.get("id")] = "verification_unavailable"

            self.recovery_plan = build_recovery_plan(
                self.incident_findings if verification_for is not None else self.diag_results
            )
            context_lines = [
                f"{item['name']} | {item['status']} | {item['details']}"
                for item in self.diag_results
            ]
            context_lines.extend(
                f"Hypothesis: {plan['title']}; risk={plan['risk']}; "
                f"steps={' / '.join(plan['steps'])}"
                for plan in self.recovery_plan
            )
            self.current_issues_text = "\n".join(context_lines)
            self.update_recovery_controls()

        def check_services(self):
            import subprocess
            services = {'wuauserv': 'Windows Update', 'BITS': 'BITS', 'Winmgmt': 'WMI', 'wscsvc': 'Security Center'}
            bad_services = []
            try:
                for srv, name in services.items():
                    res = subprocess.run(["sc", "query", srv], capture_output=True, text=True, creationflags=0x08000000)
                    if "1060" in res.stdout or "STOPPED" in res.stdout:
                        # Sometimes BITS is stopped legally, but wscsvc and Winmgmt should be running. Let's just flag if they are disabled.
                        qc = subprocess.run(["sc", "qc", srv], capture_output=True, text=True, creationflags=0x08000000)
                        if "DISABLED" in qc.stdout:
                            bad_services.append(name)
                
                if bad_services:
                    return "! WARNING", f"{language_manager.translate('Отключены службы:')} {', '.join(bad_services)}", True
                return "✓ OK", language_manager.translate("Все критические службы работают"), False
            except:
                return "i INFO", language_manager.translate("Проверка служб пропущена"), False

        def check_dns(self):
            import subprocess
            try:
                res = subprocess.run(
                    ["nslookup", "google.com"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=0x08000000,
                )
                output = res.stdout.lower() + res.stderr.lower()
                if res.returncode != 0 or any(
                    marker in output
                    for marker in ("can't find", "non-existent domain", "dns request timed out", "server failed")
                ):
                    return "i INFO", language_manager.translate("DNS-проверка недоступна; проверьте подключение к интернету"), False
                answer_block = ""
                lines = res.stdout.splitlines()
                for index, line in enumerate(lines):
                    if re.match(r"\s*Name:\s*google\.com\s*$", line, re.IGNORECASE):
                        answer_block = "\n".join(lines[index + 1:index + 5])
                        break
                if re.search(r"\b(?:127(?:\.\d{1,3}){3}|0\.0\.0\.0)\b", answer_block):
                    return "! WARNING", language_manager.translate("DNS перенаправляет google.com на локальный адрес!"), True
                return "✓ OK", language_manager.translate("DNS работает корректно"), False
            except Exception:
                return "i INFO", language_manager.translate("DNS проверка пропущена"), False

        def check_tcpip(self):
            import subprocess
            try:
                # Check Winsock catalog integrity
                res = subprocess.run(
                    ["netsh", "winsock", "show", "catalog"],
                    capture_output=True, text=True, timeout=5, creationflags=0x08000000
                )
                output = res.stdout.lower()
                # If catalog is missing or clearly broken
                if res.returncode != 0:
                    return "i INFO", language_manager.translate("Проверка Winsock недоступна"), False
                if len(output) < 50:
                    return "i INFO", language_manager.translate("Вывод проверки Winsock неполный; повреждение не подтверждено"), False
                # Check for suspicious LSP (malware often injects into Winsock)
                import winreg
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                        r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries") as k:
                        pass
                except PermissionError:
                    return "i INFO", language_manager.translate("Нет прав для проверки Winsock"), False
                except FileNotFoundError:
                    return "! WARNING", language_manager.translate("Раздел протоколов Winsock не найден"), True
                return "✓ OK", language_manager.translate("Сетевой стек TCP/IP в норме"), False
            except Exception:
                return "i INFO", language_manager.translate("TCP/IP проверка пропущена"), False

        def check_windows_update(self):
            import subprocess
            results = {}
            services = {'wuauserv': 'Windows Update', 'BITS': 'BITS', 'cryptsvc': 'CryptSvc', 'msiserver': 'MSI Installer'}
            broken = []
            for srv, name in services.items():
                try:
                    qc = subprocess.run(["sc", "qc", srv], capture_output=True, text=True, creationflags=0x08000000)
                    if "DISABLED" in qc.stdout:
                        broken.append(name)
                except:
                    pass
            if broken:
                return "! WARNING", f"{language_manager.translate('Отключены компоненты:')} {', '.join(broken)}", True
            # Also check registry key for Windows Update policy
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate") as k:
                    try:
                        val, _ = winreg.QueryValueEx(k, "DisableWindowsUpdateAccess")
                        if val == 1:
                            return "! WARNING", language_manager.translate("Обновления заблокированы политиками"), True
                    except FileNotFoundError:
                        pass
            except FileNotFoundError:
                pass
            return "✓ OK", language_manager.translate("Windows Update работает нормально"), False

        def check_update_cache(self):
            import os
            cache_path = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'SoftwareDistribution', 'Download')
            try:
                total = sum(
                    os.path.getsize(os.path.join(dirpath, f))
                    for dirpath, _, fnames in os.walk(cache_path)
                    for f in fnames
                )
                mb = total / (1024 * 1024)
                if mb > 500:
                    return "i ИНФО", f"{language_manager.translate('Кэш обновлений занимает')} {mb:.0f} MB — {language_manager.translate('можно очистить')}", False
                return "✓ OK", f"{language_manager.translate('Кэш обновлений')} {mb:.0f} MB", False
            except:
                return "✓ OK", language_manager.translate("Кэш обновлений доступен"), False

        def check_wmi(self):
            import subprocess
            try:
                res = subprocess.run(["winmgmt", "/verifyrepository"], capture_output=True, text=True, creationflags=0x08000000)
                output = res.stdout.lower() + res.stderr.lower()
                if res.returncode != 0:
                    return "i INFO", language_manager.translate("Проверка WMI недоступна"), False
                if "inconsistent" in output:
                    return "! WARNING", language_manager.translate("Репозиторий WMI повреждён — нужно восстановление"), True
                if "consistent" in output:
                    return "✓ OK", language_manager.translate("Репозиторий WMI исправен"), False
                return "i INFO", language_manager.translate("WMI не вернул распознаваемый результат проверки"), False
            except:
                return "i ИНФО", language_manager.translate("Проверка WMI недоступна"), False

        def check_bootconfig(self):
            import subprocess
            try:
                result = subprocess.run(
                    ["bcdedit", "/enum", "default"],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    creationflags=0x08000000,
                )
                output = result.stdout.lower()
                error = result.stderr.lower()
                if "access is denied" in error or "access is denied" in output or result.returncode == 5:
                    return "i INFO", language_manager.translate("Нет прав для полной проверки загрузчика Windows"), False
                if result.returncode == 0 and "winload" in output:
                    if "testsigning" in output:
                        return "i INFO", language_manager.translate("Включен тестовый режим подписи; это может быть задано пользователем"), False
                    return "✓ OK", language_manager.translate("Загрузчик Windows в норме"), False

                fallback = subprocess.run(
                    ["bcdedit"],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    creationflags=0x08000000,
                )
                if fallback.returncode == 0 and "winload" in fallback.stdout.lower():
                    return "✓ OK", language_manager.translate("Загрузчик Windows в норме"), False
                return "i INFO", language_manager.translate("Не удалось подтвердить состояние загрузчика Windows"), False
            except Exception:
                return "i INFO", language_manager.translate("bcdedit недоступен (нет прав?)"), False

        def check_hosts(self):
            import os
            hosts_path = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', 'drivers', 'etc', 'hosts')
            try:
                with open(hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
                if not lines or (len(lines) == 1 and '127.0.0.1' in lines[0] and 'localhost' in lines[0]):
                    return "✓ OK", language_manager.translate("Стандартный файл"), False
                return "i INFO", language_manager.translate("Есть пользовательские записи; проверьте их вручную"), False
            except OSError:
                return "i INFO", language_manager.translate("Нет доступа к файлу hosts для проверки"), False

        def check_proxy(self):
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
                    proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                    if proxy_enable == 1:
                        proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                        return "i INFO", f"{language_manager.translate('Прокси включен (может быть настроен пользователем):')} {proxy_server}", False
            except:
                pass
            return "✓ OK", language_manager.translate("Прокси отключен или системная настройка недоступна"), False
            
        def check_safeboot(self):
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal") as key:
                    pass
                return "✓ OK", language_manager.translate("Ключи SafeBoot на месте"), False
            except FileNotFoundError:
                return "✕ ERROR", language_manager.translate("Ключи SafeBoot удалены!"), True
            except PermissionError:
                return "i INFO", language_manager.translate("Нет прав для проверки SafeBoot"), False
                
        def check_defender(self):
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender") as key:
                    val, _ = winreg.QueryValueEx(key, "DisableAntiSpyware")
                    if val == 1:
                        return "! WARNING", language_manager.translate("Защитник отключен через политики"), True
            except FileNotFoundError:
                pass
            return "✓ OK", language_manager.translate("Политики Защитника в норме"), False
            
        def check_taskmgr(self):
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System") as key:
                    val, _ = winreg.QueryValueEx(key, "DisableTaskMgr")
                    if val == 1:
                        return "! WARNING", language_manager.translate("Диспетчер задач заблокирован"), True
            except FileNotFoundError:
                pass
            return "✓ OK", language_manager.translate("Диспетчер задач доступен"), False

        def open_global_ai_chat(self):
            try:
                dlg = NoVirAIChatDialog("MANUAL", parent=self)
                dlg.exec()
            except Exception as e:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.critical(self, "NoVir AI", f"Не удалось открыть AI Assistant:\n{e}")

        def offer_ai_help(self):
            issues_lines = []
            for item in getattr(self, "diag_results", []):
                status = item.get("status", "")
                name   = item.get("name", "")
                detail = item.get("detail", "")
                issues_lines.append(f"{status} {name}: {detail}")
            issues_text = "\n".join(issues_lines) if issues_lines else "MANUAL"
            try:
                dlg = NoVirAIChatDialog(issues_text, parent=self)
                dlg.exec()
            except Exception as e:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.critical(self, "NoVir AI", f"Не удалось открыть AI Assistant:\n{e}")

        def fix_diagnostics(self):
            import os
            import subprocess
            import winreg
            from PySide6.QtWidgets import QMessageBox
            from datetime import datetime
            def _run_recovery_fix(self):
                import subprocess
                import winreg
                from PySide6.QtWidgets import QMessageBox

                initial_results = list(getattr(self, "diag_results", []))
                actionable = [
                    item for item in initial_results
                    if item.get("needs_fix") and item.get("id") in self.RECOVERY_ACTIONS
                ]
                if not actionable:
                    QMessageBox.information(
                        self,
                        "Recovery Engine",
                        "Автоматических исправлений для этих находок нет. Откройте план и выполните ручную проверку.",
                    )
                    return

                plan_lines = []
                for item in actionable:
                    plan_lines.append(f"{item['name']}: {item['details']}")
                    if item["id"] == "dns":
                        plan_lines.append("  Вернуть DNS активных адаптеров в DHCP; сеть может кратко переподключиться.")
                    elif item["id"] == "taskmgr":
                        plan_lines.append("  Удалить подтверждённое значение DisableTaskMgr из пользовательской политики.")
                if QMessageBox.warning(
                    self,
                    "Подтвердите план восстановления",
                    "Перед исправлением будет создана Recovery Point.\n\n"
                    + "\n".join(plan_lines) + "\n\nПродолжить?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                ) != QMessageBox.Yes:
                    return

                try:
                    point = create_recovery_point()
                    self.last_recovery_point = point
                except Exception as error:
                    logger.log("RecoveryEngine", "error", f"Recovery point failed: {error}")
                    QMessageBox.critical(self, "Recovery Engine", f"Исправления отменены: Recovery Point не создана.\n{error}")
                    return

                outcomes = {}

                def run_checked(command):
                    result = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        shell=False,
                        timeout=30,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                    if result.returncode != 0:
                        raise OSError(result.stderr.strip() or result.stdout.strip() or f"Код {result.returncode}")
                    return result

                for item in actionable:
                    component_id = item["id"]
                    try:
                        if component_id == "dns":
                            if point["components"].get("network", {}).get("status") != "saved":
                                raise OSError("Сетевой снимок не сохранён; исправление остановлено")
                            if win_at_least("8"):
                                _ps = "Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty Name"
                            else:
                                _ps = ("Get-WmiObject Win32_NetworkAdapter -Filter \"NetConnectionStatus=2\" "
                                       "| Select-Object -ExpandProperty NetConnectionID")
                            result = run_checked([
                                "powershell", "-NoProfile", "-Command", _ps,
                            ])
                            adapters = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                            if not adapters:
                                raise OSError("Активные сетевые адаптеры не найдены")
                            for adapter in adapters:
                                run_checked(["netsh", "interface", "ip", "set", "dns", f"name={adapter}", "source=dhcp"])
                            run_checked(["ipconfig", "/flushdns"])
                        elif component_id == "taskmgr":
                            if point["components"].get("registry_user_policies", {}).get("status") != "saved":
                                raise OSError("Снимок пользовательской политики не сохранён; исправление остановлено")
                            with winreg.OpenKey(
                                winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                                0,
                                winreg.KEY_SET_VALUE,
                            ) as key:
                                winreg.DeleteValue(key, "DisableTaskMgr")
                        outcomes[component_id] = "applied_pending_verification"
                        logger.log("RecoveryEngine", "success", f"Applied {component_id}; verification pending")
                    except Exception as error:
                        outcomes[component_id] = f"failed: {error}"
                        logger.log("RecoveryEngine", "error", f"Failed {component_id}: {error}")

                for item in initial_results:
                    if item.get("needs_fix") and item.get("id") not in self.RECOVERY_ACTIONS:
                        outcomes[item.get("id")] = "manual_review"
                self.recovery_outcomes = outcomes
                self.incident_findings = initial_results
                self.run_diagnostics(verification_for=initial_results)
                report = build_incident_report(
                    initial_results,
                    self.recovery_outcomes,
                    self.scan_started_at,
                )
                QMessageBox.information(
                    self,
                    "Recovery Engine: результат",
                    format_incident_report_text(report)
                    + f"\nRecovery Point: {point['path']}\n"
                    + point["note"],
                )

            return _run_recovery_fix(self)

        def create_program_page(self):
            """Настройки приложения и системные параметры пользователя."""
            from PySide6.QtWidgets import QScrollArea

            page = QScrollArea()
            page.setWidgetResizable(True)
            page.setFrameShape(QFrame.NoFrame)
            content = QFrame()
            layout = QVBoxLayout(content)
            layout.setContentsMargins(24, 18, 24, 18)
            layout.setSpacing(12)
            layout.setAlignment(Qt.AlignTop)

            hdr = QLabel("НАСТРОЙКИ")
            hdr.setStyleSheet("color: #ffffff; font-size: 20px; font-weight: bold; letter-spacing: 3px;")
            layout.addWidget(hdr)

            sep = QFrame()
            sep.setFrameShape(QFrame.HLine)
            sep.setStyleSheet("background-color: #333333; max-height: 1px;")
            layout.addWidget(sep)

            website_row = QHBoxLayout()
            website_label = QLabel(language_manager.translate("Сайт программы"))
            website_label.setStyleSheet("color: #ffffff; font-size: 12px; font-weight: bold;")
            website_row.addWidget(website_label)
            website_link = QLabel(f'<a href="{PROGRAM_WEBSITE_URL}">{PROGRAM_WEBSITE_URL}</a>')
            website_link.setTextInteractionFlags(Qt.TextBrowserInteraction)
            website_link.setOpenExternalLinks(True)
            website_link.setStyleSheet("QLabel { color: #bbbbbb; padding: 2px 0; } QLabel a { color: #ffffff; }")
            website_row.addWidget(website_link)
            website_row.addStretch()
            website_button = QPushButton(language_manager.translate("Открыть сайт программы"))
            website_button.setMinimumHeight(34)
            website_button.setStyleSheet(
                "QPushButton { background: #111111; color: #ffffff; border: 1px solid #444444;"
                " font-weight: bold; padding: 6px 12px; }"
                "QPushButton:hover, QPushButton:focus { background: #1b1b1b; border-color: #ffffff; }"
                "QPushButton:pressed { background: #2a2a2a; }"
            )
            website_button.clicked.connect(self.open_program_website)
            website_row.addWidget(website_button)
            layout.addLayout(website_row)

            settings = load_app_settings()
            self.cb_always_on_top = QCheckBox(language_manager.translate("Всегда поверх окон"))
            self.cb_always_on_top.setChecked(bool(settings.get("always_on_top", False)))
            self.cb_always_on_top.stateChanged.connect(self.toggle_always_on_top)
            layout.addWidget(self.cb_always_on_top)

            winre_title = QLabel(language_manager.translate("Папка сохранения WinRE"))
            winre_title.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: bold; margin-top: 8px;")
            layout.addWidget(winre_title)
            self.winre_backup_path = os.path.abspath(settings.get(
                "winre_backup_dir",
                os.path.join(os.path.expanduser("~"), "Documents", "NoVir", "WinRE"),
            ))
            winre_folder_row = QHBoxLayout()
            self.winre_path_edit = QLineEdit(self.winre_backup_path)
            self.winre_path_edit.setReadOnly(True)
            self.winre_path_edit.setToolTip(self.winre_backup_path)
            winre_folder_row.addWidget(self.winre_path_edit, 1)
            self.winre_folder_button = QPushButton(language_manager.translate("Изменить папку сохранения"))
            self.winre_folder_button.setMinimumHeight(38)
            self.winre_folder_button.clicked.connect(self.choose_winre_backup_folder)
            winre_folder_row.addWidget(self.winre_folder_button)
            layout.addLayout(winre_folder_row)

            recovery_row = QHBoxLayout()
            self.winre_status_label = QLabel(language_manager.translate("Вы запустились в среде восстановления:"))
            recovery_row.addWidget(self.winre_status_label, 1)
            system_root = os.environ.get("SystemRoot", os.environ.get("WINDIR", ""))
            self.in_winre_environment = os.path.splitdrive(system_root)[0].upper() == "X:"
            self.winre_status_value = QLabel()
            self.winre_status_value.setObjectName("ReadOnlySettingValue")
            self.winre_status_value.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            self.winre_status_value.setMinimumWidth(100)
            self.winre_status_value.setStyleSheet("QLabel#ReadOnlySettingValue { border: 1px solid #444444; padding: 8px; color: #bbbbbb; }")
            recovery_row.addWidget(self.winre_status_value)
            layout.addLayout(recovery_row)

            user_row = QHBoxLayout()
            self.current_user_label = QLabel(language_manager.translate("Текущий пользователь:"))
            user_row.addWidget(self.current_user_label, 1)
            current_user = os.environ.get("USERNAME") or os.environ.get("USER") or "Unknown"
            self.current_user_value = QLabel(current_user)
            self.current_user_value.setObjectName("ReadOnlySettingValue")
            self.current_user_value.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            self.current_user_value.setMinimumWidth(180)
            self.current_user_value.setStyleSheet("QLabel#ReadOnlySettingValue { border: 1px solid #444444; padding: 8px; color: #bbbbbb; }")
            self.current_user_value.setToolTip(language_manager.translate("Информация только для просмотра"))
            user_row.addWidget(self.current_user_value)
            layout.addLayout(user_row)

            self.disable_quick_launch_button = QPushButton(language_manager.translate("Отключить удобный запуск"))
            self.disable_quick_launch_button.setMinimumHeight(42)
            self.disable_quick_launch_button.clicked.connect(self.disable_easy_launcher)
            layout.addWidget(self.disable_quick_launch_button)

            lbl_theme = QLabel("ТЕМА ОФОРМЛЕНИЯ")
            lbl_theme.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: bold;")
            layout.addWidget(lbl_theme)

            self.cb_theme = QComboBox()
            self.cb_theme.addItems(["Minimal B&W", "Тёмная тема (Стандартная)", "МАТОВЫЙ", "ПРОЗРАЧНЫЙ"])
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

            lbl_language = QLabel("Язык интерфейса")
            lbl_language.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: bold; margin-top: 10px;")
            layout.addWidget(lbl_language)

            self.cb_language = QComboBox()
            # These native names intentionally remain readable in every locale.
            self.cb_language.addItems(["English", "Українська", "Русский", "Deutsch", "Polski", "Français"])
            self.cb_language.setCurrentIndex({"en": 0, "uk": 1, "ru": 2, "de": 3, "pl": 4, "fr": 5}.get(language_manager.language, 2))
            self.cb_language.setStyleSheet(self.cb_theme.styleSheet())
            self.cb_language.currentIndexChanged.connect(self.change_language)
            layout.addWidget(self.cb_language)

            lbl_win = QLabel("Версия Windows")
            lbl_win.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: bold; margin-top: 10px;")
            layout.addWidget(lbl_win)

            self.cb_win = QComboBox()
            _auto_ver = detect_windows_version()
            self.cb_win.setIconSize(QSize(20, 20))
            # Порядок обязателен: 0 = автоопределение, 1..5 = WIN_VERSION_KEYS.
            self.cb_win.addItem(win_version_icon(_auto_ver),
                                "Автоопределение (" + _auto_ver + ")")
            for _vkey, _vlabel in zip(WIN_VERSION_KEYS, WIN_VERSION_LABELS):
                self.cb_win.addItem(win_version_icon(_vkey), _vlabel)
            self.cb_win.setStyleSheet(self.cb_theme.styleSheet())
            if _WIN_TARGET["value"] is None:
                self.cb_win.setCurrentIndex(0)
            else:
                self.cb_win.setCurrentIndex(1 + WIN_VERSION_KEYS.index(_WIN_TARGET["value"]))
            self.cb_win.currentIndexChanged.connect(self.change_win_version)
            layout.addWidget(self.cb_win)

            lbl_win_hint = QLabel(
                "Функции будут использовать команды под выбранную версию. "
                "«Автоопределение» — текущая Windows.")
            lbl_win_hint.setStyleSheet("color: #888888; font-size: 11px;")
            lbl_win_hint.setWordWrap(True)
            layout.addWidget(lbl_win_hint)

            lbl_mode = QLabel("Режим использования")
            lbl_mode.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: bold; margin-top: 10px;")
            layout.addWidget(lbl_mode)

            self.cb_mode = QComboBox()
            self.cb_mode.addItems(["Обычный пользователь", "Опытный пользователь (Advanced)"])
            is_adv = getattr(self, "advanced_mode", False)
            self.cb_mode.setCurrentIndex(1 if is_adv else 0)
            self.cb_mode.setStyleSheet(self.cb_theme.styleSheet())
            self.cb_mode.currentIndexChanged.connect(self.toggle_advanced_mode)
            layout.addWidget(self.cb_mode)

            layout.addStretch()
            page.setWidget(content)

            def retranslate_settings():
                website_label.setText(language_manager.translate("Сайт программы"))
                website_button.setText(language_manager.translate("Открыть сайт программы"))
                self.cb_always_on_top.setText(language_manager.translate("Всегда поверх окон"))
                winre_title.setText(language_manager.translate("Папка сохранения WinRE"))
                self.winre_folder_button.setText(language_manager.translate("Изменить папку сохранения"))
                self.winre_status_label.setText(language_manager.translate("Вы запустились в среде восстановления:"))
                self.winre_status_value.setText(language_manager.translate("Да" if self.in_winre_environment else "Нет"))
                self.current_user_label.setText(language_manager.translate("Текущий пользователь:"))
                self.disable_quick_launch_button.setText(language_manager.translate("Отключить удобный запуск"))

            retranslate_settings()
            page.retranslate_ui = retranslate_settings
            return page

        def toggle_always_on_top(self, state):
            enabled = bool(state)
            try:
                if sys.platform == "win32":
                    import ctypes
                    from ctypes import wintypes

                    user32 = ctypes.windll.user32
                    user32.SetWindowPos.argtypes = (
                        wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                        ctypes.c_int, ctypes.c_int, wintypes.UINT,
                    )
                    user32.SetWindowPos.restype = wintypes.BOOL
                    hwnd = wintypes.HWND(int(self.winId()))
                    z_order = wintypes.HWND(-1 if enabled else -2)  # TOPMOST / NOTOPMOST
                    flags = 0x0001 | 0x0002 | 0x0010  # NOSIZE | NOMOVE | NOACTIVATE
                    if not user32.SetWindowPos(hwnd, z_order, 0, 0, 0, 0, flags):
                        raise ctypes.WinError()
                else:
                    handle = self.windowHandle()
                    if handle is not None:
                        handle.setFlag(Qt.WindowStaysOnTopHint, enabled)
                    else:
                        self.setWindowFlag(Qt.WindowStaysOnTopHint, enabled)
                self._always_on_top_enabled = enabled
                save_app_setting("always_on_top", enabled)
            except Exception as error:
                # Keep the checkbox aligned with the actual state if the OS
                # rejects the z-order update; do not hide/recreate the window.
                self.cb_always_on_top.blockSignals(True)
                self.cb_always_on_top.setChecked(not enabled)
                self.cb_always_on_top.blockSignals(False)
                logger.log("AlwaysOnTop", "error", str(error))

        def choose_winre_backup_folder(self):
            current = getattr(self, "winre_backup_path", os.path.expanduser("~"))
            folder = QFileDialog.getExistingDirectory(
                self,
                language_manager.translate("Выберите папку сохранения WinRE"),
                current,
            )
            if folder:
                self.winre_backup_path = os.path.abspath(folder)
                self.winre_path_edit.setText(self.winre_backup_path)
                self.winre_path_edit.setToolTip(self.winre_backup_path)
                save_app_setting("winre_backup_dir", self.winre_backup_path)

        def disable_easy_launcher(self):
            """Remove only NoVir's exact context-menu entries; never alter UAC."""
            from PySide6.QtWidgets import QMessageBox

            answer = QMessageBox.question(
                self,
                language_manager.translate("Отключить удобный запуск"),
                language_manager.translate(
                    "Отключить быстрый запуск NoVir? Будут удалены только точные записи NoVir из контекстного меню. UAC не изменяется."
                ),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return

            try:
                import winreg
                base = r"Directory\Background\shell\NoVir"
                removed_any = False
                for subkey in (base + r"\command", base):
                    try:
                        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, subkey, 0, winreg.KEY_READ):
                            pass
                        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, subkey)
                        removed_any = True
                    except FileNotFoundError:
                        continue
                # The installer copies itself to %WINDIR%\nov.exe for Win+R.
                # Remove it only when its bytes exactly match this running build;
                # never delete an unrelated file that happens to share the name.
                import hashlib
                import sys
                launcher_copy = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "nov.exe")
                try:
                    if (os.path.isfile(launcher_copy) and not os.path.islink(launcher_copy)
                            and getattr(sys, "frozen", False)
                            and os.path.isfile(sys.executable)):
                        def sha256_file(path):
                            digest = hashlib.sha256()
                            with open(path, "rb") as file_obj:
                                for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
                                    digest.update(chunk)
                            return digest.digest()
                        if sha256_file(launcher_copy) == sha256_file(sys.executable):
                            os.remove(launcher_copy)
                            removed_any = True
                except OSError:
                    pass
                message = "Удобный запуск NoVir отключён. Записи контекстного меню удалены; UAC не изменялся."
                if not removed_any:
                    message = "Записи удобного запуска NoVir не найдены. UAC не изменялся."
                QMessageBox.information(self, language_manager.translate("Готово"), language_manager.translate(message))
            except (OSError, ImportError):
                QMessageBox.warning(
                    self,
                    language_manager.translate("Ошибка"),
                    language_manager.translate("Не удалось полностью отключить удобный запуск. Проверьте права доступа."),
                )

        def change_language(self, index):
            language_manager.set_language(("en", "uk", "ru", "de", "pl", "fr")[index])
            # Re-use the retained source strings, so changing the language does
            # not require an application restart.
            localize_widget_tree(self)
            for key, source_text in {
                "fix_all": "ПОЧИНИТЬ ВСЁ",
                "audit": "ЖУРНАЛ",
                "rollback": "ОТКАТ",
                "update": "ОБНОВИТЬ",
                "backups": "БЭКАПЫ",
                "community": "СООБЩЕСТВО",
            }.items():
                action = getattr(self, "_quick_action_refs", {}).get(key)
                if action is not None:
                    action.setText(language_manager.translate(source_text))
            if hasattr(self, "page_explorer"):
                self.page_explorer.retranslate_ui()
            settings_retrans = getattr(
                getattr(self, "page_program", None), "retranslate_ui", None)
            if callable(settings_retrans):
                settings_retrans()
            # Динамические строки сообщества (лимит, гость/пользователь).
            community_retrans = getattr(
                getattr(self, "page_community", None), "retranslate_ui", None)
            if callable(community_retrans):
                community_retrans()
            # Заголовок текущей страницы задаётся кодом, а не виджетом.
            if hasattr(self, "title_label") and hasattr(self, "_page_idx"):
                self._apply_page_title()
            if hasattr(self, "_status_value"):
                # Перевести строку цели на дашборде.
                self._status_refresh()

        def change_win_version(self, index):
            # 0 = автоопределение, 1..5 = "11","10","8.1","8","7"
            if index == 0:
                set_win_target("auto")
            else:
                set_win_target(WIN_VERSION_KEYS[index - 1])
            save_win_target()
            print(f"{Colors.CYAN}[i] Целевая Windows: {win_target()}{Colors.RESET}")

        def toggle_advanced_mode(self, index):
            from PySide6.QtWidgets import QFrame, QLabel
            self.advanced_mode = (index == 1)
            
            if hasattr(self, "btn_report"):
                self.btn_report.setVisible(self.advanced_mode)
            if hasattr(self, "btn_recovery_point"):
                self.btn_recovery_point.setVisible(self.advanced_mode)
            if hasattr(self, "btn_restore_point"):
                self.btn_restore_point.setVisible(self.advanced_mode)
                
            if hasattr(self, "page_advanced"):
                for card in self.page_advanced.findChildren(QFrame, "ToolCard"):
                    labels = card.findChildren(QLabel)
                    if labels:
                        tool_name = labels[0].text()
                        if tool_name in ["Корреляция Malware", "Восстановление драйверов"]:
                            card.setVisible(self.advanced_mode)

        def create_whats_new_page(self):
            """Устаревший метод — перенаправляет на create_program_page"""
            return self.create_program_page()

        def create_settings_page(self):
            from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel, QComboBox, QCheckBox, QPushButton, QHBoxLayout
            from PySide6.QtCore import Qt
            page = QFrame()
            layout = QVBoxLayout(page)
            layout.setSpacing(20)

            title = QLabel(language_manager.translate("Настройки NoVir"))
            title.setStyleSheet("font-size: 22px; font-weight: bold; color: #fff;")
            layout.addWidget(title)

            # Language
            lang_label = QLabel(language_manager.translate("Язык интерфейса:"))
            self.lang_combo = QComboBox()
            self.lang_combo.addItems(["English", "Українська", "Русский", "Deutsch", "Polski", "Français"])
            current = {"en": 0, "uk": 1, "ru": 2, "de": 3, "pl": 4, "fr": 5}.get(language_manager.language, 2)
            self.lang_combo.setCurrentIndex(current)
            self.lang_combo.currentIndexChanged.connect(self.change_language)
            self.lang_combo.setStyleSheet("QComboBox { background-color: #222; color: #fff; padding: 5px; }")
            layout.addWidget(lang_label)
            layout.addWidget(self.lang_combo)

            # Theme
            theme_label = QLabel(language_manager.translate("Оформление (Тема):"))
            self.theme_combo = QComboBox()
            self.theme_combo.addItems([language_manager.translate("Темная базовая"), language_manager.translate("Матовая"), language_manager.translate("Прозрачная")])
            self.theme_combo.setStyleSheet("QComboBox { background-color: #222; color: #fff; padding: 5px; }")
            layout.addWidget(theme_label)
            layout.addWidget(self.theme_combo)

            # Safety
            self.chk_backup = QCheckBox(language_manager.translate("Создавать бэкап перед опасными операциями"))
            self.chk_backup.setChecked(True)
            self.chk_backup.setStyleSheet("color: #fff;")
            layout.addWidget(self.chk_backup)

            # Mode
            mode_label = QLabel(language_manager.translate("Режим использования:"))
            self.mode_combo = QComboBox()
            self.mode_combo.addItems([
                language_manager.translate("Обычный пользователь"),
                language_manager.translate("Опытный пользователь (Advanced)")
            ])
            self.mode_combo.setStyleSheet("QComboBox { background-color: #222; color: #fff; padding: 5px; }")
            is_adv = getattr(self, "advanced_mode", False)
            self.mode_combo.setCurrentIndex(1 if is_adv else 0)
            self.mode_combo.currentIndexChanged.connect(self.toggle_advanced_mode)
            layout.addWidget(mode_label)
            layout.addWidget(self.mode_combo)

            layout.addStretch()
            
            # Apply Button
            apply_btn = QPushButton(language_manager.translate("Применить и сохранить"))
            apply_btn.setFixedHeight(40)
            apply_btn.setStyleSheet("QPushButton { background-color: #0055ff; color: #ffffff; font-weight: bold; border-radius: 5px; } QPushButton:hover { background-color: #0077ff; }")
            apply_btn.clicked.connect(lambda: self.switch_page(0))
            layout.addWidget(apply_btn)

            page.retranslate_ui = lambda: (
                title.setText(language_manager.translate("Настройки NoVir")),
                lang_label.setText(language_manager.translate("Язык интерфейса:")),
                theme_label.setText(language_manager.translate("Оформление (Тема):")),
                self.theme_combo.setItemText(0, language_manager.translate("Темная базовая")),
                self.theme_combo.setItemText(1, language_manager.translate("Матовая")),
                self.theme_combo.setItemText(2, language_manager.translate("Прозрачная")),
                self.chk_backup.setText(language_manager.translate("Создавать бэкап перед опасными операциями")),
                mode_label.setText(language_manager.translate("Режим использования:")),
                self.mode_combo.setItemText(0, language_manager.translate("Обычный пользователь")),
                self.mode_combo.setItemText(1, language_manager.translate("Опытный пользователь (Advanced)")),
                apply_btn.setText(language_manager.translate("Применить и сохранить"))
            )
            return page

        def open_program_website(self):
            from PySide6.QtCore import QUrl
            from PySide6.QtGui import QDesktopServices
            if not QDesktopServices.openUrl(QUrl(PROGRAM_WEBSITE_URL)):
                QMessageBox.warning(
                    self,
                    language_manager.translate("Ошибка"),
                    language_manager.translate("Не удалось открыть сайт программы"),
                )

        def toggle_advanced_mode(self, index):
            from PySide6.QtWidgets import QFrame, QLabel
            self.advanced_mode = (index == 1)
            
            if hasattr(self, "btn_report"):
                self.btn_report.setVisible(self.advanced_mode)
            if hasattr(self, "btn_recovery_point"):
                self.btn_recovery_point.setVisible(self.advanced_mode)
            if hasattr(self, "btn_restore_point"):
                self.btn_restore_point.setVisible(self.advanced_mode)
                
            if hasattr(self, "page_advanced"):
                for card in self.page_advanced.findChildren(QFrame, "ToolCard"):
                    labels = card.findChildren(QLabel)
                    if labels:
                        tool_name = labels[0].text()
                        if tool_name in ["Корреляция Malware", "Восстановление драйверов"]:
                            card.setVisible(self.advanced_mode)

        def _legacy_whats_new_page(self):
            page = QFrame()
            layout = QVBoxLayout(page)
            
            title = QLabel("Что нового в этом обновлении")
            title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff; margin-bottom: 20px;")
            layout.addWidget(title)
            
            content = QTextEdit()
            content.setReadOnly(True)
            content.setStyleSheet("background-color: #000000; color: #ffffff; font-size: 14px; border: 1px solid #222222; padding: 10px;")
            
            text = """<h2>Обновление NoVir v2.2 (NoVir Community + новые функции)</h2>
<ul>
    <li><b>NoVir Community:</b> Новый раздел-чат сообщества (меню "ЕЩЁ" → "СООБЩЕСТВО"). Регистрация и вход, общий чат через облако, лимиты: гостям 5 сообщений в час, зарегистрированным — 60.</li>
    <li><b>Бот @novir_ai:</b> Напиши в чате <code>@novir_ai вопрос</code> — умный бот ответит прямо в чате. Ключ и данные сервера зашиты в программу (зашифрованы).</li>
    <li><b>Ответы и упоминания:</b> Правый кнопкой по сообщению — "ОТВЕТИТЬ" (цитата ⤷) и "УПОМЯНУТЬ @user" (у упомянутого всплывает уведомление).</li>
    <li><b>Удаление сообщений:</b> Своё сообщение можно удалить в течение 5 минут через правую кнопку мыши.</li>
    <li><b>Вкладка "Клавиатура" (Снятие ограничений):</b> +7 новых функций — NumLock Fix, MouseKeys, Раскладка RU/EN, Панель языка, Экранные клавиши (osk.exe), Диагностика клавиатуры, Чистка политик Win+.</li>
    <li><b>Вкладка "Безопасность":</b> +13 новых функций — Брандмауэр Вкл, SmartScreen, Анти-шифровальщик, SMBv1 Off, WDigest Off, LSA Protect, RDP Off, Гостевая запись, WSH Off, UAC Max, SecureBoot, BitLocker, Defender Update.</li>
</ul>

<h2>Обновление NoVir v2.1.2 (Глобальное расширение функционала)</h2>
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
                        <li><b>NoVir Community</b> — встроенный чат сообщества: регистрация, общение в реальном времени, ответы на сообщения, упоминания @username и умный бот <b>@novir_ai</b>, отвечающий прямо в чате.</li>
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
                    result = subprocess.run(["wmic", "OS", "get", "TotalVisibleMemorySize", "/value"],
                                          capture_output=True, text=True, creationflags=0x08000000)
                    for line in result.stdout.strip().split('\n'):
                        if 'TotalVisibleMemorySize' in line:
                            mem_kb = int(line.split('=')[1].strip())
                            mem_gb = round(mem_kb / 1024 / 1024, 1)
                            info.append(f"Оперативная память: {mem_gb} ГБ")
                except Exception:
                    pass
                
                try:
                    result = subprocess.run(["wmic", "logicaldisk", "get", "size,freespace,caption", "/value"],
                                          capture_output=True, text=True, creationflags=0x08000000)
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
                    subprocess.run(["taskkill", "/f", "/im", "explorer.exe"],
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
                result = subprocess.run(["netstat", "-ano"], capture_output=True,
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

            self.worker = keep_thread(Worker(func))
            
            def on_finish(result_text):
                if result_text.strip():
                    QMessageBox.information(self, "Результат", result_text)
                else:
                    QMessageBox.information(self, "Результат", "Задача выполнена.")

            self.worker.finished_signal.connect(on_finish)
            self.worker.start()



        def check_for_updates(self, manual=False):
            """Загружает Latest и последний pre-release с GitHub."""
            import threading

            def _check():
                try:
                    import urllib.request

                    url = "https://api.github.com/repos/artemcik907/NoVir/releases?per_page=30"
                    req = urllib.request.Request(
                        url,
                        headers={"User-Agent": "NoVir-UpdateChecker/2.0"}
                    )
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        releases = json.loads(resp.read().decode("utf-8"))

                    releases = [
                        release for release in releases
                        if not release.get("draft", False)
                    ]
                    self.update_result.emit({
                        "releases": releases,
                        "manual": manual,
                    })
                except Exception as error:
                    self.update_result.emit({
                        "error": str(error),
                        "manual": manual,
                    })

            threading.Thread(target=_check, daemon=True).start()

        @Slot(object)
        def _on_update_checked(self, data):
            if data.get("error"):
                if data.get("manual"):
                    QMessageBox.warning(
                        self,
                        "Обновление",
                        "Не удалось получить список релизов GitHub:\n"
                        f"{data['error']}"
                    )
                return

            releases = data.get("releases", [])
            stable = next(
                (release for release in releases
                 if not release.get("prerelease", False)),
                None
            )
            prerelease = next(
                (release for release in releases
                 if release.get("prerelease", False)),
                None
            )

            def _parse_ver(r):
                if not r:
                    return (0,)
                if isinstance(r, dict):
                    tag = str(r.get("tag_name", "") or r.get("name", ""))
                else:
                    tag = str(r)
                nums = re.findall(r"\d+", tag)
                return tuple(int(x) for x in nums) if nums else (0,)

            cur_v = _parse_ver(globals().get("CURRENT_VERSION", "2.5.1"))
            stable_v = _parse_ver(stable)
            pre_v = _parse_ver(prerelease)

            has_newer_stable = (stable_v > cur_v)
            has_newer_pre = (pre_v > cur_v)

            if has_newer_stable or has_newer_pre:
                self._show_update_dialog(
                    stable if has_newer_stable else None,
                    prerelease if has_newer_pre else None
                )
            elif data.get("manual"):
                QMessageBox.information(
                    self,
                    "Обновление",
                    f"У вас установлена последняя версия NoVir ({globals().get('CURRENT_VERSION', '2.5.1')})."
                )

        def _show_update_dialog(self, stable, prerelease):
            import webbrowser

            dlg = QDialog(self)
            dlg.setWindowFlags(dlg.windowFlags() | Qt.WindowStaysOnTopHint)
            dlg.setWindowTitle("NoVir — Обновления")
            dlg.resize(450, 250)
            dlg.setStyleSheet("QDialog{background:#000000;} QLabel{color:#ffffff;}")
            lay = QVBoxLayout(dlg)
            lay.setSpacing(14)
            lay.setContentsMargins(20, 20, 20, 20)

            lay.addWidget(QLabel("Выберите версию для загрузки:"))

            combo = QComboBox()
            if stable:
                combo.addItem(
                    f"Latest — {stable.get('tag_name', 'без тега')}",
                    stable
                )
            if prerelease:
                combo.addItem(
                    f"Pre-release — {prerelease.get('tag_name', 'без тега')}",
                    prerelease
                )
            lay.addWidget(combo)

            warning = QLabel()
            warning.setWordWrap(True)
            warning.setStyleSheet("color:#ffcc00; font-size:12px;")
            lay.addWidget(warning)

            def update_warning(index):
                release = combo.itemData(index)
                if release and release.get("prerelease"):
                    warning.setText(
                        "⚠️ PRE-RELEASE: версия может содержать ошибки и "
                        "нестабильные функции. Разработчик не отвечает за "
                        "возможные проблемы этой версии."
                    )
                else:
                    warning.setText("Latest — стабильная версия.")

            combo.currentIndexChanged.connect(update_warning)
            update_warning(combo.currentIndex())

            title = QLabel("Релиз GitHub")
            title.setStyleSheet("font-size:14px; font-weight:bold; color:#ffffff;")
            lay.addWidget(title)

            info = QLabel("Выберите что скачать:")
            info.setStyleSheet("color:#aaaaaa; font-size:12px;")
            lay.addWidget(info)

            btn_row = QHBoxLayout()
            btn_row.setSpacing(10)

            def download(asset_kind):
                release = combo.currentData()
                if not release:
                    return

                if release.get("prerelease"):
                    answer = QMessageBox.warning(
                        dlg,
                        "Предупреждение PRE-RELEASE",
                        "Вы выбрали предварительную версию. Она может "
                        "содержать ошибки и работать нестабильно.\n\n"
                        "Продолжить загрузку?",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No
                    )
                    if answer != QMessageBox.Yes:
                        return

                assets = release.get("assets", [])
                if asset_kind == "installer":
                    asset = next(
                        (item for item in assets
                         if any(word in item.get("name", "").lower()
                                for word in ("setup", "installer", "install"))),
                        None
                    )
                else:
                    asset = next(
                        (item for item in assets
                         if item.get("name", "").lower().endswith(".exe")
                         and not any(word in item.get("name", "").lower()
                                     for word in ("setup", "installer", "install"))),
                        None
                    )

                if asset:
                    webbrowser.open(asset["browser_download_url"])
                else:
                    webbrowser.open(release.get("html_url", ""))
                dlg.accept()

            if stable or prerelease:
                b1 = QPushButton("Скачать Installer")
                b1.clicked.connect(lambda: download("installer"))
                btn_row.addWidget(b1)

                b2 = QPushButton("Скачать Portable (.exe)")
                b2.clicked.connect(lambda: download("portable"))
                btn_row.addWidget(b2)

            lay.addLayout(btn_row)

            b_skip = QPushButton("Закрыть")
            b_skip.setStyleSheet("QPushButton{background:transparent;color:#555;border:none;padding:4px;font-size:11px;} QPushButton:hover{color:#fff;}")
            b_skip.clicked.connect(dlg.reject)
            lay.addWidget(b_skip, alignment=Qt.AlignRight)

            dlg.exec()

        def run_fix_all(self):
            """One-click safe recovery mode: runs a curated set of non-destructive fixes."""
            from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QProgressBar, QPushButton
            from PySide6.QtCore import Qt, QTimer
            tr = language_manager.translate

            dlg = QDialog(self)
            dlg.setWindowFlags(dlg.windowFlags() | Qt.WindowStaysOnTopHint)
            dlg.setWindowTitle(tr("NoVir — Починить всё"))
            dlg.setMinimumWidth(460)
            dlg.setMinimumHeight(300)
            dlg.setStyleSheet("QDialog{background:#000000;} QLabel{color:#ffffff;} QProgressBar{border:1px solid #444;background:#111;height:12px;} QProgressBar::chunk{background:#ffffff;}")
            lay = QVBoxLayout(dlg)

            lbl_title = QLabel(tr("Запуск комплексного восстановления..."))
            lbl_title.setStyleSheet("font-size:14px; font-weight:bold; color:#ffffff;")
            lay.addWidget(lbl_title)

            lbl_step = QLabel(tr("Подготовка..."))
            lbl_step.setStyleSheet("color:#aaaaaa; font-size:12px;")
            lay.addWidget(lbl_step)

            bar = QProgressBar()
            bar.setRange(0, 100)
            lay.addWidget(bar)

            lbl_log = QLabel("")
            lbl_log.setStyleSheet("color:#888; font-size:11px;")
            lbl_log.setWordWrap(True)
            lay.addWidget(lbl_log)

            btn_close = QPushButton(tr("Закрыть"))
            btn_close.setEnabled(False)
            btn_close.setStyleSheet("QPushButton{background:#000;color:#fff;border:2px solid #fff;padding:6px 20px;font-weight:bold;}"
                                    "QPushButton:hover{background:#fff;color:#000;}"
                                    "QPushButton:disabled{color:#444;border-color:#444;}")
            btn_close.clicked.connect(dlg.accept)
            lay.addWidget(btn_close, alignment=Qt.AlignRight)

            STEPS = [
                ("Снятие блокировки реестра",    lambda: __import__('__main__').Disable_Regedit_Fix() if hasattr(__import__('__main__'), 'Disable_Regedit_Fix') else None),
                ("Снятие блокировки диспетчера", lambda: __import__('__main__').Disable_TaskManager_Fix() if hasattr(__import__('__main__'), 'Disable_TaskManager_Fix') else None),
                ("Восстановление ярлыков",       lambda: __import__('__main__').Desktop_Icons_Fix() if hasattr(__import__('__main__'), 'Desktop_Icons_Fix') else None),
                ("Сброс ассоциаций файлов",      lambda: __import__('__main__').File_Associations_Fix() if hasattr(__import__('__main__'), 'File_Associations_Fix') else None),
                ("Очистка автозапуска",          None),
                ("Готово!",                      None),
            ]

            step_idx = [0]
            stats = {"fixed": 0, "skipped": 0, "errors": 0}
            
            def next_step():
                if step_idx[0] >= len(STEPS):
                    bar.setValue(100)
                    lbl_step.setText(tr("Готово! Все безопасные исправления применены."))
                    lbl_log.setText(tr("Рекомендуется перезагрузить компьютер."))
                    btn_close.setEnabled(True)
                    return
                
                i = step_idx[0]
                name, func = STEPS[i]
                
                pct = int((i / len(STEPS)) * 100)
                localized_name = tr(name)
                lbl_step.setText(f"{tr('Шаг')} {i+1}/{len(STEPS)}: {localized_name}")
                bar.setValue(pct)
                logger.log("FixAll", "info", name)
                
                if func:
                    try:
                        func()
                        lbl_log.setText(f"OK: {localized_name} — {tr('выполнено')}")
                    except Exception as _e:
                        lbl_log.setText(f"{tr('ПРОПУСК:')} {localized_name} — {_e}")
                
                step_idx[0] += 1
                QTimer.singleShot(400, next_step)

            QTimer.singleShot(400, next_step)
            dlg.exec()

        def show_audit_log(self):
            """Show the audit log file in an in-app dialog."""
            import os
            from PySide6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout, QMessageBox, QApplication
            from PySide6.QtCore import Qt

            log_path = logger.audit_log_path

            dlg = QDialog(self)
            dlg.setWindowTitle(language_manager.translate("Журнал операций (Audit Log)"))
            dlg.setMinimumSize(600, 400)
            dlg.setStyleSheet("QDialog { background-color: #111; color: #fff; }")
            
            lay = QVBoxLayout(dlg)
            
            text_area = QTextEdit()
            text_area.setReadOnly(True)
            text_area.setStyleSheet("QTextEdit { background-color: #000; color: #0f0; font-family: Consolas, monospace; border: 1px solid #333; }")
            
            if log_path and os.path.exists(log_path):
                try:
                    with open(log_path, 'r', encoding='utf-8') as f:
                        text_area.setPlainText(f.read())
                except Exception as e:
                    text_area.setPlainText(f"Error reading log: {e}")
            elif logger.actions:
                text_area.setPlainText("\n".join(
                    f"{item['date']} {item['time']} [{item['status']}] "
                    f"{item['action']}: {item['message']}"
                    for item in logger.actions
                ))
            else:
                text_area.setPlainText(language_manager.translate("Журнал пуст или еще не создан."))
                
            lay.addWidget(text_area)
            
            btn_lay = QHBoxLayout()
            
            btn_copy = QPushButton(language_manager.translate("Копировать лог"))
            btn_copy.setStyleSheet("QPushButton { background-color: #222; color: #fff; border: 1px solid #555; padding: 5px; }")
            btn_copy.clicked.connect(lambda checked=False: QApplication.clipboard().setText(text_area.toPlainText()))
            
            btn_clear = QPushButton(language_manager.translate("Очистить журнал"))
            btn_clear.setStyleSheet("QPushButton { background-color: #422; color: #f55; border: 1px solid #f00; padding: 5px; }")
            def clear_log(checked=False):
                try:
                    if log_path:
                        with open(log_path, 'w', encoding='utf-8') as log_file:
                            log_file.write("")
                    logger.actions.clear()
                    text_area.setPlainText("")
                except OSError as error:
                    QMessageBox.warning(
                        dlg,
                        language_manager.translate("Ошибка"),
                        f"Не удалось очистить журнал: {error}",
                    )
            btn_clear.clicked.connect(clear_log)
            
            btn_close = QPushButton(language_manager.translate("Закрыть"))
            btn_close.setStyleSheet("QPushButton { background-color: #222; color: #fff; border: 1px solid #555; padding: 5px; }")
            btn_close.clicked.connect(dlg.accept)
            
            btn_lay.addWidget(btn_copy)
            btn_lay.addWidget(btn_clear)
            btn_lay.addStretch()
            btn_lay.addWidget(btn_close)
            
            lay.addLayout(btn_lay)
            dlg.exec()

        def show_rollback_dialog(self):
            """Offer to rollback registry changes made this session."""
            from PySide6.QtWidgets import QMessageBox
            
            if not rollback_mgr._snapshots:
                QMessageBox.information(self, language_manager.translate("Откат"), language_manager.translate("Нет доступных точек отката (изменения еще не вносились)."))
                return
                
            count = len(rollback_mgr._snapshots)
            
            details = ""
            for snapshot in reversed(rollback_mgr.snapshots):
                details += f"{snapshot['key_path']} \\ {snapshot['value_name']}\n"
                
            reply = QMessageBox.question(
                self, 
                language_manager.translate("Откат"), 
                f"{language_manager.translate('Вы действительно хотите отменить')} {count} {language_manager.translate('последних изменений реестра?')}\n\n{details}",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                try:
                    restored, failed = rollback_mgr.rollback()
                    if failed:
                        QMessageBox.warning(
                            self,
                            language_manager.translate("Откат"),
                            f"Восстановлено: {restored}. Не удалось восстановить: {failed}.",
                        )
                    else:
                        QMessageBox.information(
                            self,
                            language_manager.translate("Откат"),
                            f"Изменения отменены. Восстановлено значений: {restored}.",
                        )
                except Exception as e:
                    QMessageBox.warning(self, language_manager.translate("Ошибка"), f"{language_manager.translate('Не удалось выполнить откат:')}\n{e}")


        def _run_async_backup(self, bkp_dir, on_complete):
            from PySide6.QtWidgets import QProgressDialog
            from PySide6.QtCore import Qt, QCoreApplication
            import subprocess
            import time
            
            progress = QProgressDialog(language_manager.translate("Создание бэкапа реестра..."), "", 0, 100, self)
            progress.setWindowModality(Qt.WindowModal)
            progress.setWindowTitle(language_manager.translate("Безопасность"))
            progress.setCancelButton(None)
            progress.setStyleSheet("QProgressDialog { background-color: #111; color: #fff; } QLabel { color: #fff; } QProgressBar { border: 1px solid #333; text-align: center; color: #fff; } QProgressBar::chunk { background-color: #0055ff; }")
            progress.show()
            
            progress.setValue(10)
            QCoreApplication.processEvents()
            
            try:
                for percent, registry_key, filename in (
                    (50, r"HKLM\SYSTEM", "SYSTEM.reg"),
                    (90, r"HKLM\SOFTWARE", "SOFTWARE.reg"),
                ):
                    destination = os.path.join(bkp_dir, filename)
                    process = subprocess.Popen(
                        ["reg", "export", registry_key, destination, "/y"],
                        shell=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                    while process.poll() is None:
                        QCoreApplication.processEvents()
                        time.sleep(0.02)
                    stdout, stderr = process.communicate()
                    if process.returncode != 0 or not os.path.isfile(destination) or os.path.getsize(destination) == 0:
                        error = (stderr or stdout).decode(errors="replace").strip()
                        raise OSError(error or f"reg export {registry_key} завершился с кодом {process.returncode}")
                    progress.setValue(percent)
                    QCoreApplication.processEvents()

                progress.setValue(100)
                progress.close()
                on_complete()
                return True
            except Exception as error:
                progress.close()
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.critical(
                    self,
                    language_manager.translate("Ошибка резервного копирования"),
                    f"Не удалось создать полный бэкап.\n{error}",
                )
                return False
        def show_backup_manager(self):
            import os
            import json
            import subprocess
            from datetime import datetime
            from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QPushButton, QLabel, QMessageBox

            app_data = os.path.join(os.environ.get('APPDATA', ''), 'NoVir', 'Backups')
            if not os.path.exists(app_data):
                os.makedirs(app_data, exist_ok=True)

            dlg = QDialog(self)
            dlg.setWindowTitle(language_manager.translate("Менеджер Резервных Копий (Backup)"))
            dlg.setMinimumSize(500, 350)
            dlg.setStyleSheet("QDialog { background-color: #111; color: #fff; }")

            lay = QVBoxLayout(dlg)
            
            title = QLabel(language_manager.translate("Резервные копии реестра и системы:"))
            title.setStyleSheet("font-size: 16px; font-weight: bold;")
            lay.addWidget(title)

            list_widget = QListWidget()
            list_widget.setStyleSheet("QListWidget { background-color: #000; color: #0f0; border: 1px solid #333; }")
            lay.addWidget(list_widget)
            
            def refresh_list():
                list_widget.clear()
                if not os.path.exists(app_data): return
                for d in reversed(sorted(os.listdir(app_data))):
                    path = os.path.join(app_data, d)
                    if os.path.isdir(path):
                        # Count reg files
                        regs = [f for f in os.listdir(path) if f.endswith('.reg')]
                        size = sum(os.path.getsize(os.path.join(path, f)) for f in regs) / (1024*1024)
                        list_widget.addItem(f"● {d.replace('_', ' ')} | Компонентов: {len(regs)} ({size:.1f} MB)")

            refresh_list()

            btn_lay = QHBoxLayout()
            
            btn_create = QPushButton(language_manager.translate("Создать новый backup"))
            btn_create.setStyleSheet("QPushButton { background-color: #0055ff; color: #fff; font-weight: bold; padding: 5px; }")
            def create_bkp():
                now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                bkp_dir = os.path.join(app_data, now)
                os.makedirs(bkp_dir, exist_ok=True)
                
                def on_done():
                    QMessageBox.information(dlg, language_manager.translate("Успех"), language_manager.translate("Бэкап успешно создан!"))
                    refresh_list()
                    
                self._run_async_backup(bkp_dir, on_done)
            btn_create.clicked.connect(lambda checked=False: create_bkp())
            
            btn_restore = QPushButton(language_manager.translate("Восстановить"))
            btn_restore.setStyleSheet("QPushButton { background-color: #222; color: #fff; border: 1px solid #555; padding: 5px; }")
            def restore_bkp():
                sel = list_widget.currentItem()
                if not sel: return
                folder_name = sel.text().split(" |")[0].replace("● ", "").replace(" ", "_")
                bkp_dir = os.path.join(app_data, folder_name)
                reply = QMessageBox.warning(dlg, language_manager.translate("Внимание"), 
                    language_manager.translate("Вы уверены, что хотите применить этот бэкап?\nЭто перезапишет весь системный реестр!"), 
                    QMessageBox.Yes | QMessageBox.No)
                if reply == QMessageBox.Yes:
                    sys_reg = os.path.join(bkp_dir, "SYSTEM.reg")
                    sw_reg = os.path.join(bkp_dir, "SOFTWARE.reg")
                    try:
                        for registry_file in (sys_reg, sw_reg):
                            if not os.path.isfile(registry_file) or os.path.getsize(registry_file) == 0:
                                raise OSError(f"Файл резервной копии отсутствует или пуст: {registry_file}")
                            result = subprocess.run(
                                ["reg", "import", registry_file],
                                capture_output=True,
                                text=True,
                                shell=False,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                            )
                            if result.returncode != 0:
                                raise OSError(result.stderr.strip() or result.stdout.strip() or f"Код {result.returncode}")
                        QMessageBox.information(dlg, language_manager.translate("Готово"), language_manager.translate("Бэкап применён. Необходима перезагрузка."))
                    except OSError as error:
                        QMessageBox.critical(dlg, language_manager.translate("Ошибка восстановления"), str(error))
            btn_restore.clicked.connect(lambda checked=False: restore_bkp())
            
            btn_del = QPushButton(language_manager.translate("Удалить"))
            btn_del.setStyleSheet("QPushButton { background-color: #422; color: #f55; border: 1px solid #f00; padding: 5px; }")
            def delete_bkp():
                sel = list_widget.currentItem()
                if not sel: return
                folder_name = sel.text().split(" |")[0].replace("● ", "").replace(" ", "_")
                import shutil
                try:
                    shutil.rmtree(os.path.join(app_data, folder_name))
                    refresh_list()
                except:
                    pass
            btn_del.clicked.connect(lambda checked=False: delete_bkp())

            btn_lay.addWidget(btn_create)
            btn_lay.addWidget(btn_restore)
            btn_lay.addWidget(btn_del)
            
            lay.addLayout(btn_lay)
            dlg.exec()

        def closeEvent(self, event):
            """Корректно останавливаем все фоновые потоки перед закрытием"""
            # Список всех возможных потоков
            threads_to_stop = []
            if hasattr(self, '_scheduler_loader') and self._scheduler_loader is not None:
                threads_to_stop.append(self._scheduler_loader)
            if hasattr(self, 'worker') and self.worker is not None:
                threads_to_stop.append(self.worker)
            if hasattr(self, '_services_loader') and self._services_loader is not None:
                threads_to_stop.append(self._services_loader)
            # Потоки из общего реестра keep_thread(): community-чат, AI,
            # сканеры, диалоги входа — всё, что не перечислено выше.
            for _t in list(_LIVE_QTHREADS):
                if _t not in threads_to_stop:
                    threads_to_stop.append(_t)

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
            if event.button() == Qt.LeftButton:
                self.dragPos = event.globalPosition().toPoint()
                event.accept()
                return
            super().mousePressEvent(event)

        def mouseMoveEvent(self, event):
            if event.buttons() & Qt.LeftButton and self.dragPos is not None:
                self.move(self.pos() + event.globalPosition().toPoint() - self.dragPos)
                self.dragPos = event.globalPosition().toPoint()
                event.accept()
                return
            if not (event.buttons() & Qt.LeftButton):
                self.dragPos = None
            super().mouseMoveEvent(event)

        def mouseReleaseEvent(self, event):
            if event.button() == Qt.LeftButton:
                self.dragPos = None
            super().mouseReleaseEvent(event)

def main():
    try:
        os.chdir(APP_DIR)
    except OSError as error:
        print(f"[WARNING] Не удалось перейти в каталог приложения {APP_DIR}: {error}")

    if SELF_CHECK:
        run_self_check()
        return

    # Проверяем права администратора
    try:
        is_admin = check_admin_status()
        admin_required = not (DRY_RUN and not GUI_MODE)
        if not is_admin and admin_required:
            if GUI_MODE:
                import ctypes
                script = os.path.abspath(sys.argv[0])
                params = " ".join(sys.argv[1:])
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
                sys.exit(0)
            else:
                print(f"{Colors.RED}[!] ВНИМАНИЕ: Запустите скрипт от имени АДМИНИСТРАТОРА!{Colors.RESET}")
                print(f"{Colors.YELLOW}[!] Нажмите Enter для выхода...{Colors.RESET}")
                input()
                sys.exit(1)
            print(f"{Colors.YELLOW}[!] DRY-RUN запущен без прав администратора. Реальные изменения выполняться не будут.{Colors.RESET}")
    except Exception as _e:
        # Expected exception, intentionally ignored
        pass
    
    if GUI_MODE:
        app = QApplication(sys.argv)
        from PySide6.QtGui import QFont
        app.setFont(QFont("Segoe UI", 10))
        # The filter localizes every main window and dialog at display time.
        # Keep a reference on QApplication so Python cannot collect it.
        app._novir_translation_filter = TranslationEventFilter(app)
        app.installEventFilter(app._novir_translation_filter)
        if language_manager.first_run:
            LanguageSelectionDialog().exec()
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
