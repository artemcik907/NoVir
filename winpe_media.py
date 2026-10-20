"""Safe discovery and helpers for creating official Windows PE media."""

import ctypes
import os
import shutil
import string
import sys


ADK_INSTALL_URL = "https://learn.microsoft.com/windows-hardware/get-started/adk-install"


def _candidate_winpe_roots():
    roots = []
    for program_files in (
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("ProgramFiles"),
        r"C:\Program Files (x86)",
        r"C:\Program Files",
    ):
        if program_files:
            roots.append(os.path.join(
                program_files,
                "Windows Kits", "10", "Assessment and Deployment Kit",
                "Windows Preinstallation Environment",
            ))

    # KitsRoot10 also covers ADK installations on non-default volumes.
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows Kits\Installed Roots") as key:
                kits_root, _ = winreg.QueryValueEx(key, "KitsRoot10")
            roots.append(os.path.join(
                kits_root, "Assessment and Deployment Kit",
                "Windows Preinstallation Environment",
            ))
        except (OSError, ImportError):
            pass

    seen = set()
    for root in roots:
        normalized = os.path.normcase(os.path.abspath(root))
        if normalized not in seen:
            seen.add(normalized)
            yield root


def find_adk_tools():
    """Return the installed ADK/WinPE scripts, or None if they are unavailable."""
    for winpe_root in _candidate_winpe_roots():
        deployment_root = os.path.join(os.path.dirname(winpe_root), "Deployment Tools")
        tools = {
            "copype": os.path.join(winpe_root, "copype.cmd"),
            "make_media": os.path.join(winpe_root, "MakeWinPEMedia.cmd"),
            "environment": os.path.join(deployment_root, "DandISetEnv.bat"),
        }
        if all(os.path.isfile(path) for path in tools.values()):
            return tools
    return None


def enumerate_removable_usb_drives():
    """List mounted Windows removable volumes, excluding the OS/app volumes."""
    if sys.platform != "win32":
        return []

    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetDriveTypeW.restype = wintypes.UINT
    kernel32.GetLogicalDrives.restype = wintypes.DWORD

    excluded = {
        os.path.splitdrive(os.environ.get("SystemDrive", ""))[0].upper(),
        os.path.splitdrive(sys.executable)[0].upper(),
    }
    mask = kernel32.GetLogicalDrives()
    drives = []
    for index, letter in enumerate(string.ascii_uppercase):
        if not mask & (1 << index):
            continue
        root = f"{letter}:\\"
        if f"{letter}:" in excluded or kernel32.GetDriveTypeW(root) != 2:
            continue  # DRIVE_REMOVABLE only; do not offer fixed/system disks.
        try:
            total, used, free = shutil.disk_usage(root)
        except OSError:
            continue

        label = "USB drive"
        volume_name = ctypes.create_unicode_buffer(261)
        volume_serial = wintypes.DWORD()
        volume_info_ok = False
        try:
            get_volume_info = kernel32.GetVolumeInformationW
            get_volume_info.argtypes = [
                wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                wintypes.LPDWORD, wintypes.LPDWORD, wintypes.LPDWORD,
                wintypes.LPWSTR, wintypes.DWORD,
            ]
            get_volume_info.restype = wintypes.BOOL
            volume_info_ok = bool(get_volume_info(
                root, volume_name, len(volume_name), ctypes.byref(volume_serial), None, None, None, 0
            ))
            if volume_info_ok and volume_name.value:
                label = volume_name.value
        except (AttributeError, OSError, TypeError):
            pass
        if not volume_info_ok:
            continue

        drives.append({
            "root": f"{letter}:",
            "label": label,
            "total": total,
            "free": free,
            "serial": volume_serial.value,
        })
    return drives


def make_working_directory(program_data=None):
    """Create a unique, app-owned directory for the temporary WinPE files."""
    import uuid

    root = os.path.join(program_data or os.environ.get("ProgramData", r"C:\ProgramData"), "NoVir", "WinPEWork")
    os.makedirs(root, exist_ok=True)
    working = os.path.join(root, "WinPE_" + uuid.uuid4().hex)
    os.mkdir(working)
    return root, working


def cleanup_working_directory(root, working):
    """Remove only a generated direct child of the NoVir WinPE work directory."""
    root_real = os.path.normcase(os.path.realpath(root))
    working_real = os.path.normcase(os.path.realpath(working))
    if (os.path.dirname(working_real) != root_real
            or not os.path.basename(working_real).startswith(os.path.normcase("WinPE_"))
            or os.path.islink(working)):
        raise ValueError("Refusing to remove a path outside the generated NoVir workspace")
    shutil.rmtree(working)
