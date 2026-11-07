# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_dynamic_libs
import os

import PySide6
import shiboken6

pyside_dir = os.path.dirname(PySide6.__file__)
shibo_dir = os.path.dirname(shiboken6.__file__)

# Collect all PySide6 dynamic libs
all_pyside_bins = collect_dynamic_libs('PySide6')

# Allowed plugin folders: platforms (qwindows.dll for GUI), styles, imageformats, tls
allowed_plugin_folders = ('platforms', 'styles', 'imageformats', 'tls')

skip_words = (
    'quick', 'qml', '3d', 'pdf', 'webengine', 'multimedia', 'location',
    'spatialaudio', 'bluetooth', 'designer', 'avcodec', 'avformat', 'avutil',
    'swresample', 'swscale', 'networkauth', 'nfc', 'positioning', 'remoteobjects',
    'scxml', 'sensors', 'serialbus', 'serialport', 'statemachine', 'texttospeech',
    'uitools', 'virtualkeyboard', 'webchannel', 'websockets', 'sqldrivers',
    'designhelpers', 'geometryloaders', 'assetimporters', 'canbus', 'sceneparsers',
    'renderplugins', 'qmllint', 'qmltooling', 'geoservices'
)

pyside_binaries = []
for b in all_pyside_bins:
    path_lower = b[0].lower()
    filename = b[0].split('\\')[-1].lower()
    if 'plugins' in path_lower:
        if any(f'plugins\\{folder}' in path_lower or f'plugins/{folder}' in path_lower for folder in allowed_plugin_folders):
            if not any(word in filename for word in skip_words):
                pyside_binaries.append(b)
    elif 'qml' in path_lower:
        continue
    else:
        if not any(word in filename for word in skip_words):
            pyside_binaries.append(b)

shibo_binaries = collect_dynamic_libs('shiboken6')

# Bundle critical System32 DLLs that may be absent in WinPE 2019.
# Qt6Gui.dll hard-imports: d3d11, d3d12, dxgi, dcomp, DWrite, dwmapi
# Qt6Widgets.dll hard-imports: dwmapi, UxTheme
#
# IMPORTANT: these DLLs must NOT be placed next to NoVir.exe. If the Windows
# loader finds build-machine system DLLs in the application directory, the exe
# crashes with "The specified procedure could not be found" on a different
# Windows build (and in WinPE). Keep them in a separate folder that the runtime
# hook adds to the DLL search path only when running inside WinPE.
sys32 = r'C:\Windows\System32'
winpe_critical_dlls = [
    'd3d11.dll',
    'd3d12.dll',
    'dxgi.dll',
    'dcomp.dll',
    'DWrite.dll',
    'dwmapi.dll',
    'UxTheme.dll',
    # qwindows.dll links these directly.
    'd3d9.dll',
    'UIAutomationCore.dll',
    # API-set forwarders used by qwindows.dll (last-resort fallback).
    'api-ms-win-shcore-scaling-l1-1-1.dll',
    'api-ms-win-core-winrt-l1-1-0.dll',
    'api-ms-win-core-winrt-string-l1-1-0.dll',
]
winpe_dll_dest = 'winpe_dlls'
extra_binaries = []
for dll in winpe_critical_dlls:
    src = os.path.join(sys32, dll)
    if os.path.exists(src):
        extra_binaries.append((src, winpe_dll_dest))

# WinRE/WinPE fallbacks for the Universal CRT API sets, UCRT itself and ICU.
# The EXEs built on Windows 11 25H2 cannot rely on the WinRE image having all
# of these on PATH, so we ship the host's copies in the WinPE-only folder.
sys32_downlevel = os.path.join(sys32, 'downlevel')
import glob as _winre_glob
for _spec in ('api-ms-win-crt-*.dll', 'api-ms-win-core-*.dll'):
    for _src in _winre_glob.glob(os.path.join(sys32_downlevel, _spec)):
        extra_binaries.append((_src, winpe_dll_dest))

for _dll in ('icu.dll', 'icuin.dll', 'icuuc.dll'):
    _src = os.path.join(sys32, _dll)
    if os.path.exists(_src):
        extra_binaries.append((_src, 'winpe_icu'))

for _dll in ('ucrtbase.dll', 'icu.dll', 'icuin.dll', 'icuuc.dll',
             'icudt*.dll', 'icudt67.dll', 'icudt69.dll', 'icudt70.dll'):
    # wildcard handling
    if '*' in _dll:
        for _src in _winre_glob.glob(os.path.join(sys32, _dll)):
            extra_binaries.append((_src, winpe_dll_dest))
    else:
        _src = os.path.join(sys32, _dll)
        if os.path.exists(_src):
            extra_binaries.append((_src, winpe_dll_dest))

# opengl32sw.dll — software OpenGL fallback, must be bundled for WinPE
opengl32sw = os.path.join(pyside_dir, 'opengl32sw.dll')
if os.path.exists(opengl32sw):
    extra_binaries.append((opengl32sw, '.'))

# Guarantee qwindows.dll exists in both platforms/ and PySide6/plugins/platforms/
platforms_dir = os.path.join(pyside_dir, 'plugins', 'platforms')
extra_datas = [
    ('win_icons', 'win_icons'),
    ('Иван.png', '.'),
    ('67_mylove.mp3', '.'),
    ('fatality.mp3', '.'),
]
if os.path.exists(platforms_dir):
    for f in os.listdir(platforms_dir):
        if f.endswith('.dll'):
            extra_datas.append((os.path.join(platforms_dir, f), 'platforms'))
            extra_datas.append((os.path.join(platforms_dir, f), 'PySide6/plugins/platforms'))

a = Analysis(
    ['virus_recovery.py'],
    pathex=[],
    binaries=pyside_binaries + shibo_binaries + extra_binaries,
    datas=extra_datas,
    hiddenimports=[
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'shiboken6',
        'explorer_tab',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['rthooks/pyi_rthook_winpe.py'],
    excludes=[
        'PySide6.QtSql',
        'PySide6.QtQuick',
        'PySide6.QtQml',
        'PySide6.Qt3DCore',
        'PySide6.QtMultimedia',
        'PySide6.QtWebEngineCore',
        'tkinter',
        'unittest',
    ],
    noarchive=False,
    optimize=0,
)

# Never ship foreign UCRT / API-set stubs. PyInstaller may resolve
# api-ms-win-*.dll and ucrtbase.dll from whatever is first on PATH (for
# example a JDK installation). Such stubs override the OS-provided runtime
# and cause "The specified procedure could not be found" at Qt import time.
def _keep_binary(entry):
    dest = str(entry[0]).lower().replace('/', '\\')
    src = str(entry[1]).lower().replace('/', '\\')
    name = dest.rsplit('\\', 1)[-1]
    # Bundled WinPE fallbacks must be retained even if they look like system
    # DLLs; they live in a separate folder and are not on the normal loader path.
    if name in ('icu.dll', 'icuin.dll', 'icuuc.dll'):
        return True
    if dest.startswith('winpe_dlls\\') or dest.startswith('winpe_icu\\'):
        return True
    if name.startswith('api-ms-win-'):
        return False
    if name == 'ucrtbase.dll':
        return False
    if '\\jdk' in src or '\\java\\' in src:
        return False
    return True

a.binaries = [entry for entry in a.binaries if _keep_binary(entry)]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NoVir_Clean',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['icon.ico'],
)
