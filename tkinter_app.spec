# -*- mode: python ; coding: utf-8 -*-

import sys


a = Analysis(
    ['tkinter_app.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('images.ico', '.'),
        ('images.png', '.'),
        ('HONGGUO_FRIDA_CAPTURE.md', '.'),
        ('hongguo_frida/hongguo_hook.js', 'hongguo_frida'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

upx_enabled = sys.platform.startswith('win')
icon_file = 'images.ico' if sys.platform.startswith('win') else None

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='视频音频高速下载神器',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=upx_enabled,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_file,
)
