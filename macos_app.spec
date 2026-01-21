# -*- mode: python ; coding: utf-8 -*-
# macOS PyInstaller 配置文件
# 视频音频高速下载神器

import sys
import os
from PyInstaller.utils.hooks import collect_all

block_cipher = None

# 收集 yt_dlp 的所有依赖
yt_dlp_datas, yt_dlp_binaries, yt_dlp_hiddenimports = collect_all('yt_dlp')

# 基础分析
a = Analysis(
    ['tkinter_app_macos.py'],
    pathex=[],
    binaries=yt_dlp_binaries,
    datas=yt_dlp_datas,
    hiddenimports=[
        'yt_dlp',
        'yt_dlp.extractor',
        'yt_dlp.extractor.youtube',
        'yt_dlp.extractor.bilibili',
        'yt_dlp.extractor.tiktok',
        'yt_dlp.extractor.instagram',
        'yt_dlp.downloader',
        'yt_dlp.postprocessor',
        'requests',
        'urllib3',
        'certifi',
        'brotli',
        'websockets',
        'mutagen',
        'pycryptodomex',
    ] + yt_dlp_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='视频下载神器',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# macOS .app bundle
app = BUNDLE(
    exe,
    name='视频下载神器.app',
    icon='app_icon.icns' if os.path.exists('app_icon.icns') else None,
    bundle_identifier='com.ytdlp.videodownloader',
    info_plist={
        'CFBundleName': '视频下载神器',
        'CFBundleDisplayName': '视频下载神器',
        'CFBundleVersion': '5.1.0',
        'CFBundleShortVersionString': '5.1.0',
        'NSHighResolutionCapable': 'True',
        'NSRequiresAquaSystemAppearance': 'False',  # 支持深色模式
    },
)
