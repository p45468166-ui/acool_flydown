#!/bin/bash
# macOS 打包脚本
# 视频音频高速下载神器 - macOS 版本

set -e

echo "=========================================="
echo "  视频音频高速下载神器 - macOS 打包脚本"
echo "=========================================="

# 检查 Python
if ! command -v python3 &> /dev/null; then
    echo "错误: 未安装 Python3"
    echo "请访问 https://www.python.org/downloads/ 下载安装"
    exit 1
fi

echo "Python 版本: $(python3 --version)"

# 创建虚拟环境
echo ""
echo "[1/5] 创建虚拟环境..."
python3 -m venv venv_macos
source venv_macos/bin/activate

# 安装依赖
echo ""
echo "[2/5] 安装依赖..."
pip install --upgrade pip
pip install pyinstaller yt-dlp requests

# 检查 tkinter
echo ""
echo "[3/5] 检查 tkinter..."
python3 -c "import tkinter" 2>/dev/null || {
    echo "错误: tkinter 未安装"
    echo "macOS 上请使用 brew install python-tk 安装"
    exit 1
}

# 创建 macOS 专用的图标（如果存在 PNG）
echo ""
echo "[4/5] 准备资源..."
if [ -f "images.png" ]; then
    # macOS 需要 .icns 格式的图标
    mkdir -p AppIcon.iconset
    sips -z 16 16 images.png --out AppIcon.iconset/icon_16x16.png 2>/dev/null || true
    sips -z 32 32 images.png --out AppIcon.iconset/icon_16x16@2x.png 2>/dev/null || true
    sips -z 32 32 images.png --out AppIcon.iconset/icon_32x32.png 2>/dev/null || true
    sips -z 64 64 images.png --out AppIcon.iconset/icon_32x32@2x.png 2>/dev/null || true
    sips -z 128 128 images.png --out AppIcon.iconset/icon_128x128.png 2>/dev/null || true
    sips -z 256 256 images.png --out AppIcon.iconset/icon_128x128@2x.png 2>/dev/null || true
    sips -z 256 256 images.png --out AppIcon.iconset/icon_256x256.png 2>/dev/null || true
    sips -z 512 512 images.png --out AppIcon.iconset/icon_256x256@2x.png 2>/dev/null || true
    sips -z 512 512 images.png --out AppIcon.iconset/icon_512x512.png 2>/dev/null || true
    sips -z 1024 1024 images.png --out AppIcon.iconset/icon_512x512@2x.png 2>/dev/null || true
    iconutil -c icns AppIcon.iconset -o app_icon.icns 2>/dev/null || true
    rm -rf AppIcon.iconset
    ICON_OPT="--icon=app_icon.icns"
else
    ICON_OPT=""
fi

# 使用 PyInstaller 打包
echo ""
echo "[5/5] 开始打包..."
pyinstaller \
    --name "视频下载神器" \
    --onefile \
    --windowed \
    --noconfirm \
    --clean \
    $ICON_OPT \
    --add-data "yt_dlp:yt_dlp" \
    --hidden-import=yt_dlp \
    --hidden-import=requests \
    --hidden-import=urllib3 \
    --hidden-import=certifi \
    --hidden-import=brotli \
    --hidden-import=websockets \
    --collect-all yt_dlp \
    tkinter_app.py

# 清理
deactivate

echo ""
echo "=========================================="
echo "  打包完成!"
echo "=========================================="
echo ""
echo "应用程序位置: dist/视频下载神器.app"
echo ""
echo "使用方法:"
echo "  1. 将 dist/视频下载神器.app 拖到 Applications 文件夹"
echo "  2. 双击运行"
echo ""
echo "如果提示「无法打开，因为无法验证开发者」:"
echo "  右键点击 App -> 选择「打开」-> 确认打开"
echo ""
