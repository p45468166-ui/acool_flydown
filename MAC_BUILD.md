# Mac 打包说明（可执行文件）

由于当前开发环境是 Windows，本地无法直接产出 macOS 可执行文件。推荐用 GitHub Actions 在 macOS runner 上自动打包，并下载产物给用户使用。

## 方式一：GitHub Actions 一键打包（推荐）

1) 推送代码到 GitHub
2) 在仓库 Actions 里运行工作流：
   - `Build Tkinter App (macOS)`
3) 运行结束后，在 Artifacts 下载：
   - `hongguo_downloader_macos/hongguo_downloader_macos.zip`

## 方式二：在 Mac 本机打包

在 macOS 上执行：

```bash
python3 -m pip install -U pip wheel setuptools
python3 -m pip install -U pyinstaller requests
pyinstaller --clean --noconfirm tkinter_app.spec
```

产物在 `dist/` 目录。

## 常见问题

### 1) macOS 提示“无法打开/已损坏”
这是 Gatekeeper 的常见提示。未签名应用在某些系统版本会被拦截。可用以下方式处理：
- 右键应用 → 打开 → 再确认一次
- 或在“系统设置 → 隐私与安全性”里允许

### 2) “一键安装/更新捕获依赖”按钮在 Mac 上失败
该按钮需要系统存在可用的 `python3` 与 `pip`。如果用户 Mac 未安装 Python，请先安装 Python 3（例如从 python.org）。

