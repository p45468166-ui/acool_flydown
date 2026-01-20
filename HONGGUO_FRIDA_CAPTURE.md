# 红果短剧：模拟器自动捕获“完整版模板” (路线B)

目标：在 PC 端模拟器里播放短剧时，自动捕获 `v*-reading-video.qznovelvod.com/...&eid=...` 这种完整版 CDN 链接，并自动填入下载器的“完整版模板”输入框。

## 使用方式（下载器内）

- 打开红果短剧下载对话框 → “完整版模板（可选）”区域
- 点击“自动捕获模板”
- 在模拟器里随便播放任意一集（进入播放页并开始播放/缓冲）
- 捕获成功后会自动停止，并把模板填入输入框

## 前置条件

这个方案属于“应用内注入”，需要模拟器/容器允许 Frida 注入到红果短剧进程。

PC 侧需要：
- Python 环境可用
- 安装依赖：`pip install frida frida-tools`

模拟器侧需要其一：
- 方式 A：能运行 `frida-server`（常见于可 root 的安卓模拟器）
- 方式 B：无法 root 时，需通过 `frida-gadget` 注入（需要重打包/重装 APK，复杂但可行）

## 方式 A：frida-server（优先推荐）

1) 确认能连到模拟器 ADB（不同模拟器入口不同）
- 能看到设备：`adb devices`

2) 如果能 root（很多安卓模拟器可以）
- `adb root`
- `adb shell id`（确认是 uid=0）

3) 推送并启动 frida-server
- 下载与模拟器 CPU 架构匹配的 frida-server（例如 x86_64 / arm64-v8a）
- 推送到设备并启动（示例命令以你的 frida-server 文件名为准）

4) 让 PC 能连接到 frida-server
- 常用端口是 27042
- 如果需要转发：`adb forward tcp:27042 tcp:27042`

5) 可选环境变量（不填也会自动尝试）
- `HONGGUO_FRIDA_DEVICE=remote:127.0.0.1:27042`
- `HONGGUO_FRIDA_PACKAGE=com.phoenix.read`

## 方式 B：frida-gadget（无 root 备选）

当你用的“腾讯应用宝-畅玩”环境不开放 ADB/root 时，通常无法直接跑 frida-server。此时可以用 frida-gadget：

- 从原 APK 注入 gadget（需要 gadget.so 与配置）
- 重新签名并在模拟器里卸载/安装

这条路和你“已经装好了红果短剧”的现状有冲突（需要替换安装包），但它是无 root 场景下最稳定的注入方式。

## 常见问题

### 1) 捕获一直没有结果
- 先确认你播放的确触发了网络加载（开始播放/拖动进度条）
- 先在日志里看是否有 “捕获运行中：请在模拟器里播放任意一集”
- 如果你的环境是“应用宝-畅玩”这种 Windows 容器式运行，可能不具备标准 ADB/Root 注入通道，此时更建议换一个可 ADB 的安卓模拟器（MuMu/雷电/夜神等）来跑 frida-server

### 2) 只捕获到了 v3-share.qznovel.com 的 30 秒试看链接
- 这是分享页的试看播放地址，不是完整版 CDN 模板
- 只有捕获到 `reading-video.qznovelvod.com` 才会自动填入模板

