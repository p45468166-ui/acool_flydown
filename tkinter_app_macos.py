#!/usr/bin/env python3
"""
视频音频高速下载神器 - macOS 兼容版
支持: YouTube, Bilibili, TikTok, Instagram, Suno, Sora等
"""

import sys
import os
import platform

# macOS 兼容性修复
IS_MACOS = platform.system() == "Darwin"

import threading
import queue
import time
import subprocess
import tkinter as tk
import requests
import zipfile
import shutil
import urllib.request
from tkinter import ttk, messagebox
from yt_dlp import YoutubeDL


def get_resource_path(relative_path):
    """获取资源文件路径，兼容打包后的环境"""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


class YTDLP_GUI:
    """视频下载神器 GUI - macOS 兼容版"""

    def __init__(self, root):
        """初始化GUI"""
        self.root = root
        self.root.title("视频下载神器")
        self.root.geometry("650x600")
        self.root.resizable(True, True)

        # macOS 字体设置
        if IS_MACOS:
            # macOS 使用系统字体
            self.root.option_add("*Font", "Helvetica 13")
            default_font = ("Helvetica", 13)
            title_font = ("Helvetica", 18, "bold")
        else:
            # Windows 字体
            self.root.option_add("*Font", "微软雅黑 10")
            default_font = ("微软雅黑", 10)
            title_font = ("微软雅黑", 16, "bold")
        
        self.default_font = default_font
        self.title_font = title_font

        # 创建消息队列
        self.queue = queue.Queue()

        # 进度节流
        self.last_progress_percent = -1
        self.last_status_message = ""
        self.update_interval = 100
        self.last_update_time = 0

        # 获取程序目录
        if getattr(sys, "frozen", False):
            if IS_MACOS:
                # macOS .app 包结构
                self.app_dir = os.path.dirname(os.path.dirname(os.path.dirname(sys.executable)))
            else:
                self.app_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        else:
            self.app_dir = os.path.dirname(os.path.abspath(__file__))

        # 设置下载目录
        if IS_MACOS:
            # macOS 默认下载到用户的 Downloads 文件夹
            self.download_dir = os.path.expanduser("~/Downloads/视频下载")
        else:
            self.download_dir = os.path.join(self.app_dir, "videos")

        os.makedirs(self.download_dir, exist_ok=True)

        # 设置图标 (macOS 不支持 .ico)
        if not IS_MACOS:
            try:
                icon_path = get_resource_path("images.ico")
                if os.path.exists(icon_path):
                    self.root.iconbitmap(default=icon_path)
            except Exception:
                pass

        # 创建主界面
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self._create_logo()
        self._create_menu()
        self._create_url_input()
        self._create_format_selector()
        self._create_download_button()
        self._create_progress()
        self._create_log()

        # 使GUI响应式
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # 启动UI更新循环
        self.update_ui()

    def _create_logo(self):
        """创建Logo"""
        logo_frame = ttk.Frame(self.main_frame)
        logo_frame.pack(pady=(10, 0))

        title_container = ttk.Frame(logo_frame)
        title_container.pack()

        # 红色播放按钮
        canvas = tk.Canvas(
            title_container, width=50, height=50, bg="#FF0000", highlightthickness=0
        )
        canvas.pack(side=tk.LEFT, padx=(0, 10))
        canvas.create_polygon(20, 12, 20, 38, 38, 25, fill="white", outline="white")

        # 标题
        ttk.Label(
            title_container, text="视频音频高速下载神器", font=self.title_font
        ).pack(side=tk.LEFT, pady=(10, 0))

        # 版本信息
        ttk.Label(logo_frame, text="V5.1.0 - 支持 YouTube/Bilibili/TikTok/Instagram/Suno").pack(pady=(5, 0))

    def _create_menu(self):
        """创建菜单栏"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="打开下载目录", command=self.open_download_dir)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)

        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="关于", command=self.show_about)

    def _create_url_input(self):
        """创建URL输入框"""
        self.url_frame = ttk.LabelFrame(self.main_frame, text="视频链接", padding="10")
        self.url_frame.pack(fill=tk.X, pady=(10, 10))

        ttk.Label(self.url_frame, text="链接:").pack(side=tk.LEFT, padx=(0, 10))

        self.url_entry = ttk.Entry(self.url_frame)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.url_entry.bind("<Return>", self.on_download)

        # macOS 使用 Command 键
        if IS_MACOS:
            self.url_entry.bind("<Command-v>", lambda e: self.paste_url())
        
        # 右键菜单
        self.url_menu = tk.Menu(self.url_entry, tearoff=0)
        self.url_menu.add_command(label="粘贴", command=self.paste_url)
        self.url_menu.add_command(label="清空", command=self.clear_url)
        
        if IS_MACOS:
            self.url_entry.bind("<Button-2>", self.show_url_menu)
        else:
            self.url_entry.bind("<Button-3>", self.show_url_menu)

    def _create_format_selector(self):
        """创建格式选择器"""
        self.format_frame = ttk.LabelFrame(self.main_frame, text="格式选项", padding="10")
        self.format_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(self.format_frame, text="格式:").pack(side=tk.LEFT, padx=(0, 10))

        self.format_var = tk.StringVar()
        self.format_combo = ttk.Combobox(self.format_frame, textvariable=self.format_var, state="readonly")
        self.format_combo["values"] = ["最佳视频", "最佳音频", "MP4视频", "MP3音频"]
        self.format_combo.current(0)
        self.format_combo.pack(side=tk.LEFT, padx=(0, 10))

    def _create_download_button(self):
        """创建下载按钮"""
        self.download_btn = ttk.Button(
            self.main_frame, text="开始下载", command=self.on_download
        )
        self.download_btn.pack(fill=tk.X, pady=(0, 10))

    def _create_progress(self):
        """创建进度条"""
        self.progress_frame = ttk.LabelFrame(self.main_frame, text="下载进度", padding="10")
        self.progress_frame.pack(fill=tk.X, pady=(0, 10))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.progress_frame, variable=self.progress_var, maximum=100
        )
        self.progress_bar.pack(fill=tk.X)

        self.progress_label = ttk.Label(self.progress_frame, text="准备就绪")
        self.progress_label.pack(pady=(5, 0))

    def _create_log(self):
        """创建日志区域"""
        self.log_frame = ttk.LabelFrame(self.main_frame, text="下载日志", padding="10")
        self.log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(self.log_frame, wrap=tk.WORD, height=12)
        self.log_text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scrollbar = ttk.Scrollbar(self.log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=scrollbar.set)

    def show_url_menu(self, event):
        """显示URL右键菜单"""
        self.url_menu.tk_popup(event.x_root, event.y_root)

    def paste_url(self):
        """粘贴URL"""
        try:
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, self.root.clipboard_get())
        except Exception:
            pass

    def clear_url(self):
        """清空URL"""
        self.url_entry.delete(0, tk.END)

    def open_download_dir(self):
        """打开下载目录"""
        if IS_MACOS:
            subprocess.run(["open", self.download_dir])
        else:
            os.startfile(self.download_dir)

    def show_about(self):
        """显示关于对话框"""
        messagebox.showinfo(
            "关于",
            "视频音频高速下载神器 V5.1.0\n\n"
            "支持平台:\n"
            "• YouTube\n"
            "• Bilibili\n"
            "• TikTok\n"
            "• Instagram\n"
            "• Suno\n"
            "• Sora\n\n"
            "基于 yt-dlp 开发"
        )

    def log(self, message):
        """添加日志消息"""
        self.queue.put(("log", message))

    def update_ui(self):
        """更新UI（从队列读取消息）"""
        try:
            while True:
                msg_type, msg = self.queue.get_nowait()
                if msg_type == "log":
                    self.log_text.insert(tk.END, f"{msg}\n")
                    self.log_text.see(tk.END)
                elif msg_type == "progress":
                    self.progress_var.set(msg)
                elif msg_type == "status":
                    self.progress_label.config(text=msg)
                elif msg_type == "done":
                    self.download_btn.config(state=tk.NORMAL)
                    self.progress_label.config(text=msg)
        except queue.Empty:
            pass
        
        self.root.after(100, self.update_ui)

    def _sanitize_url(self, url):
        """清理URL"""
        import re
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        if not url:
            return ""

        cleaned = re.sub(r'^["\'`]+|["\'`]+$', "", url.strip())

        # YouTube URL 清理
        if "youtube.com/watch" in cleaned or "youtu.be/" in cleaned:
            try:
                parsed = urlparse(cleaned)
                params = parse_qs(parsed.query)
                essential = {}
                if 'v' in params:
                    essential['v'] = params['v'][0]
                new_query = urlencode(essential)
                cleaned = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, ''
                ))
            except Exception:
                pass

        return cleaned

    def on_download(self, event=None):
        """处理下载"""
        url = self._sanitize_url(self.url_entry.get())

        # 验证URL
        valid_platforms = [
            "youtube.com/watch", "youtube.com/shorts/", "youtu.be/",
            "tiktok.com/", "vm.tiktok.com/",
            "bilibili.com/", "b23.tv/",
            "instagram.com/", "www.instagram.com/",
            "suno.ai/", "suno.com/",
            "sora.chatgpt.com/"
        ]

        if not url or not any(p in url for p in valid_platforms):
            messagebox.showerror("错误", "请输入有效的视频链接")
            return

        self.download_btn.config(state=tk.DISABLED)
        self.progress_var.set(0)
        self.progress_label.config(text="开始下载...")
        self.log(f"开始下载: {url}")

        # 格式映射
        format_map = {
            "最佳视频": "best",
            "最佳音频": "bestaudio/best",
            "MP4视频": "best[ext=mp4]/best",
            "MP3音频": "bestaudio[ext=m4a]/bestaudio/best",
        }
        format_str = format_map.get(self.format_var.get(), "best")

        # 在线程中下载
        thread = threading.Thread(
            target=self.download_video, args=(url, format_str), daemon=True
        )
        thread.start()

    def download_video(self, url, format_str):
        """下载视频"""
        try:
            output_template = os.path.join(
                self.download_dir, "%(title)s-%(id)s.%(ext)s"
            )

            def progress_hook(d):
                if d['status'] == 'downloading':
                    if 'total_bytes' in d and d['total_bytes'] > 0:
                        percent = d['downloaded_bytes'] * 100 / d['total_bytes']
                        self.queue.put(("progress", percent))
                    if '_percent_str' in d:
                        self.queue.put(("status", f"下载中: {d['_percent_str']}"))
                elif d['status'] == 'finished':
                    self.queue.put(("progress", 100))
                    self.queue.put(("status", "处理中..."))

            ydl_opts = {
                'format': format_str,
                'outtmpl': output_template,
                'progress_hooks': [progress_hook],
                'quiet': False,
                'no_warnings': True,
            }

            # 检测平台添加特殊配置
            is_youtube = "youtube.com" in url or "youtu.be/" in url
            is_bilibili = "bilibili.com" in url or "b23.tv" in url
            is_tiktok = "tiktok.com" in url

            if is_youtube:
                ydl_opts['extractor_args'] = {'youtube': {'impersonate': 'chrome'}}
                # 尝试获取浏览器cookies
                for browser in ['safari', 'chrome', 'firefox', 'edge']:
                    try:
                        ydl_opts['cookiesfrombrowser'] = (browser,)
                        break
                    except Exception:
                        continue

            if is_bilibili:
                ydl_opts['extractor_args'] = {'bilibili': {'danmaku': False}}

            if is_tiktok:
                ydl_opts['extractor_args'] = {'tiktok': {'api_hostname': 'api22-normal-c-alisg.tiktokv.com'}}

            self.log("正在获取视频信息...")

            with YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=True)
                title = info.get('title', 'Unknown')
                self.log(f"标题: {title}")
                self.log(f"下载完成!")
                self.queue.put(("done", f"下载完成: {title}"))

        except Exception as e:
            error_msg = str(e)
            self.log(f"下载失败: {error_msg}")
            self.queue.put(("done", "下载失败"))

    def check_download_status(self, thread):
        """检查下载状态"""
        if thread.is_alive():
            self.root.after(100, self.check_download_status, thread)
        else:
            self.download_btn.config(state=tk.NORMAL)


def main():
    root = tk.Tk()
    
    # macOS 特殊设置
    if IS_MACOS:
        # 允许在 macOS 上正确显示应用名
        try:
            from Foundation import NSBundle
            bundle = NSBundle.mainBundle()
            info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
            info['CFBundleName'] = '视频下载神器'
        except Exception:
            pass
    
    app = YTDLP_GUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
