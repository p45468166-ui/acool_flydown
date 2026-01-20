#!/usr/bin/env python3
"""
有图比快速下载神器
"""

import sys
import os
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

try:
    from hongguo_frida import HongguoFridaRunner
except Exception:
    HongguoFridaRunner = None


# 这是一个常用的函数，用来解决打包后找不到图标文件的问题
def get_resource_path(relative_path):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


class YTDLP_GUI:
    """有图比快速下载神器 GUI"""

    def __init__(self, root):
        """初始化GUI"""
        self.root = root
        self.root.title("视频快速下载神器")
        self.root.geometry("600x550")
        self.root.resizable(True, True)

        # 设置中文字体，解决乱码问题
        self.root.option_add("*Font", "微软雅黑 10")

        # 创建一个队列用于线程安全通信
        self.queue = queue.Queue()

        # 添加进度节流相关的属性
        self.last_progress_percent = -1  # 用于进度更新节流
        self.last_status_message = ""  # 用于状态消息更新节流
        self.update_interval = 100  # 最小更新间隔（毫秒）
        self.last_update_time = 0  # 上次更新时间

        # 获取当前可执行文件所在目录
        # 获取当前脚本或可执行文件的目录
        if getattr(sys, "frozen", False):
            # 如果是打包后的可执行文件
            # 使用sys.argv[0]获取原始可执行文件路径，避免临时目录问题
            self.app_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        else:
            # 如果是直接运行的脚本
            self.app_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 设置下载目录为程序目录下的 videos 子目录
        self.download_dir = os.path.join(self.app_dir, "videos")

        # 确保下载目录存在
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir, exist_ok=True)

        # 设置窗口左上角的图标
        try:
            # 使用images.ico作为图标
            icon_path = get_resource_path("images.ico")
            if os.path.exists(icon_path):
                # 使用 default= 参数避免 "bitmap not defined" 错误
                self.root.iconbitmap(default=icon_path)
            else:
                # 如果在打包目录找不到，尝试在 exe 所在目录找
                alt_icon_path = os.path.join(self.download_dir, "images.ico")
                if os.path.exists(alt_icon_path):
                    self.root.iconbitmap(default=alt_icon_path)
        except tk.TclError as e:
            # TclError 通常表示图标格式问题，静默忽略
            pass
        except Exception as e:
            pass  # 图标加载失败不影响程序运行

        # 设置主布局
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # YouTube LOGO（使用base64编码的简单LOGO）
        self.add_youtube_logo()

        self._create_menu()

        # URL输入部分
        self.url_frame = ttk.LabelFrame(self.main_frame, text="视频链接", padding="10")
        self.url_frame.pack(fill=tk.X, pady=(10, 10))

        self.url_label = ttk.Label(self.url_frame, text="链接:")
        self.url_label.pack(side=tk.LEFT, padx=(0, 10))

        self.url_entry = ttk.Entry(self.url_frame)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.url_entry.bind("<Return>", self.on_download)
        self.url_entry.setvar(value="https://")

        # 创建右键菜单
        self.url_entry_menu = tk.Menu(self.url_entry, tearoff=0)
        self.url_entry_menu.add_command(label="粘贴", command=self.paste_url)
        self.url_entry_menu.add_command(label="全选", command=self.select_all_url)
        self.url_entry_menu.add_command(label="清空", command=self.clear_url)

        # 绑定右键菜单事件
        self.url_entry.bind("<Button-3>", self.show_url_menu)

        # 格式选择部分
        self.format_frame = ttk.LabelFrame(
            self.main_frame, text="格式选项", padding="10"
        )
        self.format_frame.pack(fill=tk.X, pady=(0, 10))

        self.format_label = ttk.Label(self.format_frame, text="格式:")
        self.format_label.pack(side=tk.LEFT, padx=(0, 10))

        self.format_var = tk.StringVar()
        self.format_combo = ttk.Combobox(
            self.format_frame, textvariable=self.format_var
        )
        self.format_combo["values"] = ["最佳视频", "最佳音频", "MP4视频", "MP3音频"]
        self.format_combo.current(0)
        self.format_combo.pack(side=tk.LEFT, padx=(0, 10))

        # 下载按钮
        self.download_btn = ttk.Button(
            self.main_frame, text="开始下载", command=self.on_download
        )
        self.download_btn.pack(fill=tk.X, pady=(0, 10))

        # 进度条
        self.progress_frame = ttk.LabelFrame(
            self.main_frame, text="下载进度", padding="10"
        )
        self.progress_frame.pack(fill=tk.X, pady=(0, 10))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.progress_frame, variable=self.progress_var, maximum=100
        )
        self.progress_bar.pack(fill=tk.X)

        self.progress_label = ttk.Label(self.progress_frame, text="准备就绪")
        self.progress_label.pack(pady=(5, 0))

        # 日志输出
        self.log_frame = ttk.LabelFrame(self.main_frame, text="下载日志", padding="10")
        self.log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(self.log_frame, wrap=tk.WORD, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        self.log_scrollbar = ttk.Scrollbar(
            self.log_frame, orient=tk.VERTICAL, command=self.log_text.yview
        )
        self.log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=self.log_scrollbar.set)

        # 使GUI响应式
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # 启动更新循环
        self.update_ui()

        self._hongguo_frida_runner = None
        self._hongguo_frida_thread = None
        self._hongguo_template_text_widget = None
        self._hongguo_template_status_label = None
        self._hongguo_template_dialog = None
        self._hongguo_last_template_url = None
        self._hongguo_capture_window = None
        self._hongguo_capture_text = None
        self._hongguo_capture_status = None
        self._hongguo_install_thread = None

    def add_youtube_logo(self):
        """添加YouTube风格的LOGO"""
        # 使用现代化设计创建YouTube风格的LOGO
        logo_frame = ttk.Frame(self.main_frame)
        logo_frame.pack(pady=(10, 0))

        # 创建一个包含LOGO和标题的水平框架
        title_container = ttk.Frame(logo_frame)
        title_container.pack()

        # 创建YouTube风格的红色播放按钮Canvas
        canvas = tk.Canvas(
            title_container, width=60, height=60, bg="#FF0000", highlightthickness=0
        )
        canvas.pack(side=tk.LEFT, padx=(0, 10))

        # 绘制白色三角形播放按钮
        canvas.create_polygon(25, 15, 25, 45, 45, 30, fill="white", outline="white")

        # 添加标题
        title_label = ttk.Label(
            title_container, text="视频音频高速下载神器", font=("微软雅黑", 16, "bold")
        )
        title_label.pack(side=tk.LEFT, pady=(15, 0))

        # 添加版本信息
        version_label = ttk.Label(logo_frame, text="V5.1.0 - 支持红果短剧")
        version_label.pack(pady=(5, 0))

    def _sanitize_url(self, url):
        """清理并标准化URL，特别处理YouTube的时间戳参数"""
        import re
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        if not url:
            return ""

        # 移除首尾的引号、反引号和空格
        cleaned_url = re.sub(r"^[\"'`]+|[\"'`]+$", "", url.strip())
        cleaned_url = cleaned_url.strip()

        # 特殊处理YouTube URL - 清理时间戳和其他非必要参数
        # 这些参数可能导致Windows命令行解析问题（&符号被解释为命令分隔符）
        if "youtube.com/watch" in cleaned_url or "youtu.be/" in cleaned_url:
            try:
                parsed = urlparse(cleaned_url)
                query_params = parse_qs(parsed.query)
                
                # 只保留必要的参数（视频ID）
                essential_params = {}
                if 'v' in query_params:
                    essential_params['v'] = query_params['v'][0]
                
                # 重建URL，移除时间戳(t)、列表(list)等非必要参数
                # 这些参数移除后不会影响视频下载，但可以避免命令行问题
                new_query = urlencode(essential_params)
                cleaned_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    ''  # 不需要fragment
                ))
                
                # 处理短链接 youtu.be/ 格式
                if "youtu.be/" in cleaned_url and "?" in cleaned_url:
                    # youtu.be链接的视频ID在路径中，不在查询参数中
                    # 清理查询参数
                    cleaned_url = cleaned_url.split("?")[0]
                    
            except Exception:
                # 如果解析失败，返回原始清理后的URL
                pass

        return cleaned_url

    def _create_yt_logger(self):
        """创建yt-dlp日志处理器，将日志重定向到GUI"""
        gui_instance = self
        
        class YTLogger:
            def debug(self, msg):
                # 过滤掉不重要的调试信息，只显示有用的
                if msg.startswith('[download]') or 'Downloading' in msg:
                    gui_instance.log(msg)
            
            def info(self, msg):
                gui_instance.log(msg)
            
            def warning(self, msg):
                # 过滤掉不需要的警告信息
                if any(keyword in msg for keyword in [
                    'JavaScript runtime',
                    'SABR streaming',
                    'n challenge solving',
                    'formats have been skipped',
                    'EJS'
                ]):
                    return  # 忽略这些警告
                gui_instance.log(f"警告: {msg}")
            
            def error(self, msg):
                gui_instance.log(f"错误: {msg}")
        
        return YTLogger()

    def check_and_install_ffmpeg(self):
        """检查并安装ffmpeg
        
        Returns:
            str or None: FFmpeg 所在目录路径，如果未找到或安装失败则返回 None
        """
        # 检查系统路径
        if shutil.which("ffmpeg"):
            # FFmpeg 在系统 PATH 中，不需要指定位置
            return ""  # 空字符串表示使用系统 PATH
        
        # 检查程序目录
        ffmpeg_in_app_dir = os.path.join(self.app_dir, "ffmpeg.exe")
        if os.path.exists(ffmpeg_in_app_dir):
            return self.app_dir
        
        # 检查当前目录
        if os.path.exists("ffmpeg.exe"):
            return os.getcwd()

        self.log("正在检测必要组件 FFmpeg...")
        
        # 提示用户
        msg = "Bilibili高清视频需要FFmpeg组件才能合并声音。\n是否自动下载并安装 FFmpeg (约100MB)？\n\n点击[是]自动下载\n点击[否]将尝试下载低质量版本"
        if not messagebox.askyesno("缺少组件", msg):
            self.log("用户取消下载FFmpeg，将尝试下载低质量版本（可能无声）")
            return None

        # 尝试多个下载源
        download_sources = [
            # GitHub 官方构建
            ("https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip", "ffmpeg-master-latest-win64-gpl/bin/ffmpeg.exe"),
            # Gyan.dev essentials (较小)
            ("https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip", "*/bin/ffmpeg.exe"),
        ]
        
        for source_url, ffmpeg_path_in_zip in download_sources:
            try:
                self.log(f"正在下载 FFmpeg，请稍候...")
                self.log(f"下载源: {source_url.split('/')[2]}")
                
                zip_path = os.path.join(self.app_dir, "ffmpeg.zip")
                
                # 使用 requests 进行下载，支持超时和流式下载
                session = requests.Session()
                response = session.get(source_url, stream=True, timeout=60)
                response.raise_for_status()
                
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                last_percent = -1
                
                with open(zip_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024*1024):  # 1MB chunks
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            
                            # 显示进度（每5%更新一次）
                            if total_size > 0:
                                percent = int(downloaded * 100 / total_size)
                                if percent >= last_percent + 5:
                                    self.log(f"下载进度: {percent}% ({downloaded / (1024*1024):.1f}MB / {total_size / (1024*1024):.1f}MB)")
                                    last_percent = percent
                
                self.log("下载完成，正在解压...")
                
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    # 查找 ffmpeg.exe
                    ffmpeg_file = None
                    for file in zip_ref.namelist():
                        if file.endswith("bin/ffmpeg.exe") or file.endswith("/ffmpeg.exe"):
                            ffmpeg_file = file
                            break
                    
                    if ffmpeg_file:
                        # 解压 ffmpeg.exe 到程序目录
                        target_path = os.path.join(self.app_dir, "ffmpeg.exe")
                        with zip_ref.open(ffmpeg_file) as source, open(target_path, "wb") as target:
                            shutil.copyfileobj(source, target)
                        self.log("FFmpeg 安装成功！")
                        self.log(f"FFmpeg 位置: {target_path}")
                        
                        # 清理
                        try:
                            os.remove(zip_path)
                        except:
                            pass
                        return self.app_dir  # 返回 FFmpeg 所在目录
                    else:
                        self.log("错误：在压缩包中未找到 ffmpeg.exe")
                
                # 清理失败的下载
                try:
                    os.remove(zip_path)
                except:
                    pass
                    
            except requests.exceptions.Timeout:
                self.log(f"下载超时，尝试下一个源...")
                continue
            except requests.exceptions.RequestException as e:
                self.log(f"下载失败: {e}，尝试下一个源...")
                continue
            except Exception as e:
                self.log(f"FFmpeg 下载/安装失败: {e}")
                continue
        
        self.log("所有下载源均失败，请手动下载 ffmpeg.exe 并放到程序目录下")
        self.log("下载地址: https://www.gyan.dev/ffmpeg/builds/")
        return None

    def check_and_install_aria2(self):
        """检查并安装 aria2c 下载加速器
        
        aria2c 是一个高性能的多协议多源下载工具，可以显著提升YouTube下载速度。
        
        Returns:
            str or None: aria2c 可执行文件的完整路径，如果未找到或安装失败则返回 None
        """
        # 检查系统路径
        aria2_in_path = shutil.which("aria2c")
        if aria2_in_path:
            self.log(f"检测到系统 aria2c: {aria2_in_path}")
            return aria2_in_path
        
        # 检查程序目录
        aria2_in_app_dir = os.path.join(self.app_dir, "aria2c.exe")
        if os.path.exists(aria2_in_app_dir):
            self.log(f"检测到本地 aria2c: {aria2_in_app_dir}")
            return aria2_in_app_dir
        
        # 检查当前目录
        if os.path.exists("aria2c.exe"):
            aria2_path = os.path.abspath("aria2c.exe")
            self.log(f"检测到当前目录 aria2c: {aria2_path}")
            return aria2_path

        self.log("正在检测下载加速组件 aria2c...")
        
        # 提示用户
        msg = "检测到没有安装 aria2c 下载加速器。\n\n" \
              "aria2c 可以大幅提升 YouTube 视频下载速度（约5-10倍）。\n\n" \
              "是否自动下载并安装 aria2c (约5MB)？\n\n" \
              "点击[是]自动下载（推荐）\n" \
              "点击[否]使用普通速度下载"
        if not messagebox.askyesno("安装下载加速器", msg):
            self.log("用户取消安装 aria2c，将使用普通速度下载")
            return None

        # 尝试多个下载源
        download_sources = [
            # GitHub 官方发布
            "https://github.com/aria2/aria2/releases/download/release-1.37.0/aria2-1.37.0-win-64bit-build1.zip",
            # 备用镜像
            "https://ghproxy.com/https://github.com/aria2/aria2/releases/download/release-1.37.0/aria2-1.37.0-win-64bit-build1.zip",
        ]
        
        for source_url in download_sources:
            try:
                self.log(f"正在下载 aria2c，请稍候...")
                self.log(f"下载源: {source_url.split('/')[2]}")
                
                zip_path = os.path.join(self.app_dir, "aria2.zip")
                
                # 使用 requests 进行下载，支持超时和流式下载
                session = requests.Session()
                response = session.get(source_url, stream=True, timeout=60)
                response.raise_for_status()
                
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                last_percent = -1
                
                with open(zip_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024*1024):  # 1MB chunks
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            
                            # 显示进度（每10%更新一次）
                            if total_size > 0:
                                percent = int(downloaded * 100 / total_size)
                                if percent >= last_percent + 10:
                                    self.log(f"下载进度: {percent}% ({downloaded / (1024*1024):.1f}MB / {total_size / (1024*1024):.1f}MB)")
                                    last_percent = percent
                
                self.log("下载完成，正在解压...")
                
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    # 查找 aria2c.exe
                    aria2_file = None
                    for file in zip_ref.namelist():
                        if file.endswith("aria2c.exe"):
                            aria2_file = file
                            break
                    
                    if aria2_file:
                        # 解压 aria2c.exe 到程序目录
                        target_path = os.path.join(self.app_dir, "aria2c.exe")
                        with zip_ref.open(aria2_file) as source, open(target_path, "wb") as target:
                            shutil.copyfileobj(source, target)
                        self.log("aria2c 安装成功！")
                        self.log(f"aria2c 位置: {target_path}")
                        
                        # 清理
                        try:
                            os.remove(zip_path)
                        except:
                            pass
                        return target_path  # 返回 aria2c 完整路径
                    else:
                        self.log("错误：在压缩包中未找到 aria2c.exe")
                
                # 清理失败的下载
                try:
                    os.remove(zip_path)
                except:
                    pass
                    
            except requests.exceptions.Timeout:
                self.log(f"下载超时，尝试下一个源...")
                continue
            except requests.exceptions.RequestException as e:
                self.log(f"下载失败: {e}，尝试下一个源...")
                continue
            except Exception as e:
                self.log(f"aria2c 下载/安装失败: {e}")
                continue
        
        self.log("所有下载源均失败，请手动下载 aria2c.exe 并放到程序目录下")
        self.log("下载地址: https://github.com/aria2/aria2/releases")
        return None

    def _run_ytdlp_cli(self, url):
        """使用命令行方式安全下载YouTube视频"""
        output_template = os.path.join(
            self.download_dir, "%(title)s-%(id)s-%(epoch)s.%(ext)s"
        )
        cmd_parts = [
            sys.executable,
            "-m",
            "yt_dlp",
            "--extractor-args",
            "youtube:impersonate=chrome",
            "--format",
            "best",
            "--hls-prefer-native",
            "--skip-unavailable-fragments",
            "--socket-timeout",
            "30",
            "--retries",
            "3",
            "--fragment-retries",
            "3",
            "--extractor-retries",
            "5",
            "--output",
            output_template,
            url,
        ]
        cmd_display = subprocess.list2cmdline(cmd_parts)
        self.log(f"执行命令: {cmd_display}")

        process = subprocess.Popen(
            cmd_parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        for line in process.stdout:
            line = line.strip()
            if line:
                self.log(line)
                if any(
                    keyword in line.lower() for keyword in ["downloading", "%", "eta"]
                ):
                    self.queue.put(("status", line))

        process.wait()
        return process.returncode == 0

    def on_download(self, event=None):
        """处理下载按钮点击"""
        url = self._sanitize_url(self.url_entry.get())

        # 验证URL是否有效
        if not url or not (
            "youtube.com/watch?v=" in url
            or "youtube.com/shorts/" in url
            or "youtu.be/" in url
            or "tiktok.com/" in url
            or "vm.tiktok.com/" in url
            or "bilibili.com/" in url
            or "b23.tv/" in url
            or "sora.chatgpt.com/p/" in url
            or url.startswith("s_")
            or "sorapure.vercel.app" in url
            or "suno.ai/song/" in url
            or "suno.ai/playlists/" in url
            or "suno.com/song/" in url
            or "suno.com/playlists/" in url
            or "suno.com/s/" in url
            or "instagram.com/reels/" in url
            or "instagram.com/reel/" in url
            or "instagram.com/p/" in url
            or "instagram.com/tv/" in url
            or "www.instagram.com/reels/" in url
            or "www.instagram.com/reel/" in url
            or "www.instagram.com/p/" in url
            or "www.instagram.com/tv/" in url
            or "novelquickapp.com/s/" in url
            or "novelquickapp.com/hongguo/" in url
        ):
            messagebox.showerror(
                "错误",
                "请输入有效的YouTube、TikTok、Bilibili、Sora2、Suno、Instagram或红果短剧链接",
            )
            return

        # 禁用下载按钮以防止多次下载
        self.download_btn.config(state=tk.DISABLED)

        format_selection = self.format_var.get()

        # 检测URL平台类型
        is_bilibili = "bilibili.com/" in url or "b23.tv/" in url

        # 针对不同平台使用不同的格式策略
        if is_bilibili:
            # Bilibili格式选择：优先使用包含音视频的单一格式
            # 避免下载分离的视频流导致无声
            format_map = {
                "最佳视频": "best",  # 最佳包含音视频的格式
                "最佳音频": "bestaudio/best",
                "MP4视频": "best[ext=mp4]/best",  # 最佳MP4格式（包含音视频）
                "MP3音频": "bestaudio[ext=m4a]/bestaudio/best",
            }
        else:
            # 其他平台：使用单一格式，避免需要ffmpeg合并
            format_map = {
                "最佳视频": "best",  # 只使用最佳单一格式，无需合并
                "最佳音频": "bestaudio/best",
                "MP4视频": "best[ext=mp4]/best",  # 只使用最佳单一MP4格式，无需合并
                "MP3音频": "bestaudio[ext=m4a]/bestaudio[ext=mp3]/bestaudio/best",
            }

        format_str = format_map.get(format_selection, "best")

        # 更新UI
        self.progress_var.set(0)
        self.progress_label.config(text="开始下载...")
        self.log_text.insert(tk.END, f"开始下载: {url}\n")
        self.log_text.see(tk.END)

        # 在单独的线程中开始下载，使用daemon=True确保线程在主线程退出时自动关闭
        download_thread = threading.Thread(
            target=self.download_video, args=(url, format_str), daemon=True
        )
        download_thread.start()

        # 添加一个状态检查，确保UI保持响应
        self.root.after(100, self.check_download_status, download_thread)

    def get_video_info(self, url):
        """获取视频信息，包括大小和时长"""
        # 检测URL平台类型
        is_instagram = (
            "instagram.com/reels/" in url
            or "instagram.com/reel/" in url
            or "instagram.com/p/" in url
            or "instagram.com/tv/" in url
            or "www.instagram.com/reels/" in url
            or "www.instagram.com/reel/" in url
            or "www.instagram.com/p/" in url
            or "www.instagram.com/tv/" in url
        )
        
        is_bilibili = "bilibili.com/" in url or "b23.tv/" in url
        is_tiktok = "tiktok.com/" in url or "vm.tiktok.com/" in url
        is_youtube = (
            "youtube.com/watch?v=" in url
            or "youtu.be/" in url
            or "youtube.com/shorts/" in url
            or "www.youtube.com/watch?v=" in url
            or "www.youtu.be/" in url
            or "www.youtube.com/shorts/" in url
        )

        # 基础配置
        ydl_opts = {
            "quiet": True,
            "no_warnings": True,
            "skip_download": True,
            # 添加模拟选项，绕过Cloudflare反爬虫
            "extractor_args": {
                "generic": {
                    "impersonate": "chrome",
                }
            },
        }

        # 如果是YouTube链接，添加特殊配置和浏览器cookies支持
        if is_youtube:
            ydl_opts["extractor_args"]["youtube"] = {
                "impersonate": "chrome",
            }
            
            # 尝试从多个浏览器获取cookies以绕过机器人检测
            browsers_to_try = ["edge", "firefox", "chrome", "brave", "opera"]
            cookie_success = False
            last_error = None
            
            for browser in browsers_to_try:
                try:
                    test_opts = {
                        **ydl_opts,
                        "cookiesfrombrowser": (browser,),
                    }
                    with YoutubeDL(test_opts) as ydl:
                        info_dict = ydl.extract_info(url, download=False)
                        self.log(f"使用 {browser.capitalize()} 浏览器 cookies 获取视频信息成功")
                        return info_dict
                except Exception as e:
                    error_str = str(e)
                    last_error = e
                    # 如果是cookies相关错误，尝试下一个浏览器
                    if "cookie" in error_str.lower() or "Sign in" in error_str:
                        continue
                    # 如果是其他错误（如视频不存在），直接返回None
                    elif "Video unavailable" in error_str or "Private video" in error_str:
                        self.log(f"获取视频信息失败: {str(e)}")
                        return None
                    # 其他错误继续尝试
                    continue
            
            # 所有浏览器都失败，尝试不使用cookies
            self.log("无法从浏览器获取cookies，尝试不使用cookies获取视频信息...")
            try:
                with YoutubeDL(ydl_opts) as ydl:
                    info_dict = ydl.extract_info(url, download=False)
                    return info_dict
            except Exception as e:
                # 如果仍然失败，记录详细错误
                error_msg = str(e)
                if "Sign in" in error_msg:
                    self.log("YouTube 需要登录验证。请在浏览器（Edge/Chrome/Firefox）中登录 YouTube 后再试。")
                else:
                    self.log(f"获取视频信息失败: {error_msg}")
                return None

        # 如果是Bilibili链接，添加特殊配置
        # 注意：使用impersonate时不要设置http_headers，会冲突
        elif is_bilibili:
            ydl_opts["extractor_args"]["bilibili"] = {
                "danmaku": False,
            }

        # 如果是TikTok链接，添加特殊配置
        elif is_tiktok:
            ydl_opts["extractor_args"]["tiktok"] = {
                "api_hostname": "api22-normal-c-alisg.tiktokv.com",
            }
            # TikTok 需要特殊的请求头
            ydl_opts["http_headers"] = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            ydl_opts["socket_timeout"] = 30
            ydl_opts["retries"] = 5

        # 如果是Instagram链接，添加特殊配置
        elif is_instagram:
            ydl_opts["extractor_args"]["instagram"] = {
                "impersonate": "chrome",
            }
            ydl_opts["ignore_no_formats_error"] = True
            ydl_opts["no_check_certificate"] = True
            ydl_opts["http_headers"] = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            }
            # 移除自动cookie获取，避免Chrome cookie数据库访问错误
            # 使用更简单的配置，依赖浏览器模拟和HTTP头
            ydl_opts["cookiefile"] = "cookies.txt"  # 允许用户手动提供cookie文件

        try:
            with YoutubeDL(ydl_opts) as ydl:
                info_dict = ydl.extract_info(url, download=False)
                return info_dict
        except Exception as e:
            self.log(f"获取视频信息失败: {str(e)}")
            return None

    def extract_sora_video_id(self, url):
        """提取Sora2视频ID"""
        if url.startswith("s_"):
            # 直接是视频ID
            return url
        elif "sora.chatgpt.com/p/" in url:
            # 从完整URL中提取
            return url.split("/p/")[-1]
        elif "sorapure.vercel.app" in url:
            # 从SoraPure链接中提取
            return url.split("/")[-1]
        return None

    def extract_sora_video_info(self, sora_url):
        """从第三方API获取Sora视频信息"""
        try:
            # 使用第三方API获取视频信息
            api_base = "https://api.soracdn.workers.dev"
            api_proxy = f"{api_base}/api-proxy/"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
                "Origin": "https://sorasave.app",
                "Referer": "https://sorasave.app/",
            }

            import urllib.parse

            api_url = api_proxy + urllib.parse.quote(sora_url, safe="")
            self.log("调用Sora API获取视频信息...")

            session = requests.Session()
            response = session.get(api_url, headers=headers, timeout=30)
            response.raise_for_status()

            video_data = response.json()

            if not video_data.get("post_id"):
                self.log("Sora API返回的视频数据中没有post_id")
                return None

            return video_data
        except Exception as e:
            self.log(f"获取Sora视频信息失败: {str(e)}")
            return None

    def generate_sora_download_url(self, video_info):
        """生成Sora视频的下载链接"""
        try:
            api_base = "https://api.soracdn.workers.dev"
            download_proxy = f"{api_base}/download-proxy"
            post_id = video_info.get("post_id")
            title = video_info.get("title", "untitled_video")

            # 清理文件名
            import re

            clean_filename = re.sub(r"[^a-zA-Z0-9]", "_", title)[:100]
            if not clean_filename:
                clean_filename = "untitled_video"

            # 生成唯一标识符，使用更安全的方式确保文件名唯一
            import os
            import time
            import uuid

            # 使用UUID生成绝对唯一的标识符，结合时间戳
            timestamp = str(int(time.time() * 1000))  # 使用毫秒级时间戳，提高唯一性
            unique_id = str(uuid.uuid4()).replace("-", "")[:12]  # 使用UUID的前12位
            # 生成最终文件名：原文件名_时间戳_UUID
            final_filename = f"{clean_filename}_{timestamp}_{unique_id}"

            import urllib.parse

            download_url = f"{download_proxy}?id={urllib.parse.quote(post_id)}&filename={urllib.parse.quote(final_filename)}"
            self.log("生成Sora下载链接...")

            return download_url, final_filename
        except Exception as e:
            self.log(f"生成Sora下载链接失败: {str(e)}")
            return None, None

    def download_sora_video(self, video_id):
        """使用第三方API下载Sora视频"""
        try:
            # 步骤1: 构建完整的Sora URL
            sora_url = f"https://sora.chatgpt.com/p/{video_id}"

            # 步骤2: 获取视频信息
            self.log(f"获取Sora视频信息: {sora_url}")
            video_info = self.extract_sora_video_info(sora_url)
            if not video_info:
                error_msg = f"无法获取Sora视频信息: {video_id}"
                self.log(error_msg)
                self.queue.put(("error", error_msg))
                return

            # 步骤3: 生成下载链接
            download_url, clean_filename = self.generate_sora_download_url(video_info)
            if not download_url:
                error_msg = f"无法生成Sora下载链接: {video_id}"
                self.log(error_msg)
                self.queue.put(("error", error_msg))
                return

            # 步骤4: 下载视频
            self.log(f"开始下载Sora视频: {clean_filename}")

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
                "Origin": "https://sorasave.app",
                "Referer": "https://sorasave.app/",
            }

            session = requests.Session()
            response = session.get(
                download_url, headers=headers, stream=True, timeout=60
            )
            response.raise_for_status()

            # 获取文件大小
            total_size = int(response.headers.get("content-length", 0))

            # 构造文件名 - 使用带有时间戳和随机ID的唯一文件名
            filename = f"{clean_filename}.mp4"
            file_path = os.path.join(self.download_dir, filename)

            self.log(f"文件大小: {total_size / (1024 * 1024):.1f}MB")

            # 下载文件并显示进度
            downloaded = 0
            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        # 计算进度百分比
                        percent = (
                            (downloaded / total_size) * 100 if total_size > 0 else 0
                        )

                        # 发送进度更新
                        self.queue.put(
                            (
                                "progress",
                                {
                                    "percent": percent,
                                    "filename": filename,
                                    "status": f"下载中: {filename} | {percent:.1f}% | 已下载: {downloaded / (1024 * 1024):.1f}MB / {total_size / (1024 * 1024):.1f}MB",
                                },
                            )
                        )

            # 验证文件大小，确保下载完整
            if os.path.getsize(file_path) < 1024 and total_size > 1024:
                self.log("下载的文件不完整，删除不完整文件")
                os.remove(file_path)  # 删除不完整文件
                error_msg = f"Sora视频下载不完整: {video_id}"
                self.log(error_msg)
                self.queue.put(("error", error_msg))
                return

            self.log(f"Sora视频下载完成: {filename}")
            self.queue.put(("complete", "Sora视频下载成功完成！"))
            return

        except Exception as e:
            self.log(f"Sora视频下载失败: {str(e)}")
            self.queue.put(("error", f"Sora视频下载失败: {str(e)}"))

    def extract_suno_song_id(self, url):
        """提取Suno歌曲ID"""
        if "suno.ai/song/" in url:
            return url.split("suno.ai/song/")[-1].split("/")[0]
        elif "suno.com/song/" in url:
            return url.split("suno.com/song/")[-1].split("/")[0]
        elif "suno.com/s/" in url:
            return url.split("suno.com/s/")[-1].split("/")[0]
        return None

    def extract_suno_playlist_id(self, url):
        """提取Suno播放列表ID"""
        if "suno.ai/playlists/" in url:
            return url.split("suno.ai/playlists/")[-1].split("/")[0]
        elif "suno.com/playlists/" in url:
            return url.split("suno.com/playlists/")[-1].split("/")[0]
        return None

    def extract_hongguo_share_id(self, url):
        """提取红果短剧分享链接ID"""
        import re
        # 匹配 novelquickapp.com/s/XXXXX 格式
        pattern = r'novelquickapp\.com/s/([a-zA-Z0-9]+)'
        match = re.search(pattern, url)
        if match:
            return match.group(1)
        return None

    def get_hongguo_drama_info(self, url):
        """从红果短剧分享链接获取短剧信息"""
        try:
            self.log("正在获取红果短剧信息...")
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            page_content = response.text
            
            import re
            import json
            
            # 从页面中提取 window._ROUTER_DATA
            router_data_pattern = r'window\._ROUTER_DATA\s*=\s*(\{.*?\});?\s*</script>'
            match = re.search(router_data_pattern, page_content, re.DOTALL)
            
            if not match:
                self.log("无法从页面提取数据")
                return None
            
            try:
                # 解析JSON数据
                router_data = json.loads(match.group(1))
                
                # 提取短剧页面数据
                page_data = router_data.get("loaderData", {}).get("video-list-share-ssr_page", {}).get("pageData", {})
                
                if not page_data:
                    self.log("无法获取短剧数据")
                    return None
                
                series_data = page_data.get("series_data", {})
                
                drama_info = {
                    "title": series_data.get("title", "未知短剧"),
                    "intro": series_data.get("series_intro", ""),
                    "cover": series_data.get("series_cover", ""),
                    "category": series_data.get("category", ""),
                    "total_episodes": series_data.get("serial_count", 0),
                    "popularity": series_data.get("popularity", 0),
                    "first_episode_url": series_data.get("play_url", ""),
                    "chapter_ids": page_data.get("chapter_ids", []),
                    "link_params": page_data.get("linkParams", {}),
                }
                
                self.log(f"短剧标题: {drama_info['title']}")
                self.log(f"总集数: {drama_info['total_episodes']}")
                self.log(f"分类: {drama_info['category']}")
                
                return drama_info
                
            except json.JSONDecodeError as e:
                self.log(f"JSON解析失败: {str(e)}")
                return None
                
        except Exception as e:
            self.log(f"获取红果短剧信息失败: {str(e)}")
            import traceback
            self.log(f"错误详情: {traceback.format_exc()}")
            return None

    def get_hongguo_full_video_url(self, preview_url):
        """尝试将预览版URL转换为完整版URL
        
        技术说明：
        - 预览版URL特征：包含 &start=0&end=30 参数限制视频为30秒
        - 完整版URL：来自不同CDN域名，需要APP内部API获取
        
        当前限制：
        - 简单移除start/end参数会导致403错误（签名验证失败）
        - 完整视频URL需要模拟APP请求获取，需要设备认证信息
        
        解决方案：
        1. 如果用户提供抓包的完整URL，直接使用
        2. 否则使用预览URL（只能获取30秒预览）
        """
        import re
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        if not preview_url:
            return None
        
        try:
            parsed = urlparse(preview_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            # 检查是否来自完整版CDN（已经是完整URL）
            if 'reading-video.qznovelvod.com' in parsed.netloc:
                self.log("检测到完整视频CDN域名")
                return preview_url
            
            # 检查是否有预览限制参数
            has_start = 'start' in params
            has_end = 'end' in params
            
            if has_start or has_end:
                start_val = params.get('start', ['0'])[0]
                end_val = params.get('end', ['30'])[0]
                self.log(f"警告: URL包含预览限制 (start={start_val}, end={end_val}秒)")
                self.log("注意: 预览版视频仅包含前30秒内容")
                
                # 由于移除参数会导致403，暂时保留预览URL
                # 未来可以通过抓包获取完整URL
                return preview_url
            else:
                return preview_url
                
        except Exception as e:
            self.log(f"URL处理失败: {str(e)}")
            return preview_url

    def is_hongguo_full_cdn_url(self, url):
        from urllib.parse import urlparse

        if not url:
            return False
        try:
            parsed = urlparse(url)
            host = (parsed.netloc or "").lower()
            return ("qznovelvod.com" in host) and ("reading-video" in host)
        except Exception:
            return False

    def modify_hongguo_url_eid(self, base_url, new_eid):
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params["eid"] = [str(int(new_eid))]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def get_hongguo_video_size(self, url):
        headers = {
            "User-Agent": "AVDML_2.1.230.141-novel_ANDROID,ShortPlay,MDLTaskPreload,MDLGroup(novel,1967)",
            "Range": "bytes=0-1023",
            "Accept": "*/*",
        }
        try:
            resp = requests.head(url, headers=headers, timeout=15, allow_redirects=True)
            if resp.status_code in [200, 206] and "Content-Range" in resp.headers:
                return int(resp.headers["Content-Range"].split("/")[-1])
        except Exception:
            return None
        return None

    def scan_hongguo_eid_list(self, full_url_template, scan_range=400):
        from urllib.parse import urlparse, parse_qs
        import time

        parsed = urlparse(full_url_template)
        params = parse_qs(parsed.query)
        try:
            center_eid = int(params.get("eid", ["0"])[0])
        except Exception:
            center_eid = 0
        if center_eid <= 0:
            return []

        base_size = self.get_hongguo_video_size(full_url_template)
        if not base_size or base_size < 500 * 1024:
            return []

        valid_eids = [center_eid]

        consecutive_fails = 0
        for offset in range(1, scan_range + 1):
            eid = center_eid - offset
            test_url = self.modify_hongguo_url_eid(full_url_template, eid)
            size = self.get_hongguo_video_size(test_url)
            if size and size > 500 * 1024:
                valid_eids.append(eid)
                consecutive_fails = 0
            else:
                consecutive_fails += 1
                if consecutive_fails >= 3:
                    break
            time.sleep(0.08)

        consecutive_fails = 0
        for offset in range(1, scan_range + 1):
            eid = center_eid + offset
            test_url = self.modify_hongguo_url_eid(full_url_template, eid)
            size = self.get_hongguo_video_size(test_url)
            if size and size > 500 * 1024:
                valid_eids.append(eid)
                consecutive_fails = 0
            else:
                consecutive_fails += 1
                if consecutive_fails >= 3:
                    break
            time.sleep(0.08)

        valid_eids = sorted(set(valid_eids))
        return valid_eids

    def get_hongguo_episode_url(self, video_id, drama_info, episode_num=1):
        """获取红果短剧指定集数的视频URL
        
        基于逆向分析和抓包结果，尝试多种方法获取视频真实地址
        核心策略：获取预览URL后移除 start/end 参数限制
        """
        import re
        import json
        import time
        
        # 方法1: 通过分享页面获取单集的play_url，然后移除预览限制
        try:
            link_params = drama_info.get("link_params", {})
            series_id = link_params.get("schemeParams", {}).get("video_series_id", "")
            
            if series_id and video_id:
                # 构建单集详情页URL
                detail_page_url = f"https://novelquickapp.com/hongguo/ug/pages/video-detail-share?video_series_id={series_id}&vid={video_id}"
                
                headers = {
                    # 模拟红果APP请求头
                    "User-Agent": "AVDML_2.1.230.141-novel_ANDROID,ShortPlay,MDLTaskPreload,MDLGroup(novel,1967)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Referer": "https://novelquickapp.com/",
                    "X-Tt-Traceid": f"{int(time.time() * 1000)}T{video_id[:5]}",
                    "X-ReqType": "preload",
                }
                
                response = requests.get(detail_page_url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # 从页面中提取视频URL（可能在多个位置）
                    # 模式1: _ROUTER_DATA中的play_url
                    router_data_pattern = r'window\._ROUTER_DATA\s*=\s*(\{.*?\});?\s*</script>'
                    match = re.search(router_data_pattern, content, re.DOTALL)
                    
                    if match:
                        try:
                            router_data = json.loads(match.group(1))
                            # 尝试多个可能的数据路径
                            page_data = None
                            for key in router_data.get("loaderData", {}):
                                if "video" in key.lower() or "detail" in key.lower():
                                    page_data = router_data["loaderData"][key].get("pageData", {})
                                    if page_data:
                                        break
                            
                            if not page_data:
                                page_data = router_data.get("loaderData", {}).get("video-list-share-ssr_page", {}).get("pageData", {})
                            
                            if page_data:
                                series_data = page_data.get("series_data", {})
                                play_url = series_data.get("play_url", "")
                                
                                if play_url:
                                    # 关键：移除预览限制参数获取完整视频
                                    full_url = self.get_hongguo_full_video_url(play_url)
                                    if full_url:
                                        self.log(f"方法1成功: 获取第 {episode_num} 集完整URL")
                                        return full_url
                        except json.JSONDecodeError:
                            pass
                    
                    # 模式2: 直接在HTML中查找视频URL
                    video_url_patterns = [
                        r'"play_url"\s*:\s*"([^"]+)"',
                        r'"video_url"\s*:\s*"([^"]+)"',
                        r'"main_url"\s*:\s*"([^"]+)"',
                        r'(https?://[^"\s]+qznovel[^"\s]+\.mp4[^"\s]*)',
                    ]
                    
                    for pattern in video_url_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            for url in matches:
                                # 解码可能的转义
                                url = url.replace('\\u0026', '&').replace('\\/', '/')
                                if 'video' in url and ('qznovel' in url or 'byteimg' in url):
                                    full_url = self.get_hongguo_full_video_url(url)
                                    if full_url:
                                        self.log(f"方法1b成功: 从HTML提取第 {episode_num} 集URL")
                                        return full_url
                                        
        except Exception as e:
            self.log(f"方法1失败: {str(e)}")
        
        # 方法2: 从分享列表页获取（使用video_id请求特定集）
        try:
            link_params = drama_info.get("link_params", {})
            series_id = link_params.get("schemeParams", {}).get("video_series_id", "")
            
            if series_id:
                share_page_url = f"https://novelquickapp.com/hongguo/ug/pages/video-list-share-ssr?video_series_id={series_id}&vid={video_id}"
                
                headers = {
                    "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Referer": "https://novelquickapp.com/",
                }
                
                response = requests.get(share_page_url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    content = response.text
                    
                    router_data_pattern = r'window\._ROUTER_DATA\s*=\s*(\{.*?\});?\s*</script>'
                    match = re.search(router_data_pattern, content, re.DOTALL)
                    
                    if match:
                        try:
                            router_data = json.loads(match.group(1))
                            page_data = router_data.get("loaderData", {}).get("video-list-share-ssr_page", {}).get("pageData", {})
                            series_data = page_data.get("series_data", {})
                            play_url = series_data.get("play_url", "")
                            
                            if play_url:
                                full_url = self.get_hongguo_full_video_url(play_url)
                                if full_url:
                                    self.log(f"方法2成功: 获取第 {episode_num} 集完整URL")
                                    return full_url
                        except:
                            pass
        except Exception as e:
            self.log(f"方法2失败: {str(e)}")
        
        # 方法3: 尝试红果短剧官方API
        try:
            api_endpoints = [
                ("https://reading.snssdk.com/novel/player/video_model/v1/", "POST"),
                ("https://novel.snssdk.com/novel/player/video_model/v1/", "POST"),
                ("https://api.hongguosp.com/api/video/detail", "GET"),
            ]
            
            app_headers = {
                "User-Agent": "AVDML_2.1.230.141-novel_ANDROID,ShortPlay,MDLTaskPreload,MDLGroup(novel,1967)",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Tt-Traceid": f"{int(time.time() * 1000)}T{video_id[:8] if video_id else 'unknown'}",
            }
            
            payload = {
                "video_id": str(video_id),
                "content_type": 1,
                "app_id": "8662",
                "device_id": str(int(time.time() * 1000)),
            }
            
            for api_url, method in api_endpoints:
                try:
                    if method == "POST":
                        resp = requests.post(api_url, headers=app_headers, json=payload, timeout=10)
                    else:
                        resp = requests.get(api_url, headers=app_headers, params={"video_id": video_id}, timeout=10)
                    
                    if resp.status_code == 200:
                        data = resp.json()
                        video_url = (
                            data.get("data", {}).get("main_url") or
                            data.get("data", {}).get("play_url") or
                            data.get("data", {}).get("url") or
                            data.get("main_url") or
                            data.get("play_url")
                        )
                        if video_url:
                            full_url = self.get_hongguo_full_video_url(video_url)
                            if full_url:
                                self.log(f"方法3成功: 从API获取第 {episode_num} 集URL")
                                return full_url
                except:
                    continue
        except Exception as e:
            self.log(f"方法3失败: {str(e)}")
        
        # 方法4: 尝试修改第一集URL中的参数
        try:
            first_url = drama_info.get("first_episode_url", "")
            if first_url and video_id:
                chapter_ids = drama_info.get("chapter_ids", [])
                if chapter_ids:
                    first_vid = chapter_ids[0]
                    if first_vid and first_vid != video_id:
                        # 尝试替换video_id
                        new_url = first_url.replace(first_vid, video_id)
                        
                        # 验证URL有效性
                        test_headers = {
                            "User-Agent": "AVDML_2.1.230.141-novel_ANDROID,ShortPlay",
                            "Range": "bytes=0-1023",
                        }
                        test_resp = requests.head(new_url, headers=test_headers, timeout=10, allow_redirects=True)
                        if test_resp.status_code in [200, 206]:
                            full_url = self.get_hongguo_full_video_url(new_url)
                            if full_url:
                                self.log(f"方法4成功: URL替换获取第 {episode_num} 集")
                                return full_url
        except Exception as e:
            self.log(f"方法4失败: {str(e)}")
        
        # 方法5: 如果是第一集，直接使用drama_info中的URL并移除限制
        if episode_num == 1:
            first_url = drama_info.get("first_episode_url", "")
            if first_url:
                full_url = self.get_hongguo_full_video_url(first_url)
                if full_url:
                    self.log(f"方法5: 使用第一集URL（已移除预览限制）")
                    return full_url
        
        self.log(f"警告: 无法获取第 {episode_num} 集的完整URL")
        return None

    def download_hongguo_drama(self, url, download_all=False, start_episode=1, end_episode=None, full_url_template=None):
        """下载红果短剧
        
        Args:
            url: 分享链接URL
            download_all: 是否下载全部集数
            start_episode: 起始集数（从1开始）
            end_episode: 结束集数（None表示下载到最后）
            full_url_template: 可选，抓包获取的完整版视频URL模板（reading-video.qznovelvod.com）
        """
        try:
            self.log(f"开始解析红果短剧链接: {url}")
            
            # 获取短剧信息
            drama_info = self.get_hongguo_drama_info(url)
            
            if not drama_info:
                self.queue.put(("error", "无法获取红果短剧信息"))
                return
            
            title = drama_info["title"]
            total_episodes = drama_info["total_episodes"]
            chapter_ids = drama_info["chapter_ids"]
            first_episode_url = drama_info["first_episode_url"]
            
            self.log(f"短剧《{title}》共 {total_episodes} 集")
            
            # 创建短剧专用目录
            import re
            safe_title = re.sub(r'[<>:"/\\|?*]', '_', title)
            drama_dir = os.path.join(self.download_dir, f"红果短剧_{safe_title}")
            if not os.path.exists(drama_dir):
                os.makedirs(drama_dir, exist_ok=True)
            
            # 确定下载范围
            if download_all:
                episodes_to_download = list(range(1, total_episodes + 1))
            else:
                # 默认只下载第一集（可以通过GUI让用户选择）
                if end_episode is None:
                    end_episode = start_episode
                episodes_to_download = list(range(start_episode, min(end_episode + 1, total_episodes + 1)))
            
            self.log(f"准备下载第 {episodes_to_download[0]} 到第 {episodes_to_download[-1]} 集")
            
            eid_list = None
            if full_url_template and self.is_hongguo_full_cdn_url(full_url_template):
                self.log("检测到用户提供了完整版URL模板，正在扫描可用集数范围...")
                eid_list = self.scan_hongguo_eid_list(full_url_template)
                if eid_list:
                    self.log(f"扫描到可用eid数量: {len(eid_list)}，范围: {eid_list[0]} - {eid_list[-1]}")
                    if total_episodes and len(eid_list) < total_episodes:
                        self.log(f"警告: 扫描到的集数({len(eid_list)})少于页面标注集数({total_episodes})，将按扫描结果下载")
                else:
                    self.log("扫描失败：模板URL可能已过期或不可用，将回退到分享页预览URL下载")

            success_count = 0
            fail_count = 0
            
            for ep_num in episodes_to_download:
                try:
                    self.log(f"正在下载第 {ep_num}/{total_episodes} 集...")
                    
                    # 更新进度
                    progress = ((ep_num - episodes_to_download[0]) / len(episodes_to_download)) * 100
                    self.queue.put(("progress", {"percent": progress, "status": f"正在下载第 {ep_num}/{total_episodes} 集..."}))
                    
                    video_url = None
                    if eid_list and (ep_num - 1) < len(eid_list):
                        eid = eid_list[ep_num - 1]
                        video_url = self.modify_hongguo_url_eid(full_url_template, eid)
                    else:
                        if ep_num - 1 < len(chapter_ids):
                            video_id = chapter_ids[ep_num - 1]
                            video_url = self.get_hongguo_episode_url(video_id, drama_info, ep_num)
                        else:
                            self.log(f"第 {ep_num} 集ID不存在")
                            fail_count += 1
                            continue
                    
                    if not video_url:
                        # 如果获取失败，使用第一集URL并移除预览限制作为备用
                        self.log(f"无法获取第 {ep_num} 集的视频URL，尝试使用备用方案...")
                        video_url = self.get_hongguo_full_video_url(first_episode_url)
                        if not video_url:
                            self.log(f"第 {ep_num} 集备用方案也失败")
                            fail_count += 1
                            continue
                    
                    # 下载视频
                    filename = f"{safe_title}_第{ep_num:02d}集.mp4"
                    filepath = os.path.join(drama_dir, filename)
                    
                    # 检查是否已存在
                    if os.path.exists(filepath):
                        file_size = os.path.getsize(filepath)
                        if file_size > 100 * 1024:  # 大于100KB视为有效
                            self.log(f"第 {ep_num} 集已存在，跳过")
                            success_count += 1
                            continue
                    
                    # 使用APP的User-Agent下载视频（模拟红果APP请求）
                    download_headers = {
                        "User-Agent": "AVDML_2.1.230.141-novel_ANDROID,ShortPlay,MDLTaskPreload,MDLGroup(novel,1967)",
                        "Accept": "*/*",
                        "Accept-Encoding": "identity",
                        "Connection": "keep-alive",
                        "Referer": "https://novelquickapp.com/",
                        "X-ReqType": "download",
                    }
                    
                    self.log(f"下载URL: {video_url[:100]}...")
                    
                    response = requests.get(video_url, headers=download_headers, stream=True, timeout=120)
                    response.raise_for_status()
                    
                    # 获取文件大小
                    total_size = int(response.headers.get('content-length', 0))
                    downloaded_size = 0
                    
                    with open(filepath, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                                downloaded_size += len(chunk)
                                
                                # 更新下载进度
                                if total_size > 0:
                                    chunk_progress = (downloaded_size / total_size) * 100
                                    overall_progress = ((ep_num - episodes_to_download[0] + chunk_progress/100) / len(episodes_to_download)) * 100
                                    size_mb = downloaded_size / (1024 * 1024)
                                    total_mb = total_size / (1024 * 1024)
                                    self.queue.put(("progress", {"percent": overall_progress, "status": f"第 {ep_num} 集: {size_mb:.1f}/{total_mb:.1f} MB"}))
                    
                    # 验证下载
                    if os.path.exists(filepath) and os.path.getsize(filepath) > 100 * 1024:
                        self.log(f"✓ 第 {ep_num} 集下载完成: {filename}")
                        success_count += 1
                    else:
                        self.log(f"✗ 第 {ep_num} 集下载失败：文件太小")
                        fail_count += 1
                        if os.path.exists(filepath):
                            os.remove(filepath)
                    
                except Exception as e:
                    self.log(f"✗ 第 {ep_num} 集下载失败: {str(e)}")
                    fail_count += 1
            
            # 完成统计
            self.queue.put(("progress", {"percent": 100, "status": "下载完成!"}))
            
            result_msg = f"红果短剧《{title}》下载完成！\n成功: {success_count} 集, 失败: {fail_count} 集\n保存位置: {drama_dir}"
            self.log(result_msg)
            
            if success_count > 0:
                self.queue.put(("complete", result_msg))
            else:
                self.queue.put(("error", f"红果短剧下载失败，没有成功下载任何集数"))
                
        except Exception as e:
            error_msg = f"红果短剧下载出错: {str(e)}"
            self.log(error_msg)
            import traceback
            self.log(f"错误详情: {traceback.format_exc()}")
            self.queue.put(("error", error_msg))

    def show_hongguo_download_dialog(self, url):
        """显示红果短剧下载选项对话框"""
        try:
            # 先获取短剧信息
            drama_info = self.get_hongguo_drama_info(url)
            
            if not drama_info:
                self.queue.put(("error", "无法获取红果短剧信息"))
                return
            
            title = drama_info["title"]
            total_episodes = drama_info["total_episodes"]
            
            # 创建对话框
            dialog = tk.Toplevel(self.root)
            dialog.title("红果短剧下载")
            dialog.geometry("420x480")
            dialog.resizable(False, False)
            dialog.transient(self.root)
            dialog.grab_set()
            
            # 居中显示
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() - 420) // 2
            y = (dialog.winfo_screenheight() - 480) // 2
            dialog.geometry(f"420x480+{x}+{y}")
            
            # 短剧信息
            info_frame = ttk.LabelFrame(dialog, text="短剧信息", padding="10")
            info_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Label(info_frame, text=f"标题: {title}").pack(anchor=tk.W)
            ttk.Label(info_frame, text=f"总集数: {total_episodes} 集").pack(anchor=tk.W)
            ttk.Label(info_frame, text=f"分类: {drama_info.get('category', '未知')}").pack(anchor=tk.W)
            
            # 下载选项
            option_frame = ttk.LabelFrame(dialog, text="下载选项", padding="10")
            option_frame.pack(fill=tk.X, padx=10, pady=10)
            
            download_option = tk.StringVar(value="first")
            
            ttk.Radiobutton(option_frame, text="只下载第1集", variable=download_option, value="first").pack(anchor=tk.W)
            ttk.Radiobutton(option_frame, text="下载全部集数", variable=download_option, value="all").pack(anchor=tk.W)
            
            # 自定义范围
            range_frame = ttk.Frame(option_frame)
            range_frame.pack(anchor=tk.W, pady=5)
            
            ttk.Radiobutton(range_frame, text="自定义范围:", variable=download_option, value="custom").pack(side=tk.LEFT)
            
            start_var = tk.StringVar(value="1")
            end_var = tk.StringVar(value=str(min(5, total_episodes)))
            
            ttk.Entry(range_frame, textvariable=start_var, width=5).pack(side=tk.LEFT, padx=5)
            ttk.Label(range_frame, text="到").pack(side=tk.LEFT)
            ttk.Entry(range_frame, textvariable=end_var, width=5).pack(side=tk.LEFT, padx=5)
            ttk.Label(range_frame, text="集").pack(side=tk.LEFT)

            template_frame = ttk.LabelFrame(dialog, text="完整版模板（可选）", padding="10")
            template_frame.pack(fill=tk.BOTH, padx=10, pady=10, expand=True)
            ttk.Label(
                template_frame,
                text="粘贴任意一集的完整版链接（v*-reading-video.qznovelvod.com），可下载完整视频；留空则下载30秒预览。",
                wraplength=380,
            ).pack(anchor=tk.W)
            template_text = tk.Text(template_frame, height=4, wrap=tk.WORD)
            template_text.pack(fill=tk.BOTH, expand=True, pady=6)

            status_row = ttk.Frame(template_frame)
            status_row.pack(fill=tk.X)
            status_label = ttk.Label(status_row, text="未启动自动捕获")
            status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
            ttk.Button(status_row, text="自动捕获模板", command=self.start_hongguo_frida_capture).pack(side=tk.RIGHT, padx=(6, 0))
            ttk.Button(status_row, text="停止捕获", command=self.stop_hongguo_frida_capture).pack(side=tk.RIGHT)

            self._hongguo_template_text_widget = template_text
            self._hongguo_template_status_label = status_label
            self._hongguo_template_dialog = dialog
            if self._hongguo_last_template_url:
                try:
                    template_text.delete("1.0", tk.END)
                    template_text.insert(tk.END, self._hongguo_last_template_url)
                    status_label.config(text="已捕获到模板，可直接下载")
                except Exception:
                    pass
            
            # 按钮
            btn_frame = ttk.Frame(dialog)
            btn_frame.pack(fill=tk.X, padx=10, pady=20)
            
            def on_download():
                self.stop_hongguo_frida_capture()
                self._hongguo_template_text_widget = None
                self._hongguo_template_status_label = None
                self._hongguo_template_dialog = None
                dialog.destroy()
                
                option = download_option.get()
                full_url_template = template_text.get("1.0", tk.END).strip() or None
                if option == "first":
                    threading.Thread(
                        target=self.download_hongguo_drama,
                        args=(url, False, 1, 1, full_url_template),
                        daemon=True
                    ).start()
                elif option == "all":
                    threading.Thread(
                        target=self.download_hongguo_drama,
                        args=(url, True, 1, None, full_url_template),
                        daemon=True
                    ).start()
                else:  # custom
                    try:
                        start = int(start_var.get())
                        end = int(end_var.get())
                        if start < 1:
                            start = 1
                        if end > total_episodes:
                            end = total_episodes
                        if start > end:
                            start, end = end, start
                        threading.Thread(
                            target=self.download_hongguo_drama,
                            args=(url, False, start, end, full_url_template),
                            daemon=True
                        ).start()
                    except ValueError:
                        messagebox.showerror("错误", "请输入有效的集数")
                        return
            
            def on_cancel():
                self.stop_hongguo_frida_capture()
                self._hongguo_template_text_widget = None
                self._hongguo_template_status_label = None
                self._hongguo_template_dialog = None
                dialog.destroy()
                # 重新启用下载按钮
                self.download_btn.config(state=tk.NORMAL)
                self.progress_label.config(text="已取消")
            
            def on_close():
                """处理窗口关闭按钮点击"""
                on_cancel()
            
            # 绑定窗口关闭事件
            dialog.protocol("WM_DELETE_WINDOW", on_close)
            
            ttk.Button(btn_frame, text="开始下载", command=on_download).pack(side=tk.LEFT, expand=True, padx=5)
            ttk.Button(btn_frame, text="取消", command=on_cancel).pack(side=tk.LEFT, expand=True, padx=5)
            
        except Exception as e:
            self.log(f"显示下载对话框失败: {str(e)}")
            self.queue.put(("error", f"无法显示下载选项: {str(e)}"))
            # 出错时也要重新启用下载按钮
            self.download_btn.config(state=tk.NORMAL)

    def download_suno_song(self, url):
        """下载单个Suno歌曲 - 基于SunoSync原理的实现"""
        try:
            self.log(f"开始下载Suno歌曲: {url}")

            # 提取Suno歌曲ID
            song_id = self.extract_suno_song_id(url)
            if not song_id:
                error_msg = "无法提取Suno歌曲ID"
                self.log(error_msg)
                self.queue.put(("error", error_msg))
                return

            self.log(f"提取到Suno歌曲ID: {song_id}")

            # 1. 构建完整的Suno分享链接
            share_url = f"https://suno.com/s/{song_id}"
            self.log(f"使用分享链接: {share_url}")

            # 2. 使用视频高速下载神器获取页面信息，但不直接下载
            self.log(f"使用视频高速下载神器获取页面信息...")
            ydl_opts = {
                "quiet": True,
                "no_warnings": True,
                "skip_download": True,
                "extractor_args": {
                    "generic": {
                        "impersonate": "chrome",
                        "referer": share_url,
                    }
                },
                "http_headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            }

            with YoutubeDL(ydl_opts) as ydl:
                info_dict = ydl.extract_info(share_url, download=False)

            # 3. 从info_dict中提取标题
            song_title = info_dict.get("title", f"suno_song_{song_id}")
            # 清理标题中的非法字符，特别是Windows系统中的斜杠
            import re

            song_title = re.sub(r'[\\/:*?"<>|]', "_", song_title)
            self.log(f"获取到歌曲标题: {song_title}")

            # 4. 构建完整的音频URL
            # 基于SunoSync的原理，我们需要直接构建音频URL
            # 根据观察，Suno的音频URL格式为: https://cdn1.suno.ai/{song_id}.mp3
            # 或者: https://cdn2.suno.ai/{song_id}.mp3

            # 尝试两个CDN服务器
            cdn_servers = ["cdn1", "cdn2"]
            audio_url = None

            for cdn in cdn_servers:
                test_url = f"https://{cdn}.suno.ai/{song_id}.mp3"
                self.log(f"尝试音频URL: {test_url}")

                try:
                    # 测试URL是否可访问
                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Referer": share_url,
                        "Origin": "https://suno.com",
                    }

                    import requests

                    # 使用HEAD请求检查URL是否可访问
                    response = requests.head(
                        test_url, headers=headers, timeout=10, allow_redirects=True
                    )
                    if response.status_code == 200:
                        audio_url = test_url
                        self.log(f"找到可用音频URL: {audio_url}")
                        break
                except Exception as e:
                    self.log(f"测试URL失败: {str(e)}")
                    continue

            # 如果没有找到，尝试另一种URL格式
            if not audio_url:
                # 尝试使用song_id的UUID部分
                if "-" in song_id:
                    uuid_part = song_id.split("-")[0]
                    for cdn in cdn_servers:
                        test_url = f"https://{cdn}.suno.ai/{uuid_part}.mp3"
                        self.log(f"尝试另一种URL格式: {test_url}")

                        try:
                            headers = {
                                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                                "Referer": share_url,
                                "Origin": "https://suno.com",
                            }

                            response = requests.head(
                                test_url,
                                headers=headers,
                                timeout=10,
                                allow_redirects=True,
                            )
                            if response.status_code == 200:
                                audio_url = test_url
                                self.log(f"找到可用音频URL: {audio_url}")
                                break
                        except Exception as e:
                            self.log(f"测试URL失败: {str(e)}")
                            continue

            if not audio_url:
                # 最后尝试使用页面重定向后的URL中的UUID
                import re

                final_url = info_dict.get("webpage_url", share_url)
                uuid_match = re.search(
                    r"/song/(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})", final_url
                )
                if uuid_match:
                    uuid = uuid_match.group(1)
                    for cdn in cdn_servers:
                        test_url = f"https://{cdn}.suno.ai/{uuid}.mp3"
                        self.log(f"尝试使用UUID URL: {test_url}")

                        try:
                            headers = {
                                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                                "Referer": share_url,
                                "Origin": "https://suno.com",
                            }

                            response = requests.head(
                                test_url,
                                headers=headers,
                                timeout=10,
                                allow_redirects=True,
                            )
                            if response.status_code == 200:
                                audio_url = test_url
                                self.log(f"找到可用音频URL: {audio_url}")
                                break
                        except Exception as e:
                            self.log(f"测试URL失败: {str(e)}")
                            continue

            if not audio_url:
                error_msg = "无法找到可用的音频URL"
                self.log(error_msg)
                self.queue.put(("error", error_msg))
                return

            # 5. 生成唯一文件名
            import time
            import uuid as uuid_lib

            timestamp = str(int(time.time()))
            unique_id = str(uuid_lib.uuid4()).replace("-", "")[:8]
            filename = f"suno_{song_title}_{song_id}_{timestamp}_{unique_id}.mp3"
            file_path = os.path.join(self.download_dir, filename)

            # 6. 准备下载头
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "identity",
                "Origin": "https://suno.com",
                "Referer": share_url,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "audio",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "same-origin",
            }

            # 7. 开始流式下载
            self.log(f"开始下载音频文件: {filename}")

            max_retries = 3
            download_success = False

            for attempt in range(max_retries):
                try:
                    with requests.get(
                        audio_url,
                        stream=True,
                        headers=headers,
                        timeout=60,
                        allow_redirects=True,
                    ) as response:
                        response.raise_for_status()

                        # 获取文件大小
                        total_size = int(response.headers.get("content-length", 0))
                        if total_size == 0:
                            self.log("警告: 无法获取文件大小")
                        else:
                            self.log(f"文件大小: {total_size / (1024 * 1024):.1f} MB")

                        # 开始写入文件
                        downloaded = 0
                        with open(file_path, "wb") as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                                    downloaded += len(chunk)

                                    # 计算进度百分比
                                    percent = (
                                        (downloaded / total_size) * 100
                                        if total_size > 0
                                        else 0
                                    )

                                    # 发送进度更新
                                    self.queue.put(
                                        (
                                            "progress",
                                            {
                                                "percent": percent,
                                                "filename": filename,
                                                "status": f"下载中: {filename} | {percent:.1f}% | 已下载: {downloaded / (1024 * 1024):.1f}MB / {total_size / (1024 * 1024):.1f}MB",
                                            },
                                        )
                                    )

                        # 验证文件大小
                        if (
                            os.path.getsize(file_path) < 1024 * 100
                        ):  # 小于100KB视为不完整
                            self.log(
                                f"警告: 下载的文件可能不完整，大小: {os.path.getsize(file_path)} 字节"
                            )
                            os.remove(file_path)
                            if attempt < max_retries - 1:
                                self.log(f"重试下载 ({attempt + 2}/{max_retries})...")
                                continue
                            else:
                                raise Exception("下载的文件不完整")

                    download_success = True
                    break
                except Exception as e:
                    if attempt < max_retries - 1:
                        self.log(
                            f"下载失败，重试 ({attempt + 2}/{max_retries}): {str(e)}"
                        )
                    else:
                        raise

            if not download_success:
                error_msg = "下载失败，已达到最大重试次数"
                self.log(error_msg)
                self.queue.put(("error", error_msg))
                return

            # 8. 验证下载结果
            self._verify_downloaded_file(
                {"filepath": file_path, "ext": "mp3"}, song_title, song_id
            )

            self.log(f"Suno歌曲下载完成: {filename}")
            self.queue.put(("complete", "Suno歌曲下载成功完成！"))
        except Exception as e:
            error_msg = f"Suno歌曲下载出错: {str(e)}"
            self.log(error_msg)
            self.queue.put(("error", error_msg))

    def _fetch_suno_page_data(self, url):
        """从Suno页面获取标题和音频URL"""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            }

            import requests
            import re

            # 使用requests获取页面内容，允许重定向
            session = requests.Session()
            response = session.get(
                url, headers=headers, timeout=30, allow_redirects=True
            )
            response.raise_for_status()
            page_content = response.text
            final_url = response.url

            self.log(f"最终URL: {final_url}")

            # 解析页面内容，提取标题和音频URL
            data = {}

            # 提取标题
            title_patterns = [
                r"<title>(.*?) \| Suno</title>",
                r'<meta property="og:title" content="(.*?)"',
                r'<meta name="title" content="(.*?)"',
            ]

            for pattern in title_patterns:
                matches = re.findall(pattern, page_content, re.DOTALL | re.IGNORECASE)
                if matches:
                    title = matches[0].strip()
                    # 清理标题中的HTML标签
                    title = re.sub(r"<[^>]*>", "", title)
                    # 清理特殊字符
                    title = re.sub(r"[^a-zA-Z0-9\u4e00-\u9fa5\-_ ]", "_", title)
                    title = title[:100]  # 限制标题长度
                    data["title"] = title
                    break

            # 提取音频URL - 使用多种策略
            audio_url = None

            # 策略1: 查找CDN URL模式
            cdn_patterns = [
                r'https://cdn[12]\.suno\.ai[^\s"\']+\.mp3[^\s"\']*',
                r'https://.*?suno.*?\.mp3[^\s"\']*',
            ]

            for pattern in cdn_patterns:
                audio_matches = re.findall(
                    pattern, page_content, re.DOTALL | re.IGNORECASE
                )
                if audio_matches:
                    audio_url = audio_matches[0]
                    self.log(f"策略1找到音频URL: {audio_url}")
                    break

            # 策略2: 查找JavaScript中的音频URL
            if not audio_url:
                js_patterns = [
                    r'audioUrl\s*[:=]\s*["\']([^"\']+\.mp3[^"\']*)["\']',
                    r'audio_url\s*[:=]\s*["\']([^"\']+\.mp3[^"\']*)["\']',
                    r'"audio_url"\s*:\s*["\']([^"\']+\.mp3[^"\']*)["\']',
                    r"clip\s*[:=]\s*({[^}]+})",
                ]

                for js_pattern in js_patterns:
                    js_matches = re.findall(
                        js_pattern, page_content, re.DOTALL | re.IGNORECASE
                    )
                    for js_match in js_matches:
                        if isinstance(js_match, str):
                            # 如果匹配到的是整个JavaScript对象，再从中提取音频URL
                            if "{" in js_match and "}" in js_match:
                                audio_url_pattern = (
                                    r'audio_url\s*:\s*["\']([^"\']+\.mp3[^"\']*)["\']'
                                )
                                audio_url_matches = re.findall(
                                    audio_url_pattern,
                                    js_match,
                                    re.DOTALL | re.IGNORECASE,
                                )
                                if audio_url_matches:
                                    audio_url = audio_url_matches[0]
                                    self.log(f"策略2找到音频URL: {audio_url}")
                                    break
                            else:
                                # 直接匹配到了音频URL
                                audio_url = js_match
                                self.log(f"策略2找到音频URL: {audio_url}")
                                break
                    if audio_url:
                        break

            # 策略3: 尝试从页面中提取JSON数据
            if not audio_url:
                json_patterns = [
                    r"<script[^>]*>\s*window\.__PRELOADED_STATE__\s*=\s*({[^<]+})\s*</script>",
                    r"<script[^>]*>\s*window\.initialProps\s*=\s*({[^<]+})\s*</script>",
                ]

                for json_pattern in json_patterns:
                    json_matches = re.findall(json_pattern, page_content, re.DOTALL)
                    if json_matches:
                        import json

                        try:
                            json_data = json.loads(json_matches[0])

                            # 递归查找音频URL
                            def find_audio_url(obj):
                                if isinstance(obj, dict):
                                    for key, value in obj.items():
                                        if (
                                            key in ["audio_url", "audioUrl", "url"]
                                            and isinstance(value, str)
                                            and value.endswith(".mp3")
                                        ):
                                            return value
                                        result = find_audio_url(value)
                                        if result:
                                            return result
                                elif isinstance(obj, list):
                                    for item in obj:
                                        result = find_audio_url(item)
                                        if result:
                                            return result
                                return None

                            audio_url = find_audio_url(json_data)
                            if audio_url:
                                self.log(f"策略3找到音频URL: {audio_url}")
                                break
                        except json.JSONDecodeError:
                            self.log("JSON解析失败")

            if audio_url:
                # 清理URL中的转义字符
                audio_url = audio_url.replace("\\/", "/")
                data["audio_url"] = audio_url

            return data if data else None
        except Exception as e:
            self.log(f"获取Suno页面数据失败: {str(e)}")
            import traceback

            self.log(f"错误详情: {traceback.format_exc()}")
            return None

    def _get_suno_song_info(self, song_id):
        """从Suno API获取完整的歌曲信息"""
        try:
            # 使用Suno的clip API获取完整信息
            api_url = f"https://studio-api.prod.suno.com/api/clip/{song_id}"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
                "Origin": "https://suno.com",
                "Referer": f"https://suno.com/s/{song_id}",
            }

            response = requests.get(api_url, headers=headers, timeout=30)
            if response.status_code != 200:
                return None

            clip_data = response.json()

            # 提取有用的歌曲信息
            song_info = {
                "title": clip_data.get("title"),
                "artist": f"{clip_data.get('display_name', '')} (@{clip_data.get('handle', '')})".strip(),
                "audio_url": clip_data.get("audio_url"),
                "cover_url": clip_data.get("image_large_url")
                or clip_data.get("image_url"),
                "lyrics": clip_data.get("metadata", {}).get("prompt"),
                "duration": clip_data.get("metadata", {}).get("duration"),
                "model_version": clip_data.get("major_model_version"),
                "styles": clip_data.get("metadata", {}).get("tags"),
            }

            return song_info
        except Exception as e:
            self.log(f"从API获取歌曲信息失败: {str(e)}")
            return None

    def _get_suno_song_title(self, url):
        """从Suno页面获取正确的歌曲标题"""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }

            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()

            # 使用正则表达式从页面中提取歌曲标题
            import re

            # 尝试多种可能的标题提取模式
            title_patterns = [
                r"<title>(.*?) \| Suno</title>",
                r'<meta property="og:title" content="(.*?)"',
                r'<meta name="title" content="(.*?)"',
                r"<h1[^>]*>(.*?)</h1>",
                r'data-testid="song-title">(.*?)</div>',
            ]

            for pattern in title_patterns:
                matches = re.findall(pattern, response.text, re.DOTALL)
                if matches:
                    title = matches[0].strip()
                    # 清理标题中的HTML标签
                    title = re.sub(r"<[^>]*>", "", title)
                    # 清理特殊字符
                    title = re.sub(r"[^a-zA-Z0-9\u4e00-\u9fa5\-_ ]", "_", title)
                    return title[:100]  # 限制标题长度

            return None
        except Exception as e:
            self.log(f"获取歌曲标题失败: {str(e)}")
            return None

    def _verify_downloaded_file(self, info_dict, song_title, song_id):
        """验证下载的文件是否完整"""
        try:
            # 获取下载的文件路径
            if "filepath" in info_dict:
                file_path = info_dict["filepath"]
                self.log(f"使用info_dict中的文件路径: {file_path}")
            else:
                # 构建文件路径，使用与yt-dlp配置相同的模板
                import time

                ext = info_dict.get("ext", "mp3")
                epoch = str(int(time.time()))
                file_path = os.path.join(
                    self.download_dir, f"suno_{song_title}_{song_id}_{epoch}.{ext}"
                )
                self.log(f"构建的文件路径: {file_path}")

            # 检查文件是否存在
            if not os.path.exists(file_path):
                # 尝试查找实际下载的文件
                import glob

                pattern = os.path.join(self.download_dir, f"suno_*{song_id}*.{ext}")
                matching_files = glob.glob(pattern)
                if matching_files:
                    file_path = matching_files[0]
                    self.log(f"找到匹配的文件: {file_path}")
                else:
                    raise Exception(f"下载文件不存在，模式: {pattern}")

            # 检查文件大小
            file_size = os.path.getsize(file_path)
            self.log(f"验证下载文件: {file_path}, 大小: {file_size} 字节")

            # 如果文件太小，给出警告
            if file_size < 1024 * 100:  # 小于100KB视为不完整
                self.log(f"警告: 下载的文件可能不完整，大小: {file_size} 字节")
            else:
                self.log(f"文件下载完整，大小: {file_size / (1024 * 1024):.2f} MB")

        except Exception as e:
            self.log(f"验证下载文件失败: {str(e)}")

    def download_suno_playlist(self, playlist_id):
        """下载Suno播放列表"""
        try:
            self.log(f"开始下载Suno播放列表: {playlist_id}")
            self.log("Suno播放列表下载功能正在开发中，敬请期待...")

            self.queue.put(("error", "Suno播放列表下载功能正在开发中，敬请期待"))
        except Exception as e:
            error_msg = f"Suno播放列表下载出错: {str(e)}"
            self.log(error_msg)
            self.queue.put(("error", error_msg))

    def download_video(self, url, format_str):
        """在后台线程中下载视频，根据平台和视频大小选择不同的下载模式"""
        try:
            # 检测URL平台类型
            is_tiktok = "tiktok.com/" in url or "vm.tiktok.com/" in url
            is_bilibili = "bilibili.com/" in url or "b23.tv/" in url
            is_sora = (
                "sora.chatgpt.com/p/" in url
                or url.startswith("s_")
                or "sorapure.vercel.app" in url
            )
            is_suno_song = (
                "suno.ai/song/" in url
                or "suno.com/song/" in url
                or "suno.com/s/" in url
            )
            is_suno_playlist = (
                "suno.ai/playlists/" in url or "suno.com/playlists/" in url
            )
            is_instagram = (
                "instagram.com/reels/" in url
                or "instagram.com/reel/" in url
                or "instagram.com/p/" in url
                or "instagram.com/tv/" in url
                or "www.instagram.com/reels/" in url
                or "www.instagram.com/reel/" in url
                or "www.instagram.com/p/" in url
                or "www.instagram.com/tv/" in url
            )
            is_youtube = (
                "youtube.com/watch?v=" in url
                or "youtu.be/" in url
                or "youtube.com/shorts/" in url
                or "www.youtube.com/watch?v=" in url
                or "www.youtu.be/" in url
                or "www.youtube.com/shorts/" in url
            )
            is_hongguo = (
                "novelquickapp.com/s/" in url
                or "novelquickapp.com/hongguo/" in url
            )

            # Sora2视频下载逻辑
            if is_sora:
                # 转换Sora2视频ID为完整URL和提取视频ID
                if url.startswith("s_"):
                    video_id = url
                    sora_url = f"https://sora.chatgpt.com/p/{url}"
                elif "sorapure.vercel.app" in url:
                    video_id = self.extract_sora_video_id(url)
                    sora_url = f"https://sora.chatgpt.com/p/{video_id}"
                elif "sora.chatgpt.com/p/" in url:
                    video_id = self.extract_sora_video_id(url)
                    sora_url = url
                else:
                    self.queue.put(("error", "无法识别的Sora2 URL格式"))
                    return

                # 使用自定义的Sora2下载方法，避免yt-dlp的Cloudflare问题
                self.log("检测到Sora2视频，将使用自定义下载方法")
                self.download_sora_video(video_id)
                return

            # Suno歌曲下载逻辑
            elif is_suno_song:
                # 直接使用原始URL下载，不提取ID，避免URL构建错误
                self.download_suno_song(url)
                return

            # Suno播放列表下载逻辑
            elif is_suno_playlist:
                playlist_id = self.extract_suno_playlist_id(url)
                if not playlist_id:
                    self.queue.put(("error", "无法提取Suno播放列表ID"))
                    return

                # 使用Suno播放列表专用下载方法
                self.download_suno_playlist(playlist_id)
                return

            # 红果短剧下载逻辑
            elif is_hongguo:
                self.log("检测到红果短剧链接，将使用专用下载方法")
                # 在主线程中显示对话框，让用户选择下载选项
                self.root.after(0, lambda: self.show_hongguo_download_dialog(url))
                return

            # 其他平台下载逻辑
            # 首先获取视频信息
            self.log("正在获取视频信息...")
            info_dict = self.get_video_info(url)

            if not info_dict:
                self.queue.put(("error", "无法获取视频信息"))
                return

            # 获取视频大小和时长
            video_size = info_dict.get("filesize", 0) or info_dict.get(
                "filesize_approx", 0
            )
            duration = info_dict.get("duration", 0)
            title = info_dict.get("title", "未知视频")

            # 转换为人类可读格式，处理可能的None值
            duration_minutes = duration / 60 if duration else 0
            size_mb = video_size / (1024 * 1024) if video_size else 0

            self.log(
                f"视频信息: {title} | 时长: {duration_minutes:.1f}分钟 | 大小: {size_mb:.1f}MB"
            )

            # 判断是否为大文件/长视频
            # 定义阈值：时长超过30分钟或大小超过500MB视为大文件
            is_large_file = duration_minutes > 30 or size_mb > 500

            if is_large_file:
                self.log("检测到长视频/大文件，将使用优化的下载模式")
            else:
                self.log("检测到短视频/小文件，将使用标准下载模式")

            # 基础配置
            base_opts = {
                "format": format_str,
                "outtmpl": os.path.join(
                    self.download_dir, "%(title)s-%(id)s-%(epoch)s.%(ext)s"
                ),
                "progress_hooks": [self.progress_hook],
                "quiet": True,
                "no_warnings": True,
                "abort_on_error": False,
                "http_headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                # 添加模拟选项，绕过Cloudflare反爬虫
                "extractor_args": {
                    "generic": {
                        "impersonate": "chrome",
                    }
                },
            }
            
            # 检查并设置 FFmpeg 路径（如果存在于程序目录）
            ffmpeg_in_app_dir = os.path.join(self.app_dir, "ffmpeg.exe")
            if os.path.exists(ffmpeg_in_app_dir):
                base_opts["ffmpeg_location"] = self.app_dir
            elif os.path.exists("ffmpeg.exe"):
                base_opts["ffmpeg_location"] = os.getcwd()

            # TikTok特定配置 - 确保无水印下载
            tiktok_opts = {
                "extractor_args": {
                    "tiktok": {
                        "download_format": "hd",  # 优先下载高清格式
                    }
                }
            }

            # Bilibili特定配置 - 使用Chrome浏览器模拟
            # 注意：使用impersonate时不要手动设置http_headers，会导致冲突
            # impersonate会自动模拟Chrome的所有请求特征
            bilibili_opts = {
                "extractor_args": {
                    "generic": {
                        "impersonate": "chrome",  # 自动模拟Chrome浏览器的所有特征
                    },
                    "bilibili": {
                        "danmaku": False,  # 不下载弹幕
                    }
                },
            }

            # YouTube特定配置 - 使用与命令行相同的成功配置
            youtube_opts = {
                # 为YouTube设置chrome模拟，这是最重要的设置
                "extractor_args": {
                    "youtube": {
                        "impersonate": "chrome",
                    }
                },
                # 基础网络配置
                "retries": 3,
                "fragment_retries": 3,
                "skip_unavailable_fragments": True,
                "socket_timeout": 30,
                # 使用简单的格式选择，与命令行保持一致
                "format": "best",
                # 启用hls原生下载器，与命令行保持一致
                "hls_prefer_native": True,
                "hls_prefer_ffmpeg": False,
            }

            # Instagram特定配置 - 解决登录限制问题
            instagram_opts = {
                # 使用chrome模拟
                "extractor_args": {
                    "instagram": {
                        "impersonate": "chrome",
                    }
                },
                # 尝试使用不同的策略绕过登录限制
                "ignore_no_formats_error": True,
                "no_check_certificate": True,
                "http_headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                },
                # 移除自动cookie获取，避免Chrome cookie数据库访问错误
                # 使用更简单的配置，依赖浏览器模拟和HTTP头
                "cookiefile": "cookies.txt",  # 允许用户手动提供cookie文件
            }

            # 根据文件大小和平台选择不同的下载配置
            if is_tiktok:
                # TikTok下载配置 - 专注于无水印高清下载
                # 注意：TikTok 服务器对并发下载非常敏感，需要禁用并发
                self.log("检测到TikTok视频，将使用无水印高清下载模式")
                ydl_opts = {
                    **base_opts,
                    **tiktok_opts,
                    "retries": 10,
                    "fragment_retries": 10,
                    "skip_unavailable_fragments": True,
                    "extractor_retries": 5,
                    "socket_timeout": 60,
                    # 关键：禁用并发下载以避免 403 Forbidden 错误
                    "concurrent_fragment_downloads": 1,
                    # 添加限速（每秒 2MB）避免被服务器限流
                    "ratelimit": 2 * 1024 * 1024,
                    # 使用 HLS 原生下载器
                    "hls_prefer_native": True,
                }
            elif is_bilibili:
                # Bilibili下载配置 - 专注于无水印高清下载
                self.log("检测到Bilibili视频，将使用无水印高清下载模式")
                
                # 检查并安装FFmpeg，返回 FFmpeg 所在目录
                ffmpeg_dir = self.check_and_install_ffmpeg()
                
                # Bilibili视频特点：音视频是分离的，没有任何合并格式
                # 必须使用FFmpeg合并才能得到完整视频
                if ffmpeg_dir is not None:
                    # 有FFmpeg：下载最佳视频和音频，然后自动合并
                    bilibili_format = "bestvideo+bestaudio/bestvideo*+bestaudio*"
                    self.log("已检测到FFmpeg，将使用最佳画质下载（音视频分离后合并）")
                else:
                    # 没有FFmpeg：Bilibili视频无法下载带声音的版本
                    # 提示用户并询问是否只下载视频（无声）
                    self.log("警告：Bilibili视频需要FFmpeg才能下载带声音的版本")
                    
                    msg = "Bilibili视频的音频和视频是分开存储的。\n没有FFmpeg，只能下载：\n\n• 仅视频（无声）\n• 或仅音频\n\n是否继续下载视频（无声）？\n点击[否]取消下载"
                    if not messagebox.askyesno("无法下载完整视频", msg):
                        self.log("用户取消下载")
                        self.queue.put(("error", "需要FFmpeg才能下载Bilibili带声音的视频"))
                        return
                    
                    # 只下载视频（无声）
                    bilibili_format = "bestvideo"
                    self.log("将下载仅视频版本（无声）")
                
                ydl_opts = {
                    **base_opts,
                    **bilibili_opts,
                    "format": bilibili_format,  # 覆盖base_opts中的format
                    "retries": 15,
                    "fragment_retries": 15,
                    "skip_unavailable_fragments": True,
                    "extractor_retries": 5,
                    "socket_timeout": 60,
                }
                
                # 如果 FFmpeg 在特定目录，设置 ffmpeg_location
                if ffmpeg_dir:  # 非空字符串表示有指定目录
                    ydl_opts["ffmpeg_location"] = ffmpeg_dir
                    self.log(f"FFmpeg 路径: {ffmpeg_dir}")
            elif is_youtube:
                # YouTube下载 - 使用 aria2c 外部下载器加速
                self.log("检测到YouTube视频，正在初始化高速下载模式...")
                try:
                    # 注意：不要在这里重复导入 YoutubeDL！
                    # 函数内的局部导入会导致 Python 将 YoutubeDL 视为局部变量，
                    # 从而使其他分支（如 Bilibili）无法访问文件顶部的全局导入。
                    
                    # 使用改进的URL清理方法，移除时间戳等非必要参数
                    clean_url = self._sanitize_url(url)
                    self.log(f"清理后的URL: {clean_url}")

                    # 根据视频大小选择下载策略
                    is_large = duration_minutes > 30 or size_mb > 500
                    
                    # 检测并安装 aria2c 下载加速器
                    aria2_path = self.check_and_install_aria2()
                    
                    # 检测并安装 FFmpeg（用于合并视频和音频）
                    ffmpeg_dir = self.check_and_install_ffmpeg()
                    
                    # YouTube特定配置
                    # 关键：使用 bestvideo+bestaudio 来避免选择 HLS/m3u8 直播流格式
                    # HLS 格式容易被 YouTube 封锁产生 403 错误
                    youtube_opts = {
                        # 输出模板
                        "outtmpl": os.path.join(
                            self.download_dir, "%(title)s-%(id)s-%(epoch)s.%(ext)s"
                        ),
                        # 为YouTube设置chrome模拟，这是最重要的设置
                        "extractor_args": {
                            "youtube": {
                                "impersonate": "chrome",
                                # 禁用 HLS 直播格式（这是导致 403 的根本原因）
                                "skip": ["hls", "dash"],
                            }
                        },
                        # 网络配置
                        "retries": 10,
                        "fragment_retries": 10,
                        "skip_unavailable_fragments": True,
                        "socket_timeout": 60 if is_large else 30,
                        "extractor_retries": 5,
                        # 使用标准视频+音频格式，避免 HLS
                        # 这会下载分离的视频和音频然后合并
                        "format": "bestvideo[ext=mp4]+bestaudio[ext=m4a]/bestvideo+bestaudio/best",
                        # 确保合并格式
                        "merge_output_format": "mp4",
                        # 不使用 HLS
                        "hls_prefer_native": False,
                        "hls_prefer_ffmpeg": False,
                        # 进度钩子
                        "progress_hooks": [self.progress_hook],
                        # 日志设置 - 隐藏警告信息（如JavaScript runtime警告）
                        "quiet": False,
                        "no_warnings": True,  # 隐藏yt-dlp的警告信息
                        # 添加自定义日志处理
                        "logger": self._create_yt_logger(),
                    }
                    
                    # 智能浏览器 cookies 获取
                    # 优先使用 Edge（通常用户不会同时运行 Edge 和 Chrome）
                    # 然后尝试 Firefox，最后尝试 Chrome
                    browsers_to_try = ["edge", "firefox", "chrome", "brave", "opera"]
                    cookie_success = False
                    
                    for browser in browsers_to_try:
                        self.log(f"尝试从 {browser.capitalize()} 浏览器获取 cookies...")
                        youtube_opts["cookiesfrombrowser"] = (browser,)
                        try:
                            # 测试是否能获取 cookies
                            test_opts = {
                                "quiet": True,
                                "no_warnings": True,
                                "skip_download": True,
                                "cookiesfrombrowser": (browser,),
                                "extractor_args": {
                                    "youtube": {
                                        "impersonate": "chrome",
                                    }
                                },
                            }
                            with YoutubeDL(test_opts) as test_ydl:
                                test_ydl.extract_info(clean_url, download=False)
                            self.log(f"✓ 成功从 {browser.capitalize()} 获取 cookies")
                            cookie_success = True
                            break
                        except Exception as e:
                            error_str = str(e)
                            if "cookie" in error_str.lower():
                                self.log(f"✗ {browser.capitalize()} cookies 不可用，尝试下一个...")
                                continue
                            elif "Sign in" in error_str:
                                # 需要登录，继续尝试下一个浏览器
                                self.log(f"✗ {browser.capitalize()} 需要登录验证，尝试下一个...")
                                continue
                            else:
                                # 其他错误，可能已经成功获取 cookies 但有其他问题
                                self.log(f"使用 {browser.capitalize()} cookies")
                                cookie_success = True
                                break
                    
                    if not cookie_success:
                        self.log("警告: 无法从任何浏览器获取 cookies，尝试不使用 cookies 下载...")
                        # 移除 cookies 配置，尝试直接下载
                        youtube_opts.pop("cookiesfrombrowser", None)
                    
                    # 如果 aria2c 可用，配置为外部下载器以大幅提升下载速度
                    if aria2_path:
                        self.log(f"启用 aria2c 高速下载模式")
                        # aria2c 外部下载器配置
                        # 使用 16 个连接并行下载，可以充分利用带宽
                        youtube_opts["external_downloader"] = {
                            "default": aria2_path,
                            # 视频和音频都使用 aria2c
                            "http": aria2_path,
                            "https": aria2_path,
                        }
                        # aria2c 参数配置
                        # -x16: 每个服务器最多16个连接
                        # -s16: 分16段下载
                        # -k1M: 每段最小1MB
                        # --file-allocation=none: 不预分配磁盘空间，加快启动速度
                        # --max-connection-per-server=16: 每个服务器最多16个连接
                        # --split=16: 分16段下载
                        # --min-split-size=1M: 每段最小1MB
                        # --allow-overwrite=true: 允许覆盖文件
                        # --auto-file-renaming=false: 禁用自动重命名
                        # --console-log-level=warn: 只显示警告级别日志
                        aria2_args = [
                            "-x16",  # 每个服务器最多16个连接
                            "-s16",  # 分16段下载
                            "-k1M",  # 每段最小1MB
                            "--file-allocation=none",  # 不预分配磁盘空间
                            "--max-connection-per-server=16",
                            "--split=16",
                            "--min-split-size=1M",
                            "--allow-overwrite=true",
                            "--auto-file-renaming=false",
                            "--console-log-level=warn",
                            "--summary-interval=0",  # 禁用进度摘要
                        ]
                        youtube_opts["external_downloader_args"] = {
                            "aria2c": aria2_args,
                        }
                        self.log("aria2c 配置: 16路并发高速下载")
                    else:
                        # 如果没有 aria2c，使用 yt-dlp 内置的并发下载
                        self.log("aria2c 不可用，使用内置下载器")
                        # 并发下载配置 - 适度并发以平衡速度和稳定性
                        youtube_opts["concurrent_fragment_downloads"] = 4 if is_large else 8
                        if is_large:
                            self.log("检测到大文件，使用 4 路并发下载")
                        else:
                            self.log("使用 8 路并发下载")
                    
                    # 设置 FFmpeg 路径（如果可用）
                    if ffmpeg_dir is not None and ffmpeg_dir != "":
                        youtube_opts["ffmpeg_location"] = ffmpeg_dir
                        self.log(f"FFmpeg 路径: {ffmpeg_dir}")
                    elif ffmpeg_dir == "":
                        # 空字符串表示使用系统 PATH
                        self.log("使用系统 FFmpeg")
                    else:
                        # 没有 FFmpeg，使用单一格式避免需要合并
                        self.log("警告: FFmpeg 不可用，使用单一格式下载（可能画质较低）")
                        youtube_opts["format"] = "best"  # 使用最佳单一格式
                        youtube_opts.pop("merge_output_format", None)

                    self.log(f"开始下载: {clean_url}")
                    
                    # 如果使用 aria2c，启动进度监控线程
                    if aria2_path:
                        import glob
                        import time as time_module
                        
                        # 记录下载开始前的文件列表
                        existing_files = set(os.listdir(self.download_dir))
                        download_start_time = time_module.time()
                        
                        # 创建一个标志来控制监控线程
                        self._download_in_progress = True
                        
                        def monitor_download_progress():
                            """监控下载进度的后台线程"""
                            last_size = 0
                            animation_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
                            frame_idx = 0
                            
                            while self._download_in_progress:
                                try:
                                    # 查找新创建的下载文件（包括临时文件）
                                    current_files = set(os.listdir(self.download_dir))
                                    new_files = current_files - existing_files
                                    
                                    total_size = 0
                                    downloading_file = None
                                    
                                    for f in new_files:
                                        file_path = os.path.join(self.download_dir, f)
                                        if os.path.isfile(file_path):
                                            try:
                                                size = os.path.getsize(file_path)
                                                total_size += size
                                                if f.endswith(('.mp4', '.webm', '.f701.mp4', '.f140.m4a', '.part', '.aria2')):
                                                    downloading_file = f
                                            except:
                                                pass
                                    
                                    # 计算下载速度
                                    elapsed = time_module.time() - download_start_time
                                    if elapsed > 0 and total_size > 0:
                                        speed = total_size / elapsed
                                        if speed > 1024 * 1024:
                                            speed_str = f"{speed / (1024 * 1024):.1f} MB/s"
                                        elif speed > 1024:
                                            speed_str = f"{speed / 1024:.1f} KB/s"
                                        else:
                                            speed_str = f"{speed:.0f} B/s"
                                        
                                        size_mb = total_size / (1024 * 1024)
                                        
                                        # 更新进度显示
                                        frame = animation_frames[frame_idx % len(animation_frames)]
                                        frame_idx += 1
                                        
                                        status_msg = f"{frame} 高速下载中: {size_mb:.1f}MB | 速度: {speed_str}"
                                        self.queue.put(("progress", {
                                            "percent": -1,  # -1 表示不确定进度
                                            "filename": downloading_file or "下载中...",
                                            "status": status_msg,
                                        }))
                                    else:
                                        # 还没开始下载，显示等待状态
                                        frame = animation_frames[frame_idx % len(animation_frames)]
                                        frame_idx += 1
                                        self.queue.put(("progress", {
                                            "percent": -1,
                                            "filename": "准备中...",
                                            "status": f"{frame} 正在初始化高速下载...",
                                        }))
                                    
                                    time_module.sleep(0.5)  # 每0.5秒更新一次
                                except Exception as e:
                                    time_module.sleep(1)
                        
                        # 启动监控线程
                        monitor_thread = threading.Thread(target=monitor_download_progress, daemon=True)
                        monitor_thread.start()
                        
                        try:
                            with YoutubeDL(youtube_opts) as ydl:
                                ydl.download([clean_url])
                        finally:
                            # 停止监控线程
                            self._download_in_progress = False
                    else:
                        # 不使用 aria2c，progress_hooks 会正常工作
                        with YoutubeDL(youtube_opts) as ydl:
                            ydl.download([clean_url])

                    self.queue.put(("complete", "YouTube视频下载成功完成！"))
                except Exception as e:
                    self.log(f"YouTube视频下载失败: {str(e)}")
                    self.queue.put(("error", f"YouTube视频下载失败: {str(e)}"))

                # 跳过后续的ydl_opts配置和下载逻辑
                return
            elif is_instagram:
                # Instagram下载配置 - 解决登录限制问题
                self.log("检测到Instagram视频，将使用特殊配置下载模式")
                ydl_opts = {
                    **base_opts,
                    **instagram_opts,
                    "retries": 15,
                    "fragment_retries": 15,
                    "skip_unavailable_fragments": True,
                    "extractor_retries": 5,
                    "socket_timeout": 60,
                }
            elif is_large_file:
                # 大文件优化配置
                ydl_opts = {
                    **base_opts,
                    # 降低并发数，减少内存占用
                    "concurrent_fragment_downloads": 8,
                    # 增加重试次数
                    "retries": 15,
                    "fragment_retries": 15,
                    "skip_unavailable_fragments": True,
                    "extractor_retries": 5,
                    "socket_timeout": 120,  # 增加超时时间
                }
            else:
                # 小文件标准配置
                ydl_opts = {
                    **base_opts,
                    "concurrent_fragment_downloads": 16,
                    "retries": 10,
                    "fragment_retries": 10,
                    "skip_unavailable_fragments": True,
                    "extractor_retries": 5,
                    "socket_timeout": 60,
                }

            try:
                with YoutubeDL(ydl_opts) as ydl:
                    self.log("开始下载...")
                    ydl.download([url])

                # 将完成消息放入队列
                self.queue.put(("complete", "下载成功完成！"))
            except Exception as e:
                # 详细记录错误信息
                error_msg = f"下载过程中出错: {str(e)}"
                self.log(error_msg)
                # 将错误消息放入队列
                self.queue.put(("error", str(e)))
        except Exception as e:
            # 捕获所有异常，确保线程不会静默失败
            error_msg = f"下载线程异常: {str(e)}"
            self.log(error_msg)
            self.queue.put(("error", f"下载失败: {str(e)}"))

    def progress_hook(self, d):
        """进度钩子，向队列发送进度更新（带节流机制）"""
        import time

        current_time = time.time() * 1000  # 转换为毫秒

        if d["status"] == "downloading":
            percent = d.get("_percent_str", "0%")
            speed = d.get("_speed_str", "N/A")
            eta = d.get("_eta_str", "N/A")
            filename = os.path.basename(d.get("filename", "未知"))
            downloaded = d.get("_downloaded_bytes_str", "N/A")
            total = d.get("_total_bytes_str", d.get("_total_bytes_estimate_str", "N/A"))

            try:
                percent_value = float(percent.replace("%", ""))
            except ValueError:
                percent_value = 0

            # 构建状态消息
            status_message = (
                f"下载中: {filename} | {percent} | 速度: {speed} | 剩余时间: {eta}"
            )

            # 节流机制：只在满足以下条件之一时才发送更新
            # 1. 进度变化超过1%
            # 2. 状态消息发生变化
            # 3. 距离上次更新超过指定间隔
            should_update = (
                abs(percent_value - self.last_progress_percent) >= 1
                or status_message != self.last_status_message
                or (current_time - self.last_update_time) > self.update_interval
            )

            if should_update:
                # 向队列发送进度更新
                self.queue.put(
                    (
                        "progress",
                        {
                            "percent": percent_value,
                            "filename": filename,
                            "status": status_message,
                        },
                    )
                )

                # 每10%或每5秒记录一次日志
                should_log = (
                    abs(percent_value - self.last_progress_percent) >= 10
                    or (current_time - self.last_update_time) > 5000
                )
                
                if should_log and percent_value > 0:
                    log_msg = f"[下载进度] {percent} | 速度: {speed} | 已下载: {downloaded}/{total} | 剩余: {eta}"
                    self.log(log_msg)

                # 更新最后进度和状态
                self.last_progress_percent = percent_value
                self.last_status_message = status_message
                self.last_update_time = current_time
        elif d["status"] == "finished":
            filename = os.path.basename(d["filename"])
            total_bytes = d.get("total_bytes", d.get("total_bytes_estimate", 0))
            elapsed = d.get("elapsed", 0)
            
            # 计算平均速度
            if elapsed > 0 and total_bytes > 0:
                avg_speed = total_bytes / elapsed
                if avg_speed > 1024 * 1024:
                    speed_str = f"{avg_speed / (1024 * 1024):.1f} MB/s"
                elif avg_speed > 1024:
                    speed_str = f"{avg_speed / 1024:.1f} KB/s"
                else:
                    speed_str = f"{avg_speed:.1f} B/s"
                
                size_mb = total_bytes / (1024 * 1024)
                self.log(f"[下载完成] {filename} | 大小: {size_mb:.1f}MB | 用时: {elapsed:.1f}秒 | 平均速度: {speed_str}")
            else:
                self.log(f"[下载完成] {filename}")
            
            status_message = f"处理中: {filename}"

            # 完成状态总是发送更新
            self.queue.put(
                (
                    "progress",
                    {"percent": 100, "filename": filename, "status": status_message},
                )
            )

            # 重置进度节流状态
            self.last_progress_percent = -1
            self.last_status_message = ""
            self.last_update_time = 0

    def show_url_menu(self, event):
        """显示URL输入框的右键菜单"""
        self.url_entry_menu.post(event.x_root, event.y_root)

    def paste_url(self):
        """粘贴剪贴板内容到URL输入框"""
        try:
            # 清空当前内容并粘贴
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, self.root.clipboard_get())
        except tk.TclError:
            # 剪贴板为空或无法访问
            pass

    def select_all_url(self):
        """全选URL输入框内容"""
        self.url_entry.select_range(0, tk.END)

    def clear_url(self):
        """清空URL输入框内容"""
        self.url_entry.delete(0, tk.END)

    def check_download_status(self, thread):
        """检查下载线程状态，确保UI保持响应"""
        if thread.is_alive():
            # 如果线程仍在运行，继续检查
            self.root.after(100, self.check_download_status, thread)
        # 否则，线程已结束，UI更新将由队列处理

    def update_ui(self):
        """从主线程更新UI，优化版本"""
        try:
            # 限制每次处理的消息数量，防止UI阻塞
            message_count = 0
            max_messages_per_update = 3  # 每次更新最多处理3条消息

            # 处理队列中的消息，但限制数量
            while not self.queue.empty() and message_count < max_messages_per_update:
                message_type, message = self.queue.get_nowait()
                message_count += 1

                if message_type == "progress":
                    # 更新进度
                    percent = message["percent"]
                    if percent >= 0:
                        # 确定进度
                        self.progress_var.set(percent)
                    else:
                        # 不确定进度（-1），使用滚动动画效果
                        # 让进度条来回滚动
                        current = self.progress_var.get()
                        if not hasattr(self, '_progress_direction'):
                            self._progress_direction = 1
                        if current >= 95:
                            self._progress_direction = -1
                        elif current <= 5:
                            self._progress_direction = 1
                        self.progress_var.set(current + self._progress_direction * 5)
                    
                    self.progress_label.config(text=message["status"])

                    # 仅在特定条件下添加到日志，大幅减少日志更新频率
                    if percent >= 0 and (
                        percent % 10 == 0 and percent > 0
                    ) or percent == 100:
                        # 每10%进度或完成时才记录日志
                        self.log_text.insert(tk.END, f"{message['status']}\n")
                        self.log_text.see(tk.END)
                elif message_type == "log":
                    # 处理日志消息
                    self.log_text.insert(tk.END, f"{message}\n")
                    self.log_text.see(tk.END)
                elif message_type == "complete":
                    # 下载完成时更新UI
                    self.progress_label.config(text="下载完成!")
                    self.log_text.insert(tk.END, f"{message}\n")
                    self.log_text.see(tk.END)
                    # 使用after方法延迟显示消息框，确保UI有时间更新
                    self.root.after(100, lambda: messagebox.showinfo("成功", message))
                    # 重新启用下载按钮
                    self.download_btn.config(state=tk.NORMAL)
                elif message_type == "error":
                    # 发生错误时更新UI
                    self.progress_label.config(text="下载失败!")
                    self.log_text.insert(tk.END, f"错误: {message}\n")
                    self.log_text.see(tk.END)
                    # 使用after方法延迟显示消息框，确保UI有时间更新
                    self.root.after(
                        100,
                        lambda: messagebox.showerror("错误", f"下载失败: {message}"),
                    )
                    # 重新启用下载按钮
                    self.download_btn.config(state=tk.NORMAL)
                elif message_type == "hongguo_template":
                    url = message.get("url") if isinstance(message, dict) else None
                    if url:
                        self._hongguo_last_template_url = url
                        if self._hongguo_template_text_widget is not None:
                            try:
                                if self._hongguo_template_text_widget.winfo_exists():
                                    self._hongguo_template_text_widget.delete("1.0", tk.END)
                                    self._hongguo_template_text_widget.insert(tk.END, url)
                                    if self._hongguo_template_status_label is not None and self._hongguo_template_status_label.winfo_exists():
                                        self._hongguo_template_status_label.config(text="已捕获到模板，可直接下载")
                            except Exception:
                                pass
                        self._update_hongguo_capture_window(url)
                        self.stop_hongguo_frida_capture()
                elif message_type == "hongguo_capture_status":
                    text = message.get("text") if isinstance(message, dict) else None
                    if text and self._hongguo_template_status_label is not None:
                        try:
                            if self._hongguo_template_status_label.winfo_exists():
                                self._hongguo_template_status_label.config(text=text)
                        except Exception:
                            pass
                    if text:
                        self._update_hongguo_capture_status(text)

                # 限制日志行数，防止内存占用过大
                self.limit_log_size()
        except queue.Empty:
            pass
        except Exception as e:
            # 捕获所有异常，防止UI更新循环崩溃
            self.log_text.insert(tk.END, f"UI更新错误: {str(e)}\n")
            self.log_text.see(tk.END)
        finally:
            # 安排下一次更新，动态调整更新间隔
            update_interval = 150  # 增加到150ms，减少UI刷新频率
            self.root.after(update_interval, self.update_ui)

    def limit_log_size(self):
        """限制日志大小，防止内存占用过大"""
        max_lines = 100  # 最大日志行数
        line_count = int(self.log_text.index("end-1c").split(".")[0])

        if line_count > max_lines:
            # 删除最旧的日志行
            self.log_text.delete(1.0, f"{line_count - max_lines}.0")

    def log(self, message):
        """添加日志消息，线程安全"""
        self.queue.put(("log", message))

    def _create_menu(self):
        menubar = tk.Menu(self.root)

        hongguo_menu = tk.Menu(menubar, tearoff=0)
        hongguo_menu.add_command(label="打开自动捕获面板", command=self.open_hongguo_capture_window)
        hongguo_menu.add_separator()
        hongguo_menu.add_command(label="开始自动捕获模板", command=self.start_hongguo_frida_capture)
        hongguo_menu.add_command(label="停止捕获", command=self.stop_hongguo_frida_capture)
        hongguo_menu.add_separator()
        hongguo_menu.add_command(label="一键安装/更新捕获依赖", command=self.install_frida_deps)
        hongguo_menu.add_command(label="捕获诊断", command=self.diagnose_frida)
        menubar.add_cascade(label="红果短剧", menu=hongguo_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于", command=self.show_about_dialog)
        menubar.add_cascade(label="帮助", menu=help_menu)

        self.root.config(menu=menubar)

    def show_about_dialog(self):
        messagebox.showinfo(
            "关于",
            "视频音频高速下载神器\n\n红果短剧：支持分享链接解析与（可选）自动捕获完整版模板。\n\n提示：自动捕获需要模拟器/环境允许注入。",
        )

    def open_hongguo_capture_window(self):
        if self._hongguo_capture_window is not None:
            try:
                if self._hongguo_capture_window.winfo_exists():
                    self._hongguo_capture_window.lift()
                    return
            except Exception:
                pass

        win = tk.Toplevel(self.root)
        win.title("红果短剧 - 自动捕获面板")
        win.geometry("520x260")
        win.resizable(True, True)
        win.transient(self.root)

        frame = ttk.Frame(win, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        row = ttk.Frame(frame)
        row.pack(fill=tk.X)

        status = ttk.Label(row, text="未启动捕获")
        status.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Button(row, text="开始捕获", command=self.start_hongguo_frida_capture).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(row, text="停止捕获", command=self.stop_hongguo_frida_capture).pack(side=tk.RIGHT)

        text = tk.Text(frame, height=6, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, pady=(10, 8))

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill=tk.X)

        def copy():
            value = (text.get("1.0", tk.END) or "").strip()
            if not value:
                messagebox.showwarning("提示", "还没有捕获到模板")
                return
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(value)
                self.root.update()
                messagebox.showinfo("成功", "已复制到剪贴板")
            except Exception:
                messagebox.showerror("错误", "复制失败")

        ttk.Button(btn_row, text="复制模板", command=copy).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="安装/更新依赖", command=self.install_frida_deps).pack(side=tk.RIGHT)
        ttk.Button(btn_row, text="诊断", command=self.diagnose_frida).pack(side=tk.RIGHT, padx=(0, 6))

        if self._hongguo_last_template_url:
            text.insert(tk.END, self._hongguo_last_template_url)
            status.config(text="已捕获到模板，可直接粘贴到下载器")

        def on_close():
            try:
                win.destroy()
            except Exception:
                pass
            self._hongguo_capture_window = None
            self._hongguo_capture_text = None
            self._hongguo_capture_status = None

        win.protocol("WM_DELETE_WINDOW", on_close)

        self._hongguo_capture_window = win
        self._hongguo_capture_text = text
        self._hongguo_capture_status = status

    def _update_hongguo_capture_window(self, url):
        if self._hongguo_capture_text is None:
            return
        try:
            if self._hongguo_capture_text.winfo_exists():
                self._hongguo_capture_text.delete("1.0", tk.END)
                self._hongguo_capture_text.insert(tk.END, url)
        except Exception:
            pass

    def _update_hongguo_capture_status(self, text):
        if self._hongguo_capture_status is None:
            return
        try:
            if self._hongguo_capture_status.winfo_exists():
                self._hongguo_capture_status.config(text=text)
        except Exception:
            pass

    def start_hongguo_frida_capture(self):
        if self._hongguo_frida_thread is not None and self._hongguo_frida_thread.is_alive():
            self.queue.put(("hongguo_capture_status", {"text": "捕获已在运行"}))
            return

        if HongguoFridaRunner is None:
            self.queue.put(("error", "未检测到 frida 依赖，请先安装: pip install frida frida-tools"))
            return

        device_hint = os.environ.get("HONGGUO_FRIDA_DEVICE") or None
        package_name = os.environ.get("HONGGUO_FRIDA_PACKAGE") or "com.phoenix.read"
        spawn = (os.environ.get("HONGGUO_FRIDA_SPAWN") or "").strip() in ("1", "true", "yes")

        def on_url(payload):
            if payload.get("full_cdn"):
                self.queue.put(("hongguo_template", {"url": payload.get("url")}))
            else:
                url = payload.get("url")
                if url and "qznovelvod.com" in url:
                    self.queue.put(("log", f"捕获到候选URL(非reading-video): {url[:160]}"))

        self._hongguo_frida_runner = HongguoFridaRunner(
            on_url=on_url,
            package_name=package_name,
            device_hint=device_hint,
            spawn=spawn,
        )

        def run():
            try:
                self.queue.put(("hongguo_capture_status", {"text": "正在连接模拟器并注入..."}))
                self._hongguo_frida_runner.start()
            except Exception as e:
                self.queue.put(("error", f"自动捕获启动失败: {e}"))
            finally:
                self._hongguo_frida_runner = None
                self.queue.put(("hongguo_capture_status", {"text": "捕获已停止"}))

        self._hongguo_frida_thread = threading.Thread(target=run, daemon=True)
        self._hongguo_frida_thread.start()
        self.queue.put(("hongguo_capture_status", {"text": "捕获运行中：请在模拟器里播放任意一集"}))

    def stop_hongguo_frida_capture(self):
        runner = self._hongguo_frida_runner
        if runner is not None:
            try:
                runner.stop()
            except Exception:
                pass
        self._hongguo_frida_runner = None

    def install_frida_deps(self):
        if self._hongguo_install_thread is not None and self._hongguo_install_thread.is_alive():
            messagebox.showinfo("提示", "依赖安装正在进行中")
            return

        def run():
            try:
                self.queue.put(("hongguo_capture_status", {"text": "正在安装/更新依赖..."}))
                cmd_candidates = []
                if getattr(sys, "frozen", False):
                    cmd_candidates.extend([
                        ["python3", "-m", "pip", "install", "-U", "frida", "frida-tools"],
                        ["python", "-m", "pip", "install", "-U", "frida", "frida-tools"],
                    ])
                cmd_candidates.append([sys.executable, "-m", "pip", "install", "-U", "frida", "frida-tools"])

                cmd = None
                for candidate in cmd_candidates:
                    try:
                        proc = subprocess.Popen(
                            candidate,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
                        )
                        cmd = candidate
                        break
                    except FileNotFoundError:
                        continue

                if cmd is None:
                    self.queue.put(("error", "未找到可用的 Python/pip，请先安装 Python 3 并配置到 PATH"))
                    return

                while True:
                    line = proc.stdout.readline() if proc.stdout else ""
                    if not line and proc.poll() is not None:
                        break
                    if line:
                        self.queue.put(("log", line.rstrip("\n")))
                code = proc.wait()
                if code == 0:
                    self.queue.put(("hongguo_capture_status", {"text": "依赖已就绪"}))
                else:
                    self.queue.put(("error", f"依赖安装失败，退出码 {code}"))
            except Exception as e:
                self.queue.put(("error", f"依赖安装失败: {e}"))

        self._hongguo_install_thread = threading.Thread(target=run, daemon=True)
        self._hongguo_install_thread.start()

    def diagnose_frida(self):
        results = []
        try:
            import frida  # noqa: F401
            results.append("frida: 已安装")
        except Exception as e:
            results.append(f"frida: 未安装或不可用 ({e})")
            messagebox.showerror("捕获诊断", "\n".join(results))
            return

        try:
            import frida
            mgr = frida.get_device_manager()
            devices = mgr.enumerate_devices()
            results.append(f"设备列表: {', '.join([d.id for d in devices[:8]])}" + ("..." if len(devices) > 8 else ""))
        except Exception as e:
            results.append(f"设备枚举失败: {e}")

        try:
            import frida
            dev = None
            try:
                dev = frida.get_usb_device(timeout=3)
                results.append(f"USB 设备: {dev.id}")
            except Exception:
                pass
            if dev is None:
                dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
                results.append("远程设备: 127.0.0.1:27042 可连接")
        except Exception as e:
            results.append(f"连接 frida-server 失败: {e}")

        messagebox.showinfo("捕获诊断", "\n".join(results))


def main():
    """主函数"""
    root = tk.Tk()
    root.title("视频音频高速下载神器")

    # 设置窗口左上角的图标
    try:
        # 使用images.ico作为图标
        root.iconbitmap(get_resource_path("images.ico"))
    except Exception as e:
        print(f"图标加载失败: {e}")

    app = YTDLP_GUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
