# yt-dlp-gui

A cross-platform graphical user interface for [yt-dlp](https://github.com/yt-dlp/yt-dlp), a powerful command-line video downloader.

## Features

- **User-Friendly Interface**: Simple and intuitive design for easy video downloading
- **Multiple Format Support**: Download videos in various formats and qualities
- **Audio Extraction**: Extract audio from videos (MP3, M4A, etc.)
- **Batch Downloading**: Support for downloading multiple videos at once
- **Subtitle Support**: Download and embed subtitles (auto-generated and manual)
- **Metadata Embedding**: Automatically embed video metadata
- **Proxy Support**: Configure proxies for downloading
- **Download Management**: View download history and manage downloads
- **Cross-Platform**: Works on Windows 11, Ubuntu, Debian, and macOS

## Installation

### Prerequisites

- Python 3.10 or higher
- PyQt6
- yt-dlp

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/yt-dlp-gui.git
   cd yt-dlp-gui
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python src/main.py
   ```

### Binary Packages

Coming soon for Windows, macOS, and Linux.

## Usage

1. **Enter URL**: Paste the YouTube or other supported video URL into the input field
2. **Choose Format**: Select a format preset or enter a custom format string
3. **Configure Options**: Adjust download options as needed
4. **Set Download Directory**: Choose where to save the downloaded files
5. **Start Download**: Click the "Download" button to begin

## Configuration

### Format Presets

- **Best Video**: Downloads the best available video quality
- **Best Audio**: Downloads the best available audio quality
- **MP4 Video**: Downloads MP4 format video
- **MP3 Audio**: Extracts MP3 audio from video
- **WebM Video**: Downloads WebM format video
- **Custom Format**: Enter your own format string

### Advanced Options

- **Concurrent Fragments**: Number of fragments to download concurrently
- **Rate Limit**: Limit download speed
- **Proxy**: Configure HTTP/HTTPS/SOCKS proxy
- **No Check Certificate**: Skip SSL certificate verification
- **Verbose Logging**: Enable detailed logging

## Project Structure

```
yt-dlp-gui/
├── src/
│   ├── main.py              # Application entry point
│   ├── app.py               # Main application class
│   ├── ui/
│   │   └── main_window.py   # Main window UI
│   ├── downloader/
│   │   ├── ytdlp_wrapper.py  # yt-dlp API wrapper
│   │   └── download_manager.py # Download manager
│   ├── models/
│   │   └── settings.py       # Settings model
│   └── utils/
├── assets/
│   ├── icons/               # Application icons
│   └── styles/              # CSS styles
├── yt_dlp_gui.spec          # PyInstaller spec file
├── pyproject.toml           # Project configuration
└── README.md                # This file
```

## Building Executable

### Using PyInstaller

```bash
pyinstaller yt_dlp_gui.spec
```

The executable will be created in the `dist` directory.

## Platform Support

- **Windows**: Windows 10 and Windows 11
- **Linux**: Ubuntu 20.04+, Debian 11+
- **macOS**: macOS 10.15+

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- [yt-dlp](https://github.com/yt-dlp/yt-dlp) - The powerful video downloader this GUI is based on
- [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) - The GUI framework used

## Support

If you encounter any issues or have questions, please open an issue on the GitHub repository.
