import os
import threading
import time


class HongguoFridaRunner:
    def __init__(
        self,
        on_url,
        package_name="com.phoenix.read",
        device_hint=None,
        spawn=False,
        timeout_s=10,
    ):
        self._on_url = on_url
        self._package_name = package_name
        self._device_hint = device_hint
        self._spawn = spawn
        self._timeout_s = timeout_s

        self._stop_event = threading.Event()
        self._device = None
        self._session = None
        self._script = None
        self._pid = None

    def start(self):
        import frida

        self._device = self._resolve_device(frida)
        if self._spawn:
            self._pid = self._device.spawn([self._package_name])
            self._session = self._device.attach(self._pid)
        else:
            self._session = self._device.attach(self._package_name)

        script_source = self._read_hook_js()
        self._script = self._session.create_script(script_source)
        self._script.on("message", self._on_message)
        self._script.load()

        if self._spawn and self._pid is not None:
            self._device.resume(self._pid)

        while not self._stop_event.is_set():
            time.sleep(0.2)

    def stop(self):
        self._stop_event.set()
        try:
            if self._script is not None:
                self._script.unload()
        except Exception:
            pass
        try:
            if self._session is not None:
                self._session.detach()
        except Exception:
            pass

    def _on_message(self, message, data):
        if message.get("type") != "send":
            return
        payload = message.get("payload") or {}
        if payload.get("type") != "hongguo_url":
            return
        url = payload.get("url")
        if not url:
            return
        try:
            self._on_url(payload)
        except Exception:
            pass

    def _resolve_device(self, frida):
        if self._device_hint:
            hint = str(self._device_hint).strip()
            if hint.lower().startswith("remote:"):
                host = hint.split(":", 1)[1].strip()
                return frida.get_device_manager().add_remote_device(host)
            if hint.lower() == "usb":
                return frida.get_usb_device(timeout=self._timeout_s)

        try:
            return frida.get_usb_device(timeout=self._timeout_s)
        except Exception:
            pass

        try:
            return frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        except Exception:
            raise RuntimeError(
                "无法连接到 Frida 设备。请确认模拟器/手机已运行 frida-server，或提供 device_hint=remote:host:port"
            )

    def _read_hook_js(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        js_path = os.path.join(base_dir, "hongguo_hook.js")
        with open(js_path, "r", encoding="utf-8") as f:
            return f.read()

