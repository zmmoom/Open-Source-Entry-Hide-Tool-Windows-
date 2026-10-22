#!/usr/bin/env python3
"""
WebView2 启动引导（走服务器兜底）
流程：
  1) 系统 WebView2 版本够新        -> 直接用系统，不下载（秒开）
  2) 本地已缓存固定内核            -> 直接用缓存，不重复下载
  3) 都没有                        -> 从【你的服务器】下载固定内核 zip，
                                     显示进度条，解压缓存到本机，再启动
核心攻击/框架与本模块无关。
"""

import os
import sys
import zipfile
import shutil
import threading
import urllib.request

# ============================================================
# 【需要你填】固定内核 zip 上传到服务器后的完整下载地址
# 例： "https://your-domain.com/files/webview2_runtime_154.zip"
# 可选：填 zip 的 SHA256（不填就不校验）
# ============================================================
SERVER_URL = "https://CHANGE-ME/files/webview2_runtime_154.zip"
ZIP_SHA256 = ""

# 系统 WebView2 低于此版本才走服务器（Evergreen 正常更新都远高于此）
MIN_SYSTEM_VERSION = (90, 0, 0, 0)

_APP_NAME = "HideAppleAccount"


# ---------------- 系统 WebView2 检测 ----------------

def _reg_version():
    import winreg
    sub = r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for s in (sub, sub.replace("WOW6432Node\\", "")):
            try:
                with winreg.OpenKey(root, s) as k:
                    pv, _ = winreg.QueryValueEx(k, "pv")
                    return pv
            except OSError:
                pass
    return None


def system_version_ok():
    pv = _reg_version()
    if not pv:
        return False
    try:
        parts = tuple(int(x) for x in str(pv).split(".")[:4])
        while len(parts) < 4:
            parts = parts + (0,)
        return parts >= MIN_SYSTEM_VERSION
    except Exception:
        return False


# ---------------- 本地缓存 ----------------

def cache_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, _APP_NAME, "webview2_runtime")


def _find_runtime_exe(root):
    """在解压目录内（含一层子目录）找 msedgewebview2.exe，返回所在目录。"""
    direct = os.path.join(root, "msedgewebview2.exe")
    if os.path.exists(direct):
        return root
    try:
        for name in os.listdir(root):
            sub = os.path.join(root, name)
            if os.path.isdir(sub) and os.path.exists(os.path.join(sub, "msedgewebview2.exe")):
                return sub
    except OSError:
        pass
    return None


def cached_runtime():
    return _find_runtime_exe(cache_dir())


# ---------------- 下载进度窗口（tkinter，标准库） ----------------

class _ProgressUI:
    def __init__(self):
        import tkinter as tk
        self.tk = tk
        self.root = tk.Tk()
        self.root.title("首次运行准备")
        self.root.geometry("420x150")
        self.root.resizable(False, False)
        self.var = tk.StringVar(value="正在准备运行环境…")
        tk.Label(self.root, textvariable=self.var, wraplength=380).pack(pady=12)
        self.bar = tk.Canvas(self.root, width=380, height=20, bg="#e6e6e6", highlightthickness=0)
        self.bar.pack()
        self.fill = self.bar.create_rectangle(0, 0, 0, 20, fill="#3b82f6", width=0)
        self.pct = tk.StringVar(value="0%")
        tk.Label(self.root, textvariable=self.pct).pack(pady=8)
        self._closed = False
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        self._closed = True
        self.root.destroy()

    def set(self, frac, text=None):
        frac = max(0.0, min(1.0, frac))
        self.bar.coords(self.fill, 0, 0, 380 * frac, 20)
        self.pct.set(f"{int(frac * 100)}%")
        if text:
            self.var.set(text)
        self.root.update_idletasks()
        self.root.update()

    def close(self):
        try:
            self.root.destroy()
        except Exception:
            pass


def _download(url, dest, ui):
    def _hook(blocks, bs, total):
        if total > 0 and ui is not None:
            ui.set(min(1.0, blocks * bs / total), "正在从服务器下载运行环境…")
    urllib.request.urlretrieve(url, dest, reporthook=_hook)


def _download_and_extract():
    ui = None
    tmp_zip = os.path.join(cache_dir() + ".zip")
    extract_root = os.path.join(os.path.dirname(cache_dir()), "_extract")
    try:
        ui = _ProgressUI()
        os.makedirs(os.path.dirname(cache_dir()), exist_ok=True)

        t = threading.Thread(target=_download, args=(SERVER_URL, tmp_zip, ui), daemon=True)
        t.start()
        while t.is_alive():
            ui.root.after(200)
            ui.root.update()
        t.join()
        if getattr(ui, "_closed", False):
            raise RuntimeError("用户取消下载")

        if ZIP_SHA256:
            import hashlib
            h = hashlib.sha256()
            with open(tmp_zip, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            if h.hexdigest().lower() != ZIP_SHA256.lower():
                raise RuntimeError("下载文件校验失败")

        ui.set(1.0, "下载完成，正在安装…")
        if os.path.exists(extract_root):
            shutil.rmtree(extract_root, ignore_errors=True)
        os.makedirs(extract_root, exist_ok=True)
        with zipfile.ZipFile(tmp_zip) as z:
            z.extractall(extract_root)

        found = _find_runtime_exe(extract_root)
        if not found:
            raise RuntimeError("压缩包内未找到 msedgewebview2.exe")

        if os.path.exists(cache_dir()):
            shutil.rmtree(cache_dir(), ignore_errors=True)
        shutil.move(found, cache_dir())
        return cache_dir()
    finally:
        try:
            if os.path.exists(tmp_zip):
                os.remove(tmp_zip)
        except OSError:
            pass
        shutil.rmtree(extract_root, ignore_errors=True)
        if ui is not None:
            ui.close()


# ---------------- 对外入口 ----------------

def ensure_runtime():
    """返回固定内核目录；返回 None 表示直接用系统 WebView2。

    商业化策略：绝不弹窗、绝不阻塞。检测到本地缓存才用，否则一律回退系统
    WebView2（缺失时由 WebView2/系统引导安装微软官方运行时）。
    """
    # 不再尝试服务器下载（URL 未配置会卡死），仅检测本地缓存
    try:
        c = cached_runtime()
        if c:
            return c
    except Exception:
        pass
    return None
