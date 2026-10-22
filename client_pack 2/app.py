#!/usr/bin/env python3
"""Hide Apple Account - Desktop App (Windows version)
攻击在【后台线程】里跑，与 run_main.py 同进程（原生 DLL 已在该环境验证通过）。
UI 用 JS 轮询 get_updates()，Python 不主动 evaluate_js，故界面不卡。
"""

import sys
import os

# 全量引导日志必须最先加载（在任何其它 import 之前），确保即使后续崩溃也有迹可循。
try:
    import bootlog
    def _blog(msg, level="LOG"):
        bootlog.log(msg, level)
except Exception as _e:  # 极端情况下 bootlog 自身都加载失败
    bootlog = None
    def _blog(msg, level="LOG"):
        try:
            import tempfile, datetime
            with open(os.path.join(tempfile.gettempdir(), "hideapple_boot_fail.log"),
                      "a", encoding="utf-8", errors="replace") as _f:
                _f.write("[%s] bootlog missing (%r): %s\n"
                         % (datetime.datetime.now(), _e, msg))
        except Exception:
            pass

import io
import time
import threading
import traceback
from pathlib import Path
from collections import deque

PROJECT_DIR = Path(__file__).resolve().parent


def _set_dpi_aware():
    """Windows 高 DPI 感知，避免网吧/高分屏比例错乱"""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        # Per-Monitor DPI Aware v2（Win10 1703+）
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
    except Exception:
        pass


# 必须最早调用，在 import webview 之前
_set_dpi_aware()


def _base_dir():
    # PyInstaller 打包后资源在 _MEIPASS；开发时就是脚本目录
    return getattr(sys, "_MEIPASS", str(PROJECT_DIR))


def resource_path(name):
    return os.path.join(_base_dir(), name)


def _setup_fixed_webview2():
    """强制使用内置/本地的 Fixed Version WebView2，不读系统那份。
    找不到固定版本时返回 False（回退系统运行时）。
    必须在 import webview 之前调用。
    """
    candidates = [
        os.path.join(_base_dir(), "webview2_runtime"),       # 打包内置
        os.path.join(str(PROJECT_DIR), "webview2_runtime"),  # 开发时项目内置
    ]
    for folder in candidates:
        exe = os.path.join(folder, "msedgewebview2.exe")
        if os.path.exists(exe):
            os.environ["WEBVIEW2_BROWSER_EXECUTABLE_FOLDER"] = folder
            return True
    return False


# 必须在 import webview 之前固定 WebView2 运行时
_FIXED_RUNTIME = _setup_fixed_webview2()

# 未内置固定内核时：系统能用就用系统，否则从服务器下载固定内核（走服务器兜底）
if not _FIXED_RUNTIME:
    try:
        import webview2_bootstrap as _boot
        _server_runtime = _boot.ensure_runtime()
        if _server_runtime:
            os.environ["WEBVIEW2_BROWSER_EXECUTABLE_FOLDER"] = _server_runtime
            _FIXED_RUNTIME = True
    except Exception as _e:
        # 服务器也失败则保持系统 WebView2
        pass

# WebView2 软件渲染，规避个别机器显卡硬件加速导致的启动卡死
os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = "--disable-gpu"

try:
    import webview
except Exception:
    webview = None


# ── 设备信息（后台线程调用）──

def _debug_log_paths():
    """返回多个必定可写的候选日志路径（临时目录 + exe/脚本旁）。"""
    import tempfile
    paths = []
    try:
        paths.append(os.path.join(tempfile.gettempdir(), "hideapple_debug.log"))
    except Exception:
        pass
    try:
        paths.append(os.path.join(str(PROJECT_DIR), "hideapple_debug.log"))
    except Exception:
        pass
    # PyInstaller：exe 所在目录（可能只读，写失败会被忽略）
    try:
        exe_dir = os.path.dirname(sys.executable)
        p = os.path.join(exe_dir, "hideapple_debug.log")
        if p not in paths:
            paths.append(p)
    except Exception:
        pass
    # 桌面：固定、最容易找到，确保用户一定能拿到日志
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.shell32.SHGetFolderPathW(0, 0, 0, 0, buf):
            # CSIDL_DESKTOP = 0
            pass
        if buf.value:
            p = os.path.join(buf.value, "hideapple_debug.log")
            if p not in paths:
                paths.append(p)
    except Exception:
        pass
    return paths


def _dbg(msg):
    """写调试日志，带时间戳，写遍所有候选路径，同时进入全量 bootlog。"""
    try:
        _blog(msg)
    except Exception:
        pass
    try:
        import datetime
        line = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}\n"
        for p in _debug_log_paths():
            try:
                with open(p, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                pass
    except Exception:
        pass


# 模块导入即写心跳：只要进程启动并加载本模块，就一定能在日志里看到。
try:
    _dbg("=" * 50)
    _dbg("app module imported; sys.frozen=%s platform=%s exe=%s"
         % (getattr(sys, "frozen", False), sys.platform, sys.executable))
except Exception:
    pass


def _list_devices():
    """枚举设备，带重试逻辑（应对驱动崩溃导致设备反复掉线）。"""
    try:
        import apple_native_wrapper as lw
        ver = getattr(lw, "_WRAPPER_VERSION", "旧版/无版本标记")
        _dbg(f"实际加载 wrapper 版本: {ver}")
        if lw.is_available():
            # 主尝试：直接调用一次
            devs = lw.list_devices()
            _dbg(f"_list_devices via MobileDevice: {devs}")
            if devs:
                return devs
            # 重试：最多 2 次，每次间隔 2 秒（驱动崩溃后设备可能短暂不可见）
            for retry in range(2):
                time.sleep(2)
                devs = lw.list_devices()
                _dbg(f"_list_devices 重试 {retry+1}/2: {devs}")
                if devs:
                    return devs
    except Exception as e:
        _dbg(f"_list_devices MobileDevice EXC: {e}")
    return []


def _read_info(udid):
    _dbg(f"_read_info START udid={udid}")
    try:
        import apple_native_wrapper as lw
        if lw.is_available():
            res = lw.read_device_info(udid=udid)
            _dbg(f"_read_info MobileDevice success={res.get('success')} "
                 f"rows={len(res.get('data', []))} err={res.get('error')}")
            return res
    except Exception as e:
        _dbg(f"_read_info MobileDevice EXC: {e}")
    return {"success": False, "data": [], "error": "MobileDevice 读取失败"}


_DIAG_BUILD = "diag-build-20260930-26"
_app_diag_shown = False


def _app_alert(stage, detail):
    """app 层兜底弹窗：置顶，确保即使设备层诊断没跑到也能看到原因。"""
    global _app_diag_shown
    if _app_diag_shown:
        return
    _app_diag_shown = True
    try:
        import ctypes
        text = "构建: %s\n\n阶段: %s\n\n%s" % (_DIAG_BUILD, stage, detail)
        _dbg("APP_ALERT stage=%s detail=%s" % (stage, detail))
        MB_OK = 0x0
        MB_TOPMOST = 0x00040000
        MB_ICONWARN = 0x30
        ctypes.windll.user32.MessageBoxW(
            0, text, "Apple 驱动诊断", MB_OK | MB_TOPMOST | MB_ICONWARN)
    except Exception:
        pass


def _startup_path_popup():
    """启动即弹窗：显示版本标识 + 日志确切路径，用于确认运行的是最新代码。"""
    try:
        import ctypes
        paths = []
        try:
            paths = bootlog.resolved_paths()
        except Exception:
            paths = []
        if not paths:
            try:
                import tempfile
                paths = [os.path.join(tempfile.gettempdir(), "hideapple_full.log")]
            except Exception:
                paths = ["<无法定位>"]
        text = (
            "本窗口仅用于确认运行版本。\n\n"
            "代码版本: %s\n"
            "frozen: %s\n\n"
            "日志文件已写到（去这个位置找 hideapple_full.log）:\n%s\n\n"
            "看到此框说明运行的就是最新打包的程序。点确定后正常使用。"
            % (_DIAG_BUILD, getattr(sys, "frozen", False),
               "\n".join(paths)))
        MB_OK = 0x0
        MB_TOPMOST = 0x00040000
        MB_ICONINFO = 0x40
        ctypes.windll.user32.MessageBoxW(
            0, text, "版本确认", MB_OK | MB_TOPMOST | MB_ICONINFO)
    except Exception:
        pass


def _find_all_copies(filename, time_budget=18.0):
    """在所有盘符里限时搜索同名文件，列出 路径/大小/修改时间。"""
    import ctypes, datetime, time as _t
    found = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        roots = []
        for i in range(26):
            if bitmask & (1 << i):
                root = "%s:\\" % chr(65 + i)
                if os.path.isdir(root):
                    roots.append(root)
    except Exception:
        roots = ["C:\\"]
    deadline = _t.time() + time_budget
    for root in roots:
        if _t.time() > deadline:
            break
        for cur, dirs, files in os.walk(root):
            if _t.time() > deadline:
                break
            # 跳过明显无关且巨大的系统/缓存目录，加快搜索
            low = cur.lower()
            dirs[:] = [d for d in dirs if d.lower() not in (
                "$recycle.bin", "system volume information", "windows",
                "node_modules", "__pycache__")]
            if filename in files:
                fp = os.path.join(cur, filename)
                try:
                    st = os.stat(fp)
                    mt = datetime.datetime.fromtimestamp(
                        st.st_mtime).strftime("%m-%d %H:%M")
                    found.append("%d B  %s  %s" % (st.st_size, mt, fp))
                except Exception:
                    found.append(fp)
        if _t.time() > deadline:
            break
    return found


def _check_driver():
    """返回 (ok, detail)。失败时 detail 携带真实加载原因用于诊断。"""
    _blog(">>> _check_driver 开始")
    try:
        _blog("    import apple_native_wrapper ...")
        import apple_native_wrapper as lw
        _blog("    import 成功，调用 is_available() ...")
        ok = bool(lw.is_available())
        _blog("    is_available() = %s" % ok)
        if ok:
            _blog("<<< _check_driver = True")
            return True, ""
        detail = str(lw.load_error() or "")
        if not detail:
            detail = "is_available()=False 但 load_error 为空（设备层未正常初始化）"
        _blog("    load_error=%r" % detail, "ERROR")
        _app_alert("设备层 is_available=False", detail)
        _blog("<<< _check_driver = False", "ERROR")
        return False, detail
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        _blog("import apple_native_wrapper 抛异常:\n%s" % tb, "FATAL")
        copies = _find_all_copies("atc_native_bridge.py")
        hint = ("%r\n\n—— 硬盘上的 atc_native_bridge.py 副本 ——\n" % e)
        hint += "\n".join(copies) if copies else "（未在常见位置找到）"
        _app_alert("import apple_native_wrapper 失败（疑似旧桥接文件）", hint)
        return False, "%r\n%s" % (e, tb)


# ── 进度/分类 ──

PROGRESS_MAP = [
    # ── 新流程 (WriteOpenHideLikeLift) ──
    ("Lift 流程: clean/preflight", 5),
    ("AFC 探测通过", 8),
    ("keep-link", 15),
    ("StreamingZip: binary stage", 20),
    ("StreamingZip: archive sent", 25),
    ("StreamingZip: stage ready", 30),
    ("Lift 流程: moveout Accounts", 35),
    ("AirTraffic moveout", 40),
    ("recovered 清理", 50),
    ("Accounts 已移出", 55),
    ("Accounts 数据已清理", 58),
    ("Accounts 已不可见", 55),
    ("Lift 流程: 删除账户目录", 35),
    ("Lift 流程: 账户目录已删除", 60),
    ("Lift 流程: 清理旧配置", 62),
    ("旧配置不存在", 65),
    ("旧配置已清理", 67),
    ("Lift 流程: 发送使用时间配置", 70),
    ("linkset 投递", 75),
    ("rename/linkdrop", 78),
    ("Lift 流程: 使用时间配置完成", 95),
    ("写入完成", 95),
    # ── 旧流程兼容 ──
    ("streaming_zip_conduit", 45),
    ("Sending ZIP", 48),
    ("Verifying staged", 58),
    ("Books.plist", 62),
    ("Stage complete", 65),
    ("SyncAllowed", 70),
    ("HostInfo", 72),
    ("SyncRequest", 75),
    ("ReadyForSync", 78),
    ("MetadataSyncFinished", 82),
    ("AssetManifest", 86),
    ("AssetCompleted", 93),
    ("Reading back", 95),
    ("Restoring Books", 97),
    ("Cleaning up", 98),
    ("Complete.", 100),
    ("[SUCCESS]", 100),
    ("[FAILED]", 100),
]


def classify_line(line):
    s = line.strip()
    if "SUCCESS" in s:
        return "ok"
    if "FAILED" in s or "error" in s.lower() or "[!]" in s:
        return "err"
    if "warn" in s.lower() or s.startswith("[!]"):
        return "warn"
    if s.startswith("[*]") or s.startswith("[Airlift") or s.startswith("[atc]"):
        return "info"
    return "mut"


def match_progress(line):
    for marker, pct in PROGRESS_MAP:
        if marker in line:
            return pct
    return -1


# ── API（JS 调用，必须快速返回）──

class Api:
    def __init__(self):
        self._window = None
        self.is_running = False
        self._monitor = None
        self._attack_thread = None

        self._lock = threading.Lock()
        self._start_lock = threading.Lock()
        self._log_queue = deque()
        self._progress = 0
        self._progress_dirty = False
        self._device_data = None
        self._device_dirty = False
        self._device_ever_pushed = False
        self._driver_warn = None
        self._driver_dirty = False
        self._trust_hint = False
        self._trust_dirty = False
        self._result_msg = None
        self._result_dirty = False
        self._busy_state = False
        self._busy_dirty = False
        self._has_updates = False
        self._max_logs_per_poll = 25

        # 授权状态（每次拉取时刷新）
        self._license = {"licensed": False, "has_serial": False,
                         "has_device": False, "message": ""}
        self._license_dirty = True

    # JS 轮询入口
    def get_updates(self):
        # 每次轮询刷新授权状态（本地+服务器校验，轻量）
        self._refresh_license()
        if not self._has_updates:
            return None
        with self._lock:
            if not self._has_updates:
                return None
            out = {}
            if self._license_dirty:
                out["license"] = self._license
                self._license_dirty = False
            if self._log_queue:
                n = min(self._max_logs_per_poll, len(self._log_queue))
                out["logs"] = [self._log_queue.popleft() for _ in range(n)]
            if self._progress_dirty:
                out["progress"] = self._progress
                self._progress_dirty = False
            if self._device_dirty:
                out["device"] = self._device_data
                self._device_dirty = False
            if self._driver_dirty:
                out["driver"] = self._driver_warn
                self._driver_dirty = False
            if self._trust_dirty:
                out["trust"] = self._trust_hint
                self._trust_dirty = False
            if self._result_dirty:
                out["result"] = self._result_msg
                self._result_dirty = False
            if self._busy_dirty:
                out["busy"] = self._busy_state
                self._busy_dirty = False
            self._has_updates = bool(
                self._log_queue or self._progress_dirty or
                self._device_dirty or self._driver_dirty or
                self._trust_dirty or self._result_dirty or
                self._busy_dirty or self._license_dirty
            )
            return out

    # ── 启动攻击（后台线程，同进程）──
    def start_attack(self):
        # 并发保护：即使用户快速连点/前端防护失效，也只允许一个攻击流程。
        if not self._start_lock.acquire(blocking=False):
            return {"ok": False, "error": "Already running"}
        try:
            if self.is_running:
                return {"ok": False, "error": "Already running"}
            # 攻击前服务器强校验，未授权直接拒绝
            try:
                import license_client as lc
                # 优先使用 DeviceMonitor 已缓存的 UDID，避免重复检测失败
                udid = ""
                if self._monitor is not None and self._monitor._udid:
                    udid = self._monitor._udid
                    _dbg(f"start_attack: using cached UDID from DeviceMonitor: {udid}")
                else:
                    udid = lc.current_udid()
                    _dbg(f"start_attack: DeviceMonitor UDID not available, called current_udid(): {udid}")
                if not udid:
                    return {"ok": False, "error": "未检测到设备，请连接并信任此电脑", "udid": ""}
                # 授权校验：网络偶发抖动时短暂重试，避免一次超时就误判“未注册”。
                ok, msg = False, ""
                for attempt in range(3):
                    ok, msg = lc.check_registered(udid)
                    if ok:
                        break
                    if "无法连接" in msg or "服务器异常" in msg:
                        _dbg(f"start_attack: 授权校验瞬时失败({attempt+1}/3): {msg}")
                        time.sleep(0.4)
                        continue
                    break
                if not ok:
                    return {"ok": False, "error": msg, "udid": udid}
            except Exception as e:
                _dbg(f"start_attack: license check exception: {e}")
                return {"ok": False, "error": f"授权校验失败: {e}", "udid": ""}
            self.is_running = True
            with self._lock:
                self._log_queue.clear()
                self._progress = 0
                self._progress_dirty = False
                self._result_msg = None
                self._result_dirty = False
            self._set_busy(True)
            self._set_progress(0)

            self._attack_udid = udid
            self._attack_thread = threading.Thread(
                target=self._run_attack_thread, args=(udid,), daemon=True)
            self._attack_thread.start()
            return {"ok": True}
        finally:
            self._start_lock.release()

    # ── 红绿灯按钮（窗口控制）──
    def close_window(self):
        try:
            if getattr(self, "_window", None):
                self._window.destroy()
        except Exception:
            pass

    def minimize_window(self):
        try:
            if getattr(self, "_window", None):
                self._window.minimize()
        except Exception:
            pass

    def maximize_window(self):
        try:
            if getattr(self, "_window", None):
                # pywebview 没有标准全屏切换；用 resize 近似
                # 若当前较小则放大，否则还原
                pass
        except Exception:
            pass

    def move_window(self, x, y):
        """移动窗口到指定屏幕坐标。由 JS 端 mousemove 调用。"""
        try:
            import ctypes
            user32 = ctypes.windll.user32
            # 获取前台窗口，向上找顶层 Form
            hwnd = user32.GetForegroundWindow()
            if hwnd == 0:
                return
            root = user32.GetAncestor(hwnd, 2)  # GA_ROOT
            if root == 0:
                root = hwnd
            SWP_NOSIZE = 0x0001
            SWP_NOZORDER = 0x0004
            SWP_NOACTIVATE = 0x0010
            user32.SetWindowPos(
                root, 0,
                int(x), int(y),
                0, 0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE
            )
        except Exception:
            pass

    def force_frameless(self):
        """Win32 fallback: strip the native caption / system buttons.

        Needed on pywebview versions where ``frameless=True`` is ignored by
        the EdgeChromium backend (window then shows both the HTML traffic
        lights and the Windows min/max/close buttons).
        """
        if sys.platform != "win32":
            return
        try:
            import ctypes
            user32 = ctypes.windll.user32
            GWL_STYLE = -16
            WS_CAPTION = 0x00C00000
            WS_THICKFRAME = 0x00040000
            WS_MINIMIZEBOX = 0x00020000
            WS_MAXIMIZEBOX = 0x00010000
            WS_SYSMENU = 0x00080000
            remove = (WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX
                      | WS_MAXIMIZEBOX | WS_SYSMENU)

            # Find our top-level window by matching the title.
            target = None

            def _enum(hwnd, _l):
                nonlocal target
                length = user32.GetWindowTextLengthW(hwnd)
                if length > 0 and user32.IsWindowVisible(hwnd):
                    buf = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buf, length + 1)
                    if buf.value == "Hide Apple Account":
                        root = user32.GetAncestor(hwnd, 2)  # GA_ROOT
                        target = root
                return True

            WNDENUMPROC = ctypes.WINFUNCTYPE(
                ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
            user32.EnumWindows(WNDENUMPROC(_enum), 0)
            if not target:
                return
            style = user32.GetWindowLongW(target, GWL_STYLE)
            style &= ~remove
            user32.SetWindowLongW(target, GWL_STYLE, style)
            # Re-apply size/position so the frame change takes effect and
            # the client area is not offset.
            SWP_NOMOVE = 0x0002
            SWP_NOSIZE = 0x0001
            SWP_NOZORDER = 0x0004
            SWP_FRAMECHANGED = 0x0020
            user32.SetWindowPos(
                target, 0, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED)
        except Exception as e:
            _dbg(f"force_frameless EXC: {e}")

    def _run_attack_thread(self, udid):
        # 逐行捕获 hide.py 打到 stderr 的内容
        def on_line(line):
            tag = classify_line(line)
            self._add_log(line, tag)
            pct = match_progress(line)
            if pct >= 0:
                self._set_progress(pct)

        buf = _LineBuffer(on_line)
        old_stderr = sys.stderr
        sys.stderr = buf
        if self._monitor is not None:
            self._monitor.pause()
            self._add_log("(paused device monitor during attack)", "mut")
        try:
            import hide as hide_mod
            _dbg(f"_run_attack_thread: using udid={udid}")
            result = hide_mod.attack_accounts(
                udid, verbose=True, dry_run=False, quiet=False,
                mode="rename",
            )
            if result.get("ok"):
                self._set_result({
                    "ok": True,
                    "text": "隐藏成功.请刷新设置或重启手机",
                })
            else:
                err = result.get("error") or self._first_failed_phase(result)
                self._add_log(f"[FAILED] {err}", "err")
                if "prerequisite_failed" in str(err):
                    self._set_result({"ok": False,
                                      "text": "程序文件不完整，请重新安装"})
                else:
                    self._set_result({"ok": False,
                                      "text": f"Attack failed: {err}"})
        except Exception as e:
            traceback.print_exc()
            self._add_log(f"[FAILED] {e}", "err")
            self._set_result({"ok": False, "text": f"Error: {e}"})
        finally:
            try:
                buf.flush()
            except Exception:
                pass
            sys.stderr = old_stderr
            if self._monitor is not None:
                self._monitor.resume()
            self.is_running = False
            self._set_busy(False)

    def _first_failed_phase(self, result):
        for k in ("renameConfirmed", "airTrafficSucceeded", "stageSucceeded",
                  "exactBytesRecovered", "cleanupComplete"):
            if result.get(k) is False:
                return k.replace("Succeeded", "")
        return "unknown"

    def abort(self):
        self.is_running = False
        self._set_busy(False)

    # ── 授权 ──
    def _refresh_license(self):
        try:
            import license_client as lc
            st = lc.status()
            changed = (st != self._license)
            self._license = st
            if changed:
                with self._lock:
                    self._license_dirty = True
                    self._has_updates = True
        except Exception:
            pass

    def activate_license(self, serial):
        # 授权统一在网站完成，软件内不再激活
        return {"ok": False, "message": "请在授权网站完成注册"}

    def open_activation_page(self, udid):
        """用系统默认浏览器打开授权网页（带上UDID）。"""
        import webbrowser
        try:
            import license_client as lc
            url = lc.activation_page_url(udid)
            webbrowser.open(url)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "message": str(e)}

    # ── 内部 setter（线程安全）──
    def _add_log(self, text, tag=""):
        with self._lock:
            if len(self._log_queue) > 300:
                items = list(self._log_queue)
                items = items[:3] + items[-80:]
                items.insert(3, {"t": "mut", "x": "  ... skipped ..."})
                self._log_queue.clear()
                self._log_queue.extend(items)
            self._log_queue.append({"t": tag, "x": text})
            self._has_updates = True

    def _set_progress(self, pct):
        pct = int(pct)
        with self._lock:
            self._progress = pct
            self._progress_dirty = True
            self._has_updates = True

    def _set_device(self, data):
        with self._lock:
            self._device_data = data
            self._device_dirty = True
            self._device_ever_pushed = True
            self._has_updates = True

    def _never_pushed_device(self):
        with self._lock:
            return not self._device_ever_pushed

    def _set_driver_warn(self, info):
        with self._lock:
            self._driver_warn = info
            self._driver_dirty = True
            self._has_updates = True

    def _set_trust_hint(self, show):
        with self._lock:
            self._trust_hint = show
            self._trust_dirty = True
            self._has_updates = True

    def _set_result(self, result):
        with self._lock:
            self._result_msg = result
            self._result_dirty = True
            self._has_updates = True

    def _set_busy(self, busy):
        with self._lock:
            self._busy_state = busy
            self._busy_dirty = True
            self._has_updates = True


class _LineBuffer(io.StringIO):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self._buf = ""

    def write(self, s):
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.rstrip("\r")
            if line:
                self.callback(line)
        return len(s)

    def flush(self):
        if self._buf:
            line = self._buf.rstrip("\r")
            self._buf = ""
            if line:
                self.callback(line)


# ── 设备监听（后台线程）──

class DeviceMonitor:
    def __init__(self, api):
        self.api = api
        self._stop = threading.Event()
        self._paused = threading.Event()
        self._thread = None
        self._udid = None
        self._driver_ok = None
        self._reading = False

    def pause(self):
        # 攻击期间暂停监听，避免与 ATC 独占会话冲突
        self._paused.set()

    def resume(self):
        self._paused.clear()

    def start(self, delay=2.0):
        if self._thread is not None:
            _dbg("DeviceMonitor.start ignored: already started")
            return
        def delayed_start():
            self._stop.wait(delay)
            if not self._stop.is_set():
                self._loop()
        self._thread = threading.Thread(target=delayed_start, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        _dbg("DeviceMonitor _loop started")
        while not self._stop.is_set():
            if self._paused.is_set():
                # 攻击期间：睡到被恢复或停止，期间不碰设备
                self._paused.wait()
                continue
            try:
                self._tick()
            except Exception:
                _dbg("_tick EXC:\n" + traceback.format_exc())
            interval = 2.0 if not self._udid else 4.0
            self._stop.wait(interval)
        _dbg("DeviceMonitor _loop exited")

    def _tick(self):
        if self._reading:
            return
        driver_ok, driver_detail = _check_driver()
        _dbg("_tick driver_ok=%s detail=%r"
             % (driver_ok, (driver_detail or "")[:300]))
        if driver_ok != self._driver_ok:
            self._driver_ok = driver_ok
            if driver_ok:
                self.api._set_driver_warn(None)
            else:
                detail = (driver_detail or "").strip()
                if detail:
                    _dbg("driver unavailable detail:\n" + detail)
                self.api._set_driver_warn({
                    "problem": "未检测到 Apple 设备驱动",
                    "suggestion": ("请安装 iTunes 或 Apple Devices 驱动后重启。"
                                   + ("\n诊断: " + detail[:400] if detail else "")),
                })
                if self._udid:
                    self._udid = None
                    self.api._set_device(
                        {"success": False, "data": [], "error": "No device"})
            return
        if not driver_ok:
            return

        devices = _list_devices()
        has_device = len(devices) > 0
        udid = devices[0] if has_device else None

        if not has_device:
            # 首次检测即无设备也要推送，否则前端永远停在占位符 "-"。
            if self._udid is not None or self.api._never_pushed_device():
                self._udid = None
                self.api._set_device(
                    {"success": False, "data": [], "error": "No device"})
            return

        if has_device and udid != self._udid:
            # 新设备接入时自动归零进度条和结果
            self.api._set_progress(0)
            self.api._set_result(None)
            self._reading = True
            try:
                result = _read_info(udid)
            finally:
                self._reading = False
            if result.get("success"):
                self._udid = udid
                self.api._set_device(result)
                self.api._set_trust_hint(bool(result.get("needs_trust")))
                _dbg("_tick: 设备信息已推送到前端")
            else:
                self.api._set_trust_hint(True)
                _dbg(f"_tick: 读取失败，未更新 _udid，error={result.get('error')}")
                # 失败也推送错误信息，便于前端提示
                self.api._set_device(result)


def _close_splash():
    """关闭 PyInstaller 单文件模式的启动屏（仅打包后存在）。"""
    try:
        import pyi_splash  # type: ignore
        pyi_splash.close()
    except Exception:
        pass


def _splash_text(text):
    """更新启动屏上的进度文字（仅打包后存在）。"""
    try:
        import pyi_splash  # type: ignore
        pyi_splash.update_text(text)
    except Exception:
        pass


def main():
    if webview is None:
        print("pywebview 未安装，请先运行: pip install pywebview")
        input("按回车退出...")
        sys.exit(1)

    _splash_text("正在启动...")
    api = Api()
    _splash_text("正在加载界面...")
    window = webview.create_window(
        title="Hide Apple Account",
        url=resource_path("index.html"),
        js_api=api,
        width=565,
        height=380,
        resizable=False,
        frameless=True,
        easy_drag=False,
        background_color="#ffffff",
    )
    api._window = window

    monitor = DeviceMonitor(api)
    api._monitor = monitor

    def on_loaded():
        _splash_text("就绪")
        # 稍作停留显示“就绪”，再关闭启动屏
        threading.Timer(0.4, _close_splash).start()
        # 兜底强制无边框（某些 pywebview 版本 frameless 被忽略）
        threading.Timer(0.6, api.force_frameless).start()
        monitor.start(delay=2.5)

    def on_closing():
        monitor.stop()

    try:
        window.events.loaded += on_loaded
        window.events.closing += on_closing
    except Exception:
        threading.Timer(3.0, lambda: monitor.start(delay=0)).start()

    # 兜底：不依赖 loaded 事件，窗口创建 4 秒后确保监控一定启动
    def _ensure_monitor():
        if monitor._thread is None:
            _dbg("loaded 未触发，强制启动 DeviceMonitor")
            monitor.start(delay=0)
    threading.Timer(4.0, _ensure_monitor).start()

    # 兜底：无论 loaded 是否触发，8 秒后强制关闭启动屏
    threading.Timer(8.0, _close_splash).start()

    webview.start()


if __name__ == "__main__":
    main()
