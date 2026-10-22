#!/usr/bin/env python3
"""
Apple 原生设备传输层（MobileDevice.dll）。

与第三方 IFineOpenHide 完全一致：直接在本进程内 P/Invoke 苹果官方
MobileDevice.dll 完成设备发现 / 配对 / 会话 / AFC / streaming_zip_conduit，
不再使用 libimobiledevice 开源 DLL。

运行时目录 proven_native_lite 内的 DLL 与第三方 AppleSupport 逐字节相同
（已 md5 校验，含 CoreFP / MobileDevice）。

本模块对外接口保持与原设备传输封装层兼容：
  is_available / load_error / list_devices / read_device_info
  iDevice / LockdownClient / AFCClient / StreamingZipConduitClient
"""

from __future__ import annotations

import os
import sys
import time
import ctypes
import subprocess
import threading
from ctypes import (
    c_void_p, c_char_p, c_int, c_uint32, c_uint64, c_longlong, byref,
    CFUNCTYPE, POINTER, Structure,
)

# 复用原生 ATC 桥里的运行时定位与 CF 封装（同一套 proven_native_lite）。
from atc_native_bridge import (
    _device_dir, _CF, _windows_version_string,  # noqa: F401
)


# ── 真机诊断弹窗（一次性，确保失败原因直接可见，不依赖日志文件）──────────
_diag_shown = False
_WRAPPER_VERSION = "trace-v5-fallback"

# 模块被 import 的第一时间留痕（即便之后 _init 失败也能看到这行）。
try:
    import bootlog as _bl0
    _bl0.log("apple_native_wrapper 模块被 import（frozen=%s exe=%s）"
             % (getattr(sys, "frozen", False), sys.executable))
except Exception as _bl0e:
    pass


def _trace(msg):
    """设备层追踪：进入全量 bootlog + 写独立 wrapper_trace.log。"""
    # ① 进入全量日志（与 app 同文件，时间线完整）
    try:
        import bootlog
        bootlog.log(msg)
    except Exception:
        pass
    import datetime
    line = "[%s] [trace] %s\n" % (
        datetime.datetime.now().strftime("%H:%M:%S"), msg)
    # ② 写独立文件（兜底）
    paths = []
    try:
        buf = ctypes.create_unicode_buffer(260)
        ctypes.windll.shell32.SHGetFolderPathW(0, 0, 0, 0, buf)
        if buf.value:
            paths.append(os.path.join(buf.value, "wrapper_trace.log"))
    except Exception:
        pass
    try:
        import tempfile
        paths.append(os.path.join(tempfile.gettempdir(), "wrapper_trace.log"))
    except Exception:
        pass
    try:
        exe_dir = os.path.dirname(sys.executable)
        p = os.path.join(exe_dir, "wrapper_trace.log")
        if p not in paths:
            paths.append(p)
    except Exception:
        pass
    for p in paths:
        try:
            with open(p, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass


def _last_win_error() -> str:
    try:
        k32 = ctypes.windll.kernel32
        code = k32.GetLastError()
        return "GetLastError=%d (0x%x)" % (code, code)
    except Exception:
        return ""


def _diag_alert(stage: str, detail: str) -> None:
    global _diag_shown
    if _diag_shown:
        return
    _diag_shown = True
    try:
        from atc_native_bridge import _third_party_style_candidates
        lines = ["阶段: " + stage, "", detail.strip(), "", "—— 候选目录 ——"]
        for d in _third_party_style_candidates():
            md_p = os.path.join(d, "MobileDevice.dll")
            cf_p = os.path.join(d, "CoreFoundation.dll")
            lines.append("[MD:%s CF:%s] %s" % (
                "Y" if os.path.isfile(md_p) else "-",
                "Y" if os.path.isfile(cf_p) else "-", d))
        text = "\n".join(lines)
        user32 = ctypes.windll.user32
        user32.MessageBoxW(0, text, "Apple 驱动诊断", 0x40)
    except Exception:
        pass


# ── AFC 常量（与苹果 AFC 协议一致）────────────────────────────────────────
AFC_FOPEN_RDONLY = 0x1
AFC_FOPEN_RW = 0x2
AFC_FOPEN_WRONLY = 0x3
AFC_FOPEN_WR = 0x4
AFC_FOPEN_APPEND = 0x5

AFC_HARDLINK = 1
AFC_SYMLINK = 2

# 设备通知消息
AMDN_MSG_CONNECTED = 1
AMDN_MSG_DISCONNECTED = 2
AMDN_MSG_UNSUBSCRIBED = 3


class _ServiceDescriptor:
    """兼容旧 lockdownd_service_descriptor_t：只需要携带服务名。"""
    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name


_md = None          # MobileDevice CDLL
_cf = None          # _CF 实例
_init_lock = threading.Lock()
_devices: dict[str, c_void_p] = {}   # udid -> 复制后的设备句柄
_raw_to_udid: dict[int, str] = {}     # 原始设备指针 → udid（供断连匹配）
_dev_lock = threading.Lock()
_load_error = ""


def _init() -> bool:
    global _md, _cf, _load_error
    _trace("=== _init 开始 ===")
    _trace("  sys.frozen=%s" % getattr(sys, 'frozen', None))
    _trace("  sys.executable=%s" % sys.executable)
    _trace("  _MEIPASS=%s" % getattr(sys, '_MEIPASS', None))
    _trace("  __file__=%s" % __file__)
    with _init_lock:
        if _md is not None:
            _trace("  _init: _md 已存在，跳过")
            return True
        # 逐字复刻第三方 Configure：补 PATH + SetDllDirectory 到含双 DLL 的目录。
        _trace("  调用 configure()...")
        from atc_native_bridge import configure, _device_dir
        if not configure():
            _load_error = ("未找到 Apple 正常模式组件。请保留发布包内 "
                           "AppleSupport 文件夹。 " + _last_win_error())
            _trace("  configure() 失败: %s" % _load_error)
            _diag_alert("Configure 失败（未找到含双 DLL 的目录）", _load_error)
            return False
        runtime = _device_dir()
        _trace("  configure() 成功, runtime=%s" % runtime)
        _trace("  runtime 目录内容: %s" % (os.listdir(runtime) if os.path.isdir(runtime) else "NOT A DIR"))
        # 加载顺序与第三方一致：先 CoreFoundation，再 MobileDevice，均按名字
        # （SetDllDirectory 已把目标目录插入默认搜索序列，含依赖解析）。
        cf_name = "CoreFoundation.dll"
        md_name = "MobileDevice.dll"
        _trace("  即将加载 %s (从 %s)..." % (cf_name, runtime))
        try:
            _cf = _CF(cf_name, runtime)
            _trace("  CoreFoundation.dll 加载成功: _cf=%s" % _cf)
            _trace("  _cf.cf=%s" % _cf.cf)
        except Exception as exc:  # noqa: BLE001
            import traceback
            _load_error = ("CoreFoundation.dll 加载失败，请检查 AppleSupport。"
                           " %r %s\n%s" % (exc, _last_win_error(),
                                          traceback.format_exc()))
            _trace("  CoreFoundation.dll 加载失败: %s" % _load_error)
            _diag_alert("CoreFoundation.dll 加载失败", _load_error)
            return False
        _trace("  即将加载 %s..." % md_name)
        try:
            _md = ctypes.CDLL(md_name)
            _trace("  MobileDevice.dll 加载成功: _md=%s" % _md)
            _trace("  _md._name=%s" % getattr(_md, '_name', 'N/A'))
        except Exception as exc:  # noqa: BLE001
            import traceback
            _load_error = ("MobileDevice.dll 加载失败，请检查 AppleSupport。"
                           " %r %s\n%s" % (exc, _last_win_error(),
                                          traceback.format_exc()))
            _trace("  MobileDevice.dll 加载失败: %s" % _load_error)
            _diag_alert("MobileDevice.dll 加载失败", _load_error)
            return False
        try:
            _trace("  调用 _bind_cf_extra()...")
            _bind_cf_extra()
            _trace("  _bind_cf_extra() 完成")
            _trace("  调用 _bind()...")
            _bind()
            _trace("  _bind() 完成")
            _trace("  调用 _start_watcher()...")
            _start_watcher()
            _trace("  _start_watcher() 完成")
        except Exception as exc:  # noqa: BLE001
            import traceback
            _load_error = ("bind/start watcher failed: %r %s\n%s"
                           % (exc, _last_win_error(), traceback.format_exc()))
            _trace("  初始化异常: %s" % _load_error)
            _diag_alert("绑定/订阅启动失败", _load_error)
            return False
        _trace("=== _init 完成 ===")
        return True


def _bind_cf_extra() -> None:
    cf = _cf.cf
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFNumberGetValue.argtypes = [c_void_p, c_int, c_void_p]
    cf.CFBooleanGetValue.restype = ctypes.c_bool
    cf.CFBooleanGetValue.argtypes = [c_void_p]
    cf.CFRunLoopRun.restype = None
    cf.CFRunLoopRun.argtypes = []


def _bind() -> None:
    md = _md

    # 设备通知
    md.AMDeviceNotificationSubscribe.restype = c_int
    md.AMDeviceNotificationSubscribe.argtypes = [
        c_void_p, c_uint32, c_uint32, c_uint32, POINTER(c_void_p)]
    md.AMDeviceNotificationUnsubscribe.restype = c_int
    md.AMDeviceNotificationUnsubscribe.argtypes = [c_void_p]

    # 同步枚举当前设备（独立于通知补发；返回 CFArrayRef，元素为 AMDeviceRef）
    md.AMDCreateDeviceList.restype = c_void_p
    md.AMDCreateDeviceList.argtypes = []

    # 生命周期
    md.AMDeviceConnect.restype = c_int
    md.AMDeviceConnect.argtypes = [c_void_p]
    md.AMDeviceDisconnect.restype = c_int
    md.AMDeviceDisconnect.argtypes = [c_void_p]
    md.AMDeviceCreateCopy.restype = c_void_p
    md.AMDeviceCreateCopy.argtypes = [c_void_p]
    md.AMDeviceIsPaired.restype = c_int
    md.AMDeviceIsPaired.argtypes = [c_void_p]
    md.AMDevicePair.restype = c_int
    md.AMDevicePair.argtypes = [c_void_p]
    md.AMDeviceUnpair.restype = c_int
    md.AMDeviceUnpair.argtypes = [c_void_p]
    md.AMDeviceValidatePairing.restype = c_int
    md.AMDeviceValidatePairing.argtypes = [c_void_p]
    md.AMDeviceStartSession.restype = c_int
    md.AMDeviceStartSession.argtypes = [c_void_p]
    md.AMDeviceStopSession.restype = c_int
    md.AMDeviceStopSession.argtypes = [c_void_p]
    md.AMDeviceCopyValue.restype = c_void_p
    # 第三方托管方法名为 AMDeviceCopyValueNative，但 P/Invoke EntryPoint 显式
    # 指向真实导出名 AMDeviceCopyValue。ctypes 按属性名查导出，故用真实名
    # 绑定，再赋同名别名以对齐第三方托管命名。
    md.AMDeviceCopyValue.argtypes = [c_void_p, c_void_p, c_void_p]
    md.AMDeviceCopyValueNative = md.AMDeviceCopyValue

    # 服务
    md.AMDeviceSecureStartService.restype = c_int
    md.AMDeviceSecureStartService.argtypes = [
        c_void_p, c_void_p, c_void_p, POINTER(c_void_p)]
    md.AMDeviceStartServiceWithOptions.restype = c_int
    md.AMDeviceStartServiceWithOptions.argtypes = [
        c_void_p, c_void_p, c_void_p, POINTER(c_void_p)]

    md.AMDServiceConnectionGetSocket.restype = c_int
    md.AMDServiceConnectionGetSocket.argtypes = [c_void_p]
    md.AMDServiceConnectionGetSecureIOContext.restype = c_void_p
    md.AMDServiceConnectionGetSecureIOContext.argtypes = [c_void_p]
    md.AMDServiceConnectionInvalidate.restype = c_int
    md.AMDServiceConnectionInvalidate.argtypes = [c_void_p]
    md.AMDServiceConnectionSend.restype = c_int
    md.AMDServiceConnectionSend.argtypes = [c_void_p, c_char_p, c_uint32]
    md.AMDServiceConnectionReceive.restype = c_int
    md.AMDServiceConnectionReceive.argtypes = [c_void_p, c_char_p, c_uint32]
    md.AMDServiceConnectionSendMessage.restype = c_int
    md.AMDServiceConnectionSendMessage.argtypes = [c_void_p, c_void_p, c_int]
    md.AMDServiceConnectionReceiveMessage.restype = c_int
    md.AMDServiceConnectionReceiveMessage.argtypes = [
        c_void_p, POINTER(c_void_p), c_void_p]

    # AFC
    md.AFCConnectionOpen.restype = c_int
    md.AFCConnectionOpen.argtypes = [c_int, c_uint32, POINTER(c_void_p)]
    md.AFCConnectionClose.restype = c_int
    md.AFCConnectionClose.argtypes = [c_void_p]
    md.AFCConnectionSetSecureContext.restype = c_int
    md.AFCConnectionSetSecureContext.argtypes = [c_void_p, c_void_p]
    md.AFCDirectoryCreate.restype = c_int
    md.AFCDirectoryCreate.argtypes = [c_void_p, c_char_p]
    md.AFCDirectoryOpen.restype = c_int
    md.AFCDirectoryOpen.argtypes = [c_void_p, c_char_p, POINTER(c_void_p)]
    md.AFCDirectoryRead.restype = c_int
    md.AFCDirectoryRead.argtypes = [
        c_void_p, c_void_p, POINTER(c_char_p)]
    md.AFCDirectoryClose.restype = c_int
    md.AFCDirectoryClose.argtypes = [c_void_p, c_void_p]
    md.AFCFileInfoOpen.restype = c_int
    md.AFCFileInfoOpen.argtypes = [c_void_p, c_char_p, POINTER(c_void_p)]
    md.AFCKeyValueRead.restype = c_int
    md.AFCKeyValueRead.argtypes = [
        c_void_p, POINTER(c_char_p), POINTER(c_char_p)]
    md.AFCKeyValueClose.restype = c_int
    md.AFCKeyValueClose.argtypes = [c_void_p]
    md.AFCRemovePath.restype = c_int
    md.AFCRemovePath.argtypes = [c_void_p, c_char_p]
    md.AFCFileRefOpen.restype = c_int
    md.AFCFileRefOpen.argtypes = [
        c_void_p, c_char_p, c_int, POINTER(c_uint64)]
    md.AFCFileRefWrite.restype = c_int
    md.AFCFileRefWrite.argtypes = [
        c_void_p, c_uint64, c_char_p, c_uint32]
    md.AFCFileRefRead.restype = c_int
    md.AFCFileRefRead.argtypes = [
        c_void_p, c_uint64, c_char_p, POINTER(c_uint32)]
    md.AFCFileRefClose.restype = c_int
    md.AFCFileRefClose.argtypes = [c_void_p, c_uint64]
    md.AFCRenamePath.restype = c_int
    md.AFCRenamePath.argtypes = [c_void_p, c_char_p, c_char_p]
    md.AFCLinkPath.restype = c_int
    md.AFCLinkPath.argtypes = [c_void_p, c_int, c_char_p, c_char_p]


# ── 设备发现（通知 + CFRunLoop，对齐第三方 DeviceWatcher）─────────────────

# 原生回调 ABI 只有两个参数：
#   arg0 = am_device_notification_callback_info* { nint dev@0; uint msg@8 }
#   arg1 = user context（订阅时为 NULL）
_AMNotificationCallback = CFUNCTYPE(None, c_void_p, c_void_p)


def _ptr(v):
    """统一取指针整数值。

    restype=c_void_p 的函数返回 Python int；而 ctypes 对象（c_void_p 实例、
    byref 包装等）带 .value。本函数把两者都规整为整数（NULL -> 0），
    避免在 int 上访问 .value 抛 'int' object has no attribute 'value'。
    """
    if v is None:
        return 0
    if isinstance(v, int):
        return v
    try:
        return int(v.value) if v.value is not None else 0
    except AttributeError:
        return int(v) if v else 0


def _copy_value(device: c_void_p, key: str):
    """AMDeviceCopyValue；返回 Python 值（字符串/数字）。domain 固定 NULL。"""
    k = _cf.s(key)
    try:
        ref = _md.AMDeviceCopyValueNative(device, None, k)
        ref_val = ref.value if hasattr(ref, 'value') else (ref or 0)
        _trace("CopyValue(%s) -> ref=0x%x" % (key, ref_val))
    except Exception as e:
        _trace("CopyValue(%s) EXCEPTION: %r" % (key, e))
        _cf.release(k)
        return None
    finally:
        try:
            _cf.release(k)
        except Exception:
            pass
    if not ref:
        return None
    try:
        # 值可能是 CFString / CFNumber / CFBoolean，统一用描述+长度判定
        return _cf_to_python(ref)
    finally:
        _cf.release(ref)


def _connect_and_read_udid(device) -> str:
    """对齐第三方 DeviceSession.Ensure 的关键顺序：

      ConnectWithRetry -> 再 CopyValue('UniqueDeviceID')

    Windows 上设备处于"发现态"、未 Connect 时 AMDeviceCopyValue 返回 NULL。
    本函数先 Connect（最多重试），再读 UDID。成功后保持连接，返回 udid；
    失败返回 None。句柄保持连接状态以便后续会话直接复用。
    """
    try:
        err = _md.AMDeviceConnect(device)
        if err != 0:
            _trace("  _connect_and_read_udid 首次 Connect=%s，进入重试"
                   % (err & 0xffffffff))
            for _ in range(2):
                try:
                    _md.AMDeviceDisconnect(device)
                except Exception:
                    pass
                time.sleep(0.35)
                err = _md.AMDeviceConnect(device)
                if err == 0:
                    break
        if err != 0:
            _trace("  _connect_and_read_udid Connect 最终失败: %s"
                   % (err & 0xffffffff))
            return None
        _trace("  _connect_and_read_udid Connect 成功，读取 UniqueDeviceID")
        udid = _copy_value(device, "UniqueDeviceID")
        _trace("  _connect_and_read_udid UniqueDeviceID=%r" % udid)
        return str(udid) if udid else None
    except Exception as exc:
        _trace("  _connect_and_read_udid 异常: %r" % exc)
        return None


def _cf_to_python(ref: c_void_p):
    # 字符串
    try:
        s = _cf.to_str(ref)
        if s is not None:
            return s
    except Exception:
        pass
    # CFNumber 取值（使用类型安全检查）
    try:
        n = _cf.to_number(ref)
        if n is not None:
            _trace("_cf_to_python: CFNumber -> %s" % n)
            return n
        else:
            _trace("_cf_to_python: to_number returned None for ref=0x%x" % (ref.value if ref and ref.value else 0))
    except Exception as exc:
        _trace("_cf_to_python: to_number EXCEPTION: %s" % exc)
    # 布尔
    try:
        if _cf.cf.CFBooleanGetValue(ref):
            return True
    except Exception:
        pass
    # 兜底：CF 描述
    try:
        d = _cf.describe(ref)
        if d:
            _trace("_cf_to_python: fell back to describe -> %s" % d[:80])
            return d
    except Exception:
        pass
    return ""


def _on_notification(info_ptr, _ctx):
    # 最直接的回调触发验证
    try:
        import tempfile as _tf
        _cp = os.path.join(_tf.gettempdir(), "callback_triggered.txt")
        with open(_cp, "a") as _cf2:
            _cf2.write("callback triggered info_ptr=%s ctx=%s time=%s\n" % (
                info_ptr, _ctx, __import__("datetime").datetime.now().isoformat()))
    except Exception:
        pass
    # 原生回调 ABI：
    #   arg0 = am_device_notification_callback_info*
    #          { nint dev@0; uint msg@8 }
    #   arg1 = user context（订阅传 NULL，忽略）
    try:
        device = ctypes.cast(info_ptr, POINTER(c_void_p))[0]
        msg = ctypes.cast(info_ptr + 8, POINTER(c_uint32))[0]
    except Exception as exc:
        _trace("回调解析 info 失败: %r" % exc)
        return
    _trace("通知到达 msg=%s device=0x%x" % (msg, _ptr(device)))
    if not device:
        return
    if msg == AMDN_MSG_CONNECTED:
        copy = _md.AMDeviceCreateCopy(device)
        _trace("AMDeviceCreateCopy -> 0x%x" % _ptr(copy))
        if not copy:
            return
        # 必须先 Connect 再读 UniqueDeviceID（对齐第三方 DeviceSession.Ensure：
        # ConnectWithRetry -> CopyValueSafe）。发现态直接 CopyValue 返回 NULL。
        udid = None
        try:
            udid = _connect_and_read_udid(copy)
        except Exception as exc:
            _trace("连接读取 UniqueDeviceID EXC: %r" % exc)
            udid = None
        # 读取后断开（真正建会话时由会话层再 Connect）。
        try:
            _md.AMDeviceDisconnect(copy)
        except Exception:
            pass
        _trace("读取 UniqueDeviceID = %r" % udid)
        if not udid:
            _cf.release(copy)
            return
        with _dev_lock:
            old = _devices.get(str(udid))
            _devices[str(udid)] = copy
            _raw_to_udid[device] = str(udid)
            _trace("已加入设备表 udid=%s 共 %d 台" % (udid, len(_devices)))
        if old:
            try:
                _cf.release(old)
            except Exception:
                pass
    elif msg == AMDN_MSG_DISCONNECTED:
        # 断连时设备已不可读，从原始指针匹配对应的 copy 并移除。
        # 利用 _raw_to_udid 映射：connect 时记录 raw_device → udid。
        _trace("断连 device=0x%x" % _ptr(device))
        matched_udid = None
        try:
            matched_udid = _raw_to_udid.pop(device, None)
        except Exception:
            pass
        _trace("断连匹配 udid=%r" % matched_udid)
        if matched_udid:
            with _dev_lock:
                ptr = _devices.pop(str(matched_udid), None)
            if ptr:
                try:
                    _cf.release(ptr)
                except Exception:
                    pass


_notif_cb = _AMNotificationCallback(_on_notification)


def _watcher_thread():
    # 最简单的直接写文件验证，不依赖任何复杂逻辑
    try:
        import tempfile
        _test_path = os.path.join(tempfile.gettempdir(), "watcher_thread_alive.txt")
        with open(_test_path, "w") as _f:
            _f.write("alive %s\n" % __import__("datetime").datetime.now().isoformat())
        import ctypes as _ct
        _buf = _ct.create_unicode_buffer(260)
        _ct.windll.shell32.SHGetFolderPathW(0, 0, 0, 0, _buf)
        if _buf.value:
            _test_path2 = os.path.join(_buf.value, "watcher_thread_alive.txt")
            with open(_test_path2, "w") as _f:
                _f.write("alive %s\n" % __import__("datetime").datetime.now().isoformat())
    except Exception as _e:
        pass

    sub = c_void_p(0)
    _trace("watcher 线程进入")
    try:
        _trace("即将 CoInitialize")
        ctypes.oledll.ole32.CoInitialize(None)
        _trace("CoInitialize 完成")
    except Exception as e:
        _trace("CoInitialize 异常: %r" % e)
    try:
        _trace("即将 Subscribe")
        err = _md.AMDeviceNotificationSubscribe(
            _notif_cb, 0, 1, 0, byref(sub))
        _trace("Subscribe 返回=%s sub=0x%x" % (err, _ptr(sub)))
        if err != 0:
            _diag_alert(
                "AMDeviceNotificationSubscribe 返回非 0",
                "订阅失败，返回码 = 0x%x (%d)。%s"
                % (err & 0xffffffff, err, _last_win_error()))
            return
        _trace("初始同步枚举（Subscribe 之后立即补一次，连接后读 UDID）...")
        try:
            arr = _md.AMDCreateDeviceList()
            if arr and (not hasattr(arr, 'value') or arr.value):
                count = _cf.array_count(arr)
                _trace("  AMDCreateDeviceList count=%d" % count)
                for i in range(count):
                    device = _cf.array_get(arr, i)
                    if device:
                        try:
                            udid = _connect_and_read_udid(device)
                            if udid:
                                copy = _md.AMDeviceCreateCopy(device)
                                if copy and _ptr(copy):
                                    with _dev_lock:
                                        _devices.setdefault(str(udid), copy)
                                        _raw_to_udid[device] = str(udid)
                                    _trace("  初始发现设备: %s" % udid)
                            try:
                                _md.AMDeviceDisconnect(device)
                            except Exception:
                                pass
                        except Exception as exc:
                            _trace("  初始枚举设备 %d 异常: %r" % (i, exc))
                try:
                    _cf.cf.CFRelease(arr)
                except Exception:
                    pass
        except Exception as exc:
            _trace("  初始 AMDCreateDeviceList 异常: %r" % exc)

        _trace("进入 Windows 消息泵（替代 CFRunLoopRun，对齐 .NET STA 行为）")
        user32 = ctypes.windll.user32
        msg = ctypes.wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        _trace("消息泵退出")
    except Exception as exc:  # noqa: BLE001
        import traceback
        _trace("监控线程异常: %r\n%s" % (exc, traceback.format_exc()))
        _diag_alert("监控线程异常", "%r %s" % (exc, _last_win_error()))
        return
    finally:
        try:
            ctypes.oledll.ole32.CoUninitialize()
        except Exception:
            pass


def _start_watcher():
    # STA 线程订阅；等待已连接设备的补发通知到达。
    _trace("_start_watcher 调用")
    t = threading.Thread(target=_watcher_thread, daemon=True)
    t.start()
    _trace("_start_watcher: thread.is_alive=%s" % t.is_alive())
    time.sleep(1.2)
    _trace("_start_watcher sleep 结束: thread.is_alive=%s" % t.is_alive())


# ── 设备会话（对齐第三方 DeviceSession）──────────────────────────────────

def _connect_with_retry(device) -> None:
    """复刻第三方 ConnectWithRetry：最多重试 2 次，间隔 350ms"""
    err = _md.AMDeviceConnect(device)
    if err == 0:
        return
    for i in range(2):  # 最多重试 2 次
        try:
            _md.AMDeviceDisconnect(device)
        except Exception:
            pass
        time.sleep(0.35)  # 350ms 等待驱动重置
        err = _md.AMDeviceConnect(device)
        if err == 0:
            return
    raise RuntimeError("AMDeviceConnect 失败: %#x" % (err & 0xFFFFFFFF))


def _start_session_with_retry(device) -> None:
    """复刻第三方 StartSessionWithRetry：最多重试 2 次，间隔 450ms"""
    err = _md.AMDeviceStartSession(device)
    if err == 0:
        return
    for i in range(2):  # 最多重试 2 次
        try:
            _md.AMDeviceStopSession(device)
        except Exception:
            pass
        try:
            _md.AMDeviceDisconnect(device)
        except Exception:
            pass
        time.sleep(0.45)  # 450ms 等待
        
        connect_result = _md.AMDeviceConnect(device)
        if connect_result != 0:
            err = connect_result
        else:
            err = _md.AMDeviceStartSession(device)
            if err == 0:
                return
    raise RuntimeError("AMDeviceStartSession 失败: %#x" % (err & 0xFFFFFFFF))


def _ensure_session(device) -> None:
    _connect_with_retry(device)
    if _md.AMDeviceValidatePairing(device) != 0:
        if _md.AMDevicePair(device) != 0:
            time.sleep(0.3)
        if _md.AMDeviceValidatePairing(device) != 0:
            raise RuntimeError("设备未信任/配对失败，请解锁手机并点击信任。")
    _start_session_with_retry(device)


# ── 对外兼容接口 ──────────────────────────────────────────────────────────

def is_available() -> bool:
    return _init()


def load_error() -> str:
    return _load_error


def list_devices() -> list[str]:
    """枚举当前连接的 iOS 设备。
    
    主路径：AMDCreateDeviceList 同步枚举（驱动崩溃时回调不可靠）。
    辅助路径：通知回调（用于热插拔检测，但驱动崩溃时会延迟或丢失）。
    """
    if not _init():
        _trace("list_devices: _init 失败，返回 []")
        return []

    with _dev_lock:
        cached = list(_devices.keys())
    _trace("list_devices: 当前回调缓存=%r" % cached)

    # 每次都做一次同步枚举对账（AMDCreateDeviceList 反映当前真实连接）。
    # 断连通知在部分环境会丢失，若只信缓存，拔掉设备后会一直返回幽灵设备。
    found = list(_native_sync_probe())
    live_udids = {u for u, _ in found if u}
    _trace("list_devices: 同步探测返回 %d 台 %r"
           % (len(found), list(live_udids)))
    with _dev_lock:
        # 新增当前在线但缓存里没有的设备
        for udid, handle in found:
            if udid and udid not in _devices:
                _devices[udid] = handle
                _trace("list_devices: 同步探测到新设备 %s" % udid)
        # 移除缓存里有、但当前已不在线的设备（=已拔除）
        stale = [u for u in list(_devices.keys()) if u not in live_udids]
        for u in stale:
            ptr = _devices.pop(u, None)
            _trace("list_devices: 设备已拔除，移除缓存 %s" % u)
            if ptr:
                try:
                    _cf.release(ptr)
                except Exception:
                    pass

    with _dev_lock:
        result = list(_devices.keys())
    _trace("list_devices: 最终返回 %r" % result)
    return result


class iDevice:
    """设备句柄包装（句柄来自通知缓存，与第三方 DevicePtr 一致）。"""

    def __init__(self, udid: str | None = None):
        if not _init():
            raise RuntimeError("Apple MobileDevice not available: " + _load_error)
        if not udid:
            with _dev_lock:
                if _devices:
                    udid = next(iter(_devices))
        self._udid = udid
        with _dev_lock:
            self._handle = _devices.get(udid) if udid else None
        if not self._handle:
            raise RuntimeError("device not found: %s" % udid)

    def free(self):
        # 句柄由全局通知缓存持有生命周期，这里不释放（对齐第三方复制语义）。
        self._handle = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def handle(self):
        return self._handle


class LockdownClient:
    """兼容垫片。

    第三方不使用 lockdown 客户端对象，直接 AMDeviceSecureStartService；
    这里保留构造/释放接口，start_service 返回携带服务名的描述符。
    """

    def __init__(self, device, label: str = "airlift", handshake: bool = True):
        self._device = device
        self._handshake = bool(handshake)

    @property
    def has_handshake(self) -> bool:
        return self._handshake

    def get_value(self, key: str | None = None, domain: str | None = None):
        if not key:
            out = {}
            for k in ("DeviceName", "ProductType", "ProductVersion",
                      "BuildVersion", "SerialNumber"):
                v = _copy_value(self._device.handle, k)
                if v is not None:
                    out[k] = v
            return out
        return _copy_value(self._device.handle, key)

    def start_service(self, name: str) -> _ServiceDescriptor:
        return _ServiceDescriptor(name)

    def free(self):
        self._device = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass


class AFCClient:
    """苹果原生 AFC 连接包装。"""

    def __init__(self, device, service):
        if not _init():
            raise RuntimeError("Apple MobileDevice not available")
        name = service.name if isinstance(service, _ServiceDescriptor) else str(service)
        self._device = device.handle
        self._svc_name = name
        self._conn = None
        self._open()

    def _secure_start(self):
        svc = c_void_p(0)
        sref = _cf.s(self._svc_name)
        try:
            err = _md.AMDeviceSecureStartService(
                self._device, sref, None, byref(svc))
        finally:
            _cf.release(sref)
        return err, svc

    @staticmethod
    def _afc_diag(msg):
        """写 AFC 诊断日志到桌面 + TEMP"""
        import os as _os
        import datetime as _dt
        line = "[%s] [afc] %s\n" % (_dt.datetime.now().strftime("%H:%M:%S"), msg)
        for d in [
            _os.path.join(_os.path.expanduser("~"), "Desktop"),
            _os.environ.get("TEMP", ""),
        ]:
            if d:
                try:
                    with open(_os.path.join(d, "afc_diag.log"), "a",
                              encoding="utf-8") as f:
                        f.write(line)
                except Exception:
                    pass
        _trace("[AFC] " + msg)

    def _open(self):
        self._afc_diag("_open 开始 device=%s svc=%s" % (
            hex(_ptr(self._device)), self._svc_name))
        try:
            _ensure_session(self._device)
            self._afc_diag("_ensure_session OK")
        except Exception as e:
            self._afc_diag("_ensure_session FAIL: %s" % e)
            raise

        err, svc = self._secure_start()
        self._afc_diag("SecureStart err=%s svc=%s" % (
            hex(err & 0xFFFFFFFF) if err else "0x0",
            hex(_ptr(svc)) if _ptr(svc) else "None"))

        socket_fd = -1
        if err == 0 and _ptr(svc):
            socket_fd = _md.AMDServiceConnectionGetSocket(svc)
            self._afc_diag("GetSocket -> fd=%s" % socket_fd)

        if socket_fd < 0:
            # 回退普通 StartService：第4参数接收 service connection 句柄。
            sref = _cf.s(self._svc_name)
            normal_svc = c_void_p(0)
            try:
                err2 = _md.AMDeviceStartServiceWithOptions(
                    self._device, sref, None, byref(normal_svc))
            finally:
                _cf.release(sref)
            self._afc_diag("Fallback StartService err=%s svc=%s" % (
                hex(err2 & 0xFFFFFFFF) if err2 else "0x0",
                hex(_ptr(normal_svc)) if _ptr(normal_svc) else "None"))
            if err2 != 0 or not _ptr(normal_svc):
                raise RuntimeError(
                    "AFC service 启动失败 secure=%#x normal=%#x"
                    % ((err or 0) & 0xFFFFFFFF, err2 & 0xFFFFFFFF))
            svc = normal_svc
            socket_fd = _md.AMDServiceConnectionGetSocket(svc)
            self._afc_diag("Fallback GetSocket -> fd=%s" % socket_fd)

        if socket_fd < 0:
            self._afc_diag("ERROR: socket_fd < 0")
            raise RuntimeError("AFC socket 获取失败")

        conn = c_void_p(0)
        cerr = _md.AFCConnectionOpen(
            socket_fd if socket_fd >= 0 else 0, 0, byref(conn))
        self._afc_diag("AFCConnectionOpen cerr=%s conn=%s" % (
            hex(cerr & 0xFFFFFFFF) if cerr else "0x0",
            hex(_ptr(conn)) if _ptr(conn) else "None"))
        if cerr != 0 or not _ptr(conn):
            raise RuntimeError("AFCConnectionOpen 失败: %#x" % (cerr & 0xFFFFFFFF))

        # 安全上下文
        try:
            ctx = _md.AMDServiceConnectionGetSecureIOContext(svc) if _ptr(svc) else None
            self._afc_diag("SecureIOContext=%s" % (hex(_ptr(ctx)) if _ptr(ctx) else "None"))
            if _ptr(ctx):
                _md.AFCConnectionSetSecureContext(conn, ctx)
                self._afc_diag("SetSecureContext done")
        except Exception as e:
            self._afc_diag("SetSecureContext exception: %s" % e)
        self._conn = conn
        self._afc_diag("_open SUCCESS conn=%s" % hex(_ptr(conn)))

    def free(self):
        if self._conn:
            try:
                _md.AFCConnectionClose(self._conn)
            except Exception:
                pass
        self._conn = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    # ── 文件信息 ──
    def get_file_info(self, path: str):
        kv = c_void_p(0)
        err = _md.AFCFileInfoOpen(self._conn, path.encode("utf-8"), byref(kv))
        if err != 0 or not kv:
            return None
        result = {}
        try:
            while True:
                kp = c_char_p()
                vp = c_char_p()
                rerr = _md.AFCKeyValueRead(kv, byref(kp), byref(vp))
                if rerr != 0 or not kp.value:
                    break
                key = kp.value.decode("utf-8", "replace")
                val = vp.value.decode("utf-8", "replace") if vp.value else ""
                result[key] = val
        finally:
            _md.AFCKeyValueClose(kv)
        return result

    def file_exists(self, path: str) -> bool:
        return self.get_file_info(path) is not None

    # ── 低层文件句柄 ──
    def file_open(self, path: str, mode: int) -> int:
        ref = c_uint64(0)
        err = _md.AFCFileRefOpen(
            self._conn, path.encode("utf-8"), c_int(mode), byref(ref))
        if err != 0:
            raise RuntimeError("AFCFileRefOpen 失败: %#x" % (err & 0xFFFFFFFF))
        return ref.value

    def file_close(self, handle: int):
        _md.AFCFileRefClose(self._conn, c_uint64(handle))

    def file_write(self, handle: int, data: bytes) -> int:
        written = _md.AFCFileRefWrite(
            self._conn, c_uint64(handle), data, c_uint32(len(data)))
        return len(data) if written == 0 else -1

    def file_read(self, handle: int, size: int) -> bytes:
        buf = ctypes.create_string_buffer(size)
        # in/out：先填请求字节数，返回时为实际读取数。
        n = c_uint32(size)
        err = _md.AFCFileRefRead(
            self._conn, c_uint64(handle), buf, byref(n))
        if err != 0:
            raise RuntimeError("AFCFileRefRead 失败: %#x" % (err & 0xFFFFFFFF))
        return buf.raw[:n.value]

    def remove_path(self, path: str) -> bool:
        return _md.AFCRemovePath(self._conn, path.encode("utf-8")) == 0

    def make_directory(self, path: str) -> bool:
        return _md.AFCDirectoryCreate(self._conn, path.encode("utf-8")) == 0

    def make_link(self, target: str, link_path: str,
                  link_type: int = AFC_SYMLINK) -> bool:
        return _md.AFCLinkPath(
            self._conn, c_int(link_type),
            target.encode("utf-8"), link_path.encode("utf-8")) == 0

    def rename(self, src: str, dst: str) -> bool:
        return _md.AFCRenamePath(
            self._conn, src.encode("utf-8"), dst.encode("utf-8")) == 0

    def read_directory(self, path: str) -> list[str]:
        d = c_void_p(0)
        err = _md.AFCDirectoryOpen(
            self._conn, path.encode("utf-8"), byref(d))
        if err != 0 or not d:
            return []
        result = []
        try:
            while True:
                name = c_char_p()
                rerr = _md.AFCDirectoryRead(self._conn, d, byref(name))
                if rerr != 0 or not name.value:
                    break
                nm = name.value.decode("utf-8", "replace")
                if nm not in (".", ".."):
                    result.append(nm)
        finally:
            _md.AFCDirectoryClose(self._conn, d)
        return result

    def write_file(self, path: str, data: bytes) -> bool:
        self._afc_diag("write_file path=%s len=%d" % (path, len(data)))
        ref = c_uint64(0)
        err = _md.AFCFileRefOpen(
            self._conn, path.encode("utf-8"),
            c_int(AFC_FOPEN_WR), byref(ref))
        self._afc_diag("  FileRefOpen(wr) err=%s ref=%s" % (
            hex(err & 0xFFFFFFFF) if err else "0x0",
            hex(ref.value) if ref.value else "None"))
        if err != 0:
            self._afc_diag("  FileRefOpen FAILED")
            return False
        try:
            total = 0
            mv = memoryview(data)
            while total < len(data):
                chunk = bytes(mv[total:total + 1 << 20])
                werr = _md.AFCFileRefWrite(
                    self._conn, ref, chunk, c_uint32(len(chunk)))
                self._afc_diag("  FileRefWrite chunk=%d werr=%s" % (
                    len(chunk),
                    hex(werr & 0xFFFFFFFF) if werr else "0x0"))
                if werr != 0:
                    self._afc_diag("  FileRefWrite FAILED")
                    return False
                total += len(chunk)
            self._afc_diag("  write_file OK total=%d" % total)
            return total == len(data)
        finally:
            _md.AFCFileRefClose(self._conn, ref)

    def read_file(self, path: str, max_size: int = 16 * 1024 * 1024):
        self._afc_diag("read_file path=%s max=%d" % (path, max_size))
        info = self.get_file_info(path)
        if not info:
            self._afc_diag("  get_file_info -> None (file not found)")
            return None
        self._afc_diag("  file_info keys=%s" % list(info.keys()))
        try:
            size = int(info.get("st_size", "0"))
        except ValueError:
            size = 0
        size = min(size, max_size)
        self._afc_diag("  st_size=%d use_size=%d" % (
            int(info.get("st_size", "0")), size))
        ref = c_uint64(0)
        err = _md.AFCFileRefOpen(
            self._conn, path.encode("utf-8"),
            c_int(AFC_FOPEN_RDONLY), byref(ref))
        self._afc_diag("  FileRefOpen(rd) err=%s ref=%s" % (
            hex(err & 0xFFFFFFFF) if err else "0x0",
            hex(ref.value) if ref.value else "None"))
        if err != 0:
            self._afc_diag("  FileRefOpen(rd) FAILED")
            return None
        parts = []
        try:
            remaining = size
            while remaining > 0:
                want = min(remaining, 1 << 20)
                buf = ctypes.create_string_buffer(want)
                # AFCFileRefRead 第4参是 in/out：调用前必须填"请求读取字节数"，
                # 否则 n=0 表示请求 0 字节，函数立即返回、读不到任何数据。
                n = c_uint32(want)
                rerr = _md.AFCFileRefRead(self._conn, ref, buf, byref(n))
                self._afc_diag("  FileRefRead rerr=%s n=%d" % (
                    hex(rerr & 0xFFFFFFFF) if rerr else "0x0", n.value))
                if rerr != 0 or n.value == 0:
                    break
                parts.append(buf.raw[:n.value])
                remaining -= n.value
        finally:
            _md.AFCFileRefClose(self._conn, ref)
        result = b"".join(parts)
        self._afc_diag("  read_file OK len=%d" % len(result))
        return result


class StreamingZipConduitClient:
    """苹果原生 streaming_zip_conduit 客户端（对齐第三方 SendStreamingZip）。"""

    def __init__(self, device, service_desc, force_ssl: bool = False):
        if not _init():
            raise RuntimeError("Apple MobileDevice not available")
        self._device = device.handle
        self._svc = None
        self._open()

    def _open(self):
        _ensure_session(self._device)
        sref = _cf.s("com.apple.streaming_zip_conduit")
        svc = c_void_p(0)
        try:
            err = _md.AMDeviceSecureStartService(
                self._device, sref, None, byref(svc))
        finally:
            _cf.release(sref)
        if err != 0 or not svc:
            raise RuntimeError(
                "streaming_zip_conduit 启动失败: %#x" % (err & 0xFFFFFFFF))
        self._svc = svc
        self._socket = _md.AMDServiceConnectionGetSocket(svc)
        self._apply_socket_timeouts(self._socket)

    @staticmethod
    def _apply_socket_timeouts(fd) -> None:
        """对齐第三方 IL：对 conduit socket 设置 SO_SNDTIMEO / SO_RCVTIMEO
        =30000ms。socket 超时为 0 会被底层判定为无效参数(0xe8000007)。"""
        try:
            fdi = int(fd)
        except (TypeError, ValueError):
            return
        if fdi < 0:
            return
        try:
            ws2 = ctypes.windll.ws2_32
        except Exception:
            return
        SOL_SOCKET = 0xFFFF
        SO_SNDTIMEO = 0x1005
        SO_RCVTIMEO = 0x1006
        ms = ctypes.c_int(30000)
        try:
            ws2.setsockopt(fdi, SOL_SOCKET, SO_SNDTIMEO,
                           ctypes.byref(ms), ctypes.c_int(4))
            ws2.setsockopt(fdi, SOL_SOCKET, SO_RCVTIMEO,
                           ctypes.byref(ms), ctypes.c_int(4))
        except Exception:
            pass
        _trace("streaming_zip socket fd=%d setsockopt timeout=30000" % fdi)

    def free(self):
        if self._svc:
            try:
                _md.AMDServiceConnectionInvalidate(self._svc)
            except Exception:
                pass
        self._svc = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    def send_all(self, data: bytes) -> bool:
        total = 0
        mv = memoryview(data)
        while total < len(data):
            chunk = bytes(mv[total:total + 1 << 20])
            sent = _md.AMDServiceConnectionSend(
                self._svc, chunk, c_uint32(len(chunk)))
            if sent <= 0:
                return False
            total += sent
        return total == len(data)

    def send_message(self, obj) -> int:
        ref = _cf.dict(obj) if isinstance(obj, dict) else _cf.to_cf(obj)
        try:
            return _md.AMDServiceConnectionSendMessage(self._svc, ref, c_int(200))
        finally:
            _cf.release(ref)

    def receive_message(self):
        ref = c_void_p(0)
        err = _md.AMDServiceConnectionReceiveMessage(
            self._svc, byref(ref), None)
        if err != 0 or not ref:
            return None
        try:
            return _cf_to_python(ref)
        finally:
            _cf.release(ref)

    def send_zip(self, media_subdir: str, zip_data: bytes) -> dict:
        # 先送 {"MediaSubdir": <dir>}
        err = self.send_message({"MediaSubdir": media_subdir})
        if err != 0:
            raise RuntimeError("StreamingZip SendMessage 失败: %#x"
                               % (err & 0xFFFFFFFF))
        if not self.send_all(zip_data):
            raise RuntimeError("StreamingZip archive 发送失败。")
        # 设备回复（成功/失败），内容不强制，取到即可
        reply = self.receive_message()
        return {"ok": True, "reply": reply}


# ── 独立进程兜底检测（逐点对齐第三方 ProbeToolFallbackAsync +
#    ToolDeviceInfoProbe）────────────────────────────────────────────────

def _tools_base_dirs():
    """对齐第三方 FindToolDir 的候选定位：优先发布包相对路径 Tools。"""
    dirs = []
    base = getattr(sys, "_MEIPASS", None)
    if base:
        dirs.append(os.path.join(base, "Tools", "NormalMode"))
    here = os.path.dirname(os.path.abspath(__file__))
    dirs.append(os.path.join(here, "Tools", "NormalMode"))
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        exe_dir = os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv else os.getcwd()
    dirs.append(os.path.join(exe_dir, "Tools", "NormalMode"))
    return dirs


def _find_tool_dir():
    """返回同时含 idevice_id.exe 与 ideviceinfo.exe 的 x64 工具目录。"""
    for cand in _tools_base_dirs():
        xdir = os.path.join(cand, "x64")
        if (os.path.isfile(os.path.join(xdir, "idevice_id.exe"))
                and os.path.isfile(os.path.join(xdir, "ideviceinfo.exe"))):
            return xdir
    return None


def _run_tool(tool_dir, exe, args, timeout=6.0):
    """运行捆绑工具，返回 stdout 文本。DLL 同目录可直接被解析。
    增强：记录 returncode、stderr 用于诊断。"""
    exe_path = os.path.join(tool_dir, exe)
    _trace("  RunTool: 执行 %s %s" % (exe, list(args)))
    _trace("  RunTool: 完整路径=%s" % exe_path)
    _trace("  RunTool: cwd=%s" % tool_dir)
    _trace("  RunTool: exe 存在? %s" % os.path.isfile(exe_path))
    try:
        creationflags = 0
        if os.name == "nt":
            creationflags = 0x08000000  # CREATE_NO_WINDOW
        proc = subprocess.run(
            [exe_path] + list(args),
            cwd=tool_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            creationflags=creationflags,
        )
        _trace("  RunTool: returncode=%d" % proc.returncode)
        # 记录 stderr
        stderr_text = ""
        if proc.stderr:
            if isinstance(proc.stderr, bytes):
                for enc in ("utf-8", "gbk", "latin-1"):
                    try:
                        stderr_text = proc.stderr.decode(enc)
                        break
                    except Exception:
                        continue
            else:
                stderr_text = proc.stderr
            if stderr_text.strip():
                _trace("  RunTool: stderr=[%s]" % stderr_text.strip())
            else:
                _trace("  RunTool: stderr 为空")
        else:
            _trace("  RunTool: stderr 为 None")
        # 解析 stdout
        out = proc.stdout
        stdout_text = ""
        if isinstance(out, bytes):
            for enc in ("utf-8", "gbk", "latin-1"):
                try:
                    stdout_text = out.decode(enc)
                    break
                except Exception:
                    continue
        else:
            stdout_text = out if out else ""
        _trace("  RunTool: stdout 长度=%d, 内容=[%s]" % (len(stdout_text), stdout_text.strip()[:200]))
        return stdout_text
    except subprocess.TimeoutExpired:
        _trace("  RunTool: %s 超时 (%.1fs)" % (exe, timeout))
        return ""
    except Exception as exc:  # noqa: BLE001
        _trace("  RunTool: %s 异常: %r" % (exe, exc))
        import traceback
        _trace("  RunTool 异常堆栈:\n%s" % traceback.format_exc())
        return ""


def _probe_udid(tool_dir):
    """对齐第三方 idevice_id.exe -l，取第一行 UDID。"""
    out = _run_tool(tool_dir, "idevice_id.exe", ["-l"])
    for line in out.splitlines():
        line = line.strip()
        if line:
            return line
    return None


def _probe_info(tool_dir, udid):
    """对齐第三方 ideviceinfo.exe -u <udid>，解析 key: value 表。"""
    out = _run_tool(tool_dir, "ideviceinfo.exe", ["-u", udid], timeout=8.0)
    info = {}
    for line in out.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            info[key.strip()] = value.strip()
    return info


def _native_sync_probe():
    """同步枚举当前已连接设备（不依赖通知补发）。

    调用 MobileDevice 的 AMDCreateDeviceList 取当前设备 CFArray，逐个读取
    UniqueDeviceID，返回 [(udid, amdevice), ...]。给出的是真实可用句柄，
    后续连接/会话/AFC 与 watcher 通道完全一致。
    """
    _trace("=== _native_sync_probe 开始 ===")
    _trace("  _md=%s _cf=%s" % (_md, _cf))
    
    # 检查 AMDCreateDeviceList 是否存在
    if not hasattr(_md, 'AMDCreateDeviceList'):
        _trace("  ERROR: _md 没有 AMDCreateDeviceList 属性!")
        return []
    
    _trace("  即将调用 AMDCreateDeviceList()...")
    try:
        arr = _md.AMDCreateDeviceList()
        _trace("  AMDCreateDeviceList 返回: raw=%s type=%s" % (arr, type(arr)))
        _trace("  AMDCreateDeviceList 返回: value=%s" % (arr.value if hasattr(arr, 'value') else 'N/A'))
    except Exception as exc:
        _trace("  AMDCreateDeviceList 抛异常: %r" % exc)
        import traceback
        _trace("  异常堆栈:\n%s" % traceback.format_exc())
        return []
    
    if not arr or (hasattr(arr, 'value') and not arr.value):
        _trace("  AMDCreateDeviceList 返回 NULL/0，无设备")
        return []
    
    result = []
    try:
        count = _cf.array_count(arr)
        _trace("  CFArrayGetCount 返回: %d" % count)
        
        for i in range(count):
            _trace("  --- 处理设备 [%d] ---" % i)
            device = _cf.array_get(arr, i)
            _trace("    array_get 返回: raw=%s type=%s" % (device, type(device)))
            if not device:
                _trace("    device 为空，跳过")
                continue
            _trace("    device.value=0x%x" % (device if isinstance(device, int) else device.value if hasattr(device, 'value') else 0))

            udid = None
            owned = None
            try:
                _trace("    连接后读取 UniqueDeviceID（对齐第三方 Ensure）...")
                udid = _connect_and_read_udid(device)
                _trace("    _connect_and_read_udid 返回: %r (type=%s)"
                       % (udid, type(udid)))
            except Exception as exc:  # noqa: BLE001
                _trace("    _connect_and_read_udid 抛异常: %r" % exc)
                import traceback
                _trace("    异常堆栈:\n%s" % traceback.format_exc())

            # 在断开、释放数组之前，用 AMDeviceCreateCopy 复制一个**自有句柄**。
            # 数组项 device 是借用引用，CFRelease(arr) 后即失效，不能直接存。
            if udid:
                try:
                    owned = _md.AMDeviceCreateCopy(device)
                    _trace("    AMDeviceCreateCopy -> 0x%x"
                           % (owned.value if owned and hasattr(owned, 'value')
                              else (owned or 0)))
                except Exception as exc:
                    _trace("    AMDeviceCreateCopy 异常: %r" % exc)
                    owned = None

            # 读取后断开借用句柄，保持"枚举不占用设备"；后续真正使用时再
            # 对自有副本 Connect。
            try:
                _md.AMDeviceDisconnect(device)
            except Exception:
                pass

            _trace("    最终 udid=%r owned=0x%x"
                   % (udid, owned.value if owned and hasattr(owned, 'value')
                      else (owned or 0)))
            result.append((str(udid) if udid else None, owned))
    except Exception as exc:
        _trace("  枚举过程异常: %r" % exc)
        import traceback
        _trace("  异常堆栈:\n%s" % traceback.format_exc())
    finally:
        try:
            _cf.release(arr)
            _trace("  CFRelease(arr) 完成")
        except Exception as exc:
            _trace("  CFRelease(arr) 异常: %r" % exc)
    
    _trace("=== _native_sync_probe 结束, 返回 %d 个设备 ===" % len(result))
    return result


def _tool_fallback_thread():
    """对齐第三方 ProbeToolFallbackAsync 的时机与结构（启动后 sleep
    900ms，watcher 无设备时走独立通道直读），直读优先使用与攻击同栈的
    MobileDevice 同步枚举（真实句柄），外部 idevice 工具作为第二兜底。
    """
    _trace("========== 兜底线程进入 ==========")
    try:
        _trace("  即将 sleep 0.9 秒...")
        time.sleep(0.9)
        _trace("  sleep 结束")
        
        with _dev_lock:
            _trace("  检查 _devices: 当前数量=%d, 内容=%s" % (len(_devices), list(_devices.keys())))
            if _devices:
                _trace("  watcher 已发现设备，兜底跳过")
                return

        # 第一兜底：苹果框架同步枚举，拿到真实句柄
        _trace("  === 开始第一兜底：AMDCreateDeviceList ===")
        found = _native_sync_probe()
        _trace("  _native_sync_probe 返回: %s" % found)
        
        registered = False
        for udid, device in found:
            if not udid or not device:
                _trace("  跳过无效条目: udid=%r device=%r" % (udid, device))
                continue
            with _dev_lock:
                _devices.setdefault(udid, c_void_p(device))
            _trace("  兜底：同步枚举补登记 udid=%s handle=0x%x"
                   % (udid, device))
            registered = True
        if registered:
            _trace("  兜底成功（同步枚举），退出")
            return

        # 第二兜底：外部独立进程（idevice_id / ideviceinfo）
        _trace("  === 开始第二兜底：外部工具 idevice_id ===")
        _trace("  调用 _find_tool_dir()...")
        tool_dir = _find_tool_dir()
        _trace("  _find_tool_dir 返回: %r" % tool_dir)
        
        if not tool_dir:
            _trace("  兜底失败：未找到 Tools 目录")
            _trace("  详细路径诊断:")
            base_dirs = _tools_base_dirs()
            _trace("    _MEIPASS=%r" % getattr(sys, "_MEIPASS", None))
            _trace("    __file__=%r" % __file__)
            _trace("    sys.frozen=%r" % getattr(sys, "frozen", None))
            if getattr(sys, "frozen", False):
                _trace("    sys.executable=%r" % sys.executable)
            for i, bd in enumerate(base_dirs):
                xdir = os.path.join(bd, "x64")
                _trace("    候选[%d]: base=%s" % (i, bd))
                _trace("      检查 x64 子目录: %s" % xdir)
                _trace("      目录存在? %s" % os.path.isdir(xdir))
                if os.path.isdir(xdir):
                    try:
                        files = os.listdir(xdir)
                        _trace("      目录内容: %s" % files)
                        has_id = "idevice_id.exe" in files
                        has_info = "ideviceinfo.exe" in files
                        _trace("      有 idevice_id.exe? %s" % has_id)
                        _trace("      有 ideviceinfo.exe? %s" % has_info)
                    except Exception as e:
                        _trace("      列目录失败: %r" % e)
                else:
                    # 检查父目录是否存在
                    parent = os.path.dirname(xdir)
                    _trace("      父目录 %s 存在? %s" % (parent, os.path.isdir(parent)))
                    if os.path.isdir(parent):
                        try:
                            _trace("      父目录内容: %s" % os.listdir(parent))
                        except Exception as e:
                            _trace("      列父目录失败: %r" % e)
            return
        
        _trace("  找到 Tools 目录: %s" % tool_dir)
        _trace("  调用 _probe_udid(%s)..." % tool_dir)
        udid = _probe_udid(tool_dir)
        _trace("  _probe_udid 返回: %r" % udid)
        
        if not udid:
            _trace("  兜底失败：idevice_id 未返回设备")
            return
        
        with _dev_lock:
            _devices.setdefault(udid, c_void_p(0xDEADBEEF))
        _trace("  兜底成功（外部工具）：补登记 udid=%s" % udid)
    except Exception as exc:  # noqa: BLE001
        _trace("  兜底线程异常: %r" % exc)
        import traceback
        _trace("  异常堆栈:\n%s" % traceback.format_exc())


def _start_tool_fallback():
    t = threading.Thread(target=_tool_fallback_thread, daemon=True)
    t.start()


def read_device_info(udid: str | None = None) -> dict:
    """读取设备信息，返回与旧结构一致：{success, data:[{label,value}], error}。"""
    if not _init():
        return {"success": False, "data": [], "error": _load_error,
                "needs_trust": False}
    if not udid:
        devs = list_devices()
        if not devs:
            return {"success": False, "data": [],
                    "error": "No device connected", "needs_trust": False}
        udid = devs[0]
    with _dev_lock:
        device = _devices.get(udid)
    if not device:
        return {"success": False, "data": [],
                "error": "device not found", "needs_trust": False}

    labels = [
        ("设备型号", "ProductType"),
        ("序列号", "SerialNumber"),
        ("产品类型", "DeviceClass"),
        ("系统版本", "ProductVersion"),
        ("销售地区", "RegionInfo"),
        ("激活状态", "ActivationState"),
        ("ECID", "UniqueChipID"),
        ("UDID", "UniqueDeviceID"),
    ]
    data = []
    try:
        _ensure_session(device)
    except Exception as exc:
        return {"success": False, "data": data, "error": str(exc),
                "needs_trust": ("信任" in str(exc))}
    # 激活状态原始值 → 中文友好映射
    _activation_map = {
        "ACT": "已激活",
        "Activated": "已激活",
        "Unactivated": "未激活",
    }

    # 将 ProductType 如 "iPhone18,1" 格式化为 "iPhone 18.1"
    import re as _re
    def _friendly_model(pt):
        m = _re.match(r'([A-Za-z]+)(\d+),(\d+)', str(pt))
        if m:
            return "%s %s.%s" % (m.group(1), m.group(2), m.group(3))
        return str(pt)

    for label, key in labels:
        try:
            v = _copy_value(device, key)
            if v is not None and v != "":
                if key == "ActivationState":
                    v = _activation_map.get(str(v).strip(), str(v))
                elif key == "ProductType":
                    v = _friendly_model(v)
                data.append({"label": label, "value": str(v)})
        except Exception as exc:
            _trace("read_device_info field %s failed: %s" % (key, exc))
    return {"success": True, "data": data, "error": None,
            "needs_trust": False}
