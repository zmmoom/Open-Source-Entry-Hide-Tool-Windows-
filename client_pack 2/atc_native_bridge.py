#!/usr/bin/env python3
"""
Apple 原生 ATC 桥（AirTrafficHost.dll + CoreFoundation.dll + CoreFP.dll）。

底层与第三方 IFineOpenHide 完全一致：直接在本进程内 P/Invoke 苹果官方
AirTrafficHost.dll，TLS / Grappa 握手 / 封帧 / HostInfo / SyncRequest /
AssetCompleted 的准确字节全部由 Apple 框架实时生成，不再重放任何外部 exe。

运行时目录 proven_native_lite 内的 15 个 DLL 与第三方 AppleSupport 逐字节
相同（已 md5 全量校验）。

流程（与第三方 AirliftWriter.Sync 的 IL 一一对应）：
  ATHostConnectionCreateWithLibrary(NULL, udid, 0)
   -> 失败再 CreateWithLibrary("iTunes", udid, 0)
   -> 再失败 ATHostConnectionCreate(udid)
  ReadMessage 等 SyncAllowed
  SendHostInfo(HostInfo) / SendSyncRequest(["Book"], {}, HostInfo)
  GetGrappaSessionId != 0   （安全会话闸门）
  ReadMessage 等 ReadyForSync
  SendMetadataSyncFinished({"Book":1}, {})
  ReadMessage 拿到 AssetManifest
  按 plan 顺序逐条 SendAssetCompleted（间隔 0.9s）
"""

from __future__ import annotations

import os
import sys
import struct
import time
import threading
import ctypes
from ctypes import c_void_p, c_char_p, c_uint32, c_ulong, c_long, c_int, c_longlong, byref


# ── 运行时定位 ────────────────────────────────────────────────────────────
# proven_native_lite == 第三方 AppleSupport（15 个 DLL，含 CoreFP，
# 不含 CoreKE/Keybag）。proven_native（含 CoreKE 的另一构建）仅作兜底。

def _candidate_dirs():
    base = getattr(sys, "_MEIPASS", None)
    here = os.path.dirname(os.path.abspath(__file__))
    dirs = []
    if base:
        dirs.append(os.path.join(base, "proven_native_lite"))
        dirs.append(os.path.join(base, "proven_native"))
    dirs.append(os.path.join(here, "proven_native_lite"))
    dirs.append(os.path.join(here, "proven_native"))
    dirs.append(os.path.join(os.getcwd(), "proven_native_lite"))
    dirs.append(os.path.join(os.getcwd(), "proven_native"))
    return dirs


# 与第三方 Configure 的候选目录完全一致（额外把我方内置运行时排在最前）。
def _third_party_style_candidates():
    # 第三方用 AppDomain.CurrentDomain.BaseDirectory（exe 所在目录）。
    if getattr(sys, "frozen", False):
        base_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        base_dir = os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv else os.getcwd()
    cands = []
    # 我方内置运行时（打包后在 _MEIPASS，优先使用）
    cands.extend(_candidate_dirs())
    # 第三方原始候选
    cands.append(os.path.join(base_dir, "AppleSupport"))
    cands.append(base_dir)
    cands.append(r"C:\Program Files\Common Files\Apple\Apple Application Support")
    cands.append(r"C:\Program Files\Common Files\Apple\Mobile Device Support")
    cands.append(r"C:\Program Files (x86)\Common Files\Apple\Apple Application Support")
    cands.append(r"C:\Program Files (x86)\Common Files\Apple\Mobile Device Support")
    cands.append(r"D:\Program Files\i4Tools9\itunesFlashDll")
    return cands


_configured = False


def configure():
    """逐字复刻第三方 Configure：补 PATH -> 找含双 DLL 的目录 -> SetDllDirectory。

    只设置搜索环境，不立即加载 DLL；之后首次 ctypes 加载时由系统解析。
    """
    global _configured
    if _configured:
        return True
    cands = _third_party_style_candidates()

    # ① 把确实存在的目录前置拼进 PATH（去重）。
    old_path = os.environ.get("PATH", "") or ""
    prefix_parts = []
    for d in cands:
        if os.path.isdir(d):
            try:
                if d.lower() not in old_path.lower():
                    prefix_parts.append(d)
            except Exception:
                prefix_parts.append(d)
    if prefix_parts:
        os.environ["PATH"] = ";".join(prefix_parts) + ";" + old_path

    # ② 找第一个同时含 MobileDevice.dll + CoreFoundation.dll 的目录。
    chosen = None
    for d in cands:
        if (os.path.isfile(os.path.join(d, "MobileDevice.dll"))
                and os.path.isfile(os.path.join(d, "CoreFoundation.dll"))):
            chosen = d
            break
    if not chosen:
        return False

    # ③ SetDllDirectoryW(chosen)（与第三方一致）。
    try:
        if not ctypes.windll.kernel32.SetDllDirectoryW(chosen):
            return False
    except Exception:
        return False
    _configured = True
    return True


def _device_dir():
    """返回设备发现所需的轻量运行时目录（只需 MobileDevice+CoreFoundation）。

    与第三方设备发现对齐：不依赖 AirTrafficHost/CoreFP，只要这两个核心
    DLL 在位即可，避免重型同步组件加载失败导致连"有没有设备"都判错。
    """
    for d in _candidate_dirs():
        if (os.path.isfile(os.path.join(d, "MobileDevice.dll"))
                and os.path.isfile(os.path.join(d, "CoreFoundation.dll"))):
            return d
    return None


def _runtime_dir():
    """返回成套 ATC 同步运行时目录；优先 lite（=第三方 AppleSupport）。"""
    for d in _candidate_dirs():
        if (os.path.isfile(os.path.join(d, "AirTrafficHost.dll"))
                and os.path.isfile(os.path.join(d, "CoreFoundation.dll"))
                and os.path.isfile(os.path.join(d, "CoreFP.dll"))):
            return d
    return None


# 设备发现/ AFC 传输的轻量预加载集（MobileDevice 依赖闭包）。
# 明确不含 CoreFP / AirTrafficHost / CoreKE / Keybag——设备层不需要它们。
_DEVICE_PRELOAD_ORDER = [
    "pthreadVC2.dll",
    "zlib1.dll",
    "ASL.dll",
    "icudt62.dll",
    "libicuin.dll",
    "libicuuc.dll",
    "libxml2.dll",
    "objc.dll",
    "libdispatch.dll",
    "SQLite3.dll",
    "CFNetwork.dll",
    "CoreFoundation.dll",
    "MobileDevice.dll",
]


# 预加载顺序：最底层依赖在前，AirTrafficHost 最后。
# 某个 DLL 一旦按全路径载入本进程，后续模块再加载同名 DLL 时 Windows 直接
# 复用已加载模块——保证整条链路都用成套版本，绝不串系统里新版 Apple 组件。
_PRELOAD_ORDER = [
    "pthreadVC2.dll",
    "zlib1.dll",
    "ASL.dll",
    "icudt62.dll",
    "libicuin.dll",
    "libicuuc.dll",
    "libxml2.dll",
    "objc.dll",
    "libdispatch.dll",
    "SQLite3.dll",
    "CFNetwork.dll",
    "CoreFoundation.dll",
    "MobileDevice.dll",
    # 部分构建把 FairPlay 拆成 CoreKE/CoreFP；lite 只有 CoreFP。
    # 存在就预加载，缺失由下方容错跳过。
    "CoreKE.dll",
    "Keybag.dll",
    "CoreFP.dll",
    "AirTrafficHost.dll",
]


def _write_corefp_registry(runtime_dir):
    """逐字对齐第三方 EnsureLocalCoreFpRegistry。

    exe 以管理员身份运行（uac_admin=True），优先写 HKLM
    ``SOFTWARE\\Apple Inc.\\CoreFP``，4 个值名 LibraryPath / CoreFPPath /
    Libi4CFPath / LibiiiiPath 全部指向 bundled CoreFP.dll 完整路径。
    HKLM 不可写时回退 HKCU（仅健壮性兜底）。失败一律不抛出。
    """
    corefp_path = os.path.join(runtime_dir, "CoreFP.dll")
    value_names = ("LibraryPath", "CoreFPPath", "Libi4CFPath", "LibiiiiPath")
    try:
        import winreg
        # ① HKLM（与第三方一致）
        try:
            with winreg.CreateKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Apple Inc.\CoreFP") as k:
                for name in value_names:
                    winreg.SetValueEx(k, name, 0, winreg.REG_SZ, corefp_path)
            # AAS InstallDir 也指向 runtime（供框架解析同目录依赖）。
            rt = runtime_dir + "\\"
            with winreg.CreateKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Apple Inc.\Apple Application Support") as k:
                winreg.SetValueEx(k, "InstallDir", 0, winreg.REG_SZ, rt)
            return True
        except OSError:
            pass
        # ② 回退 HKCU
        rt = runtime_dir + "\\"
        with winreg.CreateKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Apple Inc.\Apple Application Support") as k:
            winreg.SetValueEx(k, "InstallDir", 0, winreg.REG_SZ, rt)
            winreg.SetValueEx(k, "Path", 0, winreg.REG_SZ, rt)
            winreg.SetValueEx(k, "CoreFP", 0, winreg.REG_SZ, corefp_path)
        with winreg.CreateKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Apple Inc.\CoreFP") as k:
            for name in value_names:
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, corefp_path)
        return True
    except Exception:
        return False


def _preload_runtime(runtime_dir, order=None):
    """按依赖顺序把成套 DLL 全路径预加载，锁版本不串库。"""
    try:
        os.add_dll_directory(runtime_dir)
    except OSError:
        pass
    try:
        os.environ["PATH"] = runtime_dir + os.pathsep + os.environ.get("PATH", "")
    except Exception:
        pass
    loaded, failed = [], []
    for name in (order if order is not None else _PRELOAD_ORDER):
        p = os.path.join(runtime_dir, name)
        if os.path.isfile(p):
            try:
                # 按裸名加载（runtime 已加入 DLL 搜索路径）。与设备层一致：
                # PyInstaller 对全路径 CoreFoundation 会加载失败，裸名可成功。
                ctypes.CDLL(name)
                loaded.append(name)
            except OSError as exc:
                # 单个可选 DLL 失败不中断整链（如 Keybag/CoreKE 缺省）。
                failed.append("%s: %s" % (name, exc))
                try:
                    import bootlog as _bt0
                    _bt0.log("ATC preload 失败 %s: %r" % (name, exc))
                except Exception:
                    pass
    if failed:
        try:
            sys.stderr.write("[atc] preload warnings: " + " | ".join(failed) + "\n")
        except Exception:
            pass
    return loaded


def _preload_device_runtime(runtime_dir):
    """只预加载设备发现/AFC 所需的轻量依赖闭包（不碰同步组件）。"""
    try:
        os.add_dll_directory(runtime_dir)
    except OSError:
        pass
    try:
        os.environ["PATH"] = runtime_dir + os.pathsep + os.environ.get("PATH", "")
    except Exception:
        pass
    loaded, failed = [], []
    for name in _DEVICE_PRELOAD_ORDER:
        p = os.path.join(runtime_dir, name)
        if os.path.isfile(p):
            try:
                ctypes.CDLL(p)
                loaded.append(name)
            except OSError as exc:
                failed.append("%s: %s" % (name, exc))
    if failed:
        try:
            sys.stderr.write("[device] preload warnings: "
                             + " | ".join(failed) + "\n")
        except Exception:
            pass
    return loaded


def _pe_machine(path):
    with open(path, "rb") as f:
        d = f.read(4096)
    e = struct.unpack_from("<I", d, 0x3C)[0]
    return struct.unpack_from("<H", d, e + 4)[0]


_kCFStringEncodingUTF8 = 0x08000100
_kCFNumberSInt64Type = 4


class _CF:
    def __init__(self, cf_path, *extra_dirs):
        for d in extra_dirs:
            if d:
                try:
                    os.add_dll_directory(d)
                except OSError:
                    pass
        cf = self.cf = ctypes.CDLL(cf_path)

        cf.CFRelease.restype = None
        cf.CFRelease.argtypes = [c_void_p]
        cf.CFStringCreateWithCString.restype = c_void_p
        cf.CFStringCreateWithCString.argtypes = [c_void_p, c_char_p, c_uint32]
        cf.CFStringGetLength.restype = c_long
        cf.CFStringGetLength.argtypes = [c_void_p]
        cf.CFStringGetCString.restype = ctypes.c_bool
        cf.CFStringGetCString.argtypes = [c_void_p, c_char_p, c_long, c_uint32]
        cf.CFCopyDescription.restype = c_void_p
        cf.CFCopyDescription.argtypes = [c_void_p]
        cf.CFArrayCreate.restype = c_void_p
        cf.CFArrayCreate.argtypes = [c_void_p, c_void_p, c_long, c_void_p]
        cf.CFDictionaryCreate.restype = c_void_p
        cf.CFDictionaryCreate.argtypes = [c_void_p, c_void_p, c_void_p, c_long,
                                          c_void_p, c_void_p]
        cf.CFNumberCreate.restype = c_void_p
        cf.CFNumberCreate.argtypes = [c_void_p, c_int, c_void_p]
        cf.CFGetTypeID.restype = c_ulong
        cf.CFGetTypeID.argtypes = [c_void_p]
        cf.CFStringGetTypeID.restype = c_ulong
        cf.CFStringGetTypeID.argtypes = []
        cf.CFNumberGetValue.restype = ctypes.c_bool
        cf.CFNumberGetValue.argtypes = [c_void_p, c_int, c_void_p]
        cf.CFNumberGetTypeID.restype = c_ulong
        cf.CFNumberGetTypeID.argtypes = []

        # CFArray 读取（供 AMDCreateDeviceList 同步枚举当前设备使用）
        cf.CFArrayGetCount.restype = c_long
        cf.CFArrayGetCount.argtypes = [c_void_p]
        cf.CFArrayGetValueAtIndex.restype = c_void_p
        cf.CFArrayGetValueAtIndex.argtypes = [c_void_p, c_long]

        class _Sym(ctypes.Structure):
            pass

        def sym_addr(name):
            return ctypes.addressof(_Sym.in_dll(cf, name))

        self.arr_cb = sym_addr("kCFTypeArrayCallBacks")
        self.dict_key_cb = sym_addr("kCFTypeDictionaryKeyCallBacks")
        self.dict_val_cb = sym_addr("kCFTypeDictionaryValueCallBacks")

        self.true = c_void_p.in_dll(cf, "kCFBooleanTrue").value
        self.false = c_void_p.in_dll(cf, "kCFBooleanFalse").value

    def release(self, obj):
        if obj:
            self.cf.CFRelease(obj)

    def s(self, text):
        r = self.cf.CFStringCreateWithCString(None, str(text).encode(),
                                              _kCFStringEncodingUTF8)
        if not r:
            raise RuntimeError("CFStringCreateWithCString failed")
        return r

    def to_str(self, ref):
        if not ref:
            return None
        # 先检查是否真的是 CFString，对非字符串类型调 CFStringGetLength 会崩
        try:
            if self.cf.CFGetTypeID(ref) != self.cf.CFStringGetTypeID():
                return None
        except Exception:
            return None
        n = self.cf.CFStringGetLength(ref)
        size = max(16, (n + 1) * 4)
        buf = ctypes.create_string_buffer(size)
        if self.cf.CFStringGetCString(ref, buf, size, _kCFStringEncodingUTF8):
            return buf.value.decode("utf-8", "replace")
        return None

    def describe(self, ref):
        if not ref:
            return ""
        d = self.cf.CFCopyDescription(ref)
        if not d:
            return ""
        try:
            return self.to_str(d) or ""
        finally:
            self.release(d)

    def to_number(self, ref):
        """将 CFNumber 转为 Python int；非 CFNumber 返回 None。"""
        if not ref:
            return None
        try:
            if self.cf.CFGetTypeID(ref) != self.cf.CFNumberGetTypeID():
                return None
        except Exception:
            return None
        try:
            out = c_longlong(0)
            ok = self.cf.CFNumberGetValue(ref, _kCFNumberSInt64Type, byref(out))
            if ok:
                return out.value
        except Exception:
            pass
        return None

    def number(self, val):
        v = c_longlong(int(val))
        return self.cf.CFNumberCreate(None, _kCFNumberSInt64Type, byref(v))

    def array(self, items):
        refs = [self.to_cf(x) for x in items]
        arr = (c_void_p * len(refs))(*refs)
        r = self.cf.CFArrayCreate(None, arr, len(refs), c_void_p(self.arr_cb))
        for x in refs:
            self.release(x)
        return r

    def array_count(self, arr):
        if not arr:
            return 0
        return int(self.cf.CFArrayGetCount(arr))

    def array_get(self, arr, index):
        if not arr:
            return None
        return self.cf.CFArrayGetValueAtIndex(arr, int(index)) or None

    def dict(self, mapping):
        keys, vals = [], []
        try:
            for k, v in mapping.items():
                keys.append(self.s(str(k)))
                vals.append(self.to_cf(v))
            ka = (c_void_p * len(keys))(*keys)
            va = (c_void_p * len(vals))(*vals)
            r = self.cf.CFDictionaryCreate(
                None, ka, va, len(keys),
                c_void_p(self.dict_key_cb), c_void_p(self.dict_val_cb))
        finally:
            for x in keys:
                self.release(x)
            for x in vals:
                self.release(x)
        if not r:
            raise RuntimeError("CFDictionaryCreate failed")
        return r

    def to_cf(self, val):
        # isinstance(True, int) == True，必须先判 bool
        if isinstance(val, bool):
            return self.true if val else self.false
        if isinstance(val, int):
            return self.number(val)
        if isinstance(val, str):
            return self.s(val)
        if isinstance(val, (list, tuple)):
            return self.array(val)
        if isinstance(val, dict):
            return self.dict(val)
        raise TypeError(f"cannot convert {type(val)}")


def _windows_version_string():
    """第三方 MacOSVersion 字段："Windows " + Environment.OSVersion.Version。"""
    try:
        ver = sys.getwindowsversion()  # type: ignore[attr-defined]
        return "Windows %d.%d.%d" % (ver.major, ver.minor, ver.build)
    except Exception:
        return "Windows 10.0.19045"


def native_airtraffic(udid, plan, progress):
    """用 Apple 原生框架跑完整个 ATC，返回结构化结果。

    progress(text: str, ratio: float)：比例 0..1。
    plan 需有 .identifiers 与 .destinations（等长字符串列表）。
    """
    result = {"ok": False}

    # 打点：直接取进程启动时已加载的 bootlog，不靠重新 import（避免静默失败）。
    import sys as _sys
    _btmod = _sys.modules.get("bootlog")
    def _btlog(m):
        if _btmod is None:
            return
        try:
            _btmod.log("ATC " + str(m))
        except Exception:
            pass
    _btlog("=== native_airtraffic 函数入口 ===")

    def _flog(msg):
        try:
            base = os.environ.get("TEMP") or os.environ.get("TMP") or ""
            if not base or not os.path.isdir(base):
                base = os.getcwd()
            with open(os.path.join(base, "hideapple_attack.log"),
                      "a", encoding="utf-8") as f:
                f.write(f"{msg}\n")
        except Exception:
            pass

    _flog(f"[atc_bridge] native_airtraffic START udid={udid}")

    _btlog("准备段: 获取 runtime 目录...")
    runtime = _runtime_dir()
    _btlog(f"准备段: runtime={runtime}")
    if not runtime:
        result["error"] = "missing bundled Apple runtime (proven_native_lite)"
        return result
    # 确保 PATH/SetDllDirectory 已按第三方 Configure 设置（与设备层一致）。
    _btlog("准备段: configure()...")
    try:
        configure()
    except Exception:
        pass
    _btlog("准备段: _preload_runtime()...")
    loaded = _preload_runtime(runtime)
    _btlog(f"准备段: preloaded={loaded}")
    _btlog("准备段: _write_corefp_registry()...")
    _write_corefp_registry(runtime)
    _flog(f"[atc_bridge] runtime={runtime} preloaded={loaded}")

    ath_path = os.path.join(runtime, "AirTrafficHost.dll")
    # CoreFoundation 按裸名加载（runtime 已在 DLL 搜索路径）：PyInstaller 对
    # 该模块的全路径加载会失败，设备层同样用裸名并已验证成功。
    cf_path = "CoreFoundation.dll"

    _btlog("准备段: _pe_machine()...")
    mach = _pe_machine(ath_path)
    dll_bits = 64 if mach == 0x8664 else 32
    py_bits = struct.calcsize("P") * 8
    _btlog(f"准备段: dll_bits={dll_bits} py_bits={py_bits}")
    if dll_bits != py_bits:
        result["error"] = f"位数不匹配: DLL {dll_bits}, Python {py_bits}"
        return result

    _btlog("准备段: 构造 _CF(CoreFoundation)...")
    cf = _CF(cf_path, runtime)
    _btlog("准备段: ctypes.CDLL(AirTrafficHost.dll)...")
    ath = ctypes.CDLL(ath_path)
    _btlog("准备段: AirTrafficHost.dll 加载完成，开始绑定签名")

    # 连接相关导出签名
    ath.ATHostConnectionCreateWithLibrary.restype = c_void_p
    ath.ATHostConnectionCreateWithLibrary.argtypes = [c_void_p, c_void_p, c_int]
    ath.ATHostConnectionCreate.restype = c_void_p
    ath.ATHostConnectionCreate.argtypes = [c_void_p]
    ath.ATHostConnectionGetGrappaSessionId.restype = c_void_p
    ath.ATHostConnectionGetGrappaSessionId.argtypes = [c_void_p]
    ath.ATHostConnectionRelease.restype = None
    ath.ATHostConnectionRelease.argtypes = [c_void_p]
    ath.ATHostConnectionReadMessage.restype = c_void_p
    ath.ATHostConnectionReadMessage.argtypes = [c_void_p]
    ath.ATHostConnectionSendHostInfo.restype = c_void_p
    ath.ATHostConnectionSendHostInfo.argtypes = [c_void_p, c_void_p]
    ath.ATHostConnectionSendSyncRequest.restype = c_void_p
    ath.ATHostConnectionSendSyncRequest.argtypes = [c_void_p, c_void_p,
                                                    c_void_p, c_void_p]
    ath.ATHostConnectionSendMetadataSyncFinished.restype = c_void_p
    ath.ATHostConnectionSendMetadataSyncFinished.argtypes = [c_void_p,
                                                             c_void_p, c_void_p]
    ath.ATHostConnectionSendAssetCompleted.restype = c_void_p
    ath.ATHostConnectionSendAssetCompleted.argtypes = [c_void_p, c_void_p,
                                                       c_void_p, c_void_p]
    ath.ATCFMessageGetName.restype = c_void_p
    ath.ATCFMessageGetName.argtypes = [c_void_p]
    _btlog("准备段: 签名绑定全部完成，cf.s(udid)...")

    udid_ref = cf.s(udid)
    _btlog(f"准备段: udid_ref={udid_ref}")

    # ── 连接三级回退（对齐第三方 CreateAirTrafficConnection）──
    conn = None
    _btlog("CreateWithLibrary(library=NULL) 调用前...")
    conn = ath.ATHostConnectionCreateWithLibrary(None, udid_ref, 0)
    _btlog(f"CreateWithLibrary(NULL) 返回 conn={conn}")
    if not conn:
        lib_ref = cf.s("iTunes")
        try:
            _btlog("CreateWithLibrary(library='iTunes') 调用前...")
            conn = ath.ATHostConnectionCreateWithLibrary(lib_ref, udid_ref, 0)
            _btlog(f"CreateWithLibrary('iTunes') 返回 conn={conn}")
        finally:
            cf.release(lib_ref)
    if not conn:
        _btlog("ATHostConnectionCreate 调用前...")
        conn = ath.ATHostConnectionCreate(udid_ref)
        _btlog(f"ATHostConnectionCreate 返回 conn={conn}")
    cf.release(udid_ref)
    if not conn:
        result["error"] = "ATHost connection create failed"
        return result
    _btlog("ATC 连接创建成功，启动 reader 线程")

    # 整条连接只用一个常驻读取线程 + 单一队列，绝不丢迟到消息。
    import queue as _queue
    _msgq: "_queue.Queue" = _queue.Queue()
    _stop = threading.Event()

    def _reader_loop():
        _btlog("reader 线程进入，开始 ReadMessage 阻塞读")
        while not _stop.is_set():
            try:
                raw = ath.ATHostConnectionReadMessage(conn)
            except Exception as e:  # noqa
                _btlog(f"reader ReadMessage 抛异常: {e}")
                _msgq.put(("__error__", e))
                return
            if not raw:
                if _stop.is_set():
                    return
                continue
            try:
                name = cf.to_str(ath.ATCFMessageGetName(raw))
            except Exception:  # noqa
                name = None
            _btlog(f"reader 读到消息 name={name}")
            _msgq.put((name, raw))
        _btlog("reader 线程收到 stop，退出")

    _reader = threading.Thread(target=_reader_loop, daemon=True)
    _reader.start()

    def read_name(wait=8.0):
        try:
            item = _msgq.get(timeout=wait)
        except _queue.Empty:
            return None, None
        name, raw = item
        if name == "__error__":
            _flog(f"[atc] reader thread error: {raw}")
            return None, None
        try:
            _flog(f"[atc] <<< {name}: {cf.describe(raw) or ''}")
        except Exception:  # noqa
            pass
        return name, raw

    try:
        # 1) SyncAllowed（最多 8 条，每条 45s 由框架内部计时，这里用 8s 轮询）
        progress("等待 SyncAllowed...", 0.67)
        sync_seen = False
        for _i in range(8):
            _btlog(f"等待 SyncAllowed 第 {_i+1}/8 轮 (timeout=8s)...")
            name, raw = read_name()
            _btlog(f"第 {_i+1} 轮结果 name={name}")
            if raw:
                cf.release(raw)
            if name == "SyncAllowed":
                sync_seen = True
                break
        if not sync_seen:
            result["error"] = "SyncAllowed not observed"
            return result
        _btlog("收到 SyncAllowed，继续 HostInfo/SyncRequest")

        # 2) HostInfo + SyncRequest（字段与第三方逐一对应）
        import uuid as _uuid
        host_info = {
            "Type": "iTunes",
            "Version": "13.7.0.161",
            "MacOSVersion": _windows_version_string(),
            "SyncHostName": "airlift",
            "LibraryID": str(_uuid.uuid4()).upper(),
            "SyncedDataclasses": ["Book"],
            "SyncedAssetTypes": ["Book"],
            "Wakeable": False,
        }
        hi = cf.dict(host_info)
        progress("发送 HostInfo + SyncRequest...", 0.72)
        ath.ATHostConnectionSendHostInfo(conn, hi)
        time.sleep(0.2)
        dcs = cf.array(["Book"])
        anchors0 = cf.dict({})
        ath.ATHostConnectionSendSyncRequest(conn, dcs, anchors0, hi)
        cf.release(dcs)
        cf.release(anchors0)
        cf.release(hi)

        # 安全会话闸门：GetGrappaSessionId 必须非 0（对齐第三方 Sync IL）。
        grappa = ath.ATHostConnectionGetGrappaSessionId(conn)
        if not grappa:
            result["error"] = ("同步协商未建立安全会话，请确认 CoreFP.dll "
                               "与 AirTrafficHost.dll 版本匹配。")
            return result
        _flog(f"[atc] Grappa session established id={grappa}")

        # 3) ReadyForSync（容忍中途的 SyncFailed，继续等到总时限）
        progress("等待 ReadyForSync...", 0.78)
        ready = False
        fail_count = 0
        deadline = time.monotonic() + 150.0
        while time.monotonic() < deadline:
            remaining = max(1.0, deadline - time.monotonic())
            name, raw = read_name(wait=min(8.0, remaining))
            if raw:
                cf.release(raw)
            if name == "ReadyForSync":
                ready = True
                break
            if name == "SyncFailed":
                fail_count += 1
                _flog("[atc] SyncFailed while waiting ReadyForSync; continuing.")
        result["syncFailCount"] = fail_count
        if not ready:
            result["error"] = ("ReadyForSync not observed"
                               + (" after SyncFailed" if fail_count else ""))
            return result

        # 4) MetadataSyncFinished
        st = cf.dict({"Book": 1})
        anchors = cf.dict({})
        progress("发送 MetadataSyncFinished...", 0.82)
        ath.ATHostConnectionSendMetadataSyncFinished(conn, st, anchors)
        cf.release(st)
        cf.release(anchors)

        # 5) AssetManifest（遇到 SyncFailed/SyncFinished 停止）
        progress("等待 AssetManifest...", 0.86)
        manifest_seen = False
        for _ in range(20):
            name, raw = read_name()
            if raw:
                if name == "AssetManifest":
                    cf.release(raw)
                    manifest_seen = True
                    break
                cf.release(raw)
                if name in ("SyncFailed", "SyncFinished"):
                    break
        result["assetManifestObserved"] = manifest_seen

        # 6) 逐条 AssetCompleted（顺序由 plan 决定），间隔 0.9s
        progress("发送 AssetCompleted...", 0.92)
        n = len(plan.identifiers)
        for idx, (identifier, destination) in enumerate(
                zip(plan.identifiers, plan.destinations)):
            i_ref = cf.s(identifier)
            dc_ref = cf.s("Book")
            p_ref = cf.s(destination)
            ath.ATHostConnectionSendAssetCompleted(conn, i_ref, dc_ref, p_ref)
            cf.release(i_ref)
            cf.release(dc_ref)
            cf.release(p_ref)
            if idx + 1 < n:
                time.sleep(0.9)

        time.sleep(2)
        result.update({"ok": True, "syncAllowed": True, "readyForSync": True,
                       "fileCompleteMessages": n})
        return result
    finally:
        # 排空队列，释放尚未消费的消息指针
        try:
            while True:
                try:
                    _qn, _qraw = _msgq.get_nowait()
                except _queue.Empty:
                    break
                if _qn != "__error__" and _qraw:
                    try:
                        cf.release(_qraw)
                    except Exception:
                        pass
        except Exception:
            pass
        ath.ATHostConnectionRelease(conn)
        _stop.set()
        _reader.join(timeout=3.0)
