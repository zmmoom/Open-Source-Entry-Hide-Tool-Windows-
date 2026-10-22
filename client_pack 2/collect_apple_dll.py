#!/usr/bin/env python3
"""
收集 AirTrafficHost.dll / CoreFoundation.dll 运行所需的【非系统】DLL，
供内置打包，让没装 iTunes/爱思的干净电脑也能直接跑。

方法（不靠静态解析猜依赖，直接观察真实加载结果）：
  1) “观察子进程”：在本机把两个 DLL 真实加载，用 Toolhelp 列出被一起拉进
     内存的全部模块（含运行时动态加载 / 延迟加载），筛掉 Windows 系统模块，
     得到真实非系统依赖清单。
  2) 主进程把这些 DLL 复制到 apple_dll\\。
  3) “验证子进程”：用一个全新、只认 apple_dll + 系统目录的进程隔离加载，
     模拟干净电脑；通过才算成功。

用法（管理员 cmd）：
    python collect_apple_dll.py
"""

import os
import sys
import json
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "apple_dll")

SEARCH_DIRS = [
    r"C:\Program Files\Common Files\Apple\Mobile Device Support",
    r"C:\Program Files (x86)\Common Files\Apple\Mobile Device Support",
    r"C:\Program Files\Common Files\Apple\Apple Application Support",
    r"C:\Program Files (x86)\Common Files\Apple\Apple Application Support",
    r"C:\Program Files\Apple\Mobile Device Support",
]


# ─────────────────────────────────────────────────────────────────────────
# 子进程 A：真实加载两个 DLL，报告新拉进内存的“非系统”模块路径
# 通过环境变量 _CA_CFG 传入 JSON：{dirs, aht, cf}
# stdout 最后一行打印 JSON：{ok, modules:[[name,path]...], error}
# ─────────────────────────────────────────────────────────────────────────
_OBSERVER_CODE = r'''
import os, sys, json, ctypes
from ctypes import wintypes

cfg = json.loads(os.environ["_CA_CFG"])

def enum_modules():
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010

    class MODULEENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("th32ModuleID", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("GlblcntUsage", wintypes.DWORD),
            ("ProccntUsage", wintypes.DWORD),
            ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
            ("modBaseSize", wintypes.DWORD),
            ("hModule", wintypes.HMODULE),
            ("szModule", wintypes.WCHAR * 256),
            ("szExePath", wintypes.WCHAR * 260),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    CreateToolhelp32Snapshot = k32.CreateToolhelp32Snapshot
    CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    Module32FirstW = k32.Module32FirstW
    Module32NextW = k32.Module32NextW
    CloseHandle = k32.CloseHandle

    snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0)
    if not snap or snap == wintypes.HANDLE(-1).value:
        return {}
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(MODULEENTRY32W)
    out = {}
    ok = Module32FirstW(snap, ctypes.byref(me))
    while ok:
        out[me.szModule.lower()] = me.szExePath
        ok = Module32NextW(snap, ctypes.byref(me))
    CloseHandle(snap)
    return out


def system_dirs():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    GetSystemDirectoryW = k32.GetSystemDirectoryW
    GetWindowsDirectoryW = k32.GetWindowsDirectoryW
    buf = ctypes.create_unicode_buffer(260)
    GetSystemDirectoryW(buf, 260)
    sysdir = os.path.realpath(buf.value)
    GetWindowsDirectoryW(buf, 260)
    win = os.path.realpath(buf.value)
    dirs = [sysdir, os.path.join(win, "SysWOW64")]
    return [d.lower() for d in dirs]


def is_system(name, path, sysdirs):
    n = name.lower()
    if n.startswith("api-ms-") or n.startswith("ext-ms-"):
        return True
    p = os.path.realpath(path).lower()
    return any(p.startswith(d + os.sep) or p == d for d in sysdirs)


def main():
    try:
        before = enum_modules()
        sysdirs = system_dirs()

        # 让依赖能在已安装的苹果组件目录中被找到
        for d in cfg["dirs"]:
            if os.path.isdir(d):
                try:
                    os.add_dll_directory(d)
                except OSError:
                    pass

        # 先 CoreFoundation，再 AirTrafficHost（后者依赖前者）
        ctypes.CDLL(cfg["cf"])
        ctypes.CDLL(cfg["aht"])

        after = enum_modules()
        modules = []
        for name, path in after.items():
            if name in before:
                continue
            if is_system(name, path, sysdirs):
                continue
            modules.append([name, os.path.realpath(path)])
        # 确保两个根 DLL 一定包含
        roots = {os.path.basename(cfg["aht"]).lower(),
                 os.path.basename(cfg["cf"]).lower()}
        havenames = {m[0] for m in modules}
        for r, p in ((os.path.basename(cfg["aht"]), cfg["aht"]),
                     (os.path.basename(cfg["cf"]), cfg["cf"])):
            if r.lower() not in havenames:
                modules.append([r.lower(), os.path.realpath(p)])
        print("@RESULT@" + json.dumps({"ok": True, "modules": modules}))
    except Exception as e:
        print("@RESULT@" + json.dumps({"ok": False, "error": str(e)}))

main()
'''


# ─────────────────────────────────────────────────────────────────────────
# 子进程 B：全新进程隔离加载，只允许 apple_dll + 系统目录
# env _CA_VERIFY=apple_dll 路径
# stdout 最后一行 JSON：{ok, error}
# ─────────────────────────────────────────────────────────────────────────
_VERIFIER_CODE = r'''
import os, json, ctypes
from ctypes import wintypes

out_dir = os.environ["_CA_VERIFY"]

LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100
LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
FLAGS = (LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
         | LOAD_LIBRARY_SEARCH_APPLICATION_DIR
         | LOAD_LIBRARY_SEARCH_SYSTEM32)

def main():
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        LoadLibraryExW = k32.LoadLibraryExW
        LoadLibraryExW.restype = wintypes.HMODULE
        LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE,
                                   wintypes.DWORD]
        FreeLibrary = k32.FreeLibrary
        FreeLibrary.argtypes = [wintypes.HMODULE]

        order = ["corefoundation.dll", "airtraffichost.dll"]
        present = {f.lower(): f for f in os.listdir(out_dir)
                   if f.lower().endswith(".dll")}
        handles = []
        for n in order:
            if n not in present:
                print("@RESULT@" + json.dumps(
                    {"ok": False, "error": "missing " + n}))
                return
            p = os.path.join(out_dir, present[n])
            h = LoadLibraryExW(p, None, FLAGS)
            if not h:
                print("@RESULT@" + json.dumps(
                    {"ok": False,
                     "error": "%s load failed (WinErr %d)"
                              % (n, ctypes.get_last_error())}))
                return
            handles.append(h)
        for h in handles:
            FreeLibrary(h)
        print("@RESULT@" + json.dumps({"ok": True}))
    except Exception as e:
        print("@RESULT@" + json.dumps({"ok": False, "error": str(e)}))

main()
'''


def _extract_result(text):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("@RESULT@"):
            return json.loads(line[len("@RESULT@"):])
    return None


def _find_root(name):
    for d in SEARCH_DIRS:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


def main():
    if not sys.platform.startswith("win"):
        print("[!] 本脚本需在 Windows 上运行（请在你真机成功的那台电脑执行）。")
        return 1

    aht = _find_root("AirTrafficHost.dll")
    cf = _find_root("CoreFoundation.dll")
    if not aht or not cf:
        print("[!] 未找到 AirTrafficHost.dll / CoreFoundation.dll。")
        print("    请先安装完整版 iTunes 64 位（官网 .exe）或爱思后重试。")
        return 1

    # ── 步骤 1：观察真实加载，得到依赖清单 ──
    print("[1/3] 真实加载并枚举实际依赖模块 ...")
    cfg = json.dumps({"dirs": SEARCH_DIRS, "aht": aht, "cf": cf})
    env = dict(os.environ)
    env["_CA_CFG"] = cfg
    proc = subprocess.run(
        [sys.executable, "-c", _OBSERVER_CODE],
        env=env, capture_output=True, text=True)
    res = _extract_result(proc.stdout)
    if not res or not res.get("ok"):
        print("[FAIL] 观察子进程无法加载这两个 DLL：")
        print("      ", (res or {}).get("error", proc.stderr.strip()))
        print("       请确认本机爱思/iTunes 能正常识别手机后重试。")
        return 1

    modules = res["modules"]

    # ── 步骤 2：复制到 apple_dll ──
    print("[2/3] 复制依赖到 apple_dll ...")
    os.makedirs(OUT, exist_ok=True)
    copied = []
    seen = set()
    for name, path in modules:
        base = os.path.basename(path)
        key = base.lower()
        if key in seen or not os.path.isfile(path):
            continue
        seen.add(key)
        shutil.copy2(path, os.path.join(OUT, base))
        copied.append(base)

    present = sorted(f for f in os.listdir(OUT) if f.lower().endswith(".dll"))
    print(f"      apple_dll 共 {len(present)} 个 DLL：")
    for n in present:
        print("        -", n)

    must = {"airtraffichost.dll", "corefoundation.dll"}
    if not must.issubset({n.lower() for n in present}):
        print("[FAIL] 缺少根 DLL，终止。")
        return 1

    # ── 步骤 3：全新进程隔离验证 ──
    print("[3/3] 全新进程隔离加载验证（模拟没装苹果软件的干净电脑）...")
    env = dict(os.environ)
    env["_CA_VERIFY"] = OUT
    proc = subprocess.run(
        [sys.executable, "-c", _VERIFIER_CODE],
        env=env, capture_output=True, text=True)
    res = _extract_result(proc.stdout)
    if res and res.get("ok"):
        print("\nPASS ✅  仅靠 apple_dll + 系统目录即可加载，干净电脑也能用。")
        print("下一步：rmdir /s /q build & rmdir /s /q dist & "
              "pyinstaller HideAppleAccount-OneFile.spec")
        return 0

    print("\nFAIL ❌  隔离加载失败：", (res or {}).get("error", "unknown"))
    print("处理：更新/重装完整版 iTunes 64 位或爱思，确认能识别手机后重跑本脚本。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
