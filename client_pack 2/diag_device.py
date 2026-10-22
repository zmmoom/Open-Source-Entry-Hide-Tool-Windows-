#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iOS 设备连接全链路诊断工具 v2
===============================
纯诊断，零修改，不启动/停止任何服务或进程。
逐层排查：环境 → 安装 → 注册表 → 进程 → 服务 → 驱动 → USB硬件 →
  DLL文件 → DLL加载 → 导出函数 → API运行时 → 外部工具 → 通信通道 → 事件日志 → 防火墙

输出：diag_report.txt（桌面 + 当前目录 + TEMP）
"""

import os, sys, subprocess, ctypes, ctypes.wintypes, time, datetime, traceback, json, socket, struct

# ═══════════════════════════════════════════════════════════════════════════════
#  日志
# ═══════════════════════════════════════════════════════════════════════════════

_lines = []

def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = "[%s] %s" % (ts, msg)
    print(line)
    _lines.append(line)

def section(title):
    log("")
    log("╔" + "═" * 68 + "╗")
    log("║  %s" % title.ljust(66) + "║")
    log("╚" + "═" * 68 + "╝")

def sub(title):
    log("")
    log("── %s ──" % title)

def warn(msg):
    log("  ★★★ %s" % msg)

def ok(msg):
    log("  ✓ %s" % msg)

def fail(msg):
    log("  ✗ %s" % msg)

def hexdump(data, prefix="    ", max_bytes=128):
    """打印前 max_bytes 字节的可读 hex dump"""
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i+16]
        hexs = " ".join("%02x" % b for b in chunk)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        log("%s%04x  %-48s  %s" % (prefix, i, hexs, asci))
    if len(data) > max_bytes:
        log("%s... (%d bytes total)" % (prefix, len(data)))


def _run(cmd, timeout=10):
    """运行命令，返回 (rc, stdout_str, stderr_str)。纯只读。"""
    try:
        cflags = 0x08000000 if os.name == "nt" else 0
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, creationflags=cflags,
            shell=isinstance(cmd, str),
        )
        def _dec(b):
            if not b: return ""
            if isinstance(b, bytes):
                for enc in ("gbk", "utf-8", "latin-1"):
                    try: return b.decode(enc)
                    except: continue
            return str(b) if b else ""
        return proc.returncode, _dec(proc.stdout), _dec(proc.stderr)
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT (%ds)" % timeout
    except Exception as e:
        return -2, "", repr(e)


def save_report():
    report = "\n".join(_lines)
    # 强制保存到桌面
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    if not os.path.isdir(desktop):
        try:
            os.makedirs(desktop, exist_ok=True)
        except Exception:
            pass
    desktop_path = os.path.join(desktop, "diag_report.txt")
    try:
        with open(desktop_path, "w", encoding="utf-8") as f:
            f.write(report)
        print("")
        print("=" * 70)
        print("  ★★★ 报告已强制保存到桌面: %s" % desktop_path)
        print("=" * 70)
    except Exception as e:
        print("保存到桌面失败: %s" % e)
        # 备用：保存到当前目录
        alt = os.path.join(os.getcwd(), "diag_report.txt")
        try:
            with open(alt, "w", encoding="utf-8") as f:
                f.write(report)
            print("备用保存到当前目录: %s" % alt)
        except Exception as e2:
            print("备用保存也失败: %s" % e2)


# ═══════════════════════════════════════════════════════════════════════════════
#  0. 基础环境
# ═══════════════════════════════════════════════════════════════════════════════

def diag_env():
    section("0. 基础环境信息")
    log("  Python: %s" % sys.version.replace("\n", " "))
    log("  可执行文件: %s" % sys.executable)
    log("  平台: %s | 架构: %s" % (sys.platform, "64-bit" if sys.maxsize > 2**32 else "32-bit"))
    log("  os.name: %s" % os.name)
    log("  CPU: %s" % os.environ.get("PROCESSOR_IDENTIFIER", "未知"))
    log("  核心数: %s" % os.environ.get("NUMBER_OF_PROCESSORS", "未知"))
    log("  用户名: %s" % os.environ.get("USERNAME", "未知"))
    log("  计算机名: %s" % os.environ.get("COMPUTERNAME", "未知"))
    log("  Windows: %s" % os.environ.get("OS", ""))

    # 管理员权限
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        log("  管理员权限: %s" % ("是" if admin else "否"))
        if not admin:
            warn("未以管理员身份运行！部分诊断信息可能不完整。")
    except:
        log("  管理员权限: 无法检测")

    # PyInstaller 环境
    sub("PyInstaller 环境")
    log("  sys.frozen: %s" % getattr(sys, "frozen", False))
    log("  _MEIPASS: %s" % getattr(sys, "_MEIPASS", "N/A"))
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass and os.path.isdir(meipass):
        try:
            entries = os.listdir(meipass)
            log("  _MEIPASS 内容 (%d项):" % len(entries))
            for e in sorted(entries)[:50]:
                fp = os.path.join(meipass, e)
                sz = os.path.getsize(fp) if os.path.isfile(fp) else "<dir>"
                log("    %s  (%s)" % (e, sz))
            if len(entries) > 50:
                log("    ... 还有 %d 项" % (len(entries) - 50))
        except Exception as e:
            log("  列目录失败: %r" % e)

    # 关键环境变量
    sub("关键环境变量")
    for k in ["PATH", "SystemRoot", "ProgramFiles", "ProgramFiles(x86)",
              "CommonProgramFiles", "CommonProgramFiles(x86)", "TEMP", "TMP"]:
        v = os.environ.get(k, "")
        if v:
            log("  %s=%s" % (k, v[:200]))
        else:
            log("  %s=(未设置)" % k)

    # Windows 版本详细信息
    sub("Windows 版本详细")
    try:
        import winreg
        nk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        for vn in ["ProductName", "CurrentBuild", "CurrentBuildNumber",
                    "DisplayVersion", "ReleaseId", "EditionID",
                    "InstallationType", "RegisteredOwner"]:
            try:
                val, _ = winreg.QueryValueEx(nk, vn)
                log("  %s = %s" % (vn, val))
            except:
                log("  %s = (无)" % vn)
        winreg.CloseKey(nk)
    except Exception as e:
        log("  读取失败: %r" % e)


# ═══════════════════════════════════════════════════════════════════════════════
#  1. Apple 软件安装
# ═══════════════════════════════════════════════════════════════════════════════

def diag_software():
    section("1. Apple 软件安装检测")

    import winreg
    kws = ["apple", "itunes", "mobile device", "bonjour", "icloud",
           "apple application support", "apple software update",
           "apple mobile", "usbaapl"]
    found = []

    reg_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, rp in reg_paths:
        sub("注册表: %s\\%s" % ("HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU", rp))
        try:
            reg = winreg.OpenKey(hive, rp)
            i = 0
            total = 0
            while True:
                try:
                    kn = winreg.EnumKey(reg, i)
                    sk = winreg.OpenKey(reg, kn)
                    try:
                        name = winreg.QueryValueEx(sk, "DisplayName")[0]
                        if any(k in name.lower() for k in kws):
                            total += 1
                            ver = iloc = pub = inst = sz = ""
                            for f, h in [("DisplayVersion","ver"),("InstallLocation","iloc"),
                                         ("Publisher","pub"),("InstallDate","inst"),("EstimatedSize","sz")]:
                                try:
                                    v = winreg.QueryValueEx(sk, f)[0]
                                    if h == "ver": ver = str(v)
                                    elif h == "iloc": iloc = str(v)
                                    elif h == "pub": pub = str(v)
                                    elif h == "inst": inst = str(v)
                                    elif h == "sz": sz = str(v)
                                except: pass
                            found.append({"name": name, "ver": ver, "loc": iloc, "pub": pub})
                            log("  [%d] %s" % (total, name))
                            log("      版本=%s 发布者=%s" % (ver, pub))
                            log("      安装路径=%s" % iloc)
                            log("      安装日期=%s 大小=%s KB" % (inst, sz))
                    except: pass
                    winreg.CloseKey(sk)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(reg)
            log("  该路径共找到 %d 个 Apple 产品" % total)
        except Exception as e:
            log("  读取失败: %r" % e)

    if not found:
        warn("未找到任何 Apple 软件！这是问题根因。")
    else:
        amds = any("mobile device" in f["name"].lower() for f in found)
        itunes = any("itunes" in f["name"].lower() for f in found)
        log("")
        log("  Apple Mobile Device Support: %s" % ("已安装 ✓" if amds else "★★★ 未安装 ★★★"))
        log("  iTunes: %s" % ("已安装 ✓" if itunes else "未安装"))

    return found


# ═══════════════════════════════════════════════════════════════════════════════
#  2. Apple 安装目录完整性检查
# ═══════════════════════════════════════════════════════════════════════════════

def diag_install_dirs():
    section("2. Apple 安装目录完整性")

    # 常见 Apple 安装路径
    candidates = []
    for pf in [os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", ""),
               os.environ.get("CommonProgramFiles", ""), os.environ.get("CommonProgramFiles(x86)", "")]:
        if not pf: continue
        for sub_path in [
            "Apple", "Apple\\Mobile Device Support",
            "Apple\\Mobile Device Support\\Apple Application Support",
            "Apple\\iTunes",
            "Common Files\\Apple", "Common Files\\Apple\\Mobile Device Support",
        ]:
            p = os.path.join(pf, sub_path)
            if os.path.isdir(p):
                candidates.append(p)

    # 也搜索 ProgramData
    pd = os.environ.get("ProgramData", "")
    if pd:
        for sp in ["Apple", "Apple\\Mobile Device Support"]:
            p = os.path.join(pd, sp)
            if os.path.isdir(p):
                candidates.append(p)

    if not candidates:
        warn("未找到任何 Apple 安装目录！")
        return

    for d in candidates:
        sub("目录: %s" % d)
        try:
            entries = os.listdir(d)
            log("  内容 (%d项):" % len(entries))
            for e in sorted(entries):
                fp = os.path.join(d, e)
                if os.path.isdir(fp):
                    log("    [DIR]  %s/" % e)
                else:
                    sz = os.path.getsize(fp)
                    log("    [FILE] %-40s  %10d bytes" % (e, sz))
        except Exception as e:
            log("  列目录失败: %r" % e)


# ═══════════════════════════════════════════════════════════════════════════════
#  3. Apple 相关进程
# ═══════════════════════════════════════════════════════════════════════════════

def diag_processes():
    section("3. Apple 相关进程")

    rc, out, err = _run(["tasklist", "/v", "/fo", "csv"], timeout=15)
    if not out:
        warn("无法获取进程列表")
        return

    kws = ["apple", "itunes", "mobiledevice", "mobile_device",
           "usbmuxd", "corefp", "airservice", "airtraffic"]

    apple_procs = []
    total_lines = 0
    for line in out.splitlines():
        total_lines += 1
        low = line.lower()
        if any(k in low for k in kws):
            apple_procs.append(line.strip())

    log("  总进程行数: %d" % total_lines)
    log("  Apple 相关进程: %d" % len(apple_procs))

    if apple_procs:
        for p in apple_procs:
            log("    %s" % p[:300])
    else:
        warn("没有发现任何 Apple 相关进程！")
        log("  ★★★ AppleMobileDeviceService.exe 未运行")
        log("  ★★★ iTunesHelper.exe 未运行")
        log("  这意味着 AMDS 服务可能未启动。")

    # 也检查所有含 "service" 或 "daemon" 的进程
    sub("所有含 'service'/'daemon' 的进程")
    svc_count = 0
    for line in out.splitlines():
        low = line.lower()
        if "service" in low or "daemon" in low:
            svc_count += 1
            if svc_count <= 15:
                log("    %s" % line.strip()[:200])
    if svc_count > 15:
        log("    ... 共 %d 个" % svc_count)


# ═══════════════════════════════════════════════════════════════════════════════
#  4. Windows 服务 (纯查询，不修改)
# ═══════════════════════════════════════════════════════════════════════════════

def diag_services():
    section("4. Windows 服务 (纯查询)")

    # 4.1 AMDS 详细状态 - 尝试多个可能的服务名
    sub("4.1 Apple Mobile Device Service (AMDS)")
    for svc_name in ["AMDS", "AppleMobileDeviceService", "Apple Mobile Device Service"]:
        rc, out, err = _run(["sc", "query", svc_name])
        log("  sc query '%s' -> rc=%d" % (svc_name, rc))
        if rc == 0 and out.strip():
            ok("找到! 服务名 = '%s'" % svc_name)
            for l in out.strip().splitlines():
                log("    %s" % l.strip())
            # 详细配置
            rc2, out2, err2 = _run(["sc", "qc", svc_name])
            log("  sc qc -> rc=%d" % rc2)
            if out2.strip():
                for l in out2.strip().splitlines():
                    log("    %s" % l.strip())
            # 触发器
            rc3, out3, _ = _run(["sc", "qtriggerinfo", svc_name])
            if out3.strip() and "失败" not in out3:
                log("  触发器:")
                for l in out3.strip().splitlines():
                    log("    %s" % l.strip())
            break
        else:
            log("    未找到 (rc=%d)" % rc)
            if err.strip():
                log("    %s" % err.strip()[:200])
    else:
        warn("所有候选服务名均未找到 AMDS!")
        log("    但进程 AppleMobileDeviceService.exe 在运行! 请手动查找实际服务名。")

    # 4.2 usbmuxd 服务
    sub("4.2 usbmuxd 服务")
    rc3, out3, err3 = _run(["sc", "query", "usbmuxd"])
    if out3.strip() and "失败" not in out3:
        for l in out3.strip().splitlines():
            log("    %s" % l.strip())
    else:
        log("    服务不存在 (正常，仅 libimobiledevice 安装方式有)")

    rc4, out4, _ = _run(["sc", "qc", "usbmuxd"])
    if out4.strip() and "失败" not in out4 and "does not exist" not in out4.lower():
        for l in out4.strip().splitlines():
            log("    [qc] %s" % l.strip())

    # 4.3 所有 Apple 相关服务
    sub("4.3 所有含 Apple/USB 关键词的服务")
    rc5, out5, _ = _run(["sc", "query", "type=", "service", "state=", "all"], timeout=20)
    if out5:
        found = []
        current_name = None
        for line in out5.splitlines():
            stripped = line.strip()
            if stripped.startswith("SERVICE_NAME:"):
                current_name = stripped.split(":", 1)[1].strip()
            elif current_name:
                low = stripped.lower()
                if any(k in low for k in ["apple", "usbmux", "mobiledevice", "mobile_device"]):
                    found.append("%s -> %s" % (current_name, stripped))
        if found:
            log("  找到 %d 个相关服务:" % len(found))
            for f in found:
                log("    %s" % f)
        else:
            warn("未找到 Apple 相关 Windows 服务")


# ═══════════════════════════════════════════════════════════════════════════════
#  5. 驱动检测
# ═══════════════════════════════════════════════════════════════════════════════

def diag_drivers():
    section("5. 驱动检测")

    # 5.1 已加载驱动中的 Apple 驱动
    sub("5.1 已加载驱动 (driverquery)")
    rc, out, err = _run(["driverquery", "/v", "/fo", "csv"], timeout=20)
    if out:
        apple_drvs = []
        for line in out.splitlines():
            low = line.lower()
            if any(k in low for k in ["apple", "usbaapl", "usbmux", "mobiledevic"]):
                apple_drvs.append(line.strip())
        if apple_drvs:
            ok("找到 %d 个 Apple 驱动:" % len(apple_drvs))
            for d in apple_drvs:
                log("    %s" % d[:400])
        else:
            warn("未找到 Apple USB 驱动！")
    else:
        log("  driverquery 失败: rc=%d" % rc)

    # 5.2 usbaapl64.sys 文件检查
    sub("5.2 usbaapl64.sys 文件检查")
    sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers")
    for fn in ["usbaapl64.sys", "usbaapl.sys", "usbaaplx64.sys", "usbmuxd.sys"]:
        fp = os.path.join(sys32, fn)
        if os.path.isfile(fp):
            sz = os.path.getsize(fp)
            log("  ✓ %s (%d bytes, %s)" % (fn, sz, os.path.getmtime(fp)))
        else:
            log("  ✗ %s 不存在" % fn)

    # 也检查 DriverStore
    sub("5.3 DriverStore 中的 Apple 驱动")
    ds = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "DriverStore", "FileRepository")
    if os.path.isdir(ds):
        apple_entries = []
        try:
            for entry in os.listdir(ds):
                if "apple" in entry.lower() or "usbaapl" in entry.lower():
                    apple_entries.append(entry)
        except Exception as e:
            log("  列目录失败: %r" % e)
        if apple_entries:
            log("  找到 %d 个 Apple 驱动仓库条目:" % len(apple_entries))
            for e in apple_entries:
                dp = os.path.join(ds, e)
                log("    %s/" % e)
                if os.path.isdir(dp):
                    try:
                        for f in os.listdir(dp)[:20]:
                            fp2 = os.path.join(dp, f)
                            sz = os.path.getsize(fp2) if os.path.isfile(fp2) else "<dir>"
                            log("      %s  (%s)" % (f, sz))
                    except: pass
        else:
            warn("DriverStore 中无 Apple 驱动")


# ═══════════════════════════════════════════════════════════════════════════════
#  6. USB 硬件设备
# ═══════════════════════════════════════════════════════════════════════════════

def diag_usb():
    section("6. USB 硬件设备枚举")

    # 6.1 所有 USB Hub 设备 (查找 Apple VID 05AC)
    sub("6.1 USB Hub 设备 (Win32_USBHub)")
    rc, out, err = _run(
        ["wmic", "path", "Win32_USBHub", "get",
         "Name,Status,DeviceID,PnPDeviceID,ConfigManagerErrorCode", "/format:list"],
        timeout=15)
    apple_usb = False
    if out:
        blocks = out.strip().split("\n\n")
        for blk in blocks:
            if not blk.strip(): continue
            upper = blk.upper()
            is_apple = "VID_05AC" in upper or "APPLE" in upper
            if is_apple:
                apple_usb = True
                log("  [APPLE USB 设备]:")
                for l in blk.strip().splitlines():
                    if l.strip(): log("    %s" % l.strip())
                log("")
    if not apple_usb:
        warn("USB Hub 列表中无 Apple 设备 (VID_05AC)")

    # 6.2 PnP 设备中搜索 iPhone/iPad/iPod
    sub("6.2 PnP 设备 (搜索 iPhone/iPad/iPod/Apple)")
    rc2, out2, err2 = _run(
        ["wmic", "path", "Win32_PnPEntity", "where",
         "Name like '%Apple%' or Name like '%iPhone%' or Name like '%iPad%' "
         "or Name like '%iPod%' or DeviceID like '%VID_05AC%'",
         "get", "Name,Status,DeviceID,ConfigManagerErrorCode,ClassGUID", "/format:list"],
        timeout=15)
    if out2 and out2.strip():
        log("  找到 PnP 设备:")
        for l in out2.strip().splitlines():
            if l.strip(): log("    %s" % l.strip())
    else:
        warn("PnP 中未找到 Apple 设备")
        log("  可能原因:")
        log("    1. 设备未连接")
        log("    2. USB 线仅充电不支持数据")
        log("    3. 驱动未安装，设备在 '其他设备' 中")
        log("    4. 手机锁屏未点击'信任此电脑'")
    if err2.strip():
        log("  stderr: %s" % err2.strip()[:300])

    # 6.3 有问题的设备 (黄色感叹号)
    sub("6.3 有问题的设备 (ConfigManagerErrorCode != 0)")
    rc3, out3, _ = _run(
        ["wmic", "path", "Win32_PnPEntity", "where",
         "ConfigManagerErrorCode<>0",
         "get", "Name,Status,DeviceID,ConfigManagerErrorCode,ClassGUID", "/format:list"],
        timeout=15)
    if out3 and out3.strip():
        blocks = out3.strip().split("\n\n")
        apple_prob = []
        other_prob = []
        for blk in blocks:
            if not blk.strip(): continue
            upper = blk.upper()
            if "05AC" in upper or "APPLE" in upper or "IPHONE" in upper or "IPAD" in upper:
                apple_prob.append(blk.strip())
            else:
                other_prob.append(blk.strip())
        if apple_prob:
            warn("有问题的 Apple 设备 (%d 个):" % len(apple_prob))
            for p in apple_prob:
                for l in p.splitlines():
                    if l.strip(): log("    %s" % l.strip())
                log("")
        log("  其他有问题设备: %d 个" % len(other_prob))
        for p in other_prob[:5]:
            for l in p.splitlines():
                if l.strip(): log("    %s" % l.strip())
            log("")
        if len(other_prob) > 5:
            log("    ... 还有 %d 个" % (len(other_prob) - 5))
    else:
        ok("没有检测到有问题的设备")

    # 6.4 完整 USB 控制器信息
    sub("6.4 USB 控制器")
    rc4, out4, _ = _run(
        ["wmic", "path", "Win32_USBController", "get",
         "Name,Status,DeviceID,Manufacturer", "/format:list"],
        timeout=15)
    if out4:
        ctrl_count = 0
        for l in out4.strip().splitlines():
            if l.strip():
                log("    %s" % l.strip())
                if l.strip().startswith("Name="): ctrl_count += 1
        log("  USB 控制器数: %d" % ctrl_count)

    # 6.5 使用 SetupAPI 深度枚举 (ctypes)
    sub("6.5 SetupAPI 深度 USB 设备枚举")
    try:
        setupapi = ctypes.windll.LoadLibrary("setupapi")
        # GUID for USB class: {36fc9e60-c465-11cf-8056-444553540000}
        class Guid(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                        ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]

        usb_guid = Guid()
        usb_guid.Data1 = 0x36fc9e60
        usb_guid.Data2 = 0xc465
        usb_guid.Data3 = 0x11cf
        for i, b in enumerate([0x80, 0x56, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00]):
            usb_guid.Data4[i] = b

        dev_info = setupapi.SetupDiGetClassDevsW(
            ctypes.byref(usb_guid), None, None, 0x12)  # DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
        if dev_info == ctypes.c_void_p(-1).value:
            log("  SetupDiGetClassDevs 失败: %s" % ctypes.GetLastError())
        else:
            log("  SetupDiGetClassDevs 成功: handle=0x%x" % dev_info)

            class SP_DEVINFO_DATA(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint32),
                            ("ClassGuid", Guid),
                            ("DevInst", ctypes.c_uint32),
                            ("Reserved", ctypes.POINTER(ctypes.c_ulong))]

            idx = 0
            total_found = 0
            apple_found = 0
            while idx < 100:
                dev_data = SP_DEVINFO_DATA()
                dev_data.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
                if not setupapi.SetupDiEnumDeviceInfo(dev_info, idx, ctypes.byref(dev_data)):
                    break
                total_found += 1

                # 获取设备描述
                buf = ctypes.create_unicode_buffer(512)
                buf_size = ctypes.c_uint32(512)
                req_size = ctypes.c_uint32()
                # SPDRP_DEVICEDESC = 0
                if setupapi.SetupDiGetDeviceRegistryPropertyW(
                        dev_info, ctypes.byref(dev_data), 0, None,
                        ctypes.cast(buf, ctypes.POINTER(ctypes.c_wchar)),
                        buf_size, ctypes.byref(req_size)):
                    name = buf.value
                    is_apple = "apple" in name.lower() or "iphone" in name.lower() or "ipad" in name.lower()
                    if is_apple:
                        apple_found += 1
                        log("  [APPLE] 设备[%d]: %s (DevInst=%d)" % (idx, name, dev_data.DevInst))

                        # 获取硬件 ID (SPDRP_HARDWAREID = 1)
                        hw_buf = ctypes.create_unicode_buffer(512)
                        hw_size = ctypes.c_uint32(512)
                        if setupapi.SetupDiGetDeviceRegistryPropertyW(
                                dev_info, ctypes.byref(dev_data), 1, None,
                                ctypes.cast(hw_buf, ctypes.POINTER(ctypes.c_wchar)),
                                hw_size, ctypes.byref(req_size)):
                            log("    HardwareID: %s" % hw_buf.value)

                        # 获取设备实例路径 (SPDRP_PHYSICAL_DEVICE_OBJECT_NAME = 14)
                        pdo_buf = ctypes.create_unicode_buffer(512)
                        pdo_size = ctypes.c_uint32(512)
                        if setupapi.SetupDiGetDeviceRegistryPropertyW(
                                dev_info, ctypes.byref(dev_data), 14, None,
                                ctypes.cast(pdo_buf, ctypes.POINTER(ctypes.c_wchar)),
                                pdo_size, ctypes.byref(req_size)):
                            log("    PDO: %s" % pdo_buf.value)

                        # 获取位置信息 (SPDRP_LOCATION_INFORMATION = 13)
                        loc_buf = ctypes.create_unicode_buffer(256)
                        loc_size = ctypes.c_uint32(256)
                        if setupapi.SetupDiGetDeviceRegistryPropertyW(
                                dev_info, ctypes.byref(dev_data), 13, None,
                                ctypes.cast(loc_buf, ctypes.POINTER(ctypes.c_wchar)),
                                loc_size, ctypes.byref(req_size)):
                            log("    Location: %s" % loc_buf.value)

                idx += 1

            setupapi.SetupDiDestroyDeviceInfoList(dev_info)
            log("  总计: USB设备=%d, Apple设备=%d" % (total_found, apple_found))
            if apple_found == 0:
                warn("SetupAPI 未检测到 Apple USB 设备")
    except Exception as e:
        log("  SetupAPI 枚举异常: %r" % e)
        log("  %s" % traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════════
#  7. DLL 文件检测 + 加载 + 导出函数
# ═══════════════════════════════════════════════════════════════════════════════

def diag_dll():
    section("7. DLL 文件检测与加载")

    # 7.1 查找所有 MobileDevice.dll 和 CoreFoundation.dll
    sub("7.1 文件查找")
    candidates_md = []
    candidates_cf = []

    search_dirs = []
    # _MEIPASS
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        for _subdir in ["", "proven_native_lite", "proven_native",
                    "AppleSupport", os.path.join("AppleSupport", "Windows")]:
            d = os.path.join(meipass, _subdir) if _subdir else meipass
            if os.path.isdir(d): search_dirs.append(d)
    # 当前脚本目录
    here = os.path.dirname(os.path.abspath(__file__))
    for _subdir in ["", "proven_native_lite", "proven_native", "AppleSupport"]:
        d = os.path.join(here, _subdir) if _subdir else here
        if os.path.isdir(d): search_dirs.append(d)
    # exe 目录
    if getattr(sys, "frozen", False):
        d = os.path.dirname(os.path.abspath(sys.executable))
        if os.path.isdir(d): search_dirs.append(d)
    # Apple 安装目录
    for pf in [os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", ""),
               os.environ.get("CommonProgramFiles", ""), os.environ.get("CommonProgramFiles(x86)", "")]:
        if not pf: continue
        for sp in ["Apple\\Mobile Device Support",
                    "Apple\\Mobile Device Support\\Apple Application Support",
                    "Common Files\\Apple\\Mobile Device Support",
                    "Common Files\\Apple\\Mobile Device Support\\Apple Application Support"]:
            d = os.path.join(pf, sp)
            if os.path.isdir(d): search_dirs.append(d)
    # PATH 目录
    for pd in os.environ.get("PATH", "").split(";"):
        if pd and os.path.isdir(pd): search_dirs.append(pd)
    # System32
    sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    if os.path.isdir(sys32): search_dirs.append(sys32)

    seen_dirs = set()
    for sd in search_dirs:
        sd = os.path.normcase(os.path.abspath(sd))
        if sd in seen_dirs: continue
        seen_dirs.add(sd)
        md = os.path.join(sd, "MobileDevice.dll")
        cf = os.path.join(sd, "CoreFoundation.dll")
        if os.path.isfile(md): candidates_md.append(md)
        if os.path.isfile(cf): candidates_cf.append(cf)

    log("  搜索了 %d 个目录" % len(seen_dirs))
    log("  MobileDevice.dll 找到 %d 个:" % len(candidates_md))
    for p in candidates_md:
        sz = os.path.getsize(p)
        mt = os.path.getmtime(p)
        log("    %s (%d bytes, mtime=%s)" % (p, sz, datetime.datetime.fromtimestamp(mt)))
    log("  CoreFoundation.dll 找到 %d 个:" % len(candidates_cf))
    for p in candidates_cf:
        sz = os.path.getsize(p)
        mt = os.path.getmtime(p)
        log("    %s (%d bytes, mtime=%s)" % (p, sz, datetime.datetime.fromtimestamp(mt)))

    if not candidates_md:
        warn("未找到任何 MobileDevice.dll！")
    if not candidates_cf:
        warn("未找到任何 CoreFoundation.dll！")

    # 7.2 PE 分析
    sub("7.2 PE 文件分析")
    for p in list(set(candidates_md[:2] + candidates_cf[:2])):
        log("  分析: %s" % p)
        try:
            with open(p, "rb") as f:
                header = f.read(512)
            # 检查 MZ 头
            if header[:2] != b"MZ":
                log("    不是有效的 PE 文件！")
                continue
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            sig = header[pe_offset:pe_offset+4]
            log("    PE signature offset: 0x%x, sig: %s" % (pe_offset, sig))
            if sig == b"PE\x00\x00":
                machine = struct.unpack_from("<H", header, pe_offset+4)[0]
                num_sections = struct.unpack_from("<H", header, pe_offset+6)[0]
                timestamp = struct.unpack_from("<I", header, pe_offset+8)[0]
                log("    Machine: 0x%x (%s)" % (machine, "x64" if machine == 0x8664 else "x86" if machine == 0x14c else "unknown"))
                log("    Sections: %d" % num_sections)
                log("    Timestamp: %s" % datetime.datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S UTC"))
        except Exception as e:
            log("    分析失败: %r" % e)

    # 7.3 加载测试
    sub("7.3 DLL 加载测试")
    loaded_md = None
    loaded_cf = None
    for p in candidates_cf[:1]:
        try:
            loaded_cf = ctypes.CDLL(p)
            ok("CoreFoundation.dll 加载: handle=0x%x" % loaded_cf._handle)
        except Exception as e:
            fail("CoreFoundation.dll 加载失败: %r" % e)
            try: log("    GetLastError: %s" % ctypes.GetLastError())
            except: pass
    for p in candidates_md[:1]:
        try:
            loaded_md = ctypes.CDLL(p)
            ok("MobileDevice.dll 加载: handle=0x%x" % loaded_md._handle)
        except Exception as e:
            fail("MobileDevice.dll 加载失败: %r" % e)
            try: log("    GetLastError: %s" % ctypes.GetLastError())
            except: pass

    # 7.4 导出函数详细检查
    sub("7.4 导出函数检查")
    md_exports = [
        "AMDeviceNotificationSubscribe", "AMDeviceNotificationUnsubscribe",
        "AMDCreateDeviceList",
        "AMDeviceConnect", "AMDeviceDisconnect",
        "AMDeviceCopyValue",
        "AMDeviceSecureStartService", "AMDeviceStartServiceWithOptions",
        "AMDeviceIsPaired", "AMDevicePair", "AMDeviceValidatePairing",
        "AMDeviceStartSession", "AMDeviceStopSession",
        "AMDeviceCreateCopy", "AMDeviceRelease",
        "AMDServiceConnectionGetSocket", "AMDServiceConnectionGetSecureIOContext",
        "AMDServiceConnectionSend", "AMDServiceConnectionReceive",
        "AMDServiceConnectionSendMessage", "AMDServiceConnectionReceiveMessage",
        "AMDServiceConnectionInvalidate",
        "AFCConnectionOpen", "AFCConnectionClose", "AFCConnectionSetSecureContext",
        "AFCFileRefOpen", "AFCFileRefWrite", "AFCFileRefRead", "AFCFileRefClose",
        "AFCDirectoryCreate", "AFCDirectoryOpen", "AFCDirectoryRead", "AFCDirectoryClose",
        "AFCFileInfoOpen", "AFCKeyValueRead", "AFCKeyValueClose",
        "AFCRemovePath", "AFCRenamePath", "AFCLinkPath",
    ]
    cf_exports = [
        "CFArrayGetCount", "CFArrayGetValueAtIndex",
        "CFStringCreateWithCString", "CFStringGetCStringPtr",
        "CFStringGetCString", "CFStringGetLength",
        "CFRelease", "CFRetain", "CFBooleanGetValue",
        "CFNumberGetValue", "CFGetTypeID",
        "CFStringGetTypeID", "CFNumberGetTypeID", "CFBooleanGetTypeID",
        "CFCopyDescription",
    ]

    if loaded_md:
        found_count = 0
        for fn in md_exports:
            try:
                f = getattr(loaded_md, fn)
                found_count += 1
            except AttributeError:
                log("  [MISSING] MobileDevice.%s" % fn)
        log("  MobileDevice 导出: %d/%d 找到" % (found_count, len(md_exports)))

    if loaded_cf:
        found_count = 0
        for fn in cf_exports:
            try:
                f = getattr(loaded_cf, fn)
                found_count += 1
            except AttributeError:
                log("  [MISSING] CoreFoundation.%s" % fn)
        log("  CoreFoundation 导出: %d/%d 找到" % (found_count, len(cf_exports)))

    return loaded_md, loaded_cf, candidates_md, candidates_cf


# ═══════════════════════════════════════════════════════════════════════════════
#  8. API 运行时测试
# ═══════════════════════════════════════════════════════════════════════════════

def diag_api(loaded_md, loaded_cf, md_paths):
    section("8. API 运行时测试")
    if not loaded_md or not loaded_cf:
        warn("DLL 加载失败，跳过 API 测试")
        return

    # 8.1 设置函数签名
    sub("8.1 函数签名设置")
    try:
        loaded_md.AMDCreateDeviceList.restype = ctypes.c_void_p
        loaded_md.AMDCreateDeviceList.argtypes = []
        ok("AMDCreateDeviceList 签名设置完成")
    except Exception as e:
        fail("AMDCreateDeviceList 签名设置失败: %r" % e)
        return

    # 8.2 AMDCreateDeviceList 测试
    sub("8.2 AMDCreateDeviceList 测试")
    try:
        arr = loaded_md.AMDCreateDeviceList()
        log("  返回值: %s (type=%s)" % (arr, type(arr)))
        if arr:
            log("  值: 0x%x" % (arr if isinstance(arr, int) else arr.value if hasattr(arr, 'value') else 0))
        if not arr or (hasattr(arr, 'value') and not arr.value):
            warn("AMDCreateDeviceList 返回 NULL/0 → 无设备")
            return
        # 尝试获取数组计数
        try:
            loaded_cf.CFArrayGetCount.restype = ctypes.c_int
            loaded_cf.CFArrayGetCount.argtypes = [ctypes.c_void_p]
            count = loaded_cf.CFArrayGetCount(arr)
            log("  CFArrayGetCount = %d" % count)
            if count > 0:
                loaded_cf.CFArrayGetValueAtIndex.restype = ctypes.c_void_p
                loaded_cf.CFArrayGetValueAtIndex.argtypes = [ctypes.c_void_p, ctypes.c_int]
                for i in range(count):
                    dev = loaded_cf.CFArrayGetValueAtIndex(arr, i)
                    log("  设备[%d] = 0x%x" % (i, dev or 0))
            else:
                warn("数组为空 (count=0) → AMDS 可能未运行或设备未被识别")
        except Exception as e:
            log("  CFArrayGetCount 异常: %r" % e)
        finally:
            try:
                loaded_cf.CFRelease.restype = ctypes.c_void_p
                loaded_cf.CFRelease.argtypes = [ctypes.c_void_p]
                loaded_cf.CFRelease(arr)
            except: pass
    except Exception as e:
        fail("AMDCreateDeviceList 调用异常: %r" % e)
        log("  %s" % traceback.format_exc())

    # 8.3 AMDeviceNotificationSubscribe 回调测试
    sub("8.3 Subscribe 回调测试 (等待5秒)")
    fired = [False]
    info_captured = [None]

    def on_notif(info_ptr, ctx):
        fired[0] = True
        info_captured[0] = (info_ptr, ctx)
        log("  >>> 回调触发! info_ptr=%s ctx=%s" % (info_ptr, ctx))

    try:
        CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)
        cb = CB(on_notif)
        log("  回调地址: %s (type=%s)" % (cb, type(cb)))

        loaded_md.AMDeviceNotificationSubscribe.restype = ctypes.c_int
        loaded_md.AMDeviceNotificationSubscribe.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]

        sub_val = ctypes.c_void_p(0)
        log("  参数: cb=%s, 0, 1, 0, byref(sub)" % cb)
        err = loaded_md.AMDeviceNotificationSubscribe(cb, 0, 1, 0, ctypes.byref(sub_val))
        log("  Subscribe 返回: %d (0x%x)" % (err, err & 0xffffffff))
        log("  sub 指针: 0x%x" % (sub_val.value or 0))

        if err == 0:
            log("  开始泵消息 + 等待 5 秒...")
            user32 = ctypes.windll.user32
            start_t = time.time()
            while time.time() - start_t < 5.0:
                msg = ctypes.wintypes.MSG()
                while user32.PeekMessageW(ctypes.byref(msg), 0, 0, 0, 1):
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
                if fired[0]:
                    break
                time.sleep(0.05)

            elapsed = time.time() - start_t
            if fired[0]:
                ok("回调在 %.2f 秒内触发!" % elapsed)
                log("  info = %s" % str(info_captured[0]))
            else:
                warn("5 秒内回调未触发")
                log("  结论: Subscribe 成功但回调不触发 → AMDS 未运行 / USB 驱动问题 / 设备未识别")

            # 清理
            try:
                loaded_md.AMDeviceNotificationUnsubscribe(sub_val)
                log("  Unsubscribe 完成")
            except Exception as e:
                log("  Unsubscribe 异常: %r" % e)
        else:
            fail("Subscribe 返回非 0: 0x%x" % (err & 0xffffffff))
    except Exception as e:
        fail("Subscribe 测试异常: %r" % e)
        log("  %s" % traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════════
#  9. 外部工具链 (libimobiledevice)
# ═══════════════════════════════════════════════════════════════════════════════

def diag_tools():
    section("9. 外部工具链 (libimobiledevice)")

    tool_dirs = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        tool_dirs.append(os.path.join(meipass, "Tools", "NormalMode", "x64"))
    here = os.path.dirname(os.path.abspath(__file__))
    tool_dirs.append(os.path.join(here, "Tools", "NormalMode", "x64"))
    if getattr(sys, "frozen", False):
        tool_dirs.append(os.path.join(os.path.dirname(os.path.abspath(sys.executable)),
                                      "Tools", "NormalMode", "x64"))

    found_dir = None
    for td in tool_dirs:
        has_id = os.path.isfile(os.path.join(td, "idevice_id.exe"))
        has_info = os.path.isfile(os.path.join(td, "ideviceinfo.exe"))
        sub("候选: %s" % td)
        log("  目录存在: %s" % os.path.isdir(td))
        if os.path.isdir(td):
            try:
                log("  内容: %s" % os.listdir(td))
            except: pass
        log("  idevice_id.exe: %s | ideviceinfo.exe: %s" % (has_id, has_info))
        if has_id and has_info:
            found_dir = td

    if not found_dir:
        warn("未找到完整的 Tools 目录!")
        return

    # 依赖 DLL 检查
    sub("9.1 Tools 目录依赖 DLL")
    for fn in ["imobiledevice.dll", "usbmuxd.dll", "plist.dll",
               "libssl-1_1-x64.dll", "libcrypto-1_1-x64.dll",
               "getopt.dll", "vcruntime140.dll"]:
        fp = os.path.join(found_dir, fn)
        if os.path.isfile(fp):
            sz = os.path.getsize(fp)
            ok("%s (%d bytes)" % (fn, sz))
        else:
            fail("%s 缺失!" % fn)

    # idevice_id -l
    sub("9.2 idevice_id -l")
    exe = os.path.join(found_dir, "idevice_id.exe")
    log("  命令: %s -l" % exe)
    log("  cwd: %s" % found_dir)
    log("  PATH 含工具目录: %s" % (found_dir in os.environ.get("PATH", "")))
    rc, out, err = _run([exe, "-l"], timeout=10)
    log("  returncode: %d" % rc)
    log("  stdout (%d bytes): [%s]" % (len(out or ""), (out or "").strip()[:500]))
    log("  stderr (%d bytes): [%s]" % (len(err or ""), (err or "").strip()[:500]))

    if out and out.strip():
        udid = out.strip().splitlines()[0].strip()
        ok("设备 UDID: %s" % udid)

        # ideviceinfo
        sub("9.3 ideviceinfo 详细信息")
        exe2 = os.path.join(found_dir, "ideviceinfo.exe")
        rc2, out2, err2 = _run([exe2, "-u", udid], timeout=10)
        log("  returncode: %d" % rc2)
        if out2:
            for l in out2.strip().splitlines()[:40]:
                log("  %s" % l.strip())
            if len(out2.strip().splitlines()) > 40:
                log("  ... (共 %d 行)" % len(out2.strip().splitlines()))
        if err2 and err2.strip():
            log("  stderr: %s" % err2.strip()[:500])
    else:
        warn("idevice_id -l 未返回设备")

    # 通信通道检查
    sub("9.4 usbmuxd 通信通道")
    for port in [27015, 27016]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            r = s.connect_ex(("127.0.0.1", port))
            log("  TCP localhost:%d -> %s (rc=%d)" % (port, "开放" if r == 0 else "关闭", r))
            s.close()
        except Exception as e:
            log("  TCP localhost:%d -> 异常: %r" % (port, e))
    pipe = r"\\.\pipe\usbmuxd"
    log("  Named pipe %s -> %s" % (pipe, "存在" if os.path.exists(pipe) else "不存在"))


# ═══════════════════════════════════════════════════════════════════════════════
#  10. apple_native_wrapper 集成测试
# ═══════════════════════════════════════════════════════════════════════════════

def diag_wrapper():
    section("10. apple_native_wrapper 集成测试")

    sub("10.1 模块加载")
    try:
        # 确保 DLL 路径
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            for _sd in ["proven_native_lite", ""]:
                d = os.path.join(meipass, _sd) if _sd else meipass
                if os.path.isdir(d) and os.path.isfile(os.path.join(d, "MobileDevice.dll")):
                    if d not in os.environ.get("PATH", ""):
                        os.environ["PATH"] = d + ";" + os.environ.get("PATH", "")
                        log("  添加 PATH: %s" % d)
        here = os.path.dirname(os.path.abspath(__file__))
        for _sd in ["proven_native_lite", ""]:
            d = os.path.join(here, _sd) if _sd else here
            if os.path.isdir(d) and os.path.isfile(os.path.join(d, "MobileDevice.dll")):
                if d not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = d + ";" + os.environ.get("PATH", "")
                    log("  添加 PATH: %s" % d)

        import apple_native_wrapper
        ok("模块加载成功")
        log("  _WRAPPER_VERSION = %s" % getattr(apple_native_wrapper, "_WRAPPER_VERSION", "?"))
    except Exception as e:
        fail("模块加载失败: %r" % e)
        log("  %s" % traceback.format_exc())
        return

    sub("10.2 _init()")
    try:
        r = apple_native_wrapper._init()
        log("  _init() = %s" % r)
        log("  _md = %s" % apple_native_wrapper._md)
        log("  _cf = %s" % apple_native_wrapper._cf)
        if apple_native_wrapper._load_error:
            log("  _load_error = %s" % apple_native_wrapper._load_error)
    except Exception as e:
        fail("_init() 异常: %r" % e)
        log("  %s" % traceback.format_exc())
        return

    sub("10.3 list_devices()")
    try:
        devs = apple_native_wrapper.list_devices()
        log("  list_devices() = %s" % devs)
        if devs:
            ok("发现 %d 台设备!" % len(devs))
        else:
            warn("list_devices() 返回空")
    except Exception as e:
        fail("list_devices() 异常: %r" % e)

    sub("10.4 _devices 内部状态")
    try:
        log("  _devices = %s" % dict(apple_native_wrapper._devices))
        log("  _raw_to_udid = %s" % dict(apple_native_wrapper._raw_to_udid))
    except Exception as e:
        log("  读取异常: %r" % e)


# ═══════════════════════════════════════════════════════════════════════════════
#  11. 事件日志
# ═══════════════════════════════════════════════════════════════════════════════

def diag_events():
    section("11. Windows 事件日志")

    sub("11.1 系统事件 - USB/驱动错误 (最近50条)")
    rc, out, err = _run(
        ["wevtutil", "qe", "System", "/q:*[System[(Level=1 or Level=2 or Level=3)]]",
         "/c:50", "/rd:true", "/f:text"],
        timeout=20)
    if out:
        usb_related = []
        for line in out.splitlines():
            low = line.lower()
            if any(k in low for k in ["usb", "apple", "driver", "mobile", "device install"]):
                usb_related.append(line.strip())
        if usb_related:
            log("  找到 %d 条相关事件:" % len(usb_related))
            for l in usb_related[:20]:
                log("    %s" % l[:200])
        else:
            log("  无 USB/驱动相关错误事件")
    else:
        log("  无输出或查询失败 (rc=%d)" % rc)

    sub("11.2 应用程序事件 - Apple 相关")
    rc2, out2, _ = _run(
        ["wevtutil", "qe", "Application", "/c:20", "/rd:true", "/f:text",
         "/q:*[System[Provider[contains(@Name,'Apple')]]]"],
        timeout=15)
    if out2 and out2.strip():
        log("  Apple 应用事件:")
        for l in out2.strip().splitlines()[:30]:
            log("    %s" % l)
    else:
        log("  无 Apple 应用事件")

    sub("11.3 安装事件")
    rc3, out3, _ = _run(
        ["wevtutil", "qe", "Microsoft-Windows-Kernel-PnP/Configuration",
         "/c:20", "/rd:true", "/f:text"],
        timeout=15)
    if out3 and out3.strip():
        log("  设备配置事件:")
        for l in out3.strip().splitlines()[:20]:
            low = l.lower()
            if any(k in low for k in ["apple", "iphone", "ipad", "usb", "driver"]):
                log("    %s" % l.strip()[:200])
    else:
        log("  无相关配置事件")


# ═══════════════════════════════════════════════════════════════════════════════
#  12. 防火墙
# ═══════════════════════════════════════════════════════════════════════════════

def diag_firewall():
    section("12. 防火墙 (Apple 相关规则)")
    rc, out, err = _run(
        ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
        timeout=15)
    if out:
        apple_rules = []
        for l in out.splitlines():
            low = l.lower()
            if any(k in low for k in ["apple", "itunes", "mobiledevice", "mobile device"]):
                apple_rules.append(l.strip())
        if apple_rules:
            log("  找到 %d 条 Apple 防火墙规则:" % len(apple_rules))
            for r in apple_rules[:10]:
                log("    %s" % r[:200])
        else:
            log("  无 Apple 防火墙规则")


# ═══════════════════════════════════════════════════════════════════════════════
#  13. 诊断总结
# ═══════════════════════════════════════════════════════════════════════════════

def diag_summary():
    section("13. 诊断总结")
    log("")
    log("  请按以下优先级排查（从高到低）：")
    log("")
    log("  [1] Apple Mobile Device Service (AMDS)")
    log("      查看第4节：AMDS 是否在运行？")
    log("      如果停止：管理员CMD运行 net start AppleMobileDeviceService")
    log("")
    log("  [2] Apple 软件安装")
    log("      查看第1节：是否安装了 iTunes 或 Apple Mobile Device Support？")
    log("      如果未安装：下载 iTunes for Windows 安装")
    log("")
    log("  [3] USB 驱动")
    log("      查看第5节：usbaapl64.sys 是否存在？")
    log("      查看第6节：USB 设备中是否有 Apple 设备 (VID_05AC)？")
    log("      如果驱动缺失：重新安装 iTunes 会自动安装驱动")
    log("")
    log("  [4] USB 连接")
    log("      查看第6节：是否有 Apple USB 设备？")
    log("      确认：USB 线支持数据 / 换口 / 手机解锁并信任电脑")
    log("")
    log("  [5] DLL 冲突")
    log("      查看第7节：是否有多个 MobileDevice.dll？")
    log("      如果冲突：只保留一份，删除旧版本")
    log("")
    log("  [6] 回调不触发")
    log("      查看第8节：Subscribe 成功但回调不触发？")
    log("      根因：AMDS 未运行或 USB 驱动未正确加载")
    log("")
    log("  请将 diag_report.txt 发给开发者获取进一步帮助。")


# ═══════════════════════════════════════════════════════════════════════════════
#  主入口
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    log("╔" + "═" * 68 + "╗")
    log("║  iOS 设备连接全链路诊断工具 v2 (纯诊断, 零修改)" + " " * 14 + "║")
    log("║  %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S").ljust(66) + "║")
    log("╚" + "═" * 68 + "╝")

    diag_env()
    diag_software()
    diag_install_dirs()
    diag_processes()
    diag_services()
    diag_drivers()
    diag_usb()

    loaded_md, loaded_cf, md_paths, cf_paths = diag_dll()

    diag_api(loaded_md, loaded_cf, md_paths)
    diag_tools()
    diag_wrapper()
    diag_events()
    diag_firewall()
    diag_summary()

    save_report()
    print("\n\n" + "=" * 70)
    print("  诊断完成！报告已保存到 diag_report.txt")
    print("=" * 70)


if __name__ == "__main__":
    main()
