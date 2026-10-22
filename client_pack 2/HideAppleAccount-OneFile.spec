# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller 打包配置 — Hide Apple Account（单 exe / 服务器授权版）
- onefile：产物为单个 HideAppleAccount.exe（约 50~65MB）
- 带自定义图标 + 启动屏(splash)
- 不内置 WebView2：用系统内核；设备交互走苹果原生 DLL + index.html
- 授权走远程服务器（license_client）

用法（管理员 cmd，项目文件夹内）：
    pyinstaller HideAppleAccount-OneFile.spec
产物：dist\\HideAppleAccount.exe   （单个文件，直接分发）
"""

import os
from PyInstaller.utils.hooks import collect_all

block_cipher = None

wv_datas, wv_binaries, wv_hidden = collect_all('webview')

# 不含 webview2_runtime；index.html 界面
datas = [
    ('index.html', '.'),
    ('device_imgs', 'device_imgs'),
    # lite 运行时（=第三方 AppleSupport，15 个 DLL 含 CoreFP）：
    # 主进程内直接 ctypes 调用 AirTrafficHost.dll 完成 Grappa 握手，
    # DLL 与第三方逐字节相同，客户免装 iTunes。
    ('proven_native_lite', 'proven_native_lite'),
    # 兜底检测工具（idevice_id/ideviceinfo 及依赖），通知补发丢失时使用
    ('Tools', 'Tools'),
]
# 内置苹果原生 DLL（AirTrafficHost/CoreFoundation 及依赖），客户免装 iTunes。
# 先用 collect_apple_dll.py 生成 apple_dll 文件夹；存在才打包。
if os.path.isdir('apple_dll'):
    datas.append(('apple_dll', 'apple_dll'))
datas += wv_datas

binaries = wv_binaries

hiddenimports = []
hiddenimports += wv_hidden
for m in ('bootlog', 'webview2_bootstrap', 'license_client', 'hide',
          'airlift_attack', 'apple_native_wrapper',
          'atc_native_bridge', 'payload_builder', 'rename_orchestrator'):
    hiddenimports.append(m)

a = Analysis(
    ['app.py'],
    pathex=[os.path.abspath('.')],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# 不使用 PyInstaller Splash：其底层是 Tcl/Tk 窗口，部分机器图片渲染失败会
# 显示成空白 Tk 框。单 exe 解压很快，双击直接进主界面即可。

# --- 管理员提权 manifest：双击 exe 即弹 UAC ---
admin_manifest = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
"""

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='HideAppleAccount',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[
        'proven_native_lite\\CoreFP.dll',
        'proven_native_lite\\AirTrafficHost.dll',
    ],
    runtime_tmpdir=None,
    console=False,            # 无黑窗口
    disable_windowed_traceback=False,
    background_color=(10, 10, 12),  # 窗口背景深色，消除白边
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='app.ico',           # 自定义图标
    uac_admin=True,           # ★ 强制管理员权限，双击即弹 UAC
    # version='version_info.txt',  # 暂时跳过，避免 PyInstaller 解析问题
)
