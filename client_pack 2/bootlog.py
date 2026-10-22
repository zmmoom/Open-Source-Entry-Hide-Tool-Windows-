#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bootlog.py —— 全量引导日志（零第三方依赖）。

设计目标：只要进程启动并 import 了本模块，就一定在多个固定位置留下日志，
即使后续任意一行代码崩溃也能定位到"最后一个字母"。

日志同时写到：
  1) 桌面        hideapple_full.log   （最容易找到）
  2) %TEMP%      hideapple_full.log
  3) exe 旁      hideapple_full.log
  4) 当前工作目录 hideapple_full.log

并安装：
  - sys.excepthook              主线程未捕获异常
  - threading.excepthook        任意后台线程未捕获异常
  - faulthandler                段错误/原生崩溃时转储堆栈

所有函数对自身错误完全免疫，绝不影响主程序。
"""

from __future__ import annotations

import os
import sys
import time
import datetime
import threading

_LOG_NAME = "hideapple_full.log"
_paths: list[str] = []
_resolved: list[str] = []
_lock = threading.Lock()
_start_clock = time.time()


def _desktop_dir() -> str:
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        # CSIDL_DESKTOP = 0
        ctypes.windll.shell32.SHGetFolderPathW(0, 0, 0, 0, buf)
        if buf.value and os.path.isdir(buf.value):
            return buf.value
    except Exception:
        pass
    return ""


def _build_paths() -> None:
    global _paths
    seen = set()
    cands: list[str] = []

    desk = _desktop_dir()
    if desk:
        cands.append(os.path.join(desk, _LOG_NAME))
    try:
        import tempfile
        cands.append(os.path.join(tempfile.gettempdir(), _LOG_NAME))
    except Exception:
        pass
    # 仅在打包（frozen）时把 exe 旁目录作为候选；开发态 sys.executable 指向
    # 系统 python（如 /usr/bin、C:\Pythonxx），不应在那里写日志。
    try:
        if getattr(sys, "frozen", False):
            cands.append(os.path.join(
                os.path.dirname(os.path.abspath(sys.executable)), _LOG_NAME))
    except Exception:
        pass
    try:
        cands.append(os.path.join(os.getcwd(), _LOG_NAME))
    except Exception:
        pass
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        cands.append(os.path.join(here, _LOG_NAME))
    except Exception:
        pass

    for p in cands:
        try:
            np = os.path.normpath(p)
            low = np.lower()
            if low not in seen:
                seen.add(low)
                _paths.append(np)
        except Exception:
            continue


_build_paths()


def _stamp() -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    el = (time.time() - _start_clock) * 1000.0
    tid = threading.get_ident()
    return "%s [%8.1fms t%05d]" % (now, el, tid % 100000)


def log(msg, level="LOG"):
    """写一条日志。msg 可以是任意对象（会转成 repr/str）。"""
    try:
        if not isinstance(msg, str):
            try:
                msg = repr(msg)
            except Exception:
                msg = object.__repr__(msg)
        # 多行内容：每一非空行都带前缀；最后统一以一个换行结尾。
        text = msg if msg.endswith("\n") else msg + "\n"
        head = "%s %-5s " % (_stamp(), str(level)[:5])
        out_lines = []
        for ln in text.split("\n"):
            out_lines.append(head + ln if ln else head.rstrip())
        # split 末尾会多产生一个空元素，去掉以免重复；再补单换行
        if out_lines and out_lines[-1] == head.rstrip():
            out_lines.pop()
        block = "\n".join(out_lines) + "\n"
    except Exception:
        try:
            block = "BOOTLOG FORMAT FAIL: %r\n" % (msg,)
        except Exception:
            block = "BOOTLOG FORMAT FAIL\n"

    with _lock:
        for p in _paths:
            try:
                with open(p, "a", encoding="utf-8", errors="replace") as f:
                    f.write(block)
                    f.flush()
                if p not in _resolved:
                    _resolved.append(p)
            except Exception:
                continue


def resolved_paths() -> list[str]:
    """返回真正成功写入过的日志路径（供弹窗告诉用户去哪找）。"""
    return list(_resolved) if _resolved else list(_paths)


# ── 崩溃捕获 ──────────────────────────────────────────────────────────────

def _excepthook(exc_type, exc, tb):
    try:
        import traceback
        log("".join(traceback.format_exception(exc_type, exc, tb)), "FATAL")
    except Exception:
        try:
            log("sys.excepthook: %r %r" % (exc_type, exc), "FATAL")
        except Exception:
            pass
    try:
        sys.__excepthook__(exc_type, exc, tb)
    except Exception:
        pass


def _thread_excepthook(args):
    try:
        import traceback
        log("未捕获异常 @ 线程 %r:\n%s"
            % (getattr(args, "thread", None),
               "".join(traceback.format_exception(
                   args.exc_type, args.exc_value, args.exc_traceback))),
            "TFATAL")
    except Exception:
        try:
            log("threading.excepthook fail: %r" % (args,), "TFATAL")
        except Exception:
            pass


def install_hooks():
    try:
        sys.excepthook = _excepthook
    except Exception:
        pass
    try:
        threading.excepthook = _thread_excepthook
    except Exception:
        pass
    try:
        import faulthandler
        # 原生崩溃（段错误）时把所有线程堆栈打到日志文件
        for p in _paths[:2]:
            try:
                fh = open(p, "a", encoding="utf-8", errors="replace")
                faulthandler.enable(file=fh, all_threads=True)
                break
            except Exception:
                continue
    except Exception:
        pass


# ── import 即记录"进程真正启动"，并写入关键环境指纹 ───────────────────────
install_hooks()
log("#" * 72)
log("# BOOT: 进程启动 bootlog 已就绪")
log("#" * 72)
_env_keys = ("PYTHONPATH", "TEMP", "TMP", "USERPROFILE", "PATH")
for k in ("sys.frozen", "sys.executable", "sys.version", "sys.platform",
          "__file__", "sys._MEIPASS", "os.getcwd"):
    try:
        if k == "sys._MEIPASS":
            v = getattr(sys, "_MEIPASS", "<无>")
        elif k == "sys.frozen":
            v = getattr(sys, "frozen", False)
        elif k == "sys.executable":
            v = sys.executable
        elif k == "sys.version":
            v = sys.version.replace("\n", " ")
        elif k == "sys.platform":
            v = sys.platform
        elif k == "os.getcwd":
            v = os.getcwd()
        else:
            v = __file__
        log("ENV %-16s = %s" % (k, v))
    except Exception as e:
        log("ENV %s 读取失败: %r" % (k, e), "WARN")

try:
    log("候选日志路径:")
    for p in _paths:
        log("   -> " + p)
except Exception:
    pass
