#!/usr/bin/env python3
"""
HideAppleAccount 客户端授权校验（与「授权管理平台」配套）
逻辑：点 Start → 取本机连接设备 UDID → POST /api/check 查是否已注册。
未注册则提示并打开授权网站（用户登录后自行注册 UDID）。
"""

import json
import os
import urllib.request
import urllib.error

BASE_URL = "http://47.82.109.215:8000"
HTTP_TIMEOUT = 12


# ── 取设备 UDID ──

def current_udid():
    """返回当前连接设备 UDID，失败返回 ''。

    仅走 apple_native_wrapper（苹果原生订阅），与主程序检测路径一致。
    """
    try:
        import apple_native_wrapper as lw
        if lw.is_available():
            ds = lw.list_devices()
            if ds:
                return str(ds[0]).strip()
    except Exception:
        pass
    return ""


# ── HTTP ──

def _post(path, payload):
    url = BASE_URL.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def check_registered(udid):
    """查询 UDID 是否已注册。返回 (ok, reason)。"""
    try:
        r = _post("/api/check", {"udid": udid})
    except urllib.error.HTTPError as e:
        return False, "授权服务器异常（%d）" % e.code
    except Exception:
        return False, "无法连接授权服务器（请检查网络）"
    if r.get("ok"):
        return True, ""
    return False, "设备未注册"


def gate_for_attack():
    """点 Start 时的闸机：返回 (ok, msg, udid)。"""
    udid = current_udid()
    if not udid:
        return False, "未检测到设备，请连接并信任此电脑", ""
    ok, reason = check_registered(udid)
    return ok, reason, udid


def activation_page_url(udid=""):
    # 打开授权网站（未登录会自动跳登录页）
    return BASE_URL.rstrip("/") + "/login"


def status():
    """供主程序轮询使用的状态摘要。"""
    udid = current_udid()
    if not udid:
        return {"licensed": False, "has_device": False,
                "message": "未检测到设备"}
    ok, reason = check_registered(udid)
    return {"licensed": ok, "has_device": True, "message": reason}
