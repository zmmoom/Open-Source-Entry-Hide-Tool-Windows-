#!/usr/bin/env python3
"""Pure-Python usbmuxd client (no native DLL dependency).

Used as the last-resort device enumeration path when the bundled
libimobiledevice DLL chain cannot load on a machine.  Talks the usbmuxd
binary protocol directly over:

  * Linux/macOS : unix socket  /var/run/usbmuxd
  * Windows     : TCP 127.0.0.1:27015 (Apple Mobile Device Service)

Only lightweight operations are needed here: list devices and read basic
lockdown values (ProductType / iOS version / serial / ECID / UDID ...).
"""

import os
import sys
import socket
import struct
import plistlib

# ── usbmuxd protocol constants ────────────────────────────────────────────

DEVICE_VERSION = 0
DEVICE_SOCKET_TYPE = 1  # 1 = connect to device port
USBMUXD_LISTEN = 1
USBMUXD_DEVICE_ADD = 1
USBMUXD_RESULT = 1
USBMUXD_PLIST_PAYLOAD = 8

# Tag we put on our request packets.
_TAG = 3735928559

PORT = 27015
SOCKET_PATH = "/var/run/usbmuxd"
TIMEOUT = 5.0


class UsbmuxError(RuntimeError):
    pass


PIPE_PATH = r"\\.\pipe\Apple_Mobiledevice_Pipe"
_PIPE_BUF = 65536


class _WinPipe:
    """Minimal socket-like wrapper over a Windows named pipe (byte stream)."""

    def __init__(self, handle):
        self._h = handle

    def sendall(self, data):
        return self._write_all(data)

    def recv(self, n):
        import ctypes
        from ctypes import wintypes
        buf = ctypes.create_string_buffer(min(n, _PIPE_BUF))
        read = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.ReadFile(
            self._h, buf, min(n, _PIPE_BUF), ctypes.byref(read), None)
        if not ok:
            raise UsbmuxError("named pipe ReadFile failed")
        return buf.raw[:read.value]

    def _write_all(self, data):
        import ctypes
        from ctypes import wintypes
        view = memoryview(data)
        while view:
            written = wintypes.DWORD(0)
            chunk = bytes(view[:_PIPE_BUF])
            ok = ctypes.windll.kernel32.WriteFile(
                self._h, chunk, len(chunk), ctypes.byref(written), None)
            if not ok or written.value == 0:
                raise UsbmuxError("named pipe WriteFile failed")
            view = view[written.value:]

    def close(self):
        import ctypes
        if self._h is not None:
            ctypes.windll.kernel32.CloseHandle(self._h)
            self._h = None

    def settimeout(self, _value):
        # Pipe opened in blocking mode with a connect timeout; reads block.
        return None


def _open_named_pipe(timeout):
    """Open the Apple Mobile Device named pipe (Windows only)."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes
    GENERIC_RW = 0xC0000000
    OPEN_EXISTING = 3
    INVALID = ctypes.c_void_p(-1).value
    name = ctypes.create_unicode_buffer(PIPE_PATH)
    handle = ctypes.windll.kernel32.CreateFileW(
        name, GENERIC_RW, 0, None, OPEN_EXISTING, 0, None)
    if not handle or handle == INVALID:
        return None
    return _WinPipe(handle)


def _open_tcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect(("127.0.0.1", PORT))
    return s


def _open_local_endpoint():
    """Open the Apple service on Windows: named pipe first, then TCP."""
    if sys.platform != "win32":
        path = os.environ.get("USBMUXD_SOCKET_ADDRESS", SOCKET_PATH)
        addr = "\x00" + path[1:] if path.startswith("@") else path
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect(addr)
        return s
    pipe = None
    try:
        pipe = _open_named_pipe(TIMEOUT)
    except Exception:
        pipe = None
    if pipe is not None:
        return pipe
    return _open_tcp()


def _open_socket():
    family, address = _socket_address()
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect(address)
    except (socket.error, OSError) as e:
        s.close()
        raise UsbmuxError(f"cannot connect to usbmuxd: {e}")
    return s


def _plist_request(message: dict):
    body = plistlib.dumps(message)
    # Header: total length, version, message type (8 = plist), tag.
    header = struct.pack("<IIII", len(body) + 16, DEVICE_VERSION,
                         USBMUXD_PLIST_PAYLOAD, _TAG)
    return header + body


def _recv_exact(s, n):
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = s.recv(remaining)
        if not chunk:
            raise UsbmuxError("usbmuxd closed connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_plist(s):
    header = _recv_exact(s, 16)
    total, _version, _mtype, _rtag = struct.unpack("<IIII", header)
    if total < 16:
        raise UsbmuxError("bad usbmuxd header")
    body = _recv_exact(s, total - 16)
    try:
        return plistlib.loads(body)
    except Exception as e:
        raise UsbmuxError(f"bad plist from usbmuxd: {e}")


# ── public API ────────────────────────────────────────────────────────────

def is_available() -> bool:
    """True if the local usbmuxd service answers."""
    s = None
    try:
        s = _open_socket()
        return bool(list_devices(sock=s))
    except Exception:
        return False
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def list_devices(sock=None):
    """Return a list of connected device UDIDs (40/25-char hex strings).

    The usbmuxd list response gives a per-device 'SerialNumber' which is
    exactly the UDID.
    """
    own = sock is None
    s = sock or _open_socket()
    try:
        msg = {
            "MessageType": "ListDevices",
            "ClientVersionString": "usbmux-helper",
            "ProgName": "usbmux-helper",
            "kLibUSBMuxVersion": 3 << 16,
        }
        s.sendall(_plist_request(msg))
        resp = _recv_plist(s)
        devices = []
        for entry in resp.get("DeviceList", []):
            props = entry.get("Properties", {})
            udid = props.get("SerialNumber")
            if udid:
                devices.append(udid)
        return devices
    finally:
        if own:
            s.close()


# ── lockdown over usbmux (read device info) ───────────────────────────────

LOCKDOWN_PORT = 62078


def _connect_to_device(s, device_id: int, port: int):
    # usbmuxd expects network byte order for the device port.
    net_port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    payload = struct.pack("<HH", net_port, DEVICE_SOCKET_TYPE)
    payload += struct.pack("<I", device_id)
    payload += b"\x00" * 2  # Protocol version (unused)
    # Message type 0 = connect.
    header = struct.pack("<IIII", len(payload) + 16, DEVICE_VERSION,
                         0, _TAG)
    s.sendall(header + payload)
    # Reply header: total, version, type(1=result), tag.
    reply = _recv_exact(s, 16)
    _total, _ver, mtype, _tag = struct.unpack("<IIII", reply)
    if mtype != USBMUXD_RESULT:
        # Some daemons reply via plist instead.
        try:
            resp = plistlib.loads(_recv_exact(s, _total - 16))
            if resp.get("Number", 0) != 0:
                raise UsbmuxError("connect rejected")
            return
        except Exception:
            pass
        raise UsbmuxError("unexpected connect reply")
    body = _recv_exact(s, _total - 16) if _total > 16 else b""
    result_code = struct.unpack("<I", body[:4])[0] if len(body) >= 4 else 0
    if result_code != 0:
        raise UsbmuxError(f"connect to device failed (code {result_code})")


def _device_id_for(udid: str):
    s = _open_socket()
    try:
        msg = {
            "MessageType": "ListDevices",
            "ClientVersionString": "usbmux-helper",
            "kLibUSBMuxVersion": 3 << 16,
        }
        s.sendall(_plist_request(msg))
        resp = _recv_plist(s)
        for entry in resp.get("DeviceList", []):
            props = entry.get("Properties", {})
            if props.get("SerialNumber") == udid:
                return props.get("DeviceID"), s
        s.close()
        return None, None
    except Exception:
        s.close()
        raise


def _lockdown_query(s, keys=None):
    """Send a lockdown GetValue (no pairing) and return parsed plist."""
    request = {
        "Label": "usbmux-helper",
        "Request": "GetValue",
    }
    if keys:
        request["Key"] = keys
    body = plistlib.dumps(request)
    # Lockdown framing: 32-bit big-endian total length, 1-byte type (0=query).
    frame = struct.pack(">I", len(body) + 1) + b"\x00" + body
    s.sendall(frame)

    raw = _recv_exact(s, 4)
    (length,) = struct.unpack(">I", raw)
    head = _recv_exact(s, 1)  # 1-byte reply type
    payload = _recv_exact(s, length - 1)
    return plistlib.loads(payload)


def _safe_get(s, key):
    try:
        resp = _lockdown_query(s, key)
        return resp.get("Value")
    except Exception:
        return None


def read_device_info_fast(udid=None, timeout_ms=5000):
    """Read lightweight device info via a raw lockdown connection.

    Returns a dict shaped like apple_native_wrapper.read_device_info:
        {"success": bool, "data": [{"label","value"}, ...], "error": str,
         "needs_trust": bool}
    """
    global TIMEOUT
    old_timeout = TIMEOUT
    TIMEOUT = max(1.0, timeout_ms / 1000.0)
    try:
        if not udid:
            devs = list_devices()
            if not devs:
                return {"success": False, "data": [],
                        "error": "No device", "needs_trust": False}
            udid = devs[0]

        device_id, s = _device_id_for(udid)
        if device_id is None:
            return {"success": False, "data": [],
                    "error": "No device", "needs_trust": False}

        try:
            _connect_to_device(s, device_id, LOCKDOWN_PORT)

            # Root GetValue returns the full untrusted domain.
            rows = []

            def add(label, key):
                val = _safe_get(s, key)
                if val is not None:
                    rows.append({"label": label, "value": _to_str(val)})

            # Basic, always available without pairing:
            all_values = None
            try:
                all_values = _lockdown_query(s, "")
            except Exception:
                all_values = {}
            root = all_values.get("Value", {}) if isinstance(
                all_values.get("Value"), dict) else {}

            mapping = [
                ("设备型号", "ProductName"),
                ("序列号", "SerialNumber"),
                ("产品类型", "ProductType"),
                ("系统版本", "ProductVersion"),
                ("销售地区", "RegionInfo"),
                ("UDID", "UniqueDeviceID"),
            ]
            seen = set()
            for label, key in mapping:
                val = root.get(key)
                if val is None:
                    val = _safe_get(s, key)
                if val is not None:
                    rows.append({"label": label, "value": _to_str(val)})
                    seen.add(label)

            # Activation state (may require pairing; tolerate failure).
            act = root.get("ActivationState") or _safe_get(s, "ActivationState")
            if act is not None:
                rows.append({"label": "激活状态",
                             "value": "已激活" if act == "Activated"
                             else _to_str(act)})

            # ECID is an integer in the untrusted domain.
            ecid = root.get("UniqueChipID")
            if ecid is None:
                ecid = _safe_get(s, "UniqueChipID")
            if ecid is not None:
                rows.append({"label": "ECID", "value": _ecid_hex(ecid)})

            if not rows:
                return {"success": False, "data": [],
                        "error": "lockdown 返回为空（可能未信任此电脑）",
                        "needs_trust": True}

            return {"success": True, "data": rows,
                    "error": None, "needs_trust": False}
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception as e:
        return {"success": False, "data": [], "error": str(e),
                "needs_trust": False}
    finally:
        TIMEOUT = old_timeout


# ── helpers ───────────────────────────────────────────────────────────────

def _to_str(val) -> str:
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8")
        except Exception:
            return val.hex()
    if isinstance(val, bool):
        return str(val)
    if isinstance(val, int):
        return str(val)
    return str(val)


def _ecid_hex(val) -> str:
    try:
        return format(int(val), "X")
    except Exception:
        return _to_str(val)


if __name__ == "__main__":
    print("devices:", list_devices())
    for d in list_devices():
        print(read_device_info_fast(d))
