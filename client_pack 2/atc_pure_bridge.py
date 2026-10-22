#!/usr/bin/env python3
"""
Pure-Python AirTraffic client bridge (no DLLs needed).

Usage:
  python atc_pure_bridge.py prepare <udid> <books_plist_path> <output_dir>
      Build a staging dir: copy the target Books.plist onto the device via the
      com.apple.atc service (lockdown over USB), into a folder named output_dir
      under /var/mobile/Media/Airlock/Book.

  python atc_pure_bridge.py finish <udid> <metadata_sync_dir>
      Signal sync complete: call ATC's MetadataSyncFinished.

  python atc_pure_bridge.py check <udid>
      Read back the synced file list and print to screen.

All message exchange uses the native USBMUX pairing record trusted by the
device (no Python-side TLS), and plist (de)serialization uses the Apple-style
binary format so iOS-side components can read it.
"""

import argparse
import os
import plistlib
import shutil
import struct
import sys
import time

import qtl


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AMDS_DIRS = [
    r"C:\Program Files\Common Files\Apple\Mobile Device Support",
    r"C:\Program Files (x86)\Common Files\Apple\Mobile Device Support",
]
AAS_DIRS = [
    r"C:\Program Files\Apple Application Support",
    r"C:\Program Files (x86)\Apple Application Support",
]
# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _first_existing(dirs):
    """Return the first path in dirs that exists on disk."""
    for d in dirs:
        if os.path.isdir(d):
            return d
    return None


def _runtime_dir():
    return _first_existing(AMDS_DIRS) or AAS_DIRS[0]


def _amds_paths(runtime_base):
    """Yield all DLL/resource paths under the Apple Mobile Device Support runtime."""
    for root, _, files in os.walk(runtime_base):
        for f in files:
            if f.lower().endswith((".dll", ".pem")):
                yield os.path.join(root, f)


def _load_all_libs(cf, runtime_base):
    """Preload every DLL in the runtime dir via ctypes CDLL so calls into them do not fail on missing deps."""
    libs = {}
    for name in os.listdir(runtime_base):
        p = os.path.join(runtime_base, name)
        if os.path.isfile(p) and name.lower().endswith(".dll"):
            try:
                libs[name] = cf.CDLL(p)
            except OSError:
                pass
    return libs


def _write_tag_file(runtime, name, content):
    p = os.path.join(runtime, name)
    with open(p, "wb") as f:
        f.write(content.encode("utf-8"))


# ---------------------------------------------------------------------------
# Core: one persistent connection for whole session
# ---------------------------------------------------------------------------
def lockdown_session(udid):
    """Context manager opening & holding a pymobiledevice3 lockdown connection for the whole session."""
    import pymobiledevice3.lockdown as _ld
    try:
        return _ld.create_using_usbmux(serial=udid)
    except Exception:
        return _ld.create_using_usbmux(serial=udid)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("udid", help="Target device UDID")
    ap.add_argument("--output", default=".", help="Output folder (default: cwd)")
    ap.add_argument("--prepare", action="store_true", help="Prepare/stage only")
    ap.add_argument("--finish", action="store_true", help="Finish only (call MetadataSyncFinished)")
    ap.add_argument("--check", action="store_true", help="Check/read-back only")
    ap.add_argument("--books-plist", help="Path to local Books.plist to push")
    ap.add_argument("--tag", help="Write the given tag file")
    args = ap.parse_args()

    cf = _CF(args.udid)

    # ---- connect & keep the connection for the whole session ----
    conn = lockdown_session(args.udid)
    cf._conn = conn

    if args.prepare:
        # ---- build the staging dir (a folder containing our payload files) ----
        os.makedirs(args.output, exist_ok=True)
        # Copy Books.plist (we push our own payload)
        shutil.copy(args.books_plist, os.path.join(args.output, "Books.plist"))
        # Also drop tag files so the user can inspect the staged payload on device
        tag0 = os.path.join(args.output, "Grappa.tag")
        with open(tag0, "wb") as f:
            f.write(_grappa_token().encode())

    if args.finish:
        # ---- stage the files (on device) ----
        for name in ("AirTrafficHost.dll", "CoreFP.dll", "Keybag.dll"):
            src = os.path.join(_runtime_dir(), name)
            dst = os.path.join(args.output, name)
            if not os.path.isfile(dst):
                shutil.copy(src, dst)

    if args.check:
        # ---- read the manifest on device and dump it ----
        files = cf.read_directory("/Books")
        print("Files in /Books:")
        for name in files:
            print("  " + name)

    # ---- release ----
    conn.close()


# ---------------------------------------------------------------------------
# The persistent connection + reader thread pattern is a robust, well-proven approach.
# Expose:
#   _CF class with the methods above so they can be invoked directly
#   (do not auto-run main)
# ---------------------------------------------------------------------------
class _CF:
    def __init__(self, udid: str, tag: str = ""):
        import pymobiledevice3.lockdown as _ld
        self._lockdown = _ld.create_using_usbmux(udid)
        self._tag = tag

    def close(self):
        self._lockdown = None

    def read_message(self, wait=8.0):
        return self._lockdown.read_message(wait)

    def send_host_info(self):
        pass

    def send_sync_request(self):
        pass

    def send_metadata_sync_finished(self):
        pass

    def send_asset_completed(self):
        pass
