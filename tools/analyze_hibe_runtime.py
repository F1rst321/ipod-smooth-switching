#!/usr/bin/env python3
"""Report the OSOS mirror and runtime endpoint references in an iPod HIBE image."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from inspect_firmware_partition import parse_images

ENDPOINTS = (0x149DD4C8, 0x149DD554, 0x149DD638, 0x149DD750)
SECTOR_SIZE = 2048


def component(raw: bytes, entries: list[dict[str, int | str | bool | None]], name: str) -> bytes:
    matches = [entry for entry in entries if entry["type"] == name]
    if len(matches) != 1 or not matches[0]["range_valid"]:
        raise ValueError(f"expected one valid {name} component")
    entry = matches[0]
    start, length = int(entry["image_start"]), int(entry["length"])
    return raw[start:start + length]


def offsets(data: bytes, needle: bytes):
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return
        yield pos
        pos += 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="read-only firmware partition backup")
    parser.add_argument("--sector-size", type=int, default=SECTOR_SIZE)
    args = parser.parse_args()
    if args.sector_size <= 0:
        parser.error("--sector-size must be positive")

    try:
        raw = args.image.read_bytes()
        version, entries = parse_images(raw, args.sector_size)
        osos = component(raw, entries, "OSOS")
        hibe = component(raw, entries, "HIBE")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    mirror_offset = 0x800
    mirror = hibe[mirror_offset:mirror_offset + len(osos)]
    print(f"Backup: {args.image} ({len(raw):,} bytes, SHA-256 {hashlib.sha256(raw).hexdigest()})")
    print(f"Firmware format: {version}")
    print(f"OSOS: {len(osos):,} bytes, SHA-256 {hashlib.sha256(osos).hexdigest()}")
    print(f"HIBE: {len(hibe):,} bytes, SHA-256 {hashlib.sha256(hibe).hexdigest()}")
    print(f"HIBE+0x{mirror_offset:x} OSOS mirror: {'exact match' if mirror == osos else 'DIFFERS'}")
    if not mirror:
        raise ValueError("HIBE does not contain a complete OSOS mirror at +0x800")

    runtime_start = mirror_offset + len(osos)
    for address in ENDPOINTS:
        needle = address.to_bytes(4, "little")
        static_hits = [pos for pos in offsets(hibe, needle) if mirror_offset <= pos < runtime_start]
        runtime_hits = [pos for pos in offsets(hibe, needle) if pos >= runtime_start]
        print(f"Endpoint 0x{address:08x}: static OSOS mirror={len(static_hits)}, runtime snapshot={len(runtime_hits)}")
        for pos in runtime_hits:
            ram_address = 0x10000000 + pos - mirror_offset
            context_start = max(0, pos - 8)
            context_end = min(len(hibe), pos + 12)
            context = hibe[context_start:context_end].hex(" ")
            print(f"  HIBE+0x{pos:08x} (RAM 0x{ram_address:08x}): {context}")

    print("Note: references identify pointers only; the pointed-to endpoint memory is not present in HIBE.")
    return 0 if mirror == osos else 1


if __name__ == "__main__":
    raise SystemExit(main())
