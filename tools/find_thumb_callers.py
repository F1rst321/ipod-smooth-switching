#!/usr/bin/env python3
"""Find Thumb-1 BL instruction pairs targeting an OSOS byte offset."""
from __future__ import annotations

import argparse
from pathlib import Path
from zipfile import BadZipFile

from disassemble_arm import read_osos


def thumb_bl_targets(data: bytes):
    """Yield (caller_offset, target_offset) for syntactic Thumb-1 BL pairs."""
    for offset in range(0, len(data) - 3, 2):
        first = int.from_bytes(data[offset:offset + 2], "little")
        second = int.from_bytes(data[offset + 2:offset + 4], "little")
        if first & 0xF800 != 0xF000 or second & 0xF800 != 0xF800:
            continue

        displacement = ((first & 0x07FF) << 12) | ((second & 0x07FF) << 1)
        # Thumb-1 BL has a signed 23-bit displacement from PC (caller + 4).
        if displacement & 0x00400000:
            displacement -= 0x00800000
        yield offset, offset + 4 + displacement


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="local IPSW or extracted OSOS binary")
    parser.add_argument("--target", required=True, type=lambda value: int(value, 0),
                        help="OSOS byte offset, e.g. 0x25db48")
    parser.add_argument("--payload", help="Firmware-* member when the IPSW has multiple payloads")
    parser.add_argument("--sector-size", type=int, default=2048)
    parser.add_argument("--raw-osos", action="store_true", help="treat source as an OSOS binary")
    args = parser.parse_args()
    if args.target < 0 or args.sector_size <= 0:
        parser.error("target must be nonnegative and sector size positive")
    try:
        osos = read_osos(args.source, args.payload, args.sector_size, args.raw_osos)
    except (OSError, BadZipFile, ValueError) as exc:
        parser.error(str(exc))

    matches = [offset for offset, target in thumb_bl_targets(osos) if target == args.target]
    print(f"OSOS size: {len(osos):,} bytes; Thumb-1 BL matches: {len(matches)}")
    for offset in matches:
        print(f"OSOS+0x{offset:06x} -> OSOS+0x{args.target:06x}")
    if not matches:
        print("No Thumb-1 BL caller found. ARM-state calls and indirect calls are not scanned.")
        return 1
    print("Raw matches may occur in data; disassemble each call site and verify Thumb state.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
