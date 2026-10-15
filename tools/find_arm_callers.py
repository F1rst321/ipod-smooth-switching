#!/usr/bin/env python3
"""Find ARM-state BL instructions targeting a byte offset in RetailOS OSOS."""
from __future__ import annotations

import argparse
from pathlib import Path
from zipfile import BadZipFile

from disassemble_arm import LOAD_ADDRESS, read_osos


def arm_bl_targets(data: bytes):
    """Yield (caller_offset, target_offset) for aligned ARM BL encodings."""
    for offset in range(0, len(data) - 3, 4):
        word = int.from_bytes(data[offset:offset + 4], "little")
        if word & 0x0F000000 != 0x0B000000:
            continue
        displacement = (word & 0x00FFFFFF) << 2
        if displacement & 0x02000000:
            displacement -= 0x04000000
        target = offset + 8 + displacement
        yield offset, target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="local IPSW or extracted OSOS binary")
    parser.add_argument("--target", required=True, type=lambda x: int(x, 0),
                        help="OSOS byte offset, e.g. 0x25a614")
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

    matches = [offset for offset, target in arm_bl_targets(osos) if target == args.target]
    print(f"OSOS size: {len(osos):,} bytes; ARM BL matches: {len(matches)}")
    for offset in matches:
        print(f"OSOS+0x{offset:06x} -> OSOS+0x{args.target:06x}")
    if not matches:
        print("No ARM-state BL caller found. Thumb calls and indirect calls are not scanned.")
        return 1
    print("Note: raw branch matches can occur in data; disassemble each call site before interpreting it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
