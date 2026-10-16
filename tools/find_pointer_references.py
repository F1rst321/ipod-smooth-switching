#!/usr/bin/env python3
"""Find aligned 32-bit OSOS pointers to an offset in the image.

RetailOS OSOS tables can store pointers as image-relative offsets, while other
data uses absolute addresses. This scanner checks both representations;
matches are candidates and need contextual inspection.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from zipfile import BadZipFile

from disassemble_arm import LOAD_ADDRESS, read_osos


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="local IPSW or extracted OSOS binary")
    parser.add_argument("--target", required=True, type=lambda x: int(x, 0),
                        help="OSOS byte offset, e.g. 0x213e10")
    parser.add_argument("--payload", help="Firmware-* member when the IPSW has multiple payloads")
    parser.add_argument("--sector-size", type=int, default=2048)
    parser.add_argument("--raw-osos", action="store_true", help="treat source as an OSOS binary")
    parser.add_argument("--limit", type=int, default=100,
                        help="maximum references to print (default: 100; 0 prints all)")
    args = parser.parse_args()
    if args.target < 0 or args.sector_size <= 0 or args.limit < 0:
        parser.error("target and limit must be nonnegative; sector size must be positive")
    try:
        osos = read_osos(args.source, args.payload, args.sector_size, args.raw_osos)
    except (OSError, BadZipFile, ValueError) as exc:
        parser.error(str(exc))
    if args.target >= len(osos):
        parser.error(f"target is outside OSOS ({len(osos):,} bytes)")

    needles = {
        "image-relative": args.target.to_bytes(4, "little"),
        "absolute": (LOAD_ADDRESS + args.target).to_bytes(4, "little"),
    }
    matches: list[tuple[int, str]] = []
    for offset in range(0, len(osos) - 3, 4):
        value = osos[offset:offset + 4]
        for representation, needle in needles.items():
            if value == needle:
                matches.append((offset, representation))
    print(f"OSOS size: {len(osos):,} bytes; aligned pointer matches: {len(matches)}")
    shown = matches if args.limit == 0 else matches[:args.limit]
    for offset, representation in shown:
        print(
            f"OSOS+0x{offset:06x} contains {representation} pointer "
            f"to OSOS+0x{args.target:06x}"
        )
    if len(shown) < len(matches):
        print(f"... {len(matches) - len(shown)} more; increase --limit or use --limit 0")
    if not matches:
        print(
            "No aligned image-relative or absolute pointer found. "
            "PC-relative, Thumb, and computed references are not scanned."
        )
        return 1
    print("Note: matches may be data tables or literal pools; inspect each surrounding function before interpreting it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
