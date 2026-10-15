#!/usr/bin/env python3
"""Locate ARM LDR-literal users of a 32-bit value in an OSOS image.

This recognizes only ARM-state, word-sized, immediate PC-relative LDR. Results
are candidates because firmware data can coincidentally resemble instructions.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from zipfile import BadZipFile

from disassemble_arm import read_osos


def parse_integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("use decimal or 0x-prefixed integer") from exc


def references(data: bytes, literal_offset: int):
    first = max(0, literal_offset - 4104) & ~3
    last = min(len(data) - 4, literal_offset + 4096)
    for instruction_offset in range(first, last + 1, 4):
        word = int.from_bytes(data[instruction_offset:instruction_offset + 4], "little")
        # ARM LDR Rd, [pc, +/-#imm12], with a word transfer and no writeback.
        if word & 0x0F7F0000 != 0x051F0000:
            continue
        displacement = word & 0xFFF
        if not word & 0x00800000:
            displacement = -displacement
        if instruction_offset + 8 + displacement == literal_offset:
            yield instruction_offset, word


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="IPSW, partition image, or raw OSOS")
    parser.add_argument("--value", required=True, type=parse_integer, help="32-bit value to find")
    parser.add_argument("--raw-osos", action="store_true")
    parser.add_argument("--payload")
    parser.add_argument("--sector-size", type=int, default=2048)
    args = parser.parse_args()
    if not 0 <= args.value <= 0xFFFFFFFF or args.sector_size <= 0:
        parser.error("value must be a 32-bit unsigned integer; sector size must be positive")
    try:
        data = read_osos(args.source, args.payload, args.sector_size, args.raw_osos)
    except (OSError, BadZipFile, ValueError) as exc:
        parser.error(str(exc))
    needle = args.value.to_bytes(4, "little")
    literals = [offset for offset in range(0, len(data) - 3, 4)
                if data[offset:offset + 4] == needle]
    print(f"OSOS size: {len(data):,} bytes; aligned literal matches: {len(literals)}")
    for literal_offset in literals:
        print(f"OSOS+0x{literal_offset:06x} = 0x{args.value:08x}")
        for instruction_offset, word in references(data, literal_offset):
            print(f"  ARM LDR candidate OSOS+0x{instruction_offset:06x} (0x{word:08x})")
    print("Validate each candidate in a disassembly; computed and Thumb references are omitted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
