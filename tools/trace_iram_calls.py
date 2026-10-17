#!/usr/bin/env python3
"""Resolve ARM BL calls in a captured IRAM routine to their OSOS sources.

RetailOS copies several noncontiguous OSOS regions into IRAM. A direct branch
retains its relative displacement, so decompiling the original file can give a
different callee from the one present at the runtime destination.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path


def unique_match(haystack: bytes, needle: bytes) -> int | None:
    """Return a source offset only when the captured bytes have one match."""
    first = haystack.find(needle)
    if first < 0 or haystack.find(needle, first + 1) >= 0:
        return None
    return first


def arm_bl_destination(word: int, address: int) -> int | None:
    """Decode a 32-bit ARM unconditional BL, including its signed offset."""
    if word >> 24 != 0xEB:
        return None
    displacement = (word & 0x00FFFFFF) << 2
    if displacement & 0x02000000:
        displacement -= 0x04000000
    return address + 8 + displacement


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("osos", type=Path, help="exact extracted OSOS binary")
    parser.add_argument("iram", type=Path, help="captured IRAM bytes")
    parser.add_argument("address", type=lambda value: int(value, 0),
                        help="runtime address at the start of the routine")
    parser.add_argument("--runtime-base", type=lambda value: int(value, 0),
                        default=0x40000000)
    parser.add_argument("--length", type=lambda value: int(value, 0),
                        default=0x80, help="bytes of the routine to scan")
    parser.add_argument("--window", type=int, default=32,
                        help="exact byte window for source matching")
    args = parser.parse_args()
    if args.length <= 0 or args.length % 4 or args.window < 16:
        parser.error("length must be positive and ARM aligned; window >= 16")
    try:
        osos = args.osos.read_bytes()
        iram = args.iram.read_bytes()
    except OSError as exc:
        parser.error(str(exc))

    start = args.address - args.runtime_base
    if start < 0 or start + max(args.length, args.window) > len(iram):
        parser.error("requested source range is outside captured IRAM")
    source = unique_match(osos, iram[start:start + args.window])
    if source is None:
        parser.error("runtime source does not map uniquely to OSOS")
    if osos[source:source + args.length] != iram[start:start + args.length]:
        parser.error("source routine differs from OSOS within scan range")
    print(f"IRAM 0x{args.address:08x} -> OSOS+0x{source:x} "
          f"({args.length} identical bytes)")

    failures = 0
    for offset in range(0, args.length, 4):
        word = struct.unpack_from("<I", iram, start + offset)[0]
        destination = arm_bl_destination(word, args.address + offset)
        if destination is None:
            continue
        destination_offset = destination - args.runtime_base
        static_target = source + offset + 8 + (
            destination - (args.address + offset + 8))
        if not 0 <= destination_offset <= len(iram) - args.window:
            print(f"  +0x{offset:x}: IRAM 0x{destination:08x} outside capture; "
                  f"static OSOS+0x{static_target:x}")
            failures += 1
            continue
        match = unique_match(
            osos, iram[destination_offset:destination_offset + args.window]
        )
        if match is None:
            print(f"  +0x{offset:x}: IRAM 0x{destination:08x} has no unique "
                  f"OSOS match; static OSOS+0x{static_target:x}")
            failures += 1
            continue
        print(f"  +0x{offset:x}: IRAM 0x{destination:08x} -> "
              f"OSOS+0x{match:x} (static BL target OSOS+0x{static_target:x})")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
