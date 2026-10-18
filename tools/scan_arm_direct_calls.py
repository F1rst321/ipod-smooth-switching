#!/usr/bin/env python3
"""Find ARM-state BL/BLX-immediate calls to addresses in a raw firmware image.

This static scan does not see Thumb calls, indirect calls, or code loaded from
another component. Hits should be confirmed against disassembly.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def decode_arm_call(word: int, address: int) -> tuple[int, str] | None:
    """Return the target and mnemonic for an ARM BL/BLX-immediate word."""
    if (word & 0x0F00_0000) == 0x0B00_0000 and (word >> 28) != 0xF:
        displacement = sign_extend(word & 0x00FF_FFFF, 24) << 2
        return address + 8 + displacement, "BL"

    if (word & 0xFE00_0000) == 0xFA00_0000:
        displacement = sign_extend(word & 0x00FF_FFFF, 24) << 2
        displacement |= ((word >> 24) & 1) << 1
        return address + 8 + displacement, "BLX"

    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="raw ARM firmware component")
    parser.add_argument(
        "targets",
        nargs="+",
        type=lambda value: int(value, 0),
        help="absolute ARM code addresses, such as 0x1024b5bc",
    )
    parser.add_argument(
        "--load-address",
        type=lambda value: int(value, 0),
        default=0x1000_0000,
        help="address where byte zero is loaded (default: 0x10000000)",
    )
    args = parser.parse_args()
    if args.load_address & 3:
        parser.error("load address must be word-aligned")

    try:
        image = args.image.read_bytes()
    except OSError as exc:
        parser.error(str(exc))
    if len(image) < 4:
        parser.error("image is too short to contain ARM instructions")

    hits = {target: [] for target in args.targets}
    for offset in range(0, len(image) - 3, 4):
        word = struct.unpack_from("<I", image, offset)[0]
        decoded = decode_arm_call(word, args.load_address + offset)
        if decoded is None:
            continue
        target, mnemonic = decoded
        normalized_target = target & ~1
        if normalized_target in hits:
            hits[normalized_target].append((offset, target, mnemonic))

    print(f"Image: {args.image} ({len(image):,} bytes)")
    print(f"Load address: 0x{args.load_address:08x}")
    for target in args.targets:
        matches = hits.get(target & ~1, [])
        print(f"Target 0x{target:08x}:")
        if not matches:
            print("  no ARM-state BL/BLX-immediate sites found")
            continue
        for offset, resolved, mnemonic in matches:
            state = " (Thumb target)" if mnemonic == "BLX" else ""
            print(
                f"  {mnemonic} at image+0x{offset:06x} "
                f"(0x{args.load_address + offset:08x}) -> "
                f"0x{resolved:08x}{state}"
            )
    print("Scope: no Thumb calls, indirect calls, or external loaded modules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
