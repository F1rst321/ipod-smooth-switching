#!/usr/bin/env python3
"""Find ARM-state PC-relative references to one OSOS byte offset.

The search is syntactic. Matches in data and unreachable code require manual
disassembly before they can be interpreted as executable references.
"""
from __future__ import annotations

import argparse
from pathlib import Path


LOAD_ADDRESS = 0x10000000


def immediate(word: int) -> int:
    value = word & 0xff
    rotate = 2 * ((word >> 8) & 0xf)
    return ((value >> rotate) | (value << (32 - rotate))) & 0xffffffff if rotate else value


def references(data: bytes, target: int):
    for offset in range(0, len(data) - 3, 4):
        word = int.from_bytes(data[offset:offset + 4], "little")
        if (word >> 28) == 0xf:
            continue

        # ARM ADD/SUB Rd, pc, #immediate (the assembler's ADR pseudo-op).
        if ((word >> 25) & 0x7) == 0x1 and ((word >> 16) & 0xf) == 15:
            opcode = (word >> 21) & 0xf
            if opcode in (2, 4):
                delta = immediate(word)
                address = offset + 8 + (delta if opcode == 4 else -delta)
                if address == target:
                    yield offset, "ADD" if opcode == 4 else "SUB"

        # ARM LDR Rd, [pc, #+/-imm12] addressing a literal pointer.
        if word & 0x0f7f0000 == 0x051f0000:
            delta = word & 0xfff
            literal = offset + 8 + (delta if (word >> 23) & 1 else -delta)
            if 0 <= literal <= len(data) - 4:
                value = int.from_bytes(data[literal:literal + 4], "little")
                # RetailOS literal pools contain both image-relative values
                # (relocated by the loader) and absolute 0x10000000 values.
                if value in (target, LOAD_ADDRESS + target):
                    yield offset, f"LDR literal at OSOS+0x{literal:x}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="extracted OSOS binary")
    parser.add_argument("--target", type=lambda value: int(value, 0), required=True)
    args = parser.parse_args()
    data = args.source.read_bytes()
    if not 0 <= args.target < len(data):
        parser.error("target is outside source")
    found = list(references(data, args.target))
    for offset, kind in found:
        print(f"OSOS+0x{offset:06x}: {kind} -> OSOS+0x{args.target:06x}")
    print(f"{len(found)} candidate PC-relative references")
    return 0 if found else 1


if __name__ == "__main__":
    raise SystemExit(main())
