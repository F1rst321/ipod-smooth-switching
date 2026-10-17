#!/usr/bin/env python3
"""Map the stock provider-0 codec overlay from OSOS into its IRAM addresses.

The loader at OSOS+0x839c0 copies three code/data ranges and clears three BSS
ranges. This tool reads the loader's literal words from the exact stock OSOS;
it never writes the firmware or accesses the connected iPod.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path


STOCK_OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"
STOCK_OSOS_SIZE = 7_561_216
OSOS_LOAD_ALIAS = 0x04000000
IRAM_START = 0x40000000
IRAM_END = 0x40020000

# Each triple is (source address, IRAM destination, byte length) as passed to
# the copy helper at OSOS+0x8438c by the provider-0 loader at OSOS+0x839c0.
COPY_LITERAL_TRIPLES = (
    (0x840D0, 0x840D4, 0x840D8),
    (0x840E4, 0x840E8, 0x840EC),
    (0x840F8, 0x840FC, 0x84100),
)


@dataclass(frozen=True)
class OverlayRange:
    source: int
    destination: int
    length: int

    def map_address(self, address: int) -> int | None:
        if self.destination <= address < self.destination + self.length:
            return self.source + address - self.destination
        return None


def read_word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def load_ranges(data: bytes) -> tuple[OverlayRange, ...]:
    ranges = []
    for source_at, destination_at, length_at in COPY_LITERAL_TRIPLES:
        source = read_word(data, source_at) - OSOS_LOAD_ALIAS
        destination = read_word(data, destination_at)
        length = read_word(data, length_at)
        if not (0 <= source < source + length <= len(data)):
            raise ValueError("overlay source lies outside the OSOS image")
        if not (IRAM_START <= destination < destination + length <= IRAM_END):
            raise ValueError("overlay destination lies outside expected IRAM")
        ranges.append(OverlayRange(source, destination, length))
    return tuple(ranges)


def resolve(address: int, ranges: tuple[OverlayRange, ...]) -> int | None:
    for item in ranges:
        mapped = item.map_address(address)
        if mapped is not None:
            return mapped
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("osos", type=Path, help="exact extracted stock OSOS")
    parser.add_argument("addresses", nargs="*", type=lambda word: int(word, 0),
                        help="IRAM runtime addresses to map back to OSOS")
    parser.add_argument("--vtable", type=lambda word: int(word, 0),
                        help="print a runtime vtable and map each method")
    parser.add_argument("--slots", type=int, default=16)
    args = parser.parse_args()
    if args.slots < 1 or args.slots > 128:
        parser.error("--slots must be between 1 and 128")

    try:
        data = args.osos.read_bytes()
    except OSError as exc:
        parser.error(str(exc))
    actual_hash = hashlib.sha256(data).hexdigest()
    if len(data) != STOCK_OSOS_SIZE or actual_hash != STOCK_OSOS_SHA256:
        parser.error("OSOS size/SHA-256 does not match the original iPod backup")
    ranges = load_ranges(data)
    for item in ranges:
        print(f"OSOS+0x{item.source:x}..0x{item.source + item.length:x} "
              f"-> IRAM 0x{item.destination:08x}..0x{item.destination + item.length:08x}")

    for address in args.addresses:
        source = resolve(address, ranges)
        print(f"0x{address:08x} -> " + (f"OSOS+0x{source:x}" if source is not None
                                     else "not in provider-0 copied ranges"))

    if args.vtable is not None:
        table_offset = resolve(args.vtable, ranges)
        table_end = resolve(args.vtable + 4 * args.slots - 1, ranges)
        if (table_offset is None or table_end is None or
                table_end - table_offset != 4 * args.slots - 1):
            parser.error("vtable is outside the copied ranges")
        print(f"vtable 0x{args.vtable:08x} -> OSOS+0x{table_offset:x}")
        for index in range(args.slots):
            value = read_word(data, table_offset + index * 4)
            if value == 0:
                target = "null"
            else:
                overlay_target = resolve(value, ranges)
                if overlay_target is not None:
                    target = f"OSOS+0x{overlay_target:x} (overlay)"
                elif value < len(data):
                    target = f"OSOS+0x{value:x} (image-relative)"
                else:
                    target = "unresolved"
            print(f"  +0x{index * 4:02x}: 0x{value:08x} -> {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
