#!/usr/bin/env python3
"""Map stock audio-provider overlays from OSOS into their IRAM addresses.

The provider loaders copy code/data ranges and clear BSS ranges in IRAM.
This tool reads their literal words from the exact stock OSOS;
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

# Triples are literal locations of (source, destination, byte length) passed
# to OSOS+0x8438c. Pairs are (destination, byte length) passed to +0x843a0.
# Provider indices follow the six-object registry at OSOS+0x63ee44. Provider 5
# uses a WAV writer and does not have one of these codec copy loaders.
PROVIDER_COPY_TRIPLES = {
    0: (0x840D0, 0x840E4, 0x840F8),
    1: (0x8410C,),
    2: (0x841C0, 0x841D4),
    3: (0x84328, 0x8433C, 0x84350),
    4: (0x84314,),
}
PROVIDER_ZERO_PAIRS = {
    0: ((0x840E0, 0x840DC), (0x840F4, 0x840F0), (0x84108, 0x84104)),
    1: ((0x8411C, 0x84118),),
    2: ((0x841D0, 0x841CC), (0x841E4, 0x841E0)),
    3: ((0x84338, 0x84334), (0x8434C, 0x84348), (0x84360, 0x8435C)),
    4: ((0x84324, 0x84320),),
}
ITEM_ADDRESS_LITERALS = {
    0: 0x1A9078, 1: 0x1B1BAC, 2: 0x19F664, 3: 0x1A911C, 4: 0x1B6BC8,
}

# Both provider-0 render paths load the same absolute addresses. Keep the
# two literal locations so the report checks each path independently rather
# than assuming that a per-item decoder context owns these destinations.
OUTPUT_STATE_LITERALS = {
    "queue object": (0x4000A8CC, 0x4000AA44),
    "output pointer slot 0": (0x4000A8D0, 0x4000AA48),
    "output pointer slot 1": (0x4000A8D4, 0x4000AA4C),
    "work buffer 1": (0x4000A8D8, 0x4000AA50),
    "work buffer 0": (0x4000A8DC, 0x4000AA54),
}


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


def load_ranges(data: bytes, provider: int) -> tuple[OverlayRange, ...]:
    ranges = []
    for first_literal in PROVIDER_COPY_TRIPLES[provider]:
        source = read_word(data, first_literal) - OSOS_LOAD_ALIAS
        destination = read_word(data, first_literal + 4)
        length = read_word(data, first_literal + 8)
        if length == 0:
            continue
        if not (0 <= source < source + length <= len(data)):
            raise ValueError("overlay source lies outside the OSOS image")
        if not (IRAM_START <= destination < destination + length <= IRAM_END):
            raise ValueError("overlay destination lies outside expected IRAM")
        ranges.append(OverlayRange(source, destination, length))
    return tuple(ranges)


def load_zero_ranges(data: bytes, provider: int) -> tuple[tuple[int, int], ...]:
    ranges = []
    for destination_at, length_at in PROVIDER_ZERO_PAIRS[provider]:
        destination = read_word(data, destination_at)
        length = read_word(data, length_at)
        if length == 0:
            continue
        if not (IRAM_START <= destination < destination + length <= IRAM_END):
            raise ValueError("BSS clear range lies outside expected IRAM")
        ranges.append((destination, destination + length))
    return tuple(ranges)


def touched_intervals(data: bytes, provider: int) -> tuple[tuple[int, int], ...]:
    intervals = [(item.destination, item.destination + item.length)
                 for item in load_ranges(data, provider)]
    intervals.extend(load_zero_ranges(data, provider))
    merged: list[list[int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return tuple((start, end) for start, end in merged)


def overlap_bytes(left: tuple[tuple[int, int], ...],
                  right: tuple[tuple[int, int], ...]) -> int:
    return sum(max(0, min(left_end, right_end) - max(left_start, right_start))
               for left_start, left_end in left
               for right_start, right_end in right)


def resolve(address: int, ranges: tuple[OverlayRange, ...]) -> int | None:
    for item in ranges:
        mapped = item.map_address(address)
        if mapped is not None:
            return mapped
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("osos", type=Path, help="exact extracted stock OSOS")
    parser.add_argument("--provider", type=int, choices=sorted(PROVIDER_COPY_TRIPLES),
                        default=0, help="provider loader to inspect (default: 0)")
    parser.add_argument("--overlap-report", action="store_true",
                        help="show IRAM overlap for provider loaders 0 through 4")
    parser.add_argument("--output-state", action="store_true",
                        help="read provider-0 render-path shared-state literals")
    parser.add_argument("addresses", nargs="*", type=lambda word: int(word, 0),
                        help="IRAM runtime addresses to map back to OSOS")
    parser.add_argument("--vtable", type=lambda word: int(word, 0),
                        help="print a runtime vtable and map each method")
    parser.add_argument("--slots", type=int, default=16)
    args = parser.parse_args()
    if args.slots < 1 or args.slots > 128:
        parser.error("--slots must be between 1 and 128")
    if args.output_state and args.provider != 0:
        parser.error("--output-state is mapped only for provider 0")

    try:
        data = args.osos.read_bytes()
    except OSError as exc:
        parser.error(str(exc))
    actual_hash = hashlib.sha256(data).hexdigest()
    if len(data) != STOCK_OSOS_SIZE or actual_hash != STOCK_OSOS_SHA256:
        parser.error("OSOS size/SHA-256 does not match the original iPod backup")
    ranges = load_ranges(data, args.provider)
    item_address = read_word(data, ITEM_ADDRESS_LITERALS[args.provider])
    print(f"provider {args.provider} item address: 0x{item_address:08x} "
          "(constructor literal; not a runtime allocation)")
    print(f"provider {args.provider} copied ranges:")
    for item in ranges:
        print(f"OSOS+0x{item.source:x}..0x{item.source + item.length:x} "
              f"-> IRAM 0x{item.destination:08x}..0x{item.destination + item.length:08x}")
    for start, end in load_zero_ranges(data, args.provider):
        print(f"BSS clear IRAM 0x{start:08x}..0x{end:08x}")

    if args.overlap_report:
        provider_intervals = {number: touched_intervals(data, number)
                              for number in PROVIDER_COPY_TRIPLES}
        for left in sorted(provider_intervals):
            for right in sorted(provider_intervals):
                if right <= left:
                    continue
                amount = overlap_bytes(provider_intervals[left],
                                       provider_intervals[right])
                print(f"provider {left}/{right}: {amount} overlapping IRAM bytes")

    if args.output_state:
        for label, literals in OUTPUT_STATE_LITERALS.items():
            values = []
            for address in literals:
                source = resolve(address, ranges)
                if source is None or resolve(address + 3, ranges) != source + 3:
                    parser.error("output-state literal is outside copied ranges")
                values.append(read_word(data, source))
            print(f"{label}: " + ", ".join(
                f"[0x{address:08x}]=0x{value:08x}"
                for address, value in zip(literals, values)
            ) + f"; same destination={values[0] == values[1]}")
        print("Static absolute references; independent decoding is not established.")

    for address in args.addresses:
        source = resolve(address, ranges)
        print(f"0x{address:08x} -> " + (f"OSOS+0x{source:x}" if source is not None
                                     else f"not in provider-{args.provider} copied ranges"))

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
