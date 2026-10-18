#!/usr/bin/env python3
"""Inspect RAM immediately beyond the stock OSOS load image in HIBE.

The iPod Video HIBE payload contains a 0x800-byte header followed by a
32 MiB RAM snapshot. The first bytes of that snapshot should match OSOS,
which is loaded at 0x10000000. This read-only report measures the saved RAM
after the end of OSOS; it cannot establish that any bytes are safe to reserve
for new code.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from inspect_firmware_partition import parse_images

SECTOR_SIZE = 2048
HIBE_HEADER_SIZE = 0x800
RAM_BASE = 0x10000000
RAM_SIZE = 0x02000000
PAGE_SIZE = 0x10000
STOCK_OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"


def extract_component(partition: bytes, entries: list[dict[str, int | str | bool | None]],
                      name: str) -> bytes:
    """Return one component after verifying its directory entry is in bounds."""
    matches = [entry for entry in entries if entry["type"] == name]
    if len(matches) != 1 or not matches[0]["range_valid"]:
        raise ValueError(f"expected one valid {name} component")
    entry = matches[0]
    start = int(entry["image_start"])
    length = int(entry["length"])
    return partition[start:start + length]


def find_zero_runs(data: bytes, minimum_size: int) -> list[tuple[int, int]]:
    """Return (start, end) offsets for maximal qualifying all-zero ranges."""
    runs: list[tuple[int, int]] = []
    offset = 0
    while offset < len(data):
        if data[offset] != 0:
            offset += 1
            continue
        start = offset
        while offset < len(data) and data[offset] == 0:
            offset += 1
        if offset - start >= minimum_size:
            runs.append((start, offset))
    return runs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path,
                        help="read-only firmware partition backup containing HIBE")
    parser.add_argument("--sector-size", type=int, default=SECTOR_SIZE)
    parser.add_argument("--window-size", type=lambda value: int(value, 0), default=0x400000,
                        help="RAM window after OSOS to summarize (default: 0x400000)")
    parser.add_argument("--minimum-zero-run", type=lambda value: int(value, 0), default=256,
                        help="minimum zero run to list (default: 256 bytes)")
    parser.add_argument("--limit", type=int, default=12,
                        help="maximum zero runs to list (default: 12)")
    args = parser.parse_args()
    if min(args.sector_size, args.window_size, args.minimum_zero_run, args.limit) <= 0:
        parser.error("sector size, window size, zero-run size, and limit must be positive")

    try:
        partition = args.backup.read_bytes()
        _version, entries = parse_images(partition, args.sector_size)
        osos = extract_component(partition, entries, "OSOS")
        hibe = extract_component(partition, entries, "HIBE")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    osos_hash = hashlib.sha256(osos).hexdigest()
    if osos_hash != STOCK_OSOS_SHA256:
        parser.error("OSOS hash does not match the pinned RetailOS 1.3 image")

    expected_hibe_size = HIBE_HEADER_SIZE + RAM_SIZE
    if len(hibe) != expected_hibe_size:
        parser.error(f"expected HIBE size {expected_hibe_size:,}, got {len(hibe):,}")
    ram = hibe[HIBE_HEADER_SIZE:]
    if ram[:len(osos)] != osos:
        parser.error("HIBE RAM at 0x10000000 does not begin with the stock OSOS image")
    if len(osos) >= RAM_SIZE:
        parser.error("OSOS image fills the captured RAM window")

    extension_offset = len(osos)
    extension = ram[extension_offset:min(RAM_SIZE, extension_offset + args.window_size)]
    runs = sorted(find_zero_runs(extension, args.minimum_zero_run),
                  key=lambda bounds: bounds[1] - bounds[0], reverse=True)

    print(f"OSOS size: {len(osos):,} bytes; SHA-256: {osos_hash}")
    print(f"HIBE size: {len(hibe):,} bytes = 0x800 header + 0x{RAM_SIZE:x} RAM bytes")
    print(f"HIBE RAM starts at 0x{RAM_BASE:08x}; OSOS end: 0x{RAM_BASE + extension_offset:08x}")
    print(f"Inspected extension-adjacent RAM: {len(extension):,} bytes")
    page_count = (len(extension) + PAGE_SIZE - 1) // PAGE_SIZE
    for index in range(page_count):
        start = index * PAGE_SIZE
        page = extension[start:start + PAGE_SIZE]
        nonzero = sum(value != 0 for value in page)
        address = RAM_BASE + extension_offset + start
        print(f"  RAM 0x{address:08x}: nonzero={nonzero:,}/{len(page):,} bytes")

    print(f"Zero runs >= {args.minimum_zero_run} bytes: {len(runs)}")
    for start, end in runs[:args.limit]:
        address = RAM_BASE + extension_offset + start
        print(f"  RAM 0x{address:08x}..0x{address + (end - start):08x}: {end - start:,} bytes")
    print("Snapshot occupancy is not an allocator map; nonzero/zero bytes do not certify usable space.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
