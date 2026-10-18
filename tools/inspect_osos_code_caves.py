#!/usr/bin/env python3
"""Report zero-filled ranges inside the pinned stock OSOS component.

The report is read-only. A zero-filled range is only a static code-space
candidate; it does not prove that the corresponding RAM is unused at runtime.
The scanner does not parse OSOS-to-IRAM overlays or indirect references.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from inspect_firmware_partition import parse_images

SECTOR_SIZE = 2048
EXPECTED_PARTITION_SIZE = 98_574_336
EXPECTED_PARTITION_SHA256 = "010bda520671d86a5a2cb010b57ee4484c980e54d97eb3e12621e08cde0423a3"
EXPECTED_OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"
OSOS_RAM_BASE = 0x10000000
KNOWN_OSOS_TO_IRAM_COPIES = (
    (0x719B00, 0x71A80C, "provider 0"),
    (0x71A80C, 0x71EE84, "provider 0"),
    (0x71EE84, 0x72292C, "provider 0"),
    (0x723594, 0x7235F8, "provider 2"),
    (0x7235F8, 0x72960C, "provider 2"),
    (0x72B704, 0x72DC04, "provider 3"),
    (0x72DC04, 0x731ED4, "provider 3"),
    (0x731ED4, 0x7326C4, "provider 3"),
    (0x72960C, 0x72B704, "provider 4"),
    (0x7335CC, 0x7358C0, "runtime helper"),
)
PROVISIONAL_CODE_WINDOW = (0x712000, 0x7161A4)


def extract_component(
    partition: bytes,
    entries: list[dict[str, int | str | bool | None]],
    name: str,
) -> bytes:
    """Extract one unique, bounds-checked image-directory component."""
    matches = [entry for entry in entries if entry["type"] == name]
    if len(matches) != 1 or not matches[0]["range_valid"]:
        raise ValueError(f"expected one valid {name} component")
    entry = matches[0]
    start = int(entry["image_start"])
    length = int(entry["length"])
    return partition[start:start + length]


def find_zero_runs(data: bytes, minimum_size: int) -> list[tuple[int, int]]:
    """Return maximal all-zero ranges meeting the minimum length."""
    ranges: list[tuple[int, int]] = []
    offset = 0
    while offset < len(data):
        if data[offset] != 0:
            offset += 1
            continue
        start = offset
        while offset < len(data) and data[offset] == 0:
            offset += 1
        if offset - start >= minimum_size:
            ranges.append((start, offset))
    return ranges


def find_address_words(
    osos: bytes,
    start: int,
    end: int,
) -> list[tuple[int, int]]:
    """Find aligned 32-bit words whose value falls inside an OSOS RAM range.

    These are candidates only: packed 16-bit data and numeric constants can
    look like absolute addresses when viewed as 32-bit words.
    """
    address_start = OSOS_RAM_BASE + start
    address_end = OSOS_RAM_BASE + end
    matches: list[tuple[int, int]] = []
    for source in range(0, len(osos) - 3, 4):
        value = int.from_bytes(osos[source:source + 4], "little")
        if address_start <= value < address_end:
            matches.append((source, value))
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path, help="pinned stock firmware partition backup")
    parser.add_argument("--minimum-size", type=lambda value: int(value, 0), default=4096,
                        help="minimum zero-range size to report (default: 4096 bytes)")
    parser.add_argument("--limit", type=int, default=20,
                        help="maximum ranges to print (default: 20)")
    args = parser.parse_args()
    if args.minimum_size <= 0 or args.limit <= 0:
        parser.error("minimum size and limit must be positive")

    try:
        partition = args.backup.read_bytes()
        partition_hash = hashlib.sha256(partition).hexdigest()
        if (len(partition) != EXPECTED_PARTITION_SIZE
                or partition_hash != EXPECTED_PARTITION_SHA256):
            raise ValueError("backup size/SHA-256 differs from the pinned original")
        _version, entries = parse_images(partition, SECTOR_SIZE)
        osos = extract_component(partition, entries, "OSOS")
        hibe = extract_component(partition, entries, "HIBE")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    osos_hash = hashlib.sha256(osos).hexdigest()
    if osos_hash != EXPECTED_OSOS_SHA256:
        parser.error("OSOS hash does not match the pinned RetailOS 1.3 image")

    runs = sorted(find_zero_runs(osos, args.minimum_size),
                  key=lambda bounds: bounds[1] - bounds[0], reverse=True)
    ram_snapshot = hibe[0x800:]
    if ram_snapshot[:len(osos)] != osos:
        parser.error("HIBE RAM at the OSOS load address does not match stock OSOS")

    print(f"Pinned partition verified: {len(partition):,} bytes; SHA-256 {partition_hash}")
    print(f"OSOS verified: {len(osos):,} bytes; SHA-256 {osos_hash}")
    window_start, window_end = PROVISIONAL_CODE_WINDOW
    window_overlays = sorted({
        name for copy_start, copy_end, name in KNOWN_OSOS_TO_IRAM_COPIES
        if window_start < copy_end and copy_start < window_end
    })
    window_words = find_address_words(osos, window_start, window_end)
    window_snapshot_match = ram_snapshot[window_start:window_end] == osos[window_start:window_end]
    print(f"Provisional window OSOS+0x{window_start:06x}..+0x{window_end:06x}: "
          f"{window_end - window_start:,} bytes; all zero={not any(osos[window_start:window_end])}; "
          f"HIBE bytes match={window_snapshot_match}; "
          f"address-like words={len(window_words)}; "
          f"known OSOS-to-IRAM copies={', '.join(window_overlays) if window_overlays else 'none known'}")
    print(f"All-zero ranges in OSOS >= {args.minimum_size:,} bytes: {len(runs)}")
    for start, end in runs[:args.limit]:
        candidates = find_address_words(osos, start, end)
        snapshot_match = ram_snapshot[start:end] == osos[start:end]
        overlay_names = sorted({
            name for copy_start, copy_end, name in KNOWN_OSOS_TO_IRAM_COPIES
            if start < copy_end and copy_start < end
        })
        overlays = ", ".join(overlay_names) if overlay_names else "none known"
        print(f"  OSOS+0x{start:06x}..+0x{end:06x}: {end - start:,} bytes; "
              f"RAM 0x{OSOS_RAM_BASE + start:08x}..0x{OSOS_RAM_BASE + end:08x}; "
              f"HIBE bytes match={snapshot_match}; "
              f"address-like words={len(candidates)}; "
              f"known OSOS-to-IRAM copies={overlays}")
        for source, value in candidates[:12]:
            print(f"    word at OSOS+0x{source:06x} = 0x{value:08x} "
                  f"(candidate target OSOS+0x{value - OSOS_RAM_BASE:06x})")
        if len(candidates) > 12:
            print(f"    ... {len(candidates) - 12} more candidate words")

    print("Address-like words may be packed data or constants; verify code/data xrefs separately.")
    print("A zero-filled file range and one matching HIBE snapshot do not certify free runtime RAM.")
    print("Overlay copy/clear ranges and indirect references are not analyzed by this scanner.")
    print("Read-only analysis only: no image is written and no physical disk is accessed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
