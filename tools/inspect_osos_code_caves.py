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


def arm_immediate(word: int) -> int:
    """Decode ARM's rotated 8-bit immediate operand."""
    value = word & 0xFF
    rotate = 2 * ((word >> 8) & 0xF)
    if rotate == 0:
        return value
    return ((value >> rotate) | (value << (32 - rotate))) & 0xFFFFFFFF


def find_arm_reference_candidates(
    osos: bytes,
    start: int,
    end: int,
) -> list[tuple[int, str, int]]:
    """Find syntactic ARM references whose targets fall inside a window.

    This scans aligned words across the image and can report instructions
    embedded in data. It intentionally does not interpret Thumb code,
    relocation tables, or computed/indirect references.
    """
    matches: set[tuple[int, str, int]] = set()
    for source in range(0, len(osos) - 3, 4):
        word = int.from_bytes(osos[source:source + 4], "little")
        if word >> 28 == 0xF:
            continue

        # ARM B/BL: PC is the current instruction address plus eight bytes.
        if word & 0x0E000000 == 0x0A000000:
            displacement = word & 0x00FFFFFF
            if displacement & 0x00800000:
                displacement -= 0x01000000
            target = source + 8 + (displacement << 2)
            if start <= target < end:
                matches.add((source, "B/BL", target))

        # ADD/SUB Rd, PC, #imm (ADR-style computed address).
        if ((word >> 25) & 0x7) == 0x1 and ((word >> 16) & 0xF) == 0xF:
            opcode = (word >> 21) & 0xF
            if opcode in (2, 4):
                delta = arm_immediate(word)
                target = source + 8 + (delta if opcode == 4 else -delta)
                if start <= target < end:
                    matches.add((source, "ADR", target))

        # ARM LDR literal, including a word in the window containing a pointer
        # into the same window or its absolute RAM address.
        if word & 0x0F7F0000 == 0x051F0000:
            delta = word & 0xFFF
            literal = source + 8 + (delta if (word >> 23) & 1 else -delta)
            if 0 <= literal <= len(osos) - 4:
                value = int.from_bytes(osos[literal:literal + 4], "little")
                if start <= literal < end:
                    matches.add((source, "LDR literal", literal))
                if start <= value < end or 0x10000000 + start <= value < 0x10000000 + end:
                    matches.add((source, "LDR pointer", value))

    # Include data pointers even when the corresponding source word is not
    # referenced by an ARM LDR instruction.
    for source in range(0, len(osos) - 3, 4):
        value = int.from_bytes(osos[source:source + 4], "little")
        if start <= value < end or 0x10000000 + start <= value < 0x10000000 + end:
            matches.add((source, "pointer word", value))
    return sorted(matches)


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
    window_refs = find_arm_reference_candidates(osos, window_start, window_end)
    window_snapshot_match = ram_snapshot[window_start:window_end] == osos[window_start:window_end]
    print(f"Provisional window OSOS+0x{window_start:06x}..+0x{window_end:06x}: "
          f"{window_end - window_start:,} bytes; all zero={not any(osos[window_start:window_end])}; "
          f"HIBE bytes match={window_snapshot_match}; "
          f"address-like words={len(window_words)}; "
          f"known OSOS-to-IRAM copies={', '.join(window_overlays) if window_overlays else 'none known'}")
    print(f"Syntactic ARM/pointer reference candidates into provisional window: {len(window_refs)}")
    for source, kind, target in window_refs[:40]:
        if 0x10000000 <= target < 0x10000000 + len(osos):
            target_text = f"RAM 0x{target:08x} (OSOS+0x{target - 0x10000000:06x})"
        else:
            target_text = f"OSOS+0x{target:06x}"
        print(f"  source OSOS+0x{source:06x}: {kind} -> {target_text}")
    if len(window_refs) > 40:
        print(f"  ... {len(window_refs) - 40} more candidates")
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
    print("ARM reference candidates are syntactic only; Thumb and indirect references are omitted.")
    print("A zero-filled file range and one matching HIBE snapshot do not certify free runtime RAM.")
    print("Overlay copy/clear ranges and indirect references are not analyzed by this scanner.")
    print("Read-only analysis only: no image is written and no physical disk is accessed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
