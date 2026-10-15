#!/usr/bin/env python3
"""Compare a read-back iPod firmware partition with an Apple IPSW payload."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from zipfile import BadZipFile, ZipFile


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def differing_ranges(left: bytes, right: bytes) -> list[tuple[int, int]]:
    """Return half-open ranges where two equal-length byte strings differ."""
    ranges: list[tuple[int, int]] = []
    start: int | None = None
    for offset, (a, b) in enumerate(zip(left, right)):
        if a != b and start is None:
            start = offset
        elif a == b and start is not None:
            ranges.append((start, offset))
            start = None
    if start is not None:
        ranges.append((start, min(len(left), len(right))))
    return ranges


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipsw", type=Path, required=True, help="official Apple IPSW ZIP file")
    parser.add_argument("--backup", type=Path, required=True, help="read-only firmware-partition backup image")
    args = parser.parse_args()

    try:
        with ZipFile(args.ipsw) as ipsw:
            candidates = [name for name in ipsw.namelist() if name.startswith("Firmware-")]
            if len(candidates) != 1:
                parser.error(f"Expected exactly one Firmware-* payload in IPSW, found {len(candidates)}")
            payload = ipsw.read(candidates[0])
    except (OSError, BadZipFile) as exc:
        parser.error(f"Cannot read IPSW: {exc}")

    try:
        backup = args.backup.read_bytes()
    except OSError as exc:
        parser.error(f"Cannot read backup image: {exc}")

    common_length = min(len(payload), len(backup))
    common_payload = payload[:common_length]
    common_backup = backup[:common_length]
    ranges = differing_ranges(common_payload, common_backup)
    differing_bytes = sum(end - start for start, end in ranges)
    tail = backup[len(payload):] if len(backup) > len(payload) else b""

    print(f"IPSW payload: {candidates[0]} ({len(payload):,} bytes), SHA-256 {sha256(payload)}")
    print(f"Device partition: {args.backup} ({len(backup):,} bytes), SHA-256 {sha256(backup)}")
    print(f"Compared bytes: {common_length:,}; differing bytes: {differing_bytes:,} in {len(ranges)} ranges")
    if ranges:
        print("Difference ranges (half-open offsets):")
        for start, end in ranges:
            print(f"  0x{start:08x}..0x{end:08x} ({end - start} bytes)")
    if tail:
        nonzero = sum(byte != 0 for byte in tail)
        non_ff = sum(byte != 0xFF for byte in tail)
        print(f"Partition bytes beyond IPSW payload: {len(tail):,}; nonzero {nonzero:,}; non-0xFF {non_ff:,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
