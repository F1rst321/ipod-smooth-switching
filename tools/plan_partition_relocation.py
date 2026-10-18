#!/usr/bin/env python3
"""Print a read-only layout plan for growing OSOS in the pinned stock image.

This command does not emit a firmware image, modify the backup, or access a
physical drive. It only checks whether the directory-listed components would
fit if OSOS and every later component were shifted by the requested amount.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from inspect_firmware_partition import parse_images

SECTOR_SIZE = 2048
EXPECTED_SIZE = 98_574_336
EXPECTED_SHA256 = "010bda520671d86a5a2cb010b57ee4484c980e54d97eb3e12621e08cde0423a3"
EXPECTED_TYPES = ("OSOS", "RSRC", "AUPD", "HIBE")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path, help="pinned stock firmware-partition backup")
    parser.add_argument("--grow-osos", type=lambda value: int(value, 0), required=True,
                        help="proposed OSOS growth in bytes; must be sector-aligned")
    args = parser.parse_args()
    if args.grow_osos <= 0 or args.grow_osos % SECTOR_SIZE:
        parser.error(f"--grow-osos must be a positive multiple of {SECTOR_SIZE}")

    try:
        raw = args.backup.read_bytes()
    except OSError as exc:
        parser.error(str(exc))
    if len(raw) != EXPECTED_SIZE or hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
        parser.error("backup size/SHA-256 differs from the pinned original")

    try:
        version, entries = parse_images(raw, SECTOR_SIZE)
    except ValueError as exc:
        parser.error(str(exc))
    if version != 3 or tuple(str(entry["type"]) for entry in entries) != EXPECTED_TYPES:
        parser.error("unexpected firmware directory version or image sequence")
    if any(not entry["range_valid"] for entry in entries):
        parser.error("firmware directory contains an out-of-range component")

    osos = entries[0]
    osos_start = int(osos["image_start"])
    last_end = max(int(entry["image_start"]) + int(entry["length"]) for entry in entries)
    final_end = last_end + args.grow_osos
    if final_end > len(raw):
        parser.error(f"proposed layout exceeds partition by {final_end - len(raw):,} bytes")

    print(f"Pinned stock partition: {len(raw):,} bytes; SHA-256 verified")
    print(f"Proposed OSOS growth: {args.grow_osos:,} bytes")
    print("Component ranges (end offset is exclusive):")
    for entry in entries:
        name = str(entry["type"])
        old_start = int(entry["image_start"])
        old_length = int(entry["length"])
        if name == "OSOS":
            new_start = old_start
            new_length = old_length + args.grow_osos
        else:
            new_start = old_start + args.grow_osos
            new_length = old_length
        print(f"  {name}: 0x{old_start:08x}..0x{old_start + old_length:08x}"
              f" -> 0x{new_start:08x}..0x{new_start + new_length:08x}")

    old_tail = len(raw) - last_end
    new_tail = len(raw) - final_end
    print(f"Trailing partition space: {old_tail:,} -> {new_tail:,} bytes")
    print("Layout only: no component bytes or directory fields were changed.")
    print("HIBE, RAM allocation, image checksums, and boot behavior are not validated here.")
    print("No firmware image was created; this plan is not installable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
