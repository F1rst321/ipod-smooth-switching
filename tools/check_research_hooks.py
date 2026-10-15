#!/usr/bin/env python3
"""Check candidate RetailOS 1.3 hook locations against a local firmware image."""
from __future__ import annotations

import argparse
from pathlib import Path
from zipfile import BadZipFile

from extract_firmware_images import load_firmware_payload
from inspect_firmware_partition import parse_images

# Candidate function starts from community reverse engineering notes. The byte
# signatures below were read from our local 25.1.3 IPSW and are used as guards.
HOOKS = {
    "resource lookup": (0x21F254, bytes.fromhex("f8 40 2d e9 01 50 a0 e1 00 10 a0 e3")),
    "list-row label draw": (0x1BB260, bytes.fromhex("f7 4f 2d e9 30 d0 4d e2 00 40 a0 e1")),
    "general label draw": (0x244924, bytes.fromhex("30 40 2d e9 01 e0 a0 e1 00 40 a0 e1")),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="local IPSW or raw firmware-partition backup")
    parser.add_argument("--payload", help="Firmware-* entry when the IPSW has multiple payloads")
    parser.add_argument("--sector-size", type=int, default=2048)
    args = parser.parse_args()
    if args.sector_size <= 0:
        parser.error("--sector-size must be positive")

    try:
        data, label = load_firmware_payload(args.source, args.payload)
        _, entries = parse_images(data, args.sector_size)
    except (OSError, BadZipFile, ValueError) as exc:
        parser.error(str(exc))
    osos_entries = [entry for entry in entries if entry["type"] == "OSOS"]
    if len(osos_entries) != 1 or not osos_entries[0]["range_valid"]:
        parser.error("could not locate one valid OSOS component")
    entry = osos_entries[0]
    base = int(entry["image_start"])
    size = int(entry["length"])
    osos = data[base:base + size]

    failed = False
    print(f"Source: {label}")
    print(f"OSOS: {size:,} bytes, load address 0x{int(entry['address']):08x}")
    for name, (offset, expected) in HOOKS.items():
        actual = osos[offset:offset + len(expected)]
        ok = actual == expected
        failed |= not ok
        state = "MATCH" if ok else "MISMATCH"
        print(f"{state:8} {name:<22} OSOS+0x{offset:06x}  {actual.hex(' ')}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
