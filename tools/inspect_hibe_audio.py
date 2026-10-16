#!/usr/bin/env python3
"""Inspect known RetailOS audio objects in an iPod Video HIBE RAM snapshot."""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from inspect_firmware_partition import parse_images

SECTOR_SIZE = 2048
RAM_BASE = 0x10000000
RAM_SIZE = 0x02000000
HIBE_SNAPSHOT_OFFSET = 0x800
OSOS_SIZE = 7_561_216


def component(raw: bytes, entries: list[dict[str, int | str | bool | None]], name: str) -> bytes:
    matches = [entry for entry in entries if entry["type"] == name]
    if len(matches) != 1 or not matches[0]["range_valid"]:
        raise ValueError(f"expected one valid {name} component")
    entry = matches[0]
    start, length = int(entry["image_start"]), int(entry["length"])
    return raw[start:start + length]


class Snapshot:
    def __init__(self, hibe: bytes) -> None:
        if len(hibe) < HIBE_SNAPSHOT_OFFSET + RAM_SIZE:
            raise ValueError("HIBE does not contain a complete 32 MiB RAM snapshot")
        self.hibe = hibe

    def read(self, address: int, length: int) -> bytes:
        if address < RAM_BASE or address + length > RAM_BASE + RAM_SIZE:
            raise ValueError(f"RAM range 0x{address:08x}+0x{length:x} is outside snapshot")
        offset = HIBE_SNAPSHOT_OFFSET + address - RAM_BASE
        return self.hibe[offset:offset + length]

    def u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="read-only firmware partition backup")
    parser.add_argument("--sector-size", type=int, default=SECTOR_SIZE)
    args = parser.parse_args()
    if args.sector_size <= 0:
        parser.error("sector size must be positive")

    try:
        raw = args.image.read_bytes()
        version, entries = parse_images(raw, args.sector_size)
        osos = component(raw, entries, "OSOS")
        hibe = component(raw, entries, "HIBE")
        snapshot = Snapshot(hibe)
        if len(osos) != OSOS_SIZE:
            raise ValueError(f"unexpected OSOS size: {len(osos)}")
        if snapshot.read(RAM_BASE, len(osos)) != osos:
            raise ValueError("HIBE RAM start does not match the OSOS component")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Backup SHA-256: {hashlib.sha256(raw).hexdigest()}")
    print(f"Firmware format: {version}; OSOS/HIBE: {len(osos):,}/{len(hibe):,} bytes")

    manager_global = 0x1081ECC8
    manager = snapshot.u32(manager_global)
    manager_vtable = snapshot.u32(manager)
    type1_queue = snapshot.u32(manager + 0x44)
    type1_capacity = snapshot.u32(type1_queue + 4)
    type1_head = snapshot.u32(type1_queue + 0x0C)
    type1_tail = snapshot.u32(type1_queue + 0x10)
    type1_active = snapshot.u32(type1_queue + 0x14)
    type1_items = snapshot.u32(type1_queue + 0x18)
    request_method = snapshot.u32(RAM_BASE + manager_vtable + 0x28)
    print(f"Interface manager pointer at RAM 0x{manager_global:08x}: 0x{manager:08x}")
    print(f"  vtable offset: 0x{manager_vtable:08x}; request method (+0x28): 0x{request_method:08x}")
    print(f"  type-1 registry: RAM 0x{type1_queue:08x}; active={type1_active}, "
          f"head={type1_head}, tail={type1_tail}, capacity={type1_capacity}")
    if type1_active and 0 < type1_capacity <= 256:
        index = type1_head
        while index != type1_tail:
            item = snapshot.u32(type1_items + index * 4)
            print(f"    queued object RAM 0x{item:08x}; vtable offset 0x{snapshot.u32(item):08x}")
            index = (index + 1) % type1_capacity

    parent = 0x109DD438
    i2s = parent + 0x54
    child = parent + 0x360
    print(f"I2S subobject RAM 0x{i2s:08x}: vtable offset 0x{snapshot.u32(i2s):08x}")
    print(f"I2S buffer-path object RAM 0x{child:08x}: vtable offset 0x{snapshot.u32(child):08x}")
    print("Buffer-path fields +0x20/+0x24: "
          f"0x{snapshot.u32(child + 0x20):08x}/0x{snapshot.u32(child + 0x24):08x}")
    print("These are saved RAM pointers/state only; the script does not access the device.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
