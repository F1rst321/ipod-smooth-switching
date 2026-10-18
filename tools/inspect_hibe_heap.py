#!/usr/bin/env python3
"""Audit the RetailOS heap free list captured in a pinned iPod backup.

This is a read-only snapshot inspection. A free block recorded in HIBE does
not guarantee that the same allocation will be available during playback.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from build_partition_image import SECTOR_SIZE, read_exact_backup
from inspect_firmware_partition import parse_images

RAM_BASE = 0x10000000
RAM_SIZE = 0x02000000
HIBE_SNAPSHOT_OFFSET = 0x800
ALLOCATOR_GLOBAL_SLOTS = {
    "heap initializer": 0x100D2E54,
    "allocate": 0x1011CA48,
    "free": 0x1011AB98,
}
ALLOCATOR_REGIONS_OFFSET = 0x0C
ALLOCATOR_REGION_COUNT_OFFSET = 0x5C
ALLOCATOR_FREE_BYTES_OFFSET = 0x00
ALLOCATOR_SENTINEL_OFFSET = 0x7C


@dataclass(frozen=True)
class FreeBlock:
    """One free block linked into the RetailOS allocator list."""

    address: int
    size: int
    next_address: int
    previous_address: int


class RamSnapshot:
    """Bounds-checked access to the 32 MiB RAM image stored in HIBE."""

    def __init__(self, hibe: bytes) -> None:
        expected_size = HIBE_SNAPSHOT_OFFSET + RAM_SIZE
        if len(hibe) < expected_size:
            raise ValueError("HIBE does not contain a complete 32 MiB RAM snapshot")
        self._data = hibe[HIBE_SNAPSHOT_OFFSET:expected_size]

    def read(self, address: int, size: int) -> bytes:
        offset = address - RAM_BASE
        if offset < 0 or size < 0 or offset + size > RAM_SIZE:
            raise ValueError(f"RAM range 0x{address:08x}+0x{size:x} is outside HIBE")
        return self._data[offset:offset + size]

    def u32(self, address: int) -> int:
        return int.from_bytes(self.read(address, 4), "little")


def extract_component(backup: bytes, image_type: str) -> bytes:
    """Extract one valid firmware-directory component from the backup."""
    _version, entries = parse_images(backup, SECTOR_SIZE)
    matches = [entry for entry in entries if entry["type"] == image_type]
    if len(matches) != 1 or not matches[0]["range_valid"]:
        raise ValueError(f"expected one valid {image_type} component")
    entry = matches[0]
    start = int(entry["image_start"])
    return backup[start:start + int(entry["length"])]


def find_allocator(snapshot: RamSnapshot) -> tuple[int, int]:
    """Resolve the three global slots to the shared heap structure."""
    cells = {
        name: snapshot.u32(address)
        for name, address in ALLOCATOR_GLOBAL_SLOTS.items()
    }
    if len(set(cells.values())) != 1:
        formatted = ", ".join(f"{name}=0x{value:08x}" for name, value in cells.items())
        raise ValueError(f"allocator global pointers disagree: {formatted}")

    pointer_cell = next(iter(cells.values()))
    allocator = snapshot.u32(pointer_cell)
    if not RAM_BASE <= allocator < RAM_BASE + RAM_SIZE:
        raise ValueError(f"allocator pointer is outside RAM: 0x{allocator:08x}")
    return pointer_cell, allocator


def allocator_regions(snapshot: RamSnapshot, allocator: int) -> list[tuple[int, int]]:
    """Return configured heap ranges and validate each one against HIBE RAM."""
    count = snapshot.u32(allocator + ALLOCATOR_REGION_COUNT_OFFSET)
    if not 0 < count <= 10:
        raise ValueError(f"unexpected allocator region count: {count}")

    ranges = []
    for index in range(count):
        entry = allocator + ALLOCATOR_REGIONS_OFFSET + index * 8
        start = snapshot.u32(entry)
        size = snapshot.u32(entry + 4)
        end = start + size
        if size == 0 or start < RAM_BASE or end > RAM_BASE + RAM_SIZE:
            raise ValueError(f"invalid allocator region {index}: 0x{start:08x}+0x{size:x}")
        ranges.append((start, end))
    return ranges


def scan_free_blocks(
    snapshot: RamSnapshot,
    allocator: int,
    regions: list[tuple[int, int]],
) -> list[FreeBlock]:
    """Walk the size-sorted free list and reject inconsistent links or blocks."""
    sentinel = allocator + ALLOCATOR_SENTINEL_OFFSET
    current = snapshot.u32(sentinel + 4)
    previous = sentinel
    seen: set[int] = set()
    blocks: list[FreeBlock] = []

    while current:
        if current in seen:
            raise ValueError(f"cycle in allocator free list at 0x{current:08x}")
        if current % 4:
            raise ValueError(f"unaligned free block at 0x{current:08x}")
        seen.add(current)

        header = snapshot.u32(current)
        size = header & 0x3FFFFFFC
        next_address = snapshot.u32(current + 4)
        previous_address = snapshot.u32(current + 8)
        if size < 12 or size % 4:
            raise ValueError(f"invalid free block size {size} at 0x{current:08x}")
        if previous_address != previous:
            raise ValueError(
                f"broken previous link at 0x{current:08x}: "
                f"got 0x{previous_address:08x}, expected 0x{previous:08x}"
            )
        if not any(start <= current and current + size <= end for start, end in regions):
            raise ValueError(f"free block 0x{current:08x}+0x{size:x} is outside heap regions")

        block = FreeBlock(current, size, next_address, previous_address)
        if blocks and blocks[-1].size > size:
            raise ValueError("allocator free list is not sorted by block size")
        blocks.append(block)
        if next_address and snapshot.u32(next_address + 8) != current:
            raise ValueError(f"broken next link after free block 0x{current:08x}")
        previous = current
        current = next_address
        if len(blocks) > 100_000:
            raise ValueError("allocator free list exceeded the safety limit")

    address_ordered = sorted(blocks, key=lambda block: block.address)
    for left, right in zip(address_ordered, address_ordered[1:]):
        if left.address + left.size > right.address:
            raise ValueError(
                f"overlapping free blocks at 0x{left.address:08x} and 0x{right.address:08x}"
            )
    return blocks


def inspect(backup_path: Path) -> None:
    """Verify the backup and print the saved heap state without writing files."""
    backup, _entries = read_exact_backup(backup_path)
    osos = extract_component(backup, "OSOS")
    hibe = extract_component(backup, "HIBE")
    snapshot = RamSnapshot(hibe)
    if snapshot.read(RAM_BASE, len(osos)) != osos:
        raise ValueError("HIBE RAM at the OSOS load address does not match stock OSOS")

    pointer_cell, allocator = find_allocator(snapshot)
    regions = allocator_regions(snapshot, allocator)
    blocks = scan_free_blocks(snapshot, allocator, regions)
    free_bytes = sum(block.size for block in blocks)
    recorded_free_bytes = snapshot.u32(allocator + ALLOCATOR_FREE_BYTES_OFFSET)
    if free_bytes != recorded_free_bytes:
        raise ValueError(
            f"free-list total {free_bytes:,} disagrees with allocator field "
            f"{recorded_free_bytes:,}"
        )

    region_bytes = sum(end - start for start, end in regions)
    print(f"Verified pinned backup: {len(backup):,} bytes; exact stock SHA-256")
    print(f"HIBE saved state resolves allocator pointer cell 0x{pointer_cell:08x} "
          f"to heap 0x{allocator:08x}")
    for index, (start, end) in enumerate(regions):
        print(f"  Heap region {index}: 0x{start:08x}..0x{end:08x} ({end - start:,} bytes)")
    print(f"  Free-list blocks: {len(blocks)}")
    print(f"  Free bytes: {free_bytes:,}/{region_bytes:,} ({100 * free_bytes / region_bytes:.1f}%)")
    print(f"  Largest contiguous free block: {max(block.size for block in blocks):,} bytes")
    print("Snapshot only: free space can differ during playback; this does not prove a "
          "second decoder or crossfade is safe.")
    print("Read-only inspection: no firmware image or physical disk was modified.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path, help="exact pinned stock partition backup")
    args = parser.parse_args()
    try:
        inspect(args.backup)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
