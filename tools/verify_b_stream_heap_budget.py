#!/usr/bin/env python3
"""Exercise the stock allocator with a conservative B-stream budget in HIBE.

This read-only Unicorn experiment allocates every currently budgeted B-side
component from a copy of the saved idle heap, then runs the stock RMIprimary /
FSbuf constructor with its private owner and backing storage. It checks that
the requested extents coexist in this snapshot. It does not open a music file,
run audio, measure playback-time memory, write firmware, or access the iPod.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "build" / "pydeps"))

from verify_b_fsbuf_constructor import (  # noqa: E402
    DEFAULT_HIBE,
    DEFAULT_IRAM,
    DEFAULT_OSOS,
    FSBUF_BACKING_POINTER_OFFSET,
    FSBUF_BACKING_SIZE_OFFSET,
    FSBUF_CHUNK_COUNT_OFFSET,
    FSBUF_CHUNK_SIZE_OFFSET,
    FSBUF_CHUNK_BYTES,
    FSBUF_OFFSET,
    HEAP_ALLOC,
    IRAM_SIZE,
    OWNER_BYTES,
    RAM_BYTES,
    RMI_CONSTRUCTOR,
    RMI_CONTEXT,
    RMI_TASK_QUEUE,
    ConstructorMachine,
    u32,
)

OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"
RAM_ALIAS_START = 0x10000000
RAM_ALIAS_END = 0x12000000

# These are candidate lower-bound allocations from the documented streaming
# design. Some entries (notably provider workspace and descriptors) are still
# ownership assumptions, so this is a budget-fit experiment, not an audio test.
BASE_ALLOCATIONS = (
    ("MP3 item", 0x3BEC),
    ("MP3 filter history", 0x1110),
    ("provider workspace candidate", 0x3C10),
    ("track resource candidate", 700),
    ("MP3 sync object candidate", 0xA4),
    ("MP3 worker stack candidate", 0x700),
    ("four-block PCM ring", 18_456),
    ("minimum PCM descriptors", 4 * 0x4C),
    ("private RMIprimary/FSbuf owner", OWNER_BYTES),
)


def parse_bytes(value: str) -> int:
    """Parse a decimal or 0x-prefixed byte count for argparse."""
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected a decimal or 0x-prefixed integer") from exc


def allocate_plan(machine: ConstructorMachine, fsbuf_bytes: int) -> dict[str, tuple[int, int]]:
    """Allocate all candidate extents and reject null, invalid, or overlapping ranges."""
    allocations = list(BASE_ALLOCATIONS)
    allocations.append(("private FSbuf backing", fsbuf_bytes))
    extents: dict[str, tuple[int, int]] = {}

    for name, size in allocations:
        address = machine.call(HEAP_ALLOC, (size,))
        if address == 0:
            raise RuntimeError(f"stock allocator refused {name} ({size:,} bytes)")
        end = address + size
        if not RAM_ALIAS_START <= address < end <= RAM_ALIAS_END:
            raise RuntimeError(
                f"allocator returned out-of-heap extent for {name}: "
                f"0x{address:08x}..0x{end:08x}"
            )
        for existing_name, (existing_start, existing_size) in extents.items():
            existing_end = existing_start + existing_size
            if address < existing_end and existing_start < end:
                raise RuntimeError(
                    f"requested extents overlap: {name} and {existing_name}"
                )
        extents[name] = (address, size)

    return extents


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osos", type=Path, default=DEFAULT_OSOS)
    parser.add_argument("--hibe", type=Path, default=DEFAULT_HIBE)
    parser.add_argument("--iram", type=Path, default=DEFAULT_IRAM)
    parser.add_argument(
        "--fsbuf-backing-bytes",
        type=parse_bytes,
        default=0x8000,
        help="private B FSbuf backing size (default: 0x8000; try 0x40000 for stock size)",
    )
    args = parser.parse_args()
    if args.fsbuf_backing_bytes <= 0 or args.fsbuf_backing_bytes % FSBUF_CHUNK_BYTES:
        parser.error("--fsbuf-backing-bytes must be a positive multiple of 0x8000")

    osos = args.osos.read_bytes()
    if hashlib.sha256(osos).hexdigest() != OSOS_SHA256:
        parser.error("OSOS SHA-256 does not match the audited original")
    hibe = args.hibe.read_bytes()
    if len(hibe) < 0x800 + RAM_BYTES:
        parser.error("HIBE RAM snapshot is too short")
    iram = args.iram.read_bytes()
    if len(iram) < IRAM_SIZE:
        parser.error("IRAM snapshot is too short")

    machine = ConstructorMachine(osos, hibe, iram)
    extents = allocate_plan(machine, args.fsbuf_backing_bytes)
    owner = extents["private RMIprimary/FSbuf owner"][0]
    backing = extents["private FSbuf backing"][0]
    machine.machine.mem_write(owner, bytes(OWNER_BYTES))
    machine.machine.mem_write(backing, bytes(args.fsbuf_backing_bytes))

    result = machine.call(
        RMI_CONSTRUCTOR,
        (owner, RMI_TASK_QUEUE, RMI_CONTEXT, backing),
        fifth=args.fsbuf_backing_bytes,
    )
    fsbuf = owner + FSBUF_OFFSET
    geometry = (
        u32(machine.machine, fsbuf + FSBUF_BACKING_POINTER_OFFSET),
        u32(machine.machine, fsbuf + FSBUF_BACKING_SIZE_OFFSET),
        u32(machine.machine, fsbuf + FSBUF_CHUNK_SIZE_OFFSET),
        u32(machine.machine, fsbuf + FSBUF_CHUNK_COUNT_OFFSET),
    )
    expected_geometry = (
        backing,
        args.fsbuf_backing_bytes,
        FSBUF_CHUNK_BYTES,
        args.fsbuf_backing_bytes // FSBUF_CHUNK_BYTES,
    )
    if result != owner or geometry != expected_geometry:
        raise RuntimeError(
            "stock RMIprimary/FSbuf constructor did not preserve the allocated "
            f"backing geometry: result=0x{result:08x}, geometry={geometry!r}"
        )

    requested_total = sum(size for _, size in BASE_ALLOCATIONS) + args.fsbuf_backing_bytes
    print("Stock allocator accepted the candidate B-stream requests in the idle HIBE copy.")
    print(f"Requested payload total: {requested_total:,} bytes across {len(extents)} extents")
    for name, (address, size) in extents.items():
        print(f"  {name}: {size:,} bytes at 0x{address:08x}")
    print(
        f"RMIprimary/FSbuf constructor: owner 0x{owner:08x}; "
        f"FSbuf 0x{fsbuf:08x}; backing 0x{backing:08x}; "
        f"{geometry[3]} x 0x{geometry[2]:x}-byte chunks"
    )
    print(
        "Snapshot-only result: no file open/read, playback-time heap measurement, "
        "audio execution, firmware write, or physical iPod access."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"B-stream heap budget verification failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
