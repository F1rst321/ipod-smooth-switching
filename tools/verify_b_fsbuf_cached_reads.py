#!/usr/bin/env python3
"""Read local MP3 bytes through two stock cached FSbuf instances in Unicorn.

The test calls the stock RetailOS bulk-read helper and the captured IRAM
FSbuf read/consume methods. It gives A and B separate stock owner/backing
allocations and preloads one 0x8000-byte cache chunk from local MP3 vectors.
The cache is marked ready directly: resource-manager open, disk I/O, playback,
firmware writing, and physical iPod access are deliberately not simulated.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "build" / "pydeps"))
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from verify_b_fsbuf_constructor import (  # noqa: E402
    DEFAULT_HIBE,
    DEFAULT_IRAM,
    DEFAULT_OSOS,
    FSBUF_BACKING_POINTER_OFFSET,
    FSBUF_BACKING_SIZE_OFFSET,
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
from verify_stock_mp3_pcm import (  # noqa: E402
    DEFAULT_MP3,
    DEFAULT_MP3_B,
    OSOS_SHA256,
    mp3_audio_offset,
)

FSBUF_BULK_READ_VTABLE_SLOT = 0x08
FSBUF_BUFFER_READ_VTABLE_SLOT = 0x0C
FSBUF_CONSUME_VTABLE_SLOT = 0x10
FSBUF_OUTER_VTABLE = 0x006745C8
FSBUF_OPEN_FLAG_OFFSET = 0x21
FSBUF_STATUS_OFFSET = 0x04
FSBUF_CACHE_CURSOR_OFFSET = 0x21E8
FSBUF_CACHE_LIMIT_OFFSET = 0x21F0
FSBUF_FLAGS_OFFSET = 0x21F8
FSBUF_FILE_SIZE_OFFSET = 0x6208
DEST_A = 0x20010000
DEST_B = 0x20012000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osos", type=Path, default=DEFAULT_OSOS)
    parser.add_argument("--hibe", type=Path, default=DEFAULT_HIBE)
    parser.add_argument("--iram", type=Path, default=DEFAULT_IRAM)
    parser.add_argument("--mp3-a", type=Path, default=DEFAULT_MP3)
    parser.add_argument("--mp3-b", type=Path, default=DEFAULT_MP3_B)
    return parser.parse_args()


def initialize_cached_fsbuf(machine: ConstructorMachine, data: bytes) -> dict[str, int | bytes]:
    """Construct one private FSbuf and mark its first cache chunk as ready."""
    owner = machine.call(HEAP_ALLOC, (OWNER_BYTES,))
    backing = machine.call(HEAP_ALLOC, (FSBUF_CHUNK_BYTES,))
    if owner == 0 or backing == 0:
        raise RuntimeError("Stock heap could not allocate an FSbuf owner and chunk")

    machine.machine.mem_write(owner, bytes(OWNER_BYTES))
    machine.machine.mem_write(backing, bytes(FSBUF_CHUNK_BYTES))
    result = machine.call(
        RMI_CONSTRUCTOR,
        (owner, RMI_TASK_QUEUE, RMI_CONTEXT, backing),
        fifth=FSBUF_CHUNK_BYTES,
    )
    if result != owner:
        raise RuntimeError(
            f"FSbuf constructor returned 0x{result:08x}, expected 0x{owner:08x}"
        )

    fsbuf = owner + FSBUF_OFFSET
    cache = data[:FSBUF_CHUNK_BYTES]
    cursor = mp3_audio_offset(data)
    if not cache or cursor >= len(cache):
        raise RuntimeError("MP3 audio frames do not fit in the first private FSbuf chunk")
    machine.machine.mem_write(backing, cache)
    machine.machine.mem_write(fsbuf + FSBUF_STATUS_OFFSET, b"\0")
    machine.machine.mem_write(fsbuf + FSBUF_OPEN_FLAG_OFFSET, b"\x01")
    machine.machine.mem_write(fsbuf + FSBUF_CACHE_CURSOR_OFFSET, struct.pack("<Q", cursor))
    machine.machine.mem_write(fsbuf + FSBUF_CACHE_LIMIT_OFFSET, struct.pack("<Q", len(cache)))
    machine.machine.mem_write(fsbuf + FSBUF_FLAGS_OFFSET, b"\0\x01\0")
    machine.machine.mem_write(
        fsbuf + FSBUF_BACKING_POINTER_OFFSET,
        struct.pack("<I", backing),
    )
    machine.machine.mem_write(
        fsbuf + FSBUF_BACKING_SIZE_OFFSET,
        struct.pack("<I", FSBUF_CHUNK_BYTES),
    )
    machine.machine.mem_write(fsbuf + FSBUF_FILE_SIZE_OFFSET, struct.pack("<Q", len(data)))

    vtable = u32(machine.machine, fsbuf)
    read_helper = u32(machine.machine, vtable + FSBUF_BULK_READ_VTABLE_SLOT)
    buffer_read = u32(machine.machine, vtable + FSBUF_BUFFER_READ_VTABLE_SLOT)
    consume = u32(machine.machine, vtable + FSBUF_CONSUME_VTABLE_SLOT)
    if (vtable, read_helper, buffer_read, consume) != (
        FSBUF_OUTER_VTABLE,
        0x002163C4,
        0x4001D24C,
        0x4001D464,
    ):
        raise RuntimeError(
            "Unexpected stock FSbuf vtable: "
            f"table=0x{vtable:08x}, bulk=0x{read_helper:08x}, "
            f"read=0x{buffer_read:08x}, consume=0x{consume:08x}"
        )

    return {
        "owner": owner,
        "backing": backing,
        "fsbuf": fsbuf,
        "cache": cache,
        "data": data,
        "cursor": cursor,
        "file_size": len(data),
        "read_helper": read_helper,
    }


def read_and_consume(
    machine: ConstructorMachine,
    stream: dict[str, int | bytes],
    count: int,
    destination: int,
) -> None:
    """Read through the stock bulk helper and verify the per-instance cursor."""
    fsbuf = int(stream["fsbuf"])
    cursor = int(stream["cursor"])
    data = bytes(stream["data"])
    result = machine.call(
        int(stream["read_helper"]),
        (fsbuf, destination, count, 0),
    )
    returned = bytes(machine.machine.mem_read(destination, result))
    expected = data[cursor:cursor + count]
    new_cursor = u32(machine.machine, fsbuf + FSBUF_CACHE_CURSOR_OFFSET)
    if result != count or returned != expected or new_cursor != cursor + count:
        raise RuntimeError(
            "Stock FSbuf read/consume mismatch: "
            f"returned={result}, cursor=0x{cursor:x}->0x{new_cursor:x}, "
            f"expected=0x{cursor + count:x}, data_match={returned == expected}"
        )
    stream["cursor"] = new_cursor


def main() -> int:
    args = parse_args()
    osos = args.osos.read_bytes()
    if hashlib.sha256(osos).hexdigest() != OSOS_SHA256:
        raise ValueError("OSOS SHA-256 does not match the audited RetailOS 1.3 image")
    hibe = args.hibe.read_bytes()
    if len(hibe) < 0x800 + RAM_BYTES:
        raise ValueError("HIBE input is too short for a 32 MiB RAM snapshot")
    iram = args.iram.read_bytes()
    if len(iram) < IRAM_SIZE:
        raise ValueError("IRAM input is too short")
    mp3_a = args.mp3_a.read_bytes()
    mp3_b = args.mp3_b.read_bytes()

    machine = ConstructorMachine(osos, hibe, iram)
    stream_a = initialize_cached_fsbuf(machine, mp3_a)
    a_owner = int(stream_a["owner"])
    a_fsbuf = int(stream_a["fsbuf"])
    a_backing = int(stream_a["backing"])
    a_before_b = bytes(machine.machine.mem_read(a_owner, OWNER_BYTES))
    a_cache_before_b = bytes(machine.machine.mem_read(a_backing, FSBUF_CHUNK_BYTES))
    stream_b = initialize_cached_fsbuf(machine, mp3_b)
    if bytes(machine.machine.mem_read(a_owner, OWNER_BYTES)) != a_before_b:
        raise RuntimeError("Constructing B changed A's private RMIprimary/FSbuf owner")
    if bytes(machine.machine.mem_read(a_backing, FSBUF_CHUNK_BYTES)) != a_cache_before_b:
        raise RuntimeError("Constructing B changed A's private FSbuf cache")

    read_and_consume(machine, stream_a, 64, DEST_A)
    read_and_consume(machine, stream_b, 48, DEST_B)
    read_and_consume(machine, stream_a, 96, DEST_A)
    read_and_consume(machine, stream_b, 128, DEST_B)
    if u32(machine.machine, a_fsbuf + FSBUF_CACHE_CURSOR_OFFSET) != int(stream_a["cursor"]):
        raise RuntimeError("Reading B changed A's FSbuf cursor")

    print("PASS: two stock RMIprimary/FSbuf owners and private 0x8000-byte chunks were constructed")
    print("PASS: stock OSOS bulk-read helper used IRAM FSbuf read and consume methods")
    print("PASS: each FSbuf returned bytes from its own local MP3 cache and retained its own cursor")
    print(
        "LIMIT: the cache is prefilled and marked ready in the emulator. "
        "Resource-manager open, filesystem reads, playback scheduling, and hardware remain untested."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"B FSbuf cached-read verification failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
