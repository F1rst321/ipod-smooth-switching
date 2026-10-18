#!/usr/bin/env python3
"""Map the early boot OSOS-to-IRAM copy routine in the stock image.

The loader called from OSOS+0x2c0 reads two (source, destination, length)
triples and two (destination, length) clear pairs from fixed OSOS literals.
This script validates the known stock OSOS before interpreting those fields.
An optional captured IRAM file can be supplied to verify copied bytes.
It only reads local files; it does not access or write the connected iPod.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


STOCK_OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"
STOCK_OSOS_SIZE = 7_561_216
OSOS_LOAD_ALIAS = 0x04000000
IRAM_BASE = 0x40000000
IRAM_SIZE = 0x20000

COPY_TRIPLES = (0x840A8, 0x840BC)
CLEAR_PAIRS = (0x840B8, 0x840CC)


def read_word(data: bytes, offset: int) -> int:
    """Read one little-endian 32-bit loader field."""
    return struct.unpack_from("<I", data, offset)[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("osos", type=Path, help="extracted stock OSOS binary")
    parser.add_argument("--iram", type=Path,
                        help="optional raw IRAM snapshot starting at 0x40000000")
    args = parser.parse_args()

    try:
        osos = args.osos.read_bytes()
        iram = args.iram.read_bytes() if args.iram else None
    except OSError as exc:
        parser.error(str(exc))

    digest = hashlib.sha256(osos).hexdigest()
    if len(osos) != STOCK_OSOS_SIZE or digest != STOCK_OSOS_SHA256:
        parser.error("OSOS size/SHA-256 does not match the pristine iPod backup")

    print(f"Stock OSOS verified: {len(osos):,} bytes, SHA-256 {digest}")
    print("Loader: OSOS+0x8392c, called by startup OSOS+0x2c0")
    snapshot_mismatch = False
    for table_offset in COPY_TRIPLES:
        source_alias = read_word(osos, table_offset)
        destination = read_word(osos, table_offset + 4)
        length = read_word(osos, table_offset + 8)
        source = source_alias - OSOS_LOAD_ALIAS
        if (source < 0 or source + length > len(osos) or
                destination < IRAM_BASE or
                destination + length > IRAM_BASE + IRAM_SIZE or length == 0):
            parser.error(f"invalid copy triple at OSOS+0x{table_offset:x}")
        print(f"Copy OSOS+0x{source:06x}..0x{source + length:06x} "
              f"-> IRAM 0x{destination:08x}..0x{destination + length:08x}")
        if iram is not None:
            iram_offset = destination - IRAM_BASE
            if iram_offset < 0 or iram_offset + length > len(iram):
                print("  snapshot: destination is outside captured IRAM")
                snapshot_mismatch = True
            else:
                same = osos[source:source + length] == iram[iram_offset:iram_offset + length]
                print(f"  snapshot: {'exact byte match' if same else 'DIFFERS'}")
                snapshot_mismatch |= not same

    for table_offset in CLEAR_PAIRS:
        destination = read_word(osos, table_offset)
        length = read_word(osos, table_offset - 4)
        print(f"Clear IRAM 0x{destination:08x}..0x{destination + length:08x} "
              f"({length} bytes)")

    print("The copy table describes early boot relocation only; it does not "
          "prove the code is currently running or safe to patch.")
    return 1 if snapshot_mismatch else 0


if __name__ == "__main__":
    raise SystemExit(main())
