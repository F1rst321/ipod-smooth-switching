#!/usr/bin/env python3
"""Map Ghidra's reconstructed IRAM globals back to stock OSOS literals.

The decoder overlay uses fixed IRAM addresses while the literals and values
live in OSOS. This read-only helper inventories globals named by Ghidra output
so shared pointers and scratch buffers can be audited before cloning a context.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from map_codec_overlay import (
    STOCK_OSOS_SHA256,
    STOCK_OSOS_SIZE,
    load_ranges,
    read_word,
    resolve,
)


GLOBAL_NAME = re.compile(r"\b(?:u|i|pu|p|c)Ram(4000[0-9a-fA-F]{4})\b")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("osos", type=Path, help="exact extracted stock OSOS")
    parser.add_argument("logs", nargs="+", type=Path,
                        help="read-only Ghidra decompiler output logs")
    parser.add_argument("--provider", type=int, choices=range(5), default=0)
    args = parser.parse_args()

    try:
        osos = args.osos.read_bytes()
    except OSError as exc:
        parser.error(str(exc))
    if (len(osos) != STOCK_OSOS_SIZE or
            hashlib.sha256(osos).hexdigest() != STOCK_OSOS_SHA256):
        parser.error("OSOS size/SHA-256 does not match the original iPod backup")

    ranges = load_ranges(osos, args.provider)
    refs: dict[int, list[str]] = {}
    for log in args.logs:
        try:
            contents = log.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            parser.error(str(exc))
        for match in GLOBAL_NAME.finditer(contents):
            refs.setdefault(int(match.group(1), 16), []).append(log.name)

    for address, sources in sorted(refs.items()):
        source_offset = resolve(address, ranges)
        if (source_offset is None or
                resolve(address + 3, ranges) != source_offset + 3):
            print(f"IRAM 0x{address:08x}: outside provider-{args.provider} copied ranges "
                  f"({', '.join(sorted(set(sources)))})")
            continue
        value = read_word(osos, source_offset)
        print(f"IRAM 0x{address:08x} -> OSOS+0x{source_offset:06x} = 0x{value:08x} "
              f"({', '.join(sorted(set(sources)))})")
    print("Static literal map only; values may be pointers, constants, or function tables.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
