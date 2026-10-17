#!/usr/bin/env python3
"""Map runtime IRAM code windows back to exact OSOS file offsets."""
from __future__ import annotations

import argparse
from pathlib import Path


def find_matches(data: bytes, needle: bytes, limit: int = 2) -> list[int]:
    """Find enough matches to distinguish a unique source from ambiguity."""
    matches: list[int] = []
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            return matches
        matches.append(offset)
        if len(matches) >= limit:
            return matches
        cursor = offset + 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("osos", type=Path, help="exact extracted OSOS binary")
    parser.add_argument("iram", type=Path, help="raw IRAM snapshot starting at --runtime-base")
    parser.add_argument("addresses", nargs="+", type=lambda value: int(value, 0),
                        help="runtime IRAM addresses, e.g. 0x4001da34")
    parser.add_argument("--runtime-base", type=lambda value: int(value, 0), default=0x40000000,
                        help="address represented by IRAM byte zero (default: 0x40000000)")
    parser.add_argument("--window", type=int, default=32,
                        help="number of exact bytes required for a match (default: 32)")
    args = parser.parse_args()
    if args.window < 8:
        parser.error("--window must be at least 8 bytes")
    try:
        osos = args.osos.read_bytes()
        iram = args.iram.read_bytes()
    except OSError as exc:
        parser.error(str(exc))

    failed = False
    for address in args.addresses:
        offset = address - args.runtime_base
        if offset < 0 or offset + args.window > len(iram):
            print(f"0x{address:08x}: outside captured IRAM; no result")
            failed = True
            continue
        window = iram[offset:offset + args.window]
        if not any(window):
            print(f"0x{address:08x}: captured IRAM is zero-filled; "
                  "no loaded routine to map")
            failed = True
            continue
        matches = find_matches(osos, window)
        if len(matches) == 1:
            print(f"0x{address:08x} -> OSOS+0x{matches[0]:x} ({args.window} bytes)")
        elif matches:
            joined = ", ".join(f"0x{match:x}" for match in matches)
            print(f"0x{address:08x}: at least two OSOS matches ({joined}); "
                  "source is ambiguous")
            failed = True
        else:
            print(f"0x{address:08x}: no exact {args.window}-byte OSOS match")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
