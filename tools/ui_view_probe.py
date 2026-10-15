#!/usr/bin/env python3
"""Inspect stock RetailOS View resource hierarchy without changing firmware."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

from ui_resource_probe import inventory


def elements(data: bytes, start: int, size: int):
    end = start + size
    if start + 4 > end:
        raise ValueError("truncated view")
    count = struct.unpack_from("<I", data, start)[0]
    if count > 1024:
        raise ValueError("implausible element count")
    pos = start + 4
    for index in range(count):
        if pos + 16 > end:
            raise ValueError("truncated view element")
        elem_size = struct.unpack_from("<I", data, pos)[0]
        stop = pos + elem_size + 4
        if elem_size < 12 or stop > end:
            raise ValueError(f"invalid element size {elem_size} at 0x{pos:x}")
        typ = data[pos + 8:pos + 12]
        ident, unk = struct.unpack_from("<hH", data, pos + 12)
        yield index, pos, stop, elem_size, typ, ident, unk
        pos = stop


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", type=Path)
    parser.add_argument("--id", type=int, required=True)
    parser.add_argument("--raw", action="store_true")
    args = parser.parse_args()
    data = args.component.read_bytes()
    matches = [r for _, _, rs in inventory(data) for r in rs if r.section_type == b"weiV" and r.id == args.id]
    if len(matches) != 1:
        parser.error(f"expected one View ID {args.id}, found {len(matches)}")
    resource = matches[0]
    print(f"View {resource.id}: OSOS+0x{resource.data_offset:x}, {resource.size} bytes")
    for index, pos, stop, elem_size, typ, ident, unk in elements(data, resource.data_offset, resource.size):
        label = typ[::-1].decode("ascii", errors="replace")
        print(f"  [{index}] 0x{pos:x}..0x{stop:x} size={elem_size} type={label!r} id={ident} unknown={unk}")
        if args.raw:
            print("    " + data[pos:stop].hex(" "))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
