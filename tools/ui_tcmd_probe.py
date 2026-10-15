#!/usr/bin/env python3
"""Read-only dump of the stock command table used by RetailOS menu rows."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

from ui_resource_probe import inventory


def commands(data: bytes, start: int, size: int):
    end = start + size
    if end > len(data) or size < 16:
        raise ValueError("command resource outside component")
    unknown_size, marker, header_words = struct.unpack_from("<IHH", data, start)
    if marker != 0:
        raise ValueError(f"unsupported command table marker {marker}")
    q = start + 8 + header_words * 4
    if q + 4 > end:
        raise ValueError("header outside command table")
    count, nwords = struct.unpack_from("<HH", data, q)
    q += 4 + nwords * 2
    if nwords & 1:
        q += 2
    if count > 10000 or q + (count + 1) * 4 > end:
        raise ValueError("offset array outside command table")
    offsets = struct.unpack_from(f"<{count + 1}I", data, q)
    base = q + (count + 1) * 4
    print(f"table offset=0x{start:x} size={size} unknown_size={unknown_size} header_words={header_words} entries={count}")
    for index in range(count):
        pos = base + offsets[index]
        stop = base + offsets[index + 1]
        if pos + 10 > stop or stop > end:
            continue
        ident, z0, z1, nsubs, sublen = struct.unpack_from("<hHHHH", data, pos)
        yield index, ident, pos, stop, z0, z1, nsubs, sublen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", type=Path)
    parser.add_argument("--id", type=int, action="append", help="show only selected command IDs")
    parser.add_argument("--all", action="store_true", help="show every command")
    args = parser.parse_args()
    data = args.component.read_bytes()
    resource = [r for _, _, resources in inventory(data) for r in resources if r.section_type == b"dmCT"]
    if len(resource) != 1:
        parser.error(f"expected one TCmd resource, found {len(resource)}")
    selected = set(args.id or [])
    for index, ident, pos, stop, z0, z1, nsubs, sublen in commands(data, resource[0].data_offset, resource[0].size):
        if args.all or ident in selected:
            print(f"[{index:4}] id={ident:6} 0x{pos:08x}..0x{stop:08x} z0={z0} z1={z1} subs={nsubs} bytes={sublen} "+data[pos:stop].hex(" "))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
