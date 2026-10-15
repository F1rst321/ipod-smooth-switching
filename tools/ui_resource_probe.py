#!/usr/bin/env python3
"""Read-only inventory of RetailOS resource blocks and menu records.

The container layout follows the GPL iPodWizard firmware.h/firmware.cpp source.
This tool intentionally has no write or repack mode.
"""
from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


KNOWN_TYPES = {b" rtS", b"paMB", b"uneM", b"epyT", b"weiV", b"dmCT", b"enoN", b"mTDL", b"stiB"}
MENU_STRUCT = struct.Struct("<IIIIhHhHHHIhHI")


@dataclass(frozen=True)
class Resource:
    block: int
    section_type: bytes
    id: int
    data_offset: int
    size: int


def inventory(data: bytes):
    """Yield plausible resource block offsets and their table entries.

    Validate every referenced table and payload bound before reporting a hit.
    """
    n = len(data)
    for block in range(0, n - 28, 4):
        magic, length, count = struct.unpack_from("<III", data, block)
        if magic != 3 or not 0 < length < 0x10000 or not 0 < count < 50:
            continue
        section_table = block + 12
        if section_table + count * 16 > n or data[section_table:section_table + 4] not in KNOWN_TYPES:
            continue
        sections = []
        ok = True
        for index in range(count):
            stype, items, flag, start = struct.unpack_from("<4sIII", data, section_table + index * 16)
            if stype not in KNOWN_TYPES or items > 20000 or flag > 1:
                ok = False
                break
            pos = block + start
            if pos < section_table + count * 16 or pos + items * 12 > n:
                ok = False
                break
            sections.append((stype, items, pos))
        if not ok or not sections:
            continue
        payload_base = section_table + count * 16 + sum(x[1] for x in sections) * 12
        if payload_base > n:
            continue
        resources = []
        for stype, items, pos in sections:
            for index in range(items):
                ident, _unknown, offset, size = struct.unpack_from("<hHII", data, pos + index * 12)
                payload = payload_base + offset
                if payload < payload_base or payload + size > n:
                    ok = False
                    break
                resources.append(Resource(block, stype, ident, payload, size))
            if not ok:
                break
        if ok:
            yield block, sections, resources


def decode_menu(data: bytes, resource: Resource):
    begin, end = resource.data_offset, resource.data_offset + resource.size
    if begin + 4 > end:
        raise ValueError("truncated menu count")
    count = struct.unpack_from("<I", data, begin)[0]
    if count > 1000:
        raise ValueError(f"implausible menu count {count}")
    pos = begin + 4
    rows = []
    for _ in range(count):
        if pos + 4 > end:
            raise ValueError("truncated menu row")
        row_size = struct.unpack_from("<I", data, pos)[0]
        if row_size < 36 or pos + 4 + row_size > end:
            raise ValueError(f"invalid row size {row_size} at 0x{pos:x}")
        if pos + MENU_STRUCT.size > end:
            raise ValueError("truncated menu row fields")
        unpacked = MENU_STRUCT.unpack_from(data, pos)
        rows.append((pos, unpacked))
        pos += row_size + 4
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", type=Path, help="extracted OSOS or RSRC binary")
    parser.add_argument("--menu", type=int, help="print fields for this menu ID")
    parser.add_argument("--list-menus", action="store_true", help="list all menu IDs")
    parser.add_argument("--menu-text", action="store_true", help="show language strings for a selected menu")
    parser.add_argument("--language-block", type=lambda value: int(value, 0),
                        help="limit --menu-text to one OSOS resource block (hex accepted)")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    data = args.component.read_bytes()
    blocks = list(inventory(data))
    print(f"{args.component}: {len(data):,} bytes, {len(blocks)} resource blocks")
    if args.menu is not None and args.menu_text:
        menus = [resource for _, _, resources in blocks for resource in resources
                 if resource.section_type == b"uneM" and resource.id == args.menu]
        if len(menus) == 1:
            ids = [row[1][-3] for row in decode_menu(data, menus[0])]
            print("Menu label resource IDs:", ids)
            for block, _, resources in blocks:
                if args.language_block is not None and block != args.language_block:
                    continue
                labels = {resource.id: data[resource.data_offset:resource.data_offset + resource.size]
                          for resource in resources if resource.section_type == b" rtS" and resource.id in ids}
                if labels:
                    rendered = [labels.get(ident, b"").split(b"\x00", 1)[0].decode("utf-8", errors="replace") for ident in ids]
                    print(f"language block 0x{block:08x}: " + " | ".join(rendered))
    for block, sections, resources in blocks:
        descriptions = ", ".join(f"{stype[::-1].decode('ascii').strip()}:{items}" for stype, items, _ in sections)
        print(f"block 0x{block:08x}: {descriptions}")
        for resource in resources:
            if resource.section_type != b"uneM":
                continue
            if args.list_menus or (args.menu is not None and resource.id == args.menu):
                print(f"  menu ID {resource.id} at 0x{resource.data_offset:08x}, {resource.size} bytes")
            if args.menu is not None and resource.id == args.menu:
                try:
                    for pos, row in decode_menu(data, resource):
                        names = ("size", "z1", "z2", "cmd", "submenu", "z3", "text", "z4", "z5", "text3", "z6", "text2", "z7", "type")
                        print(f"    0x{pos:08x}: " + " ".join(f"{name}={value}" for name, value in zip(names, row)))
                except ValueError as exc:
                    print(f"    decode error: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
