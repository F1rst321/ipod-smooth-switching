#!/usr/bin/env python3
"""List validated ELF32 VideoCore modules embedded in a firmware component.

This is a read-only structural inventory. It does not disassemble the target
ISA or claim that exported decoder entry points are used by the music player.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

ELF_HEADER = struct.Struct("<16sHHIIIIIHHHHHH")
SECTION_HEADER = struct.Struct("<IIIIIIIIII")
SYMBOL = struct.Struct("<IIIBBH")
ET_DYN = 3
EM_VIDEOCORE = 95
SHT_SYMTAB = 2
SHT_DYNSYM = 11
STB_GLOBAL = 1
STB_WEAK = 2
STT_FUNC = 2


def c_string(data: bytes, offset: int) -> str:
    if not 0 <= offset < len(data):
        return ""
    end = data.find(b"\0", offset)
    if end < 0:
        return ""
    return data[offset:end].decode("ascii", errors="replace")


def module_at(data: bytes, base: int) -> dict | None:
    if base + ELF_HEADER.size > len(data):
        return None
    values = ELF_HEADER.unpack_from(data, base)
    ident = values[0]
    if (ident[:4] != b"\x7fELF" or ident[4:7] != b"\x01\x01\x01"
            or values[1] != ET_DYN or values[2] != EM_VIDEOCORE):
        return None
    shoff, shentsize, shnum, shstrndx = values[6], values[11], values[12], values[13]
    if shentsize != SECTION_HEADER.size or not 1 <= shnum <= 4096 or shstrndx >= shnum:
        return None
    table_end = base + shoff + shentsize * shnum
    if shoff < ELF_HEADER.size or table_end > len(data):
        return None
    sections = [SECTION_HEADER.unpack_from(data, base + shoff + i * shentsize)
                for i in range(shnum)]
    if any(section[4] + section[5] > len(data) - base for section in sections if section[1] != 8):
        return None
    names_section = sections[shstrndx]
    names_start = base + names_section[4]
    names = data[names_start:names_start + names_section[5]]
    if not names or names[-1] != 0:
        return None
    section_names = [c_string(names, section[0]) for section in sections]
    if not section_names[0] == "":
        return None

    exports: set[str] = set()
    for section in sections:
        if section[1] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if section[9] != SYMBOL.size or section[5] % SYMBOL.size or section[6] >= shnum:
            continue
        string_section = sections[section[6]]
        strings_start = base + string_section[4]
        strings = data[strings_start:strings_start + string_section[5]]
        if len(strings) != string_section[5]:
            continue
        for index in range(section[5] // SYMBOL.size):
            name_offset, _value, _size, info, _other, shndx = SYMBOL.unpack_from(
                data, base + section[4] + index * SYMBOL.size
            )
            name = c_string(strings, name_offset)
            if name and shndx and (info >> 4) in (STB_GLOBAL, STB_WEAK) and (info & 0x0f) == STT_FUNC:
                exports.add(name)

    end = max([table_end] + [base + section[4] + section[5]
                             for section in sections if section[1] != 8])
    return {"offset": base, "end": end, "sections": shnum,
            "exports": sorted(exports)}


def scan(data: bytes):
    found = []
    offset = 0
    while True:
        offset = data.find(b"\x7fELF", offset)
        if offset < 0:
            break
        module = module_at(data, offset)
        if module is not None:
            found.append(module)
        offset += 4
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", type=Path, help="extracted RSRC or raw firmware image")
    parser.add_argument("--export", action="append", default=[],
                        help="show exported function names containing this substring (repeatable)")
    args = parser.parse_args()
    data = args.component.read_bytes()
    modules = scan(data)
    print(f"{args.component}: {len(data):,} bytes; {len(modules)} validated VideoCore ELF module(s)")
    for module in modules:
        exports = module["exports"]
        if args.export:
            filters = [term.casefold() for term in args.export]
            exports = [name for name in exports if any(term in name.casefold() for term in filters)]
        print(f"  0x{module['offset']:08x}..0x{module['end']:08x} "
              f"({module['end'] - module['offset']:,} bytes), {module['sections']} sections")
        for name in exports:
            print(f"    {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
