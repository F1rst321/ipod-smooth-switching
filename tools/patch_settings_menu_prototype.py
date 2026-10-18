#!/usr/bin/env python3
"""Build an offline Settings-menu resource prototype for RetailOS 1.3.

This prototype adds a 19th Settings row and language labels while keeping the
OSOS component size fixed. It reuses the stock Volume Limit view, but does not
add the property handlers or audio hooks required for a working crossfade.
The output is research material only and is never written to a physical disk.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from ui_resource_probe import decode_menu, inventory


EXPECTED_OSOS_SIZE = 7_561_216
EXPECTED_OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"
RESOURCE_WINDOW_START = 0x712000
RESOURCE_WINDOW_END = 0x7161A4
SETTINGS_MENU_ID = 24598
VOLUME_LIMIT_VIEW_ID = 17538
VOLUME_LIMIT_MENU_ID = 24600
CROSSFADE_STRING_ID = 30000
CROSSFADE_VALUE_STRING_BASE = 30001
CROSSFADE_PROPERTY_KEY = 0x6089
RUSSIAN_BLOCK = 0x30FCF4
MENU_STRUCT = struct.Struct("<IIIIhHhHHHIhHI")
RESOURCE_RECORD = struct.Struct("<hHII")
SECTION_HEADER = struct.Struct("<4sIII")
BLOCK_HEADER = struct.Struct("<III")


@dataclass
class Section:
    """One type-specific resource table within an OSOS resource block."""

    kind: bytes
    count: int
    flags: int
    start: int
    records: list[tuple[int, int, int, int]]


@dataclass
class ResourceBlock:
    """A parsed resource block plus the original payload base."""

    start: int
    length: int
    sections: list[Section]
    payload_base: int


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_resource_block(data: bytes, start: int) -> ResourceBlock:
    """Parse one block with strict table and payload bounds checks."""
    magic, length, section_count = BLOCK_HEADER.unpack_from(data, start)
    if magic != 3 or not 0 < section_count < 50:
        raise ValueError(f"invalid resource block header at 0x{start:x}")
    if start + length > len(data):
        raise ValueError(f"resource table exceeds OSOS at 0x{start:x}")

    sections: list[Section] = []
    record_count = 0
    section_table = start + BLOCK_HEADER.size
    for index in range(section_count):
        kind, count, flags, offset = SECTION_HEADER.unpack_from(
            data, section_table + index * SECTION_HEADER.size
        )
        records: list[tuple[int, int, int, int]] = []
        for record_index in range(count):
            records.append(RESOURCE_RECORD.unpack_from(
                data, start + offset + record_index * RESOURCE_RECORD.size
            ))
        sections.append(Section(kind, count, flags, offset, records))
        record_count += count

    expected_length = (
        BLOCK_HEADER.size
        + section_count * SECTION_HEADER.size
        + record_count * RESOURCE_RECORD.size
    )
    if length != expected_length:
        raise ValueError(
            f"resource table length mismatch at 0x{start:x}: "
            f"{length} != {expected_length}"
        )
    payload_base = start + length
    for section in sections:
        for resource_id, _unknown, offset, size in section.records:
            if payload_base + offset + size > len(data):
                raise ValueError(
                    f"resource {resource_id} exceeds OSOS in block 0x{start:x}"
                )
    return ResourceBlock(start, length, sections, payload_base)


def find_block(blocks: list[ResourceBlock], start: int) -> ResourceBlock:
    matches = [block for block in blocks if block.start == start]
    if len(matches) != 1:
        raise ValueError(f"expected one resource block at 0x{start:x}")
    return matches[0]


def find_resource(
    block: ResourceBlock, section_type: bytes, resource_id: int
) -> tuple[Section, int, tuple[int, int, int, int]]:
    matches = [
        (section, index, record)
        for section in block.sections
        if section.kind == section_type
        for index, record in enumerate(section.records)
        if record[0] == resource_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected one {section_type!r} resource {resource_id} "
            f"in block 0x{block.start:x}; found {len(matches)}"
        )
    return matches[0]


def first_resource_overlapped_by_growth(
    block: ResourceBlock,
    growth_bytes: int,
) -> list[tuple[Section, int, tuple[int, int, int, int]]]:
    """Return payloads overlapped by the expanded resource-record table."""
    new_payload_base = block.payload_base + growth_bytes
    overlapping = []
    for section in block.sections:
        for index, record in enumerate(section.records):
            _resource_id, _unknown, offset, size = record
            old_start = block.payload_base + offset
            if size and old_start < new_payload_base:
                overlapping.append((section, index, record))
    return overlapping


class WindowAllocator:
    """Allocate immutable relocated resource bytes inside the zero window."""

    def __init__(self, original: bytes):
        if any(original[RESOURCE_WINDOW_START:RESOURCE_WINDOW_END]):
            raise ValueError("audited OSOS resource window is not entirely zero")
        self.cursor = RESOURCE_WINDOW_START
        self.end = RESOURCE_WINDOW_END
        self.items: list[dict[str, object]] = []
        self.data = bytearray(original)

    def add(self, name: str, blob: bytes, alignment: int = 4) -> int:
        destination = (self.cursor + alignment - 1) & ~(alignment - 1)
        finish = destination + len(blob)
        if finish > self.end:
            raise ValueError(
                f"resource window full while placing {name}: "
                f"need through 0x{finish:x}, limit 0x{self.end:x}"
            )
        self.data[destination:finish] = blob
        self.cursor = finish
        self.items.append({
            "name": name,
            "offset": destination,
            "size": len(blob),
            "sha256": sha256(blob),
        })
        return destination


def rebuild_block(
    block: ResourceBlock,
    allocator: WindowAllocator,
    relocations: dict[tuple[bytes, int], int],
    added_strings: dict[int, list[tuple[int, bytes]]],
) -> bytes:
    """Rebuild a block table, preserving existing payload addresses."""
    section_count = len(block.sections)
    new_payload_base = block.payload_base + len(added_strings[block.start]) * RESOURCE_RECORD.size
    rebuilt_sections: list[tuple[bytes, int, int, list[tuple[int, int, int, int]]]] = []
    records_total = 0

    for section in block.sections:
        records = []
        for resource_id, unknown, old_offset, size in section.records:
            key = (section.kind, resource_id)
            old_address = block.payload_base + old_offset
            if key in relocations:
                address = relocations[key]
            elif old_address < new_payload_base:
                raise ValueError(
                    f"resource {resource_id} in block 0x{block.start:x} "
                    "was not relocated before table growth"
                )
            else:
                address = old_address
            new_offset = address - new_payload_base
            if new_offset < 0:
                raise ValueError("relocated resource precedes its new payload base")
            records.append((resource_id, unknown, new_offset, size))

        if section.kind == b" rtS":
            for string_id, new_blob in added_strings[block.start]:
                address = allocator.add(
                    f"string-{string_id}-block-{block.start:08x}",
                    new_blob,
                    alignment=1,
                )
                records.append((string_id, 0, address - new_payload_base, len(new_blob)))

        rebuilt_sections.append((section.kind, section.flags, section.start, records))
        records_total += len(records)

    new_length = (
        BLOCK_HEADER.size
        + section_count * SECTION_HEADER.size
        + records_total * RESOURCE_RECORD.size
    )
    output = bytearray(new_length)
    BLOCK_HEADER.pack_into(output, 0, 3, new_length, section_count)
    records_cursor = BLOCK_HEADER.size + section_count * SECTION_HEADER.size
    for index, (kind, flags, _old_start, records) in enumerate(rebuilt_sections):
        SECTION_HEADER.pack_into(
            output,
            BLOCK_HEADER.size + index * SECTION_HEADER.size,
            kind,
            len(records),
            flags,
            records_cursor,
        )
        for record in records:
            RESOURCE_RECORD.pack_into(output, records_cursor, *record)
            records_cursor += RESOURCE_RECORD.size
    return bytes(output)


def add_crossfade_menu_row(menu_bytes: bytes) -> bytes:
    """Insert a row immediately after Volume Limit, reusing its native view."""
    count = struct.unpack_from("<I", menu_bytes, 0)[0]
    if count != 18:
        raise ValueError(f"expected 18 stock Settings rows, found {count}")
    rows = decode_menu(menu_bytes, type("R", (), {
        "data_offset": 0,
        "size": len(menu_bytes),
    })())
    volume_index = next(
        (index for index, (_, values) in enumerate(rows)
         if values[3] == VOLUME_LIMIT_VIEW_ID and values[11] == 24656),
        None,
    )
    if volume_index is None:
        raise ValueError("could not locate the stock Volume Limit row")
    row = list(rows[volume_index][1])
    row[8] = CROSSFADE_STRING_ID
    row[10] = (row[10] & 0xFFFF0000) | CROSSFADE_PROPERTY_KEY
    row[11] = CROSSFADE_STRING_ID
    encoded_row = MENU_STRUCT.pack(*row)
    insertion = rows[volume_index][0] + MENU_STRUCT.size
    result = bytearray(menu_bytes)
    result[insertion:insertion] = encoded_row
    struct.pack_into("<I", result, 0, count + 1)
    return bytes(result)


def build_prototype(original: bytes) -> tuple[bytes, dict[str, object]]:
    if len(original) != EXPECTED_OSOS_SIZE or sha256(original) != EXPECTED_OSOS_SHA256:
        raise ValueError("input OSOS size/SHA-256 does not match the audited stock image")
    blocks = [parse_resource_block(original, start) for start, _, _ in inventory(original)]
    if len(blocks) != 25:
        raise ValueError(f"expected 25 resource blocks, found {len(blocks)}")

    allocator = WindowAllocator(original)
    relocation_addresses: dict[tuple[int, bytes, int], int] = {}
    old_resource_bytes: dict[tuple[int, bytes, int], bytes] = {}
    add_strings: dict[int, list[tuple[int, bytes]]] = {}

    # Give every installed locale a valid label; Russian keeps the requested
    # wording while other locales receive a short English label for now.
    for block in blocks:
        if any(section.kind == b" rtS" for section in block.sections):
            strings = [record[0] for section in block.sections if section.kind == b" rtS"
                       for record in section.records]
            new_ids = [CROSSFADE_STRING_ID] + [
                CROSSFADE_VALUE_STRING_BASE + index for index in range(8)
            ]
            collisions = set(strings).intersection(new_ids)
            if collisions:
                raise ValueError(f"crossfade string IDs already exist: {sorted(collisions)}")
            russian = block.start == RUSSIAN_BLOCK
            label = "Плавный переход" if russian else "Crossfade"
            suffix = " сек" if russian else " s"
            add_strings[block.start] = [
                (CROSSFADE_STRING_ID, label.encode("utf-8") + b"\0")
            ]
            add_strings[block.start].extend(
                (
                    CROSSFADE_VALUE_STRING_BASE + index,
                    f"{index + 3}{suffix}".encode("utf-8") + b"\0",
                )
                for index in range(8)
            )

    # Expanding each table by one 12-byte entry overlaps the first data object.
    # Move every such object into the audited zero window and adjust only its
    # resource record; all other resources keep their original file addresses.
    for block in blocks:
        if block.start not in add_strings:
            continue
        growth_bytes = len(add_strings[block.start]) * RESOURCE_RECORD.size
        for section, _index, record in first_resource_overlapped_by_growth(
            block, growth_bytes
        ):
            resource_id, _unknown, offset, size = record
            key = (block.start, section.kind, resource_id)
            address = block.payload_base + offset
            blob = original[address:address + size]
            destination = allocator.add(
                f"relocated-{section.kind[::-1].decode('ascii').strip()}-"
                f"{resource_id}-block-{block.start:08x}",
                blob,
            )
            relocation_addresses[key] = destination
            old_resource_bytes[key] = blob

    main_block = find_block(blocks, 0x331DA0)
    _, _, menu_record = find_resource(main_block, b"uneM", SETTINGS_MENU_ID)
    _, _, next_menu_record = find_resource(main_block, b"uneM", VOLUME_LIMIT_MENU_ID)
    menu_address = main_block.payload_base + menu_record[2]
    next_menu_address = main_block.payload_base + next_menu_record[2]
    menu_original = original[menu_address:menu_address + menu_record[3]]
    if menu_address + menu_record[3] != next_menu_address:
        raise ValueError("Settings menu is not contiguous with the adjacent stock menu")

    # The adjacent menu occupies the bytes where the new 40-byte row belongs.
    # Relocate it and leave the original range available for the expanded menu.
    moved_menu = original[next_menu_address:next_menu_address + next_menu_record[3]]
    moved_menu_address = allocator.add(f"relocated-menu-{VOLUME_LIMIT_MENU_ID}", moved_menu)
    relocation_addresses[(main_block.start, b"uneM", VOLUME_LIMIT_MENU_ID)] = moved_menu_address
    old_resource_bytes[(main_block.start, b"uneM", VOLUME_LIMIT_MENU_ID)] = moved_menu

    # Store all new localized strings in the same audited OSOS window.
    patched_blocks: dict[int, bytes] = {}
    for block in blocks:
        if block.start in add_strings:
            patched_blocks[block.start] = rebuild_block(
                block,
                allocator,
                {
                    (section_kind, resource_id): address
                    for (block_start, section_kind, resource_id), address
                    in relocation_addresses.items()
                    if block_start == block.start
                },
                add_strings,
            )
        else:
            patched_blocks[block.start] = original[
                block.start:block.start + block.length
            ]

    patched = bytearray(allocator.data)
    for block in blocks:
        table = patched_blocks[block.start]
        patched[block.start:block.start + len(table)] = table

    expanded_menu = add_crossfade_menu_row(menu_original)
    if len(expanded_menu) != menu_record[3] + MENU_STRUCT.size:
        raise ValueError("expanded menu size is not exactly one row larger")
    patched[menu_address:menu_address + len(expanded_menu)] = expanded_menu

    # Increase the menu resource size in the rebuilt main-block table.
    new_main = parse_resource_block(bytes(patched), main_block.start)
    menu_section, menu_index, updated_record = find_resource(
        new_main, b"uneM", SETTINGS_MENU_ID
    )
    menu_section.records[menu_index] = (
        updated_record[0], updated_record[1], updated_record[2], len(expanded_menu)
    )
    patched[main_block.start:main_block.start + new_main.length] = serialize_block(new_main)

    verify_prototype(original, bytes(patched), blocks, expanded_menu,
                     relocation_addresses, old_resource_bytes, add_strings)
    manifest: dict[str, object] = {
        "artifact_type": "offline_settings_ui_resource_prototype",
        "device_ready": False,
        "runtime_validated": False,
        "audio_path_connected": False,
        "base_osos_sha256": EXPECTED_OSOS_SHA256,
        "output_osos_sha256": sha256(bytes(patched)),
        "settings_menu_id": SETTINGS_MENU_ID,
        "stock_settings_rows": 18,
        "prototype_settings_rows": 19,
        "reused_view_id": VOLUME_LIMIT_VIEW_ID,
        "property_key": f"0x{CROSSFADE_PROPERTY_KEY:04x}",
        "string_resource_id": CROSSFADE_STRING_ID,
        "value_string_ids": [
            CROSSFADE_VALUE_STRING_BASE + index for index in range(8)
        ],
        "resource_window": {
            "start": RESOURCE_WINDOW_START,
            "end": RESOURCE_WINDOW_END,
            "used_end": allocator.cursor,
            "bytes_used": allocator.cursor - RESOURCE_WINDOW_START,
            "items": allocator.items,
        },
        "notes": [
            "The custom property getter/setter are not patched.",
            "The stock Volume Limit slider is reused as a UI prototype.",
            "No audio decoder, PCM mixer callback, or track handoff hook is installed.",
            "This artifact is not an installable firmware image.",
        ],
    }
    return bytes(patched), manifest


def serialize_block(block: ResourceBlock) -> bytes:
    """Serialize parsed section metadata and records at its current counts."""
    section_count = len(block.sections)
    record_count = sum(len(section.records) for section in block.sections)
    length = BLOCK_HEADER.size + section_count * SECTION_HEADER.size + record_count * RESOURCE_RECORD.size
    result = bytearray(length)
    BLOCK_HEADER.pack_into(result, 0, 3, length, section_count)
    cursor = BLOCK_HEADER.size + section_count * SECTION_HEADER.size
    for index, section in enumerate(block.sections):
        SECTION_HEADER.pack_into(
            result,
            BLOCK_HEADER.size + index * SECTION_HEADER.size,
            section.kind,
            len(section.records),
            section.flags,
            cursor,
        )
        for record in section.records:
            RESOURCE_RECORD.pack_into(result, cursor, *record)
            cursor += RESOURCE_RECORD.size
    return bytes(result)


def verify_prototype(
    original: bytes,
    patched: bytes,
    original_blocks: list[ResourceBlock],
    expanded_menu: bytes,
    relocations: dict[tuple[int, bytes, int], int],
    expected_relocated: dict[tuple[int, bytes, int], bytes],
    added_strings: dict[int, list[tuple[int, bytes]]],
) -> None:
    """Reparse the result and check menu, strings, and relocated resources."""
    if len(patched) != len(original):
        raise ValueError("prototype changed the OSOS component size")
    parsed = [parse_resource_block(patched, start) for start, _, _ in inventory(patched)]
    if [block.start for block in parsed] != [block.start for block in original_blocks]:
        raise ValueError("resource block discovery changed after the prototype patch")
    main = find_block(parsed, 0x331DA0)
    _, _, menu = find_resource(main, b"uneM", SETTINGS_MENU_ID)
    menu_data = patched[main.payload_base + menu[2]:main.payload_base + menu[2] + menu[3]]
    if menu_data != expanded_menu or menu[3] != len(expanded_menu):
        raise ValueError("expanded Settings menu failed byte-for-byte verification")
    rows = decode_menu(menu_data, type("R", (), {"data_offset": 0, "size": len(menu_data)})())
    if len(rows) != 19:
        raise ValueError(f"expected 19 Settings rows after patch, found {len(rows)}")
    added_row = rows[5][1]
    if (added_row[3] != VOLUME_LIMIT_VIEW_ID
            or added_row[10] & 0xFFFF != CROSSFADE_PROPERTY_KEY
            or added_row[11] != CROSSFADE_STRING_ID):
        raise ValueError("new Settings row does not point to the expected view/property/string")

    _, _, moved = find_resource(main, b"uneM", VOLUME_LIMIT_MENU_ID)
    moved_data = patched[main.payload_base + moved[2]:main.payload_base + moved[2] + moved[3]]
    if moved_data != expected_relocated[
        (main.start, b"uneM", VOLUME_LIMIT_MENU_ID)
    ]:
        raise ValueError("relocated adjacent menu failed byte-for-byte verification")

    for block in parsed:
        if block.start not in added_strings:
            continue
        for string_id, expected_string in added_strings[block.start]:
            section, _, record = find_resource(block, b" rtS", string_id)
            del section
            string = patched[
                block.payload_base + record[2]:
                block.payload_base + record[2] + record[3]
            ]
            if string != expected_string:
                raise ValueError(
                    f"localized string {string_id} failed verification "
                    f"in block 0x{block.start:x}"
                )

    for (block_start, section_type, resource_id), address in relocations.items():
        block = find_block(parsed, block_start)
        _, _, record = find_resource(block, section_type, resource_id)
        relocated_data = patched[block.payload_base + record[2]:block.payload_base + record[2] + record[3]]
        if relocated_data != expected_relocated[(block_start, section_type, resource_id)]:
            raise ValueError(
                f"relocated resource {resource_id} failed byte-for-byte verification"
            )
        if address < RESOURCE_WINDOW_START or address >= RESOURCE_WINDOW_END:
            raise ValueError("resource relocation escaped audited zero window")

    moved_keys = set(relocations)
    for old_block in original_blocks:
        new_block = find_block(parsed, old_block.start)
        for old_section in old_block.sections:
            new_section = next(
                section for section in new_block.sections
                if section.kind == old_section.kind
            )
            for record_index, old_record in enumerate(old_section.records):
                resource_id, _unknown, old_offset, size = old_record
                key = (old_block.start, old_section.kind, resource_id)
                if key in moved_keys or key == (
                    old_block.start, b"uneM", SETTINGS_MENU_ID
                ):
                    continue
                new_record = new_section.records[record_index]
                old_address = old_block.payload_base + old_offset
                new_address = new_block.payload_base + new_record[2]
                old_bytes = original[old_address:old_address + size]
                new_bytes = patched[new_address:new_address + new_record[3]]
                if new_record[3] != size or new_bytes != old_bytes:
                    raise ValueError(
                        f"unmodified resource {resource_id} changed in "
                        f"block 0x{old_block.start:x}"
                    )


def output_path(path: Path) -> Path:
    root = Path(__file__).resolve().parents[1]
    build = (root / "build").resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(build)
    except ValueError as exc:
        raise ValueError("output must stay under the project's ignored build/ directory") from exc
    if resolved.parent != build:
        raise ValueError("output must be directly inside build/")
    if resolved.exists() or resolved.with_suffix(resolved.suffix + ".json").exists():
        raise FileExistsError(f"refusing to overwrite existing output: {resolved}")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("osos", type=Path, help="exact extracted stock OSOS component")
    parser.add_argument("--output", type=Path, required=True,
                        help="new offline OSOS output directly under build/")
    args = parser.parse_args()
    try:
        target = output_path(args.output)
        original = args.osos.read_bytes()
        patched, manifest = build_prototype(original)
        with target.open("xb") as stream:
            stream.write(patched)
        manifest_path = target.with_suffix(target.suffix + ".json")
        with manifest_path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        if target.read_bytes() != patched:
            raise ValueError("written OSOS failed byte-for-byte verification")
        if json.loads(manifest_path.read_text(encoding="utf-8")) != manifest:
            raise ValueError("written manifest failed verification")
    except (OSError, ValueError, struct.error) as exc:
        parser.error(str(exc))
    print(f"Prototype OSOS: {target} ({len(patched):,} bytes)")
    print(f"SHA-256: {manifest['output_osos_sha256']}")
    window = manifest["resource_window"]
    print(f"Resource data placed in OSOS zero window: {window['bytes_used']:,}/16,804 bytes")
    print("Offline Settings UI prototype only; not an installable firmware image.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
