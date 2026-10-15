#!/usr/bin/env python3
"""List the images stored in an Apple iPod firmware partition or IPSW payload."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path
from zipfile import BadZipFile, ZipFile

IMAGE_TYPES = {
    b"soso": "OSOS",
    b"crsr": "RSRC",
    b"dpua": "AUPD",
    b"kbso": "OSBK",
    b"ebih": "HIBE",
}
DIRECTORY_MARKERS = {b"!ATA", b"DNAN"}
HEADER_MAGIC = b"]ih["


def parse_images(data: bytes, sector_size: int) -> tuple[int, list[dict[str, int | str | bool | None]]]:
    if len(data) < 0x10C or data[0x100:0x104] != HEADER_MAGIC:
        raise ValueError("missing iPod firmware header marker ]ih[")

    directory_pointer = struct.unpack_from("<I", data, 0x104)[0]
    version = struct.unpack_from("<H", data, 0x10A)[0]
    directory_offset = directory_pointer + 0x200
    if directory_offset >= len(data):
        raise ValueError(f"directory offset 0x{directory_offset:x} is outside the image")

    entries: list[dict[str, int | str | bool | None]] = []
    for index in range(16):
        offset = directory_offset + index * 40
        record = data[offset:offset + 40]
        if len(record) < 40 or record[:4] not in DIRECTORY_MARKERS:
            break
        image_type = record[4:8]
        ident, device_offset, length, address, entry_offset, checksum, image_version, load_address = (
            struct.unpack_from("<8I", record, 8)
        )
        entries.append({
            "type": IMAGE_TYPES.get(image_type, image_type.decode("ascii", errors="replace")),
            "id": ident,
            "device_offset": device_offset,
            "length": length,
            "address": address,
            "entry_offset": entry_offset,
            "checksum": checksum,
            "version": image_version,
            "load_address": load_address,
        })

    if not entries:
        raise ValueError(f"no image records found at directory offset 0x{directory_offset:x}")

    # Rockbox's ipodpatcher format handling treats multi-image v2 firmware
    # offsets as partition-relative; later formats start after the header sector.
    image_base = 0 if version == 2 and len(entries) > 1 else sector_size
    for entry in entries:
        image_start = image_base + int(entry["device_offset"])
        image_end = image_start + int(entry["length"])
        entry["image_start"] = image_start
        entry["range_valid"] = 0 <= image_start <= image_end <= len(data)
        if entry["range_valid"]:
            payload = data[image_start:image_end]
            entry["checksum_matches"] = (sum(payload) & 0xFFFFFFFF) == int(entry["checksum"])
        else:
            entry["checksum_matches"] = None
    return version, entries


def report(label: str, data: bytes, sector_size: int) -> None:
    version, entries = parse_images(data, sector_size)
    print(f"{label}: {len(data):,} bytes, firmware format {version}")
    for entry in entries:
        if not entry["range_valid"]:
            bounds = "OUT OF IMAGE"
        else:
            bounds = f"0x{int(entry['image_start']):08x}..0x{int(entry['image_start']) + int(entry['length']):08x}"
        if not entry["checksum"]:
            checksum = "no sum field"
        elif entry["checksum_matches"]:
            checksum = "byte-sum matches field"
        else:
            checksum = "byte-sum differs from field"
        print(
            f"  {entry['type']:<4} offset={bounds} length={int(entry['length']):,} "
            f"load=0x{int(entry['address']):08x} entry=0x{int(entry['entry_offset']):08x} "
            f"stored-sum={checksum}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True, help="raw firmware-partition backup")
    parser.add_argument("--ipsw", type=Path, help="optional Apple IPSW to inspect alongside the backup")
    parser.add_argument("--sector-size", type=int, default=2048, help="device logical sector size (default: 2048)")
    args = parser.parse_args()
    if args.sector_size <= 0:
        parser.error("--sector-size must be positive")

    try:
        report(str(args.image), args.image.read_bytes(), args.sector_size)
        if args.ipsw:
            with ZipFile(args.ipsw) as ipsw:
                payload_names = [name for name in ipsw.namelist() if name.startswith("Firmware-")]
                if len(payload_names) != 1:
                    parser.error(f"Expected exactly one Firmware-* payload in IPSW, found {len(payload_names)}")
                report(f"{args.ipsw}::{payload_names[0]}", ipsw.read(payload_names[0]), args.sector_size)
    except (OSError, BadZipFile, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
