#!/usr/bin/env python3
"""Read-only comparison of this iPod's firmware partition with a local image.

The device is opened with GENERIC_READ only. The disk number and mounted FAT32
volume are cross-checked before any firmware bytes are read. No file is made.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from ctypes import wintypes

from backup_ipod_firmware import BackupError, open_disk, parse_mbr, read_at
from build_partition_image import read_exact_backup, verify_candidate

EXPECTED_DISK_SIZE = 30_005_821_440
EXPECTED_FIRMWARE_SIZE = 98_574_336
EXPECTED_FIRMWARE_OFFSET = 129_024
CHUNK_SIZE = 1024 * 1024


def powershell_json(command: str) -> dict:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        check=True, capture_output=True, text=True,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("Windows returned an unexpected object")
    return value


def windows_disk_info(number: int, letter: str) -> tuple[dict, dict]:
    # Both interpolated values have already been constrained to digits/one letter.
    disk = powershell_json(
        f"Get-Disk -Number {number} | "
        "Select-Object Number,FriendlyName,Size,BusType,PartitionStyle,LogicalSectorSize | "
        "ConvertTo-Json -Compress"
    )
    data = powershell_json(
        f"Get-Partition -DriveLetter {letter} | "
        "Select-Object DiskNumber,Offset,Size,DriveLetter | ConvertTo-Json -Compress"
    )
    if (
        disk.get("Number") != number
        or disk.get("FriendlyName") != "Apple iPod"
        or disk.get("BusType") != "USB"
        or disk.get("PartitionStyle") != "MBR"
        or disk.get("Size") != EXPECTED_DISK_SIZE
        or disk.get("LogicalSectorSize") != 2048
    ):
        raise ValueError("selected disk does not match the recorded Apple iPod geometry")
    if data.get("DiskNumber") != number or data.get("DriveLetter") != letter:
        raise ValueError("mounted data drive is not on the selected disk")
    return disk, data


def firmware_layout(handle: int, logical_sector: int, data: dict) -> tuple[int, int]:
    mbr = read_at(handle, 0, logical_sector, logical_sector)
    partitions = parse_mbr(mbr)
    firmware = next((p for p in partitions if p["number"] == 1), None)
    music = next((p for p in partitions if p["number"] == 2), None)
    if (firmware is None or firmware["type"] != 0 or music is None
            or music["type"] not in (0x0B, 0x0C)):
        raise ValueError("selected disk does not have the expected iPod MBR layout")
    matching_units = [
        unit for unit in (512, logical_sector)
        if music["start_sector"] * unit == data["Offset"]
        and music["sector_count"] * unit == data["Size"]
    ]
    if len(matching_units) != 1:
        raise ValueError("MBR data partition does not uniquely match the mounted drive")
    unit = matching_units[0]
    offset = firmware["start_sector"] * unit
    size = firmware["sector_count"] * unit
    if (offset, size) != (EXPECTED_FIRMWARE_OFFSET, EXPECTED_FIRMWARE_SIZE):
        raise ValueError("firmware partition differs from the recorded original layout")
    if offset + size != data["Offset"]:
        raise ValueError("firmware and data partition boundaries are not contiguous")
    return offset, size


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disk-number", type=int, required=True,
                        help="current Windows disk number, checked against mounted data drive")
    parser.add_argument("--data-drive", required=True,
                        help="current mounted FAT32 drive letter, e.g. E")
    parser.add_argument("--backup", type=Path, required=True,
                        help="pinned, original firmware-partition backup")
    parser.add_argument("--expected-image", type=Path, required=True,
                        help="original backup or structurally verified candidate image")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("raw-device comparison currently supports Windows only")
    if args.disk_number < 0:
        parser.error("--disk-number must be nonnegative")
    letter = args.data_drive.rstrip(":\\/").upper()
    if len(letter) != 1 or not ("A" <= letter <= "Z"):
        parser.error("--data-drive must be one drive letter")

    original, entries = read_exact_backup(args.backup)
    if not args.expected_image.is_file():
        parser.error(f"expected image is not a regular file: {args.expected_image}")
    expected = args.expected_image.read_bytes()
    if expected != original:
        verify_candidate(original, expected, entries)
    disk, data = windows_disk_info(args.disk_number, letter)
    handle = open_disk(args.disk_number)
    close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    try:
        offset, size = firmware_layout(handle, int(disk["LogicalSectorSize"]), data)
        digest = hashlib.sha256()
        first_difference = None
        for start in range(0, size, CHUNK_SIZE):
            amount = min(CHUNK_SIZE, size - start)
            block = read_at(handle, offset + start, amount, int(disk["LogicalSectorSize"]))
            digest.update(block)
            sample = expected[start:start + amount]
            if first_difference is None and block != sample:
                first_difference = start + next(
                    index for index, pair in enumerate(zip(block, sample))
                    if pair[0] != pair[1]
                )
    finally:
        close_handle(handle)

    print(f"Read-only firmware comparison on Apple iPod disk {args.disk_number}, drive {letter}:")
    print(f"Partition: offset {offset:,}, size {size:,} bytes")
    print(f"Device SHA-256: {digest.hexdigest()}")
    print(f"Expected SHA-256: {hashlib.sha256(expected).hexdigest()}")
    if first_difference is not None:
        raise ValueError(f"device differs at partition offset 0x{first_difference:x}")
    print("Byte-for-byte match. No device or local file write was made.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BackupError, OSError, ValueError, subprocess.SubprocessError,
            json.JSONDecodeError) as exc:
        print(f"Verification failed: {exc}", file=sys.stderr)
        sys.exit(2)
