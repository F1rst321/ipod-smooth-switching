#!/usr/bin/env python3
"""Read the iPod's firmware partition to a local backup on Windows."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from ctypes import wintypes

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_BEGIN = 0
SECTOR_SIZE = 512
CHUNK_SIZE = 1024 * 1024
FAT32_TYPES = {0x0B, 0x0C}


class BackupError(RuntimeError):
    pass


def win_error(action: str) -> BackupError:
    code = ctypes.get_last_error()
    return BackupError(f"{action}: {ctypes.WinError(code)}")


def open_disk(disk_number: int) -> wintypes.HANDLE:
    if os.name != "nt":
        raise BackupError("This raw-disk reader currently supports Windows only")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        rf"\\.\PhysicalDrive{disk_number}", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise win_error(f"Cannot open PhysicalDrive{disk_number} read-only")
    return handle


def read_at(handle: wintypes.HANDLE, offset: int, count: int) -> bytes:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_pointer = kernel32.SetFilePointerEx
    set_pointer.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                            ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
    set_pointer.restype = wintypes.BOOL
    if not set_pointer(handle, offset, None, FILE_BEGIN):
        raise win_error(f"Cannot seek to byte offset {offset}")

    read_file = kernel32.ReadFile
    read_file.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                          ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    read_file.restype = wintypes.BOOL
    buffer = ctypes.create_string_buffer(count)
    actual = wintypes.DWORD()
    if not read_file(handle, buffer, count, ctypes.byref(actual), None):
        raise win_error(f"Cannot read {count} bytes at offset {offset}")
    if actual.value != count:
        raise BackupError(f"Short read at offset {offset}: got {actual.value}, expected {count}")
    return buffer.raw


def parse_mbr(sector: bytes) -> list[dict[str, int]]:
    if len(sector) != SECTOR_SIZE or sector[510:512] != b"\x55\xaa":
        raise BackupError("Disk has no valid MBR signature; refusing to guess the layout")
    result = []
    for index in range(4):
        entry = sector[446 + index * 16: 446 + (index + 1) * 16]
        part_type = entry[4]
        start_sector = int.from_bytes(entry[8:12], "little")
        sector_count = int.from_bytes(entry[12:16], "little")
        if part_type or start_sector or sector_count:
            result.append({
                "number": index + 1,
                "type": part_type,
                "start_sector": start_sector,
                "sector_count": sector_count,
            })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disk-number", type=int, required=True,
                        help="Windows disk number, checked against the mounted data partition")
    parser.add_argument("--data-drive", required=True,
                        help="mounted iPod data drive letter, for layout cross-check (for example E)")
    parser.add_argument("--output", type=Path, required=True,
                        help="new output .img path; existing files are never overwritten")
    args = parser.parse_args()

    drive = args.data_drive.rstrip(":\\/").upper()
    if len(drive) != 1 or not drive.isalpha():
        parser.error("--data-drive must be a single Windows drive letter")
    output = args.output.resolve()
    manifest_path = output.with_suffix(output.suffix + ".json")
    if output.exists() or manifest_path.exists():
        raise BackupError(f"Refusing to overwrite existing backup or manifest: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    handle = open_disk(args.disk_number)
    close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    partial_created = False
    try:
        mbr = read_at(handle, 0, SECTOR_SIZE)
        partitions = parse_mbr(mbr)
        if len(partitions) < 2:
            raise BackupError("Expected an iPod firmware partition and a FAT32 data partition")
        firmware = next((p for p in partitions if p["number"] == 1), None)
        data = next((p for p in partitions if p["number"] == 2), None)
        if not firmware or firmware["type"] != 0 or firmware["sector_count"] == 0:
            raise BackupError("MBR entry 1 does not match the expected iPod firmware partition layout")
        if not data or data["type"] not in FAT32_TYPES:
            raise BackupError("MBR entry 2 is not a FAT32 iPod data partition; refusing to read")

        volume_offset = firmware["start_sector"] * SECTOR_SIZE
        volume_size = firmware["sector_count"] * SECTOR_SIZE
        data_offset = data["start_sector"] * SECTOR_SIZE
        data_size = data["sector_count"] * SECTOR_SIZE
        try:
            import subprocess
            ps = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"(Get-Partition -DriveLetter {drive}).Offset; (Get-Partition -DriveLetter {drive}).Size"],
                check=True, capture_output=True, text=True,
            )
            values = [int(line.strip()) for line in ps.stdout.splitlines() if line.strip()]
        except Exception as exc:
            raise BackupError(f"Could not cross-check drive {drive}: against Windows partition data: {exc}") from exc
        if len(values) < 2 or values[0] != data_offset or values[1] != data_size:
            raise BackupError(
                f"Drive {drive}: does not match PhysicalDrive{args.disk_number}'s FAT32 partition; refusing to read"
            )

        print(f"Verified iPod-style MBR on PhysicalDrive{args.disk_number}")
        print(f"Firmware partition: offset {volume_offset:,}, size {volume_size:,} bytes")
        print(f"Data partition: {drive}: offset {data_offset:,}, size {data_size:,} bytes (cross-check OK)")
        print("Reading firmware partition only; opening the device read-only.")

        digest = hashlib.sha256()
        partial_created = True
        with output.open("xb") as destination:
            remaining = volume_size
            offset = volume_offset
            while remaining:
                amount = min(CHUNK_SIZE, remaining)
                block = read_at(handle, offset, amount)
                destination.write(block)
                digest.update(block)
                offset += amount
                remaining -= amount
        manifest = {
            "captured_utc": datetime.now(timezone.utc).isoformat(),
            "device": "Apple iPod Video 5.5G, 30 GB, firmware version 1.3",
            "disk_number": args.disk_number,
            "data_drive": f"{drive}:",
            "partition_number": firmware["number"],
            "partition_type": firmware["type"],
            "partition_start_sector": firmware["start_sector"],
            "sector_size": SECTOR_SIZE,
            "size_bytes": volume_size,
            "sha256": digest.hexdigest(),
            "read_only": True,
        }
        with manifest_path.open("x", encoding="utf-8", newline="\n") as sidecar:
            json.dump(manifest, sidecar, indent=2)
            sidecar.write("\n")
        print(f"Backup: {output}")
        print(f"SHA-256: {digest.hexdigest()}")
        print(f"Metadata: {manifest_path}")
    except Exception:
        if partial_created and output.exists():
            output.unlink()
        raise
    finally:
        close_handle(handle)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BackupError as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(2)
