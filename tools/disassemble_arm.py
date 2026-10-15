#!/usr/bin/env python3
"""Disassemble a range of the iPod Video OSOS image using Capstone."""
from __future__ import annotations

import argparse
from pathlib import Path
from zipfile import BadZipFile

from extract_firmware_images import load_firmware_payload
from inspect_firmware_partition import parse_images

LOAD_ADDRESS = 0x10000000


def parse_integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("use a decimal or 0x-prefixed integer") from exc


def read_osos(source: Path, payload: str | None, sector_size: int, raw_osos: bool) -> bytes:
    if raw_osos:
        if payload:
            raise ValueError("--payload cannot be used with --raw-osos")
        return source.read_bytes()
    raw, _ = load_firmware_payload(source, payload)
    _, entries = parse_images(raw, sector_size)
    matches = [entry for entry in entries if entry["type"] == "OSOS"]
    if len(matches) != 1 or not matches[0]["range_valid"]:
        raise ValueError("could not locate one valid OSOS component")
    entry = matches[0]
    start = int(entry["image_start"])
    return raw[start:start + int(entry["length"])]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="local IPSW, raw partition backup, or OSOS binary")
    parser.add_argument("--start", type=parse_integer, required=True, help="OSOS byte offset, e.g. 0x21f254")
    parser.add_argument("--count", type=int, default=64, help="maximum instruction count (default: 64)")
    parser.add_argument("--mode", choices=("arm", "thumb"), default="arm")
    parser.add_argument("--payload", help="Firmware-* member when the IPSW has multiple payloads")
    parser.add_argument("--sector-size", type=int, default=2048)
    parser.add_argument("--raw-osos", action="store_true", help="treat source as an extracted OSOS component")
    args = parser.parse_args()
    if args.start < 0 or args.count < 1 or args.sector_size <= 0:
        parser.error("start must be nonnegative; count and sector size must be positive")

    try:
        osos = read_osos(args.source, args.payload, args.sector_size, args.raw_osos)
    except (OSError, BadZipFile, ValueError) as exc:
        parser.error(str(exc))
    if args.start >= len(osos):
        parser.error(f"start 0x{args.start:x} is outside OSOS ({len(osos):,} bytes)")
    try:
        from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs
    except ImportError:
        parser.error("Capstone is required; install it with `python -m pip install -r requirements-analysis.txt`")

    mode = CS_MODE_ARM if args.mode == "arm" else CS_MODE_THUMB
    engine = Cs(CS_ARCH_ARM, mode | CS_MODE_LITTLE_ENDIAN)
    decoded = engine.disasm(osos[args.start:], LOAD_ADDRESS + args.start, count=args.count)
    for instruction in decoded:
        offset = instruction.address - LOAD_ADDRESS
        print(f"OSOS+0x{offset:06x}  {instruction.bytes.hex(' '):<23} {instruction.mnemonic:<8} {instruction.op_str}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
