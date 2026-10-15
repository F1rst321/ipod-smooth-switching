#!/usr/bin/env python3
"""Find printable strings in a component file or directly in an IPSW."""
from __future__ import annotations

import argparse
import re
from pathlib import Path
from zipfile import BadZipFile

from extract_firmware_images import load_firmware_payload
from inspect_firmware_partition import parse_images


def strings(data: bytes, minimum: int):
    patterns = (("ascii", re.compile(rb"[\x20-\x7e]{" + str(minimum).encode() + rb",}")),
                ("utf16le", re.compile(rb"(?:[\x20-\x7e]\x00){" + str(minimum).encode() + rb",}")))
    found = []
    for encoding, pattern in patterns:
        for match in pattern.finditer(data):
            raw = match.group()
            text = raw.decode("ascii" if encoding == "ascii" else "utf-16le", errors="replace")
            found.append((match.start(), encoding, text))
    return sorted(found)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="component file, firmware partition, or IPSW")
    parser.add_argument("--type", dest="image_type", help="component type for a partition or IPSW, such as OSOS")
    parser.add_argument("--payload", help="Firmware-* member when the IPSW has multiple payloads")
    parser.add_argument("--sector-size", type=int, default=2048)
    parser.add_argument("--min-length", type=int, default=5)
    parser.add_argument("--contains", help="print only strings containing this text, case-insensitively")
    parser.add_argument("--output", type=Path, help="write results to a new UTF-8 text file")
    args = parser.parse_args()
    if args.min_length < 1:
        parser.error("--min-length must be positive")
    if args.sector_size <= 0:
        parser.error("--sector-size must be positive")

    try:
        if args.source.suffix.lower() == ".ipsw" or args.image_type:
            data, _ = load_firmware_payload(args.source, args.payload)
            _, entries = parse_images(data, args.sector_size)
            if not args.image_type:
                parser.error("--type is required when scanning an IPSW")
            matches = [entry for entry in entries if str(entry["type"]).casefold() == args.image_type.casefold()]
            if len(matches) != 1 or not matches[0]["range_valid"]:
                parser.error(f"component {args.image_type!r} is missing or outside the image")
            entry = matches[0]
            start = int(entry["image_start"])
            data = data[start:start + int(entry["length"])]
        else:
            if args.payload:
                parser.error("--payload is only valid with an IPSW")
            data = args.source.read_bytes()
    except (OSError, BadZipFile, ValueError) as exc:
        parser.error(str(exc))

    needle = args.contains.casefold() if args.contains else None
    results = [
        f"0x{offset:08x}\t{encoding}\t{text}"
        for offset, encoding, text in strings(data, args.min_length)
        if needle is None or needle in text.casefold()
    ]
    rendered = "\n".join(results) + ("\n" if results else "")
    if args.output:
        if args.output.exists():
            parser.error(f"output file already exists: {args.output}")
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote {len(results)} strings to {args.output}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
