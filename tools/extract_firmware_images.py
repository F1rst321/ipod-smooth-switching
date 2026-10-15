#!/usr/bin/env python3
"""Extract selected images from an iPod firmware partition or Apple IPSW."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from inspect_firmware_partition import parse_images


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_firmware_payload(path: Path, payload_name: str | None) -> tuple[bytes, str]:
    if path.suffix.lower() == ".ipsw":
        with ZipFile(path) as package:
            names = [name for name in package.namelist() if name.startswith("Firmware-")]
            if payload_name:
                if payload_name not in names:
                    raise ValueError(f"{payload_name!r} is not a Firmware-* entry in this IPSW")
                name = payload_name
            elif len(names) == 1:
                name = names[0]
            else:
                raise ValueError(f"Expected one Firmware-* entry, found {len(names)}; use --payload")
            return package.read(name), f"{path.name}::{name}"
    if payload_name:
        raise ValueError("--payload is only valid when the input is an IPSW")
    return path.read_bytes(), str(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="firmware-partition backup or IPSW")
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory for extracted components")
    parser.add_argument("--types", nargs="+", default=["OSOS", "RSRC"], help="image types to extract (default: OSOS RSRC)")
    parser.add_argument("--payload", help="Firmware-* member to use when the IPSW has multiple payloads")
    parser.add_argument("--sector-size", type=int, default=2048, help="partition logical sector size (default: 2048)")
    args = parser.parse_args()

    if args.sector_size <= 0:
        parser.error("--sector-size must be positive")
    try:
        raw, source_label = load_firmware_payload(args.source, args.payload)
        version, entries = parse_images(raw, args.sector_size)
        wanted = {value.upper() for value in args.types}
        matches = [entry for entry in entries if str(entry["type"]).upper() in wanted]
        missing = wanted - {str(entry["type"]).upper() for entry in matches}
        if missing:
            raise ValueError("requested image type(s) not found: " + ", ".join(sorted(missing)))
        invalid = [entry for entry in matches if not entry["range_valid"]]
        if invalid:
            raise ValueError("refusing to extract an image whose range is outside the source")
        if args.output_dir.exists():
            raise FileExistsError(f"output directory already exists: {args.output_dir}")

        args.output_dir.mkdir(parents=True)
        manifest = {
            "source": source_label,
            "source_sha256": sha256(raw),
            "firmware_format": version,
            "components": [],
        }
        for entry in matches:
            component = str(entry["type"]).upper()
            start = int(entry["image_start"])
            length = int(entry["length"])
            payload = raw[start:start + length]
            filename = f"{component.lower()}.bin"
            (args.output_dir / filename).write_bytes(payload)
            manifest["components"].append({
                "type": component,
                "file": filename,
                "offset": start,
                "length": length,
                "load_address": int(entry["address"]),
                "entry_offset": int(entry["entry_offset"]),
                "stored_checksum": int(entry["checksum"]),
                "byte_sum_matches": bool(entry["checksum_matches"]),
                "sha256": sha256(payload),
            })
        (args.output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
    except (OSError, BadZipFile, ValueError) as exc:
        parser.error(str(exc))

    print(f"Extracted {len(matches)} component(s) to {args.output_dir}")
    for item in manifest["components"]:
        print(f"  {item['type']}: {item['length']:,} bytes, SHA-256 {item['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
