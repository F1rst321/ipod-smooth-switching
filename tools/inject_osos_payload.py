#!/usr/bin/env python3
"""Place an ARM payload in the audited OSOS static window, without building firmware.

The output is an offline research artifact. It is not an installable image until
the payload's callers, runtime ownership, and device behavior have been proven.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from inspect_firmware_partition import parse_images

SECTOR_SIZE = 2048
EXPECTED_PARTITION_SIZE = 98_574_336
EXPECTED_PARTITION_SHA256 = "010bda520671d86a5a2cb010b57ee4484c980e54d97eb3e12621e08cde0423a3"
EXPECTED_OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"
OSOS_WINDOW_START = 0x712000
OSOS_WINDOW_END = 0x7161A4


def extract_osos(partition: bytes) -> bytes:
    """Return the unique, bounds-checked OSOS component."""
    _version, entries = parse_images(partition, SECTOR_SIZE)
    matches = [entry for entry in entries if entry["type"] == "OSOS"]
    if len(matches) != 1 or not matches[0]["range_valid"]:
        raise ValueError("expected one valid OSOS directory entry")
    entry = matches[0]
    start = int(entry["image_start"])
    return partition[start:start + int(entry["length"])]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def output_under_build(path: Path) -> Path:
    """Resolve a new artifact path and keep it in the ignored build directory."""
    project_root = Path(__file__).resolve().parents[1]
    build_root = (project_root / "build").resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(build_root)
    except ValueError as exc:
        raise ValueError("output must stay inside the project's ignored build/ directory") from exc
    if resolved.exists():
        raise FileExistsError(f"refusing to overwrite existing output: {resolved}")
    if resolved.parent != build_root:
        raise ValueError("output must be directly inside build/")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path, help="pinned, untouched stock partition backup")
    parser.add_argument("payload", type=Path, help="compiled binary payload to insert")
    parser.add_argument("--output", type=Path, required=True,
                        help="new OSOS output file directly inside the ignored build/ directory")
    args = parser.parse_args()

    try:
        partition = args.backup.read_bytes()
        if (len(partition) != EXPECTED_PARTITION_SIZE
                or sha256(partition) != EXPECTED_PARTITION_SHA256):
            raise ValueError("backup size/SHA-256 differs from the pinned original")
        osos = extract_osos(partition)
        if (len(osos) != 7_561_216 or sha256(osos) != EXPECTED_OSOS_SHA256):
            raise ValueError("OSOS size/SHA-256 differs from the pinned original")
        payload = args.payload.read_bytes()
        if not payload:
            raise ValueError("payload must not be empty")
        window_size = OSOS_WINDOW_END - OSOS_WINDOW_START
        if len(payload) > window_size:
            raise ValueError(f"payload is {len(payload):,} bytes; window holds {window_size:,}")
        if any(osos[OSOS_WINDOW_START:OSOS_WINDOW_END]):
            raise ValueError("reserved OSOS window is no longer all zero; refusing to patch")
        output_path = output_under_build(args.output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    patched = bytearray(osos)
    patched[OSOS_WINDOW_START:OSOS_WINDOW_START + len(payload)] = payload
    patched_bytes = bytes(patched)
    manifest_path = output_path.with_suffix(output_path.suffix + ".json")
    if manifest_path.exists():
        parser.error(f"refusing to overwrite existing manifest: {manifest_path}")

    manifest = {
        "artifact_type": "offline_osos_payload_placement",
        "device_ready": False,
        "base_partition_sha256": EXPECTED_PARTITION_SHA256,
        "base_osos_sha256": EXPECTED_OSOS_SHA256,
        "output_osos_sha256": sha256(patched_bytes),
        "payload_sha256": sha256(payload),
        "payload_size": len(payload),
        "osos_window_start": OSOS_WINDOW_START,
        "payload_ram_address": 0x10000000 + OSOS_WINDOW_START,
        "osos_window_end": OSOS_WINDOW_END,
        "window_size": OSOS_WINDOW_END - OSOS_WINDOW_START,
        "runtime_validated": False,
    }

    try:
        with output_path.open("xb") as stream:
            stream.write(patched_bytes)
        with manifest_path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, indent=2)
            stream.write("\n")
        on_disk = output_path.read_bytes()
        if (len(on_disk) != len(osos)
                or on_disk[:OSOS_WINDOW_START] != osos[:OSOS_WINDOW_START]
                or on_disk[OSOS_WINDOW_START:OSOS_WINDOW_START + len(payload)] != payload
                or on_disk[OSOS_WINDOW_START + len(payload):] != osos[OSOS_WINDOW_START + len(payload):]
                or sha256(on_disk) != manifest["output_osos_sha256"]):
            raise ValueError("written OSOS failed byte-for-byte verification")
        if json.loads(manifest_path.read_text(encoding="utf-8")) != manifest:
            raise ValueError("written manifest failed verification")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Placed payload: {len(payload):,}/{window_size:,} bytes at OSOS+0x{OSOS_WINDOW_START:06x}")
    print(f"Output OSOS: {output_path} ({len(on_disk):,} bytes; SHA-256 {sha256(on_disk)})")
    print(f"Manifest: {manifest_path}")
    print("Offline placement only: this output is not an installable or runtime-validated firmware image.")
    print("No stock backup or physical disk was modified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
