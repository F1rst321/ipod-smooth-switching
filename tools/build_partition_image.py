#!/usr/bin/env python3
"""Build or verify an offline iPod Video 5.5G RetailOS 1.3 partition image.

This tool never opens a physical drive. It only replaces same-size OSOS/RSRC
payloads in the exact, SHA-256-pinned read-back partition supplied by the user.
Structural validation does not establish that patched code will boot or work.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from inspect_firmware_partition import parse_images

SECTOR_SIZE = 2048
EXPECTED_BACKUP_SIZE = 98_574_336
EXPECTED_BACKUP_SHA256 = "010bda520671d86a5a2cb010b57ee4484c980e54d97eb3e12621e08cde0423a3"
EXPECTED_TYPES = ("OSOS", "RSRC", "AUPD", "HIBE")
EXPECTED_COMPONENTS = {
    "OSOS": (
        0x5000,
        7_561_216,
        "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251",
    ),
    "RSRC": (
        0x73B800,
        5_244_928,
        "080d43f7cf87fb4b4a3f079ce7f35731a217031bf59f1fc80cb87fa49821af11",
    ),
}
PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = PROJECT_ROOT / "build"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_exact_backup(path: Path) -> tuple[bytes, list[dict]]:
    if not path.is_file():
        raise ValueError(f"backup is not a regular file: {path}")
    raw = path.read_bytes()
    if len(raw) != EXPECTED_BACKUP_SIZE or sha256(raw) != EXPECTED_BACKUP_SHA256:
        raise ValueError("backup size/SHA-256 differs from the pinned original; refusing to build")
    version, entries = parse_images(raw, SECTOR_SIZE)
    if version != 3 or tuple(str(e["type"]) for e in entries) != EXPECTED_TYPES:
        raise ValueError("unexpected firmware directory version or image sequence")
    if any(not e["range_valid"] for e in entries):
        raise ValueError("firmware directory points outside the backup")
    for name, (start, length, digest) in EXPECTED_COMPONENTS.items():
        entry = next(e for e in entries if e["type"] == name)
        if (entry["image_start"], entry["length"]) != (start, length):
            raise ValueError(f"unexpected {name} range")
        if sha256(raw[start:start + length]) != digest or not entry["checksum_matches"]:
            raise ValueError(f"{name} in the backup does not match the verified original")
    return raw, entries


def directory_checksum_offset(raw: bytes, index: int) -> int:
    directory = struct.unpack_from("<I", raw, 0x104)[0] + 0x200
    offset = directory + index * 40 + 28
    if offset + 4 > len(raw):
        raise ValueError("firmware directory checksum field is out of range")
    return offset


def changed_components(original: bytes, candidate: bytes, entries: list[dict]) -> list[str]:
    changed = []
    for entry in entries:
        if entry["type"] not in EXPECTED_COMPONENTS:
            continue
        start = int(entry["image_start"])
        end = start + int(entry["length"])
        if original[start:end] != candidate[start:end]:
            changed.append(str(entry["type"]))
    return changed


def verify_candidate(original: bytes, candidate: bytes, entries: list[dict]) -> list[str]:
    if len(candidate) != len(original):
        raise ValueError("candidate partition size differs from the original")
    changed = changed_components(original, candidate, entries)
    if not changed:
        raise ValueError("candidate has no changed OSOS/RSRC payload; no patch to verify")

    # Only changed payloads and their four-byte directory checksums may differ.
    allowed: list[tuple[int, int]] = []
    for index, entry in enumerate(entries):
        if entry["type"] not in changed:
            continue
        start = int(entry["image_start"])
        allowed.append((start, start + int(entry["length"])))
        checksum_offset = directory_checksum_offset(original, index)
        allowed.append((checksum_offset, checksum_offset + 4))
        payload = candidate[start:start + int(entry["length"])]
        if struct.unpack_from("<I", candidate, checksum_offset)[0] != (sum(payload) & 0xFFFFFFFF):
            raise ValueError(f"{entry['type']} directory checksum does not match its payload")

    cursor = 0
    for start, end in sorted(allowed):
        if start < cursor or original[cursor:start] != candidate[cursor:start]:
            raise ValueError("candidate changes bytes outside permitted payload/checksum ranges")
        cursor = end
    if original[cursor:] != candidate[cursor:]:
        raise ValueError("candidate changes bytes outside permitted payload/checksum ranges")

    version, candidate_entries = parse_images(candidate, SECTOR_SIZE)
    if version != 3 or len(candidate_entries) != len(entries):
        raise ValueError("candidate firmware directory changed structure")
    for before, after in zip(entries, candidate_entries):
        for field in (
            "type", "id", "device_offset", "length", "address", "entry_offset",
            "version", "load_address", "image_start",
        ):
            if before[field] != after[field]:
                raise ValueError(f"candidate firmware directory changed {field}")
        if not after["range_valid"]:
            raise ValueError("candidate contains an out-of-range image")
        if after["type"] in changed and not after["checksum_matches"]:
            raise ValueError(f"candidate {after['type']} byte sum failed validation")
    return changed


def read_replacement(path: Path, name: str, original: bytes, entry: dict) -> bytes:
    if not path.is_file():
        raise ValueError(f"{name} replacement is not a regular file: {path}")
    payload = path.read_bytes()
    length = int(entry["length"])
    if len(payload) != length:
        raise ValueError(f"{name} must have exactly {length:,} bytes; relocation is unsupported")
    start = int(entry["image_start"])
    if payload == original[start:start + length]:
        raise ValueError(f"{name} replacement is byte-identical to the stock component")
    return payload


def preflight(args: argparse.Namespace) -> None:
    """Reassemble stock components in memory and demand a byte-identical image."""
    original, entries = read_exact_backup(args.backup)
    rebuilt = bytearray(original)
    sources = {"OSOS": args.osos, "RSRC": args.rsrc}
    for index, entry in enumerate(entries):
        name = str(entry["type"])
        if name not in sources:
            continue
        path = sources[name]
        if not path.is_file():
            raise ValueError(f"stock {name} component is not a regular file: {path}")
        payload = path.read_bytes()
        start, length, digest = EXPECTED_COMPONENTS[name]
        if len(payload) != length or sha256(payload) != digest:
            raise ValueError(f"stock {name} component differs from the pinned original")
        rebuilt[start:start + length] = payload
        checksum_offset = directory_checksum_offset(original, index)
        struct.pack_into("<I", rebuilt, checksum_offset, sum(payload) & 0xFFFFFFFF)
    if rebuilt != original:
        raise ValueError("stock component round-trip did not reproduce the exact backup")
    print("Stock OSOS/RSRC round-trip reproduced the backup byte for byte.")
    print(f"SHA-256: {EXPECTED_BACKUP_SHA256}")
    print("No output image or device write was made.")


def check_output_path(output: Path) -> Path:
    BUILD_DIR.mkdir(exist_ok=True)
    if BUILD_DIR.is_symlink() or BUILD_DIR.resolve().parent != PROJECT_ROOT.resolve():
        raise ValueError("build directory must be a real directory inside the project")
    if output.parent.resolve() != BUILD_DIR.resolve() or output.suffix.lower() != ".img":
        raise ValueError("output must be a .img file directly inside project build/")
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"output already exists: {output}")
    manifest = output.with_suffix(output.suffix + ".json")
    if manifest.exists() or manifest.is_symlink():
        raise FileExistsError(f"manifest already exists: {manifest}")
    return manifest


def build(args: argparse.Namespace) -> None:
    original, entries = read_exact_backup(args.backup)
    if args.osos is None and args.rsrc is None:
        raise ValueError("provide at least one of --osos or --rsrc")
    manifest_path = check_output_path(args.output)
    replacement_paths = {"OSOS": args.osos, "RSRC": args.rsrc}
    candidate = bytearray(original)
    input_manifest = []
    for index, entry in enumerate(entries):
        name = str(entry["type"])
        path = replacement_paths.get(name)
        if path is None:
            continue
        if path.resolve() == args.backup.resolve() or path.resolve() == args.output.resolve():
            raise ValueError(f"{name} replacement path overlaps a source/output path")
        payload = read_replacement(path, name, original, entry)
        start = int(entry["image_start"])
        candidate[start:start + len(payload)] = payload
        checksum_offset = directory_checksum_offset(original, index)
        struct.pack_into("<I", candidate, checksum_offset, sum(payload) & 0xFFFFFFFF)
        input_manifest.append({
            "type": name,
            "source_file": str(path.resolve()),
            "sha256": sha256(payload),
        })

    candidate = bytes(candidate)
    changed = verify_candidate(original, candidate, entries)
    report = {
        "format": "ipod-video-5.5g-stock-partition-v3",
        "structural_validation_only": True,
        "original_sha256": EXPECTED_BACKUP_SHA256,
        "image_sha256": sha256(candidate),
        "size": len(candidate),
        "changed_components": changed,
        "replacements": input_manifest,
    }
    # Exclusive create: never overwrite a previous build or the backup.
    created_output = False
    created_manifest = False
    try:
        with args.output.open("xb") as stream:
            created_output = True
            stream.write(candidate)
        on_disk = args.output.read_bytes()
        if sha256(on_disk) != report["image_sha256"]:
            raise ValueError("written image does not match the in-memory image")
        verify_candidate(original, on_disk, entries)
        with manifest_path.open("x", encoding="utf-8") as stream:
            created_manifest = True
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    except Exception:
        if created_output:
            args.output.unlink(missing_ok=True)
        if created_manifest:
            manifest_path.unlink(missing_ok=True)
        raise
    print(f"Structurally verified: {args.output}")
    print(f"SHA-256: {report['image_sha256']}")
    print(f"Changed components: {', '.join(changed)}")
    print("Boot, UI and audio behavior remain unverified.")


def verify(args: argparse.Namespace) -> None:
    original, entries = read_exact_backup(args.backup)
    if not args.image.is_file():
        raise ValueError(f"candidate is not a regular file: {args.image}")
    candidate = args.image.read_bytes()
    changed = verify_candidate(original, candidate, entries)
    manifest_path = args.image.with_suffix(args.image.suffix + ".json")
    if manifest_path.exists():
        report = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (report.get("original_sha256") != EXPECTED_BACKUP_SHA256
                or report.get("image_sha256") != sha256(candidate)):
            raise ValueError("build manifest hash does not match this candidate")
        if report.get("changed_components") != changed or report.get("size") != len(candidate):
            raise ValueError("build manifest component list or size does not match this candidate")
    print(f"Structurally verified: {args.image}")
    print(f"SHA-256: {sha256(candidate)}")
    print(f"Changed components: {', '.join(changed)}")
    print("Boot, UI and audio behavior remain unverified.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    builder = subcommands.add_parser("build", help="create a new offline image under build/")
    builder.add_argument("--backup", type=Path, required=True,
                         help="exact original partition backup")
    builder.add_argument("--osos", type=Path, help="same-size patched OSOS component")
    builder.add_argument("--rsrc", type=Path, help="same-size patched RSRC component")
    builder.add_argument("--output", type=Path, required=True, help="new build/*.img output")
    checker = subcommands.add_parser(
        "verify", help="verify only permitted bytes differ from backup"
    )
    checker.add_argument("--backup", type=Path, required=True,
                         help="exact original partition backup")
    checker.add_argument("--image", type=Path, required=True, help="candidate partition image")
    stock_check = subcommands.add_parser(
        "preflight", help="reassemble stock components in memory and compare byte for byte"
    )
    stock_check.add_argument("--backup", type=Path, required=True,
                             help="exact original partition backup")
    stock_check.add_argument("--osos", type=Path, required=True,
                             help="exact stock OSOS component")
    stock_check.add_argument("--rsrc", type=Path, required=True,
                             help="exact stock RSRC component")
    args = parser.parse_args()
    try:
        if args.action == "build":
            build(args)
        elif args.action == "verify":
            verify(args)
        else:
            preflight(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
