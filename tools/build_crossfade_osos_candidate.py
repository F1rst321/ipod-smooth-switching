#!/usr/bin/env python3
"""Build an offline RetailOS Settings-hook candidate without touching a device.

The candidate combines the 19-row resource prototype with the compiled
0x6089 Settings getter/setter. It remains experimental: it does not add an
audio mixer hook or establish that the static window is safe at runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from patch_settings_menu_prototype import (
    EXPECTED_OSOS_SHA256,
    EXPECTED_OSOS_SIZE,
    RESOURCE_WINDOW_END,
    RESOURCE_WINDOW_START,
    build_prototype,
    sha256,
)

OSOS_LOAD_ADDRESS = 0x10000000
GET_BRANCH_OFFSET = 0x190ED8
SET_BRANCH_OFFSET = 0x191D10
GET_STOCK_BRANCH = 0xEA000294
SET_STOCK_BRANCH = 0xEA0002B3
GET_STOCK_DEFAULT_TARGET = 0x10191930
SET_SUCCESS_TARGET = 0x101927E8
SET_FAILURE_TARGET = 0x101927E4
HANDLER_START = 0x10714000
HANDLER_END = OSOS_LOAD_ADDRESS + RESOURCE_WINDOW_END
HANDLER_FILE_OFFSET = HANDLER_START - OSOS_LOAD_ADDRESS


def arm_branch(instruction_address: int, target_address: int) -> int:
    """Encode an ARM-state unconditional B instruction."""
    delta = target_address - (instruction_address + 8)
    if delta & 3:
        raise ValueError("ARM branch target must be word-aligned")
    displacement = delta // 4
    if not -(1 << 23) <= displacement < (1 << 23):
        raise ValueError("ARM branch target is outside the +/-32 MiB range")
    return 0xEA000000 | (displacement & 0x00FFFFFF)


def branch_target(instruction_address: int, instruction: int) -> int:
    """Decode an unconditional ARM B instruction target."""
    if instruction >> 28 != 0xE or instruction & 0x0F000000 != 0x0A000000:
        raise ValueError(f"0x{instruction:08x} is not an unconditional ARM B")
    immediate = instruction & 0x00FFFFFF
    if immediate & 0x00800000:
        immediate -= 1 << 24
    return instruction_address + 8 + immediate * 4


def require_payload(payload_path: Path, manifest_path: Path) -> tuple[bytes, dict[str, object]]:
    payload = payload_path.read_bytes()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "retailos_settings_handler_payload":
        raise ValueError("handler manifest has an unexpected artifact type")
    if manifest.get("payload_address") != HANDLER_START:
        raise ValueError("handler payload was not linked at the audited code address")
    if manifest.get("payload_size") != len(payload):
        raise ValueError("handler payload size does not match its manifest")
    if manifest.get("payload_sha256") != sha256(payload):
        raise ValueError("handler payload SHA-256 does not match its manifest")
    symbols = manifest.get("symbols")
    if not isinstance(symbols, dict):
        raise ValueError("handler manifest is missing its exported symbol table")
    if symbols.get("ipod_crossfade_settings_get_handler") != HANDLER_START:
        raise ValueError("getter symbol does not match the reserved handler address")
    if symbols.get("ipod_crossfade_settings_set_handler") != HANDLER_START + 0xD4:
        raise ValueError("setter symbol does not match the expected code layout")
    if manifest.get("runtime_validated") is not False or manifest.get("device_ready") is not False:
        raise ValueError("handler manifest incorrectly claims runtime/device validation")
    if not payload or HANDLER_START + len(payload) > HANDLER_END:
        raise ValueError("handler payload exceeds the reserved OSOS window")
    return payload, manifest


def build_candidate(stock_osos: bytes, payload: bytes) -> tuple[bytes, dict[str, object]]:
    if len(stock_osos) != EXPECTED_OSOS_SIZE or sha256(stock_osos) != EXPECTED_OSOS_SHA256:
        raise ValueError("input OSOS does not match the pinned original")
    ui_candidate, ui_manifest = build_prototype(stock_osos)

    resource_used_end = int(ui_manifest["resource_window"]["used_end"])
    if resource_used_end > HANDLER_FILE_OFFSET:
        raise ValueError(
            f"resource prototype reaches 0x{resource_used_end:x}, overlapping handler code"
        )
    if any(stock_osos[HANDLER_FILE_OFFSET:HANDLER_FILE_OFFSET + len(payload)]):
        raise ValueError("the handler placement range is not zero in stock OSOS")

    get_site = OSOS_LOAD_ADDRESS + GET_BRANCH_OFFSET
    set_site = OSOS_LOAD_ADDRESS + SET_BRANCH_OFFSET
    stock_get_word = struct.unpack_from("<I", stock_osos, GET_BRANCH_OFFSET)[0]
    stock_set_word = struct.unpack_from("<I", stock_osos, SET_BRANCH_OFFSET)[0]
    if stock_get_word != GET_STOCK_BRANCH:
        raise ValueError(f"unexpected getter branch at OSOS+0x{GET_BRANCH_OFFSET:x}")
    if stock_set_word != SET_STOCK_BRANCH:
        raise ValueError(f"unexpected setter branch at OSOS+0x{SET_BRANCH_OFFSET:x}")
    if branch_target(get_site, stock_get_word) != GET_STOCK_DEFAULT_TARGET:
        raise ValueError("getter stock branch no longer targets its expected default path")
    if branch_target(set_site, stock_set_word) != SET_FAILURE_TARGET:
        raise ValueError("setter stock branch no longer targets its expected failure path")

    get_hook = arm_branch(get_site, HANDLER_START)
    set_hook = arm_branch(set_site, HANDLER_START + int(
        ui_manifest.get("settings_set_handler_offset", 0xD4)
    ))
    candidate = bytearray(ui_candidate)
    candidate[HANDLER_FILE_OFFSET:HANDLER_FILE_OFFSET + len(payload)] = payload
    struct.pack_into("<I", candidate, GET_BRANCH_OFFSET, get_hook)
    struct.pack_into("<I", candidate, SET_BRANCH_OFFSET, set_hook)

    # Every change to the stock OSOS must be accounted for by the resource
    # prototype, the code payload, or these two audited dispatch instructions.
    expected = bytearray(ui_candidate)
    expected[HANDLER_FILE_OFFSET:HANDLER_FILE_OFFSET + len(payload)] = payload
    struct.pack_into("<I", expected, GET_BRANCH_OFFSET, get_hook)
    struct.pack_into("<I", expected, SET_BRANCH_OFFSET, set_hook)
    if candidate != expected or len(candidate) != EXPECTED_OSOS_SIZE:
        raise ValueError("candidate differs outside explicitly permitted OSOS patches")

    if struct.unpack_from("<I", candidate, GET_BRANCH_OFFSET)[0] != get_hook:
        raise ValueError("getter branch write failed verification")
    if struct.unpack_from("<I", candidate, SET_BRANCH_OFFSET)[0] != set_hook:
        raise ValueError("setter branch write failed verification")
    if branch_target(get_site, get_hook) != HANDLER_START:
        raise ValueError("getter branch does not reach its handler")
    if branch_target(set_site, set_hook) != HANDLER_START + 0xD4:
        raise ValueError("setter branch does not reach its handler")
    if candidate[HANDLER_FILE_OFFSET:HANDLER_FILE_OFFSET + len(payload)] != payload:
        raise ValueError("handler code bytes differ from the compiled payload")

    manifest: dict[str, object] = {
        "artifact_type": "experimental_offline_retailos_osos_candidate",
        "device_ready": False,
        "runtime_validated": False,
        "audio_path_connected": False,
        "stock_osos_sha256": EXPECTED_OSOS_SHA256,
        "candidate_osos_sha256": sha256(bytes(candidate)),
        "osos_size": len(candidate),
        "settings_menu_rows": 19,
        "property_key": "0x6089",
        "handler_payload": {
            "address": HANDLER_START,
            "file_offset": HANDLER_FILE_OFFSET,
            "size": len(payload),
            "sha256": sha256(payload),
        },
        "patched_dispatch_branches": {
            "getter": {
                "file_offset": GET_BRANCH_OFFSET,
                "branch_word": f"0x{get_hook:08x}",
                "target": f"0x{HANDLER_START:08x}",
            },
            "setter": {
                "file_offset": SET_BRANCH_OFFSET,
                "branch_word": f"0x{set_hook:08x}",
                "target": f"0x{HANDLER_START + 0xD4:08x}",
            },
        },
        "resource_window": ui_manifest["resource_window"],
        "validation": {
            "resource_tables": "static parser and byte-preservation checks passed",
            "dispatch_targets": "ARM branch target checks passed",
            "settings_handler_emulation": "not run by this builder",
            "target_device": "not tested",
            "audio_mixing": "not connected",
        },
        "limitations": [
            "The static zero window is not proven free at runtime.",
            "The Volume Limit View is reused as a UI hypothesis; wheel behavior is unverified.",
            "The Settings property handlers have not been emulated in this build step.",
            "No second decoder, crossfade mixer callback, or track handoff is installed.",
            "This OSOS is not an installable or verified firmware image.",
        ],
    }
    return bytes(candidate), manifest


def output_in_build(path: Path) -> Path:
    root = Path(__file__).resolve().parents[1]
    build_dir = (root / "build").resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(build_dir)
    except ValueError as exc:
        raise ValueError("output must stay under this project's ignored build/ directory") from exc
    if resolved.parent != build_dir:
        raise ValueError("output must be directly inside build/")
    if resolved.exists() or resolved.with_suffix(resolved.suffix + ".json").exists():
        raise FileExistsError(f"refusing to overwrite existing output: {resolved}")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("osos", type=Path, help="exact extracted stock OSOS component")
    parser.add_argument("payload", type=Path, help="compiled settings hook payload")
    parser.add_argument(
        "--manifest", type=Path,
        help="payload manifest; defaults to PAYLOAD.bin.json",
    )
    parser.add_argument("--output", type=Path, required=True,
                        help="new experimental OSOS output directly under build/")
    args = parser.parse_args()
    manifest_path = args.manifest or args.payload.with_suffix(args.payload.suffix + ".json")
    try:
        target = output_in_build(args.output)
        payload, _payload_manifest = require_payload(args.payload, manifest_path)
        candidate, manifest = build_candidate(args.osos.read_bytes(), payload)
        output_manifest = target.with_suffix(target.suffix + ".json")
        with target.open("xb") as stream:
            stream.write(candidate)
        with output_manifest.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        written = target.read_bytes()
        if written != candidate or sha256(written) != manifest["candidate_osos_sha256"]:
            raise ValueError("written candidate failed byte-for-byte or SHA-256 verification")
        if json.loads(output_manifest.read_text(encoding="utf-8")) != manifest:
            raise ValueError("candidate manifest failed round-trip verification")
    except (OSError, ValueError, struct.error, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    print(f"Experimental OSOS candidate: {target} ({len(written):,} bytes)")
    print(f"SHA-256: {manifest['candidate_osos_sha256']}")
    print(f"Resource data: {manifest['resource_window']['bytes_used']:,} bytes")
    print(f"Settings handlers: {len(payload):,} bytes at OSOS+0x{HANDLER_FILE_OFFSET:06x}")
    print("Offline research artifact only: audio path and target hardware are unvalidated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
