#!/usr/bin/env python3
"""Build an offline RetailOS Settings-hook candidate without touching a device.

The candidate combines the 19-row resource prototype with the compiled
0x6089 Settings getter/setter and may include an optional experimental audio
hook payload. It remains experimental and does not establish that the static
window is safe at runtime.
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
AUDIO_HOOK_START = 0x10714200
AUDIO_HOOK_SITE_OFFSET = 0x1D606C
AUDIO_HOOK_STOCK_BRANCH = 0xEB010711
AUDIO_HOOK_STOCK_TARGET = 0x10217CB8
AUDIO_B_PCM_BYTES = 4608


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
    """Decode an unconditional ARM B or BL instruction target."""
    if instruction >> 28 != 0xE or instruction & 0x0E000000 != 0x0A000000:
        raise ValueError(f"0x{instruction:08x} is not an unconditional ARM B/BL")
    immediate = instruction & 0x00FFFFFF
    if immediate & 0x00800000:
        immediate -= 1 << 24
    return instruction_address + 8 + immediate * 4


def arm_link_branch(instruction_address: int, target_address: int) -> int:
    """Encode an unconditional ARM BL instruction."""
    delta = target_address - (instruction_address + 8)
    if delta & 3:
        raise ValueError("ARM BL target must be word-aligned")
    displacement = delta // 4
    if not -(1 << 23) <= displacement < (1 << 23):
        raise ValueError("ARM BL target is outside the +/-32 MiB range")
    return 0xEB000000 | (displacement & 0x00FFFFFF)


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


def require_audio_payload(
    payload_path: Path, manifest_path: Path
) -> tuple[bytes, dict[str, object]]:
    payload = payload_path.read_bytes()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "experimental_retailos_audio_hook_payload":
        raise ValueError("audio payload manifest has an unexpected artifact type")
    if manifest.get("payload_address") != AUDIO_HOOK_START:
        raise ValueError("audio hook payload must be linked at 0x10714200")
    if manifest.get("payload_size") != len(payload):
        raise ValueError("audio payload size does not match its manifest")
    if manifest.get("payload_sha256") != sha256(payload):
        raise ValueError("audio payload SHA-256 does not match its manifest")
    if manifest.get("runtime_validated") is not False or manifest.get("device_ready") is not False:
        raise ValueError("audio payload manifest incorrectly claims device validation")
    symbols = manifest.get("symbols")
    if not isinstance(symbols, dict):
        raise ValueError("audio payload manifest is missing its symbol table")
    gate = symbols.get("ipod_crossfade_playback_mix_gate")
    if not isinstance(gate, int) or gate & 3:
        raise ValueError("audio payload has no aligned ARM playback gate")
    if gate < AUDIO_HOOK_START or gate >= AUDIO_HOOK_START + len(payload):
        raise ValueError("audio playback gate is outside the payload")
    if not payload or AUDIO_HOOK_START + len(payload) > OSOS_LOAD_ADDRESS + RESOURCE_WINDOW_END:
        raise ValueError("audio payload exceeds the audited OSOS zero window")
    state_address = symbols.get("ipod_crossfade_playback_hook_state")
    if not isinstance(state_address, int):
        raise ValueError("audio payload has no playback-hook state symbol")
    state_offset = state_address - AUDIO_HOOK_START
    if state_offset < 0 or state_offset + 40 > len(payload):
        raise ValueError("playback-hook state is outside the audio payload")
    state_fields = struct.unpack_from("<10I", payload, state_offset)
    state_magic, state_enabled = state_fields[:2]
    state_output, state_capacity = state_fields[8:10]
    if state_magic != 0x43524650 or state_enabled != 0:
        raise ValueError("playback hook must have its expected magic and default disabled state")
    scratch_address = symbols.get("ipod_crossfade_output_b_scratch")
    if not isinstance(scratch_address, int) or scratch_address & 3:
        raise ValueError("audio payload has no aligned B PCM scratch buffer")
    scratch_offset = scratch_address - AUDIO_HOOK_START
    if state_output != scratch_address or state_capacity != AUDIO_B_PCM_BYTES:
        raise ValueError("playback-hook state does not point at its 1,152-frame PCM buffer")
    if scratch_offset < 0 or scratch_offset + state_capacity > len(payload):
        raise ValueError("B PCM scratch buffer is outside the audio payload")
    return payload, manifest


def build_candidate(
    stock_osos: bytes,
    payload: bytes,
    audio_payload: bytes | None = None,
    audio_manifest: dict[str, object] | None = None,
) -> tuple[bytes, dict[str, object]]:
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

    audio_hook_word: int | None = None
    audio_gate: int | None = None
    if audio_payload is not None:
        if audio_manifest is None:
            raise ValueError("audio payload manifest is required")
        audio_symbols = audio_manifest.get("symbols")
        if not isinstance(audio_symbols, dict):
            raise ValueError("audio payload manifest is missing its symbols")
        audio_gate = int(audio_symbols["ipod_crossfade_playback_mix_gate"])
        audio_file_offset = AUDIO_HOOK_START - OSOS_LOAD_ADDRESS
        if resource_used_end > HANDLER_FILE_OFFSET:
            raise ValueError("UI resource region overlaps Settings handler placement")
        if audio_file_offset < HANDLER_FILE_OFFSET + len(payload):
            raise ValueError("audio payload overlaps the Settings handler")
        if any(stock_osos[audio_file_offset:audio_file_offset + len(audio_payload)]):
            raise ValueError("audio payload placement range is not zero in stock OSOS")
        stock_audio_word = struct.unpack_from("<I", stock_osos, AUDIO_HOOK_SITE_OFFSET)[0]
        if stock_audio_word != AUDIO_HOOK_STOCK_BRANCH:
            raise ValueError(
                f"unexpected stock voice-mixer call at OSOS+0x{AUDIO_HOOK_SITE_OFFSET:x}"
            )
        audio_site = OSOS_LOAD_ADDRESS + AUDIO_HOOK_SITE_OFFSET
        if branch_target(audio_site, stock_audio_word) != AUDIO_HOOK_STOCK_TARGET:
            raise ValueError("stock voice-mixer call no longer has the audited target")
        audio_hook_word = arm_link_branch(audio_site, audio_gate)
        candidate[audio_file_offset:audio_file_offset + len(audio_payload)] = audio_payload
        struct.pack_into("<I", candidate, AUDIO_HOOK_SITE_OFFSET, audio_hook_word)

    # Account for every changed OSOS byte in the resource prototype or one of
    # the explicitly placed payloads and audited dispatch instructions.
    expected = bytearray(ui_candidate)
    expected[HANDLER_FILE_OFFSET:HANDLER_FILE_OFFSET + len(payload)] = payload
    struct.pack_into("<I", expected, GET_BRANCH_OFFSET, get_hook)
    struct.pack_into("<I", expected, SET_BRANCH_OFFSET, set_hook)
    if audio_payload is not None and audio_hook_word is not None:
        audio_file_offset = AUDIO_HOOK_START - OSOS_LOAD_ADDRESS
        expected[audio_file_offset:audio_file_offset + len(audio_payload)] = audio_payload
        struct.pack_into("<I", expected, AUDIO_HOOK_SITE_OFFSET, audio_hook_word)
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
    if audio_payload is not None and audio_hook_word is not None:
        audio_file_offset = AUDIO_HOOK_START - OSOS_LOAD_ADDRESS
        if candidate[audio_file_offset:audio_file_offset + len(audio_payload)] != audio_payload:
            raise ValueError("audio hook code bytes differ from the compiled payload")
        if branch_target(OSOS_LOAD_ADDRESS + AUDIO_HOOK_SITE_OFFSET, audio_hook_word) != audio_gate:
            raise ValueError("playback hook BL does not reach its ARM gate")

    manifest: dict[str, object] = {
        "artifact_type": "experimental_offline_retailos_osos_candidate",
        "device_ready": False,
        "runtime_validated": False,
        "audio_path_connected": False,
        "playback_hook_installed": audio_payload is not None,
        "b_pcm_scratch_buffer": (
            {
                "address": f"0x{int(audio_manifest['symbols']['ipod_crossfade_output_b_scratch']):08x}",
                "bytes": AUDIO_B_PCM_BYTES,
                "frames_stereo_pcm16": 1152,
            }
            if audio_manifest is not None
            else None
        ),
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
            "audio_mixing": "helper included but runtime setup not connected",
        },
        "limitations": [
            "The static zero window is not proven free at runtime.",
            "The Volume Limit View is reused as a UI hypothesis; wheel behavior is unverified.",
            "The Settings property handlers have not been emulated in this build step.",
            "The optional playback helper branch and its default-off data need device validation.",
            "No next-track resource/item lifecycle or automatic fade trigger is installed.",
            "This OSOS is not an installable or verified firmware image.",
        ],
    }
    if audio_payload is not None and audio_hook_word is not None and audio_gate is not None:
        manifest["audio_hook_payload"] = {
            "address": AUDIO_HOOK_START,
            "file_offset": AUDIO_HOOK_START - OSOS_LOAD_ADDRESS,
            "size": len(audio_payload),
            "sha256": sha256(audio_payload),
        }
        manifest["patched_dispatch_branches"]["playback_mix"] = {
            "file_offset": AUDIO_HOOK_SITE_OFFSET,
            "branch_word": f"0x{audio_hook_word:08x}",
            "target": f"0x{audio_gate:08x}",
            "stock_target": f"0x{AUDIO_HOOK_STOCK_TARGET:08x}",
        }
    payload_window_used_end = max(
        resource_used_end,
        HANDLER_FILE_OFFSET + len(payload),
        (AUDIO_HOOK_START - OSOS_LOAD_ADDRESS + len(audio_payload))
        if audio_payload is not None
        else 0,
    )
    if payload_window_used_end > RESOURCE_WINDOW_END:
        raise ValueError("combined resources and payload exceed the OSOS zero window")
    manifest["payload_window"] = {
        "start_address": f"0x{OSOS_LOAD_ADDRESS + RESOURCE_WINDOW_START:08x}",
        "end_address_exclusive": f"0x{OSOS_LOAD_ADDRESS + RESOURCE_WINDOW_END:08x}",
        "used_end_address_exclusive": f"0x{OSOS_LOAD_ADDRESS + payload_window_used_end:08x}",
        "used_high_water_bytes": payload_window_used_end - RESOURCE_WINDOW_START,
        "remaining_bytes": RESOURCE_WINDOW_END - payload_window_used_end,
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
    parser.add_argument(
        "--audio-payload",
        type=Path,
        help="optional experimental mixer/worker-hook payload linked at 0x10714200",
    )
    parser.add_argument(
        "--audio-manifest",
        type=Path,
        help="audio manifest; defaults to AUDIO_PAYLOAD.bin.json",
    )
    parser.add_argument("--output", type=Path, required=True,
                        help="new experimental OSOS output directly under build/")
    args = parser.parse_args()
    manifest_path = args.manifest or args.payload.with_suffix(args.payload.suffix + ".json")
    audio_manifest_path = (
        args.audio_manifest
        or (args.audio_payload.with_suffix(args.audio_payload.suffix + ".json")
            if args.audio_payload is not None else None)
    )
    if args.audio_manifest is not None and args.audio_payload is None:
        parser.error("--audio-manifest requires --audio-payload")
    try:
        target = output_in_build(args.output)
        payload, _payload_manifest = require_payload(args.payload, manifest_path)
        audio_payload = None
        audio_payload_manifest = None
        if args.audio_payload is not None and audio_manifest_path is not None:
            audio_payload, audio_payload_manifest = require_audio_payload(
                args.audio_payload, audio_manifest_path
            )
        candidate, manifest = build_candidate(
            args.osos.read_bytes(), payload, audio_payload, audio_payload_manifest
        )
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
    if audio_payload is not None:
        print(
            f"Experimental playback helper: {len(audio_payload):,} bytes at "
            f"OSOS+0x{AUDIO_HOOK_START - OSOS_LOAD_ADDRESS:06x}; "
            "B item lifecycle is not initialized by this candidate."
        )
    print("Offline research artifact only: audio path and target hardware are unvalidated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
