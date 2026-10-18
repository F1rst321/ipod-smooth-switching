#!/usr/bin/env python3
"""Emulate the injected RetailOS 0x6089 Settings handlers in Unicorn.

The test executes only the new handlers. Stock continuation addresses and the
two localized-string functions are modeled with small ARM stubs; this does not
emulate the full UI, preference writer, boot process, or audio path.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

try:
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR,
        UC_ARM_REG_PC,
        UC_ARM_REG_R0,
        UC_ARM_REG_R1,
        UC_ARM_REG_R4,
        UC_ARM_REG_R5,
        UC_ARM_REG_R6,
        UC_ARM_REG_R9,
        UC_ARM_REG_R10,
    )
except ImportError as exc:  # pragma: no cover - dependency hint for CLI users
    raise SystemExit(
        "Unicorn is required; install the pinned emulator dependency with "
        "'.venv\\Scripts\\python.exe -m pip install -r requirements-emulation.txt'"
    ) from exc

from build_crossfade_osos_candidate import (
    GET_BRANCH_OFFSET,
    HANDLER_START,
    OSOS_LOAD_ADDRESS,
    SET_BRANCH_OFFSET,
    SET_FAILURE_TARGET,
    SET_SUCCESS_TARGET,
    branch_target,
)

GET_SUCCESS_TARGET = 0x101918C0
GET_ZERO_TARGET = 0x101918C8
STRING_PROVIDER = 0x1021F3B8
STRING_LOOKUP = 0x1021F418
RAW_KIND = 0x51
STRING_KIND = 0x52
OUTPUT_POINTER = 0x230100
SETTINGS_OBJECT = 0x200000
SETTINGS_LINK = 0x210000
PREFERENCES_OBJECT = 0x220000
SET_VALUE_POINTER = 0x250000
STRING_PROVIDER_OBJECT = 0x230000
LOOKUP_RESULT = 0x240000
OSOS_MAP_SIZE = 0x740000
TEST_RAM_START = 0x200000
TEST_RAM_SIZE = 0x100000
SENTINEL = 0x2FFF00


def write_u32(uc: Uc, address: int, value: int) -> None:
    uc.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))


def read_u32(uc: Uc, address: int) -> int:
    return struct.unpack("<I", uc.mem_read(address, 4))[0]


def new_emulator(candidate: bytes) -> tuple[Uc, dict[str, int | bool]]:
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(OSOS_LOAD_ADDRESS, OSOS_MAP_SIZE)
    uc.mem_write(OSOS_LOAD_ADDRESS, candidate)
    uc.mem_map(TEST_RAM_START, TEST_RAM_SIZE)

    # Test-only callees: each loads a harmless sentinel pointer and returns via LR.
    stub = struct.pack("<III", 0xE59F0000, 0xE12FFF1E, STRING_PROVIDER_OBJECT)
    uc.mem_write(STRING_PROVIDER, stub)
    stub = struct.pack("<III", 0xE59F0000, 0xE12FFF1E, LOOKUP_RESULT)
    uc.mem_write(STRING_LOOKUP, stub)

    write_u32(uc, SETTINGS_OBJECT + 0x98, SETTINGS_LINK)
    write_u32(uc, SETTINGS_LINK + 0xCA0, PREFERENCES_OBJECT)
    uc.mem_write(PREFERENCES_OBJECT + 0xB70, b"\x03")
    uc.mem_write(PREFERENCES_OBJECT + 0xB74, b"\x00")
    write_u32(uc, OUTPUT_POINTER, 0xFFFFFFFF)
    write_u32(uc, SENTINEL, 0)

    state: dict[str, int | bool] = {
        "stopped": False,
        "stop_address": 0,
        "return_value": 0,
        "lookup_provider": 0,
        "lookup_id": 0,
    }

    def code_hook(machine: Uc, address: int, _size: int, user_data: object) -> None:
        del user_data
        if address == STRING_LOOKUP:
            state["lookup_provider"] = machine.reg_read(UC_ARM_REG_R0)
            state["lookup_id"] = machine.reg_read(UC_ARM_REG_R1)
        elif address in (
            GET_SUCCESS_TARGET,
            GET_ZERO_TARGET,
            SET_SUCCESS_TARGET,
            SET_FAILURE_TARGET,
        ):
            state["stop_address"] = address
            state["return_value"] = machine.reg_read(UC_ARM_REG_R0)
            if address == GET_SUCCESS_TARGET:
                write_u32(machine, machine.reg_read(UC_ARM_REG_R4), int(state["return_value"]))
            elif address == GET_ZERO_TARGET:
                write_u32(machine, machine.reg_read(UC_ARM_REG_R4), 0)
            state["stopped"] = True
            machine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, code_hook)
    return uc, state


def prepare_getter(uc: Uc, *, request_kind: int, value: int | None, preferences_link: bool = True) -> None:
    if preferences_link:
        write_u32(uc, SETTINGS_OBJECT + 0x98, SETTINGS_LINK)
        write_u32(uc, SETTINGS_LINK + 0xCA0, PREFERENCES_OBJECT)
    else:
        write_u32(uc, SETTINGS_OBJECT + 0x98, 0)
    if value is not None:
        uc.mem_write(PREFERENCES_OBJECT + 0xB70, bytes([value & 0xFF]))
    uc.reg_write(UC_ARM_REG_R4, OUTPUT_POINTER)
    uc.reg_write(UC_ARM_REG_R5, SETTINGS_OBJECT)
    uc.reg_write(UC_ARM_REG_R6, request_kind)
    uc.reg_write(UC_ARM_REG_R9, RAW_KIND)
    uc.reg_write(UC_ARM_REG_R10, STRING_KIND)
    uc.reg_write(UC_ARM_REG_LR, SENTINEL)


def run_getter(candidate: bytes, *, request_kind: int, value: int | None,
               preferences_link: bool = True) -> tuple[int, int, dict[str, int | bool]]:
    uc, state = new_emulator(candidate)
    prepare_getter(uc, request_kind=request_kind, value=value,
                   preferences_link=preferences_link)
    uc.emu_start(HANDLER_START, 0, count=1000)
    if not state["stopped"]:
        raise AssertionError("getter did not reach a stock continuation")
    output = read_u32(uc, OUTPUT_POINTER)
    return output, int(state["stop_address"]), state


def run_setter(candidate: bytes, value: int, *, preferences_link: bool = True
               ) -> tuple[int, int, int, dict[str, int | bool]]:
    uc, state = new_emulator(candidate)
    if preferences_link:
        write_u32(uc, SETTINGS_OBJECT + 0x98, SETTINGS_LINK)
        write_u32(uc, SETTINGS_LINK + 0xCA0, PREFERENCES_OBJECT)
    else:
        write_u32(uc, SETTINGS_OBJECT + 0x98, 0)
    write_u32(uc, SET_VALUE_POINTER, value)
    uc.reg_write(UC_ARM_REG_R4, SETTINGS_OBJECT)
    uc.reg_write(UC_ARM_REG_R5, SET_VALUE_POINTER)
    uc.reg_write(UC_ARM_REG_LR, SENTINEL)
    uc.emu_start(HANDLER_START + 0xD4, 0, count=1000)
    if not state["stopped"]:
        raise AssertionError("setter did not reach a stock continuation")
    stored = uc.mem_read(PREFERENCES_OBJECT + 0xB70, 1)[0]
    dirty = uc.mem_read(PREFERENCES_OBJECT + 0xB74, 1)[0]
    return stored, dirty, int(state["return_value"]), state


def verify(candidate_path: Path) -> None:
    candidate = candidate_path.read_bytes()
    get_site = OSOS_LOAD_ADDRESS + GET_BRANCH_OFFSET
    set_site = OSOS_LOAD_ADDRESS + SET_BRANCH_OFFSET
    get_word = struct.unpack_from("<I", candidate, GET_BRANCH_OFFSET)[0]
    set_word = struct.unpack_from("<I", candidate, SET_BRANCH_OFFSET)[0]
    if branch_target(get_site, get_word) != HANDLER_START:
        raise AssertionError("getter dispatch branch misses its handler")
    if branch_target(set_site, set_word) != HANDLER_START + 0xD4:
        raise AssertionError("setter dispatch branch misses its handler")

    for value, expected in ((3, 3), (7, 7), (10, 10), (0, 3), (11, 3)):
        result, target, _state = run_getter(candidate, request_kind=RAW_KIND, value=value)
        if (result, target) != (expected, GET_SUCCESS_TARGET):
            raise AssertionError(f"raw getter {value} returned {result} via 0x{target:x}")
    result, target, _state = run_getter(
        candidate, request_kind=RAW_KIND, value=None, preferences_link=False
    )
    if (result, target) != (3, GET_SUCCESS_TARGET):
        raise AssertionError("getter did not provide the default 3-second value")

    for value, expected_id in ((3, 30001), (5, 30003), (10, 30008), (11, 30001)):
        result, target, state = run_getter(
            candidate, request_kind=STRING_KIND, value=value
        )
        if (result, target) != (LOOKUP_RESULT, GET_SUCCESS_TARGET):
            raise AssertionError("localized getter did not return the resolved value string")
        if (state["lookup_provider"], state["lookup_id"]) != (
            STRING_PROVIDER_OBJECT, expected_id
        ):
            raise AssertionError(
                f"localized getter used provider/id {state['lookup_provider']}/"
                f"{state['lookup_id']}, expected {STRING_PROVIDER_OBJECT}/{expected_id}"
            )

    result, target, _state = run_getter(candidate, request_kind=0x77, value=5)
    if (result, target) != (0, GET_ZERO_TARGET):
        raise AssertionError("unsupported getter request did not follow the stock zero path")

    for value, expected in ((3, 3), (6, 6), (10, 10), (0, 3), (11, 10)):
        stored, dirty, returned, _state = run_setter(candidate, value)
        if (stored, dirty, returned) != (expected, 1, 1):
            raise AssertionError(
                f"setter {value} produced stored/dirty/return="
                f"{stored}/{dirty}/{returned}, expected {expected}/1/1"
            )

    stored, dirty, returned, state = run_setter(candidate, 6, preferences_link=False)
    if (stored, dirty, returned, state["stop_address"]) != (
        3, 0, 0, SET_FAILURE_TARGET
    ):
        raise AssertionError("setter null-link case did not follow the stock failure path")

    print(f"Candidate OSOS SHA-256: {hashlib.sha256(candidate).hexdigest()}")
    print("Settings handler Unicorn cases passed: raw values, clamping, default, strings, dirty flag, null links.")
    print("Dispatch branches reach handlers. Stock continuations and string APIs were modeled; UI/runtime/audio remain unverified.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="offline patched OSOS candidate")
    args = parser.parse_args()
    try:
        verify(args.candidate)
    except (OSError, ValueError, AssertionError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
