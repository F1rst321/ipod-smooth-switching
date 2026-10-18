#!/usr/bin/env python3
"""Emulate the stock provider-0 MP3 context constructor in isolated RAM.

This checks only the constructor from the reconstructed stock overlay. It does
not open a track, run an MP3 frame, produce PCM, or emulate the rest of RetailOS.
Install the optional emulator dependency into ignored build/ with
``py -m pip install --target build/pydeps -r requirements-emulation.txt``.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from map_codec_overlay import (
    STOCK_OSOS_SHA256,
    STOCK_OSOS_SIZE,
    load_ranges,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OSOS = PROJECT_ROOT / "firmware" / "extracted" / "audio-analysis" / "osos.bin"
IRAM_BASE = 0x40000000
IRAM_SIZE = 0x20000
CONSTRUCTOR_ADDRESS = 0x4000BC9C
RAM_BASE = 0x20000000
RAM_SIZE = 0x20000
ITEM_A_ADDRESS = RAM_BASE + 0x1000
ITEM_B_ADDRESS = RAM_BASE + 0x5000
ITEM_BYTES = 0x3BEC
CONTEXT_OFFSET = 0x44
STACK_ADDRESS = RAM_BASE + 0x1F000
RETURN_ADDRESS = RAM_BASE + 0x1FFF0


class ConstructorEmulator:
    """Run the ARM7TDMI provider constructor over the stock overlay bytes."""

    def __init__(self, osos: bytes) -> None:
        # Dependencies installed with pip --target live in ignored build/.
        emulation_deps = str(PROJECT_ROOT / "build" / "pydeps")
        if emulation_deps not in sys.path:
            sys.path.insert(0, emulation_deps)
        try:
            from unicorn import (
                UC_ARCH_ARM,
                UC_HOOK_CODE,
                UC_HOOK_MEM_WRITE,
                UC_MODE_ARM,
                UC_MODE_LITTLE_ENDIAN,
                Uc,
            )
            from unicorn.arm_const import (
                UC_ARM_REG_LR,
                UC_ARM_REG_PC,
                UC_ARM_REG_R0,
                UC_ARM_REG_R1,
                UC_ARM_REG_R2,
                UC_ARM_REG_SP,
            )
        except ImportError as exc:
            raise RuntimeError(
                "Unicorn is required; install requirements-emulation.txt"
            ) from exc

        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
        self.r0 = UC_ARM_REG_R0
        self.r1 = UC_ARM_REG_R1
        self.r2 = UC_ARM_REG_R2
        self.sp = UC_ARM_REG_SP
        self.lr = UC_ARM_REG_LR
        self.pc = UC_ARM_REG_PC
        self.write_addresses: list[tuple[int, int]] = []
        self.uc.mem_map(IRAM_BASE, IRAM_SIZE)
        for region in load_ranges(osos, 0):
            self.uc.mem_write(
                region.destination,
                osos[region.source:region.source + region.length],
            )
        self.uc.mem_map(RAM_BASE, RAM_SIZE)

        def stop_at_return(machine, address, _size, _user_data):
            if address == RETURN_ADDRESS:
                machine.emu_stop()

        def record_write(_machine, _access, address, size, _value, _user_data):
            self.write_addresses.append((address, size))

        self.uc.hook_add(UC_HOOK_CODE, stop_at_return)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, record_write)

    def construct(self, item_address: int) -> tuple[int, list[tuple[int, int]]]:
        before = len(self.write_addresses)
        self.uc.reg_write(self.r0, item_address + CONTEXT_OFFSET)
        self.uc.reg_write(self.r1, 0)
        self.uc.reg_write(self.r2, 0)
        self.uc.reg_write(self.sp, STACK_ADDRESS)
        self.uc.reg_write(self.lr, RETURN_ADDRESS)
        self.uc.reg_write(self.pc, CONSTRUCTOR_ADDRESS)
        self.uc.emu_start(CONSTRUCTOR_ADDRESS, 0, count=5_000_000)
        if self.uc.reg_read(self.pc) != RETURN_ADDRESS:
            raise RuntimeError("stock MP3 context constructor did not return")
        return self.uc.reg_read(self.r0), self.write_addresses[before:]


def verify(osos_path: Path) -> None:
    try:
        osos = osos_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cannot read OSOS: {exc}") from exc
    digest = hashlib.sha256(osos).hexdigest()
    if len(osos) != STOCK_OSOS_SIZE or digest != STOCK_OSOS_SHA256:
        raise ValueError("OSOS size/SHA-256 does not match the untouched backup")

    emulator = ConstructorEmulator(osos)
    uc = emulator.uc
    uc.mem_write(ITEM_A_ADDRESS, bytes(ITEM_BYTES))
    uc.mem_write(ITEM_B_ADDRESS, bytes(ITEM_BYTES))

    result_a, writes_a = emulator.construct(ITEM_A_ADDRESS)
    if result_a != ITEM_A_ADDRESS + CONTEXT_OFFSET:
        raise AssertionError(f"unexpected A context pointer: 0x{result_a:08x}")
    item_a_after_first = bytes(uc.mem_read(ITEM_A_ADDRESS, ITEM_BYTES))

    result_b, writes_b = emulator.construct(ITEM_B_ADDRESS)
    if result_b != ITEM_B_ADDRESS + CONTEXT_OFFSET:
        raise AssertionError(f"unexpected B context pointer: 0x{result_b:08x}")
    item_a_after_second = bytes(uc.mem_read(ITEM_A_ADDRESS, ITEM_BYTES))
    item_b = bytes(uc.mem_read(ITEM_B_ADDRESS, ITEM_BYTES))

    if item_a_after_second != item_a_after_first:
        raise AssertionError("constructing B modified the existing A context")
    if item_b == item_a_after_first:
        raise AssertionError("A and B constructor images unexpectedly match")

    for label, item, writes in (
        ("A", ITEM_A_ADDRESS, writes_a),
        ("B", ITEM_B_ADDRESS, writes_b),
    ):
        unexpected = [
            (address, size)
            for address, size in writes
            if not (item <= address and address + size <= item + ITEM_BYTES)
            and not (STACK_ADDRESS - 0x1000 <= address < STACK_ADDRESS + 0x1000)
        ]
        if unexpected:
            formatted = [(hex(address), size) for address, size in unexpected[:8]]
            raise AssertionError(f"{label} constructor wrote outside item/stack: {formatted}")

    print(f"OSOS SHA-256: {digest}")
    print(f"PASS: stock provider-0 constructor returned A=0x{result_a:08x}")
    print(f"PASS: stock provider-0 constructor returned B=0x{result_b:08x}")
    print(f"PASS: A item remained byte-for-byte unchanged while B was constructed")
    print(f"PASS: constructor writes stayed inside each item and the emulated stack")
    print(f"Constructor writes: A={len(writes_a):,}, B={len(writes_b):,}")
    print(
        "LIMIT: no track resource, stream initialization, MP3 frame, PCM, or "
        "device playback was emulated"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osos", type=Path, default=DEFAULT_OSOS)
    args = parser.parse_args()
    try:
        verify(args.osos.resolve())
    except (OSError, RuntimeError, ValueError, AssertionError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
