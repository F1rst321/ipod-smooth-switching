#!/usr/bin/env python3
"""Run the stock RMIprimary/FSbuf constructor in the captured HIBE state.

This is a read-only Unicorn experiment. It allocates a private owner and one
0x8000-byte FSbuf chunk from a copy of the saved idle heap, then calls the
stock OSOS constructor with the captured shared TPCMQUEUE/context pointers.
It does not run a file open, decode audio, write firmware, or access the iPod.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "build" / "pydeps"))

from unicorn import (  # noqa: E402
    UC_ARCH_ARM,
    UC_HOOK_CODE,
    UC_HOOK_MEM_INVALID,
    UC_MODE_ARM,
    UC_MODE_LITTLE_ENDIAN,
    Uc,
    UcError,
)
from unicorn.arm_const import (  # noqa: E402
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_SP,
)

DEFAULT_OSOS = PROJECT_ROOT / "firmware" / "extracted" / "audio-analysis" / "osos.bin"
DEFAULT_HIBE = PROJECT_ROOT / "build" / "audio-analysis" / "hibe.bin"
DEFAULT_IRAM = PROJECT_ROOT / "build" / "audio-analysis" / "iram-after-600m.bin"
OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"
RAM_BYTES = 0x02000000
RAM_BASES = (0x00000000, 0x10000000, 0x14000000)
IRAM_BASE = 0x40000000
IRAM_SIZE = 0x20000
SCRATCH_BASE = 0x20000000
SCRATCH_SIZE = 0x00100000
STACK = 0x200F0000
RETURN = 0x200FF000
HEAP_ALLOC = 0x1025A974
RMI_CONSTRUCTOR = 0x1024B5BC
RMI_TASK_QUEUE = 0x149388B0
RMI_CONTEXT = 0x149E83A0
OWNER_BYTES = 0x90C8
FSBUF_OFFSET = 0x2E60
FSBUF_BACKING_POINTER_OFFSET = 0x6204
FSBUF_BACKING_SIZE_OFFSET = 0x6210
FSBUF_CHUNK_SIZE_OFFSET = 0x6214
FSBUF_CHUNK_COUNT_OFFSET = 0x6218
FSBUF_BACKING_BYTES = 0x8000
FSBUF_CHUNK_BYTES = 0x8000


def u32(machine: Uc, address: int) -> int:
    return struct.unpack("<I", machine.mem_read(address, 4))[0]


class ConstructorMachine:
    """Emulate ARM calls using the saved OSOS, HIBE RAM, and IRAM snapshot."""

    def __init__(self, osos: bytes, hibe: bytes, iram: bytes) -> None:
        self.machine = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
        self.last_pcs: list[int] = []
        self.invalid_memory: list[str] = []
        self.machine.hook_add(UC_HOOK_CODE, self._on_code)
        self.machine.hook_add(UC_HOOK_MEM_INVALID, self._on_invalid_memory)
        for base in RAM_BASES:
            self.machine.mem_map(base, RAM_BYTES)
            self.machine.mem_write(base, hibe[0x800:0x800 + RAM_BYTES])
        self.machine.mem_map(IRAM_BASE, IRAM_SIZE)
        self.machine.mem_write(IRAM_BASE, iram[:IRAM_SIZE])
        self.machine.mem_map(0x60000000, 0x1000)
        self.machine.mem_write(0x60000000, struct.pack("<I", 0x55))
        self.machine.mem_map(SCRATCH_BASE, SCRATCH_SIZE)
        if self.machine.mem_read(0x14000000, len(osos)) != osos:
            raise ValueError("HIBE RAM does not begin with the audited OSOS image")

    def _on_code(self, machine: Uc, address: int, _size: int, _user_data) -> None:
        self.last_pcs.append(address)
        if len(self.last_pcs) > 24:
            del self.last_pcs[0]
        if address == RETURN:
            machine.emu_stop()

    def _on_invalid_memory(
        self, _machine: Uc, access: int, address: int, size: int,
        value: int, _user_data,
    ) -> bool:
        self.invalid_memory.append(
            f"access={access} address=0x{address:08x} size={size} value=0x{value:x}"
        )
        return False

    def call(self, address: int, arguments: tuple[int, ...], *, fifth: int | None = None) -> int:
        registers = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
        if len(arguments) > len(registers):
            raise ValueError("at most four register arguments are supported")
        for register, value in zip(registers, arguments):
            self.machine.reg_write(register, value)
        self.machine.reg_write(UC_ARM_REG_SP, STACK)
        self.machine.reg_write(UC_ARM_REG_LR, RETURN)
        if fifth is not None:
            self.machine.mem_write(STACK, struct.pack("<I", fifth))
        self.last_pcs.clear()
        self.invalid_memory.clear()
        try:
            self.machine.emu_start(address, RETURN, count=10_000_000)
        except UcError as exc:
            trace = " ".join(f"0x{pc:08x}" for pc in self.last_pcs[-12:])
            detail = "; ".join(self.invalid_memory)
            raise RuntimeError(
                f"ARM call 0x{address:08x} failed: {exc}; {detail}; PCs: {trace}"
            ) from exc
        if self.machine.reg_read(UC_ARM_REG_PC) != RETURN:
            trace = " ".join(f"0x{pc:08x}" for pc in self.last_pcs[-12:])
            raise RuntimeError(
                f"ARM call 0x{address:08x} did not return; PCs: {trace}"
            )
        return self.machine.reg_read(UC_ARM_REG_R0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osos", type=Path, default=DEFAULT_OSOS)
    parser.add_argument("--hibe", type=Path, default=DEFAULT_HIBE)
    parser.add_argument("--iram", type=Path, default=DEFAULT_IRAM)
    args = parser.parse_args()
    osos = args.osos.read_bytes()
    if hashlib.sha256(osos).hexdigest() != OSOS_SHA256:
        parser.error("OSOS SHA-256 does not match the audited original")
    hibe = args.hibe.read_bytes()
    if len(hibe) < 0x800 + RAM_BYTES:
        parser.error("HIBE RAM snapshot is too short")
    iram = args.iram.read_bytes()
    if len(iram) < IRAM_SIZE:
        parser.error("IRAM snapshot is too short")

    emu = ConstructorMachine(osos, hibe, iram)
    parent = emu.call(HEAP_ALLOC, (OWNER_BYTES,))
    backing = emu.call(HEAP_ALLOC, (FSBUF_BACKING_BYTES,))
    if parent == 0 or backing == 0:
        raise RuntimeError("saved idle RetailOS heap could not allocate the B owner")
    emu.machine.mem_write(parent, bytes(OWNER_BYTES))
    emu.machine.mem_write(backing, bytes(FSBUF_BACKING_BYTES))
    if parent + OWNER_BYTES > 0x16000000 or backing + FSBUF_BACKING_BYTES > 0x16000000:
        raise RuntimeError("heap returned an address outside the captured RAM aliases")

    result = emu.call(
        RMI_CONSTRUCTOR,
        (parent, RMI_TASK_QUEUE, RMI_CONTEXT, backing),
        fifth=FSBUF_BACKING_BYTES,
    )
    fsbuf = parent + FSBUF_OFFSET
    stored_backing = u32(emu.machine, fsbuf + FSBUF_BACKING_POINTER_OFFSET)
    stored_size = u32(emu.machine, fsbuf + FSBUF_BACKING_SIZE_OFFSET)
    chunk_size = u32(emu.machine, fsbuf + FSBUF_CHUNK_SIZE_OFFSET)
    chunk_count = u32(emu.machine, fsbuf + FSBUF_CHUNK_COUNT_OFFSET)
    if result != parent:
        raise RuntimeError(
            f"stock constructor returned 0x{result:08x}, expected owner 0x{parent:08x}"
        )
    if (stored_backing, stored_size, chunk_size, chunk_count) != (
        backing, FSBUF_BACKING_BYTES, FSBUF_CHUNK_BYTES, 1
    ):
        raise RuntimeError(
            "unexpected FSbuf backing geometry: "
            f"pointer=0x{stored_backing:08x} size=0x{stored_size:x} "
            f"chunk=0x{chunk_size:x} count={chunk_count}"
        )

    print("Stock RMIprimary/FSbuf constructor returned in the HIBE emulator.")
    print(f"Allocated B owner: 0x{parent:08x}, minimum extent 0x{OWNER_BYTES:x}")
    print(f"B FSbuf: 0x{fsbuf:08x}, vtable 0x{u32(emu.machine, fsbuf):08x}")
    print(f"Private backing: 0x{stored_backing:08x}, size 0x{stored_size:x}, "
          f"chunk 0x{chunk_size:x}, chunks {chunk_count}")
    print("This validates object construction only; it does not open a URI or read B audio.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Constructor verification failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
