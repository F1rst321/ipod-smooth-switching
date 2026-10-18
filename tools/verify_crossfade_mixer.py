#!/usr/bin/env python3
"""Run the compiled ARMv4T mixer in Unicorn and check its PCM/state behavior.

Install the optional dependency into ignored build/ with
``py -m pip install --target build/pydeps -r requirements-emulation.txt`` and
build the payload first with ``py tools/build_crossfade_mixer.py``. This verifies
the isolated C routine; it does not emulate RetailOS or prove device integration.
"""
from __future__ import annotations

import argparse
import re
import struct
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUILD_DIR = PROJECT_ROOT / "build" / "crossfade-mixer"
DEFAULT_TOOLCHAIN_BIN = (
    PROJECT_ROOT / "build" / "toolchains" / "arm-gnu-14.3" / "unpacked" / "bin"
)
CODE_BASE = 0x10712000
CODE_MAP_SIZE = 0x10000
RAM_BASE = 0x20000000
RAM_MAP_SIZE = 0x20000
STATE_ADDRESS = RAM_BASE + 0x1000
A_ADDRESS = RAM_BASE + 0x2000
B_ADDRESS = RAM_BASE + 0x4000
OUT_ADDRESS = RAM_BASE + 0x6000
RING_STORAGE_ADDRESS = RAM_BASE + 0x8000
RING_INPUT_ADDRESS = RAM_BASE + 0x9000
RING_OUTPUT_ADDRESS = RAM_BASE + 0xA000
RETAILOS_ALLOC_ADDRESS = 0x1025A974
RETAILOS_FREE_ADDRESS = 0x1025A8F4
STACK_ADDRESS = RAM_BASE + 0x1F000
RETURN_ADDRESS = RAM_BASE + 0x1FFF0
Q15_ONE = 32768


def load_symbols(nm: Path, elf: Path) -> dict[str, int]:
    result = subprocess.run(
        [str(nm), "-n", str(elf)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    symbols = {}
    for line in result.stdout.splitlines():
        match = re.match(r"^([0-9a-fA-F]+)\s+[A-Za-z]\s+(ipod_crossfade_\w+)$", line)
        if match:
            symbols[match.group(2)] = int(match.group(1), 16)
    required = {
        "ipod_crossfade_begin",
        "ipod_crossfade_mix_block",
        "ipod_crossfade_pcm_ring_storage_bytes",
        "ipod_crossfade_pcm_ring_create",
        "ipod_crossfade_pcm_ring_destroy",
        "ipod_crossfade_pcm_ring_init",
        "ipod_crossfade_pcm_ring_available",
        "ipod_crossfade_pcm_ring_write",
        "ipod_crossfade_pcm_ring_read",
    }
    if not required.issubset(symbols):
        raise ValueError(f"ELF is missing payload entry points: {required - symbols.keys()}")
    return symbols


def pack_state(values: tuple[int, int, int, int, int, int, int]) -> bytes:
    return struct.pack("<6IB3x", *values)


class MixerEmulator:
    """Small ARM emulator wrapper for the two exported mixer functions."""

    def __init__(self, code: bytes, symbols: dict[str, int]):
        try:
            from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_LITTLE_ENDIAN, UC_MODE_THUMB, Uc
            from unicorn.arm_const import (
                UC_ARM_REG_LR,
                UC_ARM_REG_PC,
                UC_ARM_REG_R0,
                UC_ARM_REG_R1,
                UC_ARM_REG_R2,
                UC_ARM_REG_R3,
                UC_ARM_REG_SP,
            )
        except ImportError as exc:
            raise RuntimeError(
                "Unicorn is required; install requirements-emulation.txt"
            ) from exc

        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN)
        self.regs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
        self.sp_register = UC_ARM_REG_SP
        self.pc_register = UC_ARM_REG_PC
        self.lr_register = UC_ARM_REG_LR
        self.symbols = symbols
        self.heap_allocate_result = 0
        self.heap_requests: list[int] = []
        self.heap_releases: list[int] = []
        self.uc.mem_map(CODE_BASE, CODE_MAP_SIZE)
        self.uc.mem_write(CODE_BASE, code)
        self.uc.mem_map(RAM_BASE, RAM_MAP_SIZE)
        self.uc.mem_map(RETAILOS_ALLOC_ADDRESS & 0xFFFFF000, 0x1000)

        def handle_code(uc, address, _size, _user_data):
            if address == RETURN_ADDRESS:
                uc.emu_stop()
            elif address == RETAILOS_ALLOC_ADDRESS:
                self.heap_requests.append(uc.reg_read(self.regs[0]))
                uc.reg_write(self.regs[0], self.heap_allocate_result)
                uc.reg_write(self.pc_register, uc.reg_read(self.lr_register))
            elif address == RETAILOS_FREE_ADDRESS:
                self.heap_releases.append(uc.reg_read(self.regs[0]))
                uc.reg_write(self.pc_register, uc.reg_read(self.lr_register))

        self.uc.hook_add(UC_HOOK_CODE, handle_code)

    def call(self, name: str, args: tuple[int, ...], stack_args: tuple[int, ...] = ()) -> int:
        if len(args) > len(self.regs):
            raise ValueError("register argument count exceeds ARM calling convention")
        for register, value in zip(self.regs, args):
            self.uc.reg_write(register, value)
        stack = STACK_ADDRESS
        if stack_args:
            self.uc.mem_write(stack, struct.pack("<" + "I" * len(stack_args), *stack_args))
        self.uc.reg_write(self.sp_register, stack)
        self.uc.reg_write(self.lr_register, RETURN_ADDRESS | 1)
        entry = self.symbols[name] | 1
        self.uc.reg_write(self.pc_register, entry)
        self.uc.emu_start(entry, 0, count=1_000_000)
        if self.uc.reg_read(self.pc_register) not in (RETURN_ADDRESS, RETURN_ADDRESS | 1):
            raise RuntimeError(f"emulation did not return from {name}")
        return self.uc.reg_read(self.regs[0])


def read_state(emulator: MixerEmulator) -> tuple[int, int, int, int, int, int, int]:
    return struct.unpack("<6IB3x", emulator.uc.mem_read(STATE_ADDRESS, 28))


def write_samples(emulator: MixerEmulator, address: int, samples: list[int]) -> None:
    emulator.uc.mem_write(address, struct.pack("<" + "h" * len(samples), *samples))


def read_samples(emulator: MixerEmulator, address: int, count: int) -> list[int]:
    return list(struct.unpack("<" + "h" * count, emulator.uc.mem_read(address, count * 2)))


def verify(build_dir: Path, toolchain_bin: Path) -> None:
    binary = build_dir / "crossfade_mixer.bin"
    elf = build_dir / "crossfade_mixer.elf"
    nm = toolchain_bin / "arm-none-eabi-nm.exe"
    if not binary.is_file() or not elf.is_file() or not nm.is_file():
        raise FileNotFoundError("build the mixer first and provide its ARM toolchain")
    symbols = load_symbols(nm, elf)
    emulator = MixerEmulator(binary.read_bytes(), symbols)

    # Five stereo frames split across three calls must produce one continuous ramp.
    assert emulator.call("ipod_crossfade_begin", (STATE_ADDRESS, 5)) == 1
    assert read_state(emulator) == (5, 0, 0, Q15_ONE // 4, 0, 0, 1)
    a = [1000, -1000] * 5
    b = [-1000, 1000] * 5
    write_samples(emulator, A_ADDRESS, a[:4])
    write_samples(emulator, B_ADDRESS, b[:4])
    assert emulator.call(
        "ipod_crossfade_mix_block",
        (STATE_ADDRESS, A_ADDRESS, B_ADDRESS, OUT_ADDRESS),
        (2, 2),
    ) == 2
    first_block = read_samples(emulator, OUT_ADDRESS, 4)
    assert first_block == [1000, -1000, 500, -500], first_block

    write_samples(emulator, A_ADDRESS, a[4:6])
    write_samples(emulator, B_ADDRESS, b[4:6])
    assert emulator.call(
        "ipod_crossfade_mix_block",
        (STATE_ADDRESS, A_ADDRESS, B_ADDRESS, OUT_ADDRESS),
        (1, 2),
    ) == 1
    assert read_samples(emulator, OUT_ADDRESS, 2) == [0, 0]

    write_samples(emulator, A_ADDRESS, a[6:])
    write_samples(emulator, B_ADDRESS, b[6:])
    assert emulator.call(
        "ipod_crossfade_mix_block",
        (STATE_ADDRESS, A_ADDRESS, B_ADDRESS, OUT_ADDRESS),
        (8, 2),
    ) == 2
    assert read_samples(emulator, OUT_ADDRESS, 4) == [-500, 500, -1000, 1000]
    assert read_state(emulator) == (5, 5, Q15_ONE, Q15_ONE // 4, 0, 0, 0)

    # Odd-length ramps distribute the remainder and preserve exact end points.
    assert emulator.call("ipod_crossfade_begin", (STATE_ADDRESS, 3)) == 1
    extremes_a = [32767, 32767, 32767]
    extremes_b = [-32768, -32768, -32768]
    write_samples(emulator, A_ADDRESS, extremes_a)
    write_samples(emulator, B_ADDRESS, extremes_b)
    assert emulator.call(
        "ipod_crossfade_mix_block",
        (STATE_ADDRESS, A_ADDRESS, B_ADDRESS, A_ADDRESS),
        (3, 1),
    ) == 3
    assert read_samples(emulator, A_ADDRESS, 3) == [32767, -1, -32768]

    # Invalid channel count leaves the active transition untouched.
    assert emulator.call("ipod_crossfade_begin", (STATE_ADDRESS, 4)) == 1
    before = read_state(emulator)
    assert emulator.call(
        "ipod_crossfade_mix_block",
        (STATE_ADDRESS, A_ADDRESS, B_ADDRESS, OUT_ADDRESS),
        (4, 3),
    ) == 0
    assert read_state(emulator) == before

    # The routine refuses a one-frame fade and clips a request to remaining frames.
    assert emulator.call("ipod_crossfade_begin", (STATE_ADDRESS, 1)) == 0
    assert emulator.call("ipod_crossfade_begin", (STATE_ADDRESS, 2)) == 1
    write_samples(emulator, A_ADDRESS, [200, 200, 200, 200])
    write_samples(emulator, B_ADDRESS, [-200, -200, -200, -200])
    assert emulator.call(
        "ipod_crossfade_mix_block",
        (STATE_ADDRESS, A_ADDRESS, B_ADDRESS, OUT_ADDRESS),
        (4, 1),
    ) == 2
    assert read_samples(emulator, OUT_ADDRESS, 2) == [200, -200]

    # The four-block stereo ring reserves one sentinel frame and wrap-tests
    # both read and write cursors without allocating from the audio callback.
    assert emulator.call(
        "ipod_crossfade_pcm_ring_storage_bytes",
        (2, 2, 2),
    ) == 40
    assert emulator.call(
        "ipod_crossfade_pcm_ring_storage_bytes",
        (2, 1152, 4),
    ) == 18456
    assert emulator.call(
        "ipod_crossfade_pcm_ring_storage_bytes",
        (3, 2, 2),
    ) == 0
    assert emulator.call(
        "ipod_crossfade_pcm_ring_storage_bytes",
        (2, 0xFFFFFFFF, 1),
    ) == 0

    # The firmware-specific allocator path reserves from the stock heap and
    # releases partial allocations when initialization cannot use the block.
    emulator.heap_allocate_result = RING_STORAGE_ADDRESS
    assert emulator.call(
        "ipod_crossfade_pcm_ring_create",
        (2, 2, 2),
    ) == RING_STORAGE_ADDRESS
    assert emulator.heap_requests[-1] == 40
    assert emulator.call(
        "ipod_crossfade_pcm_ring_available",
        (RING_STORAGE_ADDRESS,),
    ) == 0
    emulator.call("ipod_crossfade_pcm_ring_destroy", (RING_STORAGE_ADDRESS,))
    assert emulator.heap_releases[-1] == RING_STORAGE_ADDRESS

    previous_release_count = len(emulator.heap_releases)
    emulator.heap_allocate_result = 0
    assert emulator.call(
        "ipod_crossfade_pcm_ring_create",
        (2, 2, 2),
    ) == 0
    assert len(emulator.heap_releases) == previous_release_count

    emulator.heap_allocate_result = RING_STORAGE_ADDRESS + 1
    assert emulator.call(
        "ipod_crossfade_pcm_ring_create",
        (2, 2, 2),
    ) == 0
    assert emulator.heap_releases[-1] == RING_STORAGE_ADDRESS + 1

    assert emulator.call(
        "ipod_crossfade_pcm_ring_init",
        (RING_STORAGE_ADDRESS, 39, 2, 2),
        (2,),
    ) == 0
    assert emulator.call(
        "ipod_crossfade_pcm_ring_init",
        (RING_STORAGE_ADDRESS + 1, 40, 2, 2),
        (2,),
    ) == 0
    assert emulator.call(
        "ipod_crossfade_pcm_ring_init",
        (RING_STORAGE_ADDRESS, 40, 2, 2),
        (2,),
    ) == RING_STORAGE_ADDRESS
    emulator.uc.mem_write(
        RING_INPUT_ADDRESS,
        struct.pack("<6h", 1, 2, 3, 4, 5, 6),
    )
    assert emulator.call(
        "ipod_crossfade_pcm_ring_write",
        (RING_STORAGE_ADDRESS, RING_INPUT_ADDRESS, 3),
    ) == 3
    assert emulator.call("ipod_crossfade_pcm_ring_available", (RING_STORAGE_ADDRESS,)) == 3
    assert emulator.call(
        "ipod_crossfade_pcm_ring_read",
        (RING_STORAGE_ADDRESS, RING_OUTPUT_ADDRESS, 2),
    ) == 2
    assert read_samples(emulator, RING_OUTPUT_ADDRESS, 4) == [1, 2, 3, 4]

    emulator.uc.mem_write(
        RING_INPUT_ADDRESS,
        struct.pack("<6h", 7, 8, 9, 10, 11, 12),
    )
    assert emulator.call(
        "ipod_crossfade_pcm_ring_write",
        (RING_STORAGE_ADDRESS, RING_INPUT_ADDRESS, 4),
    ) == 3
    assert emulator.call("ipod_crossfade_pcm_ring_available", (RING_STORAGE_ADDRESS,)) == 4
    assert emulator.call(
        "ipod_crossfade_pcm_ring_read",
        (RING_STORAGE_ADDRESS, RING_OUTPUT_ADDRESS, 4),
    ) == 4
    assert read_samples(emulator, RING_OUTPUT_ADDRESS, 8) == [5, 6, 7, 8, 9, 10, 11, 12]

    assert emulator.call(
        "ipod_crossfade_pcm_ring_write",
        (RING_STORAGE_ADDRESS, RING_INPUT_ADDRESS, 4),
    ) == 4
    assert emulator.call(
        "ipod_crossfade_pcm_ring_write",
        (RING_STORAGE_ADDRESS, RING_INPUT_ADDRESS, 1),
    ) == 0
    assert emulator.call(
        "ipod_crossfade_pcm_ring_read",
        (RING_STORAGE_ADDRESS, RING_OUTPUT_ADDRESS, 4),
    ) == 4
    assert emulator.call("ipod_crossfade_pcm_ring_available", (RING_STORAGE_ADDRESS,)) == 0

    print("PASS: 5-frame stereo fade persists correctly across blocks")
    print("PASS: odd-length ramp reaches exact endpoints and supports in-place output")
    print("PASS: invalid channel count is rejected without advancing state")
    print("PASS: one-frame fade is rejected and oversized block is clipped")
    print("PASS: PCM ring validates runtime allocation size and rejects invalid geometry")
    print("PASS: PCM ring wraps read/write cursors and reports full/empty states")
    print("PASS: PCM ring calls the RetailOS heap API and frees unusable allocations")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument("--toolchain-bin", type=Path, default=DEFAULT_TOOLCHAIN_BIN)
    args = parser.parse_args()
    try:
        verify(args.build_dir.resolve(), args.toolchain_bin.resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
