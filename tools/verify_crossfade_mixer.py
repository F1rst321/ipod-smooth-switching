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
import sys
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
FAKE_PLAYER_ADDRESS = RAM_BASE + 0xB000
FAKE_TRACK_B_ADDRESS = RAM_BASE + 0xC000
FAKE_RESOURCE_OUT_ADDRESS = RAM_BASE + 0xD000
FAKE_STREAM_ADDRESS = RAM_BASE + 0xE000
RETAILOS_ALLOC_ADDRESS = 0x1025A974
RETAILOS_FREE_ADDRESS = 0x1025A8F4
RETAILOS_TRACK_RESOURCE_FACTORY = 0x1010B894
RETAILOS_RESOURCE_REGISTRY_RESET = 0x101332A8
STACK_ADDRESS = RAM_BASE + 0x1F000
RETURN_ADDRESS = RAM_BASE + 0x1FFF0
Q15_ONE = 32768
PLAYER_CURRENT_TRACK_OFFSET = 0x2A4
TRACK_ID_OFFSET = 0x10


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
        "ipod_crossfade_open_track_resource_b",
        "ipod_crossfade_resource_registry_reset_gate",
        "ipod_crossfade_resource_gate_state",
    }
    if not required.issubset(symbols):
        raise ValueError(f"ELF is missing payload entry points: {required - symbols.keys()}")
    return symbols


def pack_state(values: tuple[int, int, int, int, int, int, int]) -> bytes:
    return struct.pack("<6IB3x", *values)


class MixerEmulator:
    """Small ARM emulator wrapper for the two exported mixer functions."""

    def __init__(self, code: bytes, symbols: dict[str, int]):
        # Dependencies installed with pip --target live in ignored build/.
        emulation_deps = str(PROJECT_ROOT / "build" / "pydeps")
        if emulation_deps not in sys.path:
            sys.path.insert(0, emulation_deps)
        try:
            from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_LITTLE_ENDIAN, UC_MODE_THUMB, Uc
            from unicorn.arm_const import (
                UC_ARM_REG_LR,
                UC_ARM_REG_PC,
                UC_ARM_REG_R0,
                UC_ARM_REG_R1,
                UC_ARM_REG_R2,
                UC_ARM_REG_R3,
                UC_ARM_REG_R5,
                UC_ARM_REG_SP,
                UC_ARM_REG_CPSR,
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
        self.r5_register = UC_ARM_REG_R5
        self.cpsr_register = UC_ARM_REG_CPSR
        self.symbols = symbols
        self.heap_allocate_result = 0
        self.heap_requests: list[int] = []
        self.heap_releases: list[int] = []
        self.resource_factory_calls: list[
            tuple[int, int, int, int, int, tuple[int, int, int]]
        ] = []
        self.resource_factory_result = 0
        self.resource_factory_value = 0xAABBCCDD
        self.registry_reset_calls: list[int] = []
        self.uc.mem_map(CODE_BASE, CODE_MAP_SIZE)
        self.uc.mem_write(CODE_BASE, code)
        self.uc.mem_map(RAM_BASE, RAM_MAP_SIZE)
        self.uc.mem_map(RETAILOS_ALLOC_ADDRESS & 0xFFFFF000, 0x1000)
        self.uc.mem_map(RETAILOS_TRACK_RESOURCE_FACTORY & 0xFFFFF000, 0x1000)
        self.uc.mem_map(RETAILOS_RESOURCE_REGISTRY_RESET & 0xFFFFF000, 0x1000)

        def handle_code(uc, address, _size, _user_data):
            if address == RETURN_ADDRESS:
                uc.emu_stop()
            elif address == RETAILOS_ALLOC_ADDRESS:
                self.heap_requests.append(uc.reg_read(self.regs[0]))
                uc.reg_write(self.regs[0], self.heap_allocate_result)
                uc.reg_write(self.pc_register, uc.reg_read(self.lr_register))
            elif address == RETAILOS_FREE_ADDRESS:
                self.heap_releases.append(uc.reg_read(self.regs[0]))
                self.return_from_mock(uc)
            elif address == RETAILOS_TRACK_RESOURCE_FACTORY:
                r0, r1, r2, r3 = (uc.reg_read(register) for register in self.regs)
                sp = uc.reg_read(self.sp_register)
                optional = struct.unpack("<I", uc.mem_read(sp, 4))[0]
                state = self.resource_gate_state()
                self.resource_factory_calls.append(
                    (r0, r1, r2, r3, optional, state)
                )
                if self.resource_factory_result == 0 and r3 != 0:
                    uc.mem_write(r3, struct.pack("<I", self.resource_factory_value))
                uc.reg_write(
                    self.regs[0], self.resource_factory_result & 0xFFFFFFFF
                )
                self.return_from_mock(uc)
            elif address == RETAILOS_RESOURCE_REGISTRY_RESET:
                self.registry_reset_calls.append(uc.reg_read(self.regs[0]))
                self.return_from_mock(uc)

        self.uc.hook_add(UC_HOOK_CODE, handle_code)

    def return_from_mock(self, uc) -> None:
        """Return from the mock using the saved interworking link register."""
        uc.reg_write(self.pc_register, uc.reg_read(self.lr_register))

    def resource_gate_state(self) -> tuple[int, int, int]:
        address = self.symbols["ipod_crossfade_resource_gate_state"]
        return struct.unpack("<3I", self.uc.mem_read(address, 12))

    def set_resource_gate_state(self, parent: int, track_id: int, armed: int) -> None:
        address = self.symbols["ipod_crossfade_resource_gate_state"]
        self.uc.mem_write(address, struct.pack("<3I", parent, track_id, armed))

    def call(
        self,
        name: str,
        args: tuple[int, ...],
        stack_args: tuple[int, ...] = (),
        *,
        thumb: bool = True,
        r5: int = 0,
    ) -> int:
        if len(args) > len(self.regs):
            raise ValueError("register argument count exceeds ARM calling convention")
        for register, value in zip(self.regs, args):
            self.uc.reg_write(register, value)
        stack = STACK_ADDRESS
        if stack_args:
            self.uc.mem_write(stack, struct.pack("<" + "I" * len(stack_args), *stack_args))
        self.uc.reg_write(self.sp_register, stack)
        self.uc.reg_write(self.r5_register, r5)
        self.uc.reg_write(self.lr_register, RETURN_ADDRESS | (1 if thumb else 0))
        entry = self.symbols[name] | (1 if thumb else 0)
        if not thumb:
            cpsr = self.uc.reg_read(self.cpsr_register)
            self.uc.reg_write(self.cpsr_register, cpsr & ~0x20)
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

    # The ARM interworking gate skips only the exact, armed parent/track pair.
    parent_context = 0x10930000
    track_id = 0x12345678
    emulator.uc.mem_write(
        FAKE_STREAM_ADDRESS + 4,
        struct.pack("<2I", parent_context, track_id),
    )
    emulator.set_resource_gate_state(parent_context, track_id, 1)
    reset_count = len(emulator.registry_reset_calls)
    assert emulator.call(
        "ipod_crossfade_resource_registry_reset_gate",
        (0xDEADBEEF,),
        thumb=False,
        r5=FAKE_STREAM_ADDRESS,
    ) == 0
    assert len(emulator.registry_reset_calls) == reset_count
    assert emulator.resource_gate_state() == (parent_context, track_id, 0)

    # An unarmed or mismatched call still reaches the stock reset function.
    emulator.set_resource_gate_state(parent_context, track_id, 0)
    assert emulator.call(
        "ipod_crossfade_resource_registry_reset_gate",
        (0xCAFEBABE,),
        thumb=False,
        r5=FAKE_STREAM_ADDRESS,
    ) == 0xCAFEBABE
    assert emulator.registry_reset_calls[-1] == 0xCAFEBABE
    emulator.set_resource_gate_state(parent_context, track_id, 1)
    emulator.uc.mem_write(
        FAKE_STREAM_ADDRESS + 8,
        struct.pack("<I", track_id + 1),
    )
    assert emulator.call(
        "ipod_crossfade_resource_registry_reset_gate",
        (0x0BADF00D,),
        thumb=False,
        r5=FAKE_STREAM_ADDRESS,
    ) == 0x0BADF00D
    assert emulator.registry_reset_calls[-1] == 0x0BADF00D
    assert emulator.resource_gate_state() == (parent_context, track_id, 1)
    emulator.uc.mem_write(
        FAKE_STREAM_ADDRESS + 4,
        struct.pack("<I", parent_context + 4),
    )
    assert emulator.call(
        "ipod_crossfade_resource_registry_reset_gate",
        (0x0D15EA5E,),
        thumb=False,
        r5=FAKE_STREAM_ADDRESS,
    ) == 0x0D15EA5E
    assert emulator.registry_reset_calls[-1] == 0x0D15EA5E
    assert emulator.resource_gate_state() == (parent_context, track_id, 1)
    emulator.uc.mem_write(
        FAKE_STREAM_ADDRESS + 4,
        struct.pack("<I", parent_context),
    )

    # The Thumb helper calls the ARM factory with stock ABI arguments, arms
    # one reset bypass, and clears that temporary state after the call.
    emulator.uc.mem_write(FAKE_PLAYER_ADDRESS, struct.pack("<I", parent_context))
    emulator.uc.mem_write(
        FAKE_PLAYER_ADDRESS + PLAYER_CURRENT_TRACK_OFFSET,
        struct.pack("<I", FAKE_TRACK_B_ADDRESS - 4),
    )
    emulator.uc.mem_write(
        FAKE_TRACK_B_ADDRESS + TRACK_ID_OFFSET,
        struct.pack("<I", track_id),
    )
    emulator.set_resource_gate_state(0, 0, 0)
    emulator.uc.mem_write(FAKE_RESOURCE_OUT_ADDRESS, struct.pack("<I", 0))
    emulator.resource_factory_result = 0
    emulator.resource_factory_value = 0xAABBCCDD
    calls_before = len(emulator.resource_factory_calls)
    resource_open_result = emulator.call(
        "ipod_crossfade_open_track_resource_b",
        (FAKE_PLAYER_ADDRESS, FAKE_TRACK_B_ADDRESS, FAKE_RESOURCE_OUT_ADDRESS),
    )
    assert resource_open_result == 0, (
        hex(resource_open_result),
        emulator.resource_factory_calls,
    )
    assert len(emulator.resource_factory_calls) == calls_before + 1
    factory_args = emulator.resource_factory_calls[-1]
    assert factory_args[:5] == (
        FAKE_PLAYER_ADDRESS,
        FAKE_TRACK_B_ADDRESS,
        0,
        FAKE_RESOURCE_OUT_ADDRESS,
        0,
    ), factory_args
    assert factory_args[5] == (parent_context, track_id, 1), factory_args
    assert struct.unpack(
        "<I", emulator.uc.mem_read(FAKE_RESOURCE_OUT_ADDRESS, 4)
    )[0] == 0xAABBCCDD
    assert emulator.resource_gate_state() == (0, 0, 0)

    # A failed factory call clears the output and also disarms the gate.
    emulator.uc.mem_write(FAKE_RESOURCE_OUT_ADDRESS, struct.pack("<I", 0xFFFFFFFF))
    emulator.resource_factory_result = -7
    assert emulator.call(
        "ipod_crossfade_open_track_resource_b",
        (FAKE_PLAYER_ADDRESS, FAKE_TRACK_B_ADDRESS, FAKE_RESOURCE_OUT_ADDRESS),
    ) == 0xFFFFFFF9
    assert struct.unpack(
        "<I", emulator.uc.mem_read(FAKE_RESOURCE_OUT_ADDRESS, 4)
    )[0] == 0
    assert emulator.resource_gate_state() == (0, 0, 0)

    # A zero track ID is allowed; the address/id pair remains the exact gate key.
    emulator.resource_factory_result = 0
    emulator.uc.mem_write(
        FAKE_TRACK_B_ADDRESS + TRACK_ID_OFFSET,
        struct.pack("<I", 0),
    )
    assert emulator.call(
        "ipod_crossfade_open_track_resource_b",
        (FAKE_PLAYER_ADDRESS, FAKE_TRACK_B_ADDRESS, FAKE_RESOURCE_OUT_ADDRESS),
    ) == 0
    assert emulator.resource_factory_calls[-1][5] == (parent_context, 0, 1)
    assert emulator.resource_gate_state() == (0, 0, 0)
    emulator.uc.mem_write(
        FAKE_TRACK_B_ADDRESS + TRACK_ID_OFFSET,
        struct.pack("<I", track_id),
    )

    # Refuse opening the already-current track or a concurrent nested request.
    calls_before = len(emulator.resource_factory_calls)
    emulator.uc.mem_write(
        FAKE_PLAYER_ADDRESS + PLAYER_CURRENT_TRACK_OFFSET,
        struct.pack("<I", FAKE_TRACK_B_ADDRESS),
    )
    assert emulator.call(
        "ipod_crossfade_open_track_resource_b",
        (FAKE_PLAYER_ADDRESS, FAKE_TRACK_B_ADDRESS, FAKE_RESOURCE_OUT_ADDRESS),
    ) == 0xFFFFFFFE
    assert len(emulator.resource_factory_calls) == calls_before
    emulator.uc.mem_write(
        FAKE_PLAYER_ADDRESS + PLAYER_CURRENT_TRACK_OFFSET,
        struct.pack("<I", FAKE_TRACK_B_ADDRESS - 4),
    )
    emulator.set_resource_gate_state(1, 2, 1)
    assert emulator.call(
        "ipod_crossfade_open_track_resource_b",
        (FAKE_PLAYER_ADDRESS, FAKE_TRACK_B_ADDRESS, FAKE_RESOURCE_OUT_ADDRESS),
    ) == 0xFFFFFFFE
    assert len(emulator.resource_factory_calls) == calls_before
    emulator.set_resource_gate_state(0, 0, 0)

    print("PASS: 5-frame stereo fade persists correctly across blocks")
    print("PASS: odd-length ramp reaches exact endpoints and supports in-place output")
    print("PASS: invalid channel count is rejected without advancing state")
    print("PASS: one-frame fade is rejected and oversized block is clipped")
    print("PASS: PCM ring validates runtime allocation size and rejects invalid geometry")
    print("PASS: PCM ring wraps read/write cursors and reports full/empty states")
    print("PASS: PCM ring calls the RetailOS heap API and frees unusable allocations")
    print("PASS: ARM reset gate skips only the armed matching parent/track resource")
    print("PASS: Thumb resource helper calls the mocked ARM factory and restores gate state")
    print("PASS: resource helper rejects current-track and nested-open requests")
    print("NOTE: RetailOS factory/reset calls are mocked; this is not device integration")


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
