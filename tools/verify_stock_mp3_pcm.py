#!/usr/bin/env python3
"""Emulate serialized A/B MP3 worker calls and inspect their PCM output.

The test runs exact local OSOS/HIBE/IRAM worker code, with separate mocked file
streams, a cloned callback/history for B, a synchronous sync-queue scheduler,
and one PP5022 MMIO value. It does not model queue concurrency or the physical
iPod. Install Unicorn with ``py -m pip install --target build/pydeps
-r requirements-emulation.txt``.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "build" / "pydeps"))
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from unicorn import (  # noqa: E402
    UC_ARCH_ARM,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
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
    UC_ARM_REG_CPSR,
)

from map_codec_overlay import load_ranges, load_zero_ranges  # noqa: E402
from verify_crossfade_mixer import load_symbols  # noqa: E402

DEFAULT_OSOS = PROJECT_ROOT / "firmware" / "extracted" / "audio-analysis" / "osos.bin"
DEFAULT_HIBE = PROJECT_ROOT / "build" / "audio-analysis" / "hibe.bin"
DEFAULT_IRAM = PROJECT_ROOT / "build" / "audio-analysis" / "iram-after-600m.bin"
DEFAULT_MP3 = (
    PROJECT_ROOT / "build" / "external" / "ipod-core" / "core" / "tests"
    / "codec-vectors" / "sine_440hz_1s_44k_s16_stereo_128k.mp3"
)
DEFAULT_MP3_B = (
    PROJECT_ROOT / "build" / "external" / "ipod-core" / "core" / "tests"
    / "codec-vectors" / "beethoven_2s_cbr128_44k_stereo.mp3"
)
DEFAULT_MIXER_BIN = PROJECT_ROOT / "build" / "crossfade-mixer" / "crossfade_mixer.bin"
DEFAULT_MIXER_ELF = PROJECT_ROOT / "build" / "crossfade-mixer" / "crossfade_mixer.elf"
DEFAULT_TOOLCHAIN_BIN = (
    PROJECT_ROOT / "build" / "toolchains" / "arm-gnu-14.3" / "unpacked" / "bin"
)
OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"
IRAM_BASE = 0x40000000
IRAM_SIZE = 0x20000
RAM_BASES = (0x00000000, 0x10000000, 0x14000000)
RAM_BYTES = 0x02000000
ITEM_ADDRESS = 0x20001000
ITEM_B_ADDRESS = 0x20005000
ITEM_BYTES = 0x3BEC
STACK_ADDRESS = 0x200F0000
STOP_ADDRESS = 0x200FF000
CALLBACK_RETURN = 0x200FF100
OUTPUT_ADDRESS = 0x20090000
OUTPUT_B_ADDRESS = 0x20092000
MIX_OUTPUT_ADDRESS = 0x20094000
MIX_STATE_ADDRESS = 0x20096000
MIXER_CODE_ADDRESS = 0x10712000
MIXER_CODE_WINDOW_BYTES = 16_804
FILE_BUFFER_ADDRESS = 0x20080000
FILE_BUFFER_B_ADDRESS = 0x20086000
CALLBACK_B_ADDRESS = 0x200B0000
CALLBACK_CONTEXT_B_ADDRESS = 0x200A0000
CALLBACK_CONTEXT_BYTES = 0x1110
PCM_BYTES = 4608
SAMPLE_RATE = 44100


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osos", type=Path, default=DEFAULT_OSOS)
    parser.add_argument("--hibe", type=Path, default=DEFAULT_HIBE)
    parser.add_argument("--iram", type=Path, default=DEFAULT_IRAM)
    parser.add_argument("--mp3", type=Path, default=DEFAULT_MP3)
    parser.add_argument("--mp3-b", type=Path, default=DEFAULT_MP3_B)
    parser.add_argument("--mixer-bin", type=Path, default=DEFAULT_MIXER_BIN)
    parser.add_argument("--mixer-elf", type=Path, default=DEFAULT_MIXER_ELF)
    parser.add_argument("--toolchain-bin", type=Path, default=DEFAULT_TOOLCHAIN_BIN)
    parser.add_argument(
        "--expected-hz", type=float, default=440.0,
        help="expected sine-wave frequency for the default verification vector",
    )
    return parser.parse_args()


def mp3_audio_offset(data: bytes) -> int:
    """Skip an ID3v2 tag and find the first MPEG audio frame sync."""
    offset = 0
    if data.startswith(b"ID3") and len(data) >= 10:
        size = sum((data[6 + index] & 0x7F) << (21 - 7 * index) for index in range(4))
        offset = 10 + size
        if data[5] & 0x10:
            offset += 10
    for candidate in range(offset, min(offset + 4096, len(data) - 1)):
        if data[candidate] == 0xFF and data[candidate + 1] & 0xE0 == 0xE0:
            return candidate
    raise ValueError("No MPEG audio frame found after the optional ID3v2 tag")


def load_emulator_inputs(
    args: argparse.Namespace,
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    missing = [str(path) for path in (
        args.osos, args.hibe, args.iram, args.mp3, args.mp3_b
    )
               if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing emulator input(s): " + ", ".join(missing))
    osos = args.osos.read_bytes()
    if len(osos) != 7_561_216:
        raise ValueError(f"Unexpected OSOS size: {len(osos):,} bytes")
    if hashlib.sha256(osos).hexdigest() != OSOS_SHA256:
        raise ValueError("OSOS SHA-256 does not match the audited RetailOS 1.3 image")
    hibe = args.hibe.read_bytes()
    if len(hibe) < 0x800 + RAM_BYTES:
        raise ValueError("HIBE input is too short for a 32 MiB RAM snapshot")
    iram = args.iram.read_bytes()
    if len(iram) < IRAM_SIZE:
        raise ValueError(f"IRAM capture is too short: {len(iram):,} bytes")
    return (
        osos,
        hibe[0x800:0x800 + RAM_BYTES],
        iram,
        args.mp3.read_bytes(),
        args.mp3_b.read_bytes(),
    )


def main() -> int:
    args = parse_args()
    osos, ram, iram_capture, file_data, file_data_b = load_emulator_inputs(args)
    required_mixer_files = (
        args.mixer_bin,
        args.mixer_elf,
        args.toolchain_bin / "arm-none-eabi-nm.exe",
    )
    missing_mixer_files = [str(path) for path in required_mixer_files if not path.is_file()]
    if missing_mixer_files:
        raise FileNotFoundError(
            "Build the crossfade payload first; missing: "
            + ", ".join(missing_mixer_files)
        )
    mixer_code = args.mixer_bin.read_bytes()
    if len(mixer_code) > MIXER_CODE_WINDOW_BYTES:
        raise ValueError(
            f"Crossfade payload exceeds the audited code window: "
            f"{len(mixer_code):,}/{MIXER_CODE_WINDOW_BYTES:,} bytes"
        )
    mixer_symbols = load_symbols(
        args.toolchain_bin / "arm-none-eabi-nm.exe",
        args.mixer_elf,
    )
    audio_offset = mp3_audio_offset(file_data)
    audio_offset_b = mp3_audio_offset(file_data_b)
    machine = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
    for base in RAM_BASES:
        machine.mem_map(base, RAM_BYTES)
        machine.mem_write(base, ram)
    if ram[:len(osos)] != osos:
        raise ValueError("HIBE RAM does not begin with the exact OSOS input")
    machine.mem_map(IRAM_BASE, IRAM_SIZE)
    machine.mem_map(0x60000000, 0x1000)
    # This PP5022 register selects the normal non-locking code path in the
    # captured worker environment. It is a test value, not a device write.
    machine.mem_write(0x60000000, struct.pack("<I", 0x55))
    machine.mem_write(IRAM_BASE, iram_capture[:IRAM_SIZE])
    for region in load_ranges(osos, 0):
        machine.mem_write(
            region.destination,
            osos[region.source:region.source + region.length],
        )
    for start, end in load_zero_ranges(osos, 0):
        machine.mem_write(start, bytes(end - start))
    machine.mem_write(MIXER_CODE_ADDRESS, mixer_code)

    machine.mem_map(0x20000000, 0x100000)
    item = ITEM_ADDRESS
    machine.mem_write(item, bytes(ITEM_BYTES))
    machine.mem_write(ITEM_B_ADDRESS, bytes(ITEM_BYTES))
    machine.mem_write(STOP_ADDRESS, b"\0" * 4)
    machine.mem_write(OUTPUT_ADDRESS, bytes(0x4000))
    output_b = OUTPUT_B_ADDRESS
    machine.mem_write(output_b, bytes(0x4000))
    machine.mem_write(FILE_BUFFER_ADDRESS, file_data)
    machine.mem_write(FILE_BUFFER_B_ADDRESS, file_data_b)

    last_pcs: list[int] = []
    last_call_instruction_count = [0]
    stream_positions = {0x20030000: 0, 0x2003A000: 0}
    stream_object = 0x20030000
    stream_b_object = 0x2003A000
    stream_vtable = 0x20031000
    stream_method_base = 0x200E0000
    metadata = 0x20032000
    parent = 0x20033000
    service_object = 0x20034000
    service_vtable = 0x20035000
    service_stub_base = 0x200E1000
    reader_object = 0x20036000
    reader_b_object = 0x20038000
    reader_vtable = 0x20037000
    reader_stub_base = 0x200E2000
    method_offsets = (0x00, 0x08, 0x0C, 0x10, 0x18, 0x20, 0x24, 0x28)
    callback_returns: list[tuple[int, int]] = []
    reader_positions = {reader_object: 0, reader_b_object: 0}
    reader_inputs = {
        reader_object: (file_data, FILE_BUFFER_ADDRESS),
        reader_b_object: (file_data_b, FILE_BUFFER_B_ADDRESS),
    }
    stream_inputs = {
        stream_object: (file_data, FILE_BUFFER_ADDRESS),
        stream_b_object: (file_data_b, FILE_BUFFER_B_ADDRESS),
    }

    machine.mem_write(stream_object, struct.pack("<I", stream_vtable))
    machine.mem_write(stream_b_object, struct.pack("<I", stream_vtable))
    for index in range(11):
        offset = index * 4
        method_index = method_offsets.index(offset) if offset in method_offsets else 0
        machine.mem_write(
            stream_vtable + offset,
            struct.pack("<I", stream_method_base + method_index * 0x20),
        )
    machine.mem_write(service_object, struct.pack("<I", service_vtable))
    machine.mem_write(service_vtable + 0x30, struct.pack("<I", service_stub_base))
    machine.mem_write(service_vtable + 0x3C, struct.pack("<I", service_stub_base + 0x20))
    machine.mem_write(reader_object, struct.pack("<I", reader_vtable))
    machine.mem_write(reader_b_object, struct.pack("<I", reader_vtable))
    machine.mem_write(reader_vtable + 0x08, struct.pack("<I", reader_stub_base))
    machine.mem_write(reader_vtable + 0x0C, struct.pack("<I", reader_stub_base + 0x20))
    metadata_words = [128000, SAMPLE_RATE, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]
    machine.mem_write(metadata, struct.pack("<12I", *metadata_words))
    machine.mem_write(parent + 0x297C, b"\0")
    machine.mem_write(item + 4, struct.pack("<I", parent))
    machine.mem_write(item + 0x3B9C, struct.pack("<I", stream_object))
    machine.mem_write(ITEM_B_ADDRESS + 4, struct.pack("<I", parent))
    machine.mem_write(ITEM_B_ADDRESS + 0x3B9C, struct.pack("<I", stream_b_object))

    def code_hook(uc, address, _size, _user_data):
        last_call_instruction_count[0] += 1
        last_pcs.append(address)
        if len(last_pcs) > 30:
            last_pcs.pop(0)
        if address == 0x4001CF90:
            queue = uc.reg_read(UC_ARM_REG_R0)
            capacity = struct.unpack("<I", uc.mem_read(queue + 0x40, 4))[0]
            completed = struct.unpack("<I", uc.mem_read(queue + 0x7C, 4))[0]
            callback = struct.unpack("<I", uc.mem_read(queue + 0x44, 4))[0]
            if capacity == 0 or callback == 0:
                raise RuntimeError("Captured MP3 queue has no callback or capacity")
            slot = completed % capacity
            submitted = struct.unpack("<I", uc.mem_read(queue + 0x78, 4))[0]
            uc.mem_write(queue + 0x78, struct.pack("<I", submitted + 1))
            callback_returns.append((queue, uc.reg_read(UC_ARM_REG_LR)))
            uc.reg_write(UC_ARM_REG_R0, callback)
            uc.reg_write(UC_ARM_REG_R1, slot)
            uc.reg_write(UC_ARM_REG_LR, CALLBACK_RETURN)
            uc.reg_write(UC_ARM_REG_PC, 0x101B1A10)
            return
        if address == CALLBACK_RETURN:
            queue, return_pc = callback_returns.pop()
            completed = struct.unpack("<I", uc.mem_read(queue + 0x7C, 4))[0]
            uc.mem_write(queue + 0x7C, struct.pack("<I", completed + 1))
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, return_pc)
            return
        if address in (0x4001D000, 0x4001D050, 0x4001D0CC):
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if address == reader_stub_base:
            reader = uc.reg_read(UC_ARM_REG_R0)
            reader_position = reader_positions[reader]
            source_data, _source_buffer = reader_inputs[reader]
            destination = uc.reg_read(UC_ARM_REG_R1)
            requested = uc.reg_read(UC_ARM_REG_R2)
            count = min(requested, len(source_data) - reader_position)
            if count > 0:
                uc.mem_write(
                    destination,
                    source_data[reader_position:reader_position + count],
                )
                reader_position += count
            reader_positions[reader] = reader_position
            uc.reg_write(UC_ARM_REG_R0, count)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if address == reader_stub_base + 0x20:
            reader = uc.reg_read(UC_ARM_REG_R0)
            source_data, _source_buffer = reader_inputs[reader]
            uc.reg_write(
                UC_ARM_REG_R0,
                int(reader_positions[reader] < len(source_data)),
            )
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if address == STOP_ADDRESS:
            uc.emu_stop()
            return
        if stream_method_base <= address < stream_method_base + len(method_offsets) * 0x20:
            method = method_offsets[(address - stream_method_base) // 0x20]
            this_object, arg1, arg2 = (uc.reg_read(register) for register in (
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2
            ))
            stream_position = stream_positions[this_object]
            source_data, source_buffer = stream_inputs[this_object]
            if method == 0x08:
                count = min(arg2, len(source_data) - stream_position)
                if count > 0:
                    uc.mem_write(
                        arg1,
                        source_data[stream_position:stream_position + count],
                    )
                    stream_position += count
                uc.reg_write(UC_ARM_REG_R0, count)
                uc.reg_write(UC_ARM_REG_R1, 0)
            elif method == 0x0C:
                start = stream_position
                count = min(arg2, len(source_data) - stream_position)
                uc.mem_write(arg1, struct.pack("<I", source_buffer + start))
                stream_position += count
                uc.reg_write(UC_ARM_REG_R0, count)
                uc.reg_write(UC_ARM_REG_R1, 0)
            elif method == 0x00:
                uc.reg_write(UC_ARM_REG_R0, 1)
            elif method == 0x18:
                # The real FSbuf +0x18 slot is an async request interface.
                uc.reg_write(UC_ARM_REG_R0, 0)
                uc.reg_write(UC_ARM_REG_R1, 0)
            elif method == 0x24:
                uc.reg_write(UC_ARM_REG_R0, stream_position)
            elif method == 0x28:
                uc.reg_write(UC_ARM_REG_R0, len(source_data))
            else:
                uc.reg_write(UC_ARM_REG_R0, 0)
                uc.reg_write(UC_ARM_REG_R1, 0)
            stream_positions[this_object] = stream_position
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if service_stub_base <= address <= service_stub_base + 0x20:
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if address == 0x14936AD0:
            uc.reg_write(UC_ARM_REG_R0, 0x14937180)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if address == 0x14936B50:
            uc.mem_write(uc.reg_read(UC_ARM_REG_R2), struct.pack("<I", service_object))
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    invalid_accesses: list[tuple[int, int, int, int]] = []

    def invalid_memory(uc, access, address, size, value, _user_data):
        invalid_accesses.append((access, address, size, uc.reg_read(UC_ARM_REG_PC)))
        return False

    machine.hook_add(UC_HOOK_CODE, code_hook)
    machine.hook_add(UC_HOOK_MEM_INVALID, invalid_memory)
    machine.hook_add(UC_HOOK_INTR, lambda uc, _intno, _user: uc.reg_write(UC_ARM_REG_R0, 0))

    def call(address: int, registers: tuple[int, ...]) -> int:
        last_call_instruction_count[0] = 0
        for register, value in zip(
            (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), registers
        ):
            machine.reg_write(register, value)
        machine.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)
        machine.reg_write(UC_ARM_REG_LR, STOP_ADDRESS)
        machine.reg_write(UC_ARM_REG_PC, address)
        try:
            machine.emu_start(address, STOP_ADDRESS, count=30_000_000)
        except UcError as exc:
            raise RuntimeError(
                f"Emulated function 0x{address:08x} failed at "
                f"0x{machine.reg_read(UC_ARM_REG_PC):08x}; "
                f"invalid access {invalid_accesses[-1:]}; "
                f"recent PCs: {[hex(pc) for pc in last_pcs[-8:]]}"
            ) from exc
        if machine.reg_read(UC_ARM_REG_PC) != STOP_ADDRESS:
            raise RuntimeError(f"Function 0x{address:08x} did not return")
        return machine.reg_read(UC_ARM_REG_R0)

    def call_thumb(
        address: int,
        registers: tuple[int, ...],
        stack_args: tuple[int, ...] = (),
    ) -> int:
        last_call_instruction_count[0] = 0
        for register, value in zip(
            (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3),
            registers,
        ):
            machine.reg_write(register, value)
        if stack_args:
            machine.mem_write(
                STACK_ADDRESS,
                struct.pack("<" + "I" * len(stack_args), *stack_args),
            )
        machine.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)
        machine.reg_write(UC_ARM_REG_LR, STOP_ADDRESS | 1)
        machine.reg_write(
            UC_ARM_REG_CPSR,
            machine.reg_read(UC_ARM_REG_CPSR) | 0x20,
        )
        entry = address | 1
        machine.reg_write(UC_ARM_REG_PC, entry)
        machine.emu_start(entry, STOP_ADDRESS, count=1_000_000)
        if machine.reg_read(UC_ARM_REG_PC) not in (STOP_ADDRESS, STOP_ADDRESS | 1):
            raise RuntimeError(f"Thumb payload function 0x{address:08x} did not return")
        return machine.reg_read(UC_ARM_REG_R0)

    call(0x4000BC9C, (item + 0x44, 0, 0))
    call(0x4000BC9C, (ITEM_B_ADDRESS + 0x44, 0, 0))
    call(0x10127DF4, (item, metadata, 0, reader_object))
    call(0x10127DF4, (ITEM_B_ADDRESS, metadata, 0, reader_b_object))
    if machine.mem_read(item + 0x3BC8, 1)[0]:
        raise RuntimeError("Stock MP3 item initialization set its failure flag")
    if machine.mem_read(ITEM_B_ADDRESS + 0x3BC8, 1)[0]:
        raise RuntimeError("Stock MP3 item B initialization set its failure flag")
    active_item_cell = 0x40013A64
    machine.mem_write(active_item_cell, struct.pack("<I", item + 0x44))
    machine.mem_write(0x4000248C, struct.pack("<I", OUTPUT_ADDRESS))
    machine.mem_write(0x40002510, struct.pack("<I", OUTPUT_ADDRESS))
    callback = struct.unpack("<I", machine.mem_read(0x149EE078 + 0x44, 4))[0]
    callback_context = struct.unpack("<I", machine.mem_read(callback + 0x0C, 4))[0]
    call(0x10124990, (callback_context,))
    callback_b = CALLBACK_B_ADDRESS
    callback_context_b = CALLBACK_CONTEXT_B_ADDRESS
    callback_bytes = bytes(machine.mem_read(callback, 0x20))
    machine.mem_write(callback_b, callback_bytes)
    machine.mem_write(callback_b + 0x0C, struct.pack("<I", callback_context_b))
    machine.mem_write(
        callback_context_b,
        bytes(machine.mem_read(callback_context, CALLBACK_CONTEXT_BYTES)),
    )
    call(0x10124990, (callback_context_b,))
    callback_context_b_reset = bytes(
        machine.mem_read(callback_context_b, CALLBACK_CONTEXT_BYTES)
    )
    # HIBE captured this shared queue idle; set its active-work flag in RAM.
    machine.mem_write(0x149EE078 + 0x80, struct.pack("<I", 1))
    stream_positions[stream_object] = audio_offset
    stream_positions[stream_b_object] = audio_offset_b
    reader_positions[reader_object] = audio_offset
    reader_positions[reader_b_object] = audio_offset_b

    worker_a_instructions: list[int] = []
    worker_a_nonzero_samples: list[int] = []
    worker_returns = []
    for _ in range(3):
        worker_returns.append(call(0x4000AE10, (item, OUTPUT_ADDRESS, PCM_BYTES)))
        worker_a_instructions.append(last_call_instruction_count[0])
        block = bytes(machine.mem_read(OUTPUT_ADDRESS, PCM_BYTES))
        block_samples = struct.unpack("<" + "h" * (len(block) // 2), block)
        worker_a_nonzero_samples.append(sum(sample != 0 for sample in block_samples))
    if worker_returns != [1, 1, 1]:
        raise RuntimeError(f"Unexpected A worker results: {worker_returns}")
    if machine.mem_read(item + 0x3BC8, 1)[0]:
        raise RuntimeError("Stock MP3 worker set its failure flag")
    pcm_bytes = bytes(machine.mem_read(OUTPUT_ADDRESS, PCM_BYTES))
    samples = struct.unpack("<" + "h" * (len(pcm_bytes) // 2), pcm_bytes)
    if not any(samples):
        raise RuntimeError("Stock MP3 worker produced a silent A block")
    history_a_before_b = bytes(
        machine.mem_read(callback_context, CALLBACK_CONTEXT_BYTES)
    )
    item_a_before_b = bytes(machine.mem_read(item, ITEM_BYTES))
    queue_submitted = struct.unpack("<I", machine.mem_read(0x149EE078 + 0x78, 4))[0]
    queue_completed = struct.unpack("<I", machine.mem_read(0x149EE078 + 0x7C, 4))[0]
    if queue_submitted != queue_completed:
        raise RuntimeError(
            f"Cannot switch contexts with pending jobs: "
            f"submitted={queue_submitted}, completed={queue_completed}"
        )
    machine.mem_write(0x149EE078 + 0x44, struct.pack("<I", callback_b))
    machine.mem_write(active_item_cell, struct.pack("<I", ITEM_B_ADDRESS + 0x44))
    machine.mem_write(0x4000248C, struct.pack("<I", output_b))
    machine.mem_write(0x40002510, struct.pack("<I", output_b))
    worker_b_instructions: list[int] = []
    worker_b_nonzero_samples: list[int] = []
    worker_b_returns = []
    for _ in range(4):
        worker_b_returns.append(
            call(0x4000AE10, (ITEM_B_ADDRESS, output_b, PCM_BYTES))
        )
        worker_b_instructions.append(last_call_instruction_count[0])
        block = bytes(machine.mem_read(output_b, PCM_BYTES))
        block_samples = struct.unpack("<" + "h" * (len(block) // 2), block)
        worker_b_nonzero_samples.append(sum(sample != 0 for sample in block_samples))
    if worker_b_returns != [1] * 4:
        raise RuntimeError(f"Unexpected B worker results: {worker_b_returns}")
    if machine.mem_read(ITEM_B_ADDRESS + 0x3BC8, 1)[0]:
        raise RuntimeError("Stock MP3 worker set item B's failure flag")
    pcm_b_bytes = bytes(machine.mem_read(output_b, PCM_BYTES))
    samples_b = struct.unpack("<" + "h" * (len(pcm_b_bytes) // 2), pcm_b_bytes)
    history_a_after = bytes(
        machine.mem_read(callback_context, CALLBACK_CONTEXT_BYTES)
    )
    history_b_after = bytes(
        machine.mem_read(callback_context_b, CALLBACK_CONTEXT_BYTES)
    )
    item_a_after_b = bytes(machine.mem_read(item, ITEM_BYTES))
    if history_a_after != history_a_before_b:
        raise RuntimeError("Decoding B changed A's separate synthesis history")
    if item_a_after_b != item_a_before_b:
        raise RuntimeError("Decoding B changed A's separate item state")
    if history_b_after == callback_context_b_reset:
        raise RuntimeError("Decoding B did not update its cloned synthesis history")
    if not any(samples_b) or samples_b == samples:
        raise RuntimeError("Stock MP3 worker did not produce distinct PCM for B")
    queue_submitted = struct.unpack("<I", machine.mem_read(0x149EE078 + 0x78, 4))[0]
    queue_completed = struct.unpack("<I", machine.mem_read(0x149EE078 + 0x7C, 4))[0]
    if queue_submitted != queue_completed:
        raise RuntimeError(
            f"Cannot resume A with pending jobs: "
            f"submitted={queue_submitted}, completed={queue_completed}"
        )
    machine.mem_write(0x149EE078 + 0x44, struct.pack("<I", callback))
    machine.mem_write(active_item_cell, struct.pack("<I", item + 0x44))
    machine.mem_write(0x4000248C, struct.pack("<I", OUTPUT_ADDRESS))
    machine.mem_write(0x40002510, struct.pack("<I", OUTPUT_ADDRESS))
    worker_a_resume = call(0x4000AE10, (item, OUTPUT_ADDRESS, PCM_BYTES))
    if machine.mem_read(item + 0x3BC8, 1)[0]:
        raise RuntimeError("Stock MP3 worker set item A's failure flag on resume")
    pcm_a_resume = bytes(machine.mem_read(OUTPUT_ADDRESS, PCM_BYTES))
    resume_samples = struct.unpack(
        "<" + "h" * (len(pcm_a_resume) // 2), pcm_a_resume
    )
    resume_left = resume_samples[::2]
    resume_crossings = sum(
        (resume_left[index] < 0 <= resume_left[index + 1])
        or (resume_left[index] > 0 >= resume_left[index + 1])
        for index in range(len(resume_left) - 1)
    )
    resume_hz = resume_crossings * SAMPLE_RATE / (2 * len(resume_left))
    if worker_a_resume != 1 or not any(resume_samples):
        raise RuntimeError("A did not resume with PCM after decoding B")
    if abs(resume_hz - args.expected_hz) > 60:
        raise RuntimeError(f"A resumed at unexpected frequency {resume_hz:.2f} Hz")
    left_samples = samples[::2]
    zero_crossings = sum(
        (left_samples[index] < 0 <= left_samples[index + 1])
        or (left_samples[index] > 0 >= left_samples[index + 1])
        for index in range(len(left_samples) - 1)
    )
    estimated_hz = zero_crossings * SAMPLE_RATE / (2 * len(left_samples))
    if not any(samples) or abs(estimated_hz - args.expected_hz) > 60:
        raise RuntimeError(
            f"PCM verification failed: {zero_crossings} zero crossings, "
            f"estimated {estimated_hz:.2f} Hz"
        )
    fade_frames = 3 * SAMPLE_RATE
    machine.mem_write(MIX_STATE_ADDRESS, bytes(28))
    machine.mem_write(MIX_OUTPUT_ADDRESS, bytes(PCM_BYTES))
    begin_result = call_thumb(
        mixer_symbols["ipod_crossfade_begin"],
        (MIX_STATE_ADDRESS, fade_frames),
    )
    if begin_result != 1:
        raise RuntimeError("ARM crossfade mixer rejected a three-second fade")
    mixed_frames = call_thumb(
        mixer_symbols["ipod_crossfade_mix_block"],
        (MIX_STATE_ADDRESS, OUTPUT_ADDRESS, output_b, MIX_OUTPUT_ADDRESS),
        (PCM_BYTES // 4, 2),
    )
    if mixed_frames != PCM_BYTES // 4:
        raise RuntimeError(f"Mixer processed only {mixed_frames} PCM frames")
    mixer_state = struct.unpack("<6IB3x", machine.mem_read(MIX_STATE_ADDRESS, 28))
    if mixer_state[0] != fade_frames or mixer_state[1] != mixed_frames or not mixer_state[6]:
        raise RuntimeError(f"Unexpected mixer state after one PCM block: {mixer_state}")
    mixed_pcm = bytes(machine.mem_read(MIX_OUTPUT_ADDRESS, PCM_BYTES))
    mixed_samples = struct.unpack("<" + "h" * (len(mixed_pcm) // 2), mixed_pcm)
    changed_samples = sum(
        mixed_samples[index] != resume_samples[index]
        for index in range(len(mixed_samples))
    )
    if not any(mixed_samples) or changed_samples == 0:
        raise RuntimeError("ARM mixer did not combine the decoded A/B PCM blocks")
    print("PASS: stock provider-0 worker decoded A, then B, then resumed A in emulation")
    print(f"  A input: {args.mp3} ({len(file_data):,} bytes; audio offset {audio_offset})")
    print(f"  A worker returns: {worker_returns}")
    print(f"  A emulated instruction count per call: {worker_a_instructions}")
    print(f"  A nonzero output samples after each call: {worker_a_nonzero_samples}")
    print(f"  A PCM16 stereo block: {sum(value != 0 for value in samples)}/{len(samples)} "
          f"nonzero samples; range {min(samples)}..{max(samples)}")
    print(f"  A tone estimate: {estimated_hz:.2f} Hz; A resume: {resume_hz:.2f} Hz")
    print(f"  B input: {args.mp3_b} ({len(file_data_b):,} bytes; audio offset {audio_offset_b})")
    print(f"  B worker returns: {worker_b_returns}")
    print(f"  B emulated instruction count per call: {worker_b_instructions}")
    print(f"  B nonzero output samples after each call: {worker_b_nonzero_samples}")
    print(f"  B PCM16 stereo block: {sum(value != 0 for value in samples_b)}/{len(samples_b)} "
          f"nonzero; range {min(samples_b)}..{max(samples_b)}")
    print("  PASS: B used its cloned synthesis history; A item and history stayed intact")
    print(f"  PASS: ARM mixer combined decoded A/B PCM for {mixed_frames} frames "
          f"inside a three-second fade ({mixer_state[1]}/{mixer_state[0]} frames done)")
    print("  Scope: instruction counts are emulator counts, not measured CPU cycles. "
          "Callbacks are dispatched synchronously at an idle queue boundary; "
          "file I/O, queue scheduling, and MMIO are mocked. No physical playback.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
