#!/usr/bin/env python3
"""Emulate RetailOS 1.3's stock MP3 worker and measure one decoded PCM block.

The test uses exact local OSOS/HIBE/IRAM inputs, while mocking the file stream,
the sync worker schedule, and one PP5022 MMIO value. It verifies the single-
track decode path only; it does not simulate two tracks or the physical iPod.
Install Unicorn with ``py -m pip install --target build/pydeps
-r requirements-emulation.txt``.
"""
from __future__ import annotations

import argparse
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
)

from map_codec_overlay import load_ranges, load_zero_ranges  # noqa: E402

DEFAULT_OSOS = PROJECT_ROOT / "firmware" / "extracted" / "audio-analysis" / "osos.bin"
DEFAULT_HIBE = PROJECT_ROOT / "build" / "audio-analysis" / "hibe.bin"
DEFAULT_IRAM = PROJECT_ROOT / "build" / "audio-analysis" / "iram-after-600m.bin"
DEFAULT_MP3 = (
    PROJECT_ROOT / "build" / "external" / "ipod-core" / "core" / "tests"
    / "codec-vectors" / "sine_440hz_1s_44k_s16_stereo_128k.mp3"
)
OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"
IRAM_BASE = 0x40000000
IRAM_SIZE = 0x20000
RAM_BASES = (0x00000000, 0x10000000, 0x14000000)
RAM_BYTES = 0x02000000
ITEM_ADDRESS = 0x20001000
ITEM_BYTES = 0x3BEC
STACK_ADDRESS = 0x200F0000
STOP_ADDRESS = 0x200FF000
CALLBACK_RETURN = 0x200FF100
OUTPUT_ADDRESS = 0x20090000
FILE_BUFFER_ADDRESS = 0x20080000
PCM_BYTES = 4608
SAMPLE_RATE = 44100


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osos", type=Path, default=DEFAULT_OSOS)
    parser.add_argument("--hibe", type=Path, default=DEFAULT_HIBE)
    parser.add_argument("--iram", type=Path, default=DEFAULT_IRAM)
    parser.add_argument("--mp3", type=Path, default=DEFAULT_MP3)
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


def load_emulator_inputs(args: argparse.Namespace) -> tuple[bytes, bytes, bytes, bytes]:
    missing = [str(path) for path in (args.osos, args.hibe, args.iram, args.mp3)
               if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing emulator input(s): " + ", ".join(missing))
    osos = args.osos.read_bytes()
    if len(osos) != 7_561_216:
        raise ValueError(f"Unexpected OSOS size: {len(osos):,} bytes")
    import hashlib

    if hashlib.sha256(osos).hexdigest() != OSOS_SHA256:
        raise ValueError("OSOS SHA-256 does not match the audited RetailOS 1.3 image")
    hibe = args.hibe.read_bytes()
    if len(hibe) < 0x800 + RAM_BYTES:
        raise ValueError("HIBE input is too short for a 32 MiB RAM snapshot")
    iram = args.iram.read_bytes()
    if len(iram) < IRAM_SIZE:
        raise ValueError(f"IRAM capture is too short: {len(iram):,} bytes")
    return osos, hibe[0x800:0x800 + RAM_BYTES], iram, args.mp3.read_bytes()


def main() -> int:
    args = parse_args()
    osos, ram, iram_capture, file_data = load_emulator_inputs(args)
    audio_offset = mp3_audio_offset(file_data)
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

    machine.mem_map(0x20000000, 0x100000)
    item = ITEM_ADDRESS
    machine.mem_write(item, bytes(ITEM_BYTES))
    machine.mem_write(STOP_ADDRESS, b"\0" * 4)
    machine.mem_write(OUTPUT_ADDRESS, bytes(0x4000))
    machine.mem_write(FILE_BUFFER_ADDRESS, file_data)

    last_pcs: list[int] = []
    stream_position = 0
    stream_object = 0x20030000
    stream_vtable = 0x20031000
    stream_method_base = 0x200E0000
    metadata = 0x20032000
    parent = 0x20033000
    service_object = 0x20034000
    service_vtable = 0x20035000
    service_stub_base = 0x200E1000
    reader_object = 0x20036000
    reader_vtable = 0x20037000
    reader_stub_base = 0x200E2000
    method_offsets = (0x00, 0x08, 0x0C, 0x10, 0x18, 0x20, 0x24, 0x28)
    callback_returns: list[tuple[int, int]] = []
    reader_position = 0

    machine.mem_write(stream_object, struct.pack("<I", stream_vtable))
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
    machine.mem_write(reader_vtable + 0x08, struct.pack("<I", reader_stub_base))
    machine.mem_write(reader_vtable + 0x0C, struct.pack("<I", reader_stub_base + 0x20))
    metadata_words = [128000, SAMPLE_RATE, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]
    machine.mem_write(metadata, struct.pack("<12I", *metadata_words))
    machine.mem_write(parent + 0x297C, b"\0")
    machine.mem_write(item + 4, struct.pack("<I", parent))
    machine.mem_write(item + 0x3B9C, struct.pack("<I", stream_object))

    def code_hook(uc, address, _size, _user_data):
        nonlocal stream_position
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
            nonlocal reader_position
            destination = uc.reg_read(UC_ARM_REG_R1)
            requested = uc.reg_read(UC_ARM_REG_R2)
            count = min(requested, len(file_data) - reader_position)
            if count > 0:
                uc.mem_write(
                    destination,
                    file_data[reader_position:reader_position + count],
                )
                reader_position += count
            uc.reg_write(UC_ARM_REG_R0, count)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if address == reader_stub_base + 0x20:
            uc.reg_write(UC_ARM_REG_R0, int(reader_position < len(file_data)))
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if address == STOP_ADDRESS:
            uc.emu_stop()
            return
        if stream_method_base <= address < stream_method_base + len(method_offsets) * 0x20:
            method = method_offsets[(address - stream_method_base) // 0x20]
            _this, arg1, arg2 = (uc.reg_read(register) for register in (
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2
            ))
            if method == 0x08:
                count = min(arg2, len(file_data) - stream_position)
                if count > 0:
                    uc.mem_write(
                        arg1,
                        file_data[stream_position:stream_position + count],
                    )
                    stream_position += count
                uc.reg_write(UC_ARM_REG_R0, count)
                uc.reg_write(UC_ARM_REG_R1, 0)
            elif method == 0x0C:
                start = stream_position
                count = min(arg2, len(file_data) - stream_position)
                uc.mem_write(arg1, struct.pack("<I", FILE_BUFFER_ADDRESS + start))
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
                uc.reg_write(UC_ARM_REG_R0, len(file_data))
            else:
                uc.reg_write(UC_ARM_REG_R0, 0)
                uc.reg_write(UC_ARM_REG_R1, 0)
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

    call(0x4000BC9C, (item + 0x44, 0, 0))
    call(0x10127DF4, (item, metadata, 0, reader_object))
    if machine.mem_read(item + 0x3BC8, 1)[0]:
        raise RuntimeError("Stock MP3 item initialization set its failure flag")
    active_item_cell = 0x40013A64
    machine.mem_write(active_item_cell, struct.pack("<I", item + 0x44))
    machine.mem_write(0x4000248C, struct.pack("<I", OUTPUT_ADDRESS))
    machine.mem_write(0x40002510, struct.pack("<I", OUTPUT_ADDRESS))
    callback = struct.unpack("<I", machine.mem_read(0x149EE078 + 0x44, 4))[0]
    callback_context = struct.unpack("<I", machine.mem_read(callback + 0x0C, 4))[0]
    call(0x10124990, (callback_context,))
    # HIBE captured this shared queue idle; set its active-work flag in RAM.
    machine.mem_write(0x149EE078 + 0x80, struct.pack("<I", 1))
    stream_position = audio_offset
    reader_position = audio_offset

    worker_returns = [call(0x4000AE10, (item, OUTPUT_ADDRESS, PCM_BYTES))
                      for _ in range(3)]
    if machine.mem_read(item + 0x3BC8, 1)[0]:
        raise RuntimeError("Stock MP3 worker set its failure flag")
    pcm_bytes = bytes(machine.mem_read(OUTPUT_ADDRESS, PCM_BYTES))
    samples = struct.unpack("<" + "h" * (len(pcm_bytes) // 2), pcm_bytes)
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
    print("PASS: stock provider-0 produced audible-shape PCM in emulation")
    print(f"  input: {args.mp3} ({len(file_data):,} bytes; audio offset {audio_offset})")
    print(f"  worker returns: {worker_returns}")
    print(f"  PCM16 stereo block: {sum(value != 0 for value in samples)}/{len(samples)} "
          f"nonzero samples; range {min(samples)}..{max(samples)}")
    print(f"  left-channel zero crossings: {zero_crossings}; "
          f"estimated tone: {estimated_hz:.2f} Hz")
    print("  Scope: single-track decode only; I/O, queue scheduling, and MMIO are mocked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
