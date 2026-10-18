#!/usr/bin/env python3
"""Inspect known RetailOS audio objects in an iPod Video HIBE RAM snapshot."""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from inspect_firmware_partition import parse_images

SECTOR_SIZE = 2048
RAM_BASE = 0x10000000
RAM_SIZE = 0x02000000
HIBE_SNAPSHOT_OFFSET = 0x800
OSOS_SIZE = 7_561_216


def component(raw: bytes, entries: list[dict[str, int | str | bool | None]], name: str) -> bytes:
    matches = [entry for entry in entries if entry["type"] == name]
    if len(matches) != 1 or not matches[0]["range_valid"]:
        raise ValueError(f"expected one valid {name} component")
    entry = matches[0]
    start, length = int(entry["image_start"]), int(entry["length"])
    return raw[start:start + length]


class Snapshot:
    def __init__(self, hibe: bytes) -> None:
        if len(hibe) < HIBE_SNAPSHOT_OFFSET + RAM_SIZE:
            raise ValueError("HIBE does not contain a complete 32 MiB RAM snapshot")
        self.hibe = hibe

    def read(self, address: int, length: int) -> bytes:
        if address < RAM_BASE or address + length > RAM_BASE + RAM_SIZE:
            raise ValueError(f"RAM range 0x{address:08x}+0x{length:x} is outside snapshot")
        offset = HIBE_SNAPSHOT_OFFSET + address - RAM_BASE
        return self.hibe[offset:offset + length]

    def u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]

    @staticmethod
    def native_ram_address(address: int) -> int:
        """Resolve the PP5022C uncached SDRAM alias to the native window."""
        if 0x14000000 <= address < 0x18000000:
            return 0x10000000 | (address & 0x03FFFFFF)
        return address

    def find_vtable(self, offset: int) -> list[int]:
        needle = struct.pack("<I", offset)
        cursor = HIBE_SNAPSHOT_OFFSET + OSOS_SIZE
        found: list[int] = []
        while True:
            position = self.hibe.find(needle, cursor)
            if position < 0:
                return found
            if (position - HIBE_SNAPSHOT_OFFSET) % 4 == 0:
                found.append(RAM_BASE + position - HIBE_SNAPSHOT_OFFSET)
            cursor = position + 1

    def find_runtime_ascii(self, needle: bytes) -> list[tuple[int, str]]:
        """Find NUL-terminated ASCII strings after HIBE's copied OSOS image."""
        cursor = HIBE_SNAPSHOT_OFFSET + OSOS_SIZE
        found: list[tuple[int, str]] = []
        while True:
            position = self.hibe.find(needle, cursor)
            if position < 0:
                return found
            end = self.hibe.find(b"\0", position)
            if end < 0:
                end = len(self.hibe)
            address = RAM_BASE + position - HIBE_SNAPSHOT_OFFSET
            value = self.hibe[position:end].decode("ascii", errors="replace")
            found.append((address, value))
            cursor = position + len(needle)


def inspect_decoder_sync_objects(snapshot: Snapshot) -> None:
    """Inspect captured MP3/AAC sync queues using their shared vtable.

    Queue capacity and two output slots describe frame scheduling. A queue
    for another codec does not establish a second instance for the same track
    format or prove that PCM was played. Resolve uncached aliases at each
    pointer dereference, since callback vtables are in RAM.
    """
    for queue in snapshot.find_vtable(0x00676944):
        name = snapshot.read(queue + 0x1C, 24).split(b"\0", 1)[0]
        if not name.startswith((b"mp3dec_sync", b"mp4_aacdec_sync")):
            continue
        callback_pointer = snapshot.u32(queue + 0x44)
        print(f"Saved decoder sync {name.decode('ascii', errors='replace')!r} "
              f"at RAM 0x{queue:08x}")
        print(f"  slots={snapshot.u32(queue + 0x40)}, "
              f"submitted={snapshot.u32(queue + 0x78)}, "
              f"completed={snapshot.u32(queue + 0x7C)}")
        if callback_pointer == 0:
            print("  no callback is attached in this snapshot")
            continue
        callback = snapshot.native_ram_address(callback_pointer)
        table = snapshot.native_ram_address(snapshot.u32(callback))
        print(f"  callback RAM 0x{callback:08x}; vtable RAM 0x{table:08x}")
        for slot in (0x04, 0x0C, 0x1C, 0x20):
            print(f"    method +0x{slot:02x}: 0x{snapshot.u32(table + slot):08x}")
        for field in (0x04, 0x08, 0x0C, 0x10, 0x14):
            print(f"    callback field +0x{field:02x}: "
                  f"0x{snapshot.u32(callback + field):08x}")
    print("Saved state only; queues for different codecs are not two tracks.")


def find_pcm_provider_geometry(snapshot: Snapshot) -> list[tuple[int, int, int, int, int]]:
    """Find aligned RAM objects matching this snapshot's PCM-provider geometry.

    This is a snapshot-specific heuristic, not a general object detector.
    Matching geometry does not prove that an object feeds music playback.
    """
    ram = snapshot.read(RAM_BASE, RAM_SIZE)
    candidates: list[tuple[int, int, int, int, int]] = []
    for offset in range(0, len(ram) - 0x38, 4):
        channels = struct.unpack_from("<I", ram, offset + 0x24)[0]
        block_size = struct.unpack_from("<I", ram, offset + 0x28)[0]
        stride = struct.unpack_from("<I", ram, offset + 0x2C)[0]
        count = struct.unpack_from("<I", ram, offset + 0x34)[0]
        if (channels, block_size, stride, count) == (3, 0x12000, 0x4000, 32):
            data = struct.unpack_from("<I", ram, offset + 0x20)[0]
            descriptors = struct.unpack_from("<I", ram, offset + 0x30)[0]
            candidates.append((RAM_BASE + offset, data, descriptors, block_size, count))
    return candidates


def inspect_audio_provider_registry(snapshot: Snapshot) -> None:
    """Print saved provider objects selected by the audio worker.

    The list is an observed object registry, not proof that each entry is a
    music codec or that multiple entries can decode songs concurrently.
    """
    player = 0x10939F60
    table_word = snapshot.u32(player + 0x0C)
    table = (RAM_BASE + table_word if table_word < OSOS_SIZE
             else snapshot.native_ram_address(table_word))
    selected = snapshot.u32(player + 0x10)
    print(f"Audio worker RAM 0x{player:08x}; provider table "
          f"0x{table_word:08x} (RAM 0x{table:08x}); selected={selected}")
    if not RAM_BASE <= table < RAM_BASE + RAM_SIZE - 8 * 4:
        print("  provider table is outside captured RAM")
        return

    for index in range(8):
        provider_alias = snapshot.u32(table + index * 4)
        if provider_alias == 0:
            break
        provider = snapshot.native_ram_address(provider_alias)
        if not RAM_BASE <= provider < RAM_BASE + RAM_SIZE - 12:
            print(f"  provider {index}: object 0x{provider_alias:08x} "
                  "outside captured RAM")
            continue
        vtable_word = snapshot.u32(provider)
        vtable = (RAM_BASE + vtable_word if vtable_word < OSOS_SIZE
                  else snapshot.native_ram_address(vtable_word))
        if RAM_BASE <= vtable < RAM_BASE + RAM_SIZE - 16:
            matcher = snapshot.u32(vtable)
            constructor = snapshot.u32(vtable + 4)
            print(f"  provider {index}: object 0x{provider_alias:08x}, "
                  f"vtable 0x{vtable_word:08x}, "
                  f"type-match method 0x{matcher:08x}, "
                  f"create method 0x{constructor:08x}, "
                  f"saved index/state={snapshot.u32(provider + 4)}/"
                  f"{snapshot.u32(provider + 8)}")
        else:
            print(f"  provider {index}: vtable 0x{vtable_word:08x} "
                  "outside captured RAM")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="read-only firmware partition backup")
    parser.add_argument("--sector-size", type=int, default=SECTOR_SIZE)
    args = parser.parse_args()
    if args.sector_size <= 0:
        parser.error("sector size must be positive")

    try:
        raw = args.image.read_bytes()
        version, entries = parse_images(raw, args.sector_size)
        osos = component(raw, entries, "OSOS")
        hibe = component(raw, entries, "HIBE")
        snapshot = Snapshot(hibe)
        if len(osos) != OSOS_SIZE:
            raise ValueError(f"unexpected OSOS size: {len(osos)}")
        if snapshot.read(RAM_BASE, len(osos)) != osos:
            raise ValueError("HIBE RAM start does not match the OSOS component")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Backup SHA-256: {hashlib.sha256(raw).hexdigest()}")
    print(f"Firmware format: {version}; OSOS/HIBE: {len(osos):,}/{len(hibe):,} bytes")

    video_core_paths = snapshot.find_runtime_ascii(b"Resources/VideoCore/Library/")
    print(f"VideoCore library path strings after copied OSOS: {len(video_core_paths)}")
    for address, path in video_core_paths:
        print(f"  RAM 0x{address:08x}: {path}")
    runtime_pcmplayer = snapshot.find_runtime_ascii(b"pcmplayer.vll")
    print(f"Runtime pcmplayer.vll path strings after copied OSOS: {len(runtime_pcmplayer)}")
    for address, path in runtime_pcmplayer:
        print(f"  RAM 0x{address:08x}: {path}")

    # The playback object pointer is stored through the uncached SDRAM alias.
    # HIBE contains only the lower 32 MiB of the 5.5G's 64 MiB SDRAM, so only
    # report an object body when its normalized address is in that snapshot.
    queue = snapshot.native_ram_address(0x149388B0)
    item_alias = snapshot.u32(queue + 0x78)
    item = snapshot.native_ram_address(item_alias)
    print(f"TPCMQUEUE object RAM 0x{queue:08x}; +0x78 item pointer: 0x{item_alias:08x} "
          f"(native alias 0x{item:08x})")
    if RAM_BASE <= item < RAM_BASE + RAM_SIZE:
        item_vtable = snapshot.u32(item)
        print(f"  captured item vtable offset: 0x{item_vtable:08x}")
        if item_vtable == 0x00666284:
            fsbuf = item + 0x270
            print(f"  playback wrapper's FSbuf at RAM 0x{fsbuf:08x}; "
                  f"vtable offset 0x{snapshot.u32(fsbuf):08x}")
    else:
        print("  item body is outside the RAM captured by HIBE")

    # The OSOS startup object named RMIprimary links to this TPCMQUEUE.
    # Confirm the relationship in the saved RAM instead of relying only on
    # the static constructor's global addresses.
    primary_task = 0x1093733C
    if snapshot.u32(primary_task) == 0x00666348:
        primary_queue_alias = snapshot.u32(primary_task + 0x4C)
        primary_queue = snapshot.native_ram_address(primary_queue_alias)
        print(f"RMIprimary task RAM 0x{primary_task:08x}; "
              f"vtable offset 0x{snapshot.u32(primary_task):08x}; "
              f"+0x4c TPCMQUEUE 0x{primary_queue_alias:08x} "
              f"(native 0x{primary_queue:08x})")
        if primary_queue != queue:
            print("  RMIprimary queue pointer differs from the inspected TPCMQUEUE")
    else:
        print(f"RMIprimary task object not confirmed at RAM 0x{primary_task:08x}")

    inspect_audio_provider_registry(snapshot)

    # TPCMQUEUE's provider is separate from the file wrapper.  Its descriptor
    # array points into a preallocated buffer region.  Report descriptor and
    # sample statistics as observations only: a static RAM snapshot cannot
    # establish the upstream decoder or prove a second track was active.
    provider_alias = snapshot.u32(queue + 0x5C)
    provider = snapshot.native_ram_address(provider_alias)
    print(f"TPCMQUEUE mode +0x65={snapshot.read(queue + 0x65, 1)[0]}; "
          f"worker gate +0xc8={snapshot.read(queue + 0xC8, 1)[0]}")
    print(f"TPCMQUEUE provider pointer: 0x{provider_alias:08x} "
          f"(native alias 0x{provider:08x})")
    if RAM_BASE <= provider < RAM_BASE + RAM_SIZE:
        data_alias = snapshot.u32(provider + 0x20)
        data_base = snapshot.native_ram_address(data_alias)
        geometry = tuple(snapshot.u32(provider + offset)
                         for offset in (0x24, 0x28, 0x2C))
        descriptor_alias = snapshot.u32(provider + 0x30)
        descriptors = snapshot.native_ram_address(descriptor_alias)
        descriptor_count = snapshot.u32(provider + 0x34)
        print(f"  buffer base 0x{data_alias:08x} (native 0x{data_base:08x}); "
              f"provider fields +0x24/+0x28/+0x2c="
              f"{geometry[0]}/0x{geometry[1]:x}/0x{geometry[2]:x}")
        print(f"  descriptor table 0x{descriptor_alias:08x} "
              f"(native 0x{descriptors:08x}); capacity={descriptor_count}")
        if 0 < descriptor_count <= 256 and RAM_BASE <= descriptors < RAM_BASE + RAM_SIZE:
            allocated: list[tuple[int, int, int, int]] = []
            states_by_count: dict[int, int] = {}
            for index in range(descriptor_count):
                entry = descriptors + index * 0x1C
                address_alias = snapshot.u32(entry)
                length = snapshot.u32(entry + 4)
                state = snapshot.u32(entry + 0x10)
                states_by_count[state] = states_by_count.get(state, 0) + 1
                if address_alias and length:
                    address = snapshot.native_ram_address(address_alias)
                    allocated.append((index, address, length, state))
            print(f"  descriptor states: {dict(sorted(states_by_count.items()))}; "
                  f"allocated buffers: {len(allocated)}/{descriptor_count}")
            # The exact IRAM consumer used in mode 0 acquires state 8. State 3
            # can be acquired on the producer side and does not prove that the
            # buffer currently holds valid, unread audio samples.
            if snapshot.read(queue + 0x65, 1)[0] == 0:
                print(f"  mode-0 consumer-ready (state 8): "
                      f"{states_by_count.get(8, 0)}")
            payload = bytearray()
            valid = 0
            for index, address, length, state in allocated:
                if length > 0x20000:
                    print(f"    descriptor {index}: unreasonable length 0x{length:x}; skipped")
                    continue
                try:
                    block = snapshot.read(address, length)
                except ValueError:
                    print(f"    descriptor {index}: data outside captured RAM; skipped")
                    continue
                valid += 1
                payload.extend(block)
                if index == allocated[0][0]:
                    sample_bytes = block[:len(block) & ~1]
                    samples = struct.unpack(f"<{len(sample_bytes) // 2}h", sample_bytes)
                    print(f"    first descriptor {index}: RAM 0x{address:08x}, "
                          f"length=0x{length:x}, state={state}, "
                          f"nonzero={sum(byte != 0 for byte in block)}/{len(block)}, "
                          f"int16 min/max={min(samples)}/{max(samples)}, "
                          f"SHA-256 {hashlib.sha256(block).hexdigest()}")
            if valid:
                samples = struct.unpack(f"<{len(payload) // 2}h", payload[:len(payload) & ~1])
                nonzero = sum(byte != 0 for byte in payload)
                strides = sorted({allocated[i + 1][1] - allocated[i][1]
                                  for i in range(len(allocated) - 1)})
                lengths = sorted({item[2] for item in allocated})
                states = sorted({item[3] for item in allocated})
                print(f"  allocated descriptor payload (may be stale): "
                      f"{valid} blocks, "
                      f"lengths={','.join(f'0x{x:x}' for x in lengths)}, "
                      f"states={states}, address strides="
                      f"{','.join(f'0x{x:x}' for x in strides) or 'n/a'}")
                print(f"  payload bytes={len(payload)}; nonzero={nonzero}; "
                      f"SHA-256 {hashlib.sha256(payload).hexdigest()}")
                print(f"  int16 view (diagnostic only): min={min(samples)}, "
                      f"max={max(samples)}, unique={len(set(samples))}")
    else:
        print("  provider body is outside the RAM captured by HIBE")

    provider_candidates = find_pcm_provider_geometry(snapshot)
    print("PCM-provider geometry candidates across captured RAM: "
          f"{len(provider_candidates)}")
    for address, data, descriptors, block_size, capacity in provider_candidates:
        print(f"  RAM 0x{address:08x}: data=0x{data:08x}, "
              f"descriptors=0x{descriptors:08x}, block=0x{block_size:x}, "
              f"capacity={capacity}")

    for name, vtable in (
        ("playback wrapper", 0x00666284),
        ("FSbuf", 0x00674628),
        ("shared sync/resource object", 0x0066E0C4),
    ):
        instances = snapshot.find_vtable(vtable)
        print(f"Captured {name} vtable references: {len(instances)}")
        for address in instances[:8]:
            print(f"  RAM 0x{address:08x}")

    manager_global = 0x1081ECC8
    manager = snapshot.u32(manager_global)
    manager_vtable = snapshot.u32(manager)
    type1_queue = snapshot.u32(manager + 0x44)
    type1_capacity = snapshot.u32(type1_queue + 4)
    type1_head = snapshot.u32(type1_queue + 0x0C)
    type1_tail = snapshot.u32(type1_queue + 0x10)
    type1_active = snapshot.u32(type1_queue + 0x14)
    type1_items = snapshot.u32(type1_queue + 0x18)
    request_method = snapshot.u32(RAM_BASE + manager_vtable + 0x28)
    print(f"Interface manager pointer at RAM 0x{manager_global:08x}: 0x{manager:08x}")
    print(f"  vtable offset: 0x{manager_vtable:08x}; request method (+0x28): 0x{request_method:08x}")
    print(f"  type-1 registry: RAM 0x{type1_queue:08x}; active={type1_active}, "
          f"head={type1_head}, tail={type1_tail}, capacity={type1_capacity}")
    if type1_active and 0 < type1_capacity <= 256:
        index = type1_head
        while index != type1_tail:
            item = snapshot.u32(type1_items + index * 4)
            print(f"    queued object RAM 0x{item:08x}; vtable offset 0x{snapshot.u32(item):08x}")
            index = (index + 1) % type1_capacity

    parent = 0x109DD438
    i2s = parent + 0x54
    child = parent + 0x360
    print(f"I2S subobject RAM 0x{i2s:08x}: vtable offset 0x{snapshot.u32(i2s):08x}")
    print(f"I2S buffer-path object RAM 0x{child:08x}: vtable offset 0x{snapshot.u32(child):08x}")
    print("Buffer-path fields +0x20/+0x24: "
          f"0x{snapshot.u32(child + 0x20):08x}/0x{snapshot.u32(child + 0x24):08x}")

    callback_vtable = 0x66D308
    for callback in snapshot.find_vtable(callback_vtable):
        endpoint = snapshot.u32(callback + 4)
        destination = snapshot.u32(endpoint + 0x1C)
        buffer = snapshot.u32(endpoint + 0x20)
        alternate_buffer = snapshot.u32(endpoint + 0x14)
        length = snapshot.u32(endpoint + 0x24)
        print(f"I2S callback RAM 0x{callback:08x}: endpoint RAM 0x{endpoint:08x}; "
              f"destination 0x{destination:08x}, buffer slots "
              f"0x{buffer:08x}/0x{alternate_buffer:08x}, length 0x{length:x}, "
              f"slot distance 0x{abs(buffer - alternate_buffer):x}")
        if 0 < length <= 0x20000:
            for slot in (buffer, alternate_buffer):
                native_slot = snapshot.native_ram_address(slot)
                try:
                    block = snapshot.read(native_slot, length)
                except ValueError:
                    print(f"  DMA slot 0x{slot:08x} is outside the captured RAM range")
                    continue
                nonzero = sum(byte != 0 for byte in block)
                print(f"  DMA slot 0x{slot:08x} (native 0x{native_slot:08x}): "
                      f"{nonzero}/{len(block)} nonzero bytes")
    inspect_decoder_sync_objects(snapshot)
    print("These are saved RAM pointers/state only; the script does not access the device.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
