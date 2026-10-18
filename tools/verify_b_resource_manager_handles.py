#!/usr/bin/env python3
"""Create two unopened stock resource handles from the saved HIBE registry.

This read-only Unicorn experiment calls RetailOS's resource-manager factory
twice with distinct MP3 URIs. It uses the provider objects and heap state from
the saved HIBE snapshot, then checks that the returned unopened resource
objects retain separate URI strings. It does not call a resource object's open
method, access a filesystem, run playback, write firmware, or access the iPod.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "build" / "pydeps"))
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from verify_b_fsbuf_constructor import (  # noqa: E402
    DEFAULT_HIBE,
    DEFAULT_IRAM,
    DEFAULT_OSOS,
    ConstructorMachine,
    u32,
)

OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"
RESOURCE_MANAGER_GLOBAL = 0x10128730
RESOURCE_MANAGER_FACTORY = 0x1012873C
RESOURCE_MANAGER_PROVIDER_ARRAY_OFFSET = 0x04
RESOURCE_MANAGER_PROVIDER_COUNT_OFFSET = 0x08
RESOURCE_HANDLE_VTABLE = 0x006662A8
RESOURCE_HANDLE_BYTES = 0x214
RESOURCE_URI_OFFSET = 0x0C
RESOURCE_URI_BYTES = 0x100
MODE_READ = 1
CONTEXT = 0
URI_A_ADDRESS = 0x20001000
URI_B_ADDRESS = 0x20001200
OUT_A_ADDRESS = 0x20002000
OUT_B_ADDRESS = 0x20002004

URI_A = b"file:///iPod_Control/Music/F00/ABCD1234.MP3"
URI_B = b"file:///iPod_Control/Music/F00/EFGH5678.MP3"


def read_c_string(machine: ConstructorMachine, address: int, size: int) -> bytes:
    """Read a bounded NUL-terminated string from emulated memory."""
    raw = bytes(machine.machine.mem_read(address, size))
    return raw.split(b"\0", 1)[0]


def create_unopened_resource(
    machine: ConstructorMachine,
    manager: int,
    uri: bytes,
    uri_address: int,
    output_address: int,
) -> int:
    """Call the stock manager factory and validate the unopened result."""
    if len(uri) >= RESOURCE_URI_BYTES:
        raise ValueError("URI does not fit the stock 0x100-byte resource field")
    machine.machine.mem_write(uri_address, uri + b"\0")
    machine.machine.mem_write(output_address, bytes(4))

    result = machine.call(
        RESOURCE_MANAGER_FACTORY,
        (manager, CONTEXT, uri_address, MODE_READ),
        fifth=output_address,
    )
    handle = u32(machine.machine, output_address)
    if result != 0 or handle == 0:
        raise RuntimeError(
            f"stock resource factory failed for {uri!r}: "
            f"result={result}, handle=0x{handle:08x}"
        )
    if u32(machine.machine, handle) != RESOURCE_HANDLE_VTABLE:
        raise RuntimeError(
            f"unexpected resource vtable at 0x{handle:08x}: "
            f"0x{u32(machine.machine, handle):08x}"
        )
    if u32(machine.machine, handle + 4) != 0xFFFFFFFF:
        raise RuntimeError("resource unexpectedly left the unopened state")
    copied_uri = read_c_string(
        machine, handle + RESOURCE_URI_OFFSET, RESOURCE_URI_BYTES
    )
    if copied_uri != uri:
        raise RuntimeError(
            f"resource copied the wrong URI: expected {uri!r}, got {copied_uri!r}"
        )
    return handle


def main() -> int:
    osos = DEFAULT_OSOS.read_bytes()
    if hashlib.sha256(osos).hexdigest() != OSOS_SHA256:
        raise ValueError("OSOS SHA-256 does not match the audited RetailOS 1.3 image")
    hibe = DEFAULT_HIBE.read_bytes()
    iram = DEFAULT_IRAM.read_bytes()
    machine = ConstructorMachine(osos, hibe, iram)

    manager = u32(machine.machine, RESOURCE_MANAGER_GLOBAL)
    provider_count = u32(
        machine.machine, manager + RESOURCE_MANAGER_PROVIDER_COUNT_OFFSET
    )
    provider_array = u32(
        machine.machine, manager + RESOURCE_MANAGER_PROVIDER_ARRAY_OFFSET
    )
    if not 1 <= provider_count <= 8 or provider_array == 0:
        raise RuntimeError(
            f"unexpected HIBE resource manager: providers={provider_count}, "
            f"array=0x{provider_array:08x}"
        )
    providers_before = bytes(
        machine.machine.mem_read(provider_array, provider_count * 4)
    )
    manager_fields_before = bytes(machine.machine.mem_read(manager, 12))

    handle_a = create_unopened_resource(
        machine, manager, URI_A, URI_A_ADDRESS, OUT_A_ADDRESS
    )
    handle_a_before_b = bytes(
        machine.machine.mem_read(handle_a, RESOURCE_HANDLE_BYTES)
    )
    handle_b = create_unopened_resource(
        machine, manager, URI_B, URI_B_ADDRESS, OUT_B_ADDRESS
    )
    if handle_a == handle_b:
        raise RuntimeError("resource manager reused A's live resource object for B")
    if bytes(machine.machine.mem_read(handle_a, RESOURCE_HANDLE_BYTES)) != handle_a_before_b:
        raise RuntimeError("creating B changed A's unopened resource object")
    if bytes(machine.machine.mem_read(provider_array, provider_count * 4)) != providers_before:
        raise RuntimeError("creating B changed the saved manager provider list")
    if bytes(machine.machine.mem_read(manager, 12)) != manager_fields_before:
        raise RuntimeError("creating B changed the manager's provider table")

    print(f"PASS: HIBE resource manager has {provider_count} registered providers")
    print(
        f"PASS: stock factory created distinct unopened handles "
        f"A=0x{handle_a:08x}, B=0x{handle_b:08x}"
    )
    print("PASS: each handle retained its own URI; B creation preserved A and the registry")
    print(
        "LIMIT: these test URIs are not opened. File existence, filesystem I/O, "
        "FSbuf async refill, decoding, playback, and hardware remain untested."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"B resource-manager verification failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
