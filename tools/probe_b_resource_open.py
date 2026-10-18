#!/usr/bin/env python3
"""Probe the stock unopened-resource method in a saved HIBE emulator copy.

The probe uses a caller-supplied URI (or a dummy MP3 URI), creates a resource
through the saved RetailOS manager, and calls its stock open method. All code
runs on copied OSOS/HIBE/IRAM bytes in Unicorn. It performs no host file access,
device access, firmware write, or audio playback.
"""
from __future__ import annotations

import argparse
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
    RMI_CONTEXT,
    ConstructorMachine,
    u32,
)

OSOS_SHA256 = "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251"
RESOURCE_MANAGER_GLOBAL = 0x10128730
RESOURCE_MANAGER_FACTORY = 0x1012873C
RESOURCE_OPEN_METHOD = 0x10125B7C
RESOURCE_HANDLE_VTABLE = 0x006662A8
RESOURCE_HANDLE_STATE_OFFSET = 0x04
RESOURCE_OPEN_ERROR_OFFSET = 0x210
URI_ADDRESS = 0x20001000
OUT_ADDRESS = 0x20002000
MODE_READ = 1
DEFAULT_URI = "file:///iPod_Control/Music/F00/ABCD1234.MP3"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osos", type=Path, default=DEFAULT_OSOS)
    parser.add_argument("--hibe", type=Path, default=DEFAULT_HIBE)
    parser.add_argument("--iram", type=Path, default=DEFAULT_IRAM)
    parser.add_argument(
        "--uri",
        default=DEFAULT_URI,
        help="URI string to pass to stock RetailOS (default is a dummy MP3 path)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    uri = args.uri.encode("ascii")
    if len(uri) >= 0x100:
        raise ValueError("URI must fit the stock 0x100-byte field")

    osos = args.osos.read_bytes()
    if hashlib.sha256(osos).hexdigest() != OSOS_SHA256:
        raise ValueError("OSOS SHA-256 does not match the audited RetailOS 1.3 image")
    hibe = args.hibe.read_bytes()
    iram = args.iram.read_bytes()
    machine = ConstructorMachine(osos, hibe, iram)

    manager = u32(machine.machine, RESOURCE_MANAGER_GLOBAL)
    machine.machine.mem_write(URI_ADDRESS, uri + b"\0")
    machine.machine.mem_write(OUT_ADDRESS, bytes(4))
    factory_result = machine.call(
        RESOURCE_MANAGER_FACTORY,
        (manager, RMI_CONTEXT, URI_ADDRESS, MODE_READ),
        fifth=OUT_ADDRESS,
    )
    resource = u32(machine.machine, OUT_ADDRESS)
    if factory_result != 0 or resource == 0:
        raise RuntimeError(
            f"resource manager factory failed: result={factory_result}, "
            f"resource=0x{resource:08x}"
        )
    if u32(machine.machine, resource) != RESOURCE_HANDLE_VTABLE:
        raise RuntimeError("factory returned an unexpected stock resource vtable")

    machine.call(RESOURCE_OPEN_METHOD, (resource,))
    state = u32(machine.machine, resource + RESOURCE_HANDLE_STATE_OFFSET)
    error = machine.machine.mem_read(resource + RESOURCE_OPEN_ERROR_OFFSET, 1)[0]
    print(f"URI submitted: {args.uri}")
    print(f"Resource object: 0x{resource:08x}; stock vtable 0x{RESOURCE_HANDLE_VTABLE:08x}")
    if state & 0x80000000:
        print(f"PROBE: resource open failed; state=0x{state:08x}, object error={error}")
    else:
        print(f"PROBE: resource open returned; state=0x{state:08x}, object error={error}")
    print(
        "LIMIT: this uses a saved HIBE RAM image, not the iPod filesystem. "
        "It does not read MP3 data, refill FSbuf, decode audio, or verify playback."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, UnicodeEncodeError, ValueError) as exc:
        print(f"Resource-open probe could not complete: {exc}", file=sys.stderr)
        raise SystemExit(2)
