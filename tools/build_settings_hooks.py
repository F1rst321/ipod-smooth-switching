#!/usr/bin/env python3
"""Build the isolated RetailOS 1.3 crossfade property handlers for ARM7TDMI."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT_ROOT / "src" / "crossfade_settings.S"
LINKER_SCRIPT = PROJECT_ROOT / "src" / "crossfade_settings.lds"
DEFAULT_TOOLCHAIN = (
    PROJECT_ROOT / "build" / "toolchains" / "arm-gnu-14.3" / "unpacked" / "bin"
)
CODE_START = 0x10714000
CODE_END = 0x107161A4


def run(command: list[str], cwd: Path) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"Command failed ({result.returncode}): "
            f"{subprocess.list2cmdline(command)}\n{result.stdout}"
        )
    return result.stdout


def symbols_from_nm(output: str) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
            symbols[parts[2]] = int(parts[0], 16)
    return symbols


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--toolchain-bin",
        type=Path,
        default=Path(os.environ.get("ARM_GNU_TOOLCHAIN_BIN", DEFAULT_TOOLCHAIN)),
        help="directory containing arm-none-eabi-gcc and binutils",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "build" / "settings-hooks",
        help="ignored build output directory",
    )
    args = parser.parse_args()

    toolchain = args.toolchain_bin.resolve()
    output_dir = args.output_dir.resolve()
    try:
        output_dir.relative_to((PROJECT_ROOT / "build").resolve())
    except ValueError:
        parser.error("output directory must remain under this project's build/")

    gcc = toolchain / "arm-none-eabi-gcc.exe"
    nm = toolchain / "arm-none-eabi-nm.exe"
    objcopy = toolchain / "arm-none-eabi-objcopy.exe"
    objdump = toolchain / "arm-none-eabi-objdump.exe"
    missing = [path for path in (gcc, nm, objcopy, objdump) if not path.is_file()]
    if missing:
        parser.error("missing cross-toolchain tools: " + ", ".join(map(str, missing)))

    output_dir.mkdir(parents=True, exist_ok=True)
    obj = output_dir / "crossfade_settings.o"
    elf = output_dir / "crossfade_settings.elf"
    binary = output_dir / "crossfade_settings.bin"
    map_file = output_dir / "crossfade_settings.map"
    manifest_file = binary.with_suffix(binary.suffix + ".json")
    try:
        version = run([str(gcc), "--version"], output_dir).splitlines()[0]
        run([
            str(gcc), "-mcpu=arm7tdmi", "-mthumb-interwork", "-c",
            str(SOURCE), "-o", str(obj),
        ], output_dir)
        run([
            str(gcc), "-mcpu=arm7tdmi", "-mthumb-interwork", "-nostdlib",
            "-Wl,--gc-sections", f"-Wl,-T,{LINKER_SCRIPT}",
            f"-Wl,-Map,{map_file}", str(obj), "-o", str(elf),
        ], output_dir)
        undefined = run([str(nm), "-u", str(elf)], output_dir).strip()
        if undefined:
            raise ValueError(f"payload has unresolved symbols:\n{undefined}")
        architecture = run([str(objdump), "-f", str(elf)], output_dir)
        if "elf32-littlearm" not in architecture or "architecture: arm" not in architecture:
            raise ValueError("payload is not an ARM ELF image")
        symbol_output = run([str(nm), "-n", str(elf)], output_dir)
        symbols = symbols_from_nm(symbol_output)
        for name in (
            "ipod_crossfade_settings_get_handler",
            "ipod_crossfade_settings_set_handler",
        ):
            if name not in symbols:
                raise ValueError(f"linked payload is missing {name}")
        if symbols["ipod_crossfade_settings_get_handler"] != CODE_START:
            raise ValueError("getter handler is not at the reserved code start")
        run([str(objcopy), "-O", "binary", str(elf), str(binary)], output_dir)
        payload = binary.read_bytes()
        if not payload or CODE_START + len(payload) > CODE_END:
            raise ValueError(
                f"settings payload exceeds its reserved OSOS code range: "
                f"{len(payload):,} bytes"
            )
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))

    manifest = {
        "artifact_type": "retailos_settings_handler_payload",
        "device_ready": False,
        "runtime_validated": False,
        "compiler": version,
        "architecture": "ARM7TDMI / ARMv4T ARM state",
        "payload_path": str(binary),
        "payload_address": CODE_START,
        "payload_size": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "code_range_end": CODE_END,
        "symbols": {
            name: address
            for name, address in symbols.items()
            if name.startswith("ipod_crossfade_settings_")
        },
        "notes": [
            "The handlers target verified but not device-tested RetailOS dispatch arms.",
            "The Settings slider resource and audio playback path are separate work.",
            "This payload is not an installable firmware image.",
        ],
    }
    manifest_file.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Compiler: {version}")
    print(f"ARM handlers: {binary} ({len(payload):,} bytes)")
    print(f"Get handler: 0x{symbols['ipod_crossfade_settings_get_handler']:08x}")
    print(f"Set handler: 0x{symbols['ipod_crossfade_settings_set_handler']:08x}")
    print(f"Manifest: {manifest_file}")
    print("Offline handler module only; no hooks or installable image are built.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
