#!/usr/bin/env python3
"""Cross-compile the isolated PCM16 mixer and ring for the iPod Video ARM7TDMI.

This creates an offline code payload under build/. It does not connect to a
device, inject hooks, update the firmware directory, or create an installable
firmware image.
"""
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT_ROOT / "src" / "crossfade_mixer.c"
RING_SOURCE = PROJECT_ROOT / "src" / "crossfade_pcm_ring.c"
RESOURCE_GATE_SOURCE = PROJECT_ROOT / "src" / "crossfade_resource_gate.c"
RESOURCE_GATE_ASSEMBLY = PROJECT_ROOT / "src" / "crossfade_resource_gate.S"
LINKER_SCRIPT = PROJECT_ROOT / "src" / "crossfade_mixer.lds"
DEFAULT_TOOLCHAIN = (
    PROJECT_ROOT / "build" / "toolchains" / "arm-gnu-14.3" / "unpacked" / "bin"
)
OSOS_WINDOW_BYTES = 0x7161A4 - 0x712000


def run(command: list[str], cwd: Path, log: list[str]) -> str:
    """Run one cross-toolchain command and keep its complete output for review."""
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log.append("$ " + subprocess.list2cmdline(command) + "\n" + result.stdout)
    if result.returncode:
        raise RuntimeError(
            f"Command failed with exit code {result.returncode}: "
            f"{subprocess.list2cmdline(command)}\n{result.stdout}"
        )
    return result.stdout


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
        default=PROJECT_ROOT / "build" / "crossfade-mixer",
        help="local ignored build output directory",
    )
    args = parser.parse_args()

    toolchain = args.toolchain_bin.resolve()
    output_dir = args.output_dir.resolve()
    build_root = (PROJECT_ROOT / "build").resolve()
    try:
        output_dir.relative_to(build_root)
    except ValueError:
        parser.error("output directory must remain under this project's ignored build/")

    gcc = toolchain / "arm-none-eabi-gcc.exe"
    nm = toolchain / "arm-none-eabi-nm.exe"
    objcopy = toolchain / "arm-none-eabi-objcopy.exe"
    objdump = toolchain / "arm-none-eabi-objdump.exe"
    required = (gcc, nm, objcopy, objdump)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        parser.error("missing cross-toolchain tools: " + ", ".join(missing))

    output_dir.mkdir(parents=True, exist_ok=True)
    obj = output_dir / "crossfade_mixer.o"
    ring_obj = output_dir / "crossfade_pcm_ring.o"
    resource_gate_obj = output_dir / "crossfade_resource_gate.o"
    resource_gate_asm_obj = output_dir / "crossfade_resource_gate_asm.o"
    elf = output_dir / "crossfade_mixer.elf"
    binary = output_dir / "crossfade_mixer.bin"
    map_file = output_dir / "crossfade_mixer.map"
    log: list[str] = []
    flags = [
        "-mcpu=arm7tdmi",
        "-mthumb-interwork",
        "-mthumb",
        "-Os",
        "-ffreestanding",
        "-fno-builtin",
        "-fno-common",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
        "-ffunction-sections",
        "-fdata-sections",
        "-Wall",
        "-Wextra",
        "-Werror",
    ]

    try:
        version = run([str(gcc), "--version"], output_dir, log).splitlines()[0]
        run(
            [
                str(gcc),
                *flags,
                "-I",
                str(SOURCE.parent),
                "-c",
                str(SOURCE),
                "-o",
                str(obj),
            ],
            output_dir,
            log,
        )
        run(
            [
                str(gcc),
                *flags,
                "-I",
                str(RESOURCE_GATE_SOURCE.parent),
                "-c",
                str(RESOURCE_GATE_SOURCE),
                "-o",
                str(resource_gate_obj),
            ],
            output_dir,
            log,
        )
        run(
            [
                str(gcc),
                "-mcpu=arm7tdmi",
                "-mthumb-interwork",
                "-c",
                str(RESOURCE_GATE_ASSEMBLY),
                "-o",
                str(resource_gate_asm_obj),
            ],
            output_dir,
            log,
        )
        run(
            [
                str(gcc),
                *flags,
                "-I",
                str(RING_SOURCE.parent),
                "-c",
                str(RING_SOURCE),
                "-o",
                str(ring_obj),
            ],
            output_dir,
            log,
        )
        run(
            [
                str(gcc),
                "-mcpu=arm7tdmi",
                "-mthumb-interwork",
                "-mthumb",
                "-nostdlib",
                "-Wl,--gc-sections",
                f"-Wl,-T,{LINKER_SCRIPT}",
                f"-Wl,-Map,{map_file}",
                str(obj),
                str(ring_obj),
                str(resource_gate_obj),
                str(resource_gate_asm_obj),
                "-lgcc",
                "-o",
                str(elf),
            ],
            output_dir,
            log,
        )
        undefined = run([str(nm), "-u", str(elf)], output_dir, log).strip()
        if undefined:
            raise ValueError(f"linked payload contains undefined symbols:\n{undefined}")
        architecture = run([str(objdump), "-f", str(elf)], output_dir, log)
        if "elf32-littlearm" not in architecture or "architecture: arm" not in architecture:
            raise ValueError("linked payload is not an ARM ELF image")
        run([str(objcopy), "-O", "binary", str(elf), str(binary)], output_dir, log)
        payload_size = binary.stat().st_size
        if payload_size == 0 or payload_size > OSOS_WINDOW_BYTES:
            raise ValueError(
                f"payload size {payload_size:,} is outside the audited "
                f"{OSOS_WINDOW_BYTES:,}-byte OSOS window"
            )
    except (OSError, RuntimeError, ValueError) as exc:
        (output_dir / "build.log").write_text("\n".join(log), encoding="utf-8")
        parser.error(str(exc))

    (output_dir / "build.log").write_text("\n".join(log), encoding="utf-8")
    print(f"Compiler: {version}")
    print(f"Target: ARM7TDMI / ARMv4T Thumb")
    print(f"Payload: {binary} ({payload_size:,}/{OSOS_WINDOW_BYTES:,} bytes)")
    print("Offline mixer, PCM ring, and resource-open gate; no decoder hook or installable image was built.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
