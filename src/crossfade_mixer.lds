/* SPDX-License-Identifier: GPL-3.0-only */
OUTPUT_ARCH(arm)
ENTRY(ipod_crossfade_begin)

SECTIONS
{
    . = 0x10712000;
    .text : ALIGN(4) {
        KEEP(*(.text.ipod_crossfade_begin))
        KEEP(*(.text.ipod_crossfade_mix_block))
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.ARM.extab* .gnu.linkonce.armextab.*)
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    }
    .data : ALIGN(4) { *(.data .data.*) }
    .bss (NOLOAD) : ALIGN(4) {
        *(.bss .bss.*)
        *(COMMON)
    }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }

    ASSERT(. <= 0x107161A4, "crossfade mixer exceeds audited OSOS window")
}
