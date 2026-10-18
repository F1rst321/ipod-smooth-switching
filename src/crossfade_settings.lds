/* SPDX-License-Identifier: GPL-3.0-only */
OUTPUT_ARCH(arm)
ENTRY(ipod_crossfade_settings_get_handler)

SECTIONS
{
    . = 0x10714000;
    .text : ALIGN(4) {
        KEEP(*(.text.ipod_crossfade_settings_get_handler))
        KEEP(*(.text.ipod_crossfade_settings_set_handler))
        *(.text .text.*)
        *(.rodata .rodata.*)
    }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }

    ASSERT(. <= 0x107161A4, "settings hooks exceed remaining audited OSOS window")
}
