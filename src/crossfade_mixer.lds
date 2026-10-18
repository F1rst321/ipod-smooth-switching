/* SPDX-License-Identifier: GPL-3.0-only */
OUTPUT_ARCH(arm)
ENTRY(ipod_crossfade_begin)

SECTIONS
{
    IPOD_CROSSFADE_CODE_BASE = DEFINED(IPOD_CROSSFADE_CODE_BASE) ? IPOD_CROSSFADE_CODE_BASE : 0x10712000;
    . = IPOD_CROSSFADE_CODE_BASE;
    .text : ALIGN(4) {
        KEEP(*(.text.ipod_crossfade_resource_registry_reset_gate))
        KEEP(*(.text.ipod_crossfade_playback_mix_gate))
        KEEP(*(.text.ipod_crossfade_mp3_item_service_gate))
        KEEP(*(.text.ipod_crossfade_playback_mix_hook))
        KEEP(*(.text.ipod_crossfade_open_track_resource_b))
        KEEP(*(.text.ipod_crossfade_begin))
        KEEP(*(.text.ipod_crossfade_mix_block))
        KEEP(*(.text.ipod_crossfade_pcm_ring_storage_bytes))
        KEEP(*(.text.ipod_crossfade_pcm_ring_create))
        KEEP(*(.text.ipod_crossfade_pcm_ring_destroy))
        KEEP(*(.text.ipod_crossfade_pcm_ring_init))
        KEEP(*(.text.ipod_crossfade_pcm_ring_available))
        KEEP(*(.text.ipod_crossfade_pcm_ring_write))
        KEEP(*(.text.ipod_crossfade_pcm_ring_read))
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.ARM.extab* .gnu.linkonce.armextab.*)
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    }
    .data : ALIGN(4) {
        KEEP(*(.data.ipod_crossfade_resource_gate_state))
        KEEP(*(.data.ipod_crossfade_playback_hook_state))
        *(.data .data.*)
    }
    .bss (NOLOAD) : ALIGN(4) {
        *(.bss .bss.*)
        *(COMMON)
    }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }

    ASSERT(. <= 0x107161A4, "crossfade mixer exceeds audited OSOS window")
}
