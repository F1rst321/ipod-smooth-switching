/* SPDX-License-Identifier: GPL-3.0-only */
.syntax unified
.cpu arm7tdmi
.arm

.section .text.ipod_crossfade_resource_registry_reset_gate, "ax", %progbits
.align 2
.global ipod_crossfade_resource_registry_reset_gate
.type ipod_crossfade_resource_registry_reset_gate, %function

/* Called at OSOS+0xec340 in place of FUN_101332a8(context). R5 is the
 * current +0xec31c stream object. Only the expected B stream skips reset. */
ipod_crossfade_resource_registry_reset_gate:
    mov     r3, r0
    ldr     r12, .Lstate_pointer
    ldr     r0, [r12, #8]
    cmp     r0, #0
    beq     .Lcall_original

    ldr     r0, [r5, #4]
    ldr     r1, [r5, #8]
    ldr     r2, [r12, #0]
    cmp     r0, r2
    bne     .Lcall_original
    ldr     r2, [r12, #4]
    cmp     r1, r2
    bne     .Lcall_original

    mov     r0, #0
    str     r0, [r12, #8]
    bx      lr

.Lcall_original:
    mov     r0, r3
    ldr     r12, .Loriginal_initializer
    bx      r12

.align 2
.Lstate_pointer:
    .word ipod_crossfade_resource_gate_state
.Loriginal_initializer:
    .word 0x101332a8

.size ipod_crossfade_resource_registry_reset_gate, .-ipod_crossfade_resource_registry_reset_gate

.section .text.ipod_crossfade_playback_mix_gate, "ax", %progbits
.align 2
.global ipod_crossfade_playback_mix_gate
.type ipod_crossfade_playback_mix_gate, %function

/* Preserve the caller's ARM LR while entering the Thumb helper. */
ipod_crossfade_playback_mix_gate:
    ldr     r12, .Lplayback_helper
    bx      r12

.align 2
.Lplayback_helper:
    .word ipod_crossfade_playback_mix_hook

.size ipod_crossfade_playback_mix_gate, .-ipod_crossfade_playback_mix_gate

.section .text.ipod_crossfade_mp3_item_service_gate, "ax", %progbits
.align 2
.global ipod_crossfade_mp3_item_service_gate
.type ipod_crossfade_mp3_item_service_gate, %function

/*
 * Replaces OSOS+0x128128, which starts the slot-5 output methods. R5 is the
 * MP3 item. Only the item recorded in playback_hook_state.item_b bypasses
 * the shared output service; A executes the displaced LDR and resumes the
 * stock instructions. B jumps to the original initializer epilogue.
 */
ipod_crossfade_mp3_item_service_gate:
    ldr     r12, .Lplayback_state_pointer
    ldr     r12, [r12, #8]
    cmp     r5, r12
    beq     .Lbypass_output_service

    /* Recreate the displaced stock instruction, preserving the A path. */
    ldr     r0, [sp, #4]
    ldr     r12, .Lstock_service_continue
    bx      r12

.Lbypass_output_service:
    ldr     r12, .Lstock_item_epilogue
    bx      r12

.align 2
.Lplayback_state_pointer:
    .word ipod_crossfade_playback_hook_state
.Lstock_service_continue:
    .word 0x1012812c
.Lstock_item_epilogue:
    .word 0x10128154

.size ipod_crossfade_mp3_item_service_gate, .-ipod_crossfade_mp3_item_service_gate
