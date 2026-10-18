/* SPDX-License-Identifier: GPL-3.0-only */
.syntax unified
.cpu arm7tdmi
.arm

/*
 * Branch-table handlers for the two stock Settings dispatchers. These
 * routines are entered in the middle of RetailOS functions, so their
 * registers and return destinations follow the verified stock instruction
 * paths documented in ui/stock_resource_map.md.
 */

.section .text.ipod_crossfade_settings_get_handler, "ax", %progbits
.align 2
.global ipod_crossfade_settings_get_handler
.type ipod_crossfade_settings_get_handler, %function

/*
 * Entry context from the getter's 0x6089 switch arm:
 *   r4 = output pointer, r5 = settings object, r6 = request kind,
 *   sb/sl = stock raw-value and localized-string request kinds.
 */
ipod_crossfade_settings_get_handler:
    cmp     r6, sb
    beq     .Lget_raw_value
    cmp     r6, sl
    beq     .Lget_value_string
    ldr     ip, .Lget_return_zero
    bx      ip

.Lget_raw_value:
    ldr     r0, [r5, #0x98]
    cmp     r0, #0
    beq     .Lget_default_value
    ldr     r0, [r0, #0xca0]
    cmp     r0, #0
    beq     .Lget_default_value
    ldrb    r0, [r0, #0xb70]
    cmp     r0, #3
    movlo   r0, #3
    cmp     r0, #10
    movhi   r0, #3
    ldr     ip, .Lget_return_value
    bx      ip

.Lget_default_value:
    mov     r0, #3
    ldr     ip, .Lget_return_value
    bx      ip

.Lget_value_string:
    /* Get the localized string provider used by neighboring Settings keys. */
    ldr     ip, .Llocalized_string_provider
    mov     lr, pc
    bx      ip
    mov     r2, r0

    ldr     r0, [r5, #0x98]
    cmp     r0, #0
    beq     .Lget_default_string
    ldr     r0, [r0, #0xca0]
    cmp     r0, #0
    beq     .Lget_default_string
    ldrb    r1, [r0, #0xb70]
    cmp     r1, #3
    movlo   r1, #3
    cmp     r1, #10
    movhi   r1, #3
    sub     r1, r1, #3
    ldr     r3, .Lvalue_string_base
    add     r1, r1, r3
    b       .Llookup_value_string

.Lget_default_string:
    ldr     r1, .Lvalue_string_base

.Llookup_value_string:
    mov     r0, r2
    ldr     ip, .Llocalized_string_lookup
    mov     lr, pc
    bx      ip
    ldr     ip, .Lget_return_value
    bx      ip

.align 2
.Lget_return_zero:
    .word 0x101918c8
.Lget_return_value:
    .word 0x101918c0
.Llocalized_string_provider:
    .word 0x1021f3b8
.Llocalized_string_lookup:
    .word 0x1021f418
.Lvalue_string_base:
    .word 30001

.size ipod_crossfade_settings_get_handler, .-ipod_crossfade_settings_get_handler


.section .text.ipod_crossfade_settings_set_handler, "ax", %progbits
.align 2
.global ipod_crossfade_settings_set_handler
.type ipod_crossfade_settings_set_handler, %function

/*
 * Entry context from the setter's 0x6089 switch arm:
 *   r4 = settings object, r5 = pointer to requested uint32 value.
 * The preferences dirty marker makes RetailOS write its existing fixed-size
 * Device/Preferences file through the normal persistence task.
 */
ipod_crossfade_settings_set_handler:
    ldr     r0, [r4, #0x98]
    cmp     r0, #0
    beq     .Lset_failure
    ldr     r0, [r0, #0xca0]
    cmp     r0, #0
    beq     .Lset_failure

    ldr     r1, [r5]
    cmp     r1, #3
    movlo   r1, #3
    cmp     r1, #10
    movhi   r1, #10
    strb    r1, [r0, #0xb70]
    mov     r1, #1
    strb    r1, [r0, #0xb74]
    mov     r0, #1
    ldr     ip, .Lset_return_success
    bx      ip

.Lset_failure:
    ldr     ip, .Lset_return_failure
    bx      ip

.align 2
.Lset_return_success:
    .word 0x101927e8
.Lset_return_failure:
    .word 0x101927e4

.size ipod_crossfade_settings_set_handler, .-ipod_crossfade_settings_set_handler
