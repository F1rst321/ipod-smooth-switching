/* SPDX-License-Identifier: GPL-3.0-only */
#include "crossfade_resource_gate.h"

#define PLAYER_CURRENT_TRACK_OFFSET 0x2A4U
#define TRACK_ID_OFFSET 0x10U

typedef int32_t (*stock_track_resource_factory_fn)(
    void *player,
    void *track,
    uint32_t flags,
    void **resource_out,
    void *optional
);

/* Keep initialized bytes in the payload so the offline injector carries them. */
volatile ipod_crossfade_resource_gate_state_t ipod_crossfade_resource_gate_state
    __attribute__((section(".data.ipod_crossfade_resource_gate_state"))) = {
        0U,
        0U,
        0U,
    };

static void compiler_barrier(void) {
    __asm__ volatile ("" ::: "memory");
}

int32_t ipod_crossfade_open_track_resource_b(
    void *player,
    void *track_b,
    void **resource_out
) {
    uint32_t parent;
    uint32_t track_id;
    void *current_track;
    stock_track_resource_factory_fn open_resource;
    int32_t result;

    if (resource_out == 0) {
        return -1;
    }
    *resource_out = 0;
    if (player == 0 || track_b == 0) {
        return -1;
    }

    parent = *(const uint32_t *)player;
    track_id = *(const uint32_t *)((const uint8_t *)track_b + TRACK_ID_OFFSET);
    if (parent == 0U) {
        return -1;
    }

    current_track = *(void **)((uint8_t *)player + PLAYER_CURRENT_TRACK_OFFSET);
    if (current_track == track_b || ipod_crossfade_resource_gate_state.armed != 0U) {
        return -2;
    }

    ipod_crossfade_resource_gate_state.expected_parent = parent;
    ipod_crossfade_resource_gate_state.expected_track_id = track_id;
    compiler_barrier();
    ipod_crossfade_resource_gate_state.armed = 1U;
    compiler_barrier();

    open_resource = (stock_track_resource_factory_fn)(uintptr_t)
        IPOD_CROSSFADE_TRACK_RESOURCE_FACTORY;
    result = open_resource(player, track_b, 0U, resource_out, 0);

    compiler_barrier();
    ipod_crossfade_resource_gate_state.armed = 0U;
    ipod_crossfade_resource_gate_state.expected_parent = 0U;
    ipod_crossfade_resource_gate_state.expected_track_id = 0U;
    compiler_barrier();

    if (result != 0) {
        *resource_out = 0;
    }
    return result;
}
