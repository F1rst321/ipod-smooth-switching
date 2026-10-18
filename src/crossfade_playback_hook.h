/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef IPOD_CROSSFADE_PLAYBACK_HOOK_H
#define IPOD_CROSSFADE_PLAYBACK_HOOK_H

#include "crossfade_mixer.h"

#include <stdint.h>

#define IPOD_CROSSFADE_PLAYBACK_HOOK_MAGIC 0x43524650U

typedef struct {
    uint32_t magic;
    uint32_t enabled;
    uint32_t item_b;
    uint32_t callback_b;
    uint32_t active_item_cell;
    uint32_t queue_callback_cell;
    uint32_t output_slot_0_cell;
    uint32_t output_slot_1_cell;
    uint32_t output_b;
    uint32_t output_capacity_bytes;
    ipod_crossfade_state_t fade;
} ipod_crossfade_playback_hook_state_t;

extern volatile ipod_crossfade_playback_hook_state_t
    ipod_crossfade_playback_hook_state;

/* Called from the normal RetailOS voice-mix path with stereo frame counts. */
int32_t ipod_crossfade_playback_mix_hook(
    void *mixer,
    int16_t *output_a,
    uint32_t frame_count
);

/* ARM-state branch target used by the RetailOS call-site patch. */
void ipod_crossfade_playback_mix_gate(void);

#endif
