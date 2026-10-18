/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef IPOD_CROSSFADE_MIXER_H
#define IPOD_CROSSFADE_MIXER_H

#include <stdint.h>

/* Linear PCM16 crossfade state. One instance belongs to one active transition. */
typedef struct {
    uint32_t total_frames;
    uint32_t frames_done;
    uint32_t gain_b_q15;
    uint32_t gain_step_q15;
    uint32_t gain_remainder;
    uint32_t step_error;
    uint8_t active;
} ipod_crossfade_state_t;

/* Start a transition lasting total_frames frames; returns 1 on success. */
int ipod_crossfade_begin(ipod_crossfade_state_t *state, uint32_t total_frames);

/*
 * Mix up to frame_count interleaved PCM16 frames from tracks A and B.
 * channels must be 1 or 2. The return value is the number of frames mixed.
 * Exact in-place output (out == a or out == b) is supported.
 */
uint32_t ipod_crossfade_mix_block(
    ipod_crossfade_state_t *state,
    const int16_t *a,
    const int16_t *b,
    int16_t *out,
    uint32_t frame_count,
    uint32_t channels
);

#endif
