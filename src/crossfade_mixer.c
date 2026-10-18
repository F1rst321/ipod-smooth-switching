/* SPDX-License-Identifier: GPL-3.0-only */
#include "crossfade_mixer.h"

#define GAIN_ONE_Q15 32768U
#define GAIN_HALF_Q15 16384

static int16_t mix_sample(int16_t a, int16_t b, uint32_t gain_b_q15) {
    const int32_t gain_b = (int32_t)gain_b_q15;
    const int32_t gain_a = (int32_t)(GAIN_ONE_Q15 - gain_b_q15);
    int32_t mixed = (int32_t)a * gain_a + (int32_t)b * gain_b;

    /* Keep exact negative values unchanged while rounding half steps away. */
    if (mixed >= 0) {
        mixed = (mixed + GAIN_HALF_Q15) >> 15;
    } else {
        mixed = -(((-mixed) + GAIN_HALF_Q15) >> 15);
    }

    if (mixed > 32767) {
        mixed = 32767;
    } else if (mixed < -32768) {
        mixed = -32768;
    }
    return (int16_t)mixed;
}

int ipod_crossfade_begin(ipod_crossfade_state_t *state, uint32_t total_frames) {
    uint32_t intervals;

    if (state == 0 || total_frames < 2U) {
        return 0;
    }

    intervals = total_frames - 1U;
    state->total_frames = total_frames;
    state->frames_done = 0U;
    state->gain_b_q15 = 0U;
    state->gain_step_q15 = GAIN_ONE_Q15 / intervals;
    state->gain_remainder = GAIN_ONE_Q15 % intervals;
    state->step_error = 0U;
    state->active = 1U;
    return 1;
}

uint32_t ipod_crossfade_mix_block(
    ipod_crossfade_state_t *state,
    const int16_t *a,
    const int16_t *b,
    int16_t *out,
    uint32_t frame_count,
    uint32_t channels
) {
    uint32_t frames;
    uint32_t frame;

    if (state == 0 || a == 0 || b == 0 || out == 0 || state->active == 0U ||
        (channels != 1U && channels != 2U)) {
        return 0U;
    }

    frames = state->total_frames - state->frames_done;
    if (frames > frame_count) {
        frames = frame_count;
    }

    for (frame = 0U; frame < frames; ++frame) {
        uint32_t channel;
        const uint32_t sample_base = frame * channels;

        for (channel = 0U; channel < channels; ++channel) {
            const uint32_t index = sample_base + channel;
            out[index] = mix_sample(a[index], b[index], state->gain_b_q15);
        }

        ++state->frames_done;
        if (state->frames_done == state->total_frames) {
            state->gain_b_q15 = GAIN_ONE_Q15;
            state->active = 0U;
            break;
        }

        state->gain_b_q15 += state->gain_step_q15;
        state->step_error += state->gain_remainder;
        if (state->step_error >= state->total_frames - 1U) {
            ++state->gain_b_q15;
            state->step_error -= state->total_frames - 1U;
        }
    }

    return frames;
}
