/* SPDX-License-Identifier: GPL-3.0-only */
#include "crossfade_playback_hook.h"

#define RETAILOS_MP3_WORKER 0x4000AE10U
#define RETAILOS_VOICE_MIXER 0x10217CB8U
#define ITEM_ACTIVE_CONTEXT_OFFSET 0x44U
#define STEREO_FRAME_BYTES 4U
#define STOCK_MP3_BLOCK_BYTES 4608U

typedef int32_t (*retailos_mp3_worker_fn)(void *, void *, uint32_t);
typedef void (*retailos_voice_mixer_fn)(void *, int16_t *, uint32_t);

/*
 * The stock MP3 worker was verified with one 1,152-frame stereo PCM block.
 * Keep one matching B output block in the payload's reserved OSOS window so
 * the audio callback does not call the heap allocator or perform file I/O.
 */
uint32_t ipod_crossfade_output_b_scratch[STOCK_MP3_BLOCK_BYTES / sizeof(uint32_t)]
    __attribute__((section(".data.ipod_crossfade_output_b_scratch"), aligned(4))) = {0U};

volatile ipod_crossfade_playback_hook_state_t ipod_crossfade_playback_hook_state
    __attribute__((section(".data.ipod_crossfade_playback_hook_state"))) = {
        IPOD_CROSSFADE_PLAYBACK_HOOK_MAGIC,
        0U,
        0U,
        0U,
        0U,
        0U,
        0U,
        0U,
        (uint32_t)(uintptr_t)ipod_crossfade_output_b_scratch,
        STOCK_MP3_BLOCK_BYTES,
        {0U, 0U, 0U, 0U, 0U, 0U, 0U},
    };

static void compiler_barrier(void) {
    __asm__ volatile ("" ::: "memory");
}

static void call_stock_voice_mixer(void *mixer, int16_t *output, uint32_t frames) {
    retailos_voice_mixer_fn voice_mixer =
        (retailos_voice_mixer_fn)(uintptr_t)RETAILOS_VOICE_MIXER;
    voice_mixer(mixer, output, frames);
}

static int32_t decode_track_b(
    volatile ipod_crossfade_playback_hook_state_t *state,
    uint32_t output_bytes
) {
    volatile uint32_t *active_item_cell =
        (volatile uint32_t *)(uintptr_t)state->active_item_cell;
    volatile uint32_t *queue_callback_cell =
        (volatile uint32_t *)(uintptr_t)state->queue_callback_cell;
    volatile uint32_t *output_slot_0_cell =
        (volatile uint32_t *)(uintptr_t)state->output_slot_0_cell;
    volatile uint32_t *output_slot_1_cell =
        (volatile uint32_t *)(uintptr_t)state->output_slot_1_cell;
    uint32_t saved_active_item = *active_item_cell;
    uint32_t saved_queue_callback = *queue_callback_cell;
    uint32_t saved_output_0 = *output_slot_0_cell;
    uint32_t saved_output_1 = *output_slot_1_cell;
    retailos_mp3_worker_fn worker =
        (retailos_mp3_worker_fn)(uintptr_t)RETAILOS_MP3_WORKER;
    int32_t result;

    *active_item_cell = state->item_b + ITEM_ACTIVE_CONTEXT_OFFSET;
    *queue_callback_cell = state->callback_b;
    *output_slot_0_cell = state->output_b;
    *output_slot_1_cell = state->output_b;
    compiler_barrier();
    result = worker((void *)(uintptr_t)state->item_b,
                    (void *)(uintptr_t)state->output_b,
                    output_bytes);
    *active_item_cell = saved_active_item;
    *queue_callback_cell = saved_queue_callback;
    *output_slot_0_cell = saved_output_0;
    *output_slot_1_cell = saved_output_1;
    compiler_barrier();
    return result;
}

static void copy_b_remainder(
    int16_t *output_a,
    const int16_t *output_b,
    uint32_t first_frame,
    uint32_t total_frames
) {
    uint32_t sample_index;
    uint32_t first_sample = first_frame * 2U;
    uint32_t end_sample = total_frames * 2U;

    for (sample_index = first_sample; sample_index < end_sample; ++sample_index) {
        output_a[sample_index] = output_b[sample_index];
    }
}

int32_t ipod_crossfade_playback_mix_hook(
    void *mixer,
    int16_t *output_a,
    uint32_t frame_count
) {
    volatile ipod_crossfade_playback_hook_state_t *state =
        &ipod_crossfade_playback_hook_state;
    uint32_t output_bytes;
    uint32_t mixed_frames = 0U;
    int32_t worker_result = 0;

    if (state->magic == IPOD_CROSSFADE_PLAYBACK_HOOK_MAGIC &&
        state->enabled != 0U && state->item_b != 0U &&
        state->callback_b != 0U && state->active_item_cell != 0U &&
        state->queue_callback_cell != 0U &&
        state->output_slot_0_cell != 0U && state->output_slot_1_cell != 0U &&
        state->output_b != 0U && output_a != 0 && frame_count != 0U &&
        frame_count <= state->output_capacity_bytes / STEREO_FRAME_BYTES &&
        frame_count <= 0x4000U && state->fade.total_frames >= 2U &&
        (state->fade.active != 0U ||
         state->fade.frames_done >= state->fade.total_frames)) {
        output_bytes = frame_count * STEREO_FRAME_BYTES;
        worker_result = decode_track_b(state, output_bytes);
        if (worker_result == 1) {
            if (state->fade.active != 0U) {
                mixed_frames = ipod_crossfade_mix_block(
                    (ipod_crossfade_state_t *)(uintptr_t)&state->fade,
                    output_a,
                    (const int16_t *)(uintptr_t)state->output_b,
                    output_a,
                    frame_count,
                    2U
                );
            } else if (state->fade.frames_done >= state->fade.total_frames) {
                copy_b_remainder(
                    output_a,
                    (const int16_t *)(uintptr_t)state->output_b,
                    0U,
                    frame_count
                );
                mixed_frames = frame_count;
            }
            if (mixed_frames < frame_count &&
                state->fade.frames_done >= state->fade.total_frames) {
                copy_b_remainder(
                    output_a,
                    (const int16_t *)(uintptr_t)state->output_b,
                    mixed_frames,
                    frame_count
                );
            }
        }
    }

    call_stock_voice_mixer(mixer, output_a, frame_count);
    return worker_result;
}
