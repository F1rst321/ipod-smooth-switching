/* SPDX-License-Identifier: GPL-3.0-only */
#include "crossfade_pcm_ring.h"

#include <stddef.h>
#include <stdint.h>

#define RING_MAGIC 0x43524644U
#define BYTES_PER_SAMPLE 2U

static void compiler_barrier(void) {
    __asm__ volatile ("" ::: "memory");
}

static uint32_t queued_frames(
    uint32_t capacity_frames,
    uint32_t read_frame,
    uint32_t write_frame
) {
    if (write_frame >= read_frame) {
        return write_frame - read_frame;
    }
    return capacity_frames - read_frame + write_frame;
}

static int ring_is_valid(const ipod_crossfade_pcm_ring_t *ring) {
    uint32_t read_frame;
    uint32_t write_frame;

    if (ring == 0 || ring->magic != RING_MAGIC || ring->capacity_frames < 2U ||
        (ring->channels != 1U && ring->channels != 2U)) {
        return 0;
    }

    read_frame = ring->read_frame;
    write_frame = ring->write_frame;
    return read_frame < ring->capacity_frames && write_frame < ring->capacity_frames;
}

uint32_t ipod_crossfade_pcm_ring_storage_bytes(
    uint32_t channels,
    uint32_t block_frames,
    uint32_t queue_blocks
) {
    uint32_t frame_bytes;
    uint32_t usable_frames;
    uint32_t capacity_frames;
    uint32_t maximum_frames;

    if ((channels != 1U && channels != 2U) || block_frames == 0U ||
        queue_blocks == 0U) {
        return 0U;
    }

    frame_bytes = channels * BYTES_PER_SAMPLE;
    maximum_frames = (UINT32_MAX - (uint32_t)sizeof(ipod_crossfade_pcm_ring_t)) /
        frame_bytes;
    if (block_frames > (maximum_frames - 1U) / queue_blocks) {
        return 0U;
    }

    usable_frames = block_frames * queue_blocks;
    capacity_frames = usable_frames + 1U;
    return (uint32_t)sizeof(ipod_crossfade_pcm_ring_t) +
        capacity_frames * frame_bytes;
}

ipod_crossfade_pcm_ring_t *ipod_crossfade_pcm_ring_init(
    void *storage,
    uint32_t storage_bytes,
    uint32_t channels,
    uint32_t block_frames,
    uint32_t queue_blocks
) {
    uint32_t required_bytes;
    uint32_t capacity_frames;
    ipod_crossfade_pcm_ring_t *ring;

    required_bytes = ipod_crossfade_pcm_ring_storage_bytes(
        channels,
        block_frames,
        queue_blocks
    );
    if (storage == 0 || required_bytes == 0U || storage_bytes < required_bytes ||
        (((uintptr_t)storage) & 3U) != 0U) {
        return 0;
    }

    ring = (ipod_crossfade_pcm_ring_t *)storage;
    capacity_frames = block_frames * queue_blocks + 1U;
    ring->capacity_frames = capacity_frames;
    ring->channels = channels;
    ring->read_frame = 0U;
    ring->write_frame = 0U;
    ring->magic = RING_MAGIC;
    return ring;
}

uint32_t ipod_crossfade_pcm_ring_available(
    const ipod_crossfade_pcm_ring_t *ring
) {
    uint32_t read_frame;
    uint32_t write_frame;

    if (!ring_is_valid(ring)) {
        return 0U;
    }

    read_frame = ring->read_frame;
    write_frame = ring->write_frame;
    return queued_frames(ring->capacity_frames, read_frame, write_frame);
}

uint32_t ipod_crossfade_pcm_ring_write(
    ipod_crossfade_pcm_ring_t *ring,
    const int16_t *samples,
    uint32_t frame_count
) {
    uint32_t read_frame;
    uint32_t write_frame;
    uint32_t used_frames;
    uint32_t free_frames;
    uint32_t copied_frames;
    uint32_t first_frames;
    uint32_t next_frame;
    uint32_t sample_count;
    uint32_t index;

    if (samples == 0 || frame_count == 0U || !ring_is_valid(ring)) {
        return 0U;
    }

    read_frame = ring->read_frame;
    write_frame = ring->write_frame;
    used_frames = queued_frames(ring->capacity_frames, read_frame, write_frame);
    free_frames = ring->capacity_frames - 1U - used_frames;
    copied_frames = frame_count < free_frames ? frame_count : free_frames;
    if (copied_frames == 0U) {
        return 0U;
    }

    first_frames = ring->capacity_frames - write_frame;
    if (first_frames > copied_frames) {
        first_frames = copied_frames;
    }

    sample_count = first_frames * ring->channels;
    for (index = 0U; index < sample_count; ++index) {
        ring->samples[write_frame * ring->channels + index] = samples[index];
    }

    sample_count = (copied_frames - first_frames) * ring->channels;
    for (index = 0U; index < sample_count; ++index) {
        ring->samples[index] = samples[first_frames * ring->channels + index];
    }

    next_frame = write_frame + copied_frames;
    if (next_frame >= ring->capacity_frames) {
        next_frame -= ring->capacity_frames;
    }
    compiler_barrier();
    ring->write_frame = next_frame;
    return copied_frames;
}

uint32_t ipod_crossfade_pcm_ring_read(
    ipod_crossfade_pcm_ring_t *ring,
    int16_t *samples,
    uint32_t frame_count
) {
    uint32_t read_frame;
    uint32_t write_frame;
    uint32_t available_frames;
    uint32_t copied_frames;
    uint32_t first_frames;
    uint32_t next_frame;
    uint32_t sample_count;
    uint32_t index;

    if (samples == 0 || frame_count == 0U || !ring_is_valid(ring)) {
        return 0U;
    }

    read_frame = ring->read_frame;
    write_frame = ring->write_frame;
    available_frames = queued_frames(ring->capacity_frames, read_frame, write_frame);
    copied_frames = frame_count < available_frames ? frame_count : available_frames;
    if (copied_frames == 0U) {
        return 0U;
    }

    first_frames = ring->capacity_frames - read_frame;
    if (first_frames > copied_frames) {
        first_frames = copied_frames;
    }

    sample_count = first_frames * ring->channels;
    for (index = 0U; index < sample_count; ++index) {
        samples[index] = ring->samples[read_frame * ring->channels + index];
    }

    sample_count = (copied_frames - first_frames) * ring->channels;
    for (index = 0U; index < sample_count; ++index) {
        samples[first_frames * ring->channels + index] = ring->samples[index];
    }

    next_frame = read_frame + copied_frames;
    if (next_frame >= ring->capacity_frames) {
        next_frame -= ring->capacity_frames;
    }
    compiler_barrier();
    ring->read_frame = next_frame;
    return copied_frames;
}
