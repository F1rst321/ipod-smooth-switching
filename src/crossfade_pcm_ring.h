/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef IPOD_CROSSFADE_PCM_RING_H
#define IPOD_CROSSFADE_PCM_RING_H

#include <stdint.h>

/* RetailOS 1.3 OSOS entry points at load base 0x10000000. */
#define IPOD_CROSSFADE_RETAILOS_HEAP_ALLOC 0x1025A974U
#define IPOD_CROSSFADE_RETAILOS_HEAP_FREE 0x1025A8F4U

/*
 * Single-producer/single-consumer ring for already decoded interleaved PCM16.
 * The producer is the decoder worker; the consumer is the audio path. Both
 * sides must stop before the backing allocation is released.
 */
typedef struct {
    uint32_t magic;
    uint32_t capacity_frames;
    uint32_t channels;
    volatile uint32_t read_frame;
    volatile uint32_t write_frame;
    int16_t samples[];
} ipod_crossfade_pcm_ring_t;

/* Return zero for invalid geometry or a size that overflows uint32_t. */
uint32_t ipod_crossfade_pcm_ring_storage_bytes(
    uint32_t channels,
    uint32_t block_frames,
    uint32_t queue_blocks
);

/*
 * Allocate from the stock RetailOS heap. Call from a task, before playback
 * callback use; returns null if the request cannot be satisfied.
 */
ipod_crossfade_pcm_ring_t *ipod_crossfade_pcm_ring_create(
    uint32_t channels,
    uint32_t block_frames,
    uint32_t queue_blocks
);

/* Call only after both ring users have stopped. */
void ipod_crossfade_pcm_ring_destroy(ipod_crossfade_pcm_ring_t *ring);

/* Initialize in place inside one block returned by the RetailOS heap. */
ipod_crossfade_pcm_ring_t *ipod_crossfade_pcm_ring_init(
    void *storage,
    uint32_t storage_bytes,
    uint32_t channels,
    uint32_t block_frames,
    uint32_t queue_blocks
);

/* Copy up to frame_count frames. Each operation is non-blocking. */
uint32_t ipod_crossfade_pcm_ring_write(
    ipod_crossfade_pcm_ring_t *ring,
    const int16_t *samples,
    uint32_t frame_count
);

uint32_t ipod_crossfade_pcm_ring_read(
    ipod_crossfade_pcm_ring_t *ring,
    int16_t *samples,
    uint32_t frame_count
);

/* Snapshot of queued frames; concurrent reads may change the result. */
uint32_t ipod_crossfade_pcm_ring_available(
    const ipod_crossfade_pcm_ring_t *ring
);

#endif
