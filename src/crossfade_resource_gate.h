/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef IPOD_CROSSFADE_RESOURCE_GATE_H
#define IPOD_CROSSFADE_RESOURCE_GATE_H

#include <stdint.h>

/* Stock RetailOS 1.3 entry point; ARM state. */
#define IPOD_CROSSFADE_TRACK_RESOURCE_FACTORY 0x1010B894U

/*
 * Open a separate resource for track B while retaining track A's shared
 * registry entries. This only opens the file resource; it does not start a
 * second decoder or audio stream.
 */
int32_t ipod_crossfade_open_track_resource_b(
    void *player,
    void *track_b,
    void **resource_out
);

typedef struct {
    volatile uint32_t expected_parent;
    volatile uint32_t expected_track_id;
    volatile uint32_t armed;
} ipod_crossfade_resource_gate_state_t;

extern volatile ipod_crossfade_resource_gate_state_t
    ipod_crossfade_resource_gate_state;

#endif
