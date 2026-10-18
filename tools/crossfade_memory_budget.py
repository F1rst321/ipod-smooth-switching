#!/usr/bin/env python3
"""Estimate PCM look-ahead and a small streaming queue for crossfade.

This is a capacity calculator only. It does not inspect or modify firmware,
allocate target memory, or claim that the RetailOS audio path can use a ring
buffer of the reported size. The private-workspace figure is the full provider-0
BSS range, treated as an isolation candidate rather than a proven per-decoder
allocation. File/cache state, callback scheduling, and allocator overhead are
not included.
"""
from __future__ import annotations

import argparse
import math

MP3_ITEM_BYTES = 0x3BEC
FILTER_HISTORY_BYTES = 0x1110
PROVIDER0_WORKSPACE_BYTES = 0x3C10
VOICE_DESCRIPTOR_MIN_BYTES = 0x4C
TRACK_RESOURCE_BYTES = 700
PLAYER_CONTEXT_PREFIX_BYTES = 0x29E0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-rate", type=int, default=44_100,
                        help="PCM sample rate in Hz (default: 44100)")
    parser.add_argument("--channels", type=int, default=2,
                        help="number of interleaved channels (default: 2)")
    parser.add_argument("--bits-per-sample", type=int, default=16,
                        help="PCM sample width (default: 16)")
    parser.add_argument("--block-frames", type=int, default=1_152,
                        help="frames per firmware PCM block (default: 1152)")
    parser.add_argument("--queued-blocks", type=int, default=4,
                        help="candidate B PCM queue depth (default: 4 blocks)")
    args = parser.parse_args()
    if min(args.sample_rate, args.channels, args.bits_per_sample,
           args.block_frames, args.queued_blocks) <= 0:
        parser.error("all format and block dimensions must be positive")
    if args.bits_per_sample % 8:
        parser.error("bits per sample must be a whole number of bytes")

    bytes_per_frame = args.channels * (args.bits_per_sample // 8)
    block_bytes = args.block_frames * bytes_per_frame
    known_decoder_state_bytes = MP3_ITEM_BYTES + FILTER_HISTORY_BYTES
    b_private_state_bytes = known_decoder_state_bytes + PROVIDER0_WORKSPACE_BYTES
    queued_pcm_bytes = args.queued_blocks * block_bytes
    descriptor_bytes = args.queued_blocks * VOICE_DESCRIPTOR_MIN_BYTES
    streaming_subtotal = (b_private_state_bytes + TRACK_RESOURCE_BYTES
                          + queued_pcm_bytes + descriptor_bytes)
    queued_seconds = args.queued_blocks * args.block_frames / args.sample_rate
    print(f"PCM format: {args.sample_rate} Hz, {args.channels} channels, "
          f"{args.bits_per_sample}-bit; {block_bytes:,} bytes/block")
    print(f"Known private B state: MP3 item {MP3_ITEM_BYTES:,} + filter history "
          f"{FILTER_HISTORY_BYTES:,} = {known_decoder_state_bytes:,} bytes")
    print(f"Optional isolated provider-0 workspace: {PROVIDER0_WORKSPACE_BYTES:,} "
          "bytes (BSS range 0x40002514..0x40006124; ownership not proven)")
    print(f"B track resource allocation observed in factory: {TRACK_RESOURCE_BYTES:,} bytes")
    print(f"Streaming queue candidate: {args.queued_blocks} B blocks = "
          f"{queued_pcm_bytes:,} PCM bytes ({queued_seconds:.3f} s of queued audio)")
    print(f"Minimum descriptor extent: {VOICE_DESCRIPTOR_MIN_BYTES} bytes each "
          f"= {descriptor_bytes:,} bytes; candidate streaming budget: "
          f"{streaming_subtotal:,} bytes with the isolated-workspace candidate")
    print(f"If isolating the track-open routine needs a shadow player, its observed "
          f"field extent is at least {PLAYER_CONTEXT_PREFIX_BYTES:,} bytes; the full "
          "object size and ownership are unknown, so this is not included.")
    print("Queue duration is buffering depth, not the selected crossfade duration. "
          "The voice descriptor's observed fields reach +0x48; its full allocation "
          "size is not known.")
    print("seconds  raw_pcm  whole_blocks  aligned_pcm  pcm_plus_B_context  "
          "two_pcm_queues_plus_B_context")
    for seconds in range(3, 11):
        frames = seconds * args.sample_rate
        raw_bytes = frames * bytes_per_frame
        blocks = math.ceil(frames / args.block_frames)
        aligned_bytes = blocks * block_bytes
        combined_bytes = aligned_bytes + b_private_state_bytes
        two_queue_bytes = 2 * aligned_bytes + b_private_state_bytes
        print(f"{seconds:>7}  {raw_bytes:>8,}  {blocks:>12,}  "
              f"{aligned_bytes:>11,}  {combined_bytes:>16,}  "
              f"{two_queue_bytes:>29,}")
    print("Candidate working-set estimate only: both look-ahead columns add the "
          "provider-0 workspace as an isolation candidate, not a proven private "
          "allocation. They exclude file/stream cache, queue descriptors, extra "
          "DMA handoff storage, allocator overhead, and runtime heap pressure. "
          "The two-queue column counts two aligned PCM buffers plus that candidate B state.")
    print("Audio-path integration and availability during playback remain "
          "unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
