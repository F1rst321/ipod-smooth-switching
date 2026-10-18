#!/usr/bin/env python3
"""Estimate PCM look-ahead and a small streaming queue for crossfade.

This is a capacity calculator only. It does not inspect or modify firmware,
allocate target memory, or claim that the RetailOS audio path can use a ring
buffer of the reported size. The private-workspace figure is the full provider-0
BSS range, treated as an isolation candidate rather than a proven per-decoder
allocation. The cloned MP3 sync object and its configured stack are included as
candidate costs. File/cache state, callback scheduling, and allocator overhead
are not included.
"""
from __future__ import annotations

import argparse
import math

MP3_ITEM_BYTES = 0x3BEC
FILTER_HISTORY_BYTES = 0x1110
PROVIDER0_WORKSPACE_BYTES = 0x3C10
VOICE_DESCRIPTOR_MIN_BYTES = 0x4C
TRACK_RESOURCE_BYTES = 700
MP3_SYNC_OBJECT_MIN_BYTES = 0xA4
MP3_SYNC_WORKER_STACK_BYTES = 0x700
TRACK_OPEN_PLAYER_PREFIX_BYTES = 0x29E0
ISOLATED_STREAM_PARENT_BYTES = 0x90C8
FSBUF_BACKING_BUFFER_BYTES = 0x40000
PCM_RING_HEADER_BYTES = 20
IDLE_HIBE_LARGEST_FREE_BLOCK_BYTES = 4_641_944


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
    parser.add_argument("--idle-largest-free", type=int,
                        default=IDLE_HIBE_LARGEST_FREE_BLOCK_BYTES,
                        help="largest block in the saved idle HIBE snapshot; comparison only")
    args = parser.parse_args()
    if min(args.sample_rate, args.channels, args.bits_per_sample,
           args.block_frames, args.queued_blocks, args.idle_largest_free) <= 0:
        parser.error("all format and block dimensions must be positive")
    if args.bits_per_sample % 8:
        parser.error("bits per sample must be a whole number of bytes")

    bytes_per_frame = args.channels * (args.bits_per_sample // 8)
    block_bytes = args.block_frames * bytes_per_frame
    known_decoder_state_bytes = MP3_ITEM_BYTES + FILTER_HISTORY_BYTES
    b_private_state_bytes = known_decoder_state_bytes + PROVIDER0_WORKSPACE_BYTES
    b_sync_control_bytes = MP3_SYNC_OBJECT_MIN_BYTES + MP3_SYNC_WORKER_STACK_BYTES
    queued_pcm_bytes = args.queued_blocks * block_bytes
    ring_overhead_bytes = PCM_RING_HEADER_BYTES + bytes_per_frame
    ring_storage_bytes = queued_pcm_bytes + ring_overhead_bytes
    descriptor_bytes = args.queued_blocks * VOICE_DESCRIPTOR_MIN_BYTES
    streaming_subtotal = (b_private_state_bytes + TRACK_RESOURCE_BYTES
                          + ring_storage_bytes + descriptor_bytes
                          + b_sync_control_bytes)
    isolated_parent_subtotal = streaming_subtotal + ISOLATED_STREAM_PARENT_BYTES
    isolated_fsbuf_subtotal = (isolated_parent_subtotal
                               + FSBUF_BACKING_BUFFER_BYTES)
    queued_seconds = args.queued_blocks * args.block_frames / args.sample_rate
    print(f"PCM format: {args.sample_rate} Hz, {args.channels} channels, "
          f"{args.bits_per_sample}-bit; {block_bytes:,} bytes/block")
    print(f"Known private B state: MP3 item {MP3_ITEM_BYTES:,} + filter history "
          f"{FILTER_HISTORY_BYTES:,} = {known_decoder_state_bytes:,} bytes")
    print(f"Optional isolated provider-0 workspace: {PROVIDER0_WORKSPACE_BYTES:,} "
          "bytes (BSS range 0x40002514..0x40006124; ownership not proven)")
    print(f"B track resource allocation observed in factory: {TRACK_RESOURCE_BYTES:,} bytes")
    print(f"Candidate MP3 sync callback/queue object: at least "
          f"{MP3_SYNC_OBJECT_MIN_BYTES} bytes; configured worker stack "
          f"0x{MP3_SYNC_WORKER_STACK_BYTES:x} = "
          f"{MP3_SYNC_WORKER_STACK_BYTES:,} bytes")
    print(f"Streaming queue candidate: {args.queued_blocks} B blocks = "
          f"{queued_pcm_bytes:,} PCM bytes + {ring_overhead_bytes} ring bytes "
          f"= {ring_storage_bytes:,} total ({queued_seconds:.3f} s of queued audio)")
    print(f"Minimum descriptor extent: {VOICE_DESCRIPTOR_MIN_BYTES} bytes each "
          f"= {descriptor_bytes:,} bytes; candidate streaming budget: "
          f"{streaming_subtotal:,} bytes with the isolated-workspace candidate")
    print(f"If B gets an isolated RMIprimary/FSbuf parent, the constructor writes "
          f"through parent+0x90c5; aligned minimum extent {ISOLATED_STREAM_PARENT_BYTES:,} "
          f"bytes, subtotal with this candidate: "
          f"{isolated_parent_subtotal:,} bytes. Full object size/ownership are unknown.")
    print(f"If B also needs a private FSbuf backing buffer, stock passes a "
          f"0x{FSBUF_BACKING_BUFFER_BYTES:x}-byte buffer for this stream; the "
          f"candidate subtotal becomes {isolated_fsbuf_subtotal:,} bytes. "
          "The second buffer requirement is not yet validated in playback.")
    print(f"Private-stream candidate vs saved idle HIBE largest block: "
          f"{isolated_fsbuf_subtotal:,}/{args.idle_largest_free:,} bytes; "
          f"snapshot-only headroom "
          f"{args.idle_largest_free - isolated_fsbuf_subtotal:,} bytes.")
    print(f"The track-open path separately reaches player+0x29dc; its observed "
          f"prefix is {TRACK_OPEN_PLAYER_PREFIX_BYTES:,} bytes, but the decoder "
          "worker needs the larger parent prefix above if that state is cloned.")
    print("Queue duration is buffering depth, not the selected crossfade duration. "
          "The voice descriptor's observed fields reach +0x48; its full allocation "
          "size is not known.")
    print("seconds  raw_pcm  whole_blocks  aligned_pcm  pcm_plus_B_context  "
          "two_pcm_queues_plus_B_context  two_queues_plus_parent_candidate  "
          "two_queues_plus_parent_and_fsbuf")
    for seconds in range(3, 11):
        frames = seconds * args.sample_rate
        raw_bytes = frames * bytes_per_frame
        blocks = math.ceil(frames / args.block_frames)
        aligned_bytes = blocks * block_bytes
        combined_bytes = aligned_bytes + b_private_state_bytes + b_sync_control_bytes
        two_queue_bytes = (2 * aligned_bytes + b_private_state_bytes
                           + b_sync_control_bytes)
        two_queue_parent_bytes = two_queue_bytes + ISOLATED_STREAM_PARENT_BYTES
        two_queue_fsbuf_bytes = (two_queue_parent_bytes
                                 + FSBUF_BACKING_BUFFER_BYTES)
        print(f"{seconds:>7}  {raw_bytes:>8,}  {blocks:>12,}  "
              f"{aligned_bytes:>11,}  {combined_bytes:>16,}  "
              f"{two_queue_bytes:>29,}  {two_queue_parent_bytes:>32,}  "
              f"{two_queue_fsbuf_bytes:>36,}")
    max_fade_frames = 10 * args.sample_rate
    max_fade_blocks = math.ceil(max_fade_frames / args.block_frames)
    max_fade_pcm = max_fade_blocks * block_bytes
    max_fade_candidate = (2 * max_fade_pcm + b_private_state_bytes
                          + b_sync_control_bytes + ISOLATED_STREAM_PARENT_BYTES
                          + FSBUF_BACKING_BUFFER_BYTES)
    print(f"10-second two-queue subtotal vs saved idle HIBE largest block: "
          f"{max_fade_candidate:,}/{args.idle_largest_free:,} bytes; "
          f"snapshot-only headroom {args.idle_largest_free - max_fade_candidate:,} bytes")
    print("Candidate working-set estimate only: both look-ahead columns add the "
          "provider-0 workspace as an isolation candidate, not a proven private "
          "allocation. They include one minimum callback/queue object and the "
          "MP3 queue's configured 0x700-byte worker stack as candidate costs. "
          "They exclude file/stream cache, PCM descriptors, extra DMA handoff "
          "storage, allocator overhead, and runtime heap pressure. The final "
          "parent column adds the observed minimum RMIprimary/FSbuf extent, not a "
          "validated second instance. The two-queue columns count two aligned PCM buffers plus "
          "that candidate B state; the final column also adds one private 0x40000-byte "
          "FSbuf backing-buffer candidate. "
          "The HIBE comparison is not a playback-time capacity guarantee.")
    print("Audio-path integration and availability during playback remain "
          "unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
