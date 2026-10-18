#!/usr/bin/env python3
"""Estimate PCM look-ahead storage for an iPod crossfade implementation.

This is a capacity calculator only. It does not inspect or modify firmware,
allocate target memory, or claim that the RetailOS audio path can use a ring
buffer of the reported size.
"""
from __future__ import annotations

import argparse
import math


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
    args = parser.parse_args()
    if min(args.sample_rate, args.channels, args.bits_per_sample,
           args.block_frames) <= 0:
        parser.error("all format and block dimensions must be positive")
    if args.bits_per_sample % 8:
        parser.error("bits per sample must be a whole number of bytes")

    bytes_per_frame = args.channels * (args.bits_per_sample // 8)
    block_bytes = args.block_frames * bytes_per_frame
    print(f"PCM format: {args.sample_rate} Hz, {args.channels} channels, "
          f"{args.bits_per_sample}-bit; {block_bytes:,} bytes/block")
    print("seconds  raw_bytes  whole_blocks  block_aligned_bytes")
    for seconds in range(3, 11):
        frames = seconds * args.sample_rate
        raw_bytes = frames * bytes_per_frame
        blocks = math.ceil(frames / args.block_frames)
        aligned_bytes = blocks * block_bytes
        print(f"{seconds:>7}  {raw_bytes:>9,}  {blocks:>12,}  "
              f"{aligned_bytes:>19,}")
    print("Capacity only: runtime heap availability and audio-path integration "
          "remain unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
