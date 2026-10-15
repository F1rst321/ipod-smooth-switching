#!/usr/bin/env python3
"""Render a linear 3-10 second crossfade between two PCM16 WAV tracks.

This host-side audio prototype does not modify iPod firmware.
"""
from __future__ import annotations

import argparse
import struct
import wave
from pathlib import Path


CHUNK_FRAMES = 4096


def copy_frames(source: wave.Wave_read, target: wave.Wave_write, count: int) -> None:
    while count:
        frames = min(CHUNK_FRAMES, count)
        data = source.readframes(frames)
        if len(data) != frames * source.getnchannels() * 2:
            raise ValueError("WAV ended before the declared number of frames")
        target.writeframesraw(data)
        count -= frames


def mix_pcm16(left: bytes, right: bytes, channels: int, first_frame: int,
              overlap_frames: int) -> bytes:
    """Mix a chunk with exact end points and symmetric integer rounding."""
    if len(left) != len(right) or len(left) % (channels * 2):
        raise ValueError("PCM chunks must have equal whole-frame lengths")
    sample_count = len(left) // 2
    a_samples = struct.unpack(f"<{sample_count}h", left)
    b_samples = struct.unpack(f"<{sample_count}h", right)
    denominator = overlap_frames - 1
    mixed = []
    for sample_index, (a, b) in enumerate(zip(a_samples, b_samples)):
        frame = first_frame + sample_index // channels
        numerator = a * (denominator - frame) + b * frame
        if numerator >= 0:
            value = (numerator + denominator // 2) // denominator
        else:
            value = -((-numerator + denominator // 2) // denominator)
        mixed.append(value)
    return struct.pack(f"<{sample_count}h", *mixed)


def render(left_path: Path, right_path: Path, output_path: Path, seconds: int) -> None:
    if not 3 <= seconds <= 10:
        raise ValueError("duration must be an integer from 3 to 10 seconds")
    if output_path.exists():
        raise FileExistsError(f"output already exists: {output_path}")
    with wave.open(str(left_path), "rb") as left, wave.open(str(right_path), "rb") as right:
        if left.getcomptype() != "NONE" or right.getcomptype() != "NONE":
            raise ValueError("both inputs must be uncompressed PCM WAV")
        if left.getsampwidth() != 2 or right.getsampwidth() != 2:
            raise ValueError("both inputs must be 16-bit PCM")
        if left.getframerate() != right.getframerate() or left.getnchannels() != right.getnchannels():
            raise ValueError("inputs must have identical sample rate and channel count")
        if left.getnchannels() not in (1, 2):
            raise ValueError("only mono and stereo are supported")
        overlap = seconds * left.getframerate()
        if overlap < 2 or left.getnframes() < overlap or right.getnframes() < overlap:
            raise ValueError("both tracks must be at least as long as the crossfade")

        # Exclusive creation protects source files and any earlier preview.
        with output_path.open("xb") as output_file:
            with wave.open(output_file, "wb") as target:
                target.setparams(left.getparams())
                copy_frames(left, target, left.getnframes() - overlap)
                for first_frame in range(0, overlap, CHUNK_FRAMES):
                    frames = min(CHUNK_FRAMES, overlap - first_frame)
                    byte_count = frames * left.getnchannels() * 2
                    a = left.readframes(frames)
                    b = right.readframes(frames)
                    if len(a) != byte_count or len(b) != byte_count:
                        raise ValueError("WAV ended during crossfade")
                    target.writeframesraw(mix_pcm16(a, b, left.getnchannels(), first_frame, overlap))
                copy_frames(right, target, right.getnframes() - overlap)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--seconds", type=int, required=True)
    args = parser.parse_args()
    try:
        render(args.first, args.second, args.output, args.seconds)
    except (OSError, EOFError, ValueError, wave.Error) as exc:
        parser.error(str(exc))
    print(f"Wrote crossfade preview: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
