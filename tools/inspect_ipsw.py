#!/usr/bin/env python3
"""Read-only inventory for an iPod firmware IPSW (ZIP) package."""
from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path


def sha1_file(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipsw", type=Path, help="path to an IPSW firmware package")
    args = parser.parse_args()

    path = args.ipsw
    if not path.is_file():
        parser.error(f"file not found: {path}")

    print(f"File: {path}")
    print(f"Size: {path.stat().st_size:,} bytes")
    print(f"SHA-1: {sha1_file(path)}")

    try:
        with zipfile.ZipFile(path) as archive:
            bad_member = archive.testzip()
            if bad_member:
                print(f"ZIP integrity: failed at {bad_member}", file=sys.stderr)
                return 2
            print("ZIP integrity: OK")
            print("\nPackage entries:")
            for entry in archive.infolist():
                print(f"{entry.file_size:>12,}  {entry.filename}")
    except zipfile.BadZipFile:
        print("Error: the file is not a readable ZIP/IPSW package", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
