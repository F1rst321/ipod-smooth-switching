# iPod Video Crossfade

Research project to add configurable track crossfade to the original Apple firmware on an iPod Video 5.5G, 30 GB (late 2006, white; firmware 1.3).

## Development languages

- Python: inspect firmware packages and build repeatable analysis/patching tools.
- C and ARM assembly: runtime code changes, if firmware analysis confirms this is practical.

## Current milestone

Safely identify and inspect the stock firmware package. No device writing or firmware patching is performed by the initial tool.

The device-reported version is 1.3. The matching late-2006 30 GB firmware family is `iPod_25.1.3.ipsw`; verify the downloaded package before analysis.

## Workflow

1. Preserve an untouched copy of the stock firmware and record its hash.
2. Inspect the package and identify the RetailOS image and its format.
3. Analyze the playback path and determine where PCM samples can be mixed.
4. Prototype and validate the crossfade logic away from the device.
5. Build a reversible firmware patch and document recovery steps before any device installation.

## Usage

Run `python tools/inspect_ipsw.py path\to\iPod_25.1.3.ipsw` to list package entries and print the package SHA-1.

## Backup of the firmware currently on the iPod

Windows restricts raw-disk access to an elevated PowerShell session. In PowerShell opened **as Administrator**, run this from the project directory (confirm the disk number and drive letter first):

```powershell
python .\tools\backup_ipod_firmware.py --disk-number 1 --data-drive E --output .\firmware\ipod_video_5.5g_30gb_stock_partition1.img
```

The script opens the physical disk read-only, verifies the iPod partition layout, cross-checks its FAT32 data partition against the selected drive letter, and refuses to overwrite an existing backup. It writes a raw image of the iPod firmware partition plus a JSON manifest with its SHA-256 hash.

Some USB bridges report a 2048-byte logical sector size for this iPod. The reader now obtains that size from Windows and aligns raw reads accordingly, while interpreting MBR partition offsets in 512-byte units. The backup file still contains only the exact byte range of the firmware partition.

The official Apple restore package `firmware/iPod_25.1.3.ipsw` is already downloaded and verified separately. It is a clean restore image, not a read-back of the copy currently installed on the device.
