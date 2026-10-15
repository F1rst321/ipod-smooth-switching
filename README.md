# iPod Video Crossfade

Research project to add configurable track crossfade to the original Apple firmware on an iPod Video 5.5G, 30 GB (late 2006, white; firmware 1.3).

## Development languages

- Python: inspect firmware packages and build repeatable analysis/patching tools.
- C and ARM assembly: runtime code changes, if firmware analysis confirms this is practical.

## Current milestone

Create verified, local working copies of firmware components and map the exact settings and audio playback code before implementing a patch. The tools do not write to the iPod and do not distribute Apple's firmware files.

The device-reported version is 1.3. The matching late-2006 30 GB firmware family is `iPod_25.1.3.ipsw`; verify the downloaded package before analysis.

## Workflow

1. Preserve an untouched copy of the stock firmware and record its hash.
2. Inspect the package and identify the RetailOS image and its format.
3. Analyze the playback path and determine where PCM samples can be mixed.
4. Prototype and validate the crossfade logic away from the device.
5. Build a reversible firmware patch and document recovery steps before any device installation.

## Usage

Run `python tools/inspect_ipsw.py path\to\iPod_25.1.3.ipsw` to list package entries and print the package SHA-1.

Extract OSOS and RSRC to a new directory (the firmware files are ignored by Git):

```powershell
python .\tools\extract_firmware_images.py .\firmware\iPod_25.1.3.ipsw --output-dir .\firmware\extracted\official
```

The extractor refuses to overwrite an existing output directory and records source/component hashes in `manifest.json`. Search a component directly from IPSW without creating an extracted binary:

```powershell
python .\tools\find_firmware_strings.py .\firmware\iPod_25.1.3.ipsw --type OSOS --contains audio
python .\tools\find_firmware_strings.py .\firmware\iPod_25.1.3.ipsw --type RSRC --contains settings
```

See [`docs/RESEARCH_STATUS.md`](docs/RESEARCH_STATUS.md) for current findings and the reverse-engineering sequence.

## Backup of the firmware currently on the iPod

Windows restricts raw-disk access to an elevated PowerShell session. In PowerShell opened **as Administrator**, run this from the project directory (confirm the disk number and drive letter first):

```powershell
python .\tools\backup_ipod_firmware.py --disk-number 1 --data-drive E --output .\firmware\ipod_video_5.5g_30gb_stock_partition1.img
```

The script opens the physical disk read-only, verifies the iPod partition layout, cross-checks its FAT32 data partition against the selected drive letter, and refuses to overwrite an existing backup. It writes a raw image of the iPod firmware partition plus a JSON manifest with its SHA-256 hash.

Some USB bridges report a 2048-byte logical sector size for this iPod. The reader obtains that size from Windows and aligns raw reads accordingly. It determines whether the MBR partition addresses use 512-byte or device-sized units by matching both the data partition offset and size against Windows before reading. The backup file contains only the exact byte range of the firmware partition.

The official Apple restore package `firmware/iPod_25.1.3.ipsw` is already downloaded and verified separately. It is a clean restore image, not a read-back of the copy currently installed on the device.

To inspect the image directory in the local backup and compare it with the IPSW payload, run:

```powershell
python .\tools\inspect_firmware_partition.py --image .\firmware\ipod_video_5.5g_30gb_stock_partition1.img --ipsw .\firmware\iPod_25.1.3.ipsw --sector-size 2048
```

This checks each directory entry's bounds and reports whether the stored checksum field matches a simple byte sum; the field may use a different meaning for some image types.

To compare the raw bytes of the backup and IPSW payload without extracting either file, run:

```powershell
python .\tools\compare_firmware_backup.py --ipsw .\firmware\iPod_25.1.3.ipsw --backup .\firmware\ipod_video_5.5g_30gb_stock_partition1.img
```

Firmware images and device backups stay under `firmware/`, which Git ignores; only source code and documentation belong in the public repository.
