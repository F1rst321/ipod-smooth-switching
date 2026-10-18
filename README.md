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

Run `py tools/inspect_ipsw.py path\to\iPod_25.1.3.ipsw` to list package entries and print the package SHA-1.

Extract OSOS and RSRC to a new directory (the firmware files are ignored by Git):

```powershell
py .\tools\extract_firmware_images.py .\firmware\iPod_25.1.3.ipsw --output-dir .\firmware\extracted\official
```

The extractor refuses to overwrite an existing output directory and records source/component hashes in `manifest.json`. Search a component directly from IPSW without creating an extracted binary:

```powershell
py .\tools\find_firmware_strings.py .\firmware\iPod_25.1.3.ipsw --type OSOS --contains audio
py .\tools\find_firmware_strings.py .\firmware\iPod_25.1.3.ipsw --type RSRC --contains settings
```

See [`docs/RESEARCH_STATUS.md`](docs/RESEARCH_STATUS.md) for current findings and the reverse-engineering sequence.
The latest verified audio references, stock Settings resource map, and offline
partition-image builder are described in [`docs/AUDIO_XREF_NOTES.md`](docs/AUDIO_XREF_NOTES.md),
[`ui/stock_resource_map.md`](ui/stock_resource_map.md), and
[`docs/IMAGE_FORMAT.md`](docs/IMAGE_FORMAT.md).
To reproduce the HIBE/OSOS comparison and list runtime references to the audio endpoints, run
`py .\tools\analyze_hibe_runtime.py .\firmware\ipod_video_5.5g_30gb_stock_partition1.img`.
To inspect the saved I²S interface registry and queued object vtables without accessing the iPod, run
`py .\tools\inspect_hibe_audio.py .\firmware\ipod_video_5.5g_30gb_stock_partition1.img`.
To report all-zero OSOS ranges and possible address-like words without changing the backup, run
`py .\tools\inspect_osos_code_caves.py .\firmware\ipod_video_5.5g_30gb_stock_partition1.img`.

The audio worker is copied into IRAM in noncontiguous sections. Direct ARM
calls from its OSOS bytes can point to different functions at runtime; use
`tools/trace_iram_calls.py` with a local IRAM capture before assigning a
callee. The verified example is in
[`docs/AUDIO_XREF_NOTES.md`](docs/AUDIO_XREF_NOTES.md#коррекция-прямых-вызовов-в-iram).

The distinction between growing the firmware file and reserving runtime PCM
memory is documented in [`docs/RUNTIME_BUFFER_PLAN.md`](docs/RUNTIME_BUFFER_PLAN.md).

For a host-side demonstration of the mixing algorithm, use two uncompressed 16-bit WAV files with the same sample rate and channel count:

```powershell
py .\tools\crossfade_preview.py .\first.wav .\second.wav .\crossfade.wav --seconds 5
```

This creates a linear crossfade of 3–10 seconds without modifying either input. It runs on the computer and is not an iPod firmware patch. The ARM I²S and DMA literal references in the exact OSOS image can be reproduced with `tools/find_arm_literal_references.py`; see [`docs/AUDIO_PATH.md`](docs/AUDIO_PATH.md).

The requested click-wheel settings screen is documented in [`docs/UI_CONCEPT.md`](docs/UI_CONCEPT.md); the visual mockup is [`docs/mockups/crossfade-wheel-settings.png`](docs/mockups/crossfade-wheel-settings.png). It is a design preview, not a firmware screenshot.

Check that known RetailOS 1.3 UI and PCM hook signatures still match the input image:

```powershell
py .\tools\check_research_hooks.py .\firmware\iPod_25.1.3.ipsw
```

For ARM disassembly, install the optional analyzer dependency once in the project interpreter:

```powershell
py -m pip install -r .\requirements-analysis.txt
py .\tools\disassemble_arm.py .\firmware\iPod_25.1.3.ipsw --start 0x21f254 --count 64
```

To locate direct ARM `BL` callers of a byte offset in OSOS, use the read-only helper:

```powershell
py .\tools\find_arm_callers.py .\firmware\iPod_25.1.3.ipsw --target 0x25a614
```

It does not find Thumb or indirect calls, and every match must be checked in context before being treated as a code reference.

To scan direct Thumb-1 `BL` pairs to an OSOS offset:

```powershell
py .\tools\find_thumb_callers.py .\firmware\iPod_25.1.3.ipsw --target 0x25db30
```

This scan also reports raw byte-pattern candidates, not confirmed reachable calls; it does not find indirect calls.

To search for aligned image-relative or absolute 32-bit pointers to an OSOS string or function, use:

```powershell
py .\tools\find_pointer_references.py .\firmware\iPod_25.1.3.ipsw --target 0x213e10
```

This scans aligned image-relative and absolute pointer words; a lack of matches does not mean the target is unused. PC-relative, Thumb, and computed references require other analysis.

## Backup of the firmware currently on the iPod

Windows restricts raw-disk access to an elevated PowerShell session. In PowerShell opened **as Administrator**, run this from the project directory (confirm the disk number and drive letter first):

```powershell
py .\tools\backup_ipod_firmware.py --disk-number 1 --data-drive E --output .\firmware\ipod_video_5.5g_30gb_stock_partition1.img
```

The script opens the physical disk read-only, verifies the iPod partition layout, cross-checks its FAT32 data partition against the selected drive letter, and refuses to overwrite an existing backup. It writes a raw image of the iPod firmware partition plus a JSON manifest with its SHA-256 hash.

Some USB bridges report a 2048-byte logical sector size for this iPod. The reader obtains that size from Windows and aligns raw reads accordingly. It determines whether the MBR partition addresses use 512-byte or device-sized units by matching both the data partition offset and size against Windows before reading. The backup file contains only the exact byte range of the firmware partition.

The official Apple restore package `firmware/iPod_25.1.3.ipsw` is already downloaded and verified separately. It is a clean restore image, not a read-back of the copy currently installed on the device.

The raw backup is a read-only recovery original. Do not use it as an output path or modify it. Any future build must start from a separate copy of the full device backup, preserve data outside the IPSW payload, and write to a new output path. The analysis commands only read the backup.

The read-back partition has been compared with the IPSW component by component. OSOS, RSRC, and AUPD match the official payload byte for byte. The 35 differences in the first 13,905,920 bytes are confined to firmware-directory metadata at offsets `0x4224`–`0x42c8`; the partition also contains additional data after the IPSW payload. Keep the full device backup as the recovery source and do not replace it with the smaller IPSW payload.

To inspect the image directory in the local backup and compare it with the IPSW payload, run:

```powershell
py .\tools\inspect_firmware_partition.py --image .\firmware\ipod_video_5.5g_30gb_stock_partition1.img --ipsw .\firmware\iPod_25.1.3.ipsw --sector-size 2048
```

This checks each directory entry's bounds and reports whether the stored checksum field matches a simple byte sum; the field may use a different meaning for some image types.

To inspect the RetailOS heap free list saved in the HIBE snapshot:

```powershell
py .\tools\inspect_hibe_heap.py .\firmware\ipod_video_5.5g_30gb_stock_partition1.img
```

This validates the saved allocator links and reports its free blocks. It is a read-only audit of one saved state; it does not promise the same free memory during playback.

To compare the raw bytes of the backup and IPSW payload without extracting either file, run:

```powershell
py .\tools\compare_firmware_backup.py --ipsw .\firmware\iPod_25.1.3.ipsw --backup .\firmware\ipod_video_5.5g_30gb_stock_partition1.img
```

Firmware images and device backups stay under `firmware/`, which Git ignores; only source code and documentation belong in the public repository.

## What is ready

The project contains read-only backup and firmware inspection tools (including an HIBE heap free-list audit), a component-level comparison against Apple's IPSW, a computer-side WAV crossfade prototype, an isolated ARM7TDMI PCM16 mixer and runtime ring buffer, a mocked ARM/Thumb helper for a second track resource, and Unicorn checks that run stock MP3 items in sequence A→B→A with separate callback/history state. A separate experimental OSOS candidate adds a Settings row, 3–10-second labels, and property getter/setter handlers; these handlers pass Unicorn checks with modeled stock continuations and string APIs. The candidate's full partition passes structural checks. The Click Wheel behavior, runtime code-window ownership, on-device persistence, a second real decoder, and the connection from mixed PCM to the stock playback output remain unverified. There is no installable crossfade firmware yet. See [the Settings candidate notes](docs/SETTINGS_CANDIDATE.md) and [the mixer core notes](docs/CROSSFADE_CORE.md). Structural image checks cannot establish boot, UI, or audio behavior.
