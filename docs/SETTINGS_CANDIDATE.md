# Experimental Settings candidate

This note covers the offline RetailOS 1.3 candidate assembled from the exact
stock OSOS and the settings-hook source. It is a research artifact, not a
firmware release for installation.

## What is in the candidate

- Settings menu 24598 has a nineteenth row, «Плавный переход».
- The row uses property key `0x6089` and the existing Volume Limit View 17538
  as a layout hypothesis.
- Localized resource records provide the label and values from 3 to 10 seconds.
- The new property getter and setter clamp values to 3–10. The setter writes
  candidate preference byte `preferences+0xb70` and marks the stock dirty byte
  `preferences+0xb74` so the regular preference writer can persist it.
- The two existing empty `0x6089` switch arms branch to ARM7TDMI handlers in
  an all-zero OSOS range. OSOS length and the firmware-partition layout stay
  unchanged.

The resource builder relocates the affected tables and menu into the audited
16,804-byte zero window at OSOS `+0x712000`. The current prototype places 7,975
resource bytes there. The 296-byte settings handler starts at `+0x714000`.
Static ownership of the zero window at runtime has not been proven, so fitting
the payload in the file does not prove that it is safe to execute on the iPod.
The code cave is not extra physical RAM. The current playback helper places one
4,608-byte B output block there; decoder state, track resources, and any larger
PCM ring still need separately reserved runtime heap memory.

## Rebuild and check

Run from the project root in PowerShell:

```powershell
.\.venv\Scripts\python.exe .\tools\build_settings_hooks.py
.\.venv\Scripts\python.exe .\tools\build_crossfade_osos_candidate.py `
  .\firmware\extracted\audio-analysis\osos.bin `
  .\build\settings-hooks\crossfade_settings.bin `
  --output .\build\crossfade-settings-candidate-osos.bin
.\.venv\Scripts\python.exe .\tools\verify_crossfade_settings.py `
  .\build\crossfade-settings-candidate-osos.bin
.\.venv\Scripts\python.exe .\tools\build_partition_image.py build `
  --backup .\firmware\ipod_video_5.5g_30gb_stock_partition1.img `
  --osos .\build\crossfade-settings-candidate-osos.bin `
  --output .\build\crossfade-settings-candidate-partition1.img
.\.venv\Scripts\python.exe .\tools\build_partition_image.py verify `
  --backup .\firmware\ipod_video_5.5g_30gb_stock_partition1.img `
  --image .\build\crossfade-settings-candidate-partition1.img
```

The Unicorn check covers raw values, clamping, a default value, localized
string IDs, the preference dirty marker, and null-pointer failure handling.
The stock return sites and string provider/lookup functions are modeled with
test stubs. This does not verify the actual RetailOS call path or persistence
on the device. The partition builder verifies the container layout, permitted
changed bytes, and OSOS byte-sum field; it cannot verify boot, screen behavior,
or audio.

The candidate built on 2026-10-18 has OSOS SHA-256
`ec8511fe02b21a8c46d42e0201d2e12d33586f496ee3c5e41fb6f8bb76f380fd` and full
partition SHA-256
`422945c2471513c37ec63c5aeff3ee5491aa64c880fc064a4bd5cac0f8cdef22`.
Both output files are under ignored `build/`; they contain Apple firmware and
are not committed to GitHub. The original backup in the project and the copy
on `D:\` still match SHA-256
`010bda520671d86a5a2cb010b57ee4484c980e54d97eb3e12621e08cde0423a3`.

## Composite offline candidate with the playback hook

On 2026-10-18 a separate ignored build combined the same Settings prototype
with the experimental worker-B helper and an ARM `BL` patch at
`OSOS+0x1d606c`, before the stock voice mixer. The helper is linked at
`0x10714200`; its static configuration starts disabled, so this image does not
start a second track by itself. The OSOS SHA-256 is
`482543c9e0a6a9acfa934d5718309872d87713ef7c259017882efacec0b10a3d`; the
structurally checked partition SHA-256 is
`825aabf22c3f7aa73bbfc7337a60adb8eb19faad1303212e90d1e6e8d2dda343`.
The image is under ignored `build/` and is a research artifact, not a release.

Rebuild the optional audio payload and combined OSOS with:

```powershell
py .\tools\build_crossfade_mixer.py --load-address 0x10714200 --output-dir .\build\crossfade-audio-hook
py .\tools\build_crossfade_osos_candidate.py `
  .\firmware\extracted\audio-analysis\osos.bin `
  .\build\settings-hooks\crossfade_settings.bin `
  --audio-payload .\build\crossfade-audio-hook\crossfade_mixer.bin `
  --output .\build\crossfade-settings-audio-hook-prototype-osos.bin
```

The branch target, embedded payload bytes, resource table, image directory, and
OSOS checksum were checked offline. The next-track item/resource lifecycle,
Settings-to-fade control, boot, UI, persistence, and audio on the physical iPod
are still unverified; do not install this candidate.

## One-block B scratch prototype

The playback helper now reserves a 4,608-byte static scratch block in the
payload window at `0x10714988`. This fits the 1,152 stereo PCM16 frames emitted
by the emulated MP3 worker and avoids calling the allocator from the audio
callback. The candidate builder checks that the initialized hook state points
to this symbol and that the full block stays inside the 16,804-byte OSOS window.

The rebuilt offline research image has OSOS SHA-256
`28316a0d998f5ae9ff6c3bab7bf198c904ad4c29fbfc4f5f25b33ebd44ac8acc` and
partition SHA-256
`cdbe85661207f6d8a264cade95858f866b0094b82c310c1ffd43735add9c2247`.
The Settings handler emulation, A/B MP3 worker scenario, PCM helper checks, and
partition structural verification passed. The hook remains default-disabled;
it still has no B item/resource setup or fade trigger, and the OSOS window's
runtime ownership and physical audio behavior remain unverified. This remains
a research image, not an installable firmware release.

## Work still required before a device-ready release

1. Establish the actual Settings-row and Click Wheel event path. The existing
   Volume Limit View has not been shown to provide the requested adjustable
   3–10-second control or display the new value.
2. Prove the candidate preference byte is safe across all runtime paths and
   confirm the stock persistence writer reloads it after a reboot.
3. Create a genuinely independent second music decoder and connect both PCM
   streams to the real playback queue/I²S path. Current mixer and MP3-context
   experiments remain mocked and are not installed in this candidate.
4. Validate boot, menu navigation, saving, reboot, and audio on the exact iPod.

Until those steps pass, this candidate must not be described as a working
crossfade firmware or flashed as a release image.
