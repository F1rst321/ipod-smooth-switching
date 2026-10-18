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
The code cave is not extra RAM; audio buffers still need runtime heap memory.

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
