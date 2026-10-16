# RetailOS 1.3 Settings UI: verified resource map

This note refers to the exact extracted `OSOS` component with SHA-256
`784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251`.
All offsets are zero-based **OSOS** offsets, not whole-IPSW or disk offsets.
The original backup and connected iPod were never written during this work.

## Confirmed resource structure

The source of [iPodWizard](https://github.com/DavidBuchanan314/iPodWizard-mirror/blob/master/firmware.h)
defines a block header, section descriptors, 12-byte resource records, 40-byte
menu rows, and variable-length View elements. The read-only parsers in
`tools/ui_resource_probe.py`, `tools/ui_tcmd_probe.py`, and
`tools/ui_view_probe.py` implement those structures with bounds checking.

The exact OSOS contains 25 resource blocks. The main block begins at
`0x331da0` and has 40 `Menu` resources and 619 `View` resources. Menu ID
`24598` is at `0x4af530`, 724 bytes long: a four-byte row count of 18 followed
by 18 rows of 40 bytes. The resource's label IDs resolve to the actual stock
Settings entries in both English and Russian. The Russian string block begins
at `0x30fcf4`; the first row's label (`textID2=-133`) is **«Конфигурация»**
there, where English has “About”. This is a string-table observation, not a
claim about the page title or translation quality.

The main block header's `length=0x6854` equals exactly its header plus eight
section descriptors plus all resource records; it is the table length, not a
free-space budget. Menu 24598 ends at `0x4af804`, and the next resource starts
at precisely `0x4af804`. There is no in-place space for an extra row.

Relevant current Settings rows:

| Row | Label in stock Russian | Row offset | `cmd` | `textID2` |
| --- | --- | --- | ---: | ---: |
| 5 | Предел громкости | `0x4af5d4` | 17538 (`0x4482`) | 24656 |
| 7 | Яркость | `0x4af624` | 17286 (`0x4386`) | -36 |

The Volume Limit command number **also matches** a View resource ID: View
17538 is at `0x4cf8b0` and is 460 bytes. It has five child elements: three
`BMap`, one `None`, and one `Str `. A parent View 24069 at `0x4d8ac4` has a
child with ID 17538. The number `0x4482` appears as an aligned 32-bit word in
only three locations: the View resource table (`0x336d10`), the Settings row
(`0x4af5e0`), and that parent View child (`0x4d8c54`). This is evidence of a
resource relationship; it does **not** identify the code handling Click Wheel
movement or storing the Volume Limit value.

The exact View 17538 contains no `Cntl` element. A scan of all 619 Views found
23 `Cntl` elements across 21 other Views; their resource graph does not link
them to Settings row `cmd=17538` or Brightness row `cmd=17286`. These controls
cannot be assigned as the stock Settings wheel slider without further runtime
evidence. The getter and setter are confirmed as the two image-relative
function-pointer entries at `0x66c94c` and `0x66c950` (`0x190b00` and
`0x1919d8`). Ghidra's ordinary xref pass did not resolve these values as loaded
addresses; this finding does not establish where the settings-object table is
selected or which UI callback dispatches to it.

The main `TCmd` resource begins at `0x4b441c` and has 1064 indexed entries;
its parsed IDs range from 152 to 5009. Therefore the menu `cmd` values
17538 and 17286 are not TCmd entry IDs. The Brightness value `0x4386` appears
as an aligned word only in its menu row and has no same-ID View resource.
The behavior of `cmd` is not yet established across the different Settings rows.

The settings-object vtable at `0x66c94c/0x66c950` contains code offsets
`0x190b00/0x1919d8` (get/set). In the getter, `0x190d90..0x190da4`
compares a property key to **`0x604f`** and reads `[settings_object+0x84]` on
the matching type path. In the setter, `0x191c0c..0x191c14` compares the key to
`0x604f`, branches to `0x1922f0`, stores the supplied 32-bit value in
`[settings_object+0x84]`, and calls `0x0b408c`. Adjacent cases compare key
`0x6055` for Brightness. In the Settings menu row metadata, the low 16 bits
of the respective `z6` words are exactly `0x604f` and `0x6055`. Thus the
menu rows, storage keys, and concrete get/set cases are now linked. The
meaning of the high half of `z6` still needs validation.

The setter's call at `0x1922fc` reaches `0x0b408c`, which updates the backing
preferences object's word at `+0xb58` and, if the value changed, branches to
`0x0a983c` to set dirty byte `+0xb74` to 1. Code at `0x0bbf1c` checks this
dirty byte and calls `0x0bbdf8`. That latter routine contains the literal path
`iPod_Control\\Device\\Preferences` (at `0x0bbef4`), calls file-oriented
helpers, and clears dirty byte `+0xb74` at `0x0bbed8` after its write path.
This establishes the current Volume Limit setting's persistence path; the
exact file format and a safe place for a new persisted key are still unknown.

## Resource lookup hook confirmed by Ghidra

The externally reported RetailOS 1.3 address `OSOS+0x21f254` is a real ARM
function in this exact OSOS. Its decompilation is:

```c
local_18 = 0;
while (param_1 != 0 &&
       ((**(code **)(*param_1 + 0x5c))(param_1, param_2, param_3,
                                         &local_18), result == 0)) {
    param_1 = (int *)param_1[4];
}
return local_18;
```

It walks a linked list of resource providers, calls each provider's virtual
lookup method at byte offset `0x5c`, and returns the first nonzero result.
Ghidra found 83 code references to this function, including callers in the
resource and view paths. This confirms a viable *candidate interception point*
for modifying resource lookup before a view is created. It does not establish
the calling convention of a custom trampoline beyond the displayed function
signature, the boot-time timing of the first lookup, or how to reserve and
execute injected ARM code. The address and hook description were independently
reported by a community RetailOS patch author. On 2026-10-16, a public account
of a separate RetailOS 1.3 Dark Mode patch described hooking this function
before the first View lookup, adding a Settings row, and patching the settings
object getter/setter at `0x66c94c/0x66c950`. The author reports that selection
is saved through stock settings and applied after a restart. This supports
these addresses as practical patch points, but the source code is not yet
public and the implementation has not been verified against this project's
backup. It does not demonstrate a Click Wheel slider, a new persisted integer
setting, or an audio mixer. Source: [Dark Mode & Album Artwork on patched
Stock OS](https://www.reddit.com/r/IpodClassic/comments/1wy2cwz/dark_mode_album_artwork_on_patched_stock_os/).

The result narrows the UI investigation: a future patch can inspect resource
IDs at this boundary and provide a replacement view or menu through an added
provider, if that provider can be safely installed. It does not by itself add
a nineteenth Settings row, create a Click Wheel slider, or persist its value.
The precise event dispatcher and a noncolliding preference field remain
unresolved, so this discovery is not enough to build or install the requested
screen.

The writer at `0x0bbdf8` loads the literal length `0xb6c` (2924 bytes),
allocates that many bytes via `0x0a8178`, and copies the current preferences
area through `0x0a8098` before the file write at `0x0bbed4`. The connected
device's existing `Preferences` file is also exactly 2924 bytes; it was read
without modification. This supports a fixed-size serialization path, but does
not identify any unused field where a new duration could safely live.

## What cannot yet be patched correctly

Cloning the Volume Limit View or substituting `cmd=17538` and key `0x604f` in
a new menu row would reuse the stock Volume Limit behavior and overwrite its
setting. A new key is not recognized by the existing get/set branches. There
is no evidence of an independent 3–10-second value or a callback into the
music player. Menu ID 24598 has no room for a nineteenth 40-byte row: adding
one requires relocating resource payloads and updating the resource table.
The existing Russian string block has no «Плавный переход» entry, so that
also requires resource work. No firmware UI modification was made.

To build an independent stock-style slider, the remaining work is specific:

1. Identify the runtime Settings-row dispatcher and the Volume Limit or
   Brightness Click Wheel event handler; prove which callback receives each
   wheel step, Select, and MENU. Its 3–10 clamp and on-screen numeric display
   must be implemented without affecting the stock controls.
2. Allocate a new property key and backing value, add guarded get/set paths,
   and trace the `Preferences` serialization format so the new value survives
   a reboot without changing any current setting or corrupting old files.
3. Rebuild the Settings menu with a nineteenth row, add localized strings and
   a new View for the horizontal track, moving circular knob, and compact
   seconds label. Update every affected resource record and checksum in an
   isolated output image.
4. Connect that value to the yet-to-be-implemented two-track PCM mixer and
   validate navigation, persistence, playback, and reboot on target hardware.

No source-backed wheel callback or free preferences slot has been established
yet. There is no UI patch to install.

Reproduction examples:

```powershell
$env:PYTHONIOENCODING = 'utf-8'
py .\tools\ui_resource_probe.py .\firmware\extracted\audio-analysis\osos.bin --menu 24598 --menu-text --language-block 0x30fcf4
py .\tools\ui_view_probe.py .\firmware\extracted\audio-analysis\osos.bin --id 17538
py .\tools\ui_tcmd_probe.py .\firmware\extracted\audio-analysis\osos.bin --id 17538 --id 17286
```
