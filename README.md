# RAMstain

A small, offline **RAM capture** tool for Windows, for forensics and incident
response.

No account, no email, no registration, no network. One portable EXE: run it,
pick where to save, click **Capture**.

<p align="center">
  <img src="docs/screenshot.png" alt="RAMstain main window" width="536">
</p>

---

## Features

- **Portable single EXE** (~800 KB). No installer, no runtime to install. The
  signed [WinPmem](#credits) imager is built in.
- **Offline.** No network calls, no telemetry, no updates.
- **Evidence-ready output.** A `.raw` image plus a `.meta` sidecar with host,
  OS, timestamp, size and MD5.
- **Split images** into 1–16 GB parts (`.001`, `.002`, …), including a
  FAT32-safe 4 GB option.
- **Live progress** for the capture and the MD5 step, with **Stop** at any
  time (the partial image is kept).
- **Safety checks:** overwrite prompt, free-space check, and a warning if you
  close the window during a capture.

## Usage

Run `RAMstain.exe` (it asks for Administrator rights), choose the output path,
and click **Capture**. When it finishes you get a summary with size, time,
speed and MD5.

### Command line

```
RAMstain.exe "D:\evidence\host1.raw"      pre-fill the save path
RAMstain.exe --split 4095                 preselect split size in MB
RAMstain.exe --driver "C:\tools\winpmem.exe"   use an external imager instead of the built-in one
RAMstain.exe --no-driver                  select the experimental driverless method
RAMstain.exe --selftest "C:\out\test.raw" 512 MB synthetic test, no real memory read
```

An external imager can also be set with the `RAMSTAIN_WINPMEM` environment
variable. Both the classic WinPmem 2.x and the Go imager (`go-winpmem`) work.

## Output

| File | Contents |
|------|----------|
| `<name>.raw` | Physical memory image. With splitting: `<name>.001`, `<name>.002`, … |
| `<name>.meta` | Image path, host, OS/kernel, capture time, size, MD5, tool version, method, and per-part MD5s when split. |

Example `host1.meta`:

```
RAMstain capture metadata
=========================
Image:       D:\evidence\host1.raw
Host:        WS-FORENSICS-01
OS:          Windows 10.0 build 26200
Kernel:      NT 10.0.26200
Captured:    20260928_163614 (local time)
Size:        34359738368 bytes
Pages:       8388608 x 4096 bytes
MD5:         2ea471360b0e7eecd12e9f61a5d2649c
Tool:        RAMstain 1.9.0
Method:      WinPmem kernel driver (WinPmem 2.x, embedded, Velocidex signed driver)
```

A stopped capture keeps its partial image but gets no MD5.

## Splitting large images

Pick a part size in the **Split** drop-down (or use `--split <MB>`). The parts
use the `.001`, `.002`, … naming that FTK Imager, X-Ways and Autopsy open
directly. Choose **4 GB parts (FAT32-safe)** for FAT32 USB drives.

The image is split in place after capture, so the extra disk space needed is
only one part. The `.meta` file lists each part with its own MD5; the main MD5
covers the whole image. To rejoin:

```
copy /b host1.001 + host1.002 + host1.003 host1.raw
```

## How it captures

Reading physical memory on Windows requires a kernel driver. RAMstain uses the
signed WinPmem driver:

1. On the first capture, the built-in imager is written to a temporary folder
   (`%TEMP%\RAMstain-<pid>\`) that only Administrators can access.
2. The imager loads its driver, writes the image, and unloads the driver.
3. When RAMstain closes, the temporary folder is deleted.

If a capture produces no image, security software or a driver-blocking policy
(such as HVCI or the vulnerable-driver blocklist) may have stopped the driver
from loading. Check Event Viewer.

**Driverless mode (experimental).** Unticking **Use WinPmem driver** tries
`OpenProcess(-1)` + `ReadProcessMemory`. This is not a documented Windows API
and fails on current Windows (error 87). It is kept only for testing.

---

## Building

Requires **Visual Studio 2022** with the C++ desktop workload (x64).

```bat
build.bat            :: Release  ->  x64\Release\RAMstain.exe
build.bat Debug      :: Debug    ->  x64\Debug\RAMstain.exe
```

Or open `RAMstain.sln` and build **Release | x64**.

Each build bumps the minor version in `src\version.h` (via
`scripts\bump-version.ps1`). Edit that file to change the major version.

### Repository layout

```
src/                  application source (RAMstain.cpp, resources, legal text)
scripts/              build helpers (version bump)
third_party/winpmem/  embedded WinPmem imager, its license, and provenance notes
build.bat             build wrapper
```

---

## Credits

RAMstain is built on **[WinPmem](https://github.com/Velocidex/WinPmem)**, the
open-source Windows memory imager by **Michael Cohen**, maintained by
**[Velocidex](https://github.com/Velocidex)**. WinPmem does the actual work of
reading physical memory through its signed kernel driver; RAMstain adds the
interface, integrity hashing, evidence sidecar and image splitting.

The embedded imager is WinPmem 2.0.1, signed by Velocidex Innovations, and is
included unmodified under the [Apache License 2.0](third_party/winpmem/LICENSE)
(Copyright 2012 Michael Cohen). The license text is also shown in the app under
**Terms of Use**. Thank you to the WinPmem authors and contributors.

## Legal and privacy

RAMstain is provided **as is**, for qualified professionals on systems they
are authorized to access. Capturing memory without authorization may be
unlawful.

RAMstain collects and sends nothing. Memory images can contain passwords,
keys and personal data, so treat them as highly sensitive.

The Disclaimer, Privacy Policy and Terms of Use are built into the app (see
the footer links) and kept in [`src/legal.h`](src/legal.h).

## License

Not yet specified. WinPmem remains under its own Apache 2.0 license.
