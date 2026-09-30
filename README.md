# RAMstain

A compact, offline **physical memory (RAM) capture** tool for Windows, written
in C++ (Win32, zero runtime dependencies) for forensics and incident response.

One goal: get a memory image off a machine **without** the friction of most
commercial/cloud capture tools — **no account, no email, no phone number, no
username, no download registration, no network connection.** RAMstain is a
single EXE that you run and that writes the dump straight to a path you choose.

---

## What it does

RAMstain captures the entire contents of physical RAM using the official,
signed **Velocidex WinPmem** imager (`go-winpmem-signed.exe`). The imager
temporarily loads its signed kernel driver, writes the image, and unloads the
driver again. RAMstain drives it from a simple UI and adds the MD5 digest and
evidence sidecar described below. Nothing is installed permanently.

An **experimental driverless path** (`OpenProcess` on PID -1 +
`ReadProcessMemory`) is still available by unticking **Use WinPmem driver**,
but it is not a documented Windows API and is expected to fail. See
[Capture methods](#capture-methods).

For each capture it produces two files in the location you specify:

| File | Description |
|------|-------------|
| `<name>.raw`  | The physical memory image, 4 KiB page-aligned. |
| `<name>.meta` | An evidence sidecar: image path, host name, OS + kernel build, capture timestamp, byte size, page count, MD5 digest, tool version, and method. |

An **MD5** digest of the finished image (the same convention WinPMEM uses for
integrity) is written to both the completion dialog and the `.meta` sidecar.

## Key properties

- **Small, self-contained EXE.** Statically linked (no VC++ runtime / MFC /
  redistributable required). ~220 KB. Needs the WinPmem imager
  (`go-winpmem-signed.exe`) placed next to it for real captures.
- **Offline by design.** No network calls, no telemetry, no update downloads.
- **Runs as Administrator** (required to read physical memory).
- **Progress + Stop.** Live progress bar; the **Close** button becomes **Stop**
  during a capture, letting you cancel cleanly (a partial image + sidecar is
  kept and marked as such). No MD5 is computed for a stopped capture, and
  pressing Stop during the MD5 step keeps the complete image but skips the hash.
- **Pre-flight checks.** Warns on an existing destination (overwrite prompt)
  and verifies enough free disk space before starting.
- **Modern UI.** Themed (Common Controls v6), per-monitor DPI aware, owner-drawn
  flat controls.
- **Legal docs built in.** Disclaimer, Privacy Policy, and Terms of Use are
  bundled in the EXE and openable from the footer — no website needed.

---

## Building

Requires **Visual Studio 2022** (C++ core tools, x64).

```bat
build.bat            :: Release x64  ->  x64\Release\RAMstain.exe
build.bat Debug      :: Debug  x64  ->  x64\Debug\RAMstain.exe
```

Or in Visual Studio: open `RAMstain.sln` → select **Release | x64** → Build.

**Versioning.** Every build bumps the minor version (1.1.0 → 1.2.0 → …).
A pre-build step runs `scripts\bump-version.ps1`, which rewrites
`src\version.h`. That header feeds the EXE's version resource, the version in
the app footer and the `Tool:` line in `.meta`. To change the major version or
reset the minor, edit the numbers in `src\version.h`; the next build continues
from there. The bump happens before compiling, so a failed build still uses up
a number.

## Running

```
RAMstain.exe
```

1. Download `go-winpmem-signed.exe` from the
   [WinPmem releases](https://github.com/Velocidex/WinPmem/releases) and place
   it next to `RAMstain.exe`.
2. Choose the output path (default is `RAMstain_<timestamp>.raw` next to the
   EXE). Use **Browse…** to pick a different location.
3. Click **Capture**. RAMstain runs as Administrator (UAC prompt at launch),
   runs the imager, and shows live progress as the image grows.
4. On completion you get a summary dialog (size, time, speed, MD5) and the
   option to open the folder.

### Command line

```
RAMstain.exe "D:\evidence\host1.raw"                  :: pre-fill the save path
RAMstain.exe --driver "C:\tools\go-winpmem-signed.exe" :: use an imager from another location
RAMstain.exe --no-driver                              :: start with the experimental driverless path selected
RAMstain.exe --selftest "C:\out\test.raw"             :: run a 512 MiB synthetic pipeline test
```

The imager is looked up in this order: `--driver <path>`, then
`go-winpmem-signed.exe` / `go-winpmem.exe` / `winpmem-go.exe` next to
`RAMstain.exe`, then the `RAMSTAIN_WINPMEM` environment variable, then
`C:\RAMstain\go-winpmem-signed.exe`.

`--selftest` writes a known synthetic 512 MiB image through the same
write → MD5 → sidecar → dialog pipeline as the driverless path. It is a way to
verify the tool, disk, and MD5 path work end-to-end **without** capturing real
memory. The `.meta` sidecar is clearly marked `SELF-TEST synthetic source`.

---

## Capture methods

**WinPmem driver (default).** Reading physical memory on Windows requires
kernel code, so the supported method is the signed WinPmem driver. During a
capture the imager creates a temporary `winpmem` service, loads the driver,
writes the image, and removes the service again. RAMstain also runs the
imager's unload command afterwards as a safety net. Both the Go imager
(`go-winpmem`, `acquire <file>`) and the classic C++ WinPmem 2.x
(`winpmem <file>`) are supported. RAMstain reads the imager's `--help` output
to tell them apart and passes the matching arguments. Progress is shown as the
image file grows, followed by a progress readout while the MD5 is computed. Security products or
driver-blocking policies (e.g. HVCI / the vulnerable-driver blocklist) can
prevent the driver from loading; check Event Viewer if a capture produces no
image.

**Driverless (experimental).** Unticking **Use WinPmem driver** (or passing
`--no-driver`) tries `OpenProcess` on PID -1 followed by `ReadProcessMemory`.
This is **not** a documented Windows API. On Windows 11 build 26200,
`OpenProcess(-1)` fails with error 87 (`ERROR_INVALID_PARAMETER`), exactly the
same error Windows returns for any process ID that does not exist. No Windows
version is known where this path captures memory. It is kept only so it can be
tested on other systems.

---

## Repository layout

```
RAMstain.sln            Visual Studio solution
RAMstain.vcxproj        project (v143 / x64, static CRT, UAC + themed manifest)
build.bat               MSBuild wrapper (app + local tools)
src/
  RAMstain.cpp          the entire application (UI + capture engine)
  md5.h                 small self-contained MD5 (for capture integrity only)
  legal.h               Disclaimer / Privacy Policy / Terms of Use text
  ramstain.rc           resources (icon, version info)
  version.h             version numbers (rewritten by scripts\bump-version.ps1 each build)
  RAMstain.ico          app icon
  RAMstain.manifest     DPI awareness + Common Controls v6 (UAC requireAdministrator is set in RAMstain.vcxproj)
scripts/
  bump-version.ps1      pre-build step: increments the minor version
.gitignore              excludes build output, captures (*.raw/*.meta), notes
```

`test/` and `tools/` (diagnostics) are intentionally **not** committed — they
contain local captures and helper scripts.

---

## Output example

`host1.raw.meta`:

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
Tool:        RAMstain 1.0.0
Method:      WinPmem kernel driver (Velocidex signed driver)
```

---

## Legal

RAMstain is provided **as is** for use by qualified professionals on systems
they are legally authorized to access. Use of this tool to capture memory
without proper authorization may be unlawful. This is not legal advice.

The full texts are embedded in the app (footer → **Disclaimer**, **Privacy
Policy**, **Terms of Use**) and maintained in [`src/legal.h`](src/legal.h).
Review them — and the source — with a qualified lawyer before public
distribution.

## Privacy

RAMstain collects nothing and transmits nothing. The only confidential data
involved is the memory image you create, which you write locally and control
entirely. Memory images can contain credentials, keys, and personal data —
treat them as highly sensitive.

## License

Not yet specified. See the legal documents above.
